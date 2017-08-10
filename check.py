#!/usr/bin/python3

import sys
import dns.resolver # Debian: python3-dnspython
import http.client
import smtplib
import ssl
import socket
import flask # Debian: python3-flask
from flask_limiter import Limiter # pip3: Flask-Limiter
from flask_limiter.util import get_remote_address
import re

# See e.g. this page how to deploy:
# http://flask.pocoo.org/docs/0.12/deploying/uwsgi/

domainPattern = re.compile('^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$')

class Result:
    def __init__(self, report):
        self.report = report
        self.warnings = []
        self.errorName = None
        self.errorValue = None
        self.value = None
        self.valid = True

    def error(self, message, value=None):
        ''' Error for this specific result '''
        self.valid = False
        self.report.valid = False
        self.errorName = message
        self.errorValue = value
        return self.report

    def warn(self, message, value=None):
        self.warnings.append({'message': message, 'value': value})
        self.report.hasWarnings = True

class Report:
    def __init__(self, domain):
        self.domain = domain
        self.hasWarnings = False
        self.dns = Result(self)
        self.policy = Result(self)
        self.mx = Result(self)
        self.valid = True

    def error(self, message):
        ''' Global error '''
        self.valid = False
        self.errorName = message
        return self

def checkDNS(result, domain):
    fullDomain = '_mta-sts.' + domain
    try:
        answers = dns.resolver.query(fullDomain, 'TXT')
    except dns.resolver.NXDOMAIN:
        return result.error('no-domain')
    except dns.resolver.NoAnswer:
        return result.error('no-answer')
    except dns.resolver.Timeout:
        return result.error('timeout')

    # From the RFC draft:
    #     If multiple TXT records for _mta-sts are returned by the resolver,
    #     records which do not begin with v=STSv1; are discarded. If the number
    #     of resulting records is not one, senders MUST assume the recipient
    #     domain does not implement MTA-STS and skip the remaining steps of
    #     policy discovery.
    dnsPolicies = []
    otherResults = []
    for record in answers:
        if len(record.strings) > 1:
            # Undefined in the spec
            # https://github.com/mrisher/smtp-sts/issues/168
            result.warn('multiple-strings-undefined')
        # assuming behaviour like in DKIM and SPF.
        if isinstance(record.strings[0], bytes):
            data = b''.join(record.strings).decode('ascii')
        else:
            data = ''.join(record.strings)
        if not data.startswith('v=STSv1;'):
            otherResults.append(data)
            continue
        dnsPolicies.append(data)
    if len(dnsPolicies) > 1:
        # TODO provide these results
        return result.error('multiple-records', dnsPolicies)
    if len(dnsPolicies) == 0:
        if len(otherResults):
            return result.error('no-valid-txt-record', otherResults)
        else:
            return result.error('no-txt-record')
    result.value = dnsPolicies[0]

    fields = list(map(lambda s: s.strip(' \t'), re.split('[ \t]*;[ \t]*', dnsPolicies[0])))

    if len(fields) < 1 or fields[0] != 'v=STSv1':
        # already covered in dns:no-valid-txt-record but checking it anyway
        return result.error('invalid-version-prefix')

    # And what if the 'id' field is the 3rd field? This is currently impossible:
    # https://github.com/mrisher/smtp-sts/issues/167
    if len(fields) < 2 or not fields[1].startswith('id='):
        return result.error('invalid-id', fields[1][3:])
    idvalue = fields[1][3:]
    # Note: the 'id' value is case-sensitive, and just an identifier - there is
    # no version numbering with higher versions being later defined.
    if not re.match('^[a-zA-Z0-9]{1,32}$', idvalue):
        return result.error('invalid-id', idvalue)
    for field in fields[2:]:
        if not field:
            continue
        if not re.match('^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}=[\x21-\x3a\x3c\x3e-\x7e]{1,}$', field):
            return result.error('invalid-ext-field', field)
        result.warn('unknown-ext-field', field)

def checkPolicyFile(result, domain):
    host = 'mta-sts.'+domain
    path = '/.well-known/mta-sts.policy'
    url = 'https://' + host + path
    result.value = {'url': url}
    try:
        conn = http.client.HTTPSConnection(host, timeout=60)
    except http.client.HTTPException:
        return result.error('connect')

    try:
        conn.request('GET', path)
        res = conn.getresponse()
        if res.status == 404:
            return result.error('policy-not-found')
        if res.status != 200:
            return result.error('http-status', res.status)
        data = res.read()
    except http.client.HTTPException:
        return result.error('request')
    except socket.gaierror as e:
        if e.errno == socket.EAI_NONAME:
            return result.error('host-not-found', host)
        else:
            return result.error('dns-error', host)
    except OSError:
        return result.error('http-resolve-unknown', url)
    finally:
        conn.close()

    if len(data) >= 65536:
        result.warn('big-file', int(round(len(data)/1024)))

    try:
        data = data.decode('ascii')
    except UnicodeDecodeError:
        return result.error('decode-error')
    result.value['data'] = data

    # FIXME: this is using a guessed syntax as the standard doesn't specify one
    # (only an example).
    info = {'mx': []}
    result.value['info'] = info
    for line in data.split('\n'):
        line = line.strip()
        if not line:
            # empty line
            continue
        if ':' not in line:
            result.warn('invalid-line', line)
            continue
        key, value = line.split(':', 2)
        key = key.strip()
        value = value.strip()
        if key == 'mx':
            info['mx'].append(value)
        else:
            if key in info:
                result.warn('duplicate-key', {'key': key, 'value': value, 'line': line})
                continue
            info[key] = value

    if 'version' not in info:
        return result.error('no-version')
    if info['version'] != 'STSv1':
        return result.error('invalid-version', info['version'])
    if 'mode' not in info:
        return result.error('no-mode')
    if info['mode'] not in ['enforce', 'report']:
        return result.error('invalid-mode', info['mode'])
    if 'max_age' not in info:
        return result.error('no-max-age')
    try:
        max_age = int(info['max_age'])
        if max_age < 0:
            raise ValueError('')
    except ValueError:
        return result.error('invalid-max-age', info['max_age'])
    if max_age < 86400: # 1 day
        return result.error('short-max-age', max_age)
    if max_age < 2592000: # 30 days
        result.warn('short-max-age', max_age/86400)
    if len(info['mx']) < 1:
        return result.error('no-mx-entries')
    for mx in info['mx']:
        # TODO: check domain using pattern that accepts .example.com
        pass
        #if not domainPattern.match(mx):
        #    return result.error('invalid-mx-entry', mx)

    for key, value in info.items():
        if key not in ['version', 'mode', 'max_age', 'mx']:
            result.warn('unknown-key', {'key': key, 'value': value})


def checkMX(result, domain, policyNames=None):
    try:
        answers = dns.resolver.query(domain, 'MX')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return result.error('dns-error')

    mxs = set()
    for record in answers:
        mxs.add(record.exchange.to_text(omit_final_dot=True))

    mxs = list(mxs)
    mxs.sort()

    result.value = []

    for mx in mxs:
        data = {'mx': mx}
        result.value.append(data)

        conn = None
        names = set()
        cert = None
        try:
            context = ssl.create_default_context()
            # we do our own hostname checking
            context.check_hostname = False
            conn = smtplib.SMTP(mx, port=25)
            conn.starttls(context=context)
            cert = conn.sock.getpeercert()

            # TODO check for expired certificate?

            for rdn in cert.get('subject', ()):
                if rdn[0][0] == 'commonName':
                    names.add(rdn[0][1])
            if 'subjectAltName' in cert:
                for san in cert['subjectAltName']:
                    if san[0] == 'DNS':
                        names.add(san[1])
        except ssl.SSLError as e:
            data['error'] = e.reason
        finally:
            # try to close the connection
            if conn is not None:
                conn.close()

        names = list(names)
        def domainsortkey(n):
            n = n.split('.')
            n.reverse()
            return n
        names.sort(key=domainsortkey)
        data['certnames'] = names

        if policyNames is not None:
            if certMatches(names, policyNames):
                data['valid'] = True
            else:
                data['valid'] = False

        if not data.get('valid'):
            result.valid = False


# algorithm from Appendix 2 of the draft (function certMatches)
def certMatches(certNames, policyNames):
    for san in certNames:
        if len(san) < 2:
            # very likely invalid
            continue
        for mx in policyNames:
            if san[0] == '*':
                if san[1] != '.':
                    # Invalid wildcard!
                    continue
            if san[0] == '.' and mx.endswith(san):
                return True
            if mx[0] == '.' and san.endswith(mx):
                return True
            if mx == san:
                return True
    return False


def checkPolicy(domain):
    report = Report(domain)

    # See: https://stackoverflow.com/a/106223/559350
    if not domainPattern.match(domain):
        return report.error('invalid-domain')

    checkDNS(report.dns, domain)
    checkPolicyFile(report.policy, domain)
    if 'info' in report.policy.value:
        checkMX(report.mx, domain, report.policy.value['info']['mx'])
    else:
        checkMX(report.mx, domain)
        if report.mx.valid:
            # don't show an error message when the names haven't been checked
            report.mx.error('no-policy')

    return report

app = flask.Flask(__name__)
app.config['PROPAGATE_EXCEPTIONS'] = True

limiter = Limiter(
    app,
    key_func=get_remote_address,
)

# Catch-all: http://flask.pocoo.org/snippets/57/
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
@limiter.limit('1 per second')
@limiter.limit('5 per minute')
@limiter.limit('200 per day')
@limiter.limit('1 per second', key_func=lambda: flask.request.args.get('domain'))
@limiter.limit('5 per minute', key_func=lambda: flask.request.args.get('domain'))
@limiter.limit('200 per day', key_func=lambda: flask.request.args.get('domain'))
def check(path=None):
    domain = flask.request.args.get('domain')
    report = checkPolicy(domain)
    return flask.render_template('result.html', report=report)


def main():
    if len(sys.argv) < 2:
        app.run()
    else:
        result = checkPolicy(sys.argv[1])
        if result.dnsPolicy:
            print('DNS TXT record:', result.dnsPolicy)
        if result.errorName:
            print('Error:         ', result.errorName)
            if result.errorValue:
                print('Error value:   ', result.errorValue)
        if result.warnings:
            print('Warnings:      ', ', '.join(result.warnings))


if __name__ == '__main__':
    main()
