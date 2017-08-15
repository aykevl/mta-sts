#!/usr/bin/python3

import sys
import dns.resolver # Debian: python3-dnspython
import urllib.parse
import http.client
import json
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
    def __init__(self):
        self.warnings = []
        self.errorName = None
        self.errorValue = None
        self.value = None
        self.valid = True

    def error(self, message, value=None):
        ''' Error for this specific result '''
        self.valid = False
        self.errorName = message
        self.errorValue = value

    def warn(self, message, value=None):
        self.warnings.append({'message': message, 'value': value})

class Report:
    def __init__(self, domain):
        self.domain = domain
        self.dns = Result()
        self.tlsrpt = Result()
        self.policy = Result()
        self.mx = Result()
        self.errorName = None
        self.errorValue = None

    def error(self, message, value=None):
        ''' Global error '''
        self.valid = False
        self.errorName = message
        self.errorValue = value
        return self

    @property
    def valid(self):
        return self.dns.valid and self.tlsrpt.valid and self.policy.valid and self.mx.valid

    @property
    def hasWarnings(self):
        return self.dns.warnings or self.tlsrpt.warnings or self.policy.warnings or self.mx.warnings

def retrieveTXTRecord(result, domain, prefix, magic):
    fullDomain = prefix + '.' + domain
    try:
        answers = dns.resolver.query(fullDomain, 'TXT')
    except dns.resolver.NXDOMAIN:
        return result.error('no-domain', fullDomain)
    except dns.resolver.NoAnswer:
        return result.error('no-answer', fullDomain)
    except dns.resolver.Timeout:
        return result.error('timeout', fullDomain)

    # From the RFC draft (MTA-STS):
    #     If multiple TXT records for _mta-sts are returned by the resolver,
    #     records which do not begin with v=STSv1; are discarded. If the number
    #     of resulting records is not one, senders MUST assume the recipient
    #     domain does not implement MTA-STS and skip the remaining steps of
    #     policy discovery.
    dnsPolicies = []
    otherResults = []
    for record in answers:
        if len(record.strings) < 1:
            # Don't know whether this is allowed, but I keep it here just to be sure.
            continue
        if len(record.strings) > 1:
            # Undefined in the spec
            # https://github.com/mrisher/smtp-sts/issues/168
            result.warn('multiple-strings-undefined')
        # assuming behaviour like in DKIM and SPF.
        if isinstance(record.strings[0], bytes):
            data = b''.join(record.strings).decode('ascii')
        else:
            data = ''.join(record.strings)
        if data.startswith(magic):
            dnsPolicies.append(data)
        else:
            otherResults.append(data)
    if len(dnsPolicies) > 1:
        # TODO provide these results
        return result.error('multiple-records', dnsPolicies)
    if len(dnsPolicies) == 0:
        if len(otherResults):
            return result.error('no-valid-txt-record', otherResults)
        else:
            return result.error('no-txt-record')

    return dnsPolicies[0]

def checkDNS(result, domain):
    dnsPolicy = retrieveTXTRecord(result, domain, '_mta-sts', 'v=STSv1;')
    if dnsPolicy is None:
        # there was an error
        return
    result.value = dnsPolicy

    fields = list(map(lambda s: s.strip(' \t'), re.split('[ \t]*;[ \t]*', dnsPolicy)))

    if fields[0] != 'v=STSv1':
        # already covered in dns:no-valid-txt-record but checking it anyway
        return result.error('invalid-version-prefix')

    # And what if the 'id' field is the 3rd field? This is currently impossible:
    # https://github.com/mrisher/smtp-sts/issues/167
    if len(fields) < 2:
        return result.error('invalid-id', '')
    if not fields[1].startswith('id='):
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

def checkReporting(result, domain):
    dnsPolicy = retrieveTXTRecord(result, domain, '_smtp-tlsrpt', 'v=TLSRPTv1;')
    if dnsPolicy is None:
        # an error was returned
        return
    result.value = dnsPolicy

    fields = list(map(lambda s: s.strip(' \t'), re.split('[ \t]*;[ \t]*', dnsPolicy)))

    if fields[0] != 'v=TLSRPTv1':
        # already covered in no-valid-txt-record but checking it anyway
        return result.error('invalid-version-prefix', fields[0])
    if len(fields) < 2:
        return result.error('invalid-rua', '')
    if not fields[1].startswith('rua='):
        return result.error('invalid-rua', fields[1])
    rua = fields[1][4:]
    if ',' in rua or '!' in rua:
        return result.error('invalid-rua', fields[1])
    try:
        for part in rua.split(','):
            url = urllib.parse.urlparse(part)
            if url.scheme not in ['mailto', 'https']:
                return result.error('invalid-rua', fields[1])
    except ValueError:
        return result.error('invalid-rua', fields[1])

    # TODO: check extension fields for syntactical validity, but do that after
    # the spec has stabilized.


def checkPolicyFile(result, domain, policytype):
    host = 'mta-sts.'+domain
    path = '/.well-known/mta-sts.' + policytype
    url = 'https://' + host + path
    result.value = {'url': url}
    try:
        # timeout of 60s suggested by the standard
        context = context = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, timeout=10, context=context)
    except (http.client.HTTPException, TimeoutError):
        return result.error('connect')

    try:
        conn.request('GET', path)
        res = conn.getresponse()
        if res.status == 404:
            return result.error('policy-not-found')
        if res.status != 200:
            return result.error('http-status', res.status)
        data = res.read(65*1024)
    except http.client.HTTPException:
        return result.error('request')
    except socket.gaierror as e:
        if e.errno == socket.EAI_NONAME:
            return result.error('host-not-found', host)
        else:
            return result.error('dns-error', host)
    except ssl.SSLError as e:
        return result.error('ssl-error', e.reason)
    except ssl.CertificateError as e:
        return result.error('certificate-error', e)
    except OSError:
        return result.error('http-resolve-unknown', url)
    finally:
        conn.close()

    if len(data) >= 64*1024:
        return result.error3('big-file', int(round(len(data)/1024)))
    if len(data) > 4*1024:
        result.warn('big-file', int(round(len(data)/1024)))

    try:
        data = data.decode('ascii')
    except UnicodeDecodeError:
        return result.error('decode-error')
    result.value['data'] = data

    if policytype == 'policy':
        # FIXME: this is using a guessed syntax as the standard doesn't specify one
        # (only an example).
        info = {'mx': []}
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
    else: # json file
        try:
            info = json.loads(data)
        except json.JSONDecodeError:
            return result.error('json-decode')

    result.value['info'] = info

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
    if 'mx' not in info or len(info['mx']) < 1:
        return result.error('no-mx-entries')
    if type(info['mx']) != list: # json
        return result.error('invalid-mx-entries')
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
        return result.error('dns-error', domain)

    mxs = {}
    for record in answers:
        mxs[record.exchange.to_text(omit_final_dot=True)] = record.preference

    def mxsortkey(mx):
        name, preference = mx
        parts = name.split('.')
        parts.reverse()
        return preference, parts

    mxs = list(mxs.items())
    mxs.sort(key=mxsortkey)

    result.value = []

    for mx, preference in mxs:
        data = {'mx': mx, 'preference': preference}
        result.value.append(data)

        conn = None
        names = set()
        cert = None
        try:
            cert = {}
            if not domainPattern.match(mx):
                data['error'] = '!invalid-mx'
            elif len(result.value) > 5:
                data['error'] = '!skip'
            else:
                # TODO test MX label validity
                context = ssl.create_default_context()
                # we do our own hostname checking
                context.check_hostname = False
                conn = smtplib.SMTP(mx, port=25, timeout=10)
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
        except (TimeoutError, socket.timeout):
            data['error'] = '!timeout'
        except smtplib.SMTPException as e:
            data['error'] = e
        finally:
            # try to close the connection
            if conn is not None:
                conn.close()

        if cert is not None and not names and not data.get('error'):
            # does this actually happen?
            data['error'] = '!unknown'

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
        return report.error('invalid-domain', domain)

    checkDNS(report.dns, domain)
    checkReporting(report.tlsrpt, domain)
    checkPolicyFile(report.policy, domain, 'policy')
    if report.policy.errorName in ['policy-not-found', 'http-status']:
        jsonpolicy = Result()
        jsonpolicy.warn('json-policy')
        checkPolicyFile(jsonpolicy, domain, 'json')
        if jsonpolicy.errorName not in ['policy-not-found', 'http-status']:
            report.policy = jsonpolicy
    checkMX(report.mx, domain, report.policy.value.get('info', {}).get('mx', None))

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
