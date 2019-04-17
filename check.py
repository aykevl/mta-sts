#!/usr/bin/python3

import sys
import dns.resolver # Debian: python3-dnspython
import urllib.parse
import http.client
import cgi
import json
import smtplib
import ssl
import socket
import re
import hashlib

import flask # Debian: python3-flask
from flask_limiter import Limiter # Debian: python3-flask-limiter or pip3: Flask-Limiter
from flask_limiter.util import get_remote_address

from cryptography.hazmat.primitives import serialization # Debian: python3-cryptography
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend

NAMESERVERS = ['8.8.8.8']
SMTP_LOCAL_HOSTNAME = None

# See e.g. this page how to deploy:
# http://flask.pocoo.org/docs/0.12/deploying/uwsgi/

domainPattern   = re.compile(       '^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$')
mxDomainPattern = re.compile('^(\*\.)?(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$')

# Set up DNS resolver that requests validation
resolver = dns.resolver.Resolver()
resolver.nameservers = NAMESERVERS
resolver.edns = 0
resolver.ednsflags = dns.flags.DO

# Ratings:
# 1: error
# 2: warning
# 3: rooom for improvement
# 4: ok
# 5: disabled (but OK)
VERDICT_MAP = {
    None: None,
    1:    'fail',
    2:    'warn',
    4:    'ok',
    5:    'off',
}

class Result:
    '''
    Result of a single test.
    '''
    def __init__(self):
        self.warnings = []
        self.errorName = None
        self.errorValue = None
        self.value = None

    def error(self, message, value=None):
        ''' Error for this specific result '''
        if self.errorName is not None and (self.errorName != message or self.errorValue != value):
            raise ValueError('Result.error: error has already been set')
        self.errorName = message
        self.errorValue = value
        return None

    def stashError(self):
        ''' Temporarily remove this error. May be re-installed with result.error(**err). '''
        err = (self.errorName, self.errorValue)
        self.errorName = None
        self.errorValue = None
        return err

    def warn(self, message, value=None):
        self.warnings.append({'message': message, 'value': value})

    @property
    def rating(self):
        if self.errorName is not None:
            return 1 # error
        if self.warnings:
            return 2 # warning
        # TODO: room for improvement
        return 4

class MailserverResult:
    '''
    Result of a single MX server (part of the mx test)
    '''
    def __init__(self, name, preference, policyNames):
        self.name = name
        self.preference = preference
        self.policyNames = policyNames
        self.dnssec_a = None
        self.dnssec_tlsa = None
        self.tlsa_records = []
        self.error = None
        self.dane_hash_cert = None
        self.dane_hash_spki = None

    @property
    def matchesPolicy(self):
        return policyMatches(self.name, self.policyNames)

    @property
    def valid(self):
        if self.error:
            return False
        return self.matchesPolicy

    @property
    def verdict(self):
        if self.policyNames is None and not self.error:
            return 'none'
        return {True: 'ok', False: 'fail'}[self.valid]

    @property
    def daneVerdict(self):
        if not self.dnssec or not len(self.tlsa_records):
            return 'fail'
        return {
            'ok':          'ok',
            'fail':        'fail',
            'unusable':    'fail',
            'unsupported': 'none',
        }[self.tlsa_state]

    @property
    def dnssec(self):
        return self.dnssec_a and self.dnssec_tlsa

    @property
    def tlsa_state(self):
        has_unsupported = False
        has_unusable = False # has record that is not "3 1 1" or "2 1 1"
        is_valid = False
        for record in self.tlsa_records:
            # From https://tools.ietf.org/html/rfc7672#section-3.1:
            #
            #   In summary, we RECOMMEND the use of "DANE-EE(3) SPKI(1) SHA2-256(1)",
            #   with "DANE-TA(2) Cert(0) SHA2-256(1)" TLSA records as a second
            #   choice, depending on site needs.  See Sections 3.1.1 and 3.1.2 for
            #   more details.  Other combinations of TLSA parameters either (1) are
            #   explicitly unsupported or (2) offer little to recommend them over
            #   these two.
            #
            # From https://tools.ietf.org/html/rfc7672#section-3.1.1:
            #
            #   TLSA records published for SMTP servers SHOULD, in most cases, be
            #   "DANE-EE(3) SPKI(1) SHA2-256(1)" records.  Since all DANE
            #   implementations are required to support SHA2-256, this record type
            #   works for all clients and need not change across certificate renewals
            #   with the same key.
            #
            # From https://tools.ietf.org/html/rfc7672#section-3.1.3:
            #
            #   SMTP client treatment of TLSA RRs with certificate usages PKIX-TA(0)
            #   or PKIX-EE(1) is undefined.  As with any other unsupported
            #   certificate usage, SMTP clients MAY treat such records as "unusable".

            # In other words, the types supported by DANE are 3 x 1 and 2 x 1.

            if record.selector not in (0, 1):
                has_unusable = True
                continue

            if record.mtype != 1:
                has_unusable = True
                continue

            if record.usage not in (2, 3):
                has_invalid = True
                continue
            if record.usage == 2:
                has_unsupported = True
                # TODO: verify hostname and chain
                continue

            # record type is "3 x 1"

            if record.selector == 0 and record.cert.hex() == self.dane_hash_cert:
                is_valid = True
            elif record.selector == 1 and record.cert.hex() == self.dane_hash_spki:
                # TODO UNTESTED
                is_valid = True

        if is_valid:
            # At least one record validates.
            return 'ok'
        elif has_unsupported:
            # Has a "2 1 1" TLSA record which hasn't been implemented.
            return 'unsupported'
        elif has_unusable:
            # Has at least one unusable TLSA record, and validation failed.
            return 'unusable'
        else:
            # Could not validate.
            return 'fail'

class Report:
    '''
    Whole result, of all tests together.
    '''
    def __init__(self, domain):
        self.domain = domain
        self.sts = Result()
        self.tlsrpt = Result()
        self.policy = Result()
        self.mx = Result()
        self.errorName = None
        self.errorValue = None

    def error(self, message, value=None):
        ''' Global error '''
        self.errorName = message
        self.errorValue = value
        return self

    @property
    def rating(self):
        if self.errorName is not None:
            return 1 # error
        return min(self.sts.rating, self.tlsrpt.rating, self.policy.rating, self.mx.rating)

    @property
    def ratingSTS(self):
        if self.errorName is not None:
            rating = 1 # error
        else:
            rating = min(self.sts.rating, self.policy.rating, self.mx.rating)

        if rating == 4 and 'info' in self.policy.value and self.policy.value['info'].get('mode') != 'enforce':
            rating = 5 # MTA-STS is not enabled
        return rating

    @property
    def verdictSTS(self):
        return VERDICT_MAP[self.ratingSTS]

    @property
    def ratingTLSRPT(self):
        if self.errorName is not None or self.tlsrpt.errorName is not None:
            rating = 1 # error
        elif 'info' in self.policy.value and self.policy.value['info'].get('mode') not in {'enforce', 'testing'}:
            rating = 5 # TLSRPT is not enabled
        else:
            rating = 4
        return min(rating, self.sts.rating)

    @property
    def verdictTLSRPT(self):
        return VERDICT_MAP[self.ratingTLSRPT]

    @property
    def verdictDANE(self):
        daneVerdicts = set()
        for server in self.mx.value['servers']:
            daneVerdicts.add(server.daneVerdict)
        if 'none' in daneVerdicts:
            return 'none'
        if 'ok' in daneVerdicts:
            return 'ok'
        return 'fail'

def retrieveTXTRecord(result, domain, prefix, magic):
    fullDomain = prefix + '.' + domain
    try:
        answers = resolver.query(fullDomain, 'TXT')
    except dns.resolver.NXDOMAIN:
        return result.error('no-domain', fullDomain)
    except dns.resolver.NoAnswer:
        return result.error('no-answer', fullDomain)
    except dns.resolver.Timeout:
        return result.error('timeout', fullDomain)
    except dns.exception.DNSException as e:
        return result.error('dns-catchall', e)

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
            # This is actually possible, though I don't know whether it is
            # allowed.
            continue
        data = b''.join(record.strings).decode('ascii')
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

def checkDNS_STS(result, domain):
    record = retrieveTXTRecord(result, domain, '_mta-sts', 'v=STSv1;')
    if record is None:
        # there was an error
        return
    result.value = record

    fields = list(map(lambda s: s.strip(' \t'), re.split('[ \t]*;[ \t]*', record)))

    if fields[0] != 'v=STSv1':
        # already covered in dns:no-valid-txt-record but checking it anyway
        return result.error('invalid-version-prefix')

    checkExtensionFields(fields[1:], result)

    idValue = None
    for field in fields[1:]:
        if field.startswith('id='):
            idValue = field[3:]

    if not idValue:
        return result.error('invalid-id', idValue or '')

    # Note: the 'id' value is case-sensitive, and just an identifier - there is
    # no version numbering with higher versions being later defined.
    if not re.match('^[a-zA-Z0-9]{1,32}$', idValue):
        return result.error('invalid-id', idValue)


def checkDNS_TLSRPT(result, domain):
    record = retrieveTXTRecord(result, domain, '_smtp._tls', 'v=TLSRPTv1;')
    if record is None and result.errorName == 'no-domain':
        # No _smtp._tls domain found, let's try the old one: _smtp-tlsrpt.
        # Stash away the current error to be restored if the old domain name
        # also doesn't exist.
        err = result.stashError()
        record = retrieveTXTRecord(result, domain, '_smtp-tlsrpt', 'v=TLSRPTv1;')
        if record is None:
            # Cannot find the old or new style domain name.
            # Restore previous error.
            result.stashError() # clear new error
            return result.error(*err) # restore old error
        else:
            # Only the old domain name exists. Give a specific error.
            result.error('old-prefix', domain)
    if record is None:
        # an error was returned
        return
    result.value = {
        'raw': record,
    }

    fields = re.split('[ \t]*;[ \t]*', record) # split at field-delim

    if fields[0] != 'v=TLSRPTv1':
        # already covered in no-valid-txt-record but checking it anyway
        return result.error('invalid-version-prefix', fields[0])

    checkExtensionFields(fields[1:], result)

    ruafield = None
    for field in fields:
        if field.startswith('rua='):
            ruafield = field
    if '!' in ruafield:
        return result.error('invalid-rua', ruafield)
    rua = ruafield[4:]

    addresses = []
    try:
        for part in re.split('[ \t]*,[ \t]*', rua):
            url = urllib.parse.urlparse(part)
            if url.scheme not in ['mailto', 'https']:
                return result.error('invalid-rua', ruafield)
            addresses.append(part)
    except ValueError:
        return result.error('invalid-rua', ruafield)
    result.value['addresses'] = addresses


def checkExtensionFields(fields, result):
    for field in fields[2:]:
        if not field:
            continue
        if not re.match('^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}=[\x21-\x3a\x3c\x3e-\x7e]{1,}$', field):
            return result.error('invalid-ext-field', field)
        result.warn('unknown-ext-field', field)


def checkPolicyFile(result, domain):
    host = 'mta-sts.'+domain
    path = '/.well-known/mta-sts.txt'
    url = 'https://' + host + path
    result.value = {
        'url': url,
    }
    try:
        # timeout of 60s suggested by the standard
        context = context = ssl.create_default_context()
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
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
        if e.reason == 'NO_PROTOCOLS_AVAILABLE':
            return result.error('tls-old-protocol')
        else:
            return result.error('tls-error', e.reason)
    except ssl.CertificateError as e:
        return result.error('certificate-error', e)
    except OSError as e:
        return result.error('http-resolve-unknown', str(e))
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

    contentType = res.getheader('Content-Type')
    if contentType is None:
        return result.error('no-content-type')
    mimetype, options = cgi.parse_header(contentType)
    if mimetype != 'text/plain':
        return result.error('invalid-content-type', contentType)
    info = {'mx': []}
    lines = data.splitlines(True)
    if lines[-1] == '':
        # Normally you would just 'continue' on empty lines, but in this
        # case we want to validate there are no empty lines before EOF.
        lines = lines[:-1]
    has_other_newlines = False
    for line in lines:
        bare_line = line.rstrip('\r\n')
        if line not in [bare_line, bare_line+'\n', bare_line+'\r', bare_line+'\r\n']:
            # TODO this is probably a strange newline, like \v or \u2028
            print('weird newline:', repr(line))
            has_other_newlines = True
        line = bare_line
        if ':' not in line:
            result.warn('invalid-line', line)
            continue
        # Regex has been derived from the ABNF in the spec.
        # TODO: allow UTF-8 chars
        if not re.match('^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}:[ \t]*[\x21-\x3a\x3c\x3e-\x7e]{1,}[ \t]*', line):
            result.warn('invalid-line', line)
            continue
        key, value = line.split(':', 1)
        value = value.strip(' \t')
        if key == 'mx':
            info['mx'].append(value)
        else:
            if key in info:
                result.warn('duplicate-key', {'key': key, 'value': value, 'line': line})
                continue
            info[key] = value
    if has_other_newlines:
        result.warn('invalid-linefeed-other')

    result.value['info'] = info

    if 'version' not in info:
        return result.error('no-version')
    if info['version'] != 'STSv1':
        return result.error('invalid-version', info['version'])
    if 'mode' not in info:
        return result.error('no-mode')
    if info['mode'] == 'report':
        return result.error('old-mode-report')
    if info['mode'] not in ['enforce', 'testing', 'none']:
        return result.error('invalid-mode', info['mode'])
    if 'max_age' not in info:
        return result.error('no-max-age')
    try:
        max_age = int(info['max_age'])
        if max_age < 0:
            raise ValueError('')
        if max_age > 10**10-1: # 9999999999, or 10 chars
            raise ValueError('')
    except ValueError:
        return result.error('invalid-max-age', info['max_age'])
    if max_age < 86400: # 1 day
        return result.error('short-max-age', max_age/86400)
    if max_age < 2419200 and info.get('mode', 'testing') != 'testing': # 28 days
        result.warn('short-max-age', max_age/86400)
    if max_age > 31557600:
        result.warn('long-max-age', max_age/86400)
    if 'mx' not in info or len(info['mx']) < 1:
        return result.error('no-mx-entries')
    for mx in info['mx']:
        # ABNF, according to the MTA-STS spec:
        #   sts-policy-mx-value      = ["*."] Domain
        #   Domain                   = sub-domain *("." sub-domain)
        #   sub-domain               = Let-dig [Ldh-str]
        #   Let-dig                  = ALPHA / DIGIT
        #   Ldh-str                  = *( ALPHA / DIGIT / "-" ) Let-dig
        if not mxDomainPattern.match(mx.lower()):
            return result.error('invalid-mx-entry', mx)

    for key, value in info.items():
        if key not in ['version', 'mode', 'max_age', 'mx']:
            result.warn('unknown-key', {'key': key, 'value': value})

def getMX(result, domain):
    try:
        answers = resolver.query(domain, 'MX')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return result.error('dns-error', domain)

    result.value['dnssec'] = bool(answers.response.flags & dns.flags.AD)

    mxs = {}
    for record in answers:
        mxs[record.exchange.to_text(omit_final_dot=True)] = record.preference

    def mxsortkey(mx):
        name, preference = mx
        parts = name.split('.')
        parts.reverse()
        return preference, parts

    return sorted(mxs.items(), key=mxsortkey)

def checkMailserver(result, mx, preference, policyNames):
    data = MailserverResult(mx, preference, policyNames)

    if not domainPattern.match(mx.lower()):
        data.error = '!invalid-mx'
    elif len(result.value['servers']) > 5:
        data.error = '!skip'
    if data.error:
        result.error('mx-fail')
        return data

    try:
        tlsarrs = resolver.query('_25._tcp.' + mx, 'TLSA')
        data.dnssec_tlsa  = bool(tlsarrs.response.flags & dns.flags.AD)
        for rr in tlsarrs:
            if not isinstance(rr, dns.rdtypes.ANY.TLSA.TLSA):
                continue
            data.tlsa_records.append(rr)
    except dns.exception.DNSException:
        # TODO: report this as a DNS error, not 'TLSA not present'
        pass

    conn = None
    cert = None
    try:

        answers = resolver.query(mx, 'A')
        # TODO: IPv6
        # TODO: try all other IP addresses returned
        data.dnssec_a = bool(answers.response.flags & dns.flags.AD)

        # TODO test MX label validity
        context = ssl.create_default_context()
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        # TODO: send SNI while using an IP address?
        conn = smtplib.SMTP(mx, port=25, timeout=30, local_hostname=SMTP_LOCAL_HOSTNAME)
        conn.starttls(context=context)

        # TODO: ignore expiration date when using DANE, as per RFC7672 section
        # 3.1.1.
        cert_der = conn.sock.getpeercert(True)
        cert_x509 = load_der_x509_certificate(cert_der, default_backend())
        cert_pk = cert_x509.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        data.dane_hash_cert = hashlib.sha256(cert_der).hexdigest()
        data.dane_hash_spki = hashlib.sha256(cert_pk).hexdigest()
    except dns.resolver.NXDOMAIN:
        data.error = '!dns-nxdomain'
    except dns.resolver.NoAnswer:
        data.error = '!dns-noanswer'
    except dns.resolver.Timeout:
        data.error = '!dns-timeout'
    except ssl.SSLError as e:
        data.error = e.reason
    except ssl.CertificateError as e:
        data.error = str(e)
    except (TimeoutError, socket.timeout):
        data.error = '!timeout'
    except smtplib.SMTPException as e:
        data.error = e
    except OSError as e:
        data.error = e.strerror
    finally:
        # try to close the connection
        if conn is not None:
            conn.close()

    if not data.valid:
        result.error('mx-fail')
    return data

# algorithm from Appendix 2 of the draft (function policyMatches)
def policyMatches(candidate, policyNames):
    if policyNames is None:
        return False
    for mx in policyNames:
        if mx == candidate:
            return True
        # Wildcard matches only the leftmost label.
        # Wildcards must always be followed by a '.'.
        if mx[0] == '*':
            parts = candidate.split('.', 1) # Split on the first '.'.
            if len(parts) > 1 and parts[1] == mx[2:]:
                return True
    return False


def renderSummary(report):
    with app.app_context():
        summary = flask.render_template('summary.html', report=report)
    return makeEventSource({'summary': summary, 'close': True})

def renderSubReport(report, reportName, rating):
    with app.app_context():
        html = flask.render_template('result-%s.html' % reportName, report=report)
    return makeEventSource({
        'reportName': reportName,
        'html':       html,
        'verdict':    VERDICT_MAP[rating]})

def makeReport(domain):
    report = Report(domain)

    # See: https://stackoverflow.com/a/106223/559350
    if not domainPattern.match(domain.lower()):
        report.error('invalid-domain', domain)
        yield renderSummary(report)
        return

    checkDNS_STS(report.sts, domain)
    yield renderSubReport(report, 'mta-sts', report.sts.rating)

    checkDNS_TLSRPT(report.tlsrpt, domain)
    yield renderSubReport(report, 'tlsrpt', report.tlsrpt.rating)

    checkPolicyFile(report.policy, domain)
    yield renderSubReport(report, 'policy', report.policy.rating)

    report.mx.value = {'servers': []}
    mailservers = getMX(report.mx, domain)
    if mailservers is not None: # DNS request was successful
        with app.app_context():
            html = flask.render_template('result-dane-mx.html',
                                         verdict='ok' if report.mx.value.get('dnssec') else 'fail',
                                         domain=domain)
        yield makeEventSource({
            'reportName': 'dane',
            'part':       html})

        policyNames = report.policy.value.get('info', {}).get('mx', None)
        yield renderSubReport(report, 'mx', None)
        for mx, preference in mailservers:
            serverResult = checkMailserver(report.mx, mx, preference, policyNames)
            report.mx.value['servers'].append(serverResult)

            with app.app_context():
                html = flask.render_template('result-dane-server.html',
                                             mx=serverResult)
            yield makeEventSource({
                'reportName': 'dane',
                'part':       html})

            with app.app_context():
                html = flask.render_template('result-mx-server.html', server=serverResult)
            yield makeEventSource({
                'reportName': 'mx',
                'part':       html})

        yield makeEventSource({
            'reportName': 'dane',
            'verdict': report.verdictDANE})

        yield makeEventSource({
            'reportName': 'mx',
            'verdict': VERDICT_MAP[report.mx.rating]})
    else:
        yield renderSubReport(report, 'mx', report.mx.rating)

    yield renderSummary(report)

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
    if not domain:
        return 'No domain given.'

    response = flask.Response(makeReport(domain), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    # Disable buffering - required for EventSource.
    # See: http://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_buffering
    response.headers['X-Accel-Buffering'] = 'no'
    return response

def makeEventSource(data):
    return 'data: ' + json.dumps(data).replace('\n', '\ndata: ') + '\n\n'


def main():
    if len(sys.argv) < 2:
        app.run(debug=True)
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
