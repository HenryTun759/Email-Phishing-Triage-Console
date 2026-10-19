"""Offline, explainable email triage. Never retrieves indicators or runs attachments."""
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from hashlib import sha256
from html.parser import HTMLParser
from urllib.parse import urlsplit
from datetime import datetime, timezone
import ipaddress
import re

MAX_BYTES = 2 * 1024 * 1024
URL_RE = re.compile(r'https?://[^\s<>"\x27]+', re.I)
RISKY_EXTENSIONS = {'.exe', '.scr', '.js', '.vbs', '.hta', '.bat', '.cmd', '.ps1', '.lnk', '.iso', '.img', '.docm', '.xlsm'}


def defang(value):
    return re.sub(r'^http', 'hxxp', str(value), flags=re.I).replace('.', '[.]').replace('@', '[@]')


def hostname(value):
    try:
        return (urlsplit(value).hostname or '').lower().rstrip('.')
    except ValueError:
        return ''


def domain(address):
    return parseaddr(str(address))[1].rsplit('@', 1)[-1].lower() if '@' in str(address) else ''


class HTMLText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.links, self.active, self.hidden = [], [], None, 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.hidden += 1
        if tag == 'a':
            self.active = [dict(attrs).get('href', ''), '']

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self.hidden = max(0, self.hidden - 1)
        if tag == 'a' and self.active:
            self.links.append(self.active)
            self.active = None

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)
            if self.active:
                self.active[1] += data


def analyze(raw):
    if not isinstance(raw, bytes) or not raw.strip():
        raise ValueError('Provide a non-empty RFC 5322 email or .eml file.')
    if len(raw) > MAX_BYTES:
        raise ValueError('Email exceeds the 2 MiB limit.')
    message = BytesParser(policy=policy.default).parsebytes(raw)
    if not any(message.get(key) for key in ('From', 'To', 'Subject', 'Date')):
        raise ValueError('No recognizable email headers found. Include From, To, or Subject.')
    findings, bodies, links, attachments, defects = [], [], [], [], []

    def add(rule, points, title, evidence):
        if not any(f['rule'] == rule for f in findings):
            findings.append(dict(rule=rule, points=points, title=title, evidence=evidence))

    def parts(node):
        yield node
        # Attached emails are evidence containers, not the outer message body.
        if node.is_multipart() and not node.get_filename() and node.get_content_disposition() != 'attachment':
            for child in node.iter_parts():
                yield from parts(child)

    for part in parts(message):
        defects.extend(type(d).__name__ for d in part.defects)
        name = part.get_filename()
        if name or part.get_content_disposition() == 'attachment':
            payload = part.get_payload(decode=True) or b''
            attachments.append({'name': name or '(unnamed)', 'type': part.get_content_type(), 'bytes': len(payload), 'sha256': sha256(payload).hexdigest() if not part.is_multipart() else None})
            if name and any(name.lower().endswith(ext) for ext in RISKY_EXTENSIONS):
                add('ATTACHMENT_RISK', 25, 'Potentially executable or active attachment', name)
            if name and re.search(r'\.(?:pdf|docx?|xlsx?|jpg|png)\.[^.]+$', name, re.I):
                add('DOUBLE_EXTENSION', 15, 'Attachment uses a double extension', name)
            continue
        if part.is_multipart():
            continue
        if part.get_content_type() in ('text/plain', 'text/html'):
            payload = part.get_payload(decode=True) or b''
            try:
                body = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
            except LookupError:
                body = payload.decode('utf-8', errors='replace')
            if part.get_content_type() == 'text/html':
                parser = HTMLText()
                parser.feed(body)
                bodies.append(' '.join(parser.text))
                links.extend(parser.links)
            else:
                bodies.append(body)
    body = '\n\n'.join(bodies)
    urls = sorted(set(URL_RE.findall(body) + [href for href, _ in links if href.lower().startswith(('http://', 'https://'))]))
    urls = [u.rstrip('.,);') for u in urls]
    for href, label in links:
        if URL_RE.match(label.strip()) and hostname(href) and hostname(label.strip()) != hostname(href):
            add('LINK_MISMATCH', 25, 'Visible link and destination hosts differ', f'{defang(label.strip())} → {defang(href)}')
    for url in urls:
        host = hostname(url)
        try:
            ipaddress.ip_address(host)
            add('IP_URL', 15, 'Link points directly to an IP address', defang(url))
        except ValueError:
            pass
        if 'xn--' in host:
            add('PUNYCODE', 10, 'Internationalized hostname needs review', defang(host))
        try:
            if urlsplit(url).username:
                add('URL_USERINFO', 15, 'URL contains a misleading user-information section', defang(url))
        except ValueError:
            add('MALFORMED_URL', 5, 'Malformed URL', defang(url))
    sender = str(message.get('From', ''))
    reply = str(message.get('Reply-To', ''))
    if reply and domain(sender) and domain(reply) and domain(sender) != domain(reply):
        add('REPLY_TO', 15, 'Reply-To domain differs from sender', f'{defang(domain(sender))} → {defang(domain(reply))}')
    auth_headers = [str(x) for x in message.get_all('Authentication-Results', [])]
    auth = {key: sorted(set(re.findall(r'\b' + key + r'\s*=\s*([a-z]+)', '\n'.join(auth_headers), re.I))) for key in ('spf', 'dkim', 'dmarc')}
    auth = {key: [value.lower() for value in values] for key, values in auth.items()}
    for key, points in [('spf', 10), ('dkim', 10), ('dmarc', 20)]:
        if any(value in ('fail', 'softfail', 'permerror') for value in auth[key]):
            add('AUTH_' + key.upper(), points, f'Reported {key.upper()} failure', 'Unverified header claim: ' + ', '.join(auth[key]))
    subject = str(message.get('Subject', '(no subject)'))
    combined = subject + '\n' + body
    if re.search(r'urgent|immediately|suspend(?:ed)?|within \d+ hours|final warning', combined, re.I):
        add('URGENCY', 10, 'Urgency or account-pressure language', 'Message contains urgency/account-pressure terms; context is required.')
    if re.search(r'verify (?:your )?(?:account|password)|confirm (?:your )?password|sign in|log in|login', combined, re.I) and urls:
        add('CREDENTIALS', 15, 'Sign-in request with an external link', 'Credential-related wording appears alongside at least one URL.')
    if defects:
        add('PARSER_DEFECT', 0, 'Email parsing anomalies', ', '.join(sorted(set(defects))))
    score = min(100, sum(f['points'] for f in findings))
    level = 'High' if score >= 50 else 'Medium' if score >= 20 else 'Low'
    digest = sha256(raw).hexdigest()
    return {
        'schema_version': 1, 'case_id': 'PH-' + digest[:10].upper(),
        'analyzed_at': datetime.now(timezone.utc).isoformat(),
        'email_sha256': digest, 'size_bytes': len(raw),
        'subject': subject, 'from': sender, 'to': str(message.get('To', '')),
        'reply_to': reply, 'date': str(message.get('Date', '')), 'message_id': str(message.get('Message-ID', '')),
        'received': [str(v) for v in message.get_all('Received', [])],
        'authentication': auth, 'authentication_headers': auth_headers,
        'score': score, 'risk': level, 'findings': findings,
        'urls': [{'value': defang(u), 'host': defang(hostname(u))} for u in sorted(set(urls))],
        'attachments': attachments, 'body_preview': defang(body[:18000]),
        'limitations': ['Heuristic score is a review priority, not a probability or verdict.', 'Authentication-Results are untrusted claims until validated against a trusted receiving gateway.', 'No DNS, reputation, sandbox, antivirus, or live SPF/DKIM/DMARC checks are performed.', 'Low risk does not mean safe. Subdomain relationships and brand ownership are not verified.'],
        'next_steps': ['Validate sender and authentication using trusted mail-gateway logs.', 'Review indicators in approved security tooling; do not open email links or attachments.', 'Check recipient exposure and related messages, then record your disposition.', 'Escalate suspected compromise under your incident-response procedure.']
    }
