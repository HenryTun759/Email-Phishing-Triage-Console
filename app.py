"""Local-only, dependency-free triage HTTP service."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import base64
import binascii
import re
import sqlite3
from triage.cases import CaseStore, Conflict
from triage.analyzer import analyze, MAX_BYTES

ROOT = Path(__file__).resolve().parent
ASSETS = {'/': ('index.html', 'text/html'), '/app.js': ('app.js', 'text/javascript'), '/workflow.js': ('workflow.js', 'text/javascript'), '/style.css': ('style.css', 'text/css')}
CASE_ROUTE = re.compile(r'^/api/cases/(CASE-[A-F0-9]{16})(/related)?$')
SAMPLES = {'credential': 'credential-phishing.eml', 'invoice': 'invoice-attachment.eml', 'routine': 'routine-update.eml'}


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_):
        pass  # Do not log email data or request paths.

    def reply(self, status, data, kind='application/json'):
        payload = json.dumps(data).encode() if kind == 'application/json' else data
        self.send_response(status)
        self.send_header('Content-Type', kind + '; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(payload)

    def valid_host(self):
        port = self.server.server_port
        return self.headers.get('Host') in (f'127.0.0.1:{port}', f'localhost:{port}')

    @property
    def cases(self):
        return self.server.case_store

    def do_GET(self):
        if not self.valid_host():
            return self.reply(403, {'error': 'Local access only.'})
        if self.path in ASSETS:
            name, kind = ASSETS[self.path]
            return self.reply(200, (ROOT / 'web' / name).read_bytes(), kind)
        if self.path.startswith('/api/sample/') and self.path.rsplit('/', 1)[-1] in SAMPLES:
            return self.reply(200, {'email': (ROOT / 'samples' / SAMPLES[self.path.rsplit('/', 1)[-1]]).read_text()})
        if self.path == '/api/cases':
            return self.reply(200, {'cases': self.cases.list()})
        match = CASE_ROUTE.fullmatch(self.path)
        if match:
            try:
                result = {'matches': self.cases.related(match[1])} if match[2] else self.cases.get(match[1])
                return self.reply(200, result)
            except KeyError:
                return self.reply(404, {'error': 'Case not found.'})
        return self.reply(404, {'error': 'Not found.'})

    def do_POST(self):
        if not self.valid_host():
            return self.reply(403, {'error': 'Local access only.'})
        origin = self.headers.get('Origin')
        if origin and origin not in (f'http://localhost:{self.server.server_port}', f'http://127.0.0.1:{self.server.server_port}'):
            return self.reply(403, {'error': 'Cross-origin requests are not allowed.'})
        match = CASE_ROUTE.fullmatch(self.path)
        is_case = self.path == '/api/cases' or (match and not match[2])
        if self.path != '/api/analyze' and not is_case:
            return self.reply(404, {'error': 'Not found.'})
        expected_type = 'application/json' if is_case else 'application/octet-stream'
        if self.headers.get('Content-Type', '').split(';')[0] != expected_type:
            return self.reply(415, {'error': f'Send the request as {expected_type}.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            limit = 3 * MAX_BYTES // 2 if is_case else MAX_BYTES
            if not 0 < length <= limit:
                return self.reply(413, {'error': 'Request is empty or too large. Email limit: 2 MiB.'})
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError('Incomplete request.')
            if not is_case:
                return self.reply(200, analyze(raw))
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError('Send a JSON object.')
            if self.path == '/api/cases':
                encoded = data.get('email_base64')
                if not isinstance(encoded, str):
                    raise ValueError('Provide the original email bytes.')
                email = base64.b64decode(encoded, validate=True)
                return self.reply(201, self.cases.create(analyze(email), data))
            return self.reply(200, self.cases.update(match[1], data))
        except Conflict as error:
            return self.reply(409, {'error': str(error)})
        except KeyError:
            return self.reply(404, {'error': 'Case not found.'})
        except (ValueError, TypeError, RecursionError, binascii.Error) as error:
            return self.reply(400, {'error': str(error) if is_case and isinstance(error, ValueError) else 'Unable to parse this email. Check its headers and MIME structure.'})
        except sqlite3.Error:
            return self.reply(503, {'error': 'Case storage is unavailable. Retry after checking local disk access.'})


if __name__ == '__main__':
    print('Email Phishing Triage Console → http://127.0.0.1:8765  (Ctrl+C to stop)')
    server = ThreadingHTTPServer(('127.0.0.1', 8765), Handler)
    server.case_store = CaseStore(ROOT / 'data' / 'cases.sqlite3')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
