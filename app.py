"""Local-only, dependency-free triage HTTP service."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
from triage.analyzer import analyze, MAX_BYTES

ROOT = Path(__file__).resolve().parent
ASSETS = {'/': ('index.html', 'text/html'), '/app.js': ('app.js', 'text/javascript'), '/style.css': ('style.css', 'text/css')}
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

    def do_GET(self):
        if not self.valid_host():
            return self.reply(403, {'error': 'Local access only.'})
        if self.path in ASSETS:
            name, kind = ASSETS[self.path]
            return self.reply(200, (ROOT / 'web' / name).read_bytes(), kind)
        if self.path.startswith('/api/sample/') and self.path.rsplit('/', 1)[-1] in SAMPLES:
            return self.reply(200, {'email': (ROOT / 'samples' / SAMPLES[self.path.rsplit('/', 1)[-1]]).read_text()})
        return self.reply(404, {'error': 'Not found.'})

    def do_POST(self):
        if not self.valid_host():
            return self.reply(403, {'error': 'Local access only.'})
        origin = self.headers.get('Origin')
        if origin and origin not in (f'http://localhost:{self.server.server_port}', f'http://127.0.0.1:{self.server.server_port}'):
            return self.reply(403, {'error': 'Cross-origin requests are not allowed.'})
        if self.path != '/api/analyze':
            return self.reply(404, {'error': 'Not found.'})
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/octet-stream':
            return self.reply(415, {'error': 'Send raw email bytes as application/octet-stream.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= MAX_BYTES:
                return self.reply(413, {'error': 'Provide an email between 1 byte and 2 MiB.'})
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError('Incomplete email upload.')
            return self.reply(200, analyze(raw))
        except (ValueError, TypeError, RecursionError):
            return self.reply(400, {'error': 'Unable to parse this email. Check its headers and MIME structure.'})


if __name__ == '__main__':
    print('Email Phishing Triage Console → http://127.0.0.1:8765  (Ctrl+C to stop)')
    server = ThreadingHTTPServer(('127.0.0.1', 8765), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
