import http.client
import json
import tempfile
import base64
from pathlib import Path
from triage.cases import CaseStore
import threading
import unittest
from http.server import ThreadingHTTPServer
from app import Handler


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.server.case_store = CaseStore(Path(cls.temp.name) / 'cases.sqlite3')
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        connection.request(method, path, body, headers or {})
        response = connection.getresponse()
        status, data, headers = response.status, response.read(), dict(response.getheaders())
        connection.close()
        return status, data, headers

    def test_assets_and_security_headers(self):
        for path in ('/', '/app.js', '/workflow.js', '/style.css'):
            status, _, headers = self.request('GET', path)
            self.assertEqual(status, 200)
            self.assertIn("object-src 'none'", headers['Content-Security-Policy'])
            self.assertEqual(headers['Cache-Control'], 'no-store')

    def test_sample_and_analysis(self):
        status, data, _ = self.request('GET', '/api/sample/credential')
        self.assertEqual(status, 200)
        status, data, _ = self.request('POST', '/api/analyze', json.loads(data)['email'].encode(), {'Content-Type': 'application/octet-stream'})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)['risk'], 'High')

    def test_bad_host_rejected(self):
        self.assertEqual(self.request('GET', '/', headers={'Host':'attacker.example'})[0], 403)

    def test_cross_origin_rejected(self):
        self.assertEqual(self.request('POST', '/api/analyze', b'Subject: test\n\nbody', {'Content-Type':'application/octet-stream', 'Origin':'https://other.example'})[0], 403)

    def test_wrong_media_type(self):
        self.assertEqual(self.request('POST', '/api/analyze', b'hello', {'Content-Type':'text/plain'})[0], 415)

    def test_empty_body(self):
        self.assertEqual(self.request('POST', '/api/analyze', b'', {'Content-Type':'application/octet-stream'})[0], 413)

    def test_bad_email(self):
        self.assertEqual(self.request('POST', '/api/analyze', b'garbage', {'Content-Type':'application/octet-stream'})[0], 400)

    def test_no_path_traversal(self):
        self.assertEqual(self.request('GET', '/../app.py')[0], 404)

    def test_case_api_lifecycle_and_conflict(self):
        headers = {'Content-Type':'application/json'}
        payload = {'email_base64':base64.b64encode(b'Subject: Case test\n\nHello').decode(), 'alert_id':'API-1', 'assignee':'Analyst'}
        status, data, _ = self.request('POST', '/api/cases', json.dumps(payload), headers)
        self.assertEqual(status, 201)
        case = json.loads(data)
        self.assertEqual(self.request('GET', '/api/cases/' + case['id'])[0], 200)
        self.assertEqual(self.request('GET', '/api/cases/' + case['id'] + '/related')[0], 200)
        update = json.dumps({'revision':1, 'action':'advance'})
        self.assertEqual(self.request('POST', '/api/cases/' + case['id'], update, headers)[0], 200)
        self.assertEqual(self.request('POST', '/api/cases/' + case['id'], update, headers)[0], 409)
        self.assertEqual(self.request('GET', '/api/cases')[0], 200)

    def test_case_json_and_encoding_validation(self):
        for payload in ('[]', '{broken', '{"email_base64":"!!!"}'):
            self.assertEqual(self.request('POST', '/api/cases', payload, {'Content-Type':'application/json'})[0], 400)

    def test_case_api_not_found(self):
        self.assertEqual(self.request('GET', '/api/cases/CASE-0000000000000000')[0], 404)


if __name__ == '__main__':
    unittest.main()
