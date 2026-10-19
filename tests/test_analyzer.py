import hashlib
from pathlib import Path
import unittest
from triage.analyzer import analyze, MAX_BYTES, defang

SAMPLES = Path(__file__).resolve().parents[1] / 'samples'


class AnalyzerTests(unittest.TestCase):
    def test_credential_case(self):
        result = analyze((SAMPLES / 'credential-phishing.eml').read_bytes())
        self.assertEqual(result['risk'], 'High')
        self.assertEqual(result['score'], 100)
        self.assertIn('LINK_MISMATCH', {f['rule'] for f in result['findings']})
        self.assertEqual(len(result['urls']), 2)

    def test_routine_not_certified_safe(self):
        result = analyze((SAMPLES / 'routine-update.eml').read_bytes())
        self.assertEqual(result['score'], 0)
        self.assertEqual(result['risk'], 'Low')
        self.assertIn('Low risk does not mean safe', ' '.join(result['limitations']))

    def test_attachment_bytes_hash_and_rules(self):
        result = analyze((SAMPLES / 'invoice-attachment.eml').read_bytes())
        expected = b'Synthetic training attachment. No executable code.\n'
        self.assertEqual(result['attachments'][0]['sha256'], hashlib.sha256(expected).hexdigest())
        self.assertEqual(result['score'], 55)
        self.assertEqual(result['attachments'][0]['bytes'], len(expected))

    def test_case_identity_uses_original_bytes(self):
        raw = b'From: a@example.org\r\nSubject: Test\r\n\r\nHello\r\n'
        self.assertEqual(analyze(raw)['email_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(analyze(raw)['case_id'], analyze(raw)['case_id'])

    def test_input_rejected(self):
        for raw in (b'', b'not an email', b'x' * (MAX_BYTES + 1)):
            with self.subTest(raw_size=len(raw)), self.assertRaises(ValueError):
                analyze(raw)

    def test_html_is_extracted_not_rendered(self):
        raw = b'Subject: HTML\nContent-Type: text/html\n\n<script>alert(1)</script><p>Hello</p><img src="https://tracker.example/pixel">'
        result = analyze(raw)
        self.assertNotIn('alert', result['body_preview'])
        self.assertIn('Hello', result['body_preview'])
        self.assertEqual(result['urls'], [])

    def test_unknown_charset_fallback(self):
        self.assertIn('hello', analyze(b'Subject: Test\nContent-Type: text/plain; charset=no-such-charset\n\nhello')['body_preview'])

    def test_base64_body(self):
        result = analyze(b'Subject: Test\nContent-Transfer-Encoding: base64\n\naGVsbG8=')
        self.assertEqual(result['body_preview'], 'hello')

    def test_ip_and_userinfo(self):
        result = analyze(b'Subject: Test\n\nhttps://trusted.example@192.0.2.1/login')
        rules = {f['rule'] for f in result['findings']}
        self.assertTrue({'IP_URL', 'URL_USERINFO'}.issubset(rules))

    def test_repeated_rule_does_not_inflate_score(self):
        result = analyze(b'Subject: Test\n\nhttp://192.0.2.1/a http://192.0.2.2/b')
        self.assertEqual(result['score'], 15)

    def test_multiple_auth_headers_retained(self):
        result = analyze(b'Subject: Test\nAuthentication-Results: one; SPF=PASS\nAuthentication-Results: two; spf=fail\n\nhello')
        self.assertIn('fail', result['authentication']['spf'])
        self.assertEqual(len(result['authentication_headers']), 2)
        self.assertEqual(result['score'], 10)

    def test_defanging(self):
        self.assertEqual(defang('https://example.org'), 'hxxps://example[.]org')


if __name__ == '__main__':
    unittest.main()
