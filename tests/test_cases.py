from pathlib import Path
import tempfile
import unittest
from triage.analyzer import analyze
from triage.cases import CaseStore, Conflict

RAW = (Path(__file__).resolve().parents[1] / 'samples' / 'credential-phishing.eml').read_bytes()


class CaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'cases.sqlite3'
        self.store = CaseStore(self.path)
        self.case = self.store.create(analyze(RAW), {'alert_id':'ALERT-001', 'assignee':'Analyst'})

    def tearDown(self):
        self.temp.cleanup()

    def change(self, action='save', **fields):
        self.case = self.store.update(self.case['id'], {'revision':self.case['revision'], 'action':action, 'fields':fields})
        return self.case

    def reach_artifacts(self):
        self.change('advance')
        self.change('advance', category='Credential phishing', notes='User reported a credential request.', priority='High')

    def reach_related(self):
        self.reach_artifacts()
        self.change('advance', sender_status='Inconclusive', sender_source='Offline headers only', sender_notes='No live reputation lookup available.', attachment_status='No attachments', attachment_notes='No attachments in MIME inventory.')

    def test_complete_five_stage_workflow(self):
        self.reach_related()
        self.change('advance', reviewed=True, notes='Checked locally saved alerts; no SIEM access.')
        self.change('complete', disposition='Escalate — suspected phishing', notes='Escalate deceptive link and credential lure for investigation.')
        self.assertEqual(self.case['status'], 'Completed')
        self.assertEqual(self.case['stage'], 5)
        self.assertEqual([h['stage'] for h in self.case['history']], [1, 1, 2, 3, 4, 5])
        self.assertEqual(CaseStore(self.path).get(self.case['id']), self.case)
        with self.assertRaisesRegex(ValueError, 'read-only'):
            self.change(notes='overwrite')

    def test_assignment_required(self):
        with self.assertRaises(ValueError):
            self.store.create(analyze(RAW), {'alert_id':'', 'assignee':'Analyst'})

    def test_cannot_complete_early(self):
        with self.assertRaisesRegex(ValueError, 'five stages'):
            self.change('complete')
        self.assertEqual(self.store.get(self.case['id'])['revision'], 1)

    def test_triage_gate_and_client_cannot_skip_stage(self):
        case = self.store.update(self.case['id'], {'revision':1, 'stage':5, 'status':'Completed'})
        self.assertEqual(case['stage'], 1)
        self.assertEqual(case['status'], 'Open')
        self.case = case
        self.change('advance')
        with self.assertRaisesRegex(ValueError, 'triage category'):
            self.change('advance')

    def test_both_artifact_reviews_required(self):
        self.reach_artifacts()
        with self.assertRaisesRegex(ValueError, 'sender assessment'):
            self.change('advance')
        with self.assertRaisesRegex(ValueError, 'No attachments'):
            self.change('advance', sender_status='Suspicious', sender_source='Training gateway', sender_notes='Unverified claims', attachment_status='Reviewed', attachment_notes='incorrect status')

    def test_real_attachment_cannot_be_marked_absent(self):
        raw = (Path(__file__).resolve().parents[1] / 'samples' / 'invoice-attachment.eml').read_bytes()
        self.case = self.store.create(analyze(raw), {'alert_id':'INV-1', 'assignee':'Analyst'})
        self.reach_artifacts()
        with self.assertRaisesRegex(ValueError, 'Reviewed'):
            self.change('advance', sender_status='Inconclusive', sender_source='Offline', sender_notes='Needs validation', attachment_status='No attachments', attachment_notes='not acceptable')

    def test_related_review_requires_notes_and_confirmation(self):
        self.reach_related()
        with self.assertRaisesRegex(ValueError, 'related-alert review'):
            self.change('advance', notes='Investigated locally')
        with self.assertRaisesRegex(ValueError, 'true or false'):
            self.change(reviewed='yes')

    def test_final_disposition_required(self):
        self.reach_related()
        self.change('advance', reviewed=True, notes='No local matches.')
        with self.assertRaisesRegex(ValueError, 'final disposition'):
            self.change('complete', notes='Unfinished')

    def test_stale_version_rejected(self):
        stale = self.case['revision']
        self.change(assignee='Second analyst')
        with self.assertRaises(Conflict):
            self.store.update(self.case['id'], {'revision':stale, 'fields':{'assignee':'Lost update'}})
        self.assertEqual(self.store.get(self.case['id'])['assignee'], 'Second analyst')

    def test_matching_evidence_and_no_self_match(self):
        other = self.store.create(analyze(RAW + b'\nDifferent delivery'), {'alert_id':'ALERT-2', 'assignee':'Analyst'})
        matches = self.store.related(self.case['id'])
        self.assertEqual([m['id'] for m in matches], [other['id']])
        self.assertTrue({'sender', 'URL host'}.issubset({reason['kind'] for reason in matches[0]['reasons']}))
        self.reach_related()
        self.change('advance', reviewed=True, notes='Shared sender and URL host; correlation needs review.')
        self.assertEqual(self.case['related_review']['matches'][0]['id'], other['id'])

    def test_no_false_match_from_empty_indicators(self):
        empty = analyze(b'Subject: Empty indicators\n\nNo URLs')
        one = self.store.create(empty, {'alert_id':'ONE', 'assignee':'A'})
        self.store.create(empty, {'alert_id':'TWO', 'assignee':'A'})
        self.assertEqual(self.store.related(one['id']), [])

    def test_attachment_hash_match(self):
        raw = (Path(__file__).resolve().parents[1] / 'samples' / 'invoice-attachment.eml').read_bytes()
        first = self.store.create(analyze(raw), {'alert_id':'INV-1', 'assignee':'A'})
        second_analysis = analyze(raw)
        second_analysis['from'] = 'Different <other@example.org>'
        second = self.store.create(second_analysis, {'alert_id':'INV-2', 'assignee':'A'})
        matches = self.store.related(first['id'])
        self.assertEqual(matches[0]['id'], second['id'])
        self.assertEqual(matches[0]['reasons'][0]['kind'], 'attachment SHA-256')

    def test_persistence_excludes_raw_payload(self):
        self.assertNotIn('email_base64', self.case)
        self.assertNotIn('raw', self.case)
        self.assertEqual(self.case['analysis']['email_sha256'], analyze(RAW)['email_sha256'])
        self.assertEqual(len(self.store.list()), 1)

    def test_unknown_case(self):
        with self.assertRaises(KeyError):
            self.store.get('CASE-UNKNOWN')


if __name__ == '__main__':
    unittest.main()
