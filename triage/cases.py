"""Local case records and the diagram's five-stage investigation workflow."""
from datetime import datetime, timezone
from email.utils import parseaddr
from pathlib import Path
import json
import sqlite3
from uuid import uuid4

STAGES = ['Assign alert', 'Alert triaging process', 'Analyze email artifacts',
          'Investigate related alerts', 'Case reporting']
PRIORITIES = ('Low', 'Medium', 'High', 'Critical')
DISPOSITIONS = ('Needs investigation', 'Escalate — suspected phishing',
                'Suspicious — monitor', 'Benign — verified')


class Conflict(ValueError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


def text(value, label, maximum=6000, required=False):
    if not isinstance(value, str) or len(value) > maximum:
        raise ValueError(f'{label} must be text of at most {maximum} characters.')
    value = value.strip()
    if required and not value:
        raise ValueError(f'{label} is required.')
    return value


def choice(value, allowed, label):
    if value not in allowed:
        raise ValueError(f'Invalid {label}.')
    return value


class CaseStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, revision INTEGER NOT NULL, updated TEXT NOT NULL, document TEXT NOT NULL)')
        self.path.chmod(0o600)

    def connect(self):
        return sqlite3.connect(self.path, timeout=5)

    def get(self, case_id):
        with self.connect() as db:
            row = db.execute('SELECT document FROM cases WHERE id = ?', (case_id,)).fetchone()
        if row is None:
            raise KeyError('Case not found.')
        return json.loads(row[0])

    def list(self):
        with self.connect() as db:
            rows = db.execute('SELECT document FROM cases ORDER BY updated DESC LIMIT 200').fetchall()
        return [self.summary(json.loads(row[0])) for row in rows]

    @staticmethod
    def summary(case):
        return {key: case[key] for key in ('id', 'alert_id', 'assignee', 'stage', 'status', 'updated_at', 'revision')} | {
            'subject': case['analysis']['subject'], 'priority': case['triage']['priority']}

    def create(self, analysis, data):
        timestamp = now()
        case = {
            'schema_version': 1, 'id': 'CASE-' + uuid4().hex[:16].upper(),
            'alert_id': text(data.get('alert_id', ''), 'Alert reference', 200, True),
            'assignee': text(data.get('assignee', ''), 'Assigned analyst', 120, True),
            'stage': 1, 'status': 'Open', 'revision': 1,
            'created_at': timestamp, 'updated_at': timestamp, 'analysis': analysis,
            'triage': {'priority': analysis['risk'], 'category': 'Unclassified', 'notes': ''},
            'sender_review': {'status': 'Pending', 'source': '', 'notes': ''},
            'attachment_review': {'status': 'Pending', 'notes': ''},
            'related_review': {'reviewed': False, 'notes': '', 'references': '', 'matches': [], 'checked_at': None},
            'report': {'disposition': 'Needs investigation', 'notes': ''},
            'history': [{'at': timestamp, 'actor': text(data.get('assignee', ''), 'Assigned analyst', 120, True), 'action': 'Assigned alert', 'stage': 1}]
        }
        with self.connect() as db:
            db.execute('INSERT INTO cases VALUES (?, ?, ?, ?)', (case['id'], 1, timestamp, json.dumps(case)))
        return case

    def update(self, case_id, data):
        case = self.get(case_id)
        if type(data.get('revision')) is not int or data['revision'] != case['revision']:
            raise Conflict('This case changed in another tab. Reload the saved case before editing.')
        if case['status'] == 'Completed':
            raise ValueError('Completed cases are read-only. Create a new alert for follow-up work.')
        action = choice(data.get('action', 'save'), ('save', 'advance', 'complete'), 'action')
        fields = data.get('fields', {})
        if not isinstance(fields, dict):
            raise ValueError('Case fields must be an object.')
        stage = case['stage']
        # Update only the current stage. The client cannot skip or rewrite completed stages.
        if stage == 1:
            case['assignee'] = text(fields.get('assignee', case['assignee']), 'Assigned analyst', 120, True)
            case['alert_id'] = text(fields.get('alert_id', case['alert_id']), 'Alert reference', 200, True)
        elif stage == 2:
            old = case['triage']
            case['triage'] = {
                'priority': choice(fields.get('priority', old['priority']), PRIORITIES, 'priority'),
                'category': choice(fields.get('category', old['category']), ('Unclassified', 'Credential phishing', 'Suspicious attachment', 'Business email compromise', 'Spam', 'Other'), 'category'),
                'notes': text(fields.get('notes', old['notes']), 'Triage notes')}
        elif stage == 3:
            sender, attachments = case['sender_review'], case['attachment_review']
            case['sender_review'] = {
                'status': choice(fields.get('sender_status', sender['status']), ('Pending', 'Suspicious', 'No adverse evidence found', 'Inconclusive'), 'sender review'),
                'source': text(fields.get('sender_source', sender['source']), 'Reputation evidence source', 1000),
                'notes': text(fields.get('sender_notes', sender['notes']), 'Sender review notes')}
            case['attachment_review'] = {
                'status': choice(fields.get('attachment_status', attachments['status']), ('Pending', 'Reviewed', 'No attachments'), 'attachment review'),
                'notes': text(fields.get('attachment_notes', attachments['notes']), 'Attachment review notes')}
        elif stage == 4:
            old = case['related_review']
            reviewed = fields.get('reviewed', old['reviewed'])
            if type(reviewed) is not bool:
                raise ValueError('Related-alert review must be true or false.')
            case['related_review'] = {
                'reviewed': reviewed, 'notes': text(fields.get('notes', old['notes']), 'Related-alert notes'),
                'references': text(fields.get('references', old['references']), 'External alert references', 2000),
                'matches': self.related(case_id), 'checked_at': now()}
        elif stage == 5:
            case['report'] = {
                'disposition': choice(fields.get('disposition', case['report']['disposition']), DISPOSITIONS, 'disposition'),
                'notes': text(fields.get('notes', case['report']['notes']), 'Case report')}
        if action == 'advance':
            self.validate_stage(case)
            if stage == 5:
                raise ValueError('Use Complete case at the reporting stage.')
            case['stage'] += 1
        elif action == 'complete':
            if stage != 5:
                raise ValueError('Finish all five stages before completing a case.')
            self.validate_stage(case)
            case['status'] = 'Completed'
        case['revision'] += 1
        case['updated_at'] = now()
        case['history'].append({'at': case['updated_at'], 'actor': case['assignee'], 'action': {'save': 'Saved stage', 'advance': 'Completed stage', 'complete': 'Completed case'}[action], 'stage': stage})
        with self.connect() as db:
            cursor = db.execute('UPDATE cases SET revision = ?, updated = ?, document = ? WHERE id = ? AND revision = ?',
                                (case['revision'], case['updated_at'], json.dumps(case), case_id, data['revision']))
            if cursor.rowcount != 1:
                raise Conflict('This case changed in another tab. Reload the saved case before editing.')
        return case

    @staticmethod
    def validate_stage(case):
        stage = case['stage']
        if stage == 2 and (case['triage']['category'] == 'Unclassified' or not case['triage']['notes']):
            raise ValueError('Choose a triage category and document the initial assessment.')
        if stage == 3:
            sender, attachments = case['sender_review'], case['attachment_review']
            if sender['status'] == 'Pending' or not sender['source'] or not sender['notes']:
                raise ValueError('Record a sender assessment, evidence source and reasoning. Use Inconclusive if verification is unavailable.')
            expected = 'Reviewed' if case['analysis']['attachments'] else 'No attachments'
            if attachments['status'] != expected or not attachments['notes']:
                raise ValueError(f'Attachment review must be "{expected}" with supporting notes.')
        if stage == 4 and (not case['related_review']['reviewed'] or not case['related_review']['notes']):
            raise ValueError('Confirm the related-alert review and record its scope and findings.')
        if stage == 5 and (case['report']['disposition'] == 'Needs investigation' or not case['report']['notes']):
            raise ValueError('Select a final disposition and document the evidence, actions and handoff.')

    @staticmethod
    def indicators(analysis):
        sender = parseaddr(analysis['from'])[1].lower()
        return {'sender': {sender} if sender else set(),
                'URL host': {url['host'] for url in analysis['urls'] if url['host']},
                'attachment SHA-256': {a['sha256'] for a in analysis['attachments'] if a['sha256']}}

    def related(self, case_id):
        target = self.get(case_id)
        indicators = self.indicators(target['analysis'])
        with self.connect() as db:
            rows = db.execute('SELECT document FROM cases WHERE id != ? ORDER BY updated DESC', (case_id,)).fetchall()
        matches = []
        for row in rows:
            other = json.loads(row[0])
            other_indicators = self.indicators(other['analysis'])
            reasons = [{'kind': kind, 'value': value} for kind in indicators for value in sorted(indicators[kind] & other_indicators[kind])]
            if reasons:
                matches.append(self.summary(other) | {'reasons': reasons})
        return matches
