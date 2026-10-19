'use strict';
const stageNames = ['Assign alert', 'Alert triaging process', 'Analyze email artifacts', 'Investigate related alerts', 'Case reporting'];
let currentCase = null;
let caseBusy = false;

function resetWorkflow() {
  currentCase = null;
  $('saved-cases').value = '';
  $('workflow-message').textContent = '';
  $('workflow-error').textContent = '';
  $('notes').disabled = false;
  $('disposition').disabled = false;
  renderWorkflow();
}
function field(id, label, value = '', options = null, multiline = false) {
  const wrap = el('div', undefined, 'workflow-field');
  const title = el('label', label, 'field-label'); title.htmlFor = id;
  const input = el(options ? 'select' : multiline ? 'textarea' : 'input'); input.id = id;
  if (options) options.forEach(option => { const node = el('option', option); node.value = option; input.append(node); });
  else if (!multiline) input.type = 'text';
  input.value = value; input.maxLength = multiline ? 6000 : id === 'case-owner' ? 120 : id === 'alert-reference' ? 200 : 1000;
  wrap.append(title, input); return wrap;
}
function group(...fields) { const node = el('div', undefined, 'workflow-grid'); node.append(...fields); return node; }
function renderWorkflow() {
  const record = currentCase, stage = record ? record.stage : 1;
  const completed = record && record.status === 'Completed';
  const steps = $('workflow-steps'); steps.replaceChildren();
  stageNames.forEach((name, index) => {
    const node = el('li'); node.dataset.state = completed || index + 1 < stage ? 'done' : index + 1 === stage ? 'active' : 'pending';
    if (index + 1 === stage) node.setAttribute('aria-current', 'step');
    node.append(el('span', node.dataset.state === 'done' ? '✓' : String(index + 1), 'stage-number'), el('span', name)); steps.append(node);
  });
  const form = $('workflow-form'); form.replaceChildren();
  if (record) form.append(el('p', `${record.id} · Alert ${record.alert_id} · Assigned to ${record.assignee} · ${record.status}`, 'case-meta'));
  if (completed) {
    form.append(el('h3', 'Case complete'), el('p', 'All five stages are documented. The saved case is read-only and ready to export.'));
  } else if (stage === 1) {
    form.append(group(field('alert-reference', 'ALERT REFERENCE', record ? record.alert_id : ''), field('case-owner', 'ASSIGNED ANALYST', record ? record.assignee : '')));
    form.append(el('p', record ? 'Confirm ownership, then continue to initial triage.' : 'Analyze an email below, enter an alert reference and analyst, then save the assigned case.', 'hint'));
  } else if (stage === 2) {
    form.append(group(field('triage-priority', 'ANALYST PRIORITY', record.triage.priority, ['Low', 'Medium', 'High', 'Critical']), field('triage-category', 'ALERT CATEGORY', record.triage.category, ['Unclassified', 'Credential phishing', 'Suspicious attachment', 'Business email compromise', 'Spam', 'Other'])));
    form.append(field('triage-notes', 'INITIAL ASSESSMENT · SCOPE · USER IMPACT', record.triage.notes, null, true));
    form.append(el('p', 'Analyst priority is independent of the automated heuristic score.', 'hint'));
  } else if (stage === 3) {
    form.append(el('h3', '3.1 Check sender reputation'));
    form.append(el('p', 'Review the sender and authentication evidence below. Record an approved reputation tool or trusted log source. No live reputation query is performed here; use Inconclusive when verification is unavailable.', 'hint'));
    form.append(group(field('sender-status', 'SENDER ASSESSMENT', record.sender_review.status, ['Pending', 'Suspicious', 'No adverse evidence found', 'Inconclusive']), field('sender-source', 'EVIDENCE SOURCE / LOOKUP REFERENCE', record.sender_review.source)));
    form.append(field('sender-notes', 'SENDER FINDINGS & LIMITATIONS', record.sender_review.notes, null, true));
    form.append(el('h3', '3.2 Review attachments'));
    form.append(el('p', `${record.analysis.attachments.length} attachment(s) inventoried. Inspect names, types and hashes in Indicators below. Attachments are never executed.`, 'hint'));
    form.append(field('attachment-status', 'ATTACHMENT REVIEW', record.attachment_review.status, ['Pending', 'Reviewed', 'No attachments']));
    form.append(field('attachment-notes', 'ATTACHMENT EVIDENCE & FINDINGS', record.attachment_review.notes, null, true));
  } else if (stage === 4) {
    form.append(el('p', 'Local matches use the exact sender address, URL hostname or attachment SHA-256. Shared infrastructure can create false associations. This searches saved local cases only, not a SIEM or mailbox.', 'hint'));
    const matches = el('div', undefined, 'related-matches'); matches.id = 'related-matches';
    const refresh = el('button', 'Check related local alerts'); refresh.type = 'button'; refresh.id = 'check-related'; refresh.addEventListener('click', loadRelated);
    form.append(refresh, matches);
    form.append(field('related-references', 'EXTERNAL SIEM / TICKET REFERENCES (OPTIONAL)', record.related_review.references));
    form.append(field('related-notes', 'SEARCH SCOPE · CORRELATION FINDINGS · EXPOSURE', record.related_review.notes, null, true));
    const label = el('label', undefined, 'review-check'), checkbox = el('input'); checkbox.type = 'checkbox'; checkbox.id = 'related-reviewed'; checkbox.checked = record.related_review.reviewed;
    label.append(checkbox, document.createTextNode(' I reviewed related alerts and documented the scope and limitations.')); form.append(label);
    showRelated(record.related_review.matches, record.related_review.checked_at);
  } else {
    form.append(el('p', 'Review the evidence below. Enter the final disposition and report in “05 Case reporting”, then save or complete the case. Completed records are read-only.', 'hint'));
  }
  if (record) {
    const history = el('details', undefined, 'case-history'); history.append(el('summary', `Activity history · ${record.history.length} entries`));
    const list = el('ol'); record.history.forEach(item => list.append(el('li', `${item.at} · ${item.actor} · ${item.action} (${item.stage})`))); history.append(list); form.append(history);
    $('notes').value = record.report.notes; $('disposition').value = record.report.disposition;
  }
  $('notes').disabled = Boolean(record && (stage !== 5 || completed));
  $('disposition').disabled = $('notes').disabled;
  $('save-case').textContent = record ? 'Save stage' : 'Save assigned case';
  $('save-case').hidden = Boolean(completed);
  $('save-case').disabled = caseBusy;
  $('advance-case').hidden = !record || Boolean(completed);
  $('advance-case').textContent = stage === 5 ? 'Complete case ✓' : 'Save & continue →';
  $('advance-case').disabled = caseBusy;
}
async function caseRequest(path, data) {
  const response = await fetch(path, data === undefined ? {} : {method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(data)});
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || 'Case request failed.');
  return payload;
}
function caseFields() {
  switch (currentCase.stage) {
    case 1: return {assignee:$('case-owner').value, alert_id:$('alert-reference').value};
    case 2: return {priority:$('triage-priority').value, category:$('triage-category').value, notes:$('triage-notes').value};
    case 3: return {sender_status:$('sender-status').value, sender_source:$('sender-source').value, sender_notes:$('sender-notes').value, attachment_status:$('attachment-status').value, attachment_notes:$('attachment-notes').value};
    case 4: return {reviewed:$('related-reviewed').checked, references:$('related-references').value, notes:$('related-notes').value};
    case 5: return {disposition:$('disposition').value, notes:$('notes').value};
  }
}
function base64Bytes(bytes) { let binary = ''; for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192)); return btoa(binary); }
function lockCase(value) {
  caseBusy = value;
  setBusy(value);
  const reportLocked = value || Boolean(currentCase && (currentCase.stage !== 5 || currentCase.status === 'Completed'));
  $('notes').disabled = reportLocked; $('disposition').disabled = reportLocked;
  document.querySelectorAll('#workflow-form input, #workflow-form select, #workflow-form textarea, #workflow-form button, #save-case, #advance-case, #saved-cases, #refresh-cases').forEach(node => node.disabled = value);
}
async function saveCase(advance = false) {
  if (caseBusy || busy) return;
  $('workflow-error').textContent = '';
  $('workflow-message').textContent = '';
  try {
    let path, data;
    if (!currentCase) {
      if (!result) throw new Error('Analyze an email first, then assign it to a case.');
      const bytes = uploaded ? new Uint8Array(uploaded) : new TextEncoder().encode($('raw-email').value);
      path = '/api/cases'; data = {email_base64:base64Bytes(bytes), alert_id:$('alert-reference').value, assignee:$('case-owner').value};
    } else {
      path = `/api/cases/${currentCase.id}`;
      data = {revision:currentCase.revision, action:advance ? (currentCase.stage === 5 ? 'complete' : 'advance') : 'save', fields:caseFields()};
    }
    lockCase(true);
    currentCase = await caseRequest(path, data);
    result = currentCase.analysis;
    renderWorkflow();
    await refreshCases();
    $('workflow-message').textContent = currentCase.status === 'Completed' ? 'Case complete. Export your saved report below.' : `Saved locally · Stage ${currentCase.stage}: ${stageNames[currentCase.stage - 1]}`;
  } catch (error) { $('workflow-error').textContent = error.message; }
  finally { lockCase(false); }
}
async function refreshCases() {
  try {
    const data = await caseRequest('/api/cases');
    const select = $('saved-cases'); select.replaceChildren(el('option', 'Choose a saved case…')); select.firstChild.value = '';
    data.cases.forEach(record => { const option = el('option', `${record.alert_id} · ${record.assignee} · ${record.status} · ${record.subject.slice(0, 50)}`); option.value = record.id; select.append(option); });
    select.value = currentCase ? currentCase.id : '';
  } catch (error) { $('workflow-error').textContent = error.message; }
}
async function openCase() {
  const id = $('saved-cases').value; if (!id || caseBusy || busy) return;
  lockCase(true); $('workflow-error').textContent = '';
  try {
    const record = await caseRequest(`/api/cases/${id}`);
    uploaded = null; $('raw-email').value = ''; $('email-file').value = ''; $('filename').textContent = 'Saved evidence loaded; original .eml is not stored'; size();
    currentCase = record; result = record.analysis; render();
    $('workflow-message').textContent = `Loaded ${record.id}. Only saved stage values are shown.`;
  } catch (error) { $('workflow-error').textContent = error.message; }
  finally { lockCase(false); }
}
function showRelated(matches, timestamp) {
  const node = $('related-matches'); if (!node) return;
  node.replaceChildren();
  if (!timestamp) { node.append(el('p', 'Run a local match check, then document your investigation. Matches are also refreshed when this stage is saved.', 'hint')); return; }
  node.append(el('p', `${matches.length} related local case(s) · checked ${timestamp}`, 'hint'));
  matches.forEach(match => {
    const card = el('article', undefined, 'indicator'); card.append(el('strong', `${match.alert_id} · ${match.id}`), el('p', match.subject));
    match.reasons.forEach(reason => card.append(el('code', `${reason.kind}: ${reason.value.replace(/@/g, '[@]')}`), el('br')));
    node.append(card);
  });
}
async function loadRelated() {
  if (!currentCase || caseBusy) return;
  $('check-related').disabled = true;
  try { const data = await caseRequest(`/api/cases/${currentCase.id}/related`); showRelated(data.matches, new Date().toISOString()); }
  catch (error) { $('workflow-error').textContent = error.message; }
  finally { if ($('check-related')) $('check-related').disabled = false; }
}
function workflowReport(data) {
  if (!currentCase) return data;
  const {analysis, ...workflow} = currentCase;
  return {...data, analyst:{disposition:workflow.report.disposition, notes:workflow.report.notes, recorded_at:workflow.updated_at}, workflow};
}
function workflowMarkdown(record) {
  if (!record) return '';
  const line = (label, value) => `**${label}:** ${safeMD(value)}\n\n`;
  return '\n## Five-stage investigation record\n\n' + line('Case', record.id) + line('Status', record.status === 'Completed' ? 'Completed' : `DRAFT — stage ${record.stage} of 5`) +
    '### 1. Assign alert\n\n' + line('Alert', record.alert_id) + line('Assigned analyst', record.assignee) +
    '### 2. Alert triaging process\n\n' + line('Priority', record.triage.priority) + line('Category', record.triage.category) + line('Assessment', record.triage.notes) +
    '### 3. Analyze email artifacts\n\n' + line('3.1 Sender reputation', record.sender_review.status) + line('Evidence source', record.sender_review.source) + line('Sender findings', record.sender_review.notes) + line('3.2 Attachment review', record.attachment_review.status) + line('Attachment findings', record.attachment_review.notes) +
    '### 4. Investigate related alerts\n\n' + line('Review confirmed', record.related_review.reviewed ? 'Yes' : 'No') + line('Scope and findings', record.related_review.notes) + line('External references', record.related_review.references) + line('Local matches at save', record.related_review.matches.map(m => `${m.id}: ${m.reasons.map(r => `${r.kind}=${r.value}`).join('; ')}`).join('\n') || 'None recorded') +
    '### 5. Case reporting\n\n' + line('Disposition', record.report.disposition) + line('Report', record.report.notes) +
    '### Activity history\n\n' + record.history.map(h => `- ${safeMD(h.at)} — ${safeMD(h.actor)}: ${safeMD(h.action)} (stage ${h.stage})`).join('\n') + '\n\nActivity history is a local convenience log, not an authenticated or tamper-proof audit trail.\n';
}
$('save-case').addEventListener('click', () => saveCase(false));
$('advance-case').addEventListener('click', () => saveCase(true));
$('saved-cases').addEventListener('change', openCase);
$('refresh-cases').addEventListener('click', refreshCases);
renderWorkflow();
refreshCases();
