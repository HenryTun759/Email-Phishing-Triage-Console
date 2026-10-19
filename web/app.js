'use strict';
const $ = id => document.getElementById(id);
let result = null;
let uploaded = null;
let busy = false;
const MAX_BYTES = 2 * 1024 * 1024;
function el(tag, text, cls) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (cls) node.className = cls; return node; }
function size() { $('byte-count').textContent = `${uploaded ? uploaded.byteLength : new TextEncoder().encode($('raw-email').value).length} bytes`; }
function resetResult() { if (typeof resetWorkflow === 'function') resetWorkflow(); result = null; $('results').hidden = true; $('empty').hidden = false; $('notes').value = ''; $('disposition').selectedIndex = 0; }
function clear() { uploaded = null; $('raw-email').value = ''; $('email-file').value = ''; $('filename').textContent = 'Maximum file size 2 MiB'; $('error').textContent = ''; resetResult(); size(); }
function setBusy(value) { busy = value; document.querySelectorAll('button[data-sample], #analyze, #clear, #email-file, #raw-email').forEach(n => n.disabled = value); $('analyze').textContent = value ? 'Analyzing…' : 'Analyze message →'; }
$('raw-email').addEventListener('input', () => { uploaded = null; $('filename').textContent = 'Using edited text source'; resetResult(); size(); });
$('clear').addEventListener('click', clear);
$('email-file').addEventListener('change', async event => {
  const file = event.target.files[0]; if (!file) return;
  resetResult(); uploaded = null; $('raw-email').value = ''; $('error').textContent = '';
  if (file.size > MAX_BYTES || file.size === 0) { $('error').textContent = 'Choose a non-empty email smaller than 2 MiB.'; $('email-file').value = ''; $('filename').textContent = 'Maximum file size 2 MiB'; size(); return; }
  setBusy(true);
  try { uploaded = await file.arrayBuffer(); $('raw-email').value = new TextDecoder().decode(uploaded); $('filename').textContent = file.name; size(); }
  catch { $('error').textContent = 'Could not read that file. Try selecting it again.'; }
  finally { setBusy(false); }
});
async function run() {
  if (busy) return;
  $('error').textContent = '';
  const body = uploaded || new TextEncoder().encode($('raw-email').value);
  if (!body.byteLength || body.byteLength > MAX_BYTES) { $('error').textContent = 'Provide an email between 1 byte and 2 MiB.'; return; }
  setBusy(true); resetResult();
  try {
    const response = await fetch('/api/analyze', {method:'POST', headers:{'Content-Type':'application/octet-stream'}, body});
    const data = await response.json(); if (!response.ok) throw new Error(data.error || 'Analysis failed.');
    result = data; render(); $('announcement').textContent = `Analysis complete. ${data.risk} review priority. ${data.findings.length} findings.`;
  } catch (err) { $('error').textContent = err.message || 'Unable to contact the local service.'; }
  finally { setBusy(false); }
}
$('analyze').addEventListener('click', run);
document.querySelectorAll('[data-sample]').forEach(button => button.addEventListener('click', async () => {
  if (busy) return; clear(); setBusy(true);
  try {
    const response = await fetch(`/api/sample/${button.dataset.sample}`);
    if (!response.ok) throw new Error('Could not load sample.');
    $('raw-email').value = (await response.json()).email;
    $('filename').textContent = 'Synthetic training email'; size();
  } catch (err) { $('error').textContent = err.message; setBusy(false); return; }
  setBusy(false); await run();
}));
function activate(name, focus = false) {
  document.querySelectorAll('[data-tab]').forEach(button => {
    const active = button.dataset.tab === name;
    button.setAttribute('aria-selected', String(active)); button.tabIndex = active ? 0 : -1;
    $(`view-${button.dataset.tab}`).hidden = !active;
    if (active && focus) button.focus();
  });
}
document.querySelectorAll('[data-tab]').forEach((button, index) => {
  button.addEventListener('click', () => activate(button.dataset.tab));
  button.addEventListener('keydown', event => {
    const tabs = [...document.querySelectorAll('[data-tab]')];
    const next = event.key === 'ArrowRight' ? (index + 1) % tabs.length : event.key === 'ArrowLeft' ? (index + tabs.length - 1) % tabs.length : event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : null;
    if (next !== null) { event.preventDefault(); activate(tabs[next].dataset.tab, true); }
  });
});
function render() {
  $('empty').hidden = true; $('results').hidden = false;
  $('case-id').textContent = `${result.case_id} / ANALYSIS COMPLETE`;
  $('subject').textContent = result.subject;
  $('sender').textContent = result.from || 'Sender unavailable';
  $('score').textContent = result.score; $('risk').textContent = `${result.risk} priority`;
  document.querySelector('.score-box').dataset.risk = result.risk;
  $('finding-count').textContent = result.findings.length; $('url-count').textContent = result.urls.length; $('attachment-count').textContent = result.attachments.length;
  const findings = $('view-findings'); findings.replaceChildren();
  if (!result.findings.length) findings.append(el('p', 'No configured rules matched. Verify the message independently before marking it benign.'));
  result.findings.forEach(f => { const card = el('article', undefined, 'finding'); card.append(el('h3', f.title), el('span', `+${f.points}`, 'points'), el('p', f.evidence), el('span', f.rule, 'rule')); findings.append(card); });
  findings.append(el('h3', 'Recommended next steps'));
  const steps = el('ol'); result.next_steps.forEach(step => steps.append(el('li', step))); findings.append(steps);
  const indicators = $('view-indicators'); indicators.replaceChildren(el('h3', 'URLs · defanged for safe review'));
  if (!result.urls.length) indicators.append(el('p', 'No HTTP(S) URLs extracted.'));
  result.urls.forEach(u => { const card = el('div', undefined, 'indicator'); card.append(el('code', u.value), el('p', `Host: ${u.host}`)); indicators.append(card); });
  indicators.append(el('h3', 'Attachment inventory · never executed'));
  if (!result.attachments.length) indicators.append(el('p', 'No attachments found.'));
  result.attachments.forEach(a => { const card = el('div', undefined, 'indicator'); card.append(el('strong', a.name), el('p', `${a.type} · ${a.bytes} bytes`), el('code', a.sha256 ? `SHA-256: ${a.sha256}` : 'Container attachment: hash unavailable')); indicators.append(card); });
  const headers = $('view-headers'); headers.replaceChildren(el('h3', 'Authentication claims — not independently verified'));
  Object.entries(result.authentication).forEach(([key, value]) => headers.append(el('p', `${key.toUpperCase()}: ${value.join(', ') || 'not reported'}`)));
  headers.append(el('pre', result.authentication_headers.join('\n') || 'No Authentication-Results header.'));
  headers.append(el('h3', 'Message metadata'), el('pre', `From: ${result.from}\nTo: ${result.to}\nReply-To: ${result.reply_to || '(none)'}\nDate: ${result.date}\nMessage-ID: ${result.message_id}\nSHA-256: ${result.email_sha256}`));
  headers.append(el('h3', 'Received chain · source order, unverified'), el('pre', result.received.join('\n\n') || 'No Received headers.'));
  $('view-message').replaceChildren(el('p', 'Plain-text preview only. HTML is never rendered; preview is capped at 18,000 characters.'), el('pre', result.body_preview || '(No text body)'));
  activate('findings');
  if (typeof renderWorkflow === 'function') renderWorkflow();
}
function report() { const data = {...result, analyst: {disposition:$('disposition').value, notes:$('notes').value, recorded_at:new Date().toISOString()}}; return typeof workflowReport === 'function' ? workflowReport(data) : data; }
// Encode untrusted strings so Markdown exports do not create active links, HTML, or headings.
function safeMD(value) { return String(value).replace(/[^a-zA-Z0-9 ,:;!?\n\-]/g, c => `&#${c.codePointAt(0)};`).replace(/\n/g, '\n> '); }
function markdown(data) {
  return `# Email phishing triage report\n\nCase: ${data.case_id}\n\nAnalyzed: ${data.analyzed_at}\n\nReview priority: **${data.risk} (${data.score}/100)**\n\nSubject: ${safeMD(data.subject)}\n\nSender: ${safeMD(data.from)}\n\nEmail SHA-256: ${data.email_sha256}\n\n## Findings\n\n${data.findings.map(f => `- **${safeMD(f.title)}** (+${f.points}, ${f.rule}): ${safeMD(f.evidence)}`).join('\n') || 'No configured rules matched.'}\n\n## URLs (defanged)\n\n${data.urls.map(u => '- ' + safeMD(u.value)).join('\n') || 'None.'}\n\n## Attachments\n\n${data.attachments.map(a => `- ${safeMD(a.name)} (${a.bytes} bytes); SHA-256: ${a.sha256 || 'unavailable'}`).join('\n') || 'None.'}\n\n## Analyst decision\n\n${safeMD(data.analyst.disposition)}\n\n${safeMD(data.analyst.notes || 'No notes recorded.')}\n\nRecorded: ${data.analyst.recorded_at}\n\n## Next steps\n\n${data.next_steps.map(s => '- ' + s).join('\n')}\n\n## Limitations\n\n${data.limitations.map(s => '- ' + s).join('\n')}\n`;
}
function download(extension) {
  if (!result) return;
  const data = report(), content = extension === 'json' ? JSON.stringify(data, null, 2) : markdown(data) + (typeof workflowMarkdown === 'function' ? workflowMarkdown(data.workflow) : '');
  const blob = new Blob([content], {type: extension === 'json' ? 'application/json' : 'text/markdown'});
  const url = URL.createObjectURL(blob), anchor = el('a'); anchor.href = url; anchor.download = `${data.workflow ? data.workflow.id : data.case_id}.${extension}`; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$('export-md').addEventListener('click', () => download('md'));
$('export-json').addEventListener('click', () => download('json'));
