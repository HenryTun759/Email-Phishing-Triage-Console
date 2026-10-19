const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
(async () => {
  const browser = await chromium.launch({headless:true});
  try {
    const page = await browser.newPage({viewport:{width:1440,height:1100}, acceptDownloads:true});
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    await page.goto('http://127.0.0.1:8765');
    await page.locator('[data-sample="credential"]').click();
    await page.locator('#results').waitFor({state:'visible'});
    await page.locator('#alert-reference').fill('BROWSER-ALERT-001');
    await page.locator('#case-owner').fill('Training analyst');
    await page.locator('#save-case').click();
    await page.waitForFunction(() => document.querySelector('#workflow-message').textContent.includes('Saved locally'));
    const id = await page.locator('#saved-cases').inputValue();
    assert.match(id, /^CASE-/);
    await page.locator('#advance-case').click();
    await page.locator('#triage-category').waitFor();
    await page.locator('#advance-case').click();
    await page.waitForFunction(() => document.querySelector('#workflow-error').textContent.includes('triage category'));
    await page.locator('#triage-category').selectOption('Credential phishing');
    await page.locator('#triage-priority').selectOption('High');
    await page.locator('#triage-notes').fill('Reported credential lure; exposure requires gateway review.');
    await page.locator('#advance-case').click();
    await page.locator('#sender-status').waitFor();
    await page.locator('#sender-status').selectOption('Inconclusive');
    await page.locator('#sender-source').fill('Synthetic message headers; no live reputation service queried');
    await page.locator('#sender-notes').fill('Sender reputation unverified. Deceptive URL requires escalation.');
    await page.locator('#attachment-status').selectOption('No attachments');
    await page.locator('#attachment-notes').fill('MIME inventory contains no attachments.');
    await page.locator('#save-case').click();
    await page.waitForFunction(() => !document.querySelector('#save-case').disabled);
    await page.reload();
    await page.locator(`#saved-cases option[value="${id}"]`).waitFor({state:'attached'});
    await page.locator('#saved-cases').selectOption(id);
    await page.locator('#sender-status').waitFor();
    assert.equal(await page.locator('#sender-status').inputValue(), 'Inconclusive');
    assert.match(await page.locator('#sender-notes').inputValue(), /reputation unverified/);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({path:path.join(__dirname,'..','docs','workflow.png'),fullPage:true});
    await page.locator('#advance-case').click();
    await page.locator('#related-notes').waitFor();
    const sample = await fs.readFile(path.join(__dirname,'..','samples','credential-phishing.eml'));
    const response = await page.request.post('http://127.0.0.1:8765/api/cases', {data:{email_base64:sample.toString('base64'),alert_id:'BROWSER-RELATED-002',assignee:'Second analyst'}});
    assert.equal(response.status(), 201);
    await page.locator('#check-related').click();
    await page.waitForFunction(() => document.querySelector('#related-matches').textContent.includes('BROWSER-RELATED-002'));
    await page.locator('#related-references').fill('Training ticket DEMO-002');
    await page.locator('#related-notes').fill('Related local alert shares sender and URL hosts; SIEM was not searched.');
    await page.locator('#related-reviewed').check();
    await page.locator('#advance-case').click();
    await page.waitForFunction(() => document.querySelector('#advance-case').textContent.includes('Complete case'));
    await page.locator('#disposition').selectOption('Escalate — suspected phishing');
    await page.locator('#notes').fill('Escalate for gateway validation and exposure investigation. No containment performed in this lab.');
    await page.locator('#advance-case').click();
    await page.waitForFunction(() => document.querySelector('#workflow-message').textContent.includes('Case complete'));
    assert.equal(await page.locator('#notes').isDisabled(), true);
    for (const extension of ['json','md']) {
      const pending = page.waitForEvent('download');
      await page.locator(`#export-${extension}`).click();
      const content = await fs.readFile(await (await pending).path(), 'utf8');
      if (extension === 'json') {
        const data = JSON.parse(content);
        assert.equal(data.workflow.status, 'Completed');
        assert.equal(data.workflow.stage, 5);
        assert.equal(data.workflow.sender_review.status, 'Inconclusive');
        assert.ok(data.workflow.related_review.matches.length > 0);
      } else {
        assert.match(content, /Five-stage investigation record/);
        assert.match(content, /Check|Sender reputation/);
        assert.match(content, /BROWSER-RELATED-002|CASE-/);
      }
    }
    await page.setViewportSize({width:390,height:844});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),true);
    await page.screenshot({path:path.join(__dirname,'..','docs','workflow-mobile.png'),fullPage:true});
    assert.deepEqual(errors,[]);
    console.log('Five-stage workflow passed: gates, persistence, related alerts, completion, exports and mobile.');
  } finally { await browser.close(); }
})().catch(error => {console.error(error);process.exitCode=1;});
