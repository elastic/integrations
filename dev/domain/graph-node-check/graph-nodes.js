'use strict';

const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

// ─── Timestamp ────────────────────────────────────────────────────────────────
const _now = new Date();
const _pad = (n) => String(n).padStart(2, '0');
const RUN_TIMESTAMP =
  `${_now.getFullYear()}-${_pad(_now.getMonth() + 1)}-${_pad(_now.getDate())}` +
  `_${_pad(_now.getHours())}h${_pad(_now.getMinutes())}`;

// ─── Config ───────────────────────────────────────────────────────────────────
const KIBANA_URL = process.env.KIBANA_URL || 'http://localhost:5601';

const CONFIG = {
  kibanaUrl: KIBANA_URL,
  username: process.env.KIBANA_USER || 'elastic',
  password: process.env.KIBANA_PASS || 'changeme',
  headless: process.env.HEADLESS === 'true',
  outputDir: path.join(process.env.HOME || '~', 'Documents', 'graph-node-runs', RUN_TIMESTAMP),
  eventsUrl: `${KIBANA_URL}/app/security/users/events?flyout=(preview:!())&timelineFlyout=(preview:!())&timeline=(activeTab:query,isOpen:!f,query:(expression:%27%27,kind:kuery))&timerange=(global:(linkTo:!(timeline),timerange:(from:%272006-06-29T21:00:00.000Z%27,fromStr:now-20y%2Fd,kind:relative,to:%272026-06-30T10:28:54.288Z%27,toStr:now)),timeline:(linkTo:!(global),timerange:(from:%272006-06-29T21:00:00.000Z%27,fromStr:now-20y%2Fd,kind:relative,to:%272026-06-30T10:28:54.288Z%27,toStr:now)),valueReport:(linkTo:!(),timerange:(from:%272026-05-30T10:28:34.608Z%27,fromStr:now-1M,kind:relative,to:%272026-06-30T10:28:34.608Z%27,toStr:now)))`,
  graphSettleMs: 6_000,   // time to wait after query submission for graph to load
  graphStableMs: 1_000,   // polling interval while checking for stable node count
  graphTimeoutMs: 20_000, // max time to wait for nodes to stabilize
};

// ─── Integrations list ────────────────────────────────────────────────────────
const INTEGRATIONS = [
  'qualys_vmdr', 'ti_misp', 'gitlab', 'slack', 'linux', 'citrix_waf',
  'zscaler_zia', 'suricata', 'fortinet_fortigate', 'cisco_secure_email_gateway',
  'cisco_umbrella', 'infoblox_bloxone_ddi', 'cisco_meraki', 'darktrace',
  'microsoft_dhcp', 'openai', 'snort', 'ping_one', 'checkpoint_email',
  'm365_defender', 'corelight', 'salesforce', 'sysdig', 'wiz', 'snyk',
  'prisma_cloud', 'gcp_vertexai', 'jamf_pro', 'azure_ai_foundry',
  'azure_app_service', 'azure_openai', 'microsoft_intune', 'aws_securityhub',
  'aws_cloudtrail_otel', 'aws_vpcflow_otel', 'aws_bedrock', 'aws_bedrock_agentcore',
  'ping_federate', 'cyera', 'entityanalytics_ad', 'entityanalytics_okta',
  'extrahop', 'forgerock', 'greenhouse', 'osquery', 'servicenow', 'tanium',
];

const results = [];
function log(msg) { process.stdout.write(msg + '\n'); }
function setupOutput() { fs.mkdirSync(CONFIG.outputDir, { recursive: true }); }

// ─── Login ────────────────────────────────────────────────────────────────────
async function login(page) {
  log('Logging in…');
  await page.goto(`${CONFIG.kibanaUrl}/login`);
  await page.waitForSelector('[data-test-subj="loginUsername"]', { timeout: 30_000 });
  await page.fill('[data-test-subj="loginUsername"]', CONFIG.username);
  await page.fill('[data-test-subj="loginPassword"]', CONFIG.password);
  await page.click('[data-test-subj="loginSubmit"]');
  await page.waitForURL(/\/app\//, { timeout: 30_000 });
  log('Logged in.');
}

// ─── Expand the Visualizations section and wait for graph to load ─────────────
async function expandVisualizationsAndWait(page) {
  // Make sure we're on the Overview tab
  const overviewTab = page.locator('[data-test-subj="securitySolutionFlyoutOverviewTab"]').first();
  if (await overviewTab.isVisible({ timeout: 3_000 }).catch(() => false)) {
    await overviewTab.click();
    await page.waitForTimeout(800);
  }

  // Scroll the flyout body down to reveal the Visualizations section
  const flyoutBody = page.locator('.euiFlyoutBody__overflow').first();
  if (await flyoutBody.isVisible({ timeout: 2_000 }).catch(() => false)) {
    await flyoutBody.evaluate((el) => { el.scrollTop += 400; });
    await page.waitForTimeout(600);
  }

  // Expand the Visualizations accordion if it's collapsed
  const vizHeader = page.locator('[data-test-subj="securitySolutionFlyoutVisualizationsHeader"]').first();
  if (await vizHeader.isVisible({ timeout: 5_000 }).catch(() => false)) {
    const vizContent = page.locator('[data-test-subj="securitySolutionFlyoutVisualizationsContent"]').first();
    const contentVisible = await vizContent.isVisible({ timeout: 1_000 }).catch(() => false);
    if (!contentVisible) {
      await vizHeader.click();
      await page.waitForTimeout(1_000);
    }
  }

  // Wait for graph loading skeleton to disappear (up to 20s)
  const loading = page.locator('[data-test-subj="securitySolutionFlyoutGraphPreviewLoading"]').first();
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (!(await loading.isVisible({ timeout: 500 }).catch(() => false))) break;
    await page.waitForTimeout(1_000);
  }
}

// ─── Navigate to graph investigation page via first available flyout ──────────
// Returns the page object to use going forward (may be a new tab).
async function openGraphPage(page, context) {
  log('\nNavigating to users/events page…');
  await page.goto(CONFIG.eventsUrl, { waitUntil: 'domcontentloaded', timeout: 30_000 });
  // Wait for the events table to actually render (Kibana can be slow)
  await page.waitForSelector('[data-test-subj="expand-event"]', { timeout: 20_000 }).catch(() => null);
  await page.waitForTimeout(1_000);

  // Try across multiple pagination pages to find a row with a rendered graph
  let pageNum = 1;
  while (pageNum <= 5) {
    const expandBtns = page.locator('[data-test-subj="expand-event"]');
    const rowCount = await expandBtns.count();
    log(`  Page ${pageNum}: ${rowCount} rows`);

    for (let i = 0; i < rowCount; i++) {
      const btn = page.locator('[data-test-subj="expand-event"]').nth(i);
      if (!(await btn.isVisible({ timeout: 2_000 }).catch(() => false))) continue;

      await btn.click();
      await page.waitForTimeout(2_000);

      // Expand visualizations and wait for graph
      await expandVisualizationsAndWait(page);

      const graphLink = page.locator('[data-test-subj="securitySolutionFlyoutGraphPreviewTitleLink"]').first();
      const visible = await graphLink.isVisible({ timeout: 3_000 }).catch(() => false);

      if (visible) {
        log(`  Found rendered graph on page ${pageNum}, row ${i + 1} — opening graph investigation page…`);

        // The link may open in a new tab — listen before clicking
        const newTabPromise = context.waitForEvent('page', { timeout: 8_000 }).catch(() => null);
        await graphLink.click();

        const newTab = await newTabPromise;
        if (newTab) {
          log('  Opened in new tab — switching to it.');
          await newTab.waitForLoadState('domcontentloaded', { timeout: 20_000 });
          await newTab.waitForTimeout(3_000);
          newTab.setDefaultTimeout(30_000);
          log('  Arrived at graph investigation page.');
          return newTab;
        }

        // Same-page navigation
        await page.waitForTimeout(4_000);
        log('  Arrived at graph investigation page.');
        return page;
      }

      // Close flyout and try next row
      await page.keyboard.press('Escape');
      await page.waitForTimeout(600);
    }

    // Move to next pagination page
    const nextBtn = page.locator('[data-test-subj="pagination-button-next"]').first();
    const nextExists = await nextBtn.isVisible({ timeout: 3_000 }).catch(() => false);
    const nextDisabled = await nextBtn.isDisabled({ timeout: 1_000 }).catch(() => true);
    if (!nextExists || nextDisabled) break;

    await nextBtn.click();
    await page.waitForTimeout(3_000);
    pageNum++;
  }

  throw new Error('Could not find a flyout with a rendered graph in the first 5 pages.');
}

// ─── Set time filter to Last 20 years ────────────────────────────────────────
async function setTimeFilter(page) {
  log('\nSetting time filter to Last 20 years…');

  // Click the badge to open the time input, then type -20y and submit
  const badge = page.locator('[data-test-subj="dateRangePickerDurationBadge"]').first();
  await badge.waitFor({ state: 'visible', timeout: 15_000 });
  await badge.click();
  await page.waitForTimeout(800);

  // Type -20y — works whether the badge becomes an input or opens a text field
  await page.keyboard.press('Meta+a');
  await page.keyboard.type('-20y');
  await page.keyboard.press('Enter');
  await page.waitForTimeout(2_000);

  log('  Time filter set (-20y).');
}

// ─── Open the graph search bar via its toggle button ─────────────────────────
async function ensureSearchBarOpen(page) {
  // Always click the toggle unconditionally — do NOT check for unifiedQueryInput
  // first, because the global Kibana search bar also has that test ID and would
  // give a false-positive "already open" early return.
  const toggleBtn = page.locator('[data-test-subj="cloudSecurityGraphGraphInvestigationToggleSearch"]').first();
  await toggleBtn.waitFor({ state: 'visible', timeout: 10_000 });
  await toggleBtn.click();
  await page.waitForTimeout(600);
  log('  Search bar toggled.');
}

// ─── Submit a query in the graph search bar ───────────────────────────────────
async function setQuery(page, integration) {
  // Some integrations require a non-default KQL query to find their documents.
  // Keys are integration names; values are the full KQL query string to use.
  const QUERY_OVERRIDES = {
    openai:           'data_stream.dataset : "openai*"',         // event.dataset not in inverted index (logsdb)
    salesforce:       'event.module : "salesforce"',             // event.dataset/data_stream.dataset not searchable; wildcard also doesn't work
    gcp_vertexai:     'data_stream.dataset : "gcp_vertexai*"',   // event.dataset wildcard fails (logsdb); data_stream.dataset wildcard works
    azure_openai:     'data_stream.dataset : "azure_openai*"',
    azure_app_service:'data_stream.dataset : "azure_app_service*"',
    azure_ai_foundry: 'data_stream.dataset : "azure_ai_foundry*"',
    forgerock:        'data_stream.dataset : "forgerock*"',
  };
  const query = QUERY_OVERRIDES[integration] ?? `event.dataset : "${integration}*"`;

  // Use .last() — the graph panel's input is added to the DOM AFTER the toggle
  // click, so it comes after the global Kibana search bar (which uses the same
  // test ID) and is always the last match.
  const input = page.locator('[data-test-subj="unifiedQueryInput"]').last();
  await input.waitFor({ state: 'visible', timeout: 8_000 });

  // force:true bypasses EUI portal overlays intercepting pointer events
  await input.click({ clickCount: 3, force: true });
  await page.waitForTimeout(200);
  await page.keyboard.type(query);

  // Dismiss any autocomplete, then submit
  await page.keyboard.press('Escape');
  await page.waitForTimeout(200);
  await page.keyboard.press('Enter');
}

// ─── Wait for graph nodes to stabilise after a query ─────────────────────────
async function waitForGraph(page) {
  // The graph renders an EuiProgress bar (role="progressbar") inside the
  // investigation container while isFetching is true. Waiting for it to appear
  // then disappear confirms the graph reloaded for the new query, preventing
  // stale nodes from a previous query being read as the current result.
  const container = page.locator('[data-test-subj="cloudSecurityGraphGraphInvestigation"]');
  const progressBar = container.locator('[role="progressbar"]').first();

  const appeared = await progressBar
    .waitFor({ state: 'visible', timeout: 6_000 })
    .then(() => true)
    .catch(() => false);

  if (appeared) {
    await progressBar.waitFor({ state: 'hidden', timeout: CONFIG.graphTimeoutMs });
    await page.waitForTimeout(500);
  } else {
    // No progress bar detected — graph loaded instantly or query had no effect
    await page.waitForTimeout(2_000);
  }

  // Stability check: poll until entity-node count is stable for two consecutive reads
  let prev = -1;
  let stable = 0;
  const deadline = Date.now() + 5_000;

  while (Date.now() < deadline) {
    const current = await page
      .locator('[data-test-subj="cloudSecurityGraphGraphInvestigationEntityNodeButton"]')
      .count();
    if (current === prev) {
      stable++;
      if (stable >= 2) break;
    } else {
      stable = 0;
      prev = current;
    }
    await page.waitForTimeout(CONFIG.graphStableMs);
  }
}

// ─── Extract all visible graph nodes, sorted by horizontal position ───────────
async function extractNodes(page) {
  const nodes = await page.evaluate(() => {
    const out = [];

    // Entity nodes: the button is the clickable target, but the VALUE text lives
    // in a sibling cloudSecurityGraphGraphInvestigationEntityNodeDetails div —
    // NOT inside the button itself. Query the details divs directly.
    for (const div of document.querySelectorAll(
      '[data-test-subj="cloudSecurityGraphGraphInvestigationEntityNodeDetails"]'
    )) {
      const fullTextEl = div.querySelector('[data-test-subj="fullText"]');
      const tagEl = div.querySelector(
        '[data-test-subj="cloudSecurityGraphGraphInvestigationTagText"]'
      );
      const rect = div.getBoundingClientRect();
      // Skip elements that are not visible on screen
      if (rect.width === 0 && rect.height === 0) continue;
      out.push({
        kind: 'entity',
        tag: tagEl?.textContent?.trim() || 'Entity',
        value: fullTextEl?.textContent?.trim() || '(unknown)',
        x: rect.left,
        y: rect.top,
      });
    }

    // Action / label nodes
    for (const div of document.querySelectorAll('[data-test-subj="label-node-text"]')) {
      const fullTextEl = div.querySelector('[data-test-subj="fullText"]');
      const rect = div.getBoundingClientRect();
      if (rect.width === 0 && rect.height === 0) continue;
      out.push({
        kind: 'action',
        tag: 'Action',
        value: fullTextEl?.textContent?.trim() || div.textContent?.trim() || '(unknown)',
        x: rect.left,
        y: rect.top,
      });
    }

    // Sort left-to-right (visual graph order), y as tiebreak
    out.sort((a, b) => a.x - b.x || a.y - b.y);
    return out;
  });

  return nodes;
}

// ─── Build a text graph visualization from sorted nodes ───────────────────────
function buildGraphText(nodes) {
  if (nodes.length === 0) return '(no nodes found)';

  // Build a chain string from the sorted node list
  const parts = nodes.map((n) =>
    n.kind === 'entity' ? `[${n.tag}: ${n.value}]` : `→ ${n.value} →`
  );

  // Wrap long chains at action boundaries for readability
  const lines = [];
  let current = '';
  for (const p of parts) {
    if (current && p.startsWith('→') && current.length > 80) {
      lines.push(current.trimEnd());
      current = '  ';
    }
    current += (current.trim() ? ' ' : '') + p;
  }
  if (current.trim()) lines.push(current.trimEnd());

  return lines.join('\n');
}

// ─── HTML escaping ────────────────────────────────────────────────────────────
function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ─── Generate HTML report ─────────────────────────────────────────────────────
function generateReport() {
  const withNodes = results.filter((r) => r.nodeCount > 0).length;
  const noNodes = results.filter((r) => r.nodeCount === 0 && !r.error).length;
  const errors = results.filter((r) => !!r.error).length;

  const rows = results
    .map((r) => {
      const hasNodes = r.nodeCount > 0;
      const rowBg = r.error ? '#fff8f8' : hasNodes ? '#f0fff4' : '#fff';
      const statusText = r.error
        ? `⚠️ Error`
        : hasNodes
        ? `✅ ${r.nodeCount} nodes`
        : `❌ No nodes`;
      const statusColor = r.error ? '#888' : hasNodes ? '#007a3e' : '#b00020';

      return `<tr style="background:${rowBg}">
        <td><code>${esc(r.integration)}</code></td>
        <td style="color:${statusColor};font-weight:600">${statusText}</td>
        <td>${r.entityCount}</td>
        <td>${r.labelCount}</td>
        <td><pre style="margin:0;font-size:0.78em;white-space:pre-wrap;max-height:160px;overflow-y:auto">${esc(r.graphText)}</pre></td>
        <td style="color:#b00020;font-size:0.82em">${r.error ? esc(r.error) : ''}</td>
      </tr>`;
    })
    .join('');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Graph Node Test — ${RUN_TIMESTAMP}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 24px; background: #f8f9fa; color: #222; }
  h1 { margin-top: 0; }
  .meta { color: #666; font-size: 0.85em; margin-bottom: 20px; }
  .summary { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 28px; }
  .stat { background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 12px 20px; min-width: 110px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,.05); }
  .stat .n { font-size: 2em; font-weight: 700; line-height: 1.1; }
  .stat .l { font-size: 0.78em; color: #666; margin-top: 2px; }
  table { border-collapse: collapse; width: 100%; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,.08); font-size: 0.87em; }
  th, td { border: 1px solid #e0e0e0; padding: 8px 11px; vertical-align: top; }
  th { background: #f0f0f0; font-weight: 600; position: sticky; top: 0; z-index: 1; }
  tr:hover td { background: rgba(0,0,255,.02); }
  code { background: #f0f0f0; padding: 1px 5px; border-radius: 3px; }
  pre { background: #f5f5f5; padding: 6px 8px; border-radius: 4px; border: 1px solid #e0e0e0; font-family: monospace; }
</style>
</head>
<body>
<h1>Graph Node Test Report</h1>
<p class="meta">Run: ${RUN_TIMESTAMP} &nbsp;|&nbsp; Integrations tested: ${results.length} &nbsp;|&nbsp; Time filter: Last 20 years</p>

<div class="summary">
  <div class="stat"><div class="n" style="color:#007a3e">${withNodes}</div><div class="l">With nodes</div></div>
  <div class="stat"><div class="n" style="color:#b00020">${noNodes}</div><div class="l">No nodes</div></div>
  <div class="stat"><div class="n" style="color:#888">${errors}</div><div class="l">Errors</div></div>
  <div class="stat"><div class="n">${results.length}</div><div class="l">Total</div></div>
</div>

<table>
  <thead>
    <tr>
      <th>Integration</th>
      <th>Status</th>
      <th>Entity nodes</th>
      <th>Action labels</th>
      <th>Graph visualization</th>
      <th>Error</th>
    </tr>
  </thead>
  <tbody>${rows}</tbody>
</table>
</body>
</html>`;

  const reportPath = path.join(CONFIG.outputDir, 'report.html');
  fs.writeFileSync(reportPath, html);
  fs.writeFileSync(
    path.join(CONFIG.outputDir, 'results.json'),
    JSON.stringify(results, null, 2)
  );
  log(`\nReport: file://${reportPath}`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  setupOutput();

  const browser = await chromium.launch({ headless: CONFIG.headless, slowMo: 50 });
  const context = await browser.newContext({ viewport: { width: 1600, height: 900 } });
  const page = await context.newPage();
  page.setDefaultTimeout(30_000);

  let graphPageUrl = null;

  // Re-open the graph investigation page from the saved URL and restore state.
  const reopenGraphPage = async () => {
    log('  [Reopening graph page…]');
    const gp = await context.newPage();
    gp.setDefaultTimeout(30_000);
    await gp.goto(graphPageUrl, { waitUntil: 'domcontentloaded', timeout: 30_000 });
    await gp.waitForTimeout(2_000);
    await ensureSearchBarOpen(gp);
    await setTimeFilter(gp);
    return gp;
  };

  try {
    await login(page);
    let graphPage = await openGraphPage(page, context);
    graphPageUrl = graphPage.url();
    log(`  Graph page URL: ${graphPageUrl}`);
    await ensureSearchBarOpen(graphPage);
    await setTimeFilter(graphPage);

    log(`\nTesting ${INTEGRATIONS.length} integrations…`);

    for (let idx = 0; idx < INTEGRATIONS.length; idx++) {
      const integration = INTEGRATIONS[idx];
      log(`\n[${idx + 1}/${INTEGRATIONS.length}] ${integration}`);

      // Recover if the tab was closed between iterations
      if (graphPage.isClosed()) {
        graphPage = await reopenGraphPage();
      }

      const runIntegration = async (gp) => {
        await setQuery(gp, integration);
        await waitForGraph(gp);
        return extractNodes(gp);
      };

      let nodes;
      try {
        nodes = await runIntegration(graphPage);
      } catch (err) {
        if (err.message.includes('closed') && graphPageUrl) {
          log('  [Tab crashed — recovering…]');
          try {
            graphPage = await reopenGraphPage();
            nodes = await runIntegration(graphPage);
          } catch (retryErr) {
            log(`  Error (after recovery): ${retryErr.message}`);
            results.push({ integration, nodeCount: 0, entityCount: 0, labelCount: 0, nodes: [], graphText: '', error: retryErr.message });
            continue;
          }
        } else {
          log(`  Error: ${err.message}`);
          results.push({ integration, nodeCount: 0, entityCount: 0, labelCount: 0, nodes: [], graphText: '', error: err.message });
          continue;
        }
      }

      const entities = nodes.filter((n) => n.kind === 'entity');
      const actions = nodes.filter((n) => n.kind === 'action');
      const graphText = buildGraphText(nodes);

      log(`  Nodes: ${nodes.length} (${entities.length} entity, ${actions.length} action)`);
      if (nodes.length > 0) log(`  ${graphText.split('\n')[0]}`);

      results.push({ integration, nodeCount: nodes.length, entityCount: entities.length, labelCount: actions.length, nodes, graphText, error: null });
    }
  } catch (err) {
    log(`\nFatal error: ${err.message}`);
  } finally {
    generateReport();
    await browser.close();
  }

  log('\nDone.');
}

main().catch((err) => {
  log(`Fatal: ${err.stack}`);
  process.exit(1);
});
