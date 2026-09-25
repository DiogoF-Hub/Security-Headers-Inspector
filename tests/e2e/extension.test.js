// Browser tests: the extension running in real Chromium against local test sites.
// Run with: npm run test:e2e   (needs Playwright's Chromium and openssl)
const test = require("node:test");
const assert = require("node:assert/strict");
const server = require("./server");
const { launch, sleep } = require("./browser");

const TIMEOUT = { timeout: 90000 };
let site;
test.before(async () => { site = await server.start(); });
test.after(() => site && site.close());

const mark = () => server.log.length;
const since = (m) => server.log.slice(m);
const extRequests = (m, host) => since(m).filter(r => r.extFetch && (!host || r.host === host));

async function withBrowser(fn) {
  const b = await launch();
  try { await fn(b); } finally { await b.close(); }
}

async function openTab(b, url) {
  const page = await b.ctx.newPage();
  await page.goto(url);
  await page.bringToFront();
  await sleep(700);
  return page;
}

const activeTab = (b) => b.sw.evaluate(async () => (await chrome.tabs.query({ active: true, lastFocusedWindow: true }))[0]);
const entryFor = (b, tabId) => b.sw.evaluate((t) => (tabHeaders[t] ? JSON.parse(JSON.stringify(tabHeaders[t])) : null), tabId);
const text = (popup, selector) => popup.evaluate(`document.querySelector(${JSON.stringify(selector)}).textContent`);

test("strong site: A+ in the real popup, breakdown, no errors", TIMEOUT, () => withBrowser(async (b) => {
  await openTab(b, "https://secure.test/");
  const popup = await b.openPopup();
  assert.equal(await text(popup, "#grade-badge"), "A+");
  assert.match(await text(popup, "#site-summary"), /6\/6 security headers present/);
  const rows = await popup.evaluate(`[...document.querySelectorAll('#breakdown tbody tr')].length`);
  assert.equal(rows, 6);
  assert.match(await text(popup, "#breakdown tfoot"), /120 \/ 120/);
  assert.deepEqual(popup.errors(), []);
  const tab = await activeTab(b);
  assert.equal(await b.sw.evaluate((t) => chrome.action.getBadgeText({ tabId: t }), tab.id), "A+");
}));

test("weak site: invalid values earn no points and show as problems", TIMEOUT, () => withBrowser(async (b) => {
  await openTab(b, "https://weak.test/");
  const popup = await b.openPopup();
  assert.equal(await text(popup, "#grade-badge"), "D");
  const missing = await popup.evaluate(`[...document.querySelectorAll('.status-pill.missing')].map(p => p.textContent)`);
  assert.deepEqual(missing.sort(), ["Permissions-Policy", "Referrer-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options"]);
  const statuses = await popup.evaluate(`[...document.querySelectorAll('#security-headers-list .header-item')].map(i => i.className.split(' ')[1])`);
  assert.deepEqual(statuses, ["warn", "bad", "bad", "bad", "bad", "bad"]);
  // The CSP cap (82%) doesn't bite at this low score, but the card warns about it
  assert.match(await text(popup, "#security-headers-list .header-item .desc-verdict"), /unsafe-inline/);
  // Nameless cookie: its value is blurred, not shown as the name
  assert.deepEqual(await popup.evaluate(`[...document.querySelectorAll('.cookie-name')].map(n => n.textContent.trim())`), ["▸ (no name)", "▸ sid"]);
  assert.deepEqual(popup.errors(), []);
}));

test("redirects: chain shown, cookie set on the redirect is kept", TIMEOUT, () => withBrowser(async (b) => {
  await openTab(b, "http://login.test/");
  const tab = await activeTab(b);
  const entry = await entryFor(b, tab.id);
  assert.equal(entry.url, "https://secure.test/welcome");
  assert.equal(entry.redirects.length, 1);
  assert.deepEqual([entry.redirects[0].status, entry.redirects[0].from], [302, "http://login.test/"]);
  assert.ok(entry.cookies.some(c => c.startsWith("__Host-session=")), "cookie from the 302 is kept");
  const popup = await b.openPopup();
  assert.match(await text(popup, "#redirect-list"), /302\s*http:\/\/login\.test\/\s+→\s+https:\/\/secure\.test\/welcome/);
}));

test("only page loads are captured, not subresources", TIMEOUT, () => withBrowser(async (b) => {
  await openTab(b, "https://sub.test/");
  const stored = await b.sw.evaluate(() => JSON.stringify({ tabHeaders, fetchedHeaders }) + JSON.stringify(Object.keys(fetchedHeaders)));
  assert.ok(!stored.includes("SUBRESOURCE_SECRET"));
  assert.ok(!stored.includes("token=abc"));
}));

test("re-checks: a page loaded from the network is not re-requested", TIMEOUT, () => withBrowser(async (b) => {
  const m = mark();
  const page = await openTab(b, "https://nohsts.test/a");
  await page.evaluate(() => { location.hash = "x"; history.pushState({}, "", "/b"); });
  await sleep(1000);
  assert.equal(extRequests(m, "nohsts.test").length, 0);
}));

test("re-checks: cached pages keep HSTS and cookies", TIMEOUT, () => withBrowser(async (b) => {
  const page = await openTab(b, "http://cache.test/page");
  const tab = await activeTab(b);
  const hsts = async () => (await entryFor(b, tab.id)).headers["strict-transport-security"];
  assert.ok(await hsts(), "network load has HSTS");

  // Back to the same URL from the cache: filled in from the earlier network load
  let m = mark();
  await page.goto("http://cache.test/other");
  await page.evaluate(() => { location.href = "/page"; });
  await sleep(1200);
  assert.equal(since(m).filter(r => r.path === "/page" && !r.extFetch).length, 0, "served from cache");
  assert.ok(await hsts(), "HSTS kept for the cached load");
  assert.equal(extRequests(m, "cache.test").length, 0, "no request needed");

  // A cached page this session never saw from the network: re-checked once
  await b.sw.evaluate(() => networkSecurityHeaders.clear());
  m = mark();
  await page.goto("http://cache.test/other");
  await page.evaluate(() => { location.href = "/page"; });
  await sleep(1500);
  assert.equal(extRequests(m, "cache.test").length, 1, "one re-check");
  assert.ok(await hsts(), "HSTS restored by the re-check");
  const entry = await entryFor(b, tab.id);
  assert.ok(entry.cookies.some(c => c.startsWith("sid=")));
}));

test("re-checks off: the popup still re-checks a cached page", TIMEOUT, () => withBrowser(async (b) => {
  await b.sw.evaluate(() => new Promise(r => chrome.storage.local.set({ settings: { autoFetch: false, showBadge: true, blurCookies: true } }, r)));
  await sleep(200);
  const page = await openTab(b, "http://cache.test/page");
  await b.sw.evaluate(() => networkSecurityHeaders.clear());
  let m = mark();
  await page.goto("http://cache.test/other");
  await page.evaluate(() => { location.href = "/page"; });
  await sleep(1200);
  assert.equal(extRequests(m, "cache.test").length, 0, "no background request");
  const tab = await activeTab(b);
  assert.equal((await entryFor(b, tab.id)).cacheIncomplete, true);
  m = mark();
  const popup = await b.openPopup();
  await sleep(800);
  assert.equal(extRequests(m, "cache.test").length, 1, "popup re-checked");
  assert.doesNotMatch(await text(popup, "#site-summary"), /Loaded from cache/);
  assert.ok((await entryFor(b, tab.id)).headers["strict-transport-security"]);
}));

test("rescan works on a site with Cross-Origin-Resource-Policy: same-origin", TIMEOUT, () => withBrowser(async (b) => {
  await openTab(b, "https://corp.test/");
  const popup = await b.openPopup();
  const m = mark();
  await popup.evaluate(`document.getElementById('rescan-btn').click()`);
  await sleep(1200);
  assert.equal(await popup.evaluate(`document.getElementById('restricted-page').classList.contains('hidden')`), true);
  assert.equal(await text(popup, "#grade-badge"), "A+");
  assert.equal(extRequests(m, "corp.test").length, 1);
  assert.doesNotMatch(await text(popup, "#site-summary"), /Rescan failed/);
}));

test("a failed rescan keeps the result instead of showing 'restricted'", TIMEOUT, () => withBrowser(async (b) => {
  await openTab(b, "https://flaky.test/");
  const popup = await b.openPopup();
  await popup.evaluate(`document.getElementById('rescan-btn').click()`);
  await sleep(1200);
  assert.equal(await popup.evaluate(`document.getElementById('restricted-page').classList.contains('hidden')`), true);
  assert.equal(await popup.evaluate(`getComputedStyle(document.getElementById('header')).display`), "flex");
  assert.match(await text(popup, "#site-summary"), /Rescan failed \(net::ERR_[A-Z_]+\), showing the last result/);
  const tab = await activeTab(b);
  assert.notEqual(await b.sw.evaluate((t) => chrome.action.getBadgeText({ tabId: t }), tab.id), "");
}));

test("settings: badge off and cookies unblurred", TIMEOUT, () => withBrowser(async (b) => {
  await b.sw.evaluate(() => new Promise(r => chrome.storage.local.set({ settings: { autoFetch: false, showBadge: false, blurCookies: false } }, r)));
  await sleep(200);
  await openTab(b, "https://weak.test/");
  const tab = await activeTab(b);
  assert.equal(await b.sw.evaluate((t) => chrome.action.getBadgeText({ tabId: t }), tab.id), "");
  const popup = await b.openPopup();
  assert.equal(await popup.evaluate(`document.querySelectorAll('.cookie-value-blurred.revealed').length`), 2);
}));

test("settings page loads with defaults and saves changes", TIMEOUT, () => withBrowser(async (b) => {
  const page = await b.ctx.newPage();
  const errors = [];
  page.on("pageerror", e => errors.push(e.message));
  await page.goto(`chrome-extension://${b.id}/options.html`);
  await sleep(300);
  assert.deepEqual(await page.evaluate(() => ["autoFetch", "showBadge", "blurCookies"].map(k => document.getElementById(k).checked)), [true, true, true]);
  await page.click("#autoFetch");
  await sleep(300);
  const saved = await b.sw.evaluate(() => new Promise(r => chrome.storage.local.get("settings", d => r(d.settings))));
  assert.equal(saved.autoFetch, false);
  assert.deepEqual(errors, []);
}));

test("keyboard: cards open with Enter, raw headers with Space; breakdown starts collapsed", TIMEOUT, () => withBrowser(async (b) => {
  await openTab(b, "https://secure.test/");
  const popup = await b.openPopup();
  const result = await popup.evaluate(`(() => {
    document.getElementById('toggle-details').click();
    const row = document.querySelector('.header-item .header-name');
    row.focus();
    row.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    const raw = document.getElementById('raw-toggle');
    raw.dispatchEvent(new KeyboardEvent('keydown', { key: ' ', bubbles: true }));
    const breakdown = document.getElementById('breakdown');
    const breakdownToggle = document.getElementById('breakdown-toggle');
    const breakdownClosedAtFirst = !breakdown.classList.contains('show') && getComputedStyle(breakdown).maxHeight === '0px';
    breakdownToggle.click();
    return {
      breakdownClosedAtFirst,
      breakdownOpens: breakdown.classList.contains('show') && breakdownToggle.getAttribute('aria-expanded') === 'true',
      focusable: row.tabIndex === 0 && row.getAttribute('role') === 'button',
      cardOpen: row.parentElement.classList.contains('expanded') && row.getAttribute('aria-expanded') === 'true',
      rawOpen: document.getElementById('raw-headers').classList.contains('show') && raw.getAttribute('aria-expanded') === 'true',
      detailsExpanded: document.getElementById('toggle-details').getAttribute('aria-expanded')
    };
  })()`);
  assert.deepEqual(result, { breakdownClosedAtFirst: true, breakdownOpens: true, focusable: true, cardOpen: true, rawOpen: true, detailsExpanded: "true" });
}));

test("copy hides cookie values", TIMEOUT, () => withBrowser(async (b) => {
  await openTab(b, "https://weak.test/");
  const popup = await b.openPopup();
  const copied = await popup.evaluate(`new Promise(r => { navigator.clipboard.writeText = (t) => { r(t); return Promise.resolve(); }; document.getElementById('copy-raw-btn').click(); })`);
  assert.ok(!copied.includes("SID_SECRET") && !copied.includes("nameless_secret_value"));
  assert.match(copied, /set-cookie: sid=\[hidden\]; Path=\//);
}));

test("Chrome Web Store: restricted, no request, no console error", TIMEOUT, () => withBrowser(async (b) => {
  const m = mark();
  const page = await b.ctx.newPage();
  await page.goto("https://teams.test/");
  await page.waitForURL(/chromewebstore/);
  await page.bringToFront();
  await sleep(800);
  const popup = await b.openPopup();
  await popup.evaluate(`document.getElementById('rescan-btn').click()`);
  await sleep(800);
  assert.equal(await popup.evaluate(`document.getElementById('restricted-page').classList.contains('hidden')`), false);
  assert.equal(extRequests(m, "chromewebstore.google.com").length, 0);
  assert.deepEqual(b.sw.errors(), []);
}));

test("hanging site: rescan answers after the timeout, not 'restricted'", TIMEOUT, () => withBrowser(async (b) => {
  await openTab(b, "https://hang.test/");
  const popup = await b.openPopup();
  const started = Date.now();
  await popup.evaluate(`document.getElementById('rescan-btn').click()`);
  let summary = "";
  for (let i = 0; i < 30; i++) {
    await sleep(500);
    summary = await text(popup, "#site-summary");
    if (!summary.startsWith("Fetching")) break;
  }
  const seconds = (Date.now() - started) / 1000;
  assert.ok(seconds >= 9 && seconds < 14, `answered after ${seconds}s`);
  assert.match(summary, /security headers present/);
  assert.equal(await popup.evaluate(`document.getElementById('restricted-page').classList.contains('hidden')`), true);
}));

test("incognito: captured, but never re-requested from the background", TIMEOUT, () => withBrowser(async (b) => {
  const ext = await b.extensionsPage();
  await ext.evaluate((id) => new Promise(r => chrome.developerPrivate.updateExtensionConfiguration({ extensionId: id, incognitoAccess: true }, r)), b.id);
  await sleep(1000);
  // Chromium disables a command-line-loaded extension when this setting changes
  await ext.evaluate((id) => new Promise(r => chrome.management.setEnabled(id, true, r)), b.id);
  await sleep(1000);
  await b.sw.evaluate(() => new Promise(r => chrome.storage.local.set({ settings: { autoFetch: true, showBadge: true, blurCookies: true } }, r)));
  const m = mark();
  const win = await b.sw.evaluate(() => chrome.windows.create({ incognito: true, url: "https://nohsts.test/incognito" }));
  await sleep(2000);
  const tab = await b.sw.evaluate(async (w) => (await chrome.tabs.query({ windowId: w }))[0], win.id);
  assert.equal(tab.incognito, true);
  assert.ok((await entryFor(b, tab.id)).headers, "headers captured from the page load");
  const response = await ext.evaluate((t) => new Promise(r => chrome.runtime.sendMessage({ type: "fetchHeaders", tabId: t }, r)), tab.id).catch(() => null);
  await sleep(500);
  assert.equal(extRequests(m).length, 0, "no background request for the incognito tab");
  void response;
}));

test("welcome page loads under the extension CSP", TIMEOUT, () => withBrowser(async (b) => {
  const page = await b.ctx.newPage();
  const errors = [];
  page.on("pageerror", e => errors.push(e.message));
  page.on("console", msg => msg.type() === "error" && errors.push(msg.text()));
  await page.goto(`chrome-extension://${b.id}/welcome.html`);
  await sleep(300);
  assert.equal(await page.evaluate(() => document.querySelector(".logo").naturalWidth > 0), true);
  assert.deepEqual(errors, []);
}));

test("downloads and empty responses keep the page's result", TIMEOUT, () => withBrowser(async (b) => {
  const page = await openTab(b, "https://secure.test/");
  const tab = await activeTab(b);
  for (const link of ["#dl", "#bin", "#nc"]) {
    await page.click(link);
    await sleep(800);
    const entry = await entryFor(b, tab.id);
    assert.equal(entry.url, "https://secure.test/", link);
    assert.equal(entry.headers["x-powered-by"], undefined, link);
  }
  const popup = await b.openPopup();
  assert.equal(await text(popup, "#grade-badge"), "A+");
}));

test("a site that is down shows 'didn't load', not 'restricted'", TIMEOUT, () => withBrowser(async (b) => {
  const page = await b.ctx.newPage();
  await page.goto("https://down.test/").catch(() => {});
  await page.bringToFront();
  await sleep(700);
  const popup = await b.openPopup();
  await sleep(1000);
  assert.equal(await popup.evaluate(`document.getElementById('restricted-page').classList.contains('hidden')`), true);
  assert.match(await text(popup, "#no-data-title"), /didn't load/);
  assert.match(await text(popup, "#no-data-hint"), /net::ERR_EMPTY_RESPONSE/);
}));

test("rescan shows the site's current headers", TIMEOUT, () => withBrowser(async (b) => {
  await openTab(b, "https://changing.test/");
  const popup = await b.openPopup();
  assert.equal(await popup.evaluate(`document.getElementById('disclosure-section').style.display`), "");
  await popup.evaluate(`document.getElementById('rescan-btn').click()`);
  await sleep(1200);
  assert.equal(await popup.evaluate(`document.getElementById('disclosure-section').style.display`), "none", "X-Powered-By is gone after the fix");
}));

test("headers with bytes that aren't UTF-8 don't break the popup", TIMEOUT, () => withBrowser(async (b) => {
  await openTab(b, "https://binary.test/");
  const popup = await b.openPopup();
  assert.equal(await popup.evaluate(`document.querySelectorAll('.cookie-item').length`), 1);
  assert.equal(await popup.evaluate(`document.querySelector('.cookie-name').textContent.trim()`), "▸ latin");
  assert.deepEqual(popup.errors(), []);
}));

test("easter egg on the extension's own pages", TIMEOUT, () => withBrowser(async (b) => {
  for (const [page, name] of [["welcome.html", "welcome page"], ["options.html", "settings page"]]) {
    const p = await b.ctx.newPage();
    await p.goto(`chrome-extension://${b.id}/${page}`);
    await p.bringToFront();
    await sleep(300);
    const popup = await b.openPopup();
    assert.equal(await text(popup, ".internal-title"), "Hey, you found me!");
    assert.match(await text(popup, "#internal-page .hint"), new RegExp(name));
    popup.close();
    await p.close();
  }
}));
