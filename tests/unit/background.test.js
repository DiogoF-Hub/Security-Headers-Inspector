// Unit tests for background.js, run against a fake chrome.* API.
// Run with: npm test
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.join(__dirname, "..", "..");
const EXT_ID = "abcdefghijklmnop";
const ORIGIN = `chrome-extension://${EXT_ID}`;
const POPUP = { id: EXT_ID, url: `${ORIGIN}/popup.html` };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const hdr = (o) => Object.entries(o).flatMap(([name, v]) => (Array.isArray(v) ? v : [v]).map(value => ({ name, value })));

// Chrome reports chrome-extension://<id> as the origin of extension URLs; Node reports "null"
class ChromeURL extends URL {
  get origin() { return this.protocol === "chrome-extension:" ? `${this.protocol}//${this.host}` : super.origin; }
}

// Load background.js (and analysis.js through importScripts) with a fake chrome API.
// fetchImpl decides how the extension's own fetch() behaves.
function loadBackground({ settings, storedTabHeaders, storedSession, storageDelay = 0, fetchImpl, existingAlarm } = {}) {
  const listeners = {};
  const ev = (name) => ({ addListener: (fn) => { listeners[name] = fn; } });
  const calls = { tabsCreate: [], menusCreate: [], menusRemoveAll: 0, fetches: [], badges: {}, sessionSet: null, setAccessLevel: false };
  let menuIds = new Set();
  const tabs = new Map();
  const local = { settings };
  const session = { ...(storedSession || {}) };
  const chrome = {
    runtime: { id: EXT_ID, getURL: (p) => `${ORIGIN}/${p}`, onInstalled: ev("onInstalled"), onStartup: ev("onStartup"), onMessage: ev("onMessage"), lastError: undefined },
    storage: {
      session: {
        setAccessLevel: () => { calls.setAccessLevel = true; },
        get: (key, cb) => setTimeout(() => cb(key === "tabHeaders" && storedTabHeaders ? { tabHeaders: storedTabHeaders } : (session[key] !== undefined ? { [key]: session[key] } : {})), storageDelay),
        // Like the real MV3 API, returns a Promise when no callback is given
        set: (o) => { Object.assign(session, JSON.parse(JSON.stringify(o))); if (o.tabHeaders) calls.sessionSet = JSON.parse(JSON.stringify(o)); return Promise.resolve(); }
      },
      local: { get: (keys, cb) => setTimeout(() => cb({ ...local }), 0), set: (o, cb) => { Object.assign(local, o); cb && cb(); } },
      onChanged: ev("storageOnChanged")
    },
    alarms: { create: (name) => { calls.alarmCreated = (calls.alarmCreated || 0) + 1; }, get: (name, cb) => cb(existingAlarm), onAlarm: ev("onAlarm") },
    webRequest: {
      onHeadersReceived: ev("onHeadersReceived"), onBeforeRedirect: ev("onBeforeRedirect"), onResponseStarted: ev("onResponseStarted"),
      onCompleted: ev("onCompleted"), onErrorOccurred: ev("onErrorOccurred")
    },
    tabs: {
      onRemoved: ev("onRemoved"), onUpdated: ev("onUpdated"),
      query: (q, cb) => cb([...tabs.values()]),
      get: (id, cb) => { const t = tabs.get(id); chrome.runtime.lastError = t ? undefined : { message: "No tab" }; cb(t); chrome.runtime.lastError = undefined; },
      create: (o) => calls.tabsCreate.push(o.url)
    },
    action: {
      setBadgeText: ({ tabId, text }) => { calls.badges[tabId] = text; return Promise.resolve(); },
      setBadgeBackgroundColor: () => Promise.resolve()
    },
    contextMenus: {
      create: (o) => { if (menuIds.has(o.id)) throw new Error("duplicate id " + o.id); menuIds.add(o.id); calls.menusCreate.push(o); },
      removeAll: (cb) => { calls.menusRemoveAll++; menuIds = new Set(); cb && cb(); },
      onClicked: ev("onClicked")
    }
  };
  const defaultFetch = (url) => { calls.fetches.push(url); return new Promise(() => {}); };
  let ctx;
  const sandbox = {
    chrome, URL: ChromeURL, AbortSignal, console, setTimeout, clearTimeout,
    fetch: fetchImpl ? (url, opts) => { calls.fetches.push(url); calls.fetchOptions = opts; return fetchImpl(url, opts, listeners); } : defaultFetch,
    importScripts: (file) => vm.runInContext(fs.readFileSync(path.join(ROOT, file), "utf8"), ctx, { filename: file })
  };
  ctx = vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(ROOT, "background.js"), "utf8"), ctx, { filename: "background.js" });
  const get = (expr) => vm.runInContext(expr, ctx);
  calls.session = session;
  const message = (msg, sender = POPUP) => new Promise((resolve) => {
    const keepOpen = listeners.onMessage(msg, sender, resolve);
    if (keepOpen !== true) setTimeout(() => resolve("NO_RESPONSE"), 20);
  });
  return { listeners, calls, tabs, get, message, local };
}

// A successful fetch that webRequest reports `delayMs` after (or, if negative, before) it resolves
function fetchReportingHeaders(delayMs, responseHeaders = { "X-Frame-Options": "DENY" }) {
  return (url, opts, listeners) => {
    const report = () => listeners.onHeadersReceived({ requestId: "r" + url, type: "xmlhttprequest", tabId: -1, initiator: ORIGIN, url, statusCode: 200, responseHeaders: hdr(responseHeaders) });
    const response = { url, type: "basic", status: 200, body: null, headers: new Map() };
    if (delayMs < 0) { report(); return Promise.resolve(response); }
    setTimeout(report, delayMs);
    return Promise.resolve(response);
  };
}

test("captures only page loads and the extension's own fetches", async () => {
  const bg = loadBackground();
  const L = bg.listeners.onHeadersReceived;
  L({ requestId: "1", type: "image", tabId: 5, url: "https://bank.test/api?token=1", statusCode: 200, responseHeaders: hdr({ "Set-Cookie": "x=SECRET" }) });
  L({ requestId: "2", type: "xmlhttprequest", tabId: -1, initiator: "chrome-extension://other", url: "https://x.test/", statusCode: 200, responseHeaders: hdr({ a: "1" }) });
  L({ requestId: "3", type: "main_frame", tabId: -1, url: "https://prerender.test/", statusCode: 200, responseHeaders: hdr({ a: "1" }) });
  assert.equal(Object.keys(bg.get("fetchedHeaders")).length, 0);
  assert.equal(Object.keys(bg.get("tabHeaders")).length, 0);
  L({ requestId: "4", type: "xmlhttprequest", tabId: -1, initiator: ORIGIN, url: "https://own.test/", statusCode: 200, responseHeaders: hdr({ a: "1" }) });
  L({ requestId: "5", type: "main_frame", tabId: 7, url: "https://page.test/", statusCode: 200, responseHeaders: hdr({ "Set-Cookie": "k=v" }) });
  assert.ok("https://own.test/" in bg.get("fetchedHeaders"));
  assert.deepEqual([...bg.get("tabHeaders")[7].cookies], ["k=v"]);
  await sleep(350);
  assert.deepEqual(Object.keys(bg.calls.sessionSet), ["tabHeaders"], "fetchedHeaders is never persisted");
  assert.equal(bg.calls.setAccessLevel, false, "storage.session keeps its default access level");
});

test("a redirect hop is recorded, and cookies set on it are kept", () => {
  const bg = loadBackground();
  const common = { requestId: "9", type: "main_frame", tabId: 3 };
  bg.listeners.onHeadersReceived({ ...common, url: "http://site.test/login", statusCode: 302, responseHeaders: hdr({ Location: "https://site.test/", "Set-Cookie": "session=abc; Secure" }) });
  bg.listeners.onBeforeRedirect({ ...common, url: "http://site.test/login", redirectUrl: "https://site.test/", statusCode: 302, statusLine: "HTTP/1.1 302 Found", responseHeaders: [] });
  bg.listeners.onBeforeRedirect({ ...common, url: "https://site.test/", redirectUrl: "https://www.site.test/", statusCode: 307, statusLine: "HTTP/1.1 307 Internal Redirect", responseHeaders: hdr({ "Non-Authoritative-Reason": "HSTS" }) });
  assert.equal(bg.get("tabHeaders")[3], undefined, "the 302 itself is not stored as the page");
  bg.listeners.onHeadersReceived({ ...common, url: "https://www.site.test/", statusCode: 200, responseHeaders: hdr({ "Set-Cookie": "theme=dark" }) });
  const entry = bg.get("tabHeaders")[3];
  assert.equal(entry.url, "https://www.site.test/");
  assert.deepEqual([...entry.cookies], ["session=abc; Secure", "theme=dark"]);
  assert.equal(entry.redirects.length, 2);
  assert.deepEqual({ ...entry.redirects[1] }, { from: "https://site.test/", to: "https://www.site.test/", status: 307, internal: true, reason: "HSTS" });
});

test("304 after an entry without headers does not throw; with headers keeps them", () => {
  const bg = loadBackground();
  bg.get("tabHeaders")[3] = { restricted: true, url: "https://c.test/" };
  assert.doesNotThrow(() => bg.listeners.onHeadersReceived({ requestId: "a", type: "main_frame", tabId: 3, url: "https://c.test/", statusCode: 304, responseHeaders: hdr({ ETag: '"v1"' }) }));
  const bg2 = loadBackground();
  bg2.listeners.onHeadersReceived({ requestId: "b", type: "main_frame", tabId: 3, url: "https://c.test/", statusCode: 200, responseHeaders: hdr({ "X-Frame-Options": "DENY" }) });
  bg2.listeners.onHeadersReceived({ requestId: "c", type: "main_frame", tabId: 3, url: "https://c.test/", statusCode: 304, responseHeaders: hdr({ ETag: '"v1"' }) });
  assert.equal(bg2.get("tabHeaders")[3].headers["x-frame-options"], "DENY");
});

test("entries captured before the stored copy loads are kept", async () => {
  const bg = loadBackground({ storageDelay: 30, storedTabHeaders: { 1: { url: "https://old.test/", headers: { a: "1" }, cookies: [] } } });
  bg.listeners.onHeadersReceived({ requestId: "x", type: "main_frame", tabId: 2, url: "https://new.test/", statusCode: 200, responseHeaders: hdr({ b: "2" }) });
  await sleep(60);
  assert.deepEqual(Object.keys(bg.get("tabHeaders")).sort(), ["1", "2"]);
});

test("fetchForHeaders waits for the capture, whichever event comes first", async () => {
  for (const delay of [-1, 0, 40, 300]) {
    const bg = loadBackground({ fetchImpl: fetchReportingHeaders(delay) });
    const started = Date.now();
    const { webReqData } = await bg.get("fetchForHeaders")("https://site.test/");
    assert.equal(webReqData && webReqData.headers["x-frame-options"], "DENY", `delay ${delay}`);
    assert.ok(Date.now() - started < delay + 200, `resolves as soon as the capture arrives (delay ${delay})`);
  }
});

test("fetchForHeaders ignores a capture from before it started", async () => {
  const bg = loadBackground({ fetchImpl: fetchReportingHeaders(5000) });
  bg.get("fetchedHeaders")["https://site.test/"] = { headers: { stale: "1" }, timestamp: Date.now() - 1000 };
  const { webReqData } = await bg.get("fetchForHeaders")("https://site.test/");
  assert.equal(webReqData, null, "old capture is not used; gives up after the capture wait");
});

test("fetchForHeaders: the Chrome Web Store is restricted without a request", async () => {
  const bg = loadBackground({ fetchImpl: fetchReportingHeaders(0) });
  await assert.rejects(bg.get("fetchForHeaders")("https://chromewebstore.google.com/detail/x"), { name: "RestrictedError" });
  await assert.rejects(bg.get("fetchForHeaders")("https://chrome.google.com/webstore/detail/x"), { name: "RestrictedError" });
  assert.equal(bg.calls.fetches.length, 0);
});

test("fetchForHeaders uses a normal (cors) request, which CORP doesn't block", async () => {
  const bg = loadBackground({ fetchImpl: fetchReportingHeaders(0) });
  await bg.get("fetchForHeaders")("https://site.test/");
  assert.equal(bg.calls.fetchOptions.mode, undefined);
  assert.equal(bg.calls.fetchOptions.credentials, "omit");
  assert.equal(bg.calls.fetchOptions.cache, "no-store");
});

test("install creates menus once per install/update, only for web pages", () => {
  const bg = loadBackground();
  bg.listeners.onInstalled({ reason: "install" });
  bg.listeners.onInstalled({ reason: "update" });
  assert.equal(bg.calls.menusRemoveAll, 2);
  assert.ok(bg.calls.menusCreate.every(m => JSON.stringify(m.documentUrlPatterns) === JSON.stringify(["http://*/*", "https://*/*"])));
  assert.equal(bg.calls.tabsCreate.filter(u => u.endsWith("welcome.html")).length, 1);
});

test("context menu scan links drop secrets and skip non-web pages", () => {
  const bg = loadBackground();
  const C = bg.listeners.onClicked;
  C({ menuItemId: "scan-securityheaders" }, { url: "https://user:pw@site.test/reset/abc?token=SECRET#frag" });
  C({ menuItemId: "scan-ssllabs" }, { url: "https://site.test:8443/x?y=1" });
  C({ menuItemId: "scan-securityheaders" }, { url: "file:///home/me/secret.pdf" });
  assert.deepEqual(bg.calls.tabsCreate, [
    "https://securityheaders.com/?q=" + encodeURIComponent("https://site.test/reset/abc") + "&hide=on&followRedirects=on",
    "https://www.ssllabs.com/ssltest/analyze.html?d=site.test&hideResults=on&latest"
  ]);
});

test("messages: only extension pages, and fetches use the tab's own URL", async () => {
  const bg = loadBackground();
  bg.tabs.set(9, { id: 9, url: "https://tab.test/page", incognito: false });
  bg.tabs.set(10, { id: 10, url: "https://incog.test/", incognito: true });
  bg.get("tabHeaders")[9] = { url: "https://tab.test/page", headers: { a: "1" } };
  assert.equal(await bg.message({ type: "getHeaders", tabId: 9 }, { id: EXT_ID, url: "https://evil.test/" }), "NO_RESPONSE");
  assert.equal(await bg.message({ type: "getHeaders", tabId: 9 }, { id: "other", url: "chrome-extension://other/x.html" }), "NO_RESPONSE");
  assert.equal((await bg.message({ type: "getHeaders", tabId: 9 })).url, "https://tab.test/page");
  bg.listeners.onMessage({ type: "fetchHeaders", tabId: 9, url: "http://192.168.1.1/admin" }, POPUP, () => {});
  await sleep(10);
  assert.deepEqual(bg.calls.fetches, ["https://tab.test/page"]);
  assert.equal(await bg.message({ type: "fetchHeaders", tabId: 10 }), null, "incognito tab: no fetch");
  assert.equal(bg.calls.fetches.length, 1);
});

// Page load helpers: a network or cache response for a tab, as webRequest reports them
function loadPage(bg, tabId, url, { headers = { "Strict-Transport-Security": "max-age=31536000", "Set-Cookie": "sid=1" }, fromCache = false } = {}) {
  // The browser cache drops these two headers
  const sent = { ...headers };
  if (fromCache) { delete sent["Strict-Transport-Security"]; delete sent["Set-Cookie"]; }
  const requestId = "req" + Math.random();
  bg.listeners.onHeadersReceived({ requestId, type: "main_frame", tabId, url, statusCode: 200, responseHeaders: hdr(sent) });
  bg.listeners.onResponseStarted({ requestId, type: "main_frame", tabId, url, statusCode: 200, fromCache });
  bg.listeners.onUpdated(tabId, { status: "complete" }, { url, incognito: false });
}

test("re-checks: a page loaded from the network is never re-requested, even without HSTS", async () => {
  const bg = loadBackground();
  bg.tabs.set(4, { id: 4, url: "https://nohsts.test/", incognito: false });
  loadPage(bg, 4, "https://nohsts.test/", { headers: { "X-Frame-Options": "DENY" } });
  await sleep(20);
  assert.equal(bg.calls.fetches.length, 0);
  assert.equal(bg.get("tabHeaders")[4].cacheIncomplete, undefined);
});

test("re-checks: a cached load of a URL seen from the network is completed without a request", async () => {
  const bg = loadBackground();
  bg.tabs.set(4, { id: 4, url: "https://site.test/", incognito: false });
  loadPage(bg, 4, "https://site.test/");
  loadPage(bg, 4, "https://site.test/", { fromCache: true });
  await sleep(20);
  const entry = bg.get("tabHeaders")[4];
  assert.equal(entry.headers["strict-transport-security"], "max-age=31536000");
  assert.deepEqual([...entry.cookies], ["sid=1"]);
  assert.equal(entry.cacheIncomplete, undefined);
  assert.equal(bg.calls.fetches.length, 0);
});

test("re-checks: nothing is remembered from Incognito tabs", async () => {
  const bg = loadBackground();
  bg.tabs.set(8, { id: 8, url: "https://private.test/", incognito: true });
  loadPage(bg, 8, "https://private.test/");
  await sleep(350);
  assert.equal(bg.get("networkSecurityHeaders").size, 0);
  assert.equal(bg.calls.session.networkSecurityHeaders, undefined);
});

test("re-checks: remembered headers survive a service worker restart", async () => {
  const first = loadBackground();
  first.tabs.set(4, { id: 4, url: "https://site.test/", incognito: false });
  loadPage(first, 4, "https://site.test/");
  await sleep(350);
  const restarted = loadBackground({ storedSession: first.calls.session });
  restarted.tabs.set(4, { id: 4, url: "https://site.test/", incognito: false });
  await sleep(10);
  loadPage(restarted, 4, "https://site.test/", { fromCache: true });
  await sleep(20);
  assert.equal(restarted.get("tabHeaders")[4].headers["strict-transport-security"], "max-age=31536000");
  assert.equal(restarted.calls.fetches.length, 0);
});

test("re-checks: an unknown cached page is re-requested once, in-page navigation adds none", async () => {
  const bg = loadBackground({ fetchImpl: fetchReportingHeaders(0, { "Strict-Transport-Security": "max-age=31536000" }) });
  bg.tabs.set(4, { id: 4, url: "https://spa.test/", incognito: false });
  loadPage(bg, 4, "https://spa.test/", { fromCache: true });
  assert.equal(bg.get("tabHeaders")[4].cacheIncomplete, true);
  const U = bg.listeners.onUpdated;
  U(4, { url: "https://spa.test/#x" }, { url: "https://spa.test/#x" });
  U(4, { status: "complete" }, { url: "https://spa.test/#x", incognito: false });
  U(4, { url: "https://spa.test/route/2" }, { url: "https://spa.test/route/2" });
  U(4, { status: "complete" }, { url: "https://spa.test/route/2", incognito: false });
  U(11, { status: "complete" }, { url: "https://incog.test/", incognito: true });
  await sleep(50);
  assert.deepEqual(bg.calls.fetches, ["https://spa.test/"]);
  const entry = bg.get("tabHeaders")[4];
  assert.equal(entry.headers["strict-transport-security"], "max-age=31536000", "filled in by the re-check");
  assert.equal(entry.cacheIncomplete, undefined);
  U(4, { url: "https://other.test/" }, { url: "https://other.test/" });
  assert.equal(bg.get("tabHeaders")[4], undefined, "cross-origin URL change clears it");
});

test("re-checks: turned off in the settings, cached pages are not re-requested", async () => {
  const bg = loadBackground({ settings: { autoFetch: false } });
  bg.tabs.set(4, { id: 4, url: "https://spa.test/", incognito: false });
  loadPage(bg, 4, "https://spa.test/", { fromCache: true });
  bg.listeners.onInstalled({ reason: "install" });
  await sleep(20);
  assert.equal(bg.calls.fetches.length, 0);
  assert.equal(bg.get("tabHeaders")[4].cacheIncomplete, true, "the popup sees it's incomplete");
});

test("re-checks: open tabs are scanned on install, not on update", async () => {
  const bg = loadBackground({ fetchImpl: fetchReportingHeaders(0) });
  bg.tabs.set(4, { id: 4, url: "https://open.test/", incognito: false });
  bg.tabs.set(5, { id: 5, url: "https://private.test/", incognito: true });
  bg.listeners.onInstalled({ reason: "update" });
  await sleep(20);
  assert.equal(bg.calls.fetches.length, 0);
  bg.listeners.onInstalled({ reason: "install" });
  await sleep(50);
  assert.deepEqual(bg.calls.fetches, ["https://open.test/"]);
});

test("rescan: a failed request keeps the captured data instead of marking the page restricted", async () => {
  const bg = loadBackground({ fetchImpl: () => Promise.reject(new TypeError("Failed to fetch")) });
  bg.tabs.set(4, { id: 4, url: "https://vault.test/", incognito: false });
  loadPage(bg, 4, "https://vault.test/");
  const response = await bg.message({ type: "fetchHeaders", tabId: 4 });
  assert.equal(response.restricted, undefined);
  assert.equal(response.rescanFailed, "request blocked");
  assert.equal(response.headers["strict-transport-security"], "max-age=31536000");
  assert.equal(bg.get("tabHeaders")[4].rescanFailed, undefined, "the flag is not stored");
});

test("rescan: with nothing captured, a failed request means restricted and clears the badge", async () => {
  const bg = loadBackground({ fetchImpl: () => Promise.reject(new TypeError("Failed to fetch")) });
  bg.tabs.set(6, { id: 6, url: "https://blocked.test/", incognito: false });
  bg.calls.badges[6] = "A+";
  const response = await bg.message({ type: "fetchHeaders", tabId: 6 });
  assert.equal(response.restricted, true);
  assert.equal(bg.calls.badges[6], "");
});

test("settings: badge can be turned off, and existing badges clear", async () => {
  const bg = loadBackground();
  bg.listeners.onHeadersReceived({ requestId: "p", type: "main_frame", tabId: 4, url: "https://a.test/", statusCode: 200, responseHeaders: hdr({ a: "1" }) });
  await sleep(10);
  assert.equal(bg.calls.badges[4], "F");
  bg.listeners.storageOnChanged({ settings: { newValue: { showBadge: false } } }, "local");
  await sleep(10);
  assert.equal(bg.calls.badges[4], "");
  bg.listeners.onHeadersReceived({ requestId: "q", type: "main_frame", tabId: 5, url: "https://b.test/", statusCode: 200, responseHeaders: hdr({ a: "1" }) });
  await sleep(10);
  assert.equal(bg.calls.badges[5], undefined);
});

test("badge grade uses the page URL (HSTS over plain HTTP doesn't count)", async () => {
  const bg = loadBackground();
  const strong = { "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'", "Strict-Transport-Security": "max-age=31536000", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=()" };
  bg.listeners.onHeadersReceived({ requestId: "s", type: "main_frame", tabId: 1, url: "https://a.test/", statusCode: 200, responseHeaders: hdr(strong) });
  bg.listeners.onHeadersReceived({ requestId: "h", type: "main_frame", tabId: 2, url: "http://a.test/", statusCode: 200, responseHeaders: hdr(strong) });
  await sleep(10);
  assert.equal(bg.calls.badges[1], "A+");
  assert.equal(bg.calls.badges[2], "A");
});

test("downloads and empty responses don't replace the page's data", () => {
  const bg = loadBackground();
  loadPage(bg, 4, "https://site.test/");
  const L = bg.listeners.onHeadersReceived;
  L({ requestId: "d1", type: "main_frame", tabId: 4, url: "https://site.test/report.pdf.zip", statusCode: 200, responseHeaders: hdr({ "Content-Type": "application/zip" }) });
  L({ requestId: "d2", type: "main_frame", tabId: 4, url: "https://site.test/export", statusCode: 200, responseHeaders: hdr({ "Content-Type": "text/csv", "Content-Disposition": "attachment; filename=a.csv" }) });
  L({ requestId: "d3", type: "main_frame", tabId: 4, url: "https://site.test/ping", statusCode: 204, responseHeaders: hdr({}) });
  assert.equal(bg.get("tabHeaders")[4].url, "https://site.test/");
  L({ requestId: "d4", type: "main_frame", tabId: 4, url: "https://site.test/doc.pdf", statusCode: 200, responseHeaders: hdr({ "Content-Type": "application/pdf" }) });
  assert.equal(bg.get("tabHeaders")[4].url, "https://site.test/doc.pdf", "a PDF is shown as a page");
});

test("a page that fails to load is recorded as a load error, not restricted", () => {
  const bg = loadBackground();
  bg.listeners.onErrorOccurred({ requestId: "e1", type: "main_frame", tabId: 4, url: "https://down.test/", error: "net::ERR_CONNECTION_REFUSED" });
  assert.deepEqual({ ...bg.get("tabHeaders")[4], timestamp: 0 }, { loadError: "net::ERR_CONNECTION_REFUSED", url: "https://down.test/", timestamp: 0 });
  bg.listeners.onErrorOccurred({ requestId: "e2", type: "main_frame", tabId: 5, url: "https://a.test/", error: "net::ERR_ABORTED" });
  assert.equal(bg.get("tabHeaders")[5], undefined, "an aborted load is not an error");
  // A failure after this request's headers arrived keeps them
  bg.listeners.onHeadersReceived({ requestId: "e3", type: "main_frame", tabId: 6, url: "https://ok.test/", statusCode: 200, responseHeaders: hdr({ a: "1" }) });
  bg.listeners.onErrorOccurred({ requestId: "e3", type: "main_frame", tabId: 6, url: "https://ok.test/", error: "net::ERR_CONNECTION_RESET" });
  assert.ok(bg.get("tabHeaders")[6].headers);
});

test("rescan: a network error reported by webRequest is a load error, not restricted", async () => {
  const bg = loadBackground({
    fetchImpl: (url, opts, listeners) => {
      listeners.onErrorOccurred({ requestId: "f1", type: "xmlhttprequest", tabId: -1, initiator: ORIGIN, url, error: "net::ERR_CERT_DATE_INVALID" });
      return Promise.reject(new TypeError("Failed to fetch"));
    }
  });
  bg.tabs.set(6, { id: 6, url: "https://expired.test/", incognito: false });
  const response = await bg.message({ type: "fetchHeaders", tabId: 6 });
  assert.equal(response.restricted, undefined);
  assert.equal(response.loadError, "net::ERR_CERT_DATE_INVALID");
});

test("rescan: fresh headers replace the old ones", async () => {
  const bg = loadBackground({ fetchImpl: fetchReportingHeaders(0, { "Strict-Transport-Security": "max-age=31536000" }) });
  bg.tabs.set(4, { id: 4, url: "https://site.test/", incognito: false });
  loadPage(bg, 4, "https://site.test/", { headers: { "X-Powered-By": "PHP/5.4", "Set-Cookie": "sid=1" } });
  const response = await bg.message({ type: "fetchHeaders", tabId: 4 });
  assert.equal(response.headers["x-powered-by"], undefined, "a header the site stopped sending is gone");
  assert.equal(response.headers["strict-transport-security"], "max-age=31536000");
  assert.deepEqual([...response.cookies], ["sid=1"], "cookies from the page load are kept");
  assert.equal(bg.calls.fetchOptions.headers.Accept.startsWith("text/html"), true, "asks for HTML like a navigation");
});

test("re-checks: only the headers the cache drops are filled in, and only for the same page", async () => {
  let release;
  const gate = new Promise(r => { release = r; });
  const bg = loadBackground({
    fetchImpl: (url, opts, listeners) => gate.then(() => fetchReportingHeaders(-1, { "Strict-Transport-Security": "max-age=31536000", "X-Powered-By": "Other" })(url, opts, listeners))
  });
  bg.tabs.set(4, { id: 4, url: "https://site.test/a", incognito: false });
  loadPage(bg, 4, "https://site.test/a", { fromCache: true });
  await sleep(10);
  assert.deepEqual(bg.calls.fetches, ["https://site.test/a"]);
  // Before the re-check returns, the tab loads another page of the same site from the network
  bg.tabs.set(4, { id: 4, url: "https://site.test/b", incognito: false });
  bg.listeners.onHeadersReceived({ requestId: "b", type: "main_frame", tabId: 4, url: "https://site.test/b", statusCode: 200, responseHeaders: hdr({ "X-Frame-Options": "DENY" }) });
  release();
  await sleep(50);
  const entry = bg.get("tabHeaders")[4];
  assert.equal(entry.url, "https://site.test/b");
  assert.equal(entry.headers["strict-transport-security"], undefined, "page A's HSTS is not added to page B");
  assert.equal(entry.headers["x-powered-by"], undefined);
});

test("header values that aren't valid UTF-8 are kept as text", () => {
  const bg = loadBackground();
  bg.listeners.onHeadersReceived({ requestId: "u", type: "main_frame", tabId: 4, url: "https://site.test/", statusCode: 200,
    responseHeaders: [{ name: "Set-Cookie", binaryValue: [97, 61, 255] }, { name: "X-Test", binaryValue: [104, 105] }] });
  const entry = bg.get("tabHeaders")[4];
  assert.equal(entry.headers["x-test"], "hi");
  assert.deepEqual([...entry.cookies], ["a=ÿ"]);
});

test("the cleanup alarm is created once, not reset on every start", () => {
  assert.equal(loadBackground().calls.alarmCreated, 1);
  assert.equal(loadBackground({ existingAlarm: { name: "prune-fetched-headers" } }).calls.alarmCreated, undefined);
});
