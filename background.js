// MV3 service worker. webRequest observation is still available.
// State is persisted via chrome.storage.session since service workers are ephemeral.

// Header analysis and grading shared with the popup
importScripts("analysis.js");

// storage.session keeps its default TRUSTED_CONTEXTS access level: it holds captured
// Set-Cookie values, and only extension pages (which are trusted) need to read it.

// Origin of this extension, used to recognise requests made by our own fetch() calls.
const EXTENSION_ORIGIN = new URL(chrome.runtime.getURL("")).origin;

// Background fetches that never return headers must not hold a queue slot forever.
const FETCH_TIMEOUT_MS = 10000;
// How long to wait for webRequest to report the headers of our own fetch
const CAPTURE_WAIT_MS = 2000;

// --- Settings ---
let settings = { ...DEFAULT_SETTINGS };
const settingsReady = new Promise((resolve) => {
  chrome.storage.local.get("settings", (result) => {
    settings = { ...DEFAULT_SETTINGS, ...(result.settings || {}) };
    resolve();
  });
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes.settings) return;
  const before = settings;
  settings = { ...DEFAULT_SETTINGS, ...(changes.settings.newValue || {}) };
  if (before.showBadge !== settings.showBadge) refreshAllBadges();
});

// --- Storage helpers ---
// Service workers can go idle at any time, so tab state lives in storage.session.
// We keep a local cache to avoid async reads on every webRequest event.
let tabHeaders = {};
// Headers captured from this extension's own fetch() calls, keyed by URL. Only
// needed until the fetch that caused them reads them, so never persisted.
let fetchedHeaders = {};

// Load state from storage on service worker startup. Entries captured before the
// read completed are newer, so they win over the stored copy.
chrome.storage.session.get("tabHeaders", (result) => {
  if (result.tabHeaders) tabHeaders = Object.assign(result.tabHeaders, tabHeaders);
});

// Debounce storage writes. Many tabs completing at once would otherwise
// serialize the entire object dozens of times per second.
let saveTabHeadersTimer = null;
function saveTabHeaders() {
  if (saveTabHeadersTimer) clearTimeout(saveTabHeadersTimer);
  saveTabHeadersTimer = setTimeout(() => {
    saveSession({ tabHeaders });
    saveTabHeadersTimer = null;
  }, 300);
}

function saveTabHeadersNow() {
  if (saveTabHeadersTimer) clearTimeout(saveTabHeadersTimer);
  saveTabHeadersTimer = null;
  saveSession({ tabHeaders });
}

function saveSession(items) {
  chrome.storage.session.set(items).catch((err) => console.warn("Could not save state:", err.message));
}

// Prune stale fetchedHeaders entries via chrome.alarms (setInterval doesn't survive idle).
// Only create the alarm once: re-creating it on every service worker start would
// restart its countdown, so it might never fire.
chrome.alarms.get("prune-fetched-headers", (alarm) => {
  if (!alarm) chrome.alarms.create("prune-fetched-headers", { periodInMinutes: 1 });
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "prune-fetched-headers") {
    const cutoff = Date.now() - 30000;
    for (const url of Object.keys(fetchedHeaders)) {
      if (fetchedHeaders[url].timestamp < cutoff) delete fetchedHeaders[url];
    }
  }
});

// Show the grade on the toolbar badge. The tab may have closed by the time a
// fetch finishes, so a rejected badge update is expected and ignored.
function setBadge(tabId, data) {
  settingsReady.then(() => {
    if (!settings.showBadge || !data || !data.headers) return;
    const grade = computeGrade(data.headers, data.url);
    chrome.action.setBadgeText({ tabId, text: grade.letter }).catch(() => {});
    chrome.action.setBadgeBackgroundColor({ tabId, color: grade.color }).catch(() => {});
  });
}

function clearBadge(tabId) {
  chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
}

function refreshAllBadges() {
  for (const [id, data] of Object.entries(tabHeaders)) {
    if (settings.showBadge) setBadge(Number(id), data);
    else clearBadge(Number(id));
  }
}

function sameOrigin(a, b) {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

// Pages Chromium hides from all extensions. Fetching them is pointless and makes the
// browser log a CORS error, so they are reported as restricted without a request.
function isKnownRestricted(url) {
  try {
    const u = new URL(url);
    return u.hostname === "chromewebstore.google.com" ||
      (u.hostname === "chrome.google.com" && u.pathname.startsWith("/webstore"));
  } catch {
    return false;
  }
}

function restrictedError() {
  const err = new Error("Page is restricted for extensions");
  err.name = "RestrictedError";
  return err;
}

// --- Waiting for our own fetch's headers ---
// webRequest reports the headers of our fetch() through a separate event, which can
// arrive before or after fetch() resolves. Instead of sleeping a fixed time, each
// fetch waits for a capture of its final URL that arrived after the fetch started.
const captureWaiters = new Map(); // url -> Set of { since, resolve }

function waitForCapture(url, since) {
  const hit = fetchedHeaders[url];
  if (hit && hit.timestamp >= since) return Promise.resolve(hit);
  return new Promise((resolve) => {
    const waiter = { since, resolve };
    if (!captureWaiters.has(url)) captureWaiters.set(url, new Set());
    captureWaiters.get(url).add(waiter);
    setTimeout(() => {
      const set = captureWaiters.get(url);
      if (set && set.delete(waiter)) {
        if (set.size === 0) captureWaiters.delete(url);
        resolve(null);
      }
    }, CAPTURE_WAIT_MS);
  });
}

function notifyCapture(url, data) {
  const set = captureWaiters.get(url);
  if (!set) return;
  for (const waiter of set) {
    if (data.timestamp >= waiter.since) {
      set.delete(waiter);
      waiter.resolve(data);
    }
  }
  if (set.size === 0) captureWaiters.delete(url);
}

// Fetch a page from the service worker so webRequest can see its full header set.
// Resolves with the Response and the headers webRequest captured for it; rejects
// for pages the browser doesn't let extensions read.
// Default (cors) mode on purpose: host permissions make every site readable, while
// no-cors requests are blocked by Cross-Origin-Resource-Policy: same-origin.
// The Accept header of a page navigation, so servers that vary on it answer with the
// same response (and headers) as for the page itself.
const NAVIGATION_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

function fetchForHeaders(url) {
  if (isKnownRestricted(url)) return Promise.reject(restrictedError());
  const since = Date.now();
  return fetch(url, { credentials: "omit", cache: "no-store", headers: { Accept: NAVIGATION_ACCEPT }, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) })
    .then((response) => {
      // Only the headers are needed, don't download the body
      if (response.body) response.body.cancel().catch(() => {});
      // response.url is the final URL after redirects
      return waitForCapture(response.url, since).then((webReqData) => ({ response, webReqData }));
    }, (err) => {
      if (isTimeout(err)) throw err;
      // webRequest reports network errors (site down, TLS error, blocked by another
      // extension) of our own requests. Restricted pages are hidden from it, so when
      // nothing was reported, the browser refused the request.
      return waitForOwnFetchError(url, since).then((netError) => {
        if (!netError) throw restrictedError();
        const e = new Error(netError);
        e.name = "NetworkError";
        e.netError = netError;
        throw e;
      });
    });
}

// Network errors webRequest reported for this extension's own requests
const ownFetchErrors = []; // { url, error, time }

function waitForOwnFetchError(url, since) {
  const find = () => {
    const recent = ownFetchErrors.filter(e => e.time >= since);
    const match = recent.find(e => e.url === url) || recent[0];
    return match ? match.error : null;
  };
  return new Promise((resolve) => {
    let waited = 0;
    const check = () => {
      const error = find();
      if (error || waited >= 500) return resolve(error);
      waited += 50;
      setTimeout(check, 50);
    };
    check();
  });
}

// A timeout says nothing about whether the page is restricted, so don't flag it as such.
function isTimeout(err) {
  return err && (err.name === "TimeoutError" || err.name === "AbortError");
}

// Tab entry for a failed request: a network error, or a page hidden from extensions
function failureEntry(err, url) {
  return err && err.netError
    ? { loadError: err.netError, url, timestamp: Date.now() }
    : { restricted: true, url, timestamp: Date.now() };
}

// Responses that don't replace the page shown in the tab: nothing to show (204/205),
// or a file the browser downloads instead of displaying.
const RENDERED_APPLICATION_TYPES = ["application/xhtml+xml", "application/xml", "application/json", "application/pdf", "application/javascript", "application/ecmascript", "application/x-javascript"];

function isNotShownAsPage(statusCode, headers) {
  if (statusCode === 204 || statusCode === 205) return true;
  if (/^\s*attachment/i.test(headers["content-disposition"] || "")) return true;
  const type = (headers["content-type"] || "").split(";")[0].trim().toLowerCase();
  if (!type) return false;
  const shown = /^(text|image|video|audio)\//.test(type) || /\+(xml|json)$/.test(type) || RENDERED_APPLICATION_TYPES.includes(type);
  return !shown;
}

// Header value as text. Chrome gives values that aren't valid UTF-8 as bytes.
function headerValue(header) {
  if (typeof header.value === "string") return header.value;
  return header.binaryValue ? String.fromCharCode(...header.binaryValue) : "";
}

// --- Capturing headers ---

// Only two kinds of response are useful: top-level page loads in a tab, and
// responses to this extension's own fetch() calls. Everything else (images,
// XHRs, other extensions' requests) is skipped so their cookies and URLs
// are never captured.
function isPageLoad(details) {
  return details.type === "main_frame" && details.tabId >= 0;
}

function isOwnFetch(details) {
  return details.tabId === -1 && details.initiator === EXTENSION_ORIGIN;
}

// Redirect hops and cookies set along the way, per request, until the final response
const redirectState = new Map(); // requestId -> { hops, cookies }

function redirectStateFor(requestId) {
  if (!redirectState.has(requestId)) redirectState.set(requestId, { hops: [], cookies: [] });
  return redirectState.get(requestId);
}

chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    if (!isPageLoad(details) && !isOwnFetch(details)) return;
    const state = redirectStateFor(details.requestId);
    if (state.hops.length >= 20) return;
    const reasonHeader = (details.responseHeaders || []).find(h => h.name.toLowerCase() === "non-authoritative-reason");
    state.hops.push({
      from: details.url,
      to: details.redirectUrl,
      status: details.statusCode,
      // Redirects Chrome makes itself (HSTS upgrades, HTTPS-Upgrades) are "Internal Redirect"s
      internal: /internal redirect/i.test(details.statusLine || ""),
      reason: reasonHeader ? reasonHeader.value : null
    });
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// The browser strips Strict-Transport-Security and Set-Cookie from responses it keeps
// in its HTTP cache, so a page served from cache (or revalidated with a 304) arrives
// here without them. Remember those headers from network responses in this session,
// per URL, so a cached load of the same URL can be completed without a request.
// Kept in storage.session too, since the service worker stops after ~30s idle.
const networkSecurityHeaders = new Map(); // url -> { hsts, cookies }
const MAX_REMEMBERED_URLS = 500;

chrome.storage.session.get("networkSecurityHeaders", (result) => {
  // Entries recorded before the read completed are newer, so they stay
  for (const [url, value] of result.networkSecurityHeaders || []) {
    if (!networkSecurityHeaders.has(url)) networkSecurityHeaders.set(url, value);
  }
});

let saveNetworkHeadersTimer = null;
function rememberNetworkHeaders(url, data) {
  networkSecurityHeaders.delete(url);
  // Cap the cookie data kept per page: session storage is limited to 10 MB in total
  const cookies = (data.cookies || []).slice(0, 30).filter(c => c.length <= 4096);
  networkSecurityHeaders.set(url, { hsts: data.headers["strict-transport-security"] || null, cookies });
  if (networkSecurityHeaders.size > MAX_REMEMBERED_URLS) {
    networkSecurityHeaders.delete(networkSecurityHeaders.keys().next().value);
  }
  clearTimeout(saveNetworkHeadersTimer);
  saveNetworkHeadersTimer = setTimeout(() => {
    saveSession({ networkSecurityHeaders: [...networkSecurityHeaders] });
  }, 300);
}

// onResponseStarted is the first event that says whether the page came from cache
chrome.webRequest.onResponseStarted.addListener(
  (details) => {
    if (!isPageLoad(details)) return;
    const entry = tabHeaders[details.tabId];
    if (!entry || !entry.headers || entry.url !== details.url) return;
    if (!details.fromCache) {
      // Never keep anything from Incognito tabs beyond the tab's own lifetime
      const snapshot = { headers: { ...entry.headers }, cookies: [...entry.cookies] };
      chrome.tabs.get(details.tabId, (tab) => {
        if (!chrome.runtime.lastError && tab && !tab.incognito) rememberNetworkHeaders(details.url, snapshot);
      });
      return;
    }
    const known = networkSecurityHeaders.get(details.url);
    if (known) {
      if (known.hsts && !entry.headers["strict-transport-security"]) entry.headers["strict-transport-security"] = known.hsts;
      if (entry.cookies.length === 0 && known.cookies.length > 0) entry.cookies = known.cookies;
      delete entry.cacheIncomplete;
    } else {
      // Not seen from the network yet: HSTS and cookies are unknown until re-checked
      entry.cacheIncomplete = true;
    }
    setBadge(details.tabId, entry);
    saveTabHeaders();
  },
  { urls: ["<all_urls>"], types: ["main_frame"] }
);

chrome.webRequest.onCompleted.addListener((details) => redirectState.delete(details.requestId), { urls: ["<all_urls>"] });

chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    redirectState.delete(details.requestId);
    if (isOwnFetch(details)) {
      ownFetchErrors.push({ url: details.url, error: details.error, time: Date.now() });
      if (ownFetchErrors.length > 50) ownFetchErrors.shift();
      return;
    }
    // ERR_ABORTED: the user stopped the load or navigated elsewhere, not a failure
    if (!isPageLoad(details) || details.error === "net::ERR_ABORTED") return;
    const entry = tabHeaders[details.tabId];
    // The headers of this very request already arrived: the page itself is fine
    if (entry && entry.headers && entry.requestId === details.requestId) return;
    tabHeaders[details.tabId] = { loadError: details.error, url: details.url, timestamp: Date.now() };
    clearBadge(details.tabId);
    saveTabHeaders();
  },
  { urls: ["<all_urls>"] }
);

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const pageLoad = isPageLoad(details);
    if (!pageLoad && !isOwnFetch(details)) return;

    // Object.create(null) avoids prototype pollution if a server sends a header
    // named __proto__ or constructor, which would mutate a regular object's prototype.
    const headers = Object.create(null);
    const cookies = [];
    for (const header of details.responseHeaders) {
      const name = header.name.toLowerCase();
      const value = headerValue(header);
      if (name === "set-cookie") {
        cookies.push(value);
      }
      headers[name] = value;
    }

    // A redirect is not the page: remember its cookies (a login often sets the
    // session cookie on a 302) and wait for the final response.
    if (details.statusCode >= 300 && details.statusCode < 400 && details.statusCode !== 304) {
      redirectStateFor(details.requestId).cookies.push(...cookies);
      return;
    }

    // A download or an empty response: the tab keeps showing the current page
    if (pageLoad && isNotShownAsPage(details.statusCode, headers)) return;

    const state = redirectState.get(details.requestId);
    const data = {
      url: details.url,
      requestId: details.requestId,
      statusCode: details.statusCode,
      headers: headers,
      cookies: state ? state.cookies.concat(cookies) : cookies,
      redirects: state ? state.hops : [],
      timestamp: Date.now()
    };

    if (pageLoad) {
      const existing = tabHeaders[details.tabId];
      if (details.statusCode === 304 && existing && existing.headers) {
        // 304 Not Modified, server sends minimal headers.
        // Keep the existing full header set, just update the timestamp.
        existing.timestamp = Date.now();
      } else {
        // Full response, store all headers
        // Preserve cookies from previous load if server didn't send new ones
        if (data.cookies.length === 0 && existing && existing.cookies && existing.cookies.length > 0) {
          data.cookies = existing.cookies;
        }
        tabHeaders[details.tabId] = data;
      }

      setBadge(details.tabId, tabHeaders[details.tabId]);
      saveTabHeaders();
    } else {
      // A fetch from this service worker, store by URL
      fetchedHeaders[details.url] = data;
      notifyCapture(details.url, data);
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders", "extraHeaders"]
);

// Clean up when tabs close
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabHeaders[tabId];
  saveTabHeaders();
});

// Scan a single tab: fetch its URL from the background to trigger webRequest
function scanTab(tab) {
  if (!isHttpUrl(tab.url)) return;
  // The service worker's fetch() runs in the regular profile, so re-requesting an
  // Incognito page would leave traces of it (HSTS, DNS, connection state) there.
  if (tab.incognito) return;
  if (tabHeaders[tab.id]) return; // Already have data

  const url = tab.url;

  fetchForHeaders(url)
    .then(({ response, webReqData }) => {
      const finalUrl = response.url;

      // Null-prototype object, same as the webRequest listener (see note there)
      const headers = Object.create(null);
      if (webReqData && webReqData.headers) Object.assign(headers, webReqData.headers);
      response.headers.forEach((value, name) => {
        if (!headers[name.toLowerCase()]) headers[name.toLowerCase()] = value;
      });

      const data = {
        url: finalUrl,
        statusCode: response.status,
        headers: headers,
        cookies: (webReqData && webReqData.cookies) ? webReqData.cookies : [],
        redirects: (webReqData && webReqData.redirects) ? webReqData.redirects : [],
        timestamp: Date.now(),
        supplemented: true
      };

      tabHeaders[tab.id] = data;
      saveTabHeaders();

      setBadge(tab.id, data);
    })
    .catch((err) => {
      // Network error or restricted page: mark the tab so the popup can show why
      if (!isTimeout(err) && !tabHeaders[tab.id]) {
        tabHeaders[tab.id] = failureEntry(err, url);
        saveTabHeaders();
        clearBadge(tab.id);
      }
    });
}

// On startup / install, scan all existing tabs in batches to avoid flooding
const SCAN_BATCH_SIZE = 3;
const SCAN_BATCH_DELAY = 500; // ms between batches

// Only when background re-checks are turned on in the settings
function scanAllTabs() {
  settingsReady.then(() => {
    if (settings.autoFetch) chrome.tabs.query({}, scanTabsInBatches);
  });
}

function scanTabsInBatches(tabs) {
  const queue = tabs.filter(tab => isHttpUrl(tab.url) && !tab.incognito && !tabHeaders[tab.id]);

  function processNext(i) {
    if (i >= queue.length) return;
    const batch = queue.slice(i, i + SCAN_BATCH_SIZE);
    for (const tab of batch) {
      scanTab(tab);
    }
    setTimeout(() => processNext(i + SCAN_BATCH_SIZE), SCAN_BATCH_DELAY);
  }

  processNext(0);
}

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    // Tabs that were open before the extension existed have no captured headers
    scanAllTabs();
    chrome.tabs.create({ url: chrome.runtime.getURL("welcome.html") });
  }

  // Create right-click context menu items. removeAll first so an update can change
  // existing items instead of failing on duplicate ids. Only offered on web pages,
  // so local file paths and internal URLs are never sent to the scanners.
  chrome.contextMenus.removeAll(() => {
    const documentUrlPatterns = ["http://*/*", "https://*/*"];
    chrome.contextMenus.create({
      id: "scan-securityheaders",
      title: "Scan on SecurityHeaders.com",
      contexts: ["page"],
      documentUrlPatterns
    });
    chrome.contextMenus.create({
      id: "scan-ssllabs",
      title: "Scan on SSL Labs",
      contexts: ["page"],
      documentUrlPatterns
    });
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (!tab || !tab.url) return;
  const target = scanTargetUrl(tab.url);
  if (!target) return;
  const hostname = new URL(target).hostname;

  if (info.menuItemId === "scan-securityheaders") {
    chrome.tabs.create({ url: `https://securityheaders.com/?q=${encodeURIComponent(target)}&hide=on&followRedirects=on` });
  } else if (info.menuItemId === "scan-ssllabs") {
    chrome.tabs.create({ url: `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(hostname)}&hideResults=on&latest` });
  }
});


// Check if captured data looks incomplete
// Only re-check when the captured data is really incomplete: nothing was captured,
// or the page came from the browser cache (which drops HSTS and Set-Cookie). A page
// loaded from the network is complete, even if it has no HSTS.
function needsSupplementaryFetch(tabId) {
  const data = tabHeaders[tabId];
  if (data && (data.restricted || data.loadError)) return false; // Already tried and failed
  // Already re-requested once for this page load. Without this, every in-page
  // navigation (hash change, SPA route change) would send another request.
  if (data && data.supplemented) return false;
  if (!data || !data.headers) return true;
  return !!data.cacheIncomplete;
}

// Headers the browser drops from responses it keeps in its HTTP cache
const HEADERS_DROPPED_BY_CACHE = ["strict-transport-security", "public-key-pins", "public-key-pins-report-only"];

const withoutFragment = (url) => (url || "").split("#")[0];

// Merge headers from a supplementary fetch into existing tab data.
function mergeSupplementaryData(tabId, webReqData, requestedUrl) {
  if (!webReqData || !webReqData.headers) return;
  // Our fetch skips the cache, so its headers are complete
  rememberNetworkHeaders(webReqData.url, webReqData);

  const existing = tabHeaders[tabId];
  if (existing && existing.headers) {
    // The tab may have loaded another page of the same site in the meantime
    if (existing.url !== webReqData.url && withoutFragment(existing.url) !== withoutFragment(requestedUrl)) return;
    let changed = false;
    if (existing.cacheIncomplete) {
      delete existing.cacheIncomplete;
      changed = true;
    }
    // Only fill in what the cache dropped: the page's own response is the reference
    for (const name of HEADERS_DROPPED_BY_CACHE) {
      if (webReqData.headers[name] && !existing.headers[name]) {
        existing.headers[name] = webReqData.headers[name];
        changed = true;
      }
    }
    if ((!existing.redirects || existing.redirects.length === 0) && webReqData.redirects && webReqData.redirects.length > 0) {
      existing.redirects = webReqData.redirects;
      changed = true;
    }
    if (webReqData.cookies && webReqData.cookies.length > 0 && (!existing.cookies || existing.cookies.length === 0)) {
      existing.cookies = webReqData.cookies;
      changed = true;
    }
    if (changed) {
      setBadge(tabId, existing);
      saveTabHeaders();
    }
  } else {
    tabHeaders[tabId] = {
      url: webReqData.url,
      statusCode: webReqData.statusCode,
      headers: Object.assign(Object.create(null), webReqData.headers),
      cookies: webReqData.cookies || [],
      redirects: webReqData.redirects || [],
      timestamp: Date.now(),
      supplemented: true
    };
    setBadge(tabId, tabHeaders[tabId]);
    saveTabHeaders();
  }
}

// Throttle supplementary fetches from tabs.onUpdated. Queue them so only
// a few run at a time when many tabs finish loading at once.
const supplementaryQueue = [];
let activeFetches = 0;
const MAX_CONCURRENT_FETCHES = 2;

const pendingSupplementary = new Set();

function enqueueSupplementaryFetch(tabId, url) {
  if (pendingSupplementary.has(tabId)) return;
  pendingSupplementary.add(tabId);
  if (tabHeaders[tabId]) tabHeaders[tabId].supplemented = true;
  supplementaryQueue.push({ tabId, url });
  drainSupplementaryQueue();
}

// Calls back only if the tab is still on the same site as `url`. Results of a slow
// fetch must not be stored for a tab that has since navigated to another site.
function ifTabStillAt(tabId, url, callback) {
  chrome.tabs.get(tabId, (tab) => {
    if (chrome.runtime.lastError || !tab || !sameOrigin(tab.url, url)) return;
    callback();
  });
}

function drainSupplementaryQueue() {
  while (activeFetches < MAX_CONCURRENT_FETCHES && supplementaryQueue.length > 0) {
    const { tabId, url } = supplementaryQueue.shift();
    activeFetches++;

    fetchForHeaders(url)
      .then(({ webReqData }) => {
        if (!webReqData) return;
        ifTabStillAt(tabId, url, () => mergeSupplementaryData(tabId, webReqData, url));
      })
      .catch((err) => {
        if (isTimeout(err)) return;
        if (!tabHeaders[tabId] || !tabHeaders[tabId].headers) {
          ifTabStillAt(tabId, url, () => {
            if (tabHeaders[tabId] && (tabHeaders[tabId].headers || tabHeaders[tabId].loadError)) return;
            tabHeaders[tabId] = failureEntry(err, url);
            saveTabHeaders();
            clearBadge(tabId);
          });
        }
      })
      .finally(() => {
        pendingSupplementary.delete(tabId);
        activeFetches--;
        drainSupplementaryQueue();
      });
  }
}

// When a tab moves to another site, clear stale headers from the previous page.
// Without this, navigating from an intermediate page (e.g. Teams redirect)
// to a restricted page (e.g. Chrome Web Store) would show the old headers.
// Same-origin URL changes are kept: hash changes and SPA route changes don't
// load a new document, and a real page load replaces the entry anyway.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    const old = tabHeaders[tabId];
    if (old && old.url && !sameOrigin(old.url, changeInfo.url)) {
      delete tabHeaders[tabId];
      clearBadge(tabId);
      saveTabHeaders();
    }
  }

  if (changeInfo.status === "complete") {
    if (tabHeaders[tabId] && tabHeaders[tabId].headers) {
      setBadge(tabId, tabHeaders[tabId]);
    }

    // Automatic re-requests only when turned on in the settings
    settingsReady.then(() => {
      if (settings.autoFetch && isHttpUrl(tab.url) && !tab.incognito && needsSupplementaryFetch(tabId)) {
        enqueueSupplementaryFetch(tabId, tab.url);
      }
    });
  }
});

// Respond to popup requests
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Only this extension's own pages (the popup) may talk to the background.
  // Content scripts would also carry our sender.id, so check the page origin too.
  if (sender.id !== chrome.runtime.id || !sender.url || !sender.url.startsWith(EXTENSION_ORIGIN + "/")) return;
  if (!message || typeof message.tabId !== "number") return;
  const tabId = message.tabId;

  if (message.type === "getHeaders") {
    sendResponse(tabHeaders[tabId] || null);
  }

  if (message.type === "fetchHeaders") {
    // Fetch the URL the tab is actually showing, never a URL supplied by the caller,
    // so this can't be used to make the extension request arbitrary addresses.
    chrome.tabs.get(tabId, (tab) => {
      if (chrome.runtime.lastError || !tab || !isHttpUrl(tab.url)) {
        sendResponse(tabHeaders[tabId] || null);
        return;
      }
      if (tab.incognito) {
        // Never re-requested (see scanTab); say so, so the popup doesn't suggest a rescan
        const entry = tabHeaders[tabId];
        sendResponse(entry ? { ...entry, incognitoNoRecheck: true } : null);
        return;
      }
      const url = tab.url;

      fetchForHeaders(url)
        .then(({ webReqData }) => {
          const result = webReqData;

          const existing = tabHeaders[tabId];
          if (result && result.headers) {
            // Our fetch skips the cache, so its headers are complete
            rememberNetworkHeaders(result.url, result);
            if (existing && existing.headers) {
              // The fresh headers replace the old ones, so a header the site stopped
              // sending disappears. Our request carries no cookies, so the site may not
              // set any: keep the ones from the page load.
              if ((!result.cookies || result.cookies.length === 0) && existing.cookies && existing.cookies.length > 0) {
                result.cookies = existing.cookies;
              }
              // The page load's redirect chain says more than the one from our fetch
              if (existing.redirects && existing.redirects.length > 0) result.redirects = existing.redirects;
            }
            result.supplemented = true;
            tabHeaders[tabId] = result;
            saveTabHeadersNow();

            setBadge(tabId, result);
            sendResponse(result);
            return;
          }

          // The request worked but its headers never reached webRequest
          sendResponse(existing && existing.headers ? { ...existing, rescanFailed: "no headers received" } : (existing || null));
        })
        .catch((err) => {
          const existing = tabHeaders[tabId];
          // Headers captured while the page loaded prove the page isn't restricted, so a
          // failed rescan (network error, blocked request, timeout) keeps them.
          if (existing && existing.headers) {
            sendResponse({ ...existing, rescanFailed: err.netError || (isTimeout(err) ? "timed out" : "request blocked") });
            return;
          }
          if (isTimeout(err)) {
            sendResponse(existing || null);
            return;
          }
          const failure = failureEntry(err, url);
          tabHeaders[tabId] = failure;
          saveTabHeaders();
          clearBadge(tabId);
          sendResponse(failure);
        });
    });

    return true; // Keep channel open for async response
  }
});

