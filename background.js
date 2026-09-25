// MV3 service worker. webRequest observation is still available.
// State is persisted via chrome.storage.session since service workers are ephemeral.

// storage.session keeps its default TRUSTED_CONTEXTS access level: it holds captured
// Set-Cookie values, and only extension pages (which are trusted) need to read it.

// Origin of this extension, used to recognise requests made by our own fetch() calls.
const EXTENSION_ORIGIN = new URL(chrome.runtime.getURL("")).origin;

// Background fetches that never return headers must not hold a queue slot forever.
const FETCH_TIMEOUT_MS = 10000;

// --- Storage helpers ---
// Service workers can go idle at any time, so tab state lives in storage.session.
// We keep a local cache to avoid async reads on every webRequest event.
let tabHeaders = {};
// Headers captured from this extension's own fetch() calls. Only read ~150ms after the
// fetch resolves, so it stays in memory and is never persisted.
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
    chrome.storage.session.set({ tabHeaders });
    saveTabHeadersTimer = null;
  }, 300);
}

function saveTabHeadersNow() {
  if (saveTabHeadersTimer) clearTimeout(saveTabHeadersTimer);
  saveTabHeadersTimer = null;
  chrome.storage.session.set({ tabHeaders });
}

// Prune stale fetchedHeaders entries via chrome.alarms (setInterval doesn't survive idle)
chrome.alarms.create("prune-fetched-headers", { periodInMinutes: 1 });

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
function setBadge(tabId, headers) {
  const grade = computeGrade(headers);
  chrome.action.setBadgeText({ tabId, text: grade.letter }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color: grade.color }).catch(() => {});
}

function sameOrigin(a, b) {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

function isHttpUrl(url) {
  return typeof url === "string" && (url.startsWith("http://") || url.startsWith("https://"));
}

// URL handed to external scanners. Drops credentials, query string and fragment,
// which can carry tokens (reset links, OAuth codes) that shouldn't leave the browser.
function scanTargetUrl(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u.origin + u.pathname;
  } catch {
    return null;
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

// Fetch a page from the service worker so webRequest can see its full header set.
// Resolves with the Response and the headers webRequest captured for it; rejects
// for pages the browser doesn't let extensions read.
function fetchForHeaders(url) {
  if (isKnownRestricted(url)) return Promise.reject(restrictedError());
  delete fetchedHeaders[url];
  // Default (cors) mode on purpose: host permissions make every site readable, while
  // no-cors requests are blocked by Cross-Origin-Resource-Policy: same-origin.
  return fetch(url, { credentials: "omit", cache: "no-store", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) })
    .then((response) => {
      // Only the headers are needed, don't download the body
      if (response.body) response.body.cancel().catch(() => {});
      return new Promise((resolve) => {
        // Give webRequest listener time to store captured headers
        setTimeout(() => {
          // Prefer the final URL: after a redirect, fetchedHeaders[url] holds the 3xx hop
          const webReqData = fetchedHeaders[response.url] || fetchedHeaders[url] || null;
          resolve({ response, webReqData });
        }, 150);
      });
    });
}

// A timeout says nothing about whether the page is restricted, so don't flag it as such.
function isTimeout(err) {
  return err && (err.name === "TimeoutError" || err.name === "AbortError");
}

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    // Only two kinds of response are useful: top-level page loads in a tab, and
    // responses to this extension's own fetch() calls. Everything else (images,
    // XHRs, other extensions' requests) is skipped so their cookies and URLs
    // are never captured.
    const isPageLoad = details.type === "main_frame" && details.tabId >= 0;
    const isOwnFetch = details.tabId === -1 && details.initiator === EXTENSION_ORIGIN;
    if (!isPageLoad && !isOwnFetch) return;

    // Object.create(null) avoids prototype pollution if a server sends a header
    // named __proto__ or constructor — those would mutate a regular object's prototype.
    const headers = Object.create(null);
    const cookies = [];
    for (const header of details.responseHeaders) {
      const name = header.name.toLowerCase();
      if (name === "set-cookie") {
        cookies.push(header.value);
      }
      headers[name] = header.value;
    }

    const data = {
      url: details.url,
      statusCode: details.statusCode,
      headers: headers,
      cookies: cookies,
      timestamp: Date.now()
    };

    if (isPageLoad) {
      if (details.statusCode === 304 && tabHeaders[details.tabId] && tabHeaders[details.tabId].headers) {
        // 304 Not Modified, server sends minimal headers.
        // Keep the existing full header set, just update the timestamp.
        tabHeaders[details.tabId].timestamp = Date.now();
      } else {
        // Full response, store all headers
        // Preserve cookies from previous load if server didn't send new ones
        if (cookies.length === 0 && tabHeaders[details.tabId] && tabHeaders[details.tabId].cookies && tabHeaders[details.tabId].cookies.length > 0) {
          data.cookies = tabHeaders[details.tabId].cookies;
        }
        tabHeaders[details.tabId] = data;
      }

      setBadge(details.tabId, tabHeaders[details.tabId].headers);

      saveTabHeaders();
    } else {
      // A fetch from this service worker, store by URL
      fetchedHeaders[details.url] = data;
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

      const cookies = (webReqData && webReqData.cookies) ? webReqData.cookies : [];

      const data = {
        url: finalUrl,
        statusCode: response.status,
        headers: headers,
        cookies: cookies,
        timestamp: Date.now(),
        supplemented: true
      };

      tabHeaders[tab.id] = data;
      saveTabHeaders();

      setBadge(tab.id, headers);
    })
    .catch((err) => {
      // Fetch blocked (CORS, restricted domain, etc.), mark tab so popup can show why
      if (!isTimeout(err) && !tabHeaders[tab.id]) {
        tabHeaders[tab.id] = { restricted: true, url: url, timestamp: Date.now() };
        saveTabHeaders();
      }
    });
}

// On startup / install, scan all existing tabs in batches to avoid flooding
const SCAN_BATCH_SIZE = 3;
const SCAN_BATCH_DELAY = 500; // ms between batches

function scanAllTabs() {
  chrome.tabs.query({}, (tabs) => {
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
  });
}

chrome.runtime.onInstalled.addListener((details) => {
  scanAllTabs();

  if (details.reason === "install") {
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

chrome.runtime.onStartup.addListener(scanAllTabs);

// Check if captured data looks incomplete
function needsSupplementaryFetch(tabId, url) {
  const data = tabHeaders[tabId];
  if (data && data.restricted) return false; // Already tried and failed
  // Already re-requested once for this page load. Without this, every in-page
  // navigation (hash change, SPA route change) on an HTTPS site without HSTS
  // would send another request to the site.
  if (data && data.supplemented) return false;
  if (!data || !data.headers) return true;
  if (url.startsWith("https://")) {
    const h = data.headers;
    const headerCount = Object.keys(h).length;
    if (headerCount < 5) return true;
    if (!h["strict-transport-security"]) return true;
  }
  return false;
}

// Merge headers from a supplementary fetch into existing tab data.
function mergeSupplementaryData(tabId, webReqData) {
  if (!webReqData || !webReqData.headers) return;

  const existing = tabHeaders[tabId];
  if (existing && existing.headers) {
    let changed = false;
    for (const [name, value] of Object.entries(webReqData.headers)) {
      if (!existing.headers[name]) {
        existing.headers[name] = value;
        changed = true;
      }
    }
    if (webReqData.cookies && webReqData.cookies.length > 0 && (!existing.cookies || existing.cookies.length === 0)) {
      existing.cookies = webReqData.cookies;
      changed = true;
    }
    if (changed) {
      setBadge(tabId, existing.headers);
      saveTabHeaders();
    }
  } else {
    tabHeaders[tabId] = {
      url: webReqData.url,
      statusCode: webReqData.statusCode,
      headers: Object.assign(Object.create(null), webReqData.headers),
      cookies: webReqData.cookies || [],
      timestamp: Date.now(),
      supplemented: true
    };
    setBadge(tabId, tabHeaders[tabId].headers);
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
        ifTabStillAt(tabId, url, () => mergeSupplementaryData(tabId, webReqData));
      })
      .catch((err) => {
        if (isTimeout(err)) return;
        if (!tabHeaders[tabId] || !tabHeaders[tabId].headers) {
          ifTabStillAt(tabId, url, () => {
            tabHeaders[tabId] = { restricted: true, url: url, timestamp: Date.now() };
            saveTabHeaders();
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
      chrome.action.setBadgeText({ tabId: tabId, text: "" }).catch(() => {});
      saveTabHeaders();
    }
  }

  if (changeInfo.status === "complete") {
    if (tabHeaders[tabId] && tabHeaders[tabId].headers) {
      setBadge(tabId, tabHeaders[tabId].headers);
    }

    if (isHttpUrl(tab.url) && !tab.incognito && needsSupplementaryFetch(tabId, tab.url)) {
      enqueueSupplementaryFetch(tabId, tab.url);
    }
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
      if (chrome.runtime.lastError || !tab || !isHttpUrl(tab.url) || tab.incognito) {
        sendResponse(tabHeaders[tabId] || null);
        return;
      }
      const url = tab.url;

      fetchForHeaders(url)
        .then(({ webReqData }) => {
          const result = webReqData;

          if (result && result.headers) {
            const existing = tabHeaders[tabId];
            if (existing && existing.headers) {
              // Merge: new headers win, but keep any existing ones the new fetch missed
              result.headers = Object.assign(Object.create(null), existing.headers, result.headers);
              if ((!result.cookies || result.cookies.length === 0) && existing.cookies && existing.cookies.length > 0) {
                result.cookies = existing.cookies;
              }
            }
            result.supplemented = true;
            tabHeaders[tabId] = result;
            saveTabHeadersNow();

            setBadge(tabId, result.headers);
          }

          sendResponse(result || tabHeaders[tabId] || null);
        })
        .catch((err) => {
          if (isTimeout(err)) {
            sendResponse(tabHeaders[tabId] || null);
            return;
          }
          const restricted = { restricted: true, url: url, timestamp: Date.now() };
          tabHeaders[tabId] = restricted;
          saveTabHeaders();
          sendResponse(restricted);
        });
    });

    return true; // Keep channel open for async response
  }
});

// Security headers we evaluate
const SECURITY_HEADERS = [
  "content-security-policy",
  "permissions-policy",
  "referrer-policy",
  "strict-transport-security",
  "x-content-type-options",
  "x-frame-options"
];

// Weighted scoring matching securityheaders.com methodology
const HEADER_WEIGHTS = {
  "content-security-policy":   25,
  "strict-transport-security": 25,
  "x-frame-options":           20,
  "x-content-type-options":    20,
  "referrer-policy":           15,
  "permissions-policy":        15
};
const MAX_SCORE = 120;

// Parse a CSP header into { directive: [sources] } the way browsers read it:
// directive names and keywords are case-insensitive, and when a directive is
// repeated only the first occurrence counts. Without this, a policy like
// "script-src 'unsafe-inline'; script-src 'self'" would be graded as safe.
// Object.create(null) prevents a CSP directive named __proto__ from mutating the prototype.
// IMPORTANT: keep in sync with the identical function in popup.js
function parseCSP(csp) {
  const directives = Object.create(null);
  for (const d of csp.toLowerCase().split(";")) {
    const parts = d.trim().split(/\s+/);
    if (!parts[0] || parts[0] in directives) continue;
    directives[parts[0]] = parts.slice(1);
  }
  return directives;
}

// HSTS max-age in seconds, or null when there is no valid max-age.
// Directive names are case-insensitive and the value may be quoted (RFC 6797).
// IMPORTANT: keep in sync with the identical function in popup.js
function hstsMaxAge(val) {
  if (!val) return null;
  const m = val.match(/max-age\s*=\s*"?(\d+)/i);
  return m ? parseInt(m[1], 10) : null;
}

// Whether a scored header actually protects the page. HSTS with max-age=0 tells
// browsers to delete the policy, and one without max-age is ignored, so neither
// counts. CSP frame-ancestors stands in for a missing X-Frame-Options.
// IMPORTANT: keep in sync with the identical function in popup.js
function countsAsPresent(h, headers) {
  if (h === "strict-transport-security") return hstsMaxAge(headers[h]) > 0;
  if (h === "x-frame-options" && !headers[h]) return "frame-ancestors" in parseCSP(headers["content-security-policy"] || "");
  return !!headers[h];
}

// CSP quality penalty: caps score if script-src has unsafe-inline/unsafe-eval
function applyCSPPenalty(csp, score) {
  if (!csp) return score;
  const directives = parseCSP(csp);
  const scriptSrc = directives["script-src"] || directives["default-src"] || [];
  const hasStrictDynamic = scriptSrc.includes("'strict-dynamic'");
  const hasNonce = scriptSrc.some(s => s.startsWith("'nonce-"));
  const hasHash = scriptSrc.some(s => /^'sha(256|384|512)-/.test(s));

  if (scriptSrc.includes("'unsafe-inline'") && !hasStrictDynamic && !hasNonce && !hasHash) {
    score = Math.min(score, MAX_SCORE * 0.82);
  }
  if (scriptSrc.some(s => s === "'unsafe-eval'")) {
    score = Math.min(score, MAX_SCORE * 0.82);
  }
  return score;
}

function computeGrade(headers) {
  const csp = headers["content-security-policy"] || "";

  let score = 0;
  let present = 0;
  const total = SECURITY_HEADERS.length;

  for (const h of SECURITY_HEADERS) {
    if (countsAsPresent(h, headers)) {
      score += HEADER_WEIGHTS[h] || 0;
      present++;
    }
  }

  score = applyCSPPenalty(csp, score);

  const pct = (score / MAX_SCORE) * 100;
  let letter, color;

  if (pct >= 95) {
    letter = "A+"; color = "#4ec83d";
  } else if (pct >= 75) {
    letter = "A"; color = "#41a832";
  } else if (pct >= 60) {
    letter = "B"; color = "#ffd242";
  } else if (pct >= 50) {
    letter = "C"; color = "#ffd242";
  } else if (pct >= 15) {
    letter = "D"; color = "#ffa500";
  } else if (pct >= 5) {
    letter = "E"; color = "#ffa500";
  } else {
    letter = "F"; color = "#ff0000";
  }

  return { letter, color, present, total, score, pct };
}
