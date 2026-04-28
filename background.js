// MV3 service worker. webRequest observation is still available.
// State is persisted via chrome.storage.session since service workers are ephemeral.

// Allow storage.session to be accessed by the popup too
chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_AND_UNTRUSTED_CONTEXTS" });

// --- Storage helpers ---
// Service workers can go idle at any time, so all state lives in storage.session.
// We keep a local cache to avoid async reads on every webRequest event.
let tabHeaders = {};
let fetchedHeaders = {};

// Load state from storage on service worker startup
chrome.storage.session.get(["tabHeaders", "fetchedHeaders"], (result) => {
  if (result.tabHeaders) tabHeaders = result.tabHeaders;
  if (result.fetchedHeaders) fetchedHeaders = result.fetchedHeaders;
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

let saveFetchedHeadersTimer = null;
function saveFetchedHeaders() {
  if (saveFetchedHeadersTimer) clearTimeout(saveFetchedHeadersTimer);
  saveFetchedHeadersTimer = setTimeout(() => {
    chrome.storage.session.set({ fetchedHeaders });
    saveFetchedHeadersTimer = null;
  }, 300);
}

// Prune stale fetchedHeaders entries via chrome.alarms (setInterval doesn't survive idle)
chrome.alarms.create("prune-fetched-headers", { periodInMinutes: 1 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "prune-fetched-headers") {
    const cutoff = Date.now() - 30000;
    let changed = false;
    for (const url of Object.keys(fetchedHeaders)) {
      if (fetchedHeaders[url].timestamp < cutoff) {
        delete fetchedHeaders[url];
        changed = true;
      }
    }
    if (changed) saveFetchedHeaders();
  }
});

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
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

    if (details.type === "main_frame") {
      if (details.statusCode === 304 && tabHeaders[details.tabId]) {
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

      // Update badge
      const grade = computeGrade(tabHeaders[details.tabId].headers);
      chrome.action.setBadgeText({ tabId: details.tabId, text: grade.letter });
      chrome.action.setBadgeBackgroundColor({ tabId: details.tabId, color: grade.color });

      saveTabHeaders();
    } else {
      // Could be a fetch from this service worker, store by URL
      fetchedHeaders[details.url] = data;
      saveFetchedHeaders();
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
  if (!tab.url || (!tab.url.startsWith("http://") && !tab.url.startsWith("https://"))) return;
  if (tabHeaders[tab.id]) return; // Already have data

  const url = tab.url;
  delete fetchedHeaders[url];

  fetch(url, { credentials: "omit", cache: "no-store" })
    .then((response) => {
      const finalUrl = response.url;

      // Give webRequest listener time to store captured headers
      setTimeout(() => {
        const webReqData = fetchedHeaders[url] || fetchedHeaders[finalUrl];

        let headers;
        if (webReqData && webReqData.headers) {
          headers = { ...webReqData.headers };
          response.headers.forEach((value, name) => {
            if (!headers[name.toLowerCase()]) headers[name.toLowerCase()] = value;
          });
        } else {
          headers = {};
          response.headers.forEach((value, name) => {
            headers[name.toLowerCase()] = value;
          });
        }

        const cookies = (webReqData && webReqData.cookies) ? webReqData.cookies : [];

        const data = {
          url: finalUrl,
          statusCode: response.status,
          headers: headers,
          cookies: cookies,
          timestamp: Date.now()
        };

        tabHeaders[tab.id] = data;
        saveTabHeaders();

        const grade = computeGrade(headers);
        chrome.action.setBadgeText({ tabId: tab.id, text: grade.letter });
        chrome.action.setBadgeBackgroundColor({ tabId: tab.id, color: grade.color });
      }, 150);
    })
    .catch(() => {
      // Fetch blocked (CORS, restricted domain, etc.), mark tab so popup can show why
      if (!tabHeaders[tab.id]) {
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
    const queue = tabs.filter(tab =>
      tab.url && (tab.url.startsWith("http://") || tab.url.startsWith("https://")) && !tabHeaders[tab.id]
    );

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

  // Create right-click context menu items
  chrome.contextMenus.create({
    id: "scan-securityheaders",
    title: "Scan on SecurityHeaders.com",
    contexts: ["page"]
  });
  chrome.contextMenus.create({
    id: "scan-ssllabs",
    title: "Scan on SSL Labs",
    contexts: ["page"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (!tab || !tab.url) return;
  let hostname;
  try { hostname = new URL(tab.url).hostname; } catch { return; }

  if (info.menuItemId === "scan-securityheaders") {
    chrome.tabs.create({ url: `https://securityheaders.com/?q=${encodeURIComponent(tab.url)}&hide=on&followRedirects=on` });
  } else if (info.menuItemId === "scan-ssllabs") {
    chrome.tabs.create({ url: `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(hostname)}&hideResults=on&latest` });
  }
});

chrome.runtime.onStartup.addListener(scanAllTabs);

// Check if captured data looks incomplete
function needsSupplementaryFetch(tabId, url) {
  const data = tabHeaders[tabId];
  if (data && data.restricted) return false; // Already tried and failed
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
      const newGrade = computeGrade(existing.headers);
      chrome.action.setBadgeText({ tabId: tabId, text: newGrade.letter });
      chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: newGrade.color });
      saveTabHeaders();
    }
  } else {
    tabHeaders[tabId] = {
      url: webReqData.url,
      statusCode: webReqData.statusCode,
      headers: { ...webReqData.headers },
      cookies: webReqData.cookies || [],
      timestamp: Date.now()
    };
    const newGrade = computeGrade(tabHeaders[tabId].headers);
    chrome.action.setBadgeText({ tabId: tabId, text: newGrade.letter });
    chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: newGrade.color });
    saveTabHeaders();
  }
}

// Throttle supplementary fetches from tabs.onUpdated. Queue them so only
// a few run at a time when many tabs finish loading at once.
const supplementaryQueue = [];
let activeFetches = 0;
const MAX_CONCURRENT_FETCHES = 2;

function enqueueSupplementaryFetch(tabId, url) {
  supplementaryQueue.push({ tabId, url });
  drainSupplementaryQueue();
}

function drainSupplementaryQueue() {
  while (activeFetches < MAX_CONCURRENT_FETCHES && supplementaryQueue.length > 0) {
    const { tabId, url } = supplementaryQueue.shift();
    activeFetches++;
    delete fetchedHeaders[url];

    fetch(url, { credentials: "omit", cache: "no-store" })
      .then(() => {
        setTimeout(() => {
          const webReqData = fetchedHeaders[url];
          if (!webReqData) {
            for (const key of Object.keys(fetchedHeaders)) {
              if (fetchedHeaders[key].timestamp > Date.now() - 5000) {
                mergeSupplementaryData(tabId, fetchedHeaders[key]);
                return;
              }
            }
            return;
          }
          mergeSupplementaryData(tabId, webReqData);
        }, 150);
      })
      .catch(() => {
        if (!tabHeaders[tabId] || !tabHeaders[tabId].headers) {
          tabHeaders[tabId] = { restricted: true, url: url, timestamp: Date.now() };
          saveTabHeaders();
        }
      })
      .finally(() => {
        activeFetches--;
        drainSupplementaryQueue();
      });
  }
}

// When a tab's URL changes, clear stale headers from the previous page.
// Without this, navigating from an intermediate page (e.g. Teams redirect)
// to a restricted page (e.g. Chrome Web Store) would show the old headers.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    const old = tabHeaders[tabId];
    if (old && old.url && old.url !== changeInfo.url) {
      delete tabHeaders[tabId];
      chrome.action.setBadgeText({ tabId: tabId, text: "" });
      saveTabHeaders();
    }
  }

  if (changeInfo.status === "complete") {
    if (tabHeaders[tabId] && tabHeaders[tabId].headers) {
      const grade = computeGrade(tabHeaders[tabId].headers);
      chrome.action.setBadgeText({ tabId: tabId, text: grade.letter });
      chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: grade.color });
    }

    if (tab.url && (tab.url.startsWith("http://") || tab.url.startsWith("https://")) && needsSupplementaryFetch(tabId, tab.url)) {
      enqueueSupplementaryFetch(tabId, tab.url);
    }
  }
});

// Respond to popup requests
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "getHeaders") {
    sendResponse(tabHeaders[message.tabId] || null);
  }

  if (message.type === "fetchHeaders") {
    const url = message.url;
    const tabId = message.tabId;
    delete fetchedHeaders[url];

    fetch(url, { credentials: "omit", cache: "no-store" })
      .then((response) => {
        const finalUrl = response.url;
        setTimeout(() => {
          const result = fetchedHeaders[url] || fetchedHeaders[finalUrl] || null;

          if (result && result.headers && tabId) {
            const existing = tabHeaders[tabId];
            if (existing && existing.headers) {
              // Merge: new headers win, but keep any existing ones the new fetch missed
              const merged = { ...existing.headers, ...result.headers };
              result.headers = merged;
              if ((!result.cookies || result.cookies.length === 0) && existing.cookies && existing.cookies.length > 0) {
                result.cookies = existing.cookies;
              }
            }
            tabHeaders[tabId] = result;
            saveTabHeadersNow();

            const grade = computeGrade(result.headers);
            chrome.action.setBadgeText({ tabId: tabId, text: grade.letter });
            chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: grade.color });
          }

          sendResponse(result || tabHeaders[tabId] || null);
        }, 150);
      })
      .catch(() => {
        const restricted = { restricted: true, url: url, timestamp: Date.now() };
        if (tabId) {
          tabHeaders[tabId] = restricted;
          saveTabHeaders();
        }
        sendResponse(restricted);
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

// CSP quality penalty: caps score if script-src has unsafe-inline/unsafe-eval
function applyCSPPenalty(csp, score) {
  if (!csp) return score;
  // Object.create(null) prevents a CSP directive named __proto__ from mutating the prototype.
  const directives = Object.create(null);
  csp.split(";").forEach((d) => {
    const parts = d.trim().split(/\s+/);
    if (parts.length > 0) directives[parts[0]] = parts.slice(1);
  });
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
  const hasFrameAncestors = /frame-ancestors\s/.test(csp);

  let score = 0;
  let present = 0;
  const total = SECURITY_HEADERS.length;

  for (const h of SECURITY_HEADERS) {
    const isPresent = headers[h] || (h === "x-frame-options" && hasFrameAncestors);
    if (isPresent) {
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
