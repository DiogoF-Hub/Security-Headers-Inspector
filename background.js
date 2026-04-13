// MV2 persistent background page — webRequest works fully here.
// Store headers per tab in memory (persistent background never goes idle).
const tabHeaders = {};

// Also store headers captured from background fetches (keyed by URL).
// These are short-lived — only needed for the fetch→webRequest handoff.
const fetchedHeaders = {};

// Prune stale fetchedHeaders entries every 60 seconds to prevent memory leak.
// Entries older than 30s have already been consumed or abandoned.
setInterval(() => {
  const cutoff = Date.now() - 30000;
  for (const url of Object.keys(fetchedHeaders)) {
    if (fetchedHeaders[url].timestamp < cutoff) {
      delete fetchedHeaders[url];
    }
  }
}, 60000);

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const headers = {};
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
        // 304 Not Modified — server sends minimal headers.
        // Keep the existing full header set, just update the timestamp.
        tabHeaders[details.tabId].timestamp = Date.now();
      } else {
        // Full response — store all headers
        // Preserve cookies from previous load if server didn't send new ones
        // (servers skip Set-Cookie when browser already has the cookies)
        if (cookies.length === 0 && tabHeaders[details.tabId] && tabHeaders[details.tabId].cookies && tabHeaders[details.tabId].cookies.length > 0) {
          data.cookies = tabHeaders[details.tabId].cookies;
        }
        tabHeaders[details.tabId] = data;
      }

      // Update badge (use whatever data we have for this tab)
      const grade = computeGrade(tabHeaders[details.tabId].headers);
      chrome.browserAction.setBadgeText({ tabId: details.tabId, text: grade.letter });
      chrome.browserAction.setBadgeBackgroundColor({ tabId: details.tabId, color: grade.color });
    } else {
      // Could be a fetch from this background page — store by URL
      fetchedHeaders[details.url] = data;
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders", "extraHeaders"]
);

// Clean up when tabs close
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabHeaders[tabId];
});

// Scan a single tab: fetch its URL from the background to trigger webRequest
// (which captures ALL headers including HSTS), then use that data.
// Response headers are only used as a fallback since browsers hide HSTS from fetch().
function scanTab(tab) {
  if (!tab.url || (!tab.url.startsWith("http://") && !tab.url.startsWith("https://"))) return;
  if (tabHeaders[tab.id]) return; // Already have data

  const url = tab.url;
  delete fetchedHeaders[url]; // Clear stale data

  fetch(url, { credentials: "omit", cache: "no-store" })
    .then((response) => {
      const finalUrl = response.url;

      // Give webRequest listener time to store captured headers
      setTimeout(() => {
        // Prefer webRequest data — it sees ALL headers including HSTS
        // (browsers strip HSTS from fetch() Response objects)
        const webReqData = fetchedHeaders[url] || fetchedHeaders[finalUrl];

        let headers;
        if (webReqData && webReqData.headers) {
          // Start with webRequest headers (includes HSTS)
          headers = { ...webReqData.headers };
          // Fill in anything webRequest missed from the Response
          response.headers.forEach((value, name) => {
            if (!headers[name.toLowerCase()]) headers[name.toLowerCase()] = value;
          });
        } else {
          // Fallback: Response headers only (no HSTS, but better than nothing)
          headers = {};
          response.headers.forEach((value, name) => {
            headers[name.toLowerCase()] = value;
          });
        }

        // Carry over cookies from webRequest data if available
        const cookies = (webReqData && webReqData.cookies) ? webReqData.cookies : [];

        const data = {
          url: finalUrl,
          statusCode: response.status,
          headers: headers,
          cookies: cookies,
          timestamp: Date.now()
        };

        tabHeaders[tab.id] = data;

        const grade = computeGrade(headers);
        chrome.browserAction.setBadgeText({ tabId: tab.id, text: grade.letter });
        chrome.browserAction.setBadgeBackgroundColor({ tabId: tab.id, color: grade.color });
      }, 150);
    })
    .catch(() => {});
}

// On startup / install, scan all existing tabs so badges show immediately
function scanAllTabs() {
  chrome.tabs.query({}, (tabs) => {
    for (const tab of tabs) {
      scanTab(tab);
    }
  });
}

chrome.runtime.onInstalled.addListener(() => {
  scanAllTabs();

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

// Check if captured data looks incomplete — missing headers that webRequest
// should have seen. This triggers a supplementary fetch to fill gaps.
function needsSupplementaryFetch(tabId, url) {
  const data = tabHeaders[tabId];
  // No data at all — definitely need to fetch
  if (!data || !data.headers) return true;
  // For HTTPS sites, check if key security headers are suspiciously absent.
  // HSTS is the most commonly missed header (stripped from cache/bfcache).
  // If we have very few headers overall, the capture was likely incomplete.
  if (url.startsWith("https://")) {
    const h = data.headers;
    const headerCount = Object.keys(h).length;
    // Very few headers suggests a cache hit with minimal data
    if (headerCount < 5) return true;
    // HSTS is the header most often missed from cached responses
    if (!h["strict-transport-security"]) return true;
  }
  return false;
}

// Merge headers from a supplementary fetch into existing tab data.
// Only adds missing headers — never overwrites what webRequest already captured.
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
      chrome.browserAction.setBadgeText({ tabId: tabId, text: newGrade.letter });
      chrome.browserAction.setBadgeBackgroundColor({ tabId: tabId, color: newGrade.color });
    }
  } else {
    // No existing data — use the fetch result directly
    tabHeaders[tabId] = {
      url: webReqData.url,
      statusCode: webReqData.statusCode,
      headers: { ...webReqData.headers },
      cookies: webReqData.cookies || [],
      timestamp: Date.now()
    };
    const newGrade = computeGrade(tabHeaders[tabId].headers);
    chrome.browserAction.setBadgeText({ tabId: tabId, text: newGrade.letter });
    chrome.browserAction.setBadgeBackgroundColor({ tabId: tabId, color: newGrade.color });
  }
}

// When a tab finishes loading, ensure the badge is set and headers are complete.
// Chrome/Brave clears per-tab badges on navigation, so we must re-apply.
// If key headers appear missing (e.g. HSTS from cached responses), do a
// supplementary fetch to fill the gaps without fetching for every single tab.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete") {
    if (tabHeaders[tabId]) {
      const grade = computeGrade(tabHeaders[tabId].headers);
      chrome.browserAction.setBadgeText({ tabId: tabId, text: grade.letter });
      chrome.browserAction.setBadgeBackgroundColor({ tabId: tabId, color: grade.color });
    }

    if (tab.url && (tab.url.startsWith("http://") || tab.url.startsWith("https://")) && needsSupplementaryFetch(tabId, tab.url)) {
      const url = tab.url;
      delete fetchedHeaders[url];

      fetch(url, { credentials: "omit", cache: "no-store" })
        .then(() => {
          setTimeout(() => {
            const webReqData = fetchedHeaders[url];
            // Also check final URL after redirects
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
        .catch(() => {});
    }
  }
});

// Respond to popup requests
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "getHeaders") {
    sendResponse(tabHeaders[message.tabId] || null);
  }

  if (message.type === "fetchHeaders") {
    // Do a fetch from the background page — this triggers webRequest
    // which captures ALL headers including HSTS
    const url = message.url;
    const tabId = message.tabId;
    delete fetchedHeaders[url]; // Clear any stale data

    fetch(url, { credentials: "omit", cache: "no-store" })
      .then((response) => {
        const finalUrl = response.url;
        // Small delay to let webRequest listener finish storing
        setTimeout(() => {
          // Check both original URL and final URL (after redirects)
          const result = fetchedHeaders[url] || fetchedHeaders[finalUrl] || null;

          // Save to tabHeaders so data persists across reloads
          if (result && tabId) {
            // Merge: keep existing cookies if the fresh fetch didn't capture new ones
            if ((!result.cookies || result.cookies.length === 0) && tabHeaders[tabId] && tabHeaders[tabId].cookies && tabHeaders[tabId].cookies.length > 0) {
              result.cookies = tabHeaders[tabId].cookies;
            }
            tabHeaders[tabId] = result;

            // Update badge
            const grade = computeGrade(result.headers);
            chrome.browserAction.setBadgeText({ tabId: tabId, text: grade.letter });
            chrome.browserAction.setBadgeBackgroundColor({ tabId: tabId, color: grade.color });
          }

          sendResponse(result);
        }, 150);
      })
      .catch(() => {
        sendResponse(null);
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
// Source: https://snyk.io/blog/website-security-score-explained/
// and https://scotthelme.co.uk/scoring-transparency-on-securityheaders-io/
const HEADER_WEIGHTS = {
  "content-security-policy":   25,
  "strict-transport-security": 25,
  "x-frame-options":           20,
  "x-content-type-options":    20,
  "referrer-policy":           15,
  "permissions-policy":        15
};
const MAX_SCORE = 120; // sum of all weights

// CSP quality penalty — caps score if script-src has unsafe-inline/unsafe-eval
// IMPORTANT: keep in sync with the identical function in popup.js
function applyCSPPenalty(csp, score) {
  if (!csp) return score;
  const directives = {};
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
    letter = "A+"; color = "#2ecc40";
  } else if (pct >= 75) {
    letter = "A"; color = "#2ecc40";
  } else if (pct >= 60) {
    letter = "B"; color = "#99cc00";
  } else if (pct >= 50) {
    letter = "C"; color = "#ffdc00";
  } else if (pct >= 15) {
    letter = "D"; color = "#ff851b";
  } else if (pct >= 5) {
    letter = "E"; color = "#ff4136";
  } else {
    letter = "F"; color = "#cc0000";
  }

  return { letter, color, present, total, score, pct };
}
