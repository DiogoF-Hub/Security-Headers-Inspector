// MV2 persistent background page — webRequest works fully here.
// Store headers per tab in memory (persistent background never goes idle).
const tabHeaders = {};

// Also store headers captured from background fetches (keyed by URL)
const fetchedHeaders = {};

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
    chrome.tabs.create({ url: `https://securityheaders.com/?q=${encodeURIComponent(hostname)}&hide=on&followRedirects=on` });
  } else if (info.menuItemId === "scan-ssllabs") {
    chrome.tabs.create({ url: `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(hostname)}&hideResults=on&latest` });
  }
});
chrome.runtime.onStartup.addListener(scanAllTabs);

// When a tab finishes loading, ensure the badge is set.
// Chrome/Brave clears per-tab badges on navigation, so we must re-apply.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete") {
    if (tabHeaders[tabId]) {
      // webRequest already captured headers — just re-apply the badge
      const grade = computeGrade(tabHeaders[tabId].headers);
      chrome.browserAction.setBadgeText({ tabId: tabId, text: grade.letter });
      chrome.browserAction.setBadgeBackgroundColor({ tabId: tabId, color: grade.color });
    } else {
      // No cached data (tab loaded before extension, or cached page) — scan it
      scanTab(tab);
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

const BONUS_HEADERS = [
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
  "cross-origin-embedder-policy"
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

  // CSP quality penalties (caps effective score)
  if (csp) {
    const directives = {};
    csp.split(";").forEach((d) => {
      const parts = d.trim().split(/\s+/);
      if (parts.length > 0) directives[parts[0]] = parts.slice(1);
    });
    const scriptSrc = directives["script-src"] || directives["default-src"] || [];
    const hasStrictDynamic = scriptSrc.includes("'strict-dynamic'");
    const hasNonce = scriptSrc.some(s => s.startsWith("'nonce-"));
    const hasHash = scriptSrc.some(s => /^'sha(256|384|512)-/.test(s));

    // unsafe-inline without strict-dynamic/nonce/hash: CSP is significantly weakened
    if (scriptSrc.includes("'unsafe-inline'") && !hasStrictDynamic && !hasNonce && !hasHash) {
      score = Math.min(score, MAX_SCORE * 0.82); // cap below A+
    }
    // unsafe-eval: penalty
    if (scriptSrc.some(s => s === "'unsafe-eval'")) {
      score = Math.min(score, MAX_SCORE * 0.82);
    }
  }

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
  } else if (pct >= 29) {
    letter = "D"; color = "#ff851b";
  } else if (pct >= 14) {
    letter = "E"; color = "#ff4136";
  } else {
    letter = "F"; color = "#cc0000";
  }

  return { letter, color, present, total, score, pct };
}
