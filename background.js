// MV2 persistent background page — webRequest works fully here.
// Store headers per tab in memory (persistent background never goes idle).
const tabHeaders = {};

// Also store headers captured from background fetches (keyed by URL)
const fetchedHeaders = {};

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const headers = {};
    for (const header of details.responseHeaders) {
      headers[header.name.toLowerCase()] = header.value;
    }

    const data = {
      url: details.url,
      statusCode: details.statusCode,
      headers: headers,
      timestamp: Date.now()
    };

    if (details.type === "main_frame") {
      if (details.statusCode === 304 && tabHeaders[details.tabId]) {
        // 304 Not Modified — server sends minimal headers.
        // Keep the existing full header set, just update the timestamp.
        tabHeaders[details.tabId].timestamp = Date.now();
      } else {
        // Full response — store all headers
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
  ["responseHeaders"]
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

        const data = {
          url: finalUrl,
          statusCode: response.status,
          headers: headers,
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

chrome.runtime.onInstalled.addListener(scanAllTabs);
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
    delete fetchedHeaders[url]; // Clear any stale data

    fetch(url, { credentials: "omit", cache: "no-store" })
      .then((response) => {
        const finalUrl = response.url;
        // Small delay to let webRequest listener finish storing
        setTimeout(() => {
          // Check both original URL and final URL (after redirects)
          sendResponse(fetchedHeaders[url] || fetchedHeaders[finalUrl] || null);
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

function computeGrade(headers) {
  // If X-Frame-Options is missing but CSP has frame-ancestors, count it as present
  // (securityheaders.com does this — frame-ancestors is the modern replacement)
  const csp = headers["content-security-policy"] || "";
  const hasFrameAncestors = /frame-ancestors\s/.test(csp);

  let present = 0;
  for (const h of SECURITY_HEADERS) {
    if (headers[h]) {
      present++;
    } else if (h === "x-frame-options" && hasFrameAncestors) {
      present++;
    }
  }

  let bonusCount = 0;
  for (const h of BONUS_HEADERS) {
    if (headers[h]) bonusCount++;
  }

  const ratio = present / SECURITY_HEADERS.length;
  let letter, color;

  if (ratio === 1 && bonusCount >= 2) {
    letter = "A+"; color = "#2ecc40";
  } else if (ratio >= 0.83) {
    letter = "A"; color = "#2ecc40";
  } else if (ratio >= 0.66) {
    letter = "B"; color = "#99cc00";
  } else if (ratio >= 0.5) {
    letter = "C"; color = "#ffdc00";
  } else if (ratio >= 0.33) {
    letter = "D"; color = "#ff851b";
  } else if (ratio >= 0.16) {
    letter = "E"; color = "#ff4136";
  } else {
    letter = "F"; color = "#cc0000";
  }

  return { letter, color };
}
