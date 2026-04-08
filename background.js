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
      // Normal page navigation — store by tab ID
      tabHeaders[details.tabId] = data;

      // Update badge
      const grade = computeGrade(headers);
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

    fetch(url, { credentials: "omit" })
      .then(() => {
        // Small delay to let webRequest listener finish storing
        setTimeout(() => {
          sendResponse(fetchedHeaders[url] || null);
        }, 100);
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
  let present = 0;
  for (const h of SECURITY_HEADERS) {
    if (headers[h]) present++;
  }

  let bonusCount = 0;
  for (const h of BONUS_HEADERS) {
    if (headers[h]) bonusCount++;
  }

  const ratio = present / SECURITY_HEADERS.length;
  let letter, color;

  if (ratio === 1 && bonusCount >= 2) {
    letter = "A+"; color = "#2ecc40";
  } else if (ratio === 1) {
    letter = "A"; color = "#2ecc40";
  } else if (ratio >= 0.83) {
    letter = "B"; color = "#99cc00";
  } else if (ratio >= 0.66) {
    letter = "C"; color = "#ffdc00";
  } else if (ratio >= 0.5) {
    letter = "D"; color = "#ff851b";
  } else if (ratio >= 0.33) {
    letter = "E"; color = "#ff4136";
  } else {
    letter = "F"; color = "#cc0000";
  }

  return { letter, color };
}
