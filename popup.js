// Header definitions: what to check, how to evaluate, descriptions
const SECURITY_HEADERS = {
  "content-security-policy": {
    label: "Content-Security-Policy",
    about: "Content Security Policy is an effective measure to protect your site from XSS attacks. By whitelisting sources of approved content, you can prevent the browser from loading malicious assets. It lets you define where scripts, styles, images, fonts, and other resources can be loaded from.",
    good: "A well-configured CSP significantly reduces the risk of cross-site scripting and data injection attacks. It acts as a second layer of defense against injection vulnerabilities.",
    recommendation: "Start with a strict policy like <code>default-src 'none'</code> and selectively allow only what your site needs. Avoid <code>'unsafe-inline'</code> and <code>'unsafe-eval'</code> when possible as they weaken protection considerably.",
    evaluate: (val) => {
      if (!val) return { status: "bad", msg: "Missing — your site has no Content Security Policy, leaving it vulnerable to XSS and data injection attacks." };
      // Parse directives to check unsafe values in the right context
      const directives = {};
      val.split(";").forEach((d) => {
        const parts = d.trim().split(/\s+/);
        if (parts.length > 0) directives[parts[0]] = parts.slice(1).join(" ");
      });
      const scriptSrc = directives["script-src"] || directives["default-src"] || "";
      // Check for 'unsafe-eval' in script-src but not 'wasm-unsafe-eval'
      const hasUnsafeEval = /(?<![w-])unsafe-eval/.test(scriptSrc);
      // Check for 'unsafe-inline' in script-src only (it's acceptable in style-src)
      const hasUnsafeInline = scriptSrc.includes("unsafe-inline");
      if (hasUnsafeInline && hasUnsafeEval)
        return { status: "warn", msg: "Present but script-src uses 'unsafe-inline' and 'unsafe-eval', which significantly weaken XSS protection." };
      if (hasUnsafeInline)
        return { status: "warn", msg: "Present but script-src uses 'unsafe-inline', which weakens XSS protection by allowing inline scripts." };
      if (hasUnsafeEval)
        return { status: "warn", msg: "Present but script-src uses 'unsafe-eval', which allows dynamic code execution via eval()." };
      return { status: "good", msg: "Well configured — approved content sources are whitelisted." };
    }
  },
  "permissions-policy": {
    label: "Permissions-Policy",
    about: "Permissions Policy (formerly Feature Policy) allows you to control which browser features and APIs can be used on your page. This includes sensitive capabilities like camera, microphone, geolocation, payment, and USB access.",
    good: "Restricting unused features reduces your attack surface. Even if an attacker injects code, they cannot access features you've disabled. It also prevents third-party iframes from using powerful features without your consent.",
    recommendation: "Disable all features you don't use with an empty allowlist, e.g. <code>camera=()</code>, <code>microphone=()</code>. Only enable features your site actually requires.",
    evaluate: (val) => {
      if (!val) return { status: "bad", msg: "Missing — any embedded content can request access to browser features like camera, microphone, and geolocation." };
      return { status: "good", msg: "Browser feature access is restricted via policy." };
    }
  },
  "referrer-policy": {
    label: "Referrer-Policy",
    about: "Referrer Policy controls how much referrer information (the URL of the previous page) the browser includes when navigating away from your site. Without it, full URLs — potentially containing sensitive data like tokens, user IDs, or internal paths — can leak to third parties.",
    good: "A strict referrer policy prevents leaking private URL paths and query parameters to external sites. This is especially important for pages that contain sensitive information in the URL.",
    recommendation: "Use <code>strict-origin-when-cross-origin</code> (a good default), <code>same-origin</code> (strictest — no referrer to other sites), or <code>no-referrer</code> (never send referrer). Avoid <code>unsafe-url</code> which sends the full URL everywhere.",
    evaluate: (val) => {
      if (!val) return { status: "bad", msg: "Missing — full referrer URLs (including paths and query strings) may leak to external sites." };
      const strong = ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"];
      if (strong.includes(val.trim().toLowerCase()))
        return { status: "good", msg: `Set to "${val.trim()}" — referrer information is properly restricted.` };
      return { status: "warn", msg: `Set to "${val.trim()}" — consider a stricter policy like "strict-origin-when-cross-origin" or "same-origin".` };
    }
  },
  "strict-transport-security": {
    label: "Strict-Transport-Security",
    about: "HTTP Strict Transport Security (HSTS) tells the browser to always use HTTPS when connecting to your site, even if the user types http:// or clicks an HTTP link. This prevents protocol downgrade attacks and cookie hijacking on insecure connections.",
    good: "HSTS ensures all communication is encrypted. Once the browser sees this header, it will refuse to connect over plain HTTP for the specified duration, protecting against man-in-the-middle attacks on the initial connection.",
    recommendation: "Set <code>max-age</code> to at least 31536000 (1 year). Add <code>includeSubDomains</code> to protect all subdomains. Add <code>preload</code> and submit your site to the HSTS preload list for protection on the very first visit.",
    evaluate: (val) => {
      if (!val) return { status: "bad", msg: "Missing — connections can be downgraded to unencrypted HTTP, exposing data to interception." };
      const maxAgeMatch = val.match(/max-age=(\d+)/);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
      const hasSub = val.toLowerCase().includes("includesubdomains");
      const hasPreload = val.toLowerCase().includes("preload");
      if (maxAge >= 31536000 && hasSub && hasPreload)
        return { status: "good", msg: `Excellent — max-age=${maxAge} (${Math.round(maxAge/86400)} days), includeSubDomains, and preload are all set.` };
      if (maxAge >= 31536000)
        return { status: "good", msg: `max-age=${maxAge} is good. Consider adding includeSubDomains and preload for complete coverage.` };
      if (maxAge < 2592000)
        return { status: "warn", msg: `max-age is only ${maxAge} seconds (${Math.round(maxAge/86400)} days). Recommend at least 31536000 (1 year).` };
      return { status: "good", msg: `max-age=${maxAge}.` };
    }
  },
  "x-content-type-options": {
    label: "X-Content-Type-Options",
    about: "X-Content-Type-Options stops the browser from trying to MIME-sniff the content type of a response and forces it to use the declared Content-Type. Without this, a browser might interpret a file differently than intended — for example, treating a plain text file as JavaScript.",
    good: "Setting this header to 'nosniff' prevents MIME-type confusion attacks. An attacker cannot trick the browser into executing a non-script resource as code, which is a common vector for XSS via uploaded files.",
    recommendation: "Always set this to <code>nosniff</code>. There is no reason not to — it has no side effects on properly configured sites.",
    evaluate: (val) => {
      if (!val) return { status: "bad", msg: "Missing — the browser may MIME-sniff responses and interpret files as a different content type than intended." };
      if (val.trim().toLowerCase() === "nosniff")
        return { status: "good", msg: "Set to 'nosniff' — MIME-type sniffing is blocked." };
      return { status: "warn", msg: `Unexpected value: "${val}". The only valid value is "nosniff".` };
    }
  },
  "x-frame-options": {
    label: "X-Frame-Options",
    about: "X-Frame-Options tells the browser whether your site is allowed to be embedded in iframes on other sites. This is the primary defense against clickjacking attacks, where an attacker overlays your site with invisible frames to trick users into clicking on hidden elements.",
    good: "Preventing framing stops attackers from embedding your site in a malicious page. Users cannot be tricked into unknowingly clicking buttons or links on your site through transparent overlay attacks.",
    recommendation: "Set to <code>DENY</code> (no framing at all) or <code>SAMEORIGIN</code> (only your own site can frame it). Note: the CSP <code>frame-ancestors</code> directive is the modern replacement and takes precedence if set.",
    evaluate: (val) => {
      if (!val) return { status: "bad", msg: "Missing — your site can be embedded in iframes by any page, making it vulnerable to clickjacking." };
      const v = val.trim().toUpperCase();
      if (v === "DENY" || v === "SAMEORIGIN")
        return { status: "good", msg: `Set to "${v}" — clickjacking protection is active.` };
      return { status: "warn", msg: `Set to "${val}" — consider using DENY or SAMEORIGIN.` };
    }
  }
};

const ADDITIONAL_HEADERS = {
  "cross-origin-opener-policy": {
    label: "Cross-Origin-Opener-Policy",
    about: "Cross-Origin Opener Policy (COOP) controls whether your window can be referenced by cross-origin pages. It severs the link between your page and any cross-origin window that opened it (or that it opened), preventing cross-origin attacks via the window.opener reference.",
    good: "Enabling COOP isolates your browsing context. Cross-origin pages cannot manipulate your window object, preventing attacks like Spectre-based side-channel data leaks and cross-origin window manipulation.",
    recommendation: "Set to <code>same-origin</code> for maximum isolation. Use <code>same-origin-allow-popups</code> if your site needs to open cross-origin popups (e.g. OAuth flows).",
    evaluate: (val) => {
      if (!val) return { status: "info", msg: "Not set — cross-origin windows may be able to reference your page. Consider adding for cross-origin isolation." };
      return { status: "good", msg: `Set to "${val.trim()}" — cross-origin window access is restricted.` };
    }
  },
  "cross-origin-resource-policy": {
    label: "Cross-Origin-Resource-Policy",
    about: "Cross-Origin Resource Policy (CORP) lets you control which origins can load your resources (images, scripts, etc.). It prevents other websites from embedding your resources without permission, protecting against data leaks and Spectre-style side-channel attacks.",
    good: "Restricting who can load your resources prevents unauthorized sites from reading your content. This is particularly important for authenticated resources that should not be accessible cross-origin.",
    recommendation: "Set to <code>same-origin</code> if your resources should only be loaded by your own site. Use <code>same-site</code> to allow subdomains. Use <code>cross-origin</code> only for public resources like CDN assets.",
    evaluate: (val) => {
      if (!val) return { status: "info", msg: "Not set — any origin can load your resources. Consider restricting this." };
      return { status: "good", msg: `Set to "${val.trim()}" — resource loading is restricted by origin.` };
    }
  },
  "cross-origin-embedder-policy": {
    label: "Cross-Origin-Embedder-Policy",
    about: "Cross-Origin Embedder Policy (COEP) ensures that all resources loaded by your page have explicitly opted in to being loaded (via CORS or CORP headers). Combined with COOP, it enables full cross-origin isolation, unlocking APIs like SharedArrayBuffer.",
    good: "COEP prevents your page from loading cross-origin resources that haven't granted permission. This blocks speculative execution attacks (like Spectre) from leaking data across origins.",
    recommendation: "Set to <code>require-corp</code> for full isolation. Note: all cross-origin resources must include appropriate CORS or CORP headers, or they will be blocked.",
    evaluate: (val) => {
      if (!val) return { status: "info", msg: "Not set — recommended for full cross-origin isolation (required for SharedArrayBuffer)." };
      return { status: "good", msg: `Set to "${val.trim()}" — cross-origin resource loading requires explicit permission.` };
    }
  },
  "x-xss-protection": {
    label: "X-XSS-Protection",
    about: "X-XSS-Protection controlled the XSS Auditor built into older browsers (Chrome < 78, Edge < 79). The auditor attempted to detect reflected XSS attacks and block or sanitize the response. However, it was found to have bypasses and could itself introduce vulnerabilities.",
    good: "Modern browsers have removed the XSS Auditor entirely. Setting this to '0' is now recommended to disable it in any remaining older browsers, as the auditor itself could be exploited. Content Security Policy is the proper replacement.",
    recommendation: "Set to <code>0</code> to disable the legacy auditor. Rely on a strong Content-Security-Policy header instead for XSS protection.",
    evaluate: (val) => {
      if (!val) return { status: "info", msg: "Not set — not required if you have a Content Security Policy. The legacy XSS Auditor has been removed from modern browsers." };
      if (val.trim() === "0")
        return { status: "good", msg: "Set to '0' — legacy XSS Auditor is disabled. CSP should be used for XSS protection instead." };
      return { status: "warn", msg: `Set to "${val.trim()}" — consider setting to '0' to disable the flawed legacy auditor, and rely on CSP instead.` };
    }
  }
};

// Grade computation
function computeGrade(headers) {
  const securityKeys = Object.keys(SECURITY_HEADERS);
  let present = 0;
  for (const h of securityKeys) {
    if (headers[h]) present++;
  }

  const bonusHeaders = ["cross-origin-opener-policy", "cross-origin-resource-policy", "cross-origin-embedder-policy"];
  let bonusCount = 0;
  for (const h of bonusHeaders) {
    if (headers[h]) bonusCount++;
  }

  const ratio = present / securityKeys.length;
  let letter, cssClass;

  if (ratio === 1 && bonusCount >= 2) {
    letter = "A+"; cssClass = "grade-aplus";
  } else if (ratio === 1) {
    letter = "A"; cssClass = "grade-a";
  } else if (ratio >= 0.83) {
    letter = "B"; cssClass = "grade-b";
  } else if (ratio >= 0.66) {
    letter = "C"; cssClass = "grade-c";
  } else if (ratio >= 0.5) {
    letter = "D"; cssClass = "grade-d";
  } else if (ratio >= 0.33) {
    letter = "E"; cssClass = "grade-e";
  } else {
    letter = "F"; cssClass = "grade-f";
  }

  return { letter, cssClass, present, total: securityKeys.length };
}

// Ask the background page to fetch headers — the background's fetch triggers
// webRequest which can see ALL headers including HSTS
function fetchHeadersViaBackground(url) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "fetchHeaders", url: url }, (response) => {
      resolve(response);
    });
  });
}

// Build the UI
function render(data) {
  const noData = document.getElementById("no-data");
  const header = document.getElementById("header");
  const quickStatus = document.getElementById("quick-status");
  const toggleBtn = document.getElementById("toggle-details");

  if (!data || !data.headers || Object.keys(data.headers).length === 0) {
    noData.classList.remove("hidden");
    header.style.display = "none";
    quickStatus.style.display = "none";
    toggleBtn.style.display = "none";
    return;
  }

  const headers = data.headers;
  const grade = computeGrade(headers);

  // Grade badge
  const badge = document.getElementById("grade-badge");
  badge.textContent = grade.letter;
  badge.className = grade.cssClass;

  // Site info
  try {
    const url = new URL(data.url);
    document.getElementById("site-url").textContent = url.hostname;
  } catch {
    document.getElementById("site-url").textContent = data.url;
  }
  document.getElementById("site-summary").textContent =
    `${grade.present}/${grade.total} security headers present`;

  // Quick status pills
  quickStatus.innerHTML = "";
  for (const [key, def] of Object.entries(SECURITY_HEADERS)) {
    const pill = document.createElement("span");
    pill.className = `status-pill ${headers[key] ? "present" : "missing"}`;
    pill.textContent = def.label;
    quickStatus.appendChild(pill);
  }

  // Security headers detail list
  const secList = document.getElementById("security-headers-list");
  secList.innerHTML = "";
  for (const [key, def] of Object.entries(SECURITY_HEADERS)) {
    secList.appendChild(createHeaderItem(key, def, headers[key]));
  }

  // Additional headers detail list
  const addList = document.getElementById("additional-headers-list");
  addList.innerHTML = "";
  for (const [key, def] of Object.entries(ADDITIONAL_HEADERS)) {
    addList.appendChild(createHeaderItem(key, def, headers[key]));
  }

  // Raw headers
  const rawContainer = document.getElementById("raw-headers");
  rawContainer.innerHTML = "";
  const sortedKeys = Object.keys(headers).sort();
  for (const key of sortedKeys) {
    const row = document.createElement("div");
    row.className = "raw-row";
    row.innerHTML = `<span class="raw-key">${escapeHtml(key)}</span><span class="raw-val">${escapeHtml(headers[key])}</span>`;
    rawContainer.appendChild(row);
  }
}

function createHeaderItem(key, def, value) {
  const result = def.evaluate(value);
  const item = document.createElement("div");
  item.className = `header-item ${result.status}`;

  const statusIcons = { good: "\u2714", bad: "\u2718", warn: "\u26A0", info: "\u2139" };

  item.innerHTML = `
    <div class="header-name">
      <span>${def.label}</span>
      <span class="status-icon ${result.status}">${statusIcons[result.status]}</span>
    </div>
    <div class="header-value">${value ? escapeHtml(value) : '<em style="color:#ff4136;">Not set</em>'}</div>
    <div class="header-desc">
      <div class="desc-verdict">${result.msg}</div>
      <div class="desc-section">
        <div class="desc-title">What is this?</div>
        <div class="desc-text">${def.about}</div>
      </div>
      <div class="desc-section">
        <div class="desc-title">Why it matters</div>
        <div class="desc-text">${def.good}</div>
      </div>
      <div class="desc-section">
        <div class="desc-title">Recommendation</div>
        <div class="desc-text">${def.recommendation}</div>
      </div>
    </div>
  `;

  item.querySelector(".header-name").addEventListener("click", () => {
    item.classList.toggle("expanded");
  });

  return item;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// Wire up toggle button
document.getElementById("toggle-details").addEventListener("click", function () {
  const details = document.getElementById("details");
  const isCollapsed = details.classList.contains("collapsed");
  details.classList.toggle("collapsed");
  this.classList.toggle("expanded");
  this.innerHTML = isCollapsed
    ? 'Hide Details <span class="arrow">&#9650;</span>'
    : 'Show Details <span class="arrow">&#9660;</span>';
});

// Wire up raw headers toggle
document.getElementById("raw-toggle").addEventListener("click", function () {
  const raw = document.getElementById("raw-headers");
  raw.classList.toggle("collapsed");
  this.classList.toggle("expanded");
});

function renderInternalPage(url) {
  document.getElementById("header").style.display = "none";
  document.getElementById("quick-status").style.display = "none";
  document.getElementById("toggle-details").style.display = "none";

  const el = document.getElementById("internal-page");
  el.classList.remove("hidden");

  document.getElementById("internal-scheme").textContent = (url || "").split(/[?#]/)[0].substring(0, 60) + ((url || "").length > 60 ? "..." : "");
}

// Init: ask background for headers (MV2 persistent background has them in memory),
// fall back to XHR for tabs loaded before extension was installed
chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
  if (!tabs[0]) {
    render(null);
    return;
  }

  const tab = tabs[0];
  const url = tab.url;

  if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) {
    renderInternalPage(url);
    return;
  }

  // Show scanning state
  let hostname = url;
  try { hostname = new URL(url).hostname; } catch {}
  document.getElementById("site-url").textContent = hostname;
  document.getElementById("site-summary").textContent = "Fetching headers...";

  // Ask persistent background page for cached headers (from page navigation)
  chrome.runtime.sendMessage({ type: "getHeaders", tabId: tab.id }, async (response) => {
    if (response && response.headers && Object.keys(response.headers).length > 0) {
      render(response);
    } else {
      // No cached data — ask background to fetch the URL.
      // The background's fetch triggers webRequest, which captures ALL headers (including HSTS).
      const data = await fetchHeadersViaBackground(url);
      render(data);
    }
  });
});
