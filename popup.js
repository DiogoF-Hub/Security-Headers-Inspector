// Popup UI. Header definitions, cookie analysis and grading live in analysis.js.

let settings = { ...DEFAULT_SETTINGS };

// Ask the background page to fetch headers. The background's fetch triggers
// webRequest which can see ALL headers including HSTS. The background looks up
// the tab's URL itself, so only the tab id is sent.
function fetchHeadersViaBackground(tabId) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "fetchHeaders", tabId: tabId }, (response) => {
      resolve(response);
    });
  });
}

// Store current headers and cookies for copy button
let currentHeaders = null;
let currentCookies = [];

// --- Accessibility helpers --------------------------------------------------------

// Make a non-button element act as a toggle button: focusable, Enter/Space, aria-expanded.
// onToggle returns the new expanded state.
function makeToggle(trigger, onToggle) {
  trigger.setAttribute("role", "button");
  trigger.tabIndex = 0;
  trigger.setAttribute("aria-expanded", "false");
  const run = () => trigger.setAttribute("aria-expanded", String(!!onToggle()));
  trigger.addEventListener("click", run);
  trigger.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      run();
    }
  });
}

// Blurred cookie value that can be revealed with a click or the keyboard
function makeRevealable(el) {
  if (!settings.blurCookies) {
    el.classList.add("revealed", "always-visible");
    return;
  }
  el.setAttribute("role", "button");
  el.tabIndex = 0;
  el.setAttribute("aria-pressed", "false");
  el.setAttribute("aria-label", "Cookie value hidden. Press to reveal.");
  const toggle = (e) => {
    e.stopPropagation();
    const shown = el.classList.toggle("revealed");
    el.setAttribute("aria-pressed", String(shown));
    el.setAttribute("aria-label", shown ? "Cookie value shown. Press to hide." : "Cookie value hidden. Press to reveal.");
  };
  el.addEventListener("click", toggle);
  el.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      toggle(e);
    }
  });
}

const STATUS_ICONS = {
  good: ["✔", "Good"],
  bad: ["✘", "Problem"],
  warn: ["⚠", "Warning"],
  info: ["ℹ", "Information"]
};

function statusIconHtml(status) {
  const [icon, label] = STATUS_ICONS[status];
  return `<span class="status-icon ${status}" role="img" aria-label="${label}">${icon}</span>`;
}

// Expandable card: the row toggles the "expanded" class on the item
function makeExpandable(item, rowSelector) {
  makeToggle(item.querySelector(rowSelector), () => item.classList.toggle("expanded"));
}

// --- Rendering ----------------------------------------------------------------------

function setDetailsOpen(open) {
  const toggleBtn = document.getElementById("toggle-details");
  document.getElementById("details").classList.toggle("show", open);
  toggleBtn.classList.toggle("expanded", open);
  toggleBtn.setAttribute("aria-expanded", String(open));
  // One arrow glyph: the .expanded class rotates it to point up
  toggleBtn.innerHTML = `${open ? "Hide" : "Show"} Details <span class="arrow" aria-hidden="true">&#9660;</span>`;
}

// Build the UI
function render(data) {
  const noData = document.getElementById("no-data");
  const header = document.getElementById("header");
  const quickStatus = document.getElementById("quick-status");
  const toggleBtn = document.getElementById("toggle-details");

  // Reset UI state so rescans start fresh
  noData.classList.add("hidden");
  header.style.display = "";
  quickStatus.style.display = "";
  toggleBtn.style.display = "";
  document.getElementById("external-scans").style.display = "";
  document.getElementById("internal-page").classList.add("hidden");
  document.getElementById("restricted-page").classList.add("hidden");

  // Reset expandable sections to collapsed
  setDetailsOpen(false);
  for (const [toggleId, contentId] of [["raw-toggle", "raw-headers"], ["breakdown-toggle", "breakdown"]]) {
    document.getElementById(contentId).classList.remove("show");
    const toggle = document.getElementById(toggleId);
    toggle.classList.remove("expanded");
    toggle.setAttribute("aria-expanded", "false");
  }

  if (!data || !data.headers || Object.keys(data.headers).length === 0) {
    // A page that failed to load (site down, TLS error, blocked) has no headers to check
    document.getElementById("no-data-title").textContent = data && data.loadError
      ? "This page didn't load, so there are no headers to check."
      : "No headers available for this page.";
    document.getElementById("no-data-hint").textContent = data && data.loadError
      ? `The browser reported ${data.loadError}. Reload the page, then open this popup again.`
      : "Try navigating to a regular website.";
    noData.classList.remove("hidden");
    header.style.display = "none";
    quickStatus.style.display = "none";
    toggleBtn.style.display = "none";
    document.getElementById("external-scans").style.display = "none";
    return;
  }

  const headers = data.headers;
  currentHeaders = headers;
  const grade = computeGrade(headers, data.url);
  const ctx = { url: data.url, redirects: data.redirects || [] };

  // Resolve cookies once: webRequest array, falling back to headers["set-cookie"]
  let resolvedCookies = data.cookies || [];
  if (resolvedCookies.length === 0 && headers["set-cookie"]) {
    resolvedCookies = [headers["set-cookie"]];
  }
  currentCookies = resolvedCookies;

  // Grade badge
  const badge = document.getElementById("grade-badge");
  badge.textContent = grade.letter;
  badge.className = grade.cssClass;
  badge.setAttribute("aria-label", `Grade ${grade.letter}`);

  // Site info
  try {
    const url = new URL(data.url);
    document.getElementById("site-url").textContent = url.hostname;
  } catch {
    document.getElementById("site-url").textContent = data.url;
  }
  let summary = `${grade.present}/${grade.total} security headers present. Score: ${Math.round(grade.pct)}%`;
  if (data.rescanFailed) summary += `. Rescan failed (${data.rescanFailed}), showing the last result`;
  else if (data.cacheIncomplete && data.incognitoNoRecheck) summary += ". Loaded from cache: HSTS and cookies may be missing (Incognito pages are never re-requested)";
  else if (data.cacheIncomplete) summary += ". Loaded from cache: HSTS and cookies may be missing, press rescan";
  document.getElementById("site-summary").textContent = summary;

  // Quick status pills
  quickStatus.innerHTML = "";
  for (const b of grade.breakdown) {
    const pill = document.createElement("span");
    pill.className = `status-pill ${b.counts ? "present" : "missing"}`;
    pill.textContent = b.label;
    pill.title = b.reason;
    pill.setAttribute("aria-label", `${b.label}: ${b.counts ? "present" : "missing or not effective"}`);
    quickStatus.appendChild(pill);
  }

  renderBreakdown(grade);
  renderRedirects(ctx.redirects);

  // Security headers detail list
  const secList = document.getElementById("security-headers-list");
  secList.innerHTML = "";
  for (const [key, def] of Object.entries(SECURITY_HEADERS)) {
    secList.appendChild(createHeaderItem(key, def, headers[key], headers, ctx, grade));
  }

  // Additional headers detail list
  const addList = document.getElementById("additional-headers-list");
  addList.innerHTML = "";
  for (const [key, def] of Object.entries(ADDITIONAL_HEADERS)) {
    addList.appendChild(createHeaderItem(key, def, headers[key], headers, ctx, grade));
  }

  // Cookie analysis
  const cookieSection = document.getElementById("cookie-section");
  const cookieList = document.getElementById("cookie-list");
  cookieList.innerHTML = "";
  if (resolvedCookies.length > 0) {
    cookieSection.style.display = "";
    for (const cookieStr of resolvedCookies) {
      const analysis = analyzeCookie(cookieStr);
      const allGood = analysis.issues.length === 0;

      const item = document.createElement("div");
      item.className = `cookie-item ${allGood ? "cookie-good" : "cookie-warn"}`;

      const flagsHtml = analysis.flags.map(f =>
        `<span class="cookie-flag good">${escapeHtml(f)}</span>`
      ).join("");

      const missing = [];
      if (analysis.rejected.length > 0) missing.push("Rejected");
      if (!analysis.hasSecure) missing.push("Secure");
      if (!analysis.hasHttpOnly) missing.push("HttpOnly");
      if (!analysis.sameSite) missing.push("SameSite");
      if (!analysis.hasPrefix && analysis.isSessionCookie) missing.push("Prefix");
      const missingHtml = missing.map(f => `<span class="cookie-flag missing">${f}</span>`).join("");

      const cookieValue = splitCookie(cookieStr).valuePart.trim();

      item.innerHTML = `
        <div class="cookie-header-row">
          <span class="cookie-name"><span class="expand-chevron" aria-hidden="true">▸</span> ${escapeHtml(analysis.name || "(no name)")}</span>
          ${statusIconHtml(allGood ? "good" : "warn")}
        </div>
        <div class="cookie-flags">${flagsHtml}${missingHtml}</div>
        <div class="cookie-value-blurred">${escapeHtml(cookieValue || "(empty)")}</div>
        <div class="cookie-reveal-hint" aria-hidden="true">Click to reveal value</div>
        <div class="cookie-details">
          ${analysis.issues.length > 0 ? '<div class="desc-verdict">' + analysis.issues.join('<br>') + '</div>' : '<div class="desc-verdict" style="color:#2ecc40;">All recommended cookie security flags are present.</div>'}
          <div class="desc-section">
            <div class="desc-title">What are cookie flags?</div>
            <div class="desc-text"><strong>Secure</strong>: Cookie is only sent over HTTPS, preventing interception on unencrypted connections.<br><strong>HttpOnly</strong>: Cookie cannot be accessed by JavaScript (document.cookie), mitigating XSS theft.<br><strong>SameSite</strong>: Controls whether cookie is sent with cross-site requests, preventing CSRF attacks.<br><strong>Prefix</strong>: <code>__Secure-</code> or <code>__Host-</code> prefixes add extra browser-enforced constraints on the cookie.<br><strong>Partitioned</strong>: Cookie is kept separate per top-level site (CHIPS), limiting cross-site tracking.</div>
          </div>
          <div class="desc-section">
            <div class="desc-title">Recommendation</div>
            <div class="desc-text">Set all cookies with <code>Secure; HttpOnly; SameSite=Lax</code> (or <code>Strict</code>) flags. Use <code>__Host-</code> prefix for session cookies where possible.</div>
          </div>
        </div>
      `;

      makeExpandable(item, ".cookie-header-row");
      makeRevealable(item.querySelector(".cookie-value-blurred"));

      cookieList.appendChild(item);
    }
  } else {
    cookieSection.style.display = "none";
  }

  // Information disclosure checks
  const disclosureSection = document.getElementById("disclosure-section");
  const disclosureList = document.getElementById("disclosure-list");
  disclosureList.innerHTML = "";
  let disclosureFound = false;

  for (const [key, def] of Object.entries(DISCLOSURE_HEADERS)) {
    const result = def.check(headers[key]);
    if (result) {
      disclosureFound = true;
      const item = document.createElement("div");
      item.className = "disclosure-item";
      item.innerHTML = `
        <div class="disclosure-header-row">
          <span><span class="expand-chevron" aria-hidden="true">▸</span> ${def.label}</span>
          ${statusIconHtml("warn")}
        </div>
        <div class="disclosure-msg">${result.msg}</div>
        <div class="disclosure-details">
          <div class="desc-verdict">${result.detail}</div>
          <div class="desc-section">
            <div class="desc-title">Why it matters</div>
            <div class="desc-text">Exposing server software, versions, or technology stack helps attackers fingerprint your infrastructure and find known vulnerabilities specific to those versions.</div>
          </div>
          <div class="desc-section">
            <div class="desc-title">Recommendation</div>
            <div class="desc-text">Remove or suppress this header in your web server or application configuration. Most reverse proxies (Nginx, Apache, Caddy) have options to strip these headers.</div>
          </div>
        </div>
      `;
      makeExpandable(item, ".disclosure-header-row");
      disclosureList.appendChild(item);
    }
  }
  disclosureSection.style.display = disclosureFound ? "" : "none";

  // Deprecated headers checks
  const deprecatedSection = document.getElementById("deprecated-section");
  const deprecatedList = document.getElementById("deprecated-list");
  deprecatedList.innerHTML = "";
  let deprecatedFound = false;

  for (const [key, def] of Object.entries(DEPRECATED_HEADERS)) {
    const result = def.check(headers[key]);
    if (result) {
      deprecatedFound = true;
      const item = document.createElement("div");
      item.className = "deprecated-item";
      item.innerHTML = `
        <div class="deprecated-header-row">
          <span><span class="expand-chevron" aria-hidden="true">▸</span> ${def.label}</span>
          ${statusIconHtml("info")}
        </div>
        <div class="deprecated-msg">${result.msg}</div>
        <div class="deprecated-details">
          <div class="desc-verdict">${result.detail}</div>
          <div class="desc-section">
            <div class="desc-title">Why it matters</div>
            <div class="desc-text">Deprecated headers are no longer supported by modern browsers and may give a false sense of security. Keeping them adds unnecessary response overhead.</div>
          </div>
          <div class="desc-section">
            <div class="desc-title">Recommendation</div>
            <div class="desc-text">Remove this header from your server configuration. Use modern alternatives where available (e.g., Certificate Transparency is now enforced by browsers without needing Expect-CT).</div>
          </div>
        </div>
      `;
      makeExpandable(item, ".deprecated-header-row");
      deprecatedList.appendChild(item);
    }
  }
  deprecatedSection.style.display = deprecatedFound ? "" : "none";

  // Raw headers, color-coded by type, with good tokens highlighted
  const securitySet = new Set(Object.keys(SECURITY_HEADERS).concat(Object.keys(ADDITIONAL_HEADERS)));
  const disclosureSet = new Set(Object.keys(DISCLOSURE_HEADERS));
  const deprecatedSet = new Set(Object.keys(DEPRECATED_HEADERS));

  const rawContainer = document.getElementById("raw-headers");
  rawContainer.innerHTML = "";
  const sortedKeys = Object.keys(headers).sort();
  for (const key of sortedKeys) {
    if (key === "set-cookie" && resolvedCookies.length > 0) continue; // shown individually below
    const row = document.createElement("div");
    let rowClass = "raw-row";
    if (securitySet.has(key)) rowClass += " raw-security";
    else if (disclosureSet.has(key) && DISCLOSURE_HEADERS[key].check(headers[key])) rowClass += " raw-disclosure";
    else if (deprecatedSet.has(key) && DEPRECATED_HEADERS[key].check(headers[key])) rowClass += " raw-deprecated";
    row.className = rowClass;
    row.innerHTML = `<span class="raw-key">${escapeHtml(key)}</span><span class="raw-val">${highlightGoodTokens(key, headers[key])}</span>`;
    rawContainer.appendChild(row);
  }

  // Also show individual Set-Cookie lines in raw headers
  if (resolvedCookies.length > 0) {
    for (const cookieStr of resolvedCookies) {
      const row = document.createElement("div");
      const cookieAnalysis = analyzeCookie(cookieStr);
      const cookieOk = cookieAnalysis.issues.length === 0;
      row.className = `raw-row ${cookieOk ? "raw-cookie-good" : "raw-cookie-warn"}`;

      // Split cookie into name=value and ;flags so we only blur the value
      const { namePart, valuePart, attrsPart: flagsPart } = splitCookie(cookieStr);

      const flagsHtml = flagsPart ? highlightGoodTokens("set-cookie", flagsPart) : "";
      row.innerHTML = `<span class="raw-key">set-cookie</span><span class="raw-val">${escapeHtml(namePart)}<span class="raw-cookie-value blurred">${escapeHtml(valuePart)}</span>${flagsHtml}</span>`;

      // Click to reveal only the blurred value portion
      makeRevealable(row.querySelector(".raw-cookie-value"));
      rawContainer.appendChild(row);
    }
  }
}

// Score breakdown: points per scored header, the CSP cap, and the total
function renderBreakdown(grade) {
  const container = document.getElementById("breakdown");
  const rows = grade.breakdown.map(b => `
    <tr class="${b.counts ? "earned" : "missed"}">
      <th scope="row">${escapeHtml(b.label)}</th>
      <td class="bd-reason">${escapeHtml(b.reason)}</td>
      <td class="bd-points">${b.counts ? "+" + b.points : "0"} / ${b.weight}</td>
    </tr>`).join("");
  const penalty = grade.penalty ? `
    <tr class="penalty">
      <th scope="row">CSP penalty</th>
      <td class="bd-reason">${escapeHtml(grade.penalty.reason)}</td>
      <td class="bd-points">${Math.round(grade.penalty.points)}</td>
    </tr>` : "";
  container.innerHTML = `
    <table class="breakdown-table">
      <caption class="sr-only">Score breakdown</caption>
      <tbody>${rows}${penalty}</tbody>
      <tfoot>
        <tr>
          <th scope="row">Total</th>
          <td class="bd-reason">${Math.round(grade.pct)}% = grade ${escapeHtml(grade.letter)}</td>
          <td class="bd-points">${Math.round(grade.score)} / ${MAX_SCORE}</td>
        </tr>
      </tfoot>
    </table>
    <div class="breakdown-scale">A+ ≥ 95% · A ≥ 75% · B ≥ 60% · C ≥ 50% · D ≥ 15% · E ≥ 5% · F below</div>`;
}

// Redirect chain of the page load (or of the background fetch)
function renderRedirects(redirects) {
  const section = document.getElementById("redirect-section");
  const list = document.getElementById("redirect-list");
  list.innerHTML = "";
  if (!redirects || redirects.length === 0) {
    section.style.display = "none";
    return;
  }
  section.style.display = "";
  const reasons = { HSTS: "upgraded to HTTPS by the browser (HSTS)" };
  for (const r of redirects) {
    const row = document.createElement("div");
    row.className = "redirect-row";
    const status = document.createElement("span");
    status.className = "redirect-status";
    status.textContent = r.status;
    const text = document.createElement("span");
    text.className = "redirect-urls";
    text.textContent = `${r.from}  →  ${r.to}`;
    row.append(status, text);
    if (r.internal) {
      const note = document.createElement("div");
      note.className = "redirect-note";
      note.textContent = reasons[r.reason] || "internal redirect by the browser";
      row.append(note);
    }
    list.appendChild(row);
  }
}

// Highlight known-good security tokens within raw header values
const GOOD_TOKENS = {
  "set-cookie": [/\bSecure\b/gi, /\bHttpOnly\b/gi, /\bSameSite=(Strict|Lax|None)\b/gi, /\b__Secure-/g, /\b__Host-/g],
  "strict-transport-security": [/\bmax-age=\d+/gi, /\bincludeSubDomains\b/gi, /\bpreload\b/gi],
  "x-content-type-options": [/\bnosniff\b/gi],
  "x-frame-options": [/\bDENY\b/gi, /\bSAMEORIGIN\b/gi],
  "referrer-policy": [/\bno-referrer\b/g, /\bstrict-origin-when-cross-origin\b/g, /\bsame-origin\b/g, /\bstrict-origin\b/g, /\bno-referrer-when-downgrade\b/g, /\borigin-when-cross-origin\b/g],
  "cross-origin-opener-policy": [/\bsame-origin\b/g, /\bsame-origin-allow-popups\b/g],
  "cross-origin-resource-policy": [/\bsame-origin\b/g, /\bsame-site\b/g, /\bcross-origin\b/g],
  "cross-origin-embedder-policy": [/\brequire-corp\b/g, /\bcredentialless\b/g],
  "content-security-policy": [/\b'strict-dynamic'\b/g, /\b'nonce-[^']+'\b/g, /\b'sha(256|384|512)-[^']+'\b/g],
  "permissions-policy": [/[a-z-]+=\(\)/g],
  "alt-svc": [/h3(?:=[^,;]*)?/g],
  "x-robots-tag": [/\bnoindex\b/gi, /\bnofollow\b/gi, /\bnone\b/gi, /\bnoarchive\b/gi, /\bnosnippet\b/gi],
  "nel": [/\breport_to\b/g, /\bmax_age\b/g, /\bfailure_fraction\b/g, /\bsuccess_fraction\b/g],
  "report-to": [/\bendpoints\b/g, /\bgroup\b/g, /\bmax_age\b/g],
};

function highlightGoodTokens(headerName, value) {
  const patterns = GOOD_TOKENS[headerName.toLowerCase()];
  if (!patterns || !value) return escapeHtml(value || "");

  // We need to escape first, then apply bold, but regex indices shift after escaping.
  // Instead: find match positions in raw value, then build highlighted escaped output.
  const marks = []; // {start, end} ranges to bold
  for (const pattern of patterns) {
    // Reset lastIndex for global regexes
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(value)) !== null) {
      marks.push({ start: match.index, end: match.index + match[0].length });
    }
  }

  if (marks.length === 0) return escapeHtml(value);

  // Sort by start position, merge overlaps
  marks.sort((a, b) => a.start - b.start);
  const merged = [marks[0]];
  for (let i = 1; i < marks.length; i++) {
    const last = merged[merged.length - 1];
    if (marks[i].start <= last.end) {
      last.end = Math.max(last.end, marks[i].end);
    } else {
      merged.push(marks[i]);
    }
  }

  // Build output with bold spans around matched ranges
  let result = "";
  let pos = 0;
  for (const m of merged) {
    if (m.start > pos) result += escapeHtml(value.slice(pos, m.start));
    result += `<strong class="raw-good">${escapeHtml(value.slice(m.start, m.end))}</strong>`;
    pos = m.end;
  }
  if (pos < value.length) result += escapeHtml(value.slice(pos));
  return result;
}

function createHeaderItem(key, def, value, allHeaders, ctx, grade) {
  const result = def.evaluate(value, allHeaders, ctx);
  const item = document.createElement("div");
  item.className = `header-item ${result.status}`;

  // Grade impact badge, taken from the same verdict that produced the grade
  const scored = grade.breakdown.find(b => b.key === key);
  let gradeBadgeHtml;
  if (!scored) {
    gradeBadgeHtml = `<span class="grade-badge info-only">info</span>`;
  } else if (!scored.counts) {
    gradeBadgeHtml = `<span class="grade-badge scored-bad">−${scored.weight} pts</span>`;
  } else if (result.status === "warn") {
    gradeBadgeHtml = `<span class="grade-badge scored-warn"><span aria-hidden="true">⚠</span> +${scored.weight} pts</span>`;
  } else {
    gradeBadgeHtml = `<span class="grade-badge scored">+${scored.weight} pts</span>`;
  }

  item.innerHTML = `
    <div class="header-name">
      <span class="header-label">
        <span class="expand-chevron" aria-hidden="true">&#9656;</span>
        ${def.label}
        ${gradeBadgeHtml}
      </span>
      ${statusIconHtml(result.status)}
    </div>
    <div class="header-value">${value ? (value.length > 120 ? `<span class="value-preview">${escapeHtml(value.substring(0, 120))}…</span><span class="value-full">${escapeHtml(value)}</span>` : escapeHtml(value)) : '<em style="color:#ff4136;">Not set</em>'}</div>
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

  makeExpandable(item, ".header-name");
  return item;
}

// Wire up toggle button
document.getElementById("toggle-details").addEventListener("click", () => {
  setDetailsOpen(!document.getElementById("details").classList.contains("show"));
});

// Wire up the collapsible sections: raw headers and score breakdown
for (const [toggleId, contentId] of [["raw-toggle", "raw-headers"], ["breakdown-toggle", "breakdown"]]) {
  makeToggle(document.getElementById(toggleId), () => {
    document.getElementById(contentId).classList.toggle("show");
    return document.getElementById(toggleId).classList.toggle("expanded");
  });
}

// Copy raw headers to clipboard
document.getElementById("copy-raw-btn").addEventListener("click", function () {
  if (!currentHeaders) return;
  const btn = this;
  // Cookie values are blurred in the UI, so keep them out of the clipboard too:
  // copied headers often end up pasted into bug reports and chats.
  const sortedKeys = Object.keys(currentHeaders).filter(k => k !== "set-cookie").sort();
  const lines = sortedKeys.map(k => `${k}: ${currentHeaders[k]}`);
  for (const cookieStr of currentCookies) {
    const { namePart, attrsPart } = splitCookie(cookieStr);
    lines.push(`set-cookie: ${namePart}[hidden]${attrsPart}`);
  }
  const text = lines.join("\n");
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = "Copied!";
    btn.classList.add("copied");
    setTimeout(() => {
      btn.textContent = "Copy";
      btn.classList.remove("copied");
    }, 1500);
  });
});

function openSecurityHeadersScan(url) {
  const target = scanTargetUrl(url);
  if (!target) return;
  chrome.tabs.create({ url: `https://securityheaders.com/?q=${encodeURIComponent(target)}&hide=on&followRedirects=on`, active: false });
}

function openSslLabsScan(url) {
  const target = scanTargetUrl(url);
  if (!target) return;
  const hostname = new URL(target).hostname;
  chrome.tabs.create({ url: `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(hostname)}&hideResults=on&latest`, active: false });
}

// External scan buttons: use the active tab's URL
function getActiveTabUrl(callback) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0] && tabs[0].url) callback(tabs[0].url);
  });
}

document.getElementById("scan-secheaders").addEventListener("click", () => {
  getActiveTabUrl(openSecurityHeadersScan);
});

document.getElementById("scan-ssllabs").addEventListener("click", () => {
  getActiveTabUrl(openSslLabsScan);
});

// Restricted page: "Why?" toggle
document.getElementById("restricted-why-toggle").addEventListener("click", () => {
  const btn = document.getElementById("restricted-why-toggle");
  const open = document.getElementById("restricted-why").classList.toggle("show");
  btn.classList.toggle("expanded", open);
  btn.setAttribute("aria-expanded", String(open));
});

// Restricted page: scan buttons
document.getElementById("restricted-scan-secheaders").addEventListener("click", () => {
  const url = document.getElementById("restricted-page").dataset.url;
  if (url) openSecurityHeadersScan(url);
});

document.getElementById("restricted-scan-ssllabs").addEventListener("click", () => {
  const url = document.getElementById("restricted-page").dataset.url;
  if (url) openSslLabsScan(url);
});

// URL without query or fragment, cut to 60 characters
function shortUrl(url) {
  const base = (url || "").split(/[?#]/)[0];
  return base.length > 60 ? base.substring(0, 60) + "..." : base;
}

function renderInternalPage(url) {
  document.getElementById("header").style.display = "none";
  document.getElementById("quick-status").style.display = "none";
  document.getElementById("toggle-details").style.display = "none";
  document.getElementById("external-scans").style.display = "none";

  const el = document.getElementById("internal-page");
  el.classList.remove("hidden");

  // Easter egg for the extension's own pages
  const ownPages = { "welcome.html": "welcome page", "options.html": "settings page", "popup.html": "popup" };
  const ownPage = Object.keys(ownPages).find(page => (url || "").startsWith(chrome.runtime.getURL(page)));
  const iconEl = document.getElementById("internal-icon");

  if (ownPage) {
    iconEl.innerHTML = "&#128075;";
    el.querySelector(".internal-title").textContent = "Hey, you found me!";
    el.querySelector(".hint").innerHTML = `Trying to scan my own ${ownPages[ownPage]}? Cheeky. &#128521;<br>Go visit a real website, I promise the headers there are more interesting.`;
  } else {
    iconEl.innerHTML = "&#128274;";
    el.querySelector(".internal-title").textContent = "Internal Page";
    el.querySelector(".hint").textContent = "Not a website. Security headers don't apply here.";
  }

  document.getElementById("internal-scheme").textContent = shortUrl(url);
}

function renderRestrictedPage(url) {
  document.getElementById("header").style.display = "none";
  document.getElementById("quick-status").style.display = "none";
  document.getElementById("toggle-details").style.display = "none";
  document.getElementById("external-scans").style.display = "none";
  document.getElementById("no-data").classList.add("hidden");
  document.getElementById("internal-page").classList.add("hidden");

  const el = document.getElementById("restricted-page");
  el.classList.remove("hidden");

  document.getElementById("restricted-url").textContent = shortUrl(url);

  // Store URL for scan buttons
  el.dataset.url = url || "";
}

// Scan the active tab: try cached headers first, fall back to background fetch
function scanActiveTab(forceRefresh = false) {
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    if (!tabs[0]) {
      render(null);
      return;
    }

    const tab = tabs[0];
    const url = tab.url;

    if (!isHttpUrl(url)) {
      renderInternalPage(url);
      return;
    }

    // Show scanning state
    let hostname = url;
    try { hostname = new URL(url).hostname; } catch {}
    document.getElementById("site-url").textContent = hostname;
    document.getElementById("site-summary").textContent = "Fetching headers...";

    if (forceRefresh) {
      // Skip cache, always do a fresh fetch via background
      const data = await fetchHeadersViaBackground(tab.id);
      if (data && data.restricted) {
        renderRestrictedPage(url);
      } else {
        render(data);
      }
    } else {
      // Try cached headers first
      chrome.runtime.sendMessage({ type: "getHeaders", tabId: tab.id }, async (response) => {
        if (response && response.restricted) {
          renderRestrictedPage(url);
        } else if (response && response.headers && Object.keys(response.headers).length > 0 && !response.cacheIncomplete) {
          render(response);
        } else if (response && response.headers && Object.keys(response.headers).length > 0) {
          // Served from the browser cache, which drops HSTS and Set-Cookie: re-check now
          const data = await fetchHeadersViaBackground(tab.id);
          render(data && data.headers ? data : response);
        } else {
          // Opening the popup is a user action, so fetch even when automatic
          // background requests are turned off in the settings
          const data = await fetchHeadersViaBackground(tab.id);
          if (data && data.restricted) {
            renderRestrictedPage(url);
          } else {
            render(data);
          }
        }
      });
    }
  });
}

// Show extension version in the footer
const versionTag = document.getElementById("version-tag");
if (versionTag) {
  const manifest = chrome.runtime.getManifest();
  versionTag.textContent = `v${manifest.version}`;
}

// Rescan button
document.getElementById("rescan-btn").addEventListener("click", () => {
  const btn = document.getElementById("rescan-btn");
  btn.classList.add("spinning");
  setTimeout(() => btn.classList.remove("spinning"), 600);
  scanActiveTab(true);
});

// Settings button
document.getElementById("settings-btn").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

// Theme toggle
function applyTheme(theme, animate) {
  const btn = document.getElementById("theme-btn");
  if (animate) {
    document.body.classList.add("theme-transition");
    btn.classList.add("theme-spin");
    setTimeout(() => {
      document.body.classList.remove("theme-transition");
      btn.classList.remove("theme-spin");
    }, 300);
  }
  if (theme === "light") {
    document.body.classList.add("light");
    btn.textContent = "\u263D"; // moon crescent
  } else {
    document.body.classList.remove("light");
    btn.textContent = "\u2600"; // sun
  }
}


document.getElementById("theme-btn").addEventListener("click", () => {
  const isLight = document.body.classList.contains("light");
  const newTheme = isLight ? "dark" : "light";
  applyTheme(newTheme, true);
  chrome.storage.local.set({ theme: newTheme });
});

// Init: load theme and settings, then scan
chrome.storage.local.get(["theme", "settings"], (data) => {
  applyTheme(data.theme || "dark");
  settings = { ...DEFAULT_SETTINGS, ...(data.settings || {}) };
  scanActiveTab();
});
