// Shared header analysis and grading.
// Loaded by the popup (<script src="analysis.js">), the background service worker
// (importScripts), and the Node tests, so the badge, the popup, and the tests
// always grade the same way. Keep it free of DOM and chrome.* APIs.

// User settings (stored in chrome.storage.local under "settings").
// autoFetch: re-check a page in the background when its captured headers are
// incomplete (served from the browser cache, which drops HSTS and Set-Cookie, or
// nothing captured), and scan tabs that were open when the extension was installed.
// The popup re-checks when you open it or press rescan either way.
const DEFAULT_SETTINGS = {
  autoFetch: true,
  showBadge: true,
  blurCookies: true
};

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function isHttpUrl(url) {
  return typeof url === "string" && (url.startsWith("http://") || url.startsWith("https://"));
}

function isPlainHttp(url) {
  return typeof url === "string" && url.startsWith("http://");
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

// --- Header value parsing -----------------------------------------------------

// Comma-separated header list, trimmed and lowercased
function listTokens(val) {
  return (val || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
}

// Parse a CSP header into { directive: [sources] } the way browsers read it:
// directive names and keywords are case-insensitive, and when a directive is
// repeated only the first occurrence counts. Without this, a policy like
// "script-src 'unsafe-inline'; script-src 'self'" would be graded as safe.
// Object.create(null) prevents a CSP directive named __proto__ from mutating the prototype.
function parseCSP(csp) {
  const directives = Object.create(null);
  for (const d of (csp || "").toLowerCase().split(";")) {
    const parts = d.trim().split(/\s+/);
    if (!parts[0] || parts[0] in directives) continue;
    directives[parts[0]] = parts.slice(1);
  }
  return directives;
}

// Script weaknesses that cap the grade. Returns the directive name responsible,
// or null. <script> elements use script-src-elem when present, eval() uses script-src.
// A nonce, hash, or 'strict-dynamic' makes browsers ignore 'unsafe-inline'.
function cspScriptWeaknesses(directives) {
  const scriptName = directives["script-src"] ? "script-src" : "default-src";
  const scriptSrc = directives["script-src"] || directives["default-src"] || [];
  const elemName = directives["script-src-elem"] ? "script-src-elem" : scriptName;
  const elemSrc = directives["script-src-elem"] || scriptSrc;
  const inlineAllowed = (list) => list.includes("'unsafe-inline'") &&
    !list.includes("'strict-dynamic'") &&
    !list.some(s => s.startsWith("'nonce-") || /^'sha(256|384|512)-/.test(s));
  return {
    unsafeInline: inlineAllowed(elemSrc) ? elemName : (inlineAllowed(scriptSrc) ? scriptName : null),
    unsafeEval: scriptSrc.includes("'unsafe-eval'") ? scriptName : null
  };
}

// frame-ancestors sources that let any site frame the page
function frameAncestorsAllowsAny(sources) {
  return sources.some(s => s === "*" || s === "https:" || s === "http:");
}

// HSTS max-age in seconds, or null when there is no valid max-age.
// Directive names are case-insensitive and the value may be quoted (RFC 6797).
function hstsMaxAge(val) {
  if (!val) return null;
  const m = val.match(/(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?:;|$)/i);
  return m ? parseInt(m[1], 10) : null;
}

function hstsHasDirective(val, name) {
  return (val || "").split(";").some(d => d.trim().toLowerCase() === name);
}

// X-Frame-Options, as browsers apply it: DENY or SAMEORIGIN protect. Conflicting
// values make browsers block all framing. Anything else (including the obsolete
// ALLOW-FROM) is ignored. Returns "deny", "sameorigin", or null.
function xfoPolicy(val) {
  const values = [...new Set(listTokens(val))];
  if (values.length > 1 && values.some(v => v === "deny" || v === "sameorigin" || v === "allowall")) return "deny";
  if (values.length === 1 && (values[0] === "deny" || values[0] === "sameorigin")) return values[0];
  return null;
}

// X-Content-Type-Options: browsers only look at the first value
function hasNosniff(val) {
  return listTokens(val)[0] === "nosniff";
}

const REFERRER_POLICIES = ["no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"];
const STRONG_REFERRER_POLICIES = ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"];

// Referrer-Policy may be a list; browsers use the last value they recognize
function effectiveReferrerPolicy(val) {
  const known = listTokens(val).filter(t => REFERRER_POLICIES.includes(t));
  return known.length > 0 ? known[known.length - 1] : null;
}

// Permissions-Policy is a structured-field dictionary: feature=(allowlist), ...
// Browsers ignore the whole header when it has a syntax error (a common one is
// separating features with spaces instead of commas). Returns null for invalid
// syntax, otherwise the features that have an allowlist.
const SF_KEY = String.raw`[a-z*][a-z0-9_.*-]*`;
const SF_BARE_ITEM = String.raw`(?:[A-Za-z*][A-Za-z0-9:/!#$%&'*+.^_` + "`" + String.raw`|~-]*|"(?:[^"\\]|\\.)*"|\?[01]|-?\d+(?:\.\d+)?)`;
const SF_PARAMS = String.raw`(?:;${SF_KEY}(?:=${SF_BARE_ITEM})?)*`;
const SF_INNER_LIST = String.raw`\(\s*(?:${SF_BARE_ITEM}${SF_PARAMS}(?:\s+${SF_BARE_ITEM}${SF_PARAMS})*)?\s*\)`;
const PP_MEMBER = new RegExp(String.raw`^(${SF_KEY})(=(?:${SF_INNER_LIST}|${SF_BARE_ITEM}))?${SF_PARAMS}$`);

function parsePermissionsPolicy(val) {
  const features = [];
  for (const member of (val || "").split(",").map(m => m.trim())) {
    const m = PP_MEMBER.exec(member);
    if (!m) return null; // includes empty members, like a trailing comma
    if (m[2]) features.push(m[1]); // a bare key (no "=") restricts nothing
  }
  return features;
}

function permissionsPolicyFeatures(val) {
  return parsePermissionsPolicy(val) || [];
}

// --- Header definitions ---------------------------------------------------------
// evaluate(value, allHeaders, ctx) returns { status, msg }. ctx is { url, redirects }.
// msg is HTML: every value taken from a response must go through escapeHtml.

const SECURITY_HEADERS = {
  "content-security-policy": {
    label: "Content-Security-Policy",
    about: "Content Security Policy is an effective measure to protect your site from XSS attacks. By whitelisting sources of approved content, you can prevent the browser from loading malicious assets. It lets you define where scripts, styles, images, fonts, and other resources can be loaded from.",
    good: "A well-configured CSP significantly reduces the risk of cross-site scripting and data injection attacks. It acts as a second layer of defense against injection vulnerabilities.",
    recommendation: "Start with a strict policy like <code>default-src 'none'</code> and selectively allow only what your site needs. Avoid <code>'unsafe-inline'</code> and <code>'unsafe-eval'</code> when possible as they weaken protection considerably.",
    evaluate: (val, headers) => {
      const reportOnly = headers && headers["content-security-policy-report-only"];
      const reportOnlyNote = "A <code>Content-Security-Policy-Report-Only</code> header is also sent. It only reports violations and doesn't block anything.";
      if (!val) return { status: "bad", msg: "Missing. Your site has no Content Security Policy, leaving it vulnerable to XSS and data injection attacks." + (reportOnly ? "<br>" + reportOnlyNote : "") };

      const directives = parseCSP(val);
      if (Object.keys(directives).length === 0)
        return { status: "bad", msg: "Set, but it contains no directives, so it doesn't restrict anything." };

      const warnings = [];
      const suggestions = [];
      const scriptSrc = directives["script-src"] || directives["default-src"] || [];
      const scriptElemSrc = directives["script-src-elem"] || scriptSrc;
      const defaultSrc = directives["default-src"];
      const weak = cspScriptWeaknesses(directives);

      if (weak.unsafeEval)
        warnings.push(`${weak.unsafeEval} uses <code>'unsafe-eval'</code>: allows dynamic code execution via eval().`);
      if (weak.unsafeInline)
        warnings.push(`${weak.unsafeInline} uses <code>'unsafe-inline'</code>: allows inline scripts, weakening XSS protection.`);
      if (scriptSrc.includes("'unsafe-hashes'") || scriptElemSrc.includes("'unsafe-hashes'") || (directives["script-src-attr"] || []).includes("'unsafe-hashes'"))
        warnings.push("Scripts allow <code>'unsafe-hashes'</code>: specific inline event handlers (like <code>onclick</code>) can run.");

      // Wildcard, data: and http: sources in the lists that control scripts
      const scriptLists = scriptElemSrc === scriptSrc ? [scriptSrc] : [scriptSrc, scriptElemSrc];
      if (scriptLists.some(l => l.includes("*")))
        warnings.push("script-src contains <code>*</code> wildcard: scripts can be loaded from any origin.");
      if (scriptLists.some(l => l.includes("data:")))
        warnings.push("script-src allows <code>data:</code> URIs: attackers can inject base64-encoded scripts.");
      if (scriptLists.some(l => l.some(s => s.startsWith("http://") || s === "http:")))
        warnings.push("script-src allows <code>http://</code> sources: scripts loaded over plain HTTP can be intercepted.");
      if (scriptLists.some(l => l.includes("https:")))
        warnings.push("script-src allows <code>https:</code>: scripts can be loaded from any HTTPS site.");

      // Missing default-src means no fallback for undeclared directives
      if (!defaultSrc)
        warnings.push("No <code>default-src</code> directive: undeclared resource types have no restrictions.");

      // Plugins (object/embed) are an old injection vector; they fall back to default-src
      const objectSrc = directives["object-src"] || defaultSrc;
      if (!objectSrc)
        warnings.push("<code>object-src</code> is not restricted: set it to <code>'none'</code> to block plugins.");
      else if (!directives["object-src"] && !objectSrc.includes("'none'") && !(objectSrc.length === 1 && objectSrc[0] === "'self'"))
        warnings.push("<code>object-src</code> is not explicitly set: consider setting to <code>'none'</code> to block plugins.");

      // base-uri doesn't fall back to default-src
      if (!directives["base-uri"])
        warnings.push("<code>base-uri</code> is not set: attackers could inject a <code>&lt;base&gt;</code> tag to hijack relative URLs.");

      // Wildcard in any other directive
      const wildcardDirs = Object.entries(directives)
        .filter(([k, v]) => k !== "script-src" && k !== "script-src-elem" && v.includes("*"))
        .map(([k]) => k);
      if (wildcardDirs.length > 0)
        warnings.push(`Wildcard <code>*</code> found in: ${wildcardDirs.map(d => `<code>${escapeHtml(d)}</code>`).join(", ")}.`);

      // Hardening suggestions: not weaknesses by themselves, so they don't change the status
      if (!directives["frame-ancestors"])
        suggestions.push("Add <code>frame-ancestors 'none'</code> (or <code>'self'</code>): the modern clickjacking protection that replaces X-Frame-Options.");
      if (!directives["form-action"])
        suggestions.push("Add <code>form-action</code>: it doesn't fall back to <code>default-src</code>, so forms can post anywhere.");
      if (!directives["upgrade-insecure-requests"])
        suggestions.push("Add <code>upgrade-insecure-requests</code> to load any leftover <code>http://</code> resources over HTTPS.");
      if (!directives["require-trusted-types-for"])
        suggestions.push("Consider <code>require-trusted-types-for 'script'</code> (Trusted Types) to block DOM XSS sinks.");
      if (reportOnly) suggestions.push(reportOnlyNote);

      let msg = warnings.length === 0 ? "Well configured. Approved content sources are whitelisted." : warnings.join("<br>");
      if (suggestions.length > 0) msg += "<br><br><strong>Suggestions:</strong><br>" + suggestions.join("<br>");
      return { status: warnings.length === 0 ? "good" : "warn", msg };
    }
  },
  "permissions-policy": {
    label: "Permissions-Policy",
    about: "Permissions Policy (formerly Feature Policy) allows you to control which browser features and APIs can be used on your page. This includes sensitive capabilities like camera, microphone, geolocation, payment, and USB access.",
    good: "Restricting unused features reduces your attack surface. Even if an attacker injects code, they cannot access features you've disabled. It also prevents third-party iframes from using powerful features without your consent.",
    recommendation: "Disable all features you don't use with an empty allowlist, e.g. <code>camera=()</code>, <code>microphone=()</code>. Only enable features your site actually requires.",
    evaluate: (val) => {
      if (!val) return { status: "bad", msg: "Missing. Any embedded content can request access to browser features like camera, microphone, and geolocation." };
      const features = parsePermissionsPolicy(val);
      if (!features)
        return { status: "bad", msg: `Set to "${escapeHtml(val.trim())}", but it isn't valid <code>feature=(...)</code> syntax (features must be separated by commas), so browsers ignore the whole header.` };
      if (features.length === 0)
        return { status: "bad", msg: `Set to "${escapeHtml(val.trim())}", but no feature has an allowlist like <code>camera=()</code>, so nothing is restricted.` };
      return { status: "good", msg: `Browser feature access is restricted via policy (${features.length} feature${features.length === 1 ? "" : "s"} configured).` };
    }
  },
  "referrer-policy": {
    label: "Referrer-Policy",
    about: "Referrer Policy controls how much referrer information (the URL of the previous page) the browser includes when navigating away from your site. Without it, full URLs (potentially containing sensitive data like tokens, user IDs, or internal paths) can leak to third parties.",
    good: "A strict referrer policy prevents leaking private URL paths and query parameters to external sites. This is especially important for pages that contain sensitive information in the URL.",
    recommendation: "Use <code>strict-origin-when-cross-origin</code> (a good default), <code>same-origin</code> (strictest, no referrer to other sites), or <code>no-referrer</code> (never send referrer). Avoid <code>unsafe-url</code> which sends the full URL everywhere.",
    evaluate: (val) => {
      if (!val) return { status: "bad", msg: "Missing. Full referrer URLs (including paths and query strings) may leak to external sites." };
      const policy = effectiveReferrerPolicy(val);
      if (!policy)
        return { status: "bad", msg: `"${escapeHtml(val.trim())}" is not a recognized policy, so browsers ignore it.` };
      // With a comma-separated list, browsers use the last value they recognize
      const listNote = listTokens(val).length > 1 ? ` Browsers use the last value they recognize, which here is "${policy}".` : "";
      if (policy === "unsafe-url")
        return { status: "bad", msg: `Effective policy is "unsafe-url": the full URL, including path and query string, is sent to every site.${listNote}` };
      if (policy === "no-referrer-when-downgrade")
        return { status: "bad", msg: `Effective policy is "no-referrer-when-downgrade": the full URL is sent to every HTTPS site. This was the old browser default, so it adds no protection.${listNote}` };
      if (STRONG_REFERRER_POLICIES.includes(policy))
        return { status: "good", msg: `Set to "${policy}". Referrer information is properly restricted.${listNote}` };
      return { status: "warn", msg: `Set to "${policy}". Consider a stricter policy like "strict-origin-when-cross-origin" or "same-origin".${listNote}` };
    }
  },
  "strict-transport-security": {
    label: "Strict-Transport-Security",
    about: "HTTP Strict Transport Security (HSTS) tells the browser to always use HTTPS when connecting to your site, even if the user types http:// or clicks an HTTP link. This prevents protocol downgrade attacks and cookie hijacking on insecure connections.",
    good: "HSTS ensures all communication is encrypted. Once the browser sees this header, it will refuse to connect over plain HTTP for the specified duration, protecting against man-in-the-middle attacks on the initial connection.",
    recommendation: "Set <code>max-age</code> to at least 31536000 (1 year). Add <code>includeSubDomains</code> to protect all subdomains. Add <code>preload</code> and submit your site to the HSTS preload list for protection on the very first visit.",
    evaluate: (val, headers, ctx) => {
      if (!val) return { status: "bad", msg: "Missing. Connections can be downgraded to unencrypted HTTP, exposing data to interception." };
      const url = ctx && ctx.url;
      if (isPlainHttp(url))
        return { status: "bad", msg: "Ignored: browsers only accept HSTS from HTTPS responses. Serve the site over HTTPS and send this header there." };
      const maxAge = hstsMaxAge(val);
      if (maxAge === null)
        return { status: "bad", msg: "No valid max-age directive. Browsers ignore this header, so HTTPS is not enforced." };
      if (maxAge === 0)
        return { status: "bad", msg: "max-age=0 tells browsers to forget this site's HSTS policy, so HTTPS is not enforced. This is only useful when intentionally switching HSTS off." };
      const hasSub = hstsHasDirective(val, "includesubdomains");
      const hasPreload = hstsHasDirective(val, "preload");

      let result;
      if (maxAge >= 31536000 && hasSub && hasPreload)
        result = { status: "good", msg: `Excellent. max-age=${maxAge} (${Math.round(maxAge/86400)} days), includeSubDomains, and preload are all set.` };
      else if (maxAge >= 31536000)
        result = { status: "good", msg: `max-age=${maxAge} is good. Consider adding includeSubDomains and preload for complete coverage.` };
      else if (maxAge < 2592000)
        result = { status: "warn", msg: `max-age is only ${maxAge} seconds (${Math.round(maxAge/86400)} days). Recommend at least 31536000 (1 year).` };
      else
        result = { status: "good", msg: `max-age=${maxAge}.` };

      // HSTS preload list: the header requirements from hstspreload.org
      const missing = [];
      if (maxAge < 31536000) missing.push("max-age of at least 31536000");
      if (!hasSub) missing.push("includeSubDomains");
      if (!hasPreload) missing.push("preload");
      let host = "";
      try { host = new URL(url).hostname; } catch {}
      result.msg += "<br><br>" + (missing.length === 0
        ? "Preload list: this header meets the requirements."
        : `Preload list: not eligible yet (needs ${missing.join(", ")}).`);
      if (host) result.msg += ` <a href="https://hstspreload.org/?domain=${encodeURIComponent(host)}" target="_blank" rel="noopener noreferrer">Check status on hstspreload.org</a>`;
      if (ctx && ctx.redirects && ctx.redirects.some(r => r.reason === "HSTS"))
        result.msg += "<br>This browser upgraded the connection to HTTPS on its own, because it already has an HSTS policy for this site (from an earlier visit or the preload list).";
      return result;
    }
  },
  "x-content-type-options": {
    label: "X-Content-Type-Options",
    about: "X-Content-Type-Options stops the browser from trying to MIME-sniff the content type of a response and forces it to use the declared Content-Type. Without this, a browser might interpret a file differently than intended, for example treating a plain text file as JavaScript.",
    good: "Setting this header to 'nosniff' prevents MIME-type confusion attacks. An attacker cannot trick the browser into executing a non-script resource as code, which is a common vector for XSS via uploaded files.",
    recommendation: "Always set this to <code>nosniff</code>. There is no reason not to, it has no side effects on properly configured sites.",
    evaluate: (val) => {
      if (!val) return { status: "bad", msg: "Missing. The browser may MIME-sniff responses and interpret files as a different content type than intended." };
      if (hasNosniff(val))
        return { status: "good", msg: "Set to 'nosniff'. MIME-type sniffing is blocked." };
      return { status: "bad", msg: `Invalid value: "${escapeHtml(val)}". Browsers only accept "nosniff" and ignore anything else.` };
    }
  },
  "x-frame-options": {
    label: "X-Frame-Options",
    about: "X-Frame-Options tells the browser whether your site is allowed to be embedded in iframes on other sites. This is the primary defense against clickjacking attacks, where an attacker overlays your site with invisible frames to trick users into clicking on hidden elements.",
    good: "Preventing framing stops attackers from embedding your site in a malicious page. Users cannot be tricked into unknowingly clicking buttons or links on your site through transparent overlay attacks.",
    recommendation: "Set to <code>DENY</code> (no framing at all) or <code>SAMEORIGIN</code> (only your own site can frame it). Note: the CSP <code>frame-ancestors</code> directive is the modern replacement and takes precedence if set.",
    evaluate: (val, headers) => {
      const frameAncestors = parseCSP((headers && headers["content-security-policy"]) || "")["frame-ancestors"];
      const policy = xfoPolicy(val);
      // Browsers use CSP frame-ancestors instead of X-Frame-Options when both are present
      if (frameAncestors) {
        if (frameAncestorsAllowsAny(frameAncestors))
          return { status: "bad", msg: "CSP <code>frame-ancestors</code> allows any site to frame this page, and browsers use it instead of X-Frame-Options. The page is not protected against clickjacking." };
        return { status: "good", msg: val
          ? `Set to "${escapeHtml(val.trim())}". CSP frame-ancestors is also configured and takes precedence in modern browsers.`
          : "Not set, but CSP frame-ancestors is configured. This is the modern replacement and takes precedence." };
      }
      if (!val) return { status: "bad", msg: "Missing. Your site can be embedded in iframes by any page, making it vulnerable to clickjacking." };
      if (policy) {
        const conflict = new Set(listTokens(val)).size > 1;
        return { status: "good", msg: conflict
          ? `Conflicting values "${escapeHtml(val.trim())}". Browsers then block all framing, which protects the page, but pick one value.`
          : `Set to "${policy.toUpperCase()}". Clickjacking protection is active.` };
      }
      if (listTokens(val).some(t => t.startsWith("allow-from")))
        return { status: "bad", msg: "ALLOW-FROM is obsolete and ignored by modern browsers, so the page can be framed by any site. Use CSP <code>frame-ancestors</code> instead." };
      return { status: "bad", msg: `Invalid value "${escapeHtml(val)}". Browsers ignore it. Use DENY or SAMEORIGIN.` };
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
      if (!val) return { status: "info", msg: "Not set. Cross-origin windows may be able to reference your page. Consider adding for cross-origin isolation." };
      return { status: "good", msg: `Set to "${escapeHtml(val.trim())}". Cross-origin window access is restricted.` };
    }
  },
  "cross-origin-resource-policy": {
    label: "Cross-Origin-Resource-Policy",
    about: "Cross-Origin Resource Policy (CORP) lets you control which origins can load your resources (images, scripts, etc.). It prevents other websites from embedding your resources without permission, protecting against data leaks and Spectre-style side-channel attacks.",
    good: "Restricting who can load your resources prevents unauthorized sites from reading your content. This is particularly important for authenticated resources that should not be accessible cross-origin.",
    recommendation: "Set to <code>same-origin</code> if your resources should only be loaded by your own site. Use <code>same-site</code> to allow subdomains. Use <code>cross-origin</code> only for public resources like CDN assets.",
    evaluate: (val) => {
      if (!val) return { status: "info", msg: "Not set. Any origin can load your resources. Consider restricting this." };
      return { status: "good", msg: `Set to "${escapeHtml(val.trim())}". Resource loading is restricted by origin.` };
    }
  },
  "cross-origin-embedder-policy": {
    label: "Cross-Origin-Embedder-Policy",
    about: "Cross-Origin Embedder Policy (COEP) ensures that all resources loaded by your page have explicitly opted in to being loaded (via CORS or CORP headers). Combined with COOP, it enables full cross-origin isolation, unlocking APIs like SharedArrayBuffer.",
    good: "COEP prevents your page from loading cross-origin resources that haven't granted permission. This blocks speculative execution attacks (like Spectre) from leaking data across origins.",
    recommendation: "Set to <code>require-corp</code> for full isolation. Note: all cross-origin resources must include appropriate CORS or CORP headers, or they will be blocked.",
    evaluate: (val) => {
      if (!val) return { status: "info", msg: "Not set. Recommended for full cross-origin isolation (required for SharedArrayBuffer)." };
      return { status: "good", msg: `Set to "${escapeHtml(val.trim())}". Cross-origin resource loading requires explicit permission.` };
    }
  },
  "x-xss-protection": {
    label: "X-XSS-Protection",
    about: "X-XSS-Protection controlled the XSS Auditor built into older browsers (Chrome < 78, Edge < 79). The auditor attempted to detect reflected XSS attacks and block or sanitize the response. However, it was found to have bypasses and could itself introduce vulnerabilities.",
    good: "Modern browsers have removed the XSS Auditor entirely. Setting this to '0' is now recommended to disable it in any remaining older browsers, as the auditor itself could be exploited. Content Security Policy is the proper replacement.",
    recommendation: "Set to <code>0</code> to disable the legacy auditor. Rely on a strong Content-Security-Policy header instead for XSS protection.",
    evaluate: (val) => {
      if (!val) return { status: "info", msg: "Not set. Not required if you have a Content Security Policy. The legacy XSS Auditor has been removed from modern browsers." };
      if (val.trim() === "0")
        return { status: "good", msg: "Set to '0'. Legacy XSS Auditor is disabled. CSP should be used for XSS protection instead." };
      return { status: "warn", msg: `Set to "${escapeHtml(val.trim())}". Consider setting to '0' to disable the flawed legacy auditor, and rely on CSP instead.` };
    }
  },
  "x-robots-tag": {
    label: "X-Robots-Tag",
    about: "The X-Robots-Tag HTTP header controls how search engines index and display your pages. It works like the <code>&lt;meta name=\"robots\"&gt;</code> HTML tag but applies at the HTTP level, useful for non-HTML resources (PDFs, images) or when you want server-wide control without modifying page content.",
    good: "Controlling search engine behavior lets you prevent sensitive pages from appearing in search results, stop caching of private content, and manage how your site is represented in search engines. For internal tools or private services, <code>noindex, nofollow</code> keeps them out of search entirely.",
    recommendation: "Set to <code>noindex, nofollow</code> for private or internal pages. Use <code>noindex</code> alone to prevent indexing but still allow link following. For public pages, this header is usually not needed since search engines index by default.",
    evaluate: (val) => {
      if (!val) return { status: "info", msg: "Not set. Search engines will index this page by default. Set this header if you want to control search engine behavior at the HTTP level." };
      const lower = val.toLowerCase();
      const hasNoindex = /noindex/.test(lower);
      const hasNofollow = /nofollow/.test(lower);
      const hasNone = /\bnone\b/.test(lower);
      if (hasNone || (hasNoindex && hasNofollow))
        return { status: "good", msg: `Set to "${escapeHtml(val.trim())}". Page is hidden from search engines and links are not followed.` };
      if (hasNoindex)
        return { status: "good", msg: `Set to "${escapeHtml(val.trim())}". Page will not appear in search results.` };
      if (hasNofollow)
        return { status: "info", msg: `Set to "${escapeHtml(val.trim())}". Search engines won't follow links on this page, but the page itself may still be indexed.` };
      return { status: "info", msg: `Set to "${escapeHtml(val.trim())}".` };
    }
  },
  "alt-svc": {
    label: "Alt-Svc",
    about: "The Alt-Svc (Alternative Services) header advertises that the same resource is available over a different protocol or network endpoint. Most commonly, it tells the browser that HTTP/3 (QUIC) is available, enabling faster, more reliable connections with built-in encryption and reduced latency.",
    good: "HTTP/3 uses QUIC, a UDP-based transport protocol with built-in TLS 1.3 encryption. It eliminates head-of-line blocking, reduces connection setup time (0-RTT), and handles network changes (e.g., switching from Wi-Fi to mobile) more gracefully than TCP.",
    recommendation: "If your server supports HTTP/3 (QUIC), this header is set automatically. Major web servers (Nginx, Caddy, LiteSpeed) and CDNs (Cloudflare, Fastly) support it. No action needed if you see <code>h3</code> in the value.",
    evaluate: (val) => {
      if (!val) return { status: "info", msg: "Not set. The site is not advertising HTTP/3 (QUIC) support. The site uses HTTP/1.1 or HTTP/2 only." };
      const hasH3 = /h3/.test(val);
      if (hasH3)
        return { status: "good", msg: "HTTP/3 (QUIC) is available. Faster, more reliable connections with built-in TLS 1.3 encryption." };
      return { status: "info", msg: `Alternative service advertised: "${escapeHtml(val.trim())}".` };
    }
  },
  "nel": {
    label: "NEL",
    about: "Network Error Logging (NEL) instructs the browser to send reports during various network or application errors. It collects information about failed connections, DNS resolution errors, TLS negotiation failures, and other network-level issues that happen before your server even sees the request.",
    good: "NEL gives you visibility into network errors your users experience that traditional server-side logging cannot capture, such as DNS failures, TCP timeouts, and TLS errors. This helps diagnose connectivity issues affecting real users.",
    recommendation: "Configure a NEL policy with a JSON value specifying <code>report_to</code> group, <code>max_age</code>, and optionally <code>failure_fraction</code> to sample errors. Pair with the <code>Report-To</code> header to define where reports are sent. Services like Report URI can collect these reports for free.",
    evaluate: (val) => {
      if (!val) return { status: "info", msg: "Not set. The site is not collecting network error reports. Consider enabling NEL to detect DNS, TLS, and connection failures affecting users." };
      return { status: "good", msg: "Network Error Logging is configured. The browser will report network-level errors to help diagnose connectivity issues." };
    }
  },
  "report-to": {
    label: "Report-To",
    about: "The Report-To header enables the Reporting API, which allows a website to collect reports from the browser about various errors that may occur, including Content Security Policy violations, deprecations, browser interventions, network errors, and crash reports.",
    good: "Having the Reporting API configured means you are actively collecting data about issues your users encounter. This helps you detect CSP violations, deprecated API usage, and other problems in production without relying on users to report them.",
    recommendation: "Configure a reporting endpoint using <code>Report-To</code> with a JSON value specifying group name, max age, and endpoint URLs. Pair with CSP's <code>report-to</code> directive to collect violation reports. Services like Report URI can collect these reports for free.",
    evaluate: (val) => {
      if (!val) return { status: "info", msg: "Not set. The site is not collecting browser reports. Consider enabling the Reporting API to monitor CSP violations and other errors in production." };
      return { status: "good", msg: "Reporting API is configured. The site collects browser reports for errors, CSP violations, and deprecations." };
    }
  }
};

// Information disclosure headers: these leak server/tech info to attackers.
// Not scored (matches securityheaders.com), just flagged as recommendations.
const DISCLOSURE_HEADERS = {
  "server": {
    label: "Server",
    check: (val) => {
      if (!val) return null; // Not present, nothing to flag
      // Flag if it contains a version number (e.g. nginx/1.18.0, Apache/2.4.41)
      if (/\/[\d]/.test(val))
        return { msg: `Exposes software version: "${escapeHtml(val)}". Remove the version number to make fingerprinting harder.`, detail: "Attackers use version info to look up known vulnerabilities for that exact release." };
      return null;
    }
  },
  "x-powered-by": {
    label: "X-Powered-By",
    check: (val) => {
      if (!val) return null;
      return { msg: `Exposes backend technology: "${escapeHtml(val)}". This header should be removed entirely.`, detail: "Knowing the framework/language helps attackers narrow down exploits. There is no reason to send this header." };
    }
  },
  "x-aspnet-version": {
    label: "X-AspNet-Version",
    check: (val) => {
      if (!val) return null;
      return { msg: `Exposes ASP.NET version: "${escapeHtml(val)}". Remove this header in your web.config.`, detail: "Version-specific exploits are well-documented for ASP.NET. Hiding this adds a layer of obscurity." };
    }
  },
  "x-aspnetmvc-version": {
    label: "X-AspNetMvc-Version",
    check: (val) => {
      if (!val) return null;
      return { msg: `Exposes ASP.NET MVC version: "${escapeHtml(val)}". Remove via MvcHandler.DisableMvcResponseHeader.`, detail: "This reveals your exact MVC framework version, making targeted attacks easier." };
    }
  },
  "x-generator": {
    label: "X-Generator",
    check: (val) => {
      if (!val) return null;
      return { msg: `Exposes site generator: "${escapeHtml(val)}". Consider removing this header.`, detail: "CMS and generator info helps attackers identify known vulnerabilities for your platform." };
    }
  },
  "via": {
    label: "Via",
    check: (val) => {
      if (!val) return null;
      return { msg: `Exposes proxy/gateway info: "${escapeHtml(val)}". Consider removing if not needed.`, detail: "This can reveal internal infrastructure details like proxy software and topology." };
    }
  },
  "x-debug-token": {
    label: "X-Debug-Token",
    check: (val) => {
      if (!val) return null;
      return { msg: "Debug token header is exposed. This should never be present in production.", detail: "Debug tokens can expose internal application state and aid in further attacks." };
    }
  },
  "x-debug-token-link": {
    label: "X-Debug-Token-Link",
    check: (val) => {
      if (!val) return null;
      return { msg: `Debug profiler link exposed: "${escapeHtml(val)}". Remove in production.`, detail: "This links directly to your debug profiler, a critical information leak in production." };
    }
  }
};

// Deprecated headers: still sent by many sites but no longer useful or actively harmful.
const DEPRECATED_HEADERS = {
  "expect-ct": {
    label: "Expect-CT",
    check: (val) => {
      if (!val) return null;
      return { msg: "This header is deprecated and being removed from browsers. It can be safely removed.", detail: "Certificate Transparency is now enforced by default in all major browsers. This header no longer does anything." };
    }
  },
  "public-key-pins": {
    label: "Public-Key-Pins",
    check: (val) => {
      if (!val) return null;
      return { msg: "HPKP has been removed from all browsers. Remove this header immediately.", detail: "HTTP Public Key Pinning was deprecated because misconfiguration could permanently brick your site. It has no effect now and wastes bytes." };
    }
  },
  "public-key-pins-report-only": {
    label: "Public-Key-Pins-Report-Only",
    check: (val) => {
      if (!val) return null;
      return { msg: "HPKP reporting has been removed from all browsers. This header can be safely removed.", detail: "Since HPKP itself is deprecated, the report-only variant serves no purpose." };
    }
  },
  "x-runtime": {
    label: "X-Runtime",
    check: (val) => {
      if (!val) return null;
      return { msg: `Exposes server processing time: "${escapeHtml(val)}". Consider removing.`, detail: "Timing information can help attackers perform timing-based side-channel attacks to enumerate users or detect differences in code paths." };
    }
  }
};

// --- Cookies ----------------------------------------------------------------------

// Split a Set-Cookie string into "name=", value, and "; attributes". Only the
// part before the first ';' holds name and value. A pair without '=' is a
// nameless cookie whose whole pair is the value, so it must not be shown as the name.
function splitCookie(cookieStr) {
  cookieStr = String(cookieStr || "");
  const semiIdx = cookieStr.indexOf(";");
  const pair = semiIdx === -1 ? cookieStr : cookieStr.substring(0, semiIdx);
  const attrsPart = semiIdx === -1 ? "" : cookieStr.substring(semiIdx);
  const eqIdx = pair.indexOf("=");
  if (eqIdx === -1) return { namePart: "", valuePart: pair, attrsPart };
  return { namePart: pair.substring(0, eqIdx + 1), valuePart: pair.substring(eqIdx + 1), attrsPart };
}

// Cookie attributes as { lowercased name: value }. When an attribute repeats, the
// last one wins, as in browsers.
function cookieAttributes(cookieStr) {
  const attrs = Object.create(null);
  for (const raw of splitCookie(cookieStr).attrsPart.split(";").slice(1)) {
    const eq = raw.indexOf("=");
    const key = (eq === -1 ? raw : raw.substring(0, eq)).trim().toLowerCase();
    if (key) attrs[key] = eq === -1 ? "" : raw.substring(eq + 1).trim();
  }
  return attrs;
}

// Cookie security analysis. `rejected` lists reasons the browser refuses to store it.
function analyzeCookie(cookieStr) {
  const name = splitCookie(cookieStr).namePart.slice(0, -1).trim();
  const attrs = cookieAttributes(cookieStr);

  const hasSecure = "secure" in attrs;
  const hasHttpOnly = "httponly" in attrs;
  const sameSite = "samesite" in attrs ? attrs.samesite.toLowerCase() : null;
  const partitioned = "partitioned" in attrs;
  const lowerName = name.toLowerCase();
  const isHostPrefix = lowerName.startsWith("__host-");
  const isSecurePrefix = lowerName.startsWith("__secure-");

  const flags = [];
  const issues = [];
  const rejected = [];

  if (hasSecure) flags.push("Secure");
  else issues.push("Missing <code>Secure</code> flag. Cookie can be sent over unencrypted HTTP.");

  if (hasHttpOnly) flags.push("HttpOnly");
  else issues.push("Missing <code>HttpOnly</code> flag. Cookie is accessible to JavaScript (document.cookie).");

  if (sameSite === "strict" || sameSite === "lax") {
    flags.push(`SameSite=${sameSite.charAt(0).toUpperCase() + sameSite.slice(1)}`);
  } else if (sameSite === "none") {
    // SameSite=None disables CSRF protection. securityheaders.com treats this as "not a SameSite cookie"
    issues.push("<code>SameSite=None</code>. This effectively disables SameSite CSRF protection. Consider <code>SameSite=Lax</code> or <code>Strict</code>.");
    if (!hasSecure) rejected.push("<code>SameSite=None</code> requires the <code>Secure</code> flag");
  } else if (sameSite !== null) {
    issues.push(`Unrecognized <code>SameSite</code> value "${escapeHtml(attrs.samesite)}". Browsers ignore it and fall back to Lax.`);
  } else {
    issues.push("Missing <code>SameSite</code> attribute. Browsers default to Lax, but setting it explicitly is recommended.");
  }

  if (partitioned) {
    flags.push("Partitioned");
    if (!hasSecure) rejected.push("<code>Partitioned</code> requires the <code>Secure</code> flag");
  }

  // Name prefixes are enforced by the browser: a cookie that breaks the rules is not stored
  if (isHostPrefix) {
    const problems = [];
    if (!hasSecure) problems.push("<code>Secure</code>");
    if (attrs.path !== "/") problems.push("<code>Path=/</code>");
    if ("domain" in attrs) problems.push("no <code>Domain</code>");
    if (problems.length > 0) rejected.push(`<code>__Host-</code> cookies require ${problems.join(", ")}`);
  } else if (isSecurePrefix && !hasSecure) {
    rejected.push("<code>__Secure-</code> cookies require the <code>Secure</code> flag");
  }
  const hasPrefix = (isHostPrefix || isSecurePrefix) && rejected.length === 0;

  // Only flag missing prefix for known session cookies (matching securityheaders.com behavior)
  const sessionPatterns = /^(phpsessid|jsessionid|asp\.net_sessionid|aspsessionid|connect\.sid|session_?id|sessionid|sid|_session|laravel_session|ci_session|cgisessid|wordpress_logged_in|wp-settings)/i;
  const isSessionCookie = sessionPatterns.test(name);

  if (hasPrefix) {
    flags.push("Prefixed");
  } else if (isSessionCookie && !isHostPrefix && !isSecurePrefix) {
    issues.push("No <code>__Secure-</code> or <code>__Host-</code> cookie prefix. Prefixed cookies provide additional protection against cookie injection.");
  }

  for (const reason of rejected) issues.unshift(`Rejected by browsers: ${reason}. This cookie is never stored.`);

  return { name, flags, issues, rejected, hasSecure, hasHttpOnly, sameSite, hasPrefix, isSessionCookie };
}

// --- Grading --------------------------------------------------------------------

// Weighted scoring based on the securityheaders.com methodology
// Source: https://snyk.io/blog/website-security-score-explained/
// 2.0 is stricter: a header only earns points if browsers actually apply its value.
const HEADER_WEIGHTS = {
  "content-security-policy":   25,
  "strict-transport-security": 25,
  "x-frame-options":           20,
  "x-content-type-options":    20,
  "referrer-policy":           15,
  "permissions-policy":        15
};
const MAX_SCORE = 120;

// Whether a scored header protects the page, with a short plain-text reason.
// The popup's evaluate() shows "bad" exactly when this returns counts: false.
function scoredHeaderVerdict(key, headers, url) {
  const val = headers[key];
  switch (key) {
    case "content-security-policy":
      if (!val) return { counts: false, reason: "Missing" };
      if (Object.keys(parseCSP(val)).length === 0) return { counts: false, reason: "No directives" };
      return { counts: true, reason: "Policy set" };
    case "strict-transport-security": {
      if (!val) return { counts: false, reason: "Missing" };
      if (isPlainHttp(url)) return { counts: false, reason: "Ignored over plain HTTP" };
      const maxAge = hstsMaxAge(val);
      if (maxAge === null) return { counts: false, reason: "No valid max-age" };
      if (maxAge === 0) return { counts: false, reason: "max-age=0 turns HSTS off" };
      return { counts: true, reason: `max-age=${maxAge}` };
    }
    case "x-frame-options": {
      const frameAncestors = parseCSP(headers["content-security-policy"] || "")["frame-ancestors"];
      if (frameAncestors) {
        return frameAncestorsAllowsAny(frameAncestors)
          ? { counts: false, reason: "CSP frame-ancestors allows any site" }
          : { counts: true, reason: "CSP frame-ancestors" };
      }
      const policy = xfoPolicy(val);
      if (policy) return { counts: true, reason: policy.toUpperCase() };
      return { counts: false, reason: val ? "Invalid value" : "Missing" };
    }
    case "x-content-type-options":
      if (!val) return { counts: false, reason: "Missing" };
      return hasNosniff(val) ? { counts: true, reason: "nosniff" } : { counts: false, reason: "Invalid value" };
    case "referrer-policy": {
      if (!val) return { counts: false, reason: "Missing" };
      const policy = effectiveReferrerPolicy(val);
      if (!policy) return { counts: false, reason: "No recognized value" };
      if (policy === "unsafe-url" || policy === "no-referrer-when-downgrade") return { counts: false, reason: `${policy} leaks full URLs` };
      return { counts: true, reason: policy };
    }
    case "permissions-policy": {
      if (!val) return { counts: false, reason: "Missing" };
      const features = parsePermissionsPolicy(val);
      if (!features) return { counts: false, reason: "Invalid syntax, ignored" };
      const n = features.length;
      return n > 0 ? { counts: true, reason: `${n} feature${n === 1 ? "" : "s"} configured` } : { counts: false, reason: "No allowlists" };
    }
  }
  return { counts: !!val, reason: val ? "Set" : "Missing" };
}

// Grade a response. url is the page URL (HSTS only counts over HTTPS).
// breakdown lists every scored header; penalty is set when the CSP caps the score.
function computeGrade(headers, url) {
  const breakdown = Object.keys(HEADER_WEIGHTS).map((key) => {
    const verdict = scoredHeaderVerdict(key, headers, url);
    return { key, label: SECURITY_HEADERS[key].label, weight: HEADER_WEIGHTS[key], counts: verdict.counts, reason: verdict.reason, points: verdict.counts ? HEADER_WEIGHTS[key] : 0 };
  });
  let score = breakdown.reduce((sum, b) => sum + b.points, 0);
  const present = breakdown.filter(b => b.counts).length;

  // CSP quality penalty: caps the score if scripts allow unsafe-inline or unsafe-eval
  let penalty = null;
  const weak = cspScriptWeaknesses(parseCSP(headers["content-security-policy"] || ""));
  if (weak.unsafeInline || weak.unsafeEval) {
    const capped = Math.min(score, MAX_SCORE * 0.82);
    if (capped < score) {
      const what = [weak.unsafeInline && `'unsafe-inline' in ${weak.unsafeInline}`, weak.unsafeEval && `'unsafe-eval' in ${weak.unsafeEval}`].filter(Boolean).join(" and ");
      penalty = { points: capped - score, reason: `CSP allows ${what}: score capped at 82%` };
    }
    score = capped;
  }

  const pct = (score / MAX_SCORE) * 100;
  let letter, color, cssClass;
  if (pct >= 95) {
    letter = "A+"; color = "#4ec83d"; cssClass = "grade-aplus";
  } else if (pct >= 75) {
    letter = "A"; color = "#41a832"; cssClass = "grade-a";
  } else if (pct >= 60) {
    letter = "B"; color = "#ffd242"; cssClass = "grade-b";
  } else if (pct >= 50) {
    letter = "C"; color = "#ffd242"; cssClass = "grade-c";
  } else if (pct >= 15) {
    letter = "D"; color = "#ffa500"; cssClass = "grade-d";
  } else if (pct >= 5) {
    letter = "E"; color = "#ffa500"; cssClass = "grade-e";
  } else {
    letter = "F"; color = "#ff0000"; cssClass = "grade-f";
  }

  return { letter, color, cssClass, present, total: breakdown.length, score, pct, breakdown, penalty };
}

// Node (tests) only: browsers have no `module`
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    DEFAULT_SETTINGS, escapeHtml, isHttpUrl, isPlainHttp, scanTargetUrl, listTokens, parseCSP, cspScriptWeaknesses,
    frameAncestorsAllowsAny, hstsMaxAge, hstsHasDirective, xfoPolicy, hasNosniff, effectiveReferrerPolicy,
    permissionsPolicyFeatures, parsePermissionsPolicy, splitCookie, cookieAttributes, analyzeCookie, scoredHeaderVerdict, computeGrade,
    SECURITY_HEADERS, ADDITIONAL_HEADERS, DISCLOSURE_HEADERS, DEPRECATED_HEADERS, HEADER_WEIGHTS, MAX_SCORE
  };
}
