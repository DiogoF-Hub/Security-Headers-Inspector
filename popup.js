// Header definitions: what to check, how to evaluate, descriptions
const SECURITY_HEADERS = {
  "content-security-policy": {
    label: "Content-Security-Policy",
    about: "Content Security Policy is an effective measure to protect your site from XSS attacks. By whitelisting sources of approved content, you can prevent the browser from loading malicious assets. It lets you define where scripts, styles, images, fonts, and other resources can be loaded from.",
    good: "A well-configured CSP significantly reduces the risk of cross-site scripting and data injection attacks. It acts as a second layer of defense against injection vulnerabilities.",
    recommendation: "Start with a strict policy like <code>default-src 'none'</code> and selectively allow only what your site needs. Avoid <code>'unsafe-inline'</code> and <code>'unsafe-eval'</code> when possible as they weaken protection considerably.",
    evaluate: (val) => {
      if (!val) return { status: "bad", msg: "Missing — your site has no Content Security Policy, leaving it vulnerable to XSS and data injection attacks." };

      // Parse directives
      const directives = {};
      val.split(";").forEach((d) => {
        const parts = d.trim().split(/\s+/);
        if (parts.length > 0) directives[parts[0]] = parts.slice(1);
      });

      const warnings = [];
      const scriptSrc = directives["script-src"] || directives["default-src"] || [];
      const defaultSrc = directives["default-src"] || [];
      const objectSrc = directives["object-src"] || defaultSrc;
      const baseSrc = directives["base-uri"] || [];

      // 'strict-dynamic' negates 'unsafe-inline' in modern browsers — don't flag it
      const hasStrictDynamic = scriptSrc.includes("'strict-dynamic'");
      const hasNonce = scriptSrc.some(s => s.startsWith("'nonce-"));
      const hasHash = scriptSrc.some(s => /^'sha(256|384|512)-/.test(s));

      // Check 'unsafe-eval' (but not 'wasm-unsafe-eval')
      if (scriptSrc.some(s => s === "'unsafe-eval'"))
        warnings.push("script-src uses <code>'unsafe-eval'</code> — allows dynamic code execution via eval().");

      // Check 'unsafe-inline' — only flag if strict-dynamic/nonce/hash don't negate it
      if (scriptSrc.includes("'unsafe-inline'") && !hasStrictDynamic && !hasNonce && !hasHash)
        warnings.push("script-src uses <code>'unsafe-inline'</code> — allows inline scripts, weakening XSS protection.");

      // Wildcard * in script-src
      if (scriptSrc.includes("*"))
        warnings.push("script-src contains <code>*</code> wildcard — scripts can be loaded from any origin.");

      // data: in script-src — allows base64-encoded script injection
      if (scriptSrc.includes("data:"))
        warnings.push("script-src allows <code>data:</code> URIs — attackers can inject base64-encoded scripts.");

      // http: in script-src — mixed content, MITM risk
      if (scriptSrc.some(s => s.startsWith("http://")))
        warnings.push("script-src allows <code>http://</code> sources — scripts loaded over plain HTTP can be intercepted.");

      // Missing default-src — no fallback for undeclared directives
      if (!directives["default-src"])
        warnings.push("No <code>default-src</code> directive — undeclared resource types have no restrictions.");

      // object-src not restricted — Flash/plugin injection vector
      if (objectSrc.length === 0 || (objectSrc.length === 1 && objectSrc[0] === "'self'")) {
        // Fine
      } else if (!objectSrc.includes("'none'") && !directives["object-src"]) {
        warnings.push("<code>object-src</code> is not explicitly set — consider setting to <code>'none'</code> to block plugins.");
      }

      // base-uri not restricted — allows base tag injection
      if (baseSrc.length === 0 && !directives["base-uri"])
        warnings.push("<code>base-uri</code> is not set — attackers could inject a <code>&lt;base&gt;</code> tag to hijack relative URLs.");

      // Wildcard in any directive
      const wildcardDirs = Object.entries(directives)
        .filter(([k, v]) => k !== "script-src" && v.includes("*"))
        .map(([k]) => k);
      if (wildcardDirs.length > 0)
        warnings.push(`Wildcard <code>*</code> found in: ${wildcardDirs.map(d => `<code>${d}</code>`).join(", ")}.`);

      if (warnings.length === 0)
        return { status: "good", msg: "Well configured — approved content sources are whitelisted." };

      return { status: "warn", msg: warnings.join("<br>") };
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
    evaluate: (val, allHeaders) => {
      if (!val) {
        // Check if CSP frame-ancestors covers this
        const csp = (allHeaders && allHeaders["content-security-policy"]) || "";
        if (/frame-ancestors\s/.test(csp)) {
          return { status: "good", msg: "Not set, but CSP frame-ancestors is configured — this is the modern replacement and takes precedence." };
        }
        return { status: "bad", msg: "Missing — your site can be embedded in iframes by any page, making it vulnerable to clickjacking." };
      }
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
  },
  "x-robots-tag": {
    label: "X-Robots-Tag",
    about: "The X-Robots-Tag HTTP header controls how search engines index and display your pages. It works like the <code>&lt;meta name=\"robots\"&gt;</code> HTML tag but applies at the HTTP level — useful for non-HTML resources (PDFs, images) or when you want server-wide control without modifying page content.",
    good: "Controlling search engine behavior lets you prevent sensitive pages from appearing in search results, stop caching of private content, and manage how your site is represented in search engines. For internal tools or private services, <code>noindex, nofollow</code> keeps them out of search entirely.",
    recommendation: "Set to <code>noindex, nofollow</code> for private or internal pages. Use <code>noindex</code> alone to prevent indexing but still allow link following. For public pages, this header is usually not needed — search engines index by default.",
    evaluate: (val) => {
      if (!val) return { status: "info", msg: "Not set — search engines will index this page by default. Set this header if you want to control search engine behavior at the HTTP level." };
      const lower = val.toLowerCase();
      const hasNoindex = /noindex/.test(lower);
      const hasNofollow = /nofollow/.test(lower);
      const hasNone = /\bnone\b/.test(lower);
      if (hasNone || (hasNoindex && hasNofollow))
        return { status: "good", msg: `Set to "${val.trim()}" — page is hidden from search engines and links are not followed.` };
      if (hasNoindex)
        return { status: "good", msg: `Set to "${val.trim()}" — page will not appear in search results.` };
      if (hasNofollow)
        return { status: "info", msg: `Set to "${val.trim()}" — search engines won't follow links on this page, but the page itself may still be indexed.` };
      return { status: "info", msg: `Set to "${val.trim()}".` };
    }
  },
  "alt-svc": {
    label: "Alt-Svc",
    about: "The Alt-Svc (Alternative Services) header advertises that the same resource is available over a different protocol or network endpoint. Most commonly, it tells the browser that HTTP/3 (QUIC) is available, enabling faster, more reliable connections with built-in encryption and reduced latency.",
    good: "HTTP/3 uses QUIC, a UDP-based transport protocol with built-in TLS 1.3 encryption. It eliminates head-of-line blocking, reduces connection setup time (0-RTT), and handles network changes (e.g., switching from Wi-Fi to mobile) more gracefully than TCP.",
    recommendation: "If your server supports HTTP/3 (QUIC), this header is set automatically. Major web servers (Nginx, Caddy, LiteSpeed) and CDNs (Cloudflare, Fastly) support it. No action needed if you see <code>h3</code> in the value.",
    evaluate: (val) => {
      if (!val) return { status: "info", msg: "Not set — the site is not advertising HTTP/3 (QUIC) support. The site uses HTTP/1.1 or HTTP/2 only." };
      const hasH3 = /h3/.test(val);
      if (hasH3)
        return { status: "good", msg: "HTTP/3 (QUIC) is available — faster, more reliable connections with built-in TLS 1.3 encryption." };
      return { status: "info", msg: `Alternative service advertised: "${val.trim()}".` };
    }
  }
};

// Information disclosure headers — these leak server/tech info to attackers.
// Not scored (matches securityheaders.com), just flagged as recommendations.
const DISCLOSURE_HEADERS = {
  "server": {
    label: "Server",
    check: (val) => {
      if (!val) return null; // Not present, nothing to flag
      // Flag if it contains a version number (e.g. nginx/1.18.0, Apache/2.4.41)
      if (/\/[\d]/.test(val))
        return { msg: `Exposes software version: "${val}". Remove the version number to make fingerprinting harder.`, detail: "Attackers use version info to look up known vulnerabilities for that exact release." };
      return null;
    }
  },
  "x-powered-by": {
    label: "X-Powered-By",
    check: (val) => {
      if (!val) return null;
      return { msg: `Exposes backend technology: "${val}". This header should be removed entirely.`, detail: "Knowing the framework/language helps attackers narrow down exploits. There is no reason to send this header." };
    }
  },
  "x-aspnet-version": {
    label: "X-AspNet-Version",
    check: (val) => {
      if (!val) return null;
      return { msg: `Exposes ASP.NET version: "${val}". Remove this header in your web.config.`, detail: "Version-specific exploits are well-documented for ASP.NET. Hiding this adds a layer of obscurity." };
    }
  },
  "x-aspnetmvc-version": {
    label: "X-AspNetMvc-Version",
    check: (val) => {
      if (!val) return null;
      return { msg: `Exposes ASP.NET MVC version: "${val}". Remove via MvcHandler.DisableMvcResponseHeader.`, detail: "This reveals your exact MVC framework version, making targeted attacks easier." };
    }
  },
  "x-generator": {
    label: "X-Generator",
    check: (val) => {
      if (!val) return null;
      return { msg: `Exposes site generator: "${val}". Consider removing this header.`, detail: "CMS and generator info helps attackers identify known vulnerabilities for your platform." };
    }
  },
  "via": {
    label: "Via",
    check: (val) => {
      if (!val) return null;
      return { msg: `Exposes proxy/gateway info: "${val}". Consider removing if not needed.`, detail: "This can reveal internal infrastructure details like proxy software and topology." };
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
      return { msg: `Debug profiler link exposed: "${val}". Remove in production.`, detail: "This links directly to your debug profiler — a critical information leak in production." };
    }
  }
};

// Deprecated headers — still sent by many sites but no longer useful or actively harmful.
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
      return { msg: `Exposes server processing time: "${val}". Consider removing.`, detail: "Timing information can help attackers perform timing-based side-channel attacks to enumerate users or detect differences in code paths." };
    }
  }
};

// Cookie security analysis
function analyzeCookie(cookieStr) {
  const lower = cookieStr.toLowerCase();

  // Extract cookie name (everything before the first '=')
  const name = cookieStr.split("=")[0].trim();

  const hasSecure = /;\s*secure/i.test(lower);
  const hasHttpOnly = /;\s*httponly/i.test(lower);
  const sameSiteMatch = lower.match(/;\s*samesite=(\w+)/);
  const sameSite = sameSiteMatch ? sameSiteMatch[1] : null;
  const hasPrefix = name.startsWith("__Secure-") || name.startsWith("__Host-");

  const flags = [];
  const issues = [];

  if (hasSecure) flags.push("Secure");
  else issues.push("Missing <code>Secure</code> flag — cookie can be sent over unencrypted HTTP.");

  if (hasHttpOnly) flags.push("HttpOnly");
  else issues.push("Missing <code>HttpOnly</code> flag — cookie is accessible to JavaScript (document.cookie).");

  if (sameSite && sameSite !== "none") {
    flags.push(`SameSite=${sameSite.charAt(0).toUpperCase() + sameSite.slice(1)}`);
  } else if (sameSite === "none") {
    // SameSite=None disables CSRF protection — securityheaders.com treats this as "not a SameSite cookie"
    issues.push("<code>SameSite=None</code> — this effectively disables SameSite CSRF protection. Consider <code>SameSite=Lax</code> or <code>Strict</code>.");
    if (!hasSecure) issues.push("<code>SameSite=None</code> also requires the <code>Secure</code> flag.");
  } else {
    issues.push("Missing <code>SameSite</code> attribute — browsers default to Lax, but setting it explicitly is recommended.");
  }

  // Only flag missing prefix for known session cookies (matching securityheaders.com behavior)
  const sessionPatterns = /^(phpsessid|jsessionid|asp\.net_sessionid|aspsessionid|connect\.sid|session_?id|sessionid|sid|_session|laravel_session|ci_session|cgisessid|wordpress_logged_in|wp-settings)/i;
  const isSessionCookie = sessionPatterns.test(name);

  if (hasPrefix) {
    flags.push("Prefixed");
  } else if (isSessionCookie) {
    issues.push("No <code>__Secure-</code> or <code>__Host-</code> cookie prefix. Prefixed cookies provide additional protection against cookie injection.");
  }

  return { name, flags, issues, hasSecure, hasHttpOnly, sameSite, hasPrefix };
}

// Weighted scoring matching securityheaders.com methodology
// Source: https://snyk.io/blog/website-security-score-explained/
const HEADER_WEIGHTS = {
  "content-security-policy":   25,
  "strict-transport-security": 25,
  "x-frame-options":           20,
  "x-content-type-options":    20,
  "referrer-policy":           15,
  "permissions-policy":        15
};
const MAX_SCORE = 120;

function computeGrade(headers) {
  const securityKeys = Object.keys(SECURITY_HEADERS);
  const csp = headers["content-security-policy"] || "";
  const hasFrameAncestors = /frame-ancestors\s/.test(csp);

  let score = 0;
  let present = 0;

  for (const h of securityKeys) {
    const isPresent = headers[h] || (h === "x-frame-options" && hasFrameAncestors);
    if (isPresent) {
      score += HEADER_WEIGHTS[h] || 0;
      present++;
    }
  }

  // CSP quality penalties
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

    if (scriptSrc.includes("'unsafe-inline'") && !hasStrictDynamic && !hasNonce && !hasHash) {
      score = Math.min(score, MAX_SCORE * 0.82);
    }
    if (scriptSrc.some(s => s === "'unsafe-eval'")) {
      score = Math.min(score, MAX_SCORE * 0.82);
    }
  }

  const pct = (score / MAX_SCORE) * 100;
  let letter, cssClass;

  if (pct >= 95) {
    letter = "A+"; cssClass = "grade-aplus";
  } else if (pct >= 75) {
    letter = "A"; cssClass = "grade-a";
  } else if (pct >= 60) {
    letter = "B"; cssClass = "grade-b";
  } else if (pct >= 50) {
    letter = "C"; cssClass = "grade-c";
  } else if (pct >= 29) {
    letter = "D"; cssClass = "grade-d";
  } else if (pct >= 14) {
    letter = "E"; cssClass = "grade-e";
  } else {
    letter = "F"; cssClass = "grade-f";
  }

  return { letter, cssClass, present, total: securityKeys.length, score, pct };
}

// Ask the background page to fetch headers — the background's fetch triggers
// webRequest which can see ALL headers including HSTS
function fetchHeadersViaBackground(url, tabId) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "fetchHeaders", url: url, tabId: tabId }, (response) => {
      resolve(response);
    });
  });
}

// Store current headers for copy button
let currentHeaders = null;

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
    document.getElementById("external-scans").style.display = "none";
    return;
  }

  const headers = data.headers;
  currentHeaders = headers;
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
    `${grade.present}/${grade.total} security headers present — Score: ${Math.round(grade.pct)}%`;

  // Check if CSP frame-ancestors covers X-Frame-Options
  const csp = headers["content-security-policy"] || "";
  const hasFrameAncestors = /frame-ancestors\s/.test(csp);

  // Quick status pills
  quickStatus.innerHTML = "";
  for (const [key, def] of Object.entries(SECURITY_HEADERS)) {
    const isPresent = headers[key] || (key === "x-frame-options" && hasFrameAncestors);
    const pill = document.createElement("span");
    pill.className = `status-pill ${isPresent ? "present" : "missing"}`;
    pill.textContent = def.label;
    quickStatus.appendChild(pill);
  }

  // Security headers detail list
  const secList = document.getElementById("security-headers-list");
  secList.innerHTML = "";
  for (const [key, def] of Object.entries(SECURITY_HEADERS)) {
    secList.appendChild(createHeaderItem(key, def, headers[key], headers));
  }

  // Additional headers detail list
  const addList = document.getElementById("additional-headers-list");
  addList.innerHTML = "";
  for (const [key, def] of Object.entries(ADDITIONAL_HEADERS)) {
    addList.appendChild(createHeaderItem(key, def, headers[key], headers));
  }

  // Cookie analysis
  const cookieSection = document.getElementById("cookie-section");
  const cookieList = document.getElementById("cookie-list");
  cookieList.innerHTML = "";
  // Use cookies array from webRequest; fall back to headers["set-cookie"] if empty
  let cookies = data.cookies || [];
  if (cookies.length === 0 && headers["set-cookie"]) {
    cookies = [headers["set-cookie"]];
  }

  if (cookies.length > 0) {
    cookieSection.style.display = "";
    for (const cookieStr of cookies) {
      const analysis = analyzeCookie(cookieStr);
      const allGood = analysis.issues.length === 0;

      const item = document.createElement("div");
      item.className = `cookie-item ${allGood ? "cookie-good" : "cookie-warn"}`;

      const flagsHtml = analysis.flags.map(f =>
        `<span class="cookie-flag good">${escapeHtml(f)}</span>`
      ).join("");

      const missingHtml = !analysis.hasSecure ? '<span class="cookie-flag missing">Secure</span>' : '';
      const missingHttp = !analysis.hasHttpOnly ? '<span class="cookie-flag missing">HttpOnly</span>' : '';
      const missingSame = !analysis.sameSite ? '<span class="cookie-flag missing">SameSite</span>' : '';
      const missingPrefix = !analysis.hasPrefix ? '<span class="cookie-flag missing">Prefix</span>' : '';

      const statusIcon = allGood ? '<span class="status-icon good">✔</span>' : '<span class="status-icon warn">⚠</span>';

      // Extract cookie value (everything after name=)
      const eqIdx = cookieStr.indexOf("=");
      const cookieValue = eqIdx !== -1 ? cookieStr.substring(eqIdx + 1).split(";")[0].trim() : "";

      item.innerHTML = `
        <div class="cookie-header-row">
          <span class="cookie-name"><span class="expand-chevron">▸</span> ${escapeHtml(analysis.name)}</span>
          ${statusIcon}
        </div>
        <div class="cookie-flags">${flagsHtml}${missingHtml}${missingHttp}${missingSame}${missingPrefix}</div>
        <div class="cookie-value-blurred">${escapeHtml(cookieValue || "(empty)")}</div>
        <div class="cookie-reveal-hint">Click to reveal value</div>
        <div class="cookie-details">
          ${analysis.issues.length > 0 ? '<div class="desc-verdict">' + analysis.issues.join('<br>') + '</div>' : '<div class="desc-verdict" style="color:#2ecc40;">All recommended cookie security flags are present.</div>'}
          <div class="desc-section">
            <div class="desc-title">What are cookie flags?</div>
            <div class="desc-text"><strong>Secure</strong> — Cookie is only sent over HTTPS, preventing interception on unencrypted connections.<br><strong>HttpOnly</strong> — Cookie cannot be accessed by JavaScript (document.cookie), mitigating XSS theft.<br><strong>SameSite</strong> — Controls whether cookie is sent with cross-site requests, preventing CSRF attacks.<br><strong>Prefix</strong> — <code>__Secure-</code> or <code>__Host-</code> prefixes add extra browser-enforced constraints on the cookie.</div>
          </div>
          <div class="desc-section">
            <div class="desc-title">Recommendation</div>
            <div class="desc-text">Set all cookies with <code>Secure; HttpOnly; SameSite=Lax</code> (or <code>Strict</code>) flags. Use <code>__Host-</code> prefix for session cookies where possible.</div>
          </div>
        </div>
      `;

      item.querySelector(".cookie-header-row").addEventListener("click", () => {
        item.classList.toggle("expanded");
      });

      // Click to reveal blurred cookie value
      const blurredVal = item.querySelector(".cookie-value-blurred");
      blurredVal.addEventListener("click", (e) => {
        e.stopPropagation();
        blurredVal.classList.toggle("revealed");
      });

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
          <span><span class="expand-chevron">▸</span> ${def.label}</span>
          <span class="status-icon warn">⚠</span>
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
      item.querySelector(".disclosure-header-row").addEventListener("click", () => {
        item.classList.toggle("expanded");
      });
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
          <span><span class="expand-chevron">▸</span> ${def.label}</span>
          <span class="status-icon info">ℹ</span>
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
      item.querySelector(".deprecated-header-row").addEventListener("click", () => {
        item.classList.toggle("expanded");
      });
      deprecatedList.appendChild(item);
    }
  }
  deprecatedSection.style.display = deprecatedFound ? "" : "none";

  // Raw headers — color-coded by type, with good tokens highlighted
  const securitySet = new Set(Object.keys(SECURITY_HEADERS).concat(Object.keys(ADDITIONAL_HEADERS)));
  const disclosureSet = new Set(Object.keys(DISCLOSURE_HEADERS));
  const deprecatedSet = new Set(Object.keys(DEPRECATED_HEADERS));

  const rawContainer = document.getElementById("raw-headers");
  rawContainer.innerHTML = "";
  const sortedKeys = Object.keys(headers).sort();
  for (const key of sortedKeys) {
    if (key === "set-cookie" && data.cookies && data.cookies.length > 0) continue; // shown individually below
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
  let rawCookies = data.cookies || [];
  if (rawCookies.length === 0 && headers["set-cookie"]) {
    rawCookies = [headers["set-cookie"]];
  }
  if (rawCookies.length > 0) {
    for (const cookieStr of rawCookies) {
      const row = document.createElement("div");
      const cookieAnalysis = analyzeCookie(cookieStr);
      const cookieOk = cookieAnalysis.issues.length === 0;
      row.className = `raw-row ${cookieOk ? "raw-cookie-good" : "raw-cookie-warn"}`;

      // Split cookie into name=value and ;flags so we only blur the value
      const eqIdx = cookieStr.indexOf("=");
      const semiIdx = cookieStr.indexOf(";");
      let namePart, valuePart, flagsPart;
      if (eqIdx !== -1) {
        namePart = cookieStr.substring(0, eqIdx + 1); // "name="
        if (semiIdx !== -1 && semiIdx > eqIdx) {
          valuePart = cookieStr.substring(eqIdx + 1, semiIdx);
          flagsPart = cookieStr.substring(semiIdx); // "; Secure; HttpOnly; ..."
        } else {
          valuePart = cookieStr.substring(eqIdx + 1);
          flagsPart = "";
        }
      } else {
        namePart = cookieStr;
        valuePart = "";
        flagsPart = "";
      }

      const flagsHtml = flagsPart ? highlightGoodTokens("set-cookie", flagsPart) : "";
      row.innerHTML = `<span class="raw-key">set-cookie</span><span class="raw-val">${escapeHtml(namePart)}<span class="raw-cookie-value blurred">${escapeHtml(valuePart)}</span>${flagsHtml}</span>`;

      // Click to reveal only the blurred value portion
      const blurredSpan = row.querySelector(".raw-cookie-value");
      blurredSpan.addEventListener("click", (e) => {
        e.stopPropagation();
        blurredSpan.classList.toggle("revealed");
      });
      rawContainer.appendChild(row);
    }
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
};

function highlightGoodTokens(headerName, value) {
  const patterns = GOOD_TOKENS[headerName.toLowerCase()];
  if (!patterns || !value) return escapeHtml(value || "");

  // We need to escape first, then apply bold — but regex indices shift after escaping.
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

function createHeaderItem(key, def, value, allHeaders) {
  const result = def.evaluate(value, allHeaders);
  const item = document.createElement("div");
  item.className = `header-item ${result.status}`;

  const statusIcons = { good: "\u2714", bad: "\u2718", warn: "\u26A0", info: "\u2139" };

  // Determine grade impact badge
  const isScored = key in HEADER_WEIGHTS;
  let gradeBadgeHtml = "";
  if (isScored) {
    const weight = HEADER_WEIGHTS[key];
    if (result.status === "good") {
      gradeBadgeHtml = `<span class="grade-badge scored">+${weight} pts</span>`;
    } else if (result.status === "warn") {
      gradeBadgeHtml = `<span class="grade-badge scored-warn">⚠ ${weight} pts</span>`;
    } else {
      gradeBadgeHtml = `<span class="grade-badge scored-bad">−${weight} pts</span>`;
    }
  } else {
    gradeBadgeHtml = `<span class="grade-badge info-only">info</span>`;
  }

  item.innerHTML = `
    <div class="header-name">
      <span class="header-label">
        <span class="expand-chevron">&#9656;</span>
        ${def.label}
        ${gradeBadgeHtml}
      </span>
      <span class="status-icon ${result.status}">${statusIcons[result.status]}</span>
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
  const isOpen = details.classList.contains("show");
  details.classList.toggle("show");
  this.classList.toggle("expanded");
  this.innerHTML = isOpen
    ? 'Show Details <span class="arrow">&#9660;</span>'
    : 'Hide Details <span class="arrow">&#9650;</span>';
});

// Wire up raw headers toggle
document.getElementById("raw-toggle").addEventListener("click", function () {
  const raw = document.getElementById("raw-headers");
  raw.classList.toggle("show");
  this.classList.toggle("expanded");
});

// Copy raw headers to clipboard
document.getElementById("copy-raw-btn").addEventListener("click", function () {
  if (!currentHeaders) return;
  const btn = this;
  const sortedKeys = Object.keys(currentHeaders).sort();
  const text = sortedKeys.map(k => `${k}: ${currentHeaders[k]}`).join("\n");
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = "Copied!";
    btn.classList.add("copied");
    setTimeout(() => {
      btn.textContent = "Copy";
      btn.classList.remove("copied");
    }, 1500);
  });
});

// External scan buttons
function getHostname() {
  const el = document.getElementById("site-url");
  return el ? el.textContent.trim() : null;
}

document.getElementById("scan-secheaders").addEventListener("click", () => {
  const host = getHostname();
  if (host && host !== "Loading...") {
    chrome.tabs.create({ url: `https://securityheaders.com/?q=${encodeURIComponent(host)}&hide=on&followRedirects=on`, active: false });
  }
});

document.getElementById("scan-ssllabs").addEventListener("click", () => {
  const host = getHostname();
  if (host && host !== "Loading...") {
    chrome.tabs.create({ url: `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(host)}&hideResults=on&latest`, active: false });
  }
});

function renderInternalPage(url) {
  document.getElementById("header").style.display = "none";
  document.getElementById("quick-status").style.display = "none";
  document.getElementById("toggle-details").style.display = "none";
  document.getElementById("external-scans").style.display = "none";

  const el = document.getElementById("internal-page");
  el.classList.remove("hidden");

  document.getElementById("internal-scheme").textContent = (url || "").split(/[?#]/)[0].substring(0, 60) + ((url || "").length > 60 ? "..." : "");
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

    if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) {
      renderInternalPage(url);
      return;
    }

    // Show scanning state
    let hostname = url;
    try { hostname = new URL(url).hostname; } catch {}
    document.getElementById("site-url").textContent = hostname;
    document.getElementById("site-summary").textContent = "Fetching headers...";

    if (forceRefresh) {
      // Skip cache — always do a fresh fetch via background
      const data = await fetchHeadersViaBackground(url, tab.id);
      render(data);
    } else {
      // Try cached headers first
      chrome.runtime.sendMessage({ type: "getHeaders", tabId: tab.id }, async (response) => {
        if (response && response.headers && Object.keys(response.headers).length > 0) {
          render(response);
        } else {
          const data = await fetchHeadersViaBackground(url, tab.id);
          render(data);
        }
      });
    }
  });
}

// Rescan button
document.getElementById("rescan-btn").addEventListener("click", () => {
  const btn = document.getElementById("rescan-btn");
  btn.classList.add("spinning");
  setTimeout(() => btn.classList.remove("spinning"), 600);
  scanActiveTab(true);
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

// Load saved theme
chrome.storage.local.get("theme", (data) => {
  applyTheme(data.theme || "dark");
});

document.getElementById("theme-btn").addEventListener("click", () => {
  const isLight = document.body.classList.contains("light");
  const newTheme = isLight ? "dark" : "light";
  applyTheme(newTheme, true);
  chrome.storage.local.set({ theme: newTheme });
});

// Init
scanActiveTab();
