# Security Headers Inspector

A Chromium browser extension (Manifest V3) that checks the security headers of any website you visit. Inspired by [securityheaders.com](https://securityheaders.com/). Works on Chrome, Brave, Edge, Opera, and any Chromium-based browser.

**Current Version:** 2.0.0

## What It Does

Every website you visit automatically gets a **letter grade** (A+ through F) displayed on the extension badge. Click the icon for the full report:

- **Letter grade** with weighted scoring based on the securityheaders.com methodology, counting only header values browsers actually apply
- **Score breakdown** showing the points each header earned or lost, and why, plus any CSP penalty
- **Redirect chain** of the page load (for example `http → https → www`), including upgrades the browser made itself because of HSTS
- **Quick status pills** for an at-a-glance view of which core headers are present or missing
- **Detailed expandable cards** for each header with:
  - Current value (or "Not set")
  - Color-coded verdict (good / warn / bad)
  - "What is this?" plain-English explanation
  - "Why it matters" security implications
  - "Recommendation" what value to set
- **Deep CSP analysis** that flags `unsafe-inline`/`unsafe-eval` (in `script-src` and `script-src-elem`), `unsafe-hashes`, wildcards, `data:` URIs, `http:` sources, missing `default-src`/`object-src`/`base-uri`, correctly handles `strict-dynamic`/nonce/hash negation of `unsafe-inline`, suggests `frame-ancestors`, `form-action`, `upgrade-insecure-requests` and Trusted Types, and points out a `Report-Only` policy that doesn't block anything
- **HSTS preload check** showing whether the header meets the preload list requirements, with a link to hstspreload.org
- **Cookie security analysis** checking each `Set-Cookie` for `Secure`, `HttpOnly`, `SameSite`, `Partitioned`, and `__Secure-`/`__Host-` prefix rules, and flagging cookies browsers reject. Cookies set on redirects (common on login) are included
- **Information disclosure detection** flagging headers that leak server versions, frameworks, or debug info
- **Deprecated header detection** identifying headers that are no longer useful (Expect-CT, HPKP, etc.)
- **Color-coded raw headers** with security headers in green, info disclosure in amber, deprecated in purple, and good security tokens highlighted in bold
- **Copy to clipboard** for one-click copy of all raw headers (cookie values are hidden)
- **External scan shortcuts** with buttons and right-click menu to scan on SecurityHeaders.com and SSL Labs
- **Internal page detection** showing a friendly message on `chrome://`, `about:`, extension pages, etc.
- **Restricted page detection** that automatically detects pages Chromium blocks extensions from inspecting, with a "Why?" explainer and external scan buttons
- **Settings page** to turn background re-checks, the toolbar badge, and cookie value blurring on or off
- **Keyboard and screen reader support**: every expandable card and toggle works with Tab, Enter and Space, with proper ARIA labels

## Headers Evaluated

### Core Security Headers (used for grading)

| Header | What it does |
|--------|-------------|
| **Content-Security-Policy** | Whitelists approved content sources to prevent XSS |
| **Strict-Transport-Security** | Forces HTTPS, prevents protocol downgrade attacks |
| **X-Frame-Options** | Prevents clickjacking via iframe embedding |
| **X-Content-Type-Options** | Prevents MIME-sniffing attacks |
| **Referrer-Policy** | Controls how much referrer info leaks to other sites |
| **Permissions-Policy** | Controls which browser features (camera, mic, etc.) are allowed |

> **Note:** CSP's `frame-ancestors` directive counts as an X-Frame-Options equivalent for grading purposes, matching securityheaders.com behavior. Browsers use `frame-ancestors` instead of X-Frame-Options when both are set, so a `frame-ancestors *` policy means no clickjacking protection even with `X-Frame-Options: DENY`.

### Additional Headers (informational, no grade impact)

| Header | What it does |
|--------|-------------|
| **Cross-Origin-Opener-Policy** | Isolates browsing context from cross-origin windows |
| **Cross-Origin-Resource-Policy** | Controls who can load your resources |
| **Cross-Origin-Embedder-Policy** | Requires explicit permission for cross-origin resource loading |
| **X-XSS-Protection** | Legacy XSS auditor (should be `0`, rely on CSP instead) |
| **X-Robots-Tag** | Controls search engine indexing at the HTTP level |
| **Alt-Svc** | Advertises HTTP/3 (QUIC) support for faster, encrypted connections |
| **NEL** | Network Error Logging, collects reports on DNS, TLS, and connection failures |
| **Report-To** | Enables the Reporting API to collect browser error and CSP violation reports |

### Information Disclosure Headers (flagged when present)

| Header | Risk |
|--------|------|
| **Server** (with version) | Exposes web server software and version |
| **X-Powered-By** | Reveals backend framework/language |
| **X-AspNet-Version** | Exposes ASP.NET version |
| **X-AspNetMvc-Version** | Exposes ASP.NET MVC version |
| **X-Generator** | Reveals CMS or site generator |
| **Via** | Leaks proxy/gateway infrastructure details |
| **X-Debug-Token / X-Debug-Token-Link** | Exposes debug profiler, critical in production |

### Deprecated Headers (flagged when present)

| Header | Why it's deprecated |
|--------|-------------------|
| **Expect-CT** | Certificate Transparency is now enforced by default in all browsers |
| **Public-Key-Pins** | Removed from browsers due to risk of site lockout |
| **HPKP-Report-Only** | Removed alongside HPKP |
| **X-Runtime** | Exposes server processing time, no security benefit |

### Cookie Security Flags

Each `Set-Cookie` header is analyzed for:

| Flag | What it does |
|------|-------------|
| **Secure** | Cookie only sent over HTTPS |
| **HttpOnly** | Cookie inaccessible to JavaScript (`document.cookie`) |
| **SameSite** | Controls cross-site cookie behavior (CSRF protection) |
| **`__Secure-`/`__Host-` prefix** | Browser-enforced constraints on cookie scope (`__Host-` needs `Secure`, `Path=/` and no `Domain`) |
| **Partitioned** | Cookie kept separate per top-level site (CHIPS); needs `Secure` |

Cookies that break these rules (for example `SameSite=None` without `Secure`) are flagged as rejected: the browser never stores them.

## Grading System

Grading uses weighted per-header scores based on the securityheaders.com methodology:

| Header | Weight |
|--------|--------|
| Content-Security-Policy | 25 |
| Strict-Transport-Security | 25 |
| X-Frame-Options | 20 |
| X-Content-Type-Options | 20 |
| Referrer-Policy | 15 |
| Permissions-Policy | 15 |
| **Total** | **120** |

**CSP quality penalties:** If `script-src` (or `script-src-elem`) contains `unsafe-inline` (without `strict-dynamic`/nonce/hash to negate it) or `unsafe-eval`, the effective score is capped at 82%, preventing an A+ grade even with all headers present.

**Only values browsers apply earn points.** Since 2.0, a header that is present but ignored by browsers scores 0, so the grade can be stricter than securityheaders.com:

| Header | Earns no points when |
|--------|----------------------|
| Content-Security-Policy | It contains no directives |
| Strict-Transport-Security | It has no valid `max-age`, `max-age=0` (which switches HSTS off), or it's sent over plain HTTP (browsers ignore it there) |
| X-Frame-Options | The value isn't `DENY` or `SAMEORIGIN` (for example the obsolete `ALLOW-FROM`), or CSP `frame-ancestors` allows any site |
| X-Content-Type-Options | The first value isn't `nosniff` |
| Referrer-Policy | No recognized value, or the effective value is `unsafe-url` or `no-referrer-when-downgrade` (both send full URLs to other sites). With a list, the last recognized value is used, as in browsers |
| Permissions-Policy | It has a syntax error (for example features separated by spaces instead of commas), which makes browsers ignore the whole header, or no feature has an allowlist like `camera=()` |

| Grade | Score % |
|-------|---------|
| **A+** | >= 95% |
| **A** | >= 75% |
| **B** | >= 60% |
| **C** | >= 50% |
| **D** | >= 15% |
| **E** | >= 5% |
| **F** | < 5% |

## Architecture

### How It Works

```
┌─────────────────────────────────────────────────────────┐
│  Browser navigates to a page                            │
│         │                                               │
│         ▼                                               │
│  webRequest.onHeadersReceived (read-only observation)   │
│  (background.js, MV3 service worker)                    │
│         │                                               │
│         ├── Captures ALL response headers (incl. HSTS)  │
│         ├── Records redirects and cookies set on them   │
│         ├── Stores in chrome.storage.session by tab ID  │
│         ├── Collects Set-Cookie into separate array     │
│         ├── Handles 304 Not Modified (preserves cache)  │
│         └── Computes grade → sets badge                 │
│                                                         │
│  User clicks extension icon                             │
│         │                                               │
│         ▼                                               │
│  popup.js requests cached headers                       │
│         │                                               │
│         ├── If cached → render immediately              │
│         └── If not → background does fetch()            │
│              └── triggers webRequest internally         │
│                   └── captures full headers → render    │
└─────────────────────────────────────────────────────────┘
```

1. **Shared analysis** (`analysis.js`), loaded by the service worker, the popup, and the tests:
   - Header definitions and evaluation, CSP parsing, cookie analysis, and grading
   - Keeps the badge, the popup, and the tests grading exactly the same way

2. **Service worker** (`background.js`), the MV3 background script:
   - Listens to `webRequest.onHeadersReceived` with `extraHeaders`, but only keeps top-level page loads and the extension's own requests (never images, scripts or API calls)
   - Captures ALL response headers (including HSTS and Set-Cookie) and stores them via `chrome.storage.session`
   - Records the redirect chain with `webRequest.onBeforeRedirect`, including cookies set on redirects
   - Keeps a local in-memory cache synced to storage for fast access
   - Preserves cached headers on 304 Not Modified responses
   - Computes weighted grade and updates the extension badge per tab
   - Re-applies badge on `tabs.onUpdated` (browsers clear per-tab badges on navigation)
   - Knows when a page came from the browser cache (`webRequest.onResponseStarted`), which drops `Strict-Transport-Security` and `Set-Cookie`. It fills them in from an earlier network load of the same URL in this session, or else re-checks the page once (if enabled in the settings, never for Incognito tabs)
   - Scans the tabs that are open when the extension is installed (if enabled in the settings)
   - Handles `fetchHeaders` messages from the popup for on-demand scanning, always using the tab's own URL
   - Waits for webRequest to report the headers of its own requests instead of guessing a delay
   - Provides right-click context menu for external scans
   - Uses `chrome.alarms` for periodic cleanup (service worker timers don't persist)

3. **Popup** (`popup.html`, `popup.css`, `popup.js`), the UI:
   - Requests cached headers from background, falls back to fresh fetch if needed
   - Renders grade, score breakdown, redirect chain, pills, expandable detail cards, cookie analysis, disclosure/deprecated warnings
   - Color-codes raw headers by category with highlighted good security tokens
   - Detects non-HTTP pages (`chrome://`, `about:`, `file://`, extensions)

4. **Settings page** (`options.html`, `options.css`, `options.js`), saved in `chrome.storage.local`

### File Structure

```
Security-Headers-Inspector/
├── manifest.json       Manifest V3 config
├── analysis.js         Header evaluation, cookie analysis and grading (shared)
├── background.js       Service worker (webRequest + storage.session)
├── popup.html          Popup markup
├── popup.css           Popup styles (dark/light theme)
├── popup.js            Popup UI rendering
├── options.html        Settings page
├── options.css         Settings page styles
├── options.js          Settings page logic
├── welcome.html/.css   First-install welcome page
├── tests/
│   ├── unit/           Unit tests (Node, no dependencies)
│   └── e2e/            Browser tests (Playwright + Chromium)
├── .github/workflows/  CI running both test suites
├── package.sh / .ps1   Build the Chrome Web Store zip
└── icons/
    ├── icon.svg        Source icon
    ├── icon16.png      Toolbar icon
    ├── icon48.png      Extension page icon
    └── icon128.png     Store/install icon
```

## Installation

### Chrome Web Store

[**Install from Chrome Web Store**](https://chromewebstore.google.com/detail/Security%20Headers%20Inspector/glhchddldhembfjaicaelbimfbnpfoen)

### Manual (Developer Mode)

1. Open `chrome://extensions/`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select the extension folder
5. Visit any website, the badge shows the grade instantly. Click for the full report

### Settings

Right-click the extension icon → **Options** (or use the ⚙ button in the popup):

| Setting | Default | What it does |
|---------|---------|--------------|
| Re-check incomplete pages in the background | On | Browsers don't keep `Strict-Transport-Security` and `Set-Cookie` in their cache, so a page loaded from cache looks like it's missing them. The extension then requests the page once more (without cookies), unless it already saw the same page load from the network in this session. Also scans the tabs open at install. Pages loaded from the network are never re-requested. When off, the toolbar grade can be wrong for cached pages; the popup still re-checks when you open it |
| Blur cookie values in the popup | On | Cookie values stay blurred until you click them |
| Show the grade on the toolbar icon | On | Letter grade badge on the extension icon |

### Optional: Restrict Site Access

For extra privacy, you can set site access to "on click":
- Right-click the extension icon → "This can read and change site data" → "When you click the extension"
- The extension will still work (fetches headers on demand via the rescan button), but won't capture headers passively in the background

## Development

```
npm test            # unit tests, no install needed (Node 22+)
npm install
npx playwright install chromium
npm run test:e2e    # browser tests against local test sites
```

The browser tests start local HTTPS/HTTP test sites on ports 8443 and 8080 (change with `E2E_HTTPS_PORT` / `E2E_HTTP_PORT`) and need `openssl` to create a throwaway certificate. Both suites run on every push through GitHub Actions.

### Packaging for the Chrome Web Store

```
./package.sh            # Linux / macOS (asks for the version)
.\package.ps1           # Windows PowerShell
```

Both scripts ask for the version (or take it as an argument, like `./package.sh 2.0.1`), write it into `manifest.json` and `package.json`, and create `dist/security-headers-inspector-<version>.zip` with only the files the extension uses and `manifest.json` at the top level of the zip, as the store requires.

## Browser Compatibility

Works on any Chromium-based browser that supports Manifest V3:

| Browser | Status |
|---------|--------|
| **Chrome** | Fully supported |
| **Brave** | Fully supported |
| **Edge** | Fully supported |
| **Opera** | Fully supported |
| **Vivaldi** | Fully supported |

## Restricted Pages

Some pages cannot be scanned by any browser extension. Chromium has a hardcoded list of protected domains built into its source code, and this applies to all Chromium-based browsers (Chrome, Brave, Edge, Opera, Vivaldi, etc.).

On these pages, the `webRequest` API (which captures headers during navigation) doesn't report anything to extensions, and extensions aren't allowed to read the response of their own `fetch` requests. This is not caused by any HTTP header or server configuration. It's a security boundary enforced by the browser itself. Administrators can also protect extra sites through browser policy.

The extension recognizes the Chrome Web Store without making any request. Any other protected page (for example one blocked by browser policy) is detected when its request fails; Chromium logs a CORS error in the extension's console for those. A page the extension saw loading is never reported as restricted: if a rescan fails there, the popup keeps showing the last result. A page that fails to load (site down, certificate error, blocked by another extension) is shown as "didn't load" with the browser's error code, not as restricted.

When the extension detects a restricted page, it shows:
- A clear message explaining why the page cannot be scanned
- A **"Why?"** dropdown with a detailed explanation
- **SecurityHeaders.com** and **SSL Labs** buttons so you can scan the page using an external service instead

External scanners work because they make requests from their own servers, outside of the browser sandbox.

**Known restricted pages include:**
- Chrome Web Store (`chromewebstore.google.com`)
- Other browser-vendor protected domains

## Privacy

All analysis runs locally in your browser. No data is sent to the extension author or any third party. The extension reads HTTP response headers from pages you visit. When you open the popup without data for a page, or press rescan, it requests the page once from the same website, without cookies. In the background it only does that for pages loaded from the browser cache that it hasn't seen from the network in this session (because the cache drops some headers), which you can turn off in the settings. It never re-requests Incognito tabs. It does not modify any page content or inject scripts.

## Changelog

| Version | Change |
|---------|--------|
| **2.0.0** | **Security:** only page loads and the extension's own requests are captured (no more subresource cookies and URLs); CSP bypasses via repeated or uppercase directives fixed; rescans only fetch the tab's own URL; no background requests for Incognito tabs; scan links drop query strings and credentials; cookie values hidden when copying; stricter extension CSP. **Grading:** only header values browsers apply earn points (HSTS `max-age=0` or over plain HTTP, invalid X-Frame-Options/X-Content-Type-Options/Referrer-Policy, Permissions-Policy syntax errors, `frame-ancestors *`); deeper CSP and cookie checks. **New:** settings page, score breakdown, redirect chain, HSTS preload check, keyboard and screen reader support. **Reliability:** pages served from the browser cache keep their HSTS and cookies; failed rescans keep the last result; sites that are down show the browser's error instead of "Restricted"; downloads and 204 responses no longer replace the page's result; the Chrome Web Store is recognized without a request. **Development:** shared `analysis.js`, unit and browser tests with CI |
| **1.6.7** | Security fixes: stop capturing headers and cookies of every subresource request; fix CSP grading bypass via repeated or uppercase directives; external scan links no longer send the query string or fragment; no background re-requests for Incognito tabs; background fetches time out and ignore caller-supplied URLs; stricter extension CSP; hash and SPA route changes no longer trigger repeated background requests; fix service worker error on a 304 after a failed scan; fix privacy policy contact link; the Chrome Web Store is recognized without a request (no more CORS error); HSTS with `max-age=0` or no valid `max-age` no longer counts toward the grade; cookie values hidden when copying raw headers; values of cookies without a name are no longer shown unblurred |
| **1.6.6** | Minor refactor on the wording across user-facing strings and documentation |
| **1.6.5** | Security fix: escape response header values before rendering in the popup to prevent HTML injection from malicious sites |
| **1.6.4** | Welcome page on first install with quick-start guide and Incognito tip; version tag in popup header; NEL and Report-To header analysis; fixed stale headers persisting across navigations |
| **1.6.3** | Restricted page detection with "Why?" explainer and external scan buttons; grade colors matched to securityheaders.com; performance throttling for bulk tab scanning; rescan merge fix |
| **1.6.2** | Migrated to Manifest V3 (service worker, chrome.storage.session, chrome.alarms); code quality refactor |
| **1.6.1** | Fix intermittent missing headers. Supplementary background fetch now merges missing headers on every page load |
| **1.6.0** | Cookie values blurred for privacy (click to reveal); grade impact badges on all header cards |
| **1.5.5** | X-Robots-Tag detection in Additional Headers section |
| **1.5.4** | Alt-Svc header detection for HTTP/3 (QUIC) availability |
| **1.5.3** | Raw header keys neutral for non-security headers; cookie warnings now yellow |
| **1.5.2** | Smooth animations on all expandable sections |
| **1.5.1** | Light/dark theme toggle with persistent preference |
| **1.5.0** | Rescan results persist; cookies survive across reloads and rescans |
| **1.4.9** | Preserve cookies across page reloads |
| **1.4.8** | SameSite=None flagged as warning; cookie fallback from headers |
| **1.4.7** | Cookie prefix warning only for known session cookies |
| **1.4.6** | Set-Cookie key in raw headers context-colored |
| **1.4.5** | Long header values truncated with expand |
| **1.4.4** | Bold green highlights for good security tokens in raw headers |
| **1.4.3** | Expandable detail cards for Cookies, Disclosure, and Deprecated sections |
| **1.4.2** | Weighted scoring system matching securityheaders.com |
| **1.4.0** | Right-click context menu; deep CSP analysis; color-coded raw headers |
| **1.3.6** | Deprecated Headers section; X-Debug-Token to info disclosure |
| **1.3.5** | Cookie `__Secure-`/`__Host-` prefix checking |
| **1.3.3** | Cookie security analysis |
| **1.3.1** | Information Disclosure section |
| **1.3.0** | CSP `frame-ancestors` counts as X-Frame-Options equivalent |
| **1.2.9** | Copy raw headers to clipboard |
| **1.2.5** | Quick-scan buttons for SecurityHeaders.com and SSL Labs |
| **1.2.4** | Fixed 304 Not Modified overwriting cached headers |
| **1.2.2** | Fixed HSTS not showing |
| **1.2.0** | Expandable chevron UI for header cards |
| **1.1.7** | Auto-scan all tabs on startup; badge without clicking |
| **1.1.3** | Background fetch fallback for tabs loaded before extension |
| **1.1.1** | Detailed header descriptions |
| **1.0.0** | Initial build |
