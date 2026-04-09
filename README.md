# Security Headers Inspector

A browser extension (Chrome/Brave) that instantly checks the security headers of any website you visit — inspired by [securityheaders.com](https://securityheaders.com/).

**Current Version:** 1.4.7

## What It Does

Every website you visit automatically gets a **letter grade** (A+ through F) displayed on the extension badge. Click the icon for the full report:

- **Letter grade** with weighted scoring matching securityheaders.com methodology
- **Score percentage** showing how the grade was calculated
- **Quick status pills** — at-a-glance view of which core headers are present or missing
- **Detailed expandable cards** for each header with:
  - Current value (or "Not set")
  - Color-coded verdict (good / warn / bad)
  - "What is this?" — plain-English explanation
  - "Why it matters" — security implications
  - "Recommendation" — what value to set
- **Deep CSP analysis** — flags wildcards, `data:` URIs, `http:` sources, missing `default-src`/`object-src`/`base-uri`, and correctly handles `strict-dynamic`/nonce/hash negation of `unsafe-inline`
- **Cookie security analysis** — checks each `Set-Cookie` for `Secure`, `HttpOnly`, `SameSite`, and `__Secure-`/`__Host-` prefix
- **Information disclosure detection** — flags headers leaking server versions, frameworks, or debug info
- **Deprecated header detection** — identifies headers that are no longer useful (Expect-CT, HPKP, etc.)
- **Color-coded raw headers** — security headers in green, info disclosure in amber, deprecated in purple, with good security tokens highlighted in bold
- **Copy to clipboard** — one-click copy of all raw headers
- **External scan shortcuts** — buttons and right-click menu to scan on SecurityHeaders.com and SSL Labs
- **Internal page detection** — friendly message on `chrome://`, `brave://`, `about:`, extension pages, etc.

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

> **Note:** CSP's `frame-ancestors` directive counts as an X-Frame-Options equivalent for grading purposes, matching securityheaders.com behavior.

### Additional Headers (informational, no grade impact)

| Header | What it does |
|--------|-------------|
| **Cross-Origin-Opener-Policy** | Isolates browsing context from cross-origin windows |
| **Cross-Origin-Resource-Policy** | Controls who can load your resources |
| **Cross-Origin-Embedder-Policy** | Requires explicit permission for cross-origin resource loading |
| **X-XSS-Protection** | Legacy XSS auditor (should be `0` — rely on CSP instead) |

### Information Disclosure Headers (flagged when present)

| Header | Risk |
|--------|------|
| **Server** (with version) | Exposes web server software and version |
| **X-Powered-By** | Reveals backend framework/language |
| **X-AspNet-Version** | Exposes ASP.NET version |
| **X-AspNetMvc-Version** | Exposes ASP.NET MVC version |
| **X-Generator** | Reveals CMS or site generator |
| **Via** | Leaks proxy/gateway infrastructure details |
| **X-Debug-Token / X-Debug-Token-Link** | Exposes debug profiler — critical in production |

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
| **`__Secure-`/`__Host-` prefix** | Browser-enforced constraints on cookie scope |

## Grading System

Grading uses weighted per-header scores matching securityheaders.com methodology:

| Header | Weight |
|--------|--------|
| Content-Security-Policy | 25 |
| Strict-Transport-Security | 25 |
| X-Frame-Options | 20 |
| X-Content-Type-Options | 20 |
| Referrer-Policy | 15 |
| Permissions-Policy | 15 |
| **Total** | **120** |

**CSP quality penalties:** If `script-src` contains `unsafe-inline` (without `strict-dynamic`/nonce/hash to negate it) or `unsafe-eval`, the effective score is capped at 82% — preventing an A+ grade even with all headers present.

| Grade | Score % |
|-------|---------|
| **A+** | >= 95% |
| **A** | >= 75% |
| **B** | >= 60% |
| **C** | >= 50% |
| **D** | >= 29% |
| **E** | >= 14% |
| **F** | < 14% |

## Architecture

### Why Manifest V2?

Brave blocks `chrome.webRequest` in Manifest V3 extensions (it conflicts with Brave's built-in ad blocker). Since `webRequest` is the **only** browser API that can see all response headers — including `Strict-Transport-Security`, which browsers strip from `fetch()`/`XMLHttpRequest` responses — MV2 with a persistent background page is required.

### How It Works

```
┌─────────────────────────────────────────────────────────┐
│  Browser navigates to a page                            │
│         │                                               │
│         ▼                                               │
│  webRequest.onHeadersReceived                           │
│  (background.js — persistent)                           │
│         │                                               │
│         ├── Captures ALL response headers (incl. HSTS)  │
│         ├── Stores in memory keyed by tab ID            │
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

1. **Background page** (`background.js`) — persistent MV2 background script:
   - Listens to `webRequest.onHeadersReceived` with `extraHeaders` on every request
   - Captures ALL response headers (including HSTS and Set-Cookie) and stores them in memory keyed by tab ID
   - Preserves cached headers on 304 Not Modified responses (which return minimal headers)
   - Computes weighted grade and updates the extension badge per tab
   - Re-applies badge on `tabs.onUpdated` (browsers clear per-tab badges on navigation)
   - Auto-scans all existing tabs on startup/install
   - Handles `fetchHeaders` messages from the popup for on-demand scanning
   - Provides right-click context menu for external scans

2. **Popup** (`popup.html`, `popup.css`, `popup.js`) — the UI:
   - Requests cached headers from background, falls back to fresh fetch if needed
   - Evaluates each header with detailed analysis (CSP directive parsing, cookie flag checking, etc.)
   - Renders grade, pills, expandable detail cards, cookie analysis, disclosure/deprecated warnings
   - Color-codes raw headers by category with highlighted good security tokens
   - Detects non-HTTP pages (`chrome://`, `brave://`, `about:`, `file://`, extensions)

### File Structure

```
Security-headers-extension/
├── manifest.json       Manifest V2 config
├── background.js       Persistent background page (webRequest + header storage + grading)
├── popup.html          Popup markup
├── popup.css           Popup styles (dark theme)
├── popup.js            Header evaluation logic + UI rendering
└── icons/
    ├── icon16.png      Toolbar icon
    ├── icon48.png      Extension page icon
    └── icon128.png     Store/install icon
```

## Installation

1. Open `brave://extensions/` (or `chrome://extensions/`)
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select the extension folder
5. Visit any website — the badge shows the grade instantly, click for the full report

### Optional: Restrict Site Access

For extra privacy, you can set site access to "on click":
- Right-click the extension icon → "This can read and change site data" → "When you click the extension"
- The extension will still work (fetches headers on demand via the rescan button), but won't capture headers passively in the background

## Key Lessons Learned

### Browser Extension Gotchas

- **Brave blocks `chrome.webRequest` in MV3** — this is not documented anywhere. The error is `TypeError: Cannot read properties of undefined (reading 'addListener')` with service worker status code 15. The only workaround is MV2.
- **MV3 service workers are ephemeral** — in-memory state is lost when they go idle (~30 seconds). You must use `chrome.storage` for persistence, but `chrome.storage.session` isn't available in all contexts.
- **Browsers clear per-tab badge text on navigation** — even if you set a badge via `browserAction.setBadgeText`, navigating the tab resets it. Must re-apply in a `tabs.onUpdated` listener when `changeInfo.status === "complete"`.
- **304 Not Modified responses return minimal headers** — if you overwrite your cache on every response, a 304 will wipe out the full header set you captured on the original 200. Always check `statusCode === 304` and preserve existing data.
- **`extraHeaders` is required to see `Set-Cookie`** — browsers hide Set-Cookie from extensions by default. You must include `"extraHeaders"` in the `webRequest.onHeadersReceived` listener options array.

### Header Visibility

- **`Strict-Transport-Security` is invisible to `fetch()`/`XHR`** — browsers handle HSTS internally and strip it from JavaScript-accessible Response objects. The `webRequest` API is the only way to see it from an extension.
- **`Set-Cookie` can appear multiple times** — HTTP allows multiple `Set-Cookie` headers. `webRequest` gives you each one separately in the `responseHeaders` array, but a simple headers object (`headers[name] = value`) will only keep the last one. Store cookies in a separate array.

### CSP Parsing

- **`wasm-unsafe-eval` is NOT `unsafe-eval`** — substring matching (`includes("unsafe-eval")`) causes false positives. You must parse CSP directives into arrays and match exact tokens.
- **`unsafe-inline` in `style-src` is acceptable** — securityheaders.com doesn't flag it. Only `unsafe-inline` in `script-src` is a security concern.
- **`strict-dynamic` and nonce/hash negate `unsafe-inline`** — in modern browsers, if `script-src` includes `'strict-dynamic'` or a nonce/hash, `'unsafe-inline'` is silently ignored. Don't flag it as a weakness in this case.
- **`frame-ancestors` is the modern replacement for `X-Frame-Options`** — securityheaders.com counts CSP `frame-ancestors` as equivalent to X-Frame-Options for grading. Your extension should too.

### Grading Accuracy

- **securityheaders.com uses weighted scoring, not simple ratios** — CSP and HSTS are worth more than Referrer-Policy. A simple "present headers / total headers" ratio won't match their grades. You need per-header weights.
- **CSP quality matters for grading** — even with all 6 headers present, `unsafe-inline` or `unsafe-eval` in script-src should prevent an A+ grade. Cap the effective score rather than penalizing the CSP weight directly.

### Extension UX

- **Popup height is capped by the browser** — Chrome/Brave limit popup height to ~600px. If your content exceeds this, the browser clips from the top (not the bottom). Set `max-height` on `body` with `overflow-y: auto` to get proper scrolling.
- **Opening a tab from a popup closes the popup** — if a button opens a new tab, the popup disappears. Use `chrome.tabs.create({ active: false })` to open in a background tab and keep the popup visible.
- **Background fetch triggers webRequest** — doing a `fetch()` from the background page fires `webRequest.onHeadersReceived` internally. This is a useful trick to capture full headers for tabs loaded before the extension was installed, without requiring the user to reload the page.

## Changelog

| Version | Change |
|---------|--------|
| **1.4.7** | Cookie prefix warning now only for known session cookies (PHPSESSID, JSESSIONID, etc.) matching securityheaders.com |
| **1.4.6** | Set-Cookie key in raw headers now context-colored: green if all flags present, amber if issues |
| **1.4.5** | Long header values (e.g. CSP) truncated with preview; full value shown on expand |
| **1.4.4** | Raw headers highlight good security tokens in bold green; individual Set-Cookie rows in raw headers |
| **1.4.3** | Expandable detail cards for Cookies, Information Disclosure, and Deprecated Headers |
| **1.4.2** | Weighted scoring system matching securityheaders.com (per-header weights, CSP penalties, percentage thresholds) |
| **1.4.0** | Right-click context menu for external scans; deep CSP analysis; color-coded raw headers |
| **1.3.6** | Deprecated Headers section (Expect-CT, HPKP, X-Runtime); X-Debug-Token to info disclosure |
| **1.3.5** | Cookie `__Secure-`/`__Host-` prefix checking |
| **1.3.3** | Cookie security analysis (Secure, HttpOnly, SameSite flags) |
| **1.3.1** | Information Disclosure section (Server version, X-Powered-By, etc.) |
| **1.3.0** | CSP `frame-ancestors` counts as X-Frame-Options equivalent |
| **1.2.9** | Copy raw headers to clipboard |
| **1.2.5** | Quick-scan buttons for SecurityHeaders.com and SSL Labs |
| **1.2.4** | Fixed 304 Not Modified overwriting cached headers |
| **1.2.2** | Fixed HSTS not showing (webRequest priority over fetch Response) |
| **1.2.0** | Expandable chevron UI for header cards |
| **1.1.7** | Auto-scan all tabs on startup; badge without clicking |
| **1.1.3** | Background fetch fallback for tabs loaded before extension |
| **1.1.1** | Detailed header descriptions (What / Why / Recommendation) |
| **1.0.6** | Switched from MV3 to MV2 (Brave webRequest compatibility) |
| **1.0.0** | Initial build |

<details>
<summary>Full version history (all 40+ versions)</summary>

- **1.0.0** — Initial MV3 build with `webRequest` service worker + popup
- **1.0.1–1.0.5** — Debugging service worker issues (MV3 ephemeral workers lose state, `chrome.storage.session` not available, `extraHeaders` crashing)
- **1.0.6** — Switched to **Manifest V2** after discovering Brave blocks `webRequest` in MV3
- **1.0.7** — Wider popup, auto-resize
- **1.0.8–1.0.9** — Fixed raw headers layout (grid → fixed column alignment)
- **1.1.0** — Full header names in status pills
- **1.1.1** — Detailed descriptions per header (What is this? / Why it matters / Recommendation)
- **1.1.2** — Fixed CSP evaluation: no longer false-flags `wasm-unsafe-eval` as `unsafe-eval`
- **1.1.3** — Background fetch fallback for capturing full headers without page reload
- **1.1.4** — Internal page detection for `chrome://`, `brave://`, `about:`, etc.
- **1.1.5** — Browser-specific labeling (Brave vs Chrome vs Edge)
- **1.1.6** — Simplified internal page message
- **1.1.7** — Auto-scan all tabs on startup/install; badge shows grade without clicking
- **1.1.8** — Fixed scanTab to read headers from fetch Response directly, handling redirects
- **1.1.9** — Fixed badge disappearing on page refresh (re-applied via `tabs.onUpdated`)
- **1.2.0** — Expandable header items with chevron arrow and hover highlight
- **1.2.1** — Added re-scan button in the header bar
- **1.2.2** — Fixed HSTS not showing on first scan: prioritize webRequest data over fetch Response
- **1.2.3** — New icon: dark shield with header lines and green checkmark
- **1.2.4** — Fixed 304 Not Modified overwriting full cached header set
- **1.2.5** — Added quick-scan buttons for SecurityHeaders.com and SSL Labs
- **1.2.6** — External scan links open in background tab
- **1.2.7** — Fixed popup content clipped at top (body `max-height: 580px` with scroll)
- **1.2.8** — Adjusted grading thresholds to match securityheaders.com
- **1.2.9** — Added "Copy" button for raw headers
- **1.3.0** — CSP `frame-ancestors` counts as X-Frame-Options equivalent
- **1.3.1** — Information Disclosure section (Server version, X-Powered-By, etc.)
- **1.3.2** — A+ no longer requires bonus headers (COOP/CORP/COEP)
- **1.3.3** — Cookie analysis section (Secure, HttpOnly, SameSite flags)
- **1.3.4** — Fixed Set-Cookie not visible: added `extraHeaders` to webRequest listener
- **1.3.5** — Cookie `__Secure-`/`__Host-` prefix flagging
- **1.3.6** — Deprecated Headers section; X-Debug-Token/Link to info disclosure
- **1.4.0** — Right-click context menu; deep CSP analysis; color-coded raw headers
- **1.4.1** — Adjusted grading thresholds (4+/6 = A)
- **1.4.2** — Weighted scoring system matching securityheaders.com methodology
- **1.4.3** — Expandable detail cards for Cookies, Disclosure, and Deprecated sections
- **1.4.4** — Bold green highlights for good security tokens in raw headers; individual Set-Cookie rows
- **1.4.5** — Long header values (e.g. CSP) truncated to 120-char preview when collapsed; full value revealed on expand
- **1.4.6** — Set-Cookie key in raw headers now context-colored: green if all cookie flags are present, amber if missing flags or prefix
- **1.4.7** — Cookie prefix (`__Secure-`/`__Host-`) warning now only triggers for known session cookie names (PHPSESSID, JSESSIONID, ASP.NET_SessionId, etc.), matching securityheaders.com behavior. Non-session cookies like jwt no longer get a false prefix warning

</details>
