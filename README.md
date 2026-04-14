# Security Headers Inspector

A Chromium browser extension (Manifest V3) that instantly checks the security headers of any website you visit — inspired by [securityheaders.com](https://securityheaders.com/). Works on Chrome, Brave, Edge, Opera, and any Chromium-based browser.

**Current Version:** 1.6.2

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
- **Internal page detection** — friendly message on `chrome://`, `about:`, extension pages, etc.

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
| **X-Robots-Tag** | Controls search engine indexing at the HTTP level |
| **Alt-Svc** | Advertises HTTP/3 (QUIC) support for faster, encrypted connections |

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
│  (background.js — MV3 service worker)                   │
│         │                                               │
│         ├── Captures ALL response headers (incl. HSTS)  │
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

1. **Service worker** (`background.js`) — MV3 background script:
   - Listens to `webRequest.onHeadersReceived` with `extraHeaders` on every request
   - Captures ALL response headers (including HSTS and Set-Cookie) and stores them via `chrome.storage.session`
   - Keeps a local in-memory cache synced to storage for fast access
   - Preserves cached headers on 304 Not Modified responses
   - Computes weighted grade and updates the extension badge per tab
   - Re-applies badge on `tabs.onUpdated` (browsers clear per-tab badges on navigation)
   - Auto-scans all existing tabs on startup/install
   - Handles `fetchHeaders` messages from the popup for on-demand scanning
   - Provides right-click context menu for external scans
   - Uses `chrome.alarms` for periodic cleanup (service worker timers don't persist)

2. **Popup** (`popup.html`, `popup.css`, `popup.js`) — the UI:
   - Requests cached headers from background, falls back to fresh fetch if needed
   - Evaluates each header with detailed analysis (CSP directive parsing, cookie flag checking, etc.)
   - Renders grade, pills, expandable detail cards, cookie analysis, disclosure/deprecated warnings
   - Color-codes raw headers by category with highlighted good security tokens
   - Detects non-HTTP pages (`chrome://`, `about:`, `file://`, extensions)

### File Structure

```
Security-Headers-Inspector/
├── manifest.json       Manifest V3 config
├── background.js       Service worker (webRequest + storage.session + grading)
├── popup.html          Popup markup
├── popup.css           Popup styles (dark/light theme)
├── popup.js            Header evaluation logic + UI rendering
└── icons/
    ├── icon.svg        Source icon
    ├── icon16.png      Toolbar icon
    ├── icon48.png      Extension page icon
    └── icon128.png     Store/install icon
```

## Installation

### Chrome Web Store

*(Coming soon)*

### Manual (Developer Mode)

1. Open `chrome://extensions/`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select the extension folder
5. Visit any website — the badge shows the grade instantly, click for the full report

### Optional: Restrict Site Access

For extra privacy, you can set site access to "on click":
- Right-click the extension icon → "This can read and change site data" → "When you click the extension"
- The extension will still work (fetches headers on demand via the rescan button), but won't capture headers passively in the background

## Browser Compatibility

Works on any Chromium-based browser that supports Manifest V3:

| Browser | Status |
|---------|--------|
| **Chrome** | Fully supported |
| **Brave** | Fully supported |
| **Edge** | Fully supported |
| **Opera** | Fully supported |
| **Vivaldi** | Fully supported |

## Privacy

All analysis runs locally in your browser. No data is sent to any server. The extension only reads HTTP response headers from pages you visit — it does not modify any page content or inject scripts.

## Changelog

| Version | Change |
|---------|--------|
| **1.6.2** | Migrated to Manifest V3 (service worker, chrome.storage.session, chrome.alarms); code quality refactor |
| **1.6.1** | Fix intermittent missing headers — supplementary background fetch merges missing headers on every page load |
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
