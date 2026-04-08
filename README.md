# Security Headers Inspector

A browser extension (Chrome/Brave) that instantly checks the security headers of any website you visit — inspired by [securityheaders.com](https://securityheaders.com/).

**Current Version:** 1.1.6

## What It Does

Click the extension icon on any tab and get an instant security report:

- **Letter grade** (A+ through F) based on how many security headers are present
- **Quick status pills** showing which of the 6 core headers are present or missing
- **Detailed expandable cards** for each header with:
  - Current value (or "Not set")
  - Verdict — color-coded assessment (good/warn/bad)
  - "What is this?" — explanation of the header
  - "Why it matters" — security implications
  - "Recommendation" — what value to set
- **Raw headers** — full list of all response headers
- **Internal page detection** — shows a friendly message on `chrome://`, `brave://`, `about:`, extension pages, etc.

## Headers Evaluated

### Core Security Headers (used for grading)

| Header | What it does |
|--------|-------------|
| **Content-Security-Policy** | Whitelists approved content sources to prevent XSS |
| **Permissions-Policy** | Controls which browser features (camera, mic, etc.) are allowed |
| **Referrer-Policy** | Controls how much referrer info leaks to other sites |
| **Strict-Transport-Security** | Forces HTTPS, prevents protocol downgrade attacks |
| **X-Content-Type-Options** | Prevents MIME-sniffing attacks |
| **X-Frame-Options** | Prevents clickjacking via iframe embedding |

### Additional Headers (informational)

| Header | What it does |
|--------|-------------|
| **Cross-Origin-Opener-Policy** | Isolates browsing context from cross-origin windows |
| **Cross-Origin-Resource-Policy** | Controls who can load your resources |
| **Cross-Origin-Embedder-Policy** | Requires explicit permission for cross-origin resource loading |
| **X-XSS-Protection** | Legacy XSS auditor (should be set to `0`, rely on CSP instead) |

### Grading System

| Grade | Criteria |
|-------|----------|
| **A+** | All 6 core headers + at least 2 bonus (COOP, CORP, COEP) |
| **A** | All 6 core headers present |
| **B** | 5 of 6 core headers |
| **C** | 4 of 6 core headers |
| **D** | 3 of 6 core headers |
| **E** | 2 of 6 core headers |
| **F** | 0–1 core headers |

## Architecture

### Why Manifest V2?

Brave blocks `chrome.webRequest` in Manifest V3 extensions (it conflicts with Brave's built-in ad blocker). Since `webRequest` is the **only** browser API that can see all response headers (including `Strict-Transport-Security`, which browsers hide from `fetch`/`XMLHttpRequest`), MV2 with a persistent background page is required.

### How It Works

1. **Background page** (`background.js`) — persistent MV2 background script that:
   - Listens to `webRequest.onHeadersReceived` on every page navigation
   - Captures ALL response headers (including HSTS) and stores them in memory keyed by tab ID
   - Updates the extension badge with the letter grade
   - Handles "fetchHeaders" requests from the popup — does a `fetch()` from the background context, which triggers `webRequest` internally, capturing full headers even for tabs loaded before the extension

2. **Popup** (`popup.html`, `popup.css`, `popup.js`) — the UI that appears when you click the icon:
   - Asks the background for cached headers (from page navigation)
   - If none exist (tab was loaded before extension), asks the background to do a fresh fetch — this triggers `webRequest` which captures all headers including HSTS
   - Evaluates each header and renders the grade, pills, and detail cards
   - Detects non-HTTP pages and shows "Internal Page" message

### File Structure

```
headers-extension/
  manifest.json       Manifest V2 config
  background.js       Persistent background page (webRequest + header storage)
  popup.html          Popup markup
  popup.css           Popup styles (dark theme)
  popup.js            Header evaluation logic + UI rendering
  icons/
    icon16.png        Toolbar icon
    icon48.png        Extension page icon
    icon128.png       Store/install icon
```

## Installation

1. Open `brave://extensions/` (or `chrome://extensions/`)
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `headers-extension` folder
5. Visit any website — click the extension icon to see the report

### Optional: Restrict Site Access

For extra security, you can set site access to "on click":
- Right-click the extension icon
- "This can read and change site data" → "When you click the extension"
- The extension will still work (fetches headers on demand), but won't capture headers passively in the background

## Development History

Built iteratively through these versions:

- **1.0.0** — Initial MV3 build with `webRequest` service worker + popup
- **1.0.1–1.0.5** — Debugging service worker issues (MV3 ephemeral workers lose state, `chrome.storage.session` not available, `extraHeaders` crashing)
- **1.0.6** — Switched to **Manifest V2** after discovering Brave blocks `webRequest` in MV3 entirely (`TypeError: Cannot read properties of undefined reading 'addListener'`)
- **1.0.7** — Wider popup, auto-resize
- **1.0.8–1.0.9** — Fixed raw headers layout (grid → fixed column alignment)
- **1.1.0** — Full header names in status pills
- **1.1.1** — Detailed descriptions per header (What is this? / Why it matters / Recommendation)
- **1.1.2** — Fixed CSP evaluation: no longer false-flags `wasm-unsafe-eval` as `unsafe-eval`, only checks `unsafe-inline` in `script-src` not `style-src`
- **1.1.3** — Background fetch fallback: popup asks background to `fetch()` the URL, triggering `webRequest` to capture all headers (including HSTS) without requiring a page reload
- **1.1.4** — Internal page detection for `chrome://`, `brave://`, `about:`, extensions, `file://`, etc.
- **1.1.5** — Browser-specific labeling (Brave vs Chrome vs Edge)
- **1.1.6** — Simplified internal page message (no browser name, just "Internal Page")

## Key Lessons Learned

- **Brave blocks `chrome.webRequest` in MV3** — this is not documented clearly anywhere. The error is `TypeError: Cannot read properties of undefined (reading 'addListener')` with service worker status code 15.
- **MV3 service workers are ephemeral** — in-memory state is lost when they go idle (~30 seconds). Must use `chrome.storage` for persistence.
- **`Strict-Transport-Security` is invisible to `fetch()`/`XHR`** — browsers handle HSTS internally and strip it from JavaScript-accessible APIs. Only `webRequest` can see it.
- **`wasm-unsafe-eval` is NOT `unsafe-eval`** — substring matching on CSP values causes false positives. Must parse directives properly.
- **`unsafe-inline` in `style-src` is acceptable** — securityheaders.com doesn't flag it. Only `unsafe-inline` in `script-src` is a concern.
