# Privacy Policy

**Security Headers Inspector** does not collect, store, transmit, or share any personal data or browsing information.

## What the extension does

- Reads HTTP response headers from websites you visit to evaluate their security configuration
- Stores header data temporarily in your browser's session storage (cleared when the browser closes)
- Saves your light/dark theme preference in local storage

## What the extension does NOT do

- Does not collect personally identifiable information
- Does not track browsing history or user activity
- Does not send any data to external servers or third parties
- Does not use analytics, telemetry, or tracking of any kind
- Does not modify, block, or intercept any web requests
- Does not inject scripts or content into any web page

## Data storage

All data remains entirely on your device:

- **Session storage**: captured HTTP headers per tab, automatically cleared when the browser session ends
- **Local storage**: theme preference (light or dark) only

## External links

The extension provides optional buttons to scan a site on [SecurityHeaders.com](https://securityheaders.com/) and [SSL Labs](https://www.ssllabs.com/ssltest/). These open in a new tab and are initiated only by the user clicking the button. No data is sent automatically.

## Permissions

| Permission | Why it's needed |
|------------|----------------|
| `webRequest` | Read HTTP response headers (read-only, never modifies requests) |
| `tabs` | Associate headers with the correct tab and read the active tab URL |
| `storage` | Persist header data across service worker restarts and save theme preference |
| `alarms` | Periodic cleanup of temporary data |
| `contextMenus` | Right-click menu for external scan shortcuts |
| `<all_urls>` | Read headers from any website the user visits |

## Contact

If you have questions about this privacy policy, please open an issue on the [GitHub repository](https://github.com/diogo/Security-Headers-Inspector).

## Changes

This privacy policy may be updated to reflect changes in the extension. Any updates will be posted to this file in the repository.

*Last updated: April 13, 2026*
