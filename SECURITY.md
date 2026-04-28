# Security Policy

Thank you for taking the time to help keep Security Headers Inspector and its users safe. This document describes how to report vulnerabilities and what to expect once you do.

## Reporting a Vulnerability

Please **do not** open public GitHub issues for security vulnerabilities. Instead, report them privately using one of the channels below.

### Preferred: Encrypted Email

Send a PGP-encrypted email to:

**diogo@carvalhofer.lu**

- **Fingerprint:** `EDCDF0EC 32719FFE 6AF1954D 9CC1892B 3BB04255`
- **Key ID:** `9CC1892B3BB04255`
- **Algorithm:** EdDSA (Curve25519)

You can fetch the public key from either of these keyservers:

- [keys.openpgp.org](https://keys.openpgp.org/search?q=diogo%40carvalhofer.lu)
- [pgp.circl.lu](https://pgp.circl.lu/pks/lookup?search=diogo%40carvalhofer.lu&fingerprint=on&op=index)

Always verify the fingerprint above matches the key you import before encrypting your report.

### Alternative: GitHub Private Vulnerability Reporting

You can also use GitHub's [private vulnerability reporting](https://github.com/DiogoF-Hub/Security-Headers-Inspector/security/advisories/new) feature if you prefer not to use email.

## What to Include

To help triage and reproduce the issue quickly, please include where applicable:

- A clear description of the vulnerability and its impact
- Affected version(s) of the extension (see the version in `manifest.json` or the popup header)
- Affected browser(s) and version(s)
- Step-by-step reproduction instructions, including a minimal test page or HTTP response if relevant
- Any proof-of-concept code, screenshots, or screen recordings
- Your assessment of severity and any suggested remediation

## Scope

In scope:

- The extension's source code in this repository (`background.js`, `popup.js`, `popup.html`, `popup.css`, `manifest.json`)
- Any code that handles or renders HTTP response headers, cookies, or other data captured from visited pages
- Permission misuse, privilege escalation, or data exfiltration paths within the extension

Out of scope:

- Vulnerabilities in third-party websites used as scan targets (report those to the respective site owners)
- Vulnerabilities in the browser itself or in the Chromium WebRequest API
- Issues that require a malicious extension already installed alongside this one
- Self-XSS that requires the user to paste attacker-controlled content into devtools

## Disclosure Process

1. Acknowledgement of your report within **72 hours**.
2. Initial assessment and triage within **7 days**.
3. Coordination on a fix and disclosure timeline. The default target is to ship a patched release within **30 days** of confirmation, faster for actively exploited issues.
4. Public disclosure via a GitHub Security Advisory and an entry in the changelog once a fixed version is published to the Chrome Web Store.

If you would like to be credited in the advisory, please let me know your preferred name or handle.

## Safe Harbor

Good-faith security research conducted in accordance with this policy is welcomed. Please:

- Avoid privacy violations, data destruction, or service disruption
- Only test against your own browser profile and pages you control or are authorized to test
- Give a reasonable amount of time to remediate before any public disclosure

Thank you for helping make the web a little safer.
