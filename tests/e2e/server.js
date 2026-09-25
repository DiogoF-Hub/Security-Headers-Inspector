// Local test sites for the browser tests. Chromium maps the *.test hostnames (and a
// fake Chrome Web Store) to these ports, so no root and no internet are needed.
const http = require("node:http");
const https = require("node:https");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const HTTPS_PORT = Number(process.env.E2E_HTTPS_PORT || 8443);
const HTTP_PORT = Number(process.env.E2E_HTTP_PORT || 8080);

const STRONG = {
  "Content-Type": "text/html",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
  "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=()",
  "X-Frame-Options": "DENY"
};

const WEAK = {
  "Content-Type": "text/html",
  "Strict-Transport-Security": "max-age=0",
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
  "X-Content-Type-Options": "yes",
  "Referrer-Policy": "unsafe-url",
  "Permissions-Policy": "garbage",
  "X-Frame-Options": "ALLOW-FROM https://a.test"
};

const log = [];
const changingSeen = new Set();

function handler(req, res) {
  const host = (req.headers.host || "").split(":")[0];
  const url = new URL(req.url, "http://x");
  // The extension's own fetch. Over plain HTTP there are no Sec-Fetch-* headers; it asks
  // for HTML like a navigation, but navigations also send Upgrade-Insecure-Requests.
  const dest = req.headers["sec-fetch-dest"];
  const extFetch = dest ? dest === "empty" : (!req.headers["upgrade-insecure-requests"] && (req.headers.accept || "").startsWith("text/html"));
  log.push({ host, path: req.url, dest: req.headers["sec-fetch-dest"] || "-", extFetch, time: Date.now() });

  if (host === "hang.test" && extFetch) return; // only the extension's own fetch hangs
  if (host === "down.test") return req.socket.destroy(); // a site that is down
  if (host === "changing.test") {
    // Sends X-Powered-By only on the first request, like a server fixed in between
    const first = !changingSeen.has(url.pathname);
    changingSeen.add(url.pathname);
    res.writeHead(200, { ...STRONG, ...(first ? { "X-Powered-By": "PHP/5.4" } : {}) });
    return res.end("<h1>changing</h1>");
  }
  if (host === "binary.test") {
    // Header bytes that aren't valid UTF-8 (0xFF)
    res.setHeader("Content-Type", "text/html");
    res.setHeader("Set-Cookie", "latin=caf\xff; Path=/");
    res.setHeader("X-Binary", "\xff\xfe");
    res.writeHead(200);
    return res.end("<h1>binary</h1>");
  }
  if (url.pathname === "/download") {
    res.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Disposition": "attachment; filename=x.bin", "X-Powered-By": "DownloadServer" });
    return res.end("data");
  }
  if (url.pathname === "/binary") {
    // A file served without Content-Disposition: Chromium downloads it because it can't render it
    res.writeHead(200, { "Content-Type": "application/octet-stream", "X-Powered-By": "BinaryServer" });
    return res.end("data");
  }
  if (url.pathname === "/nocontent") { res.writeHead(204, { "X-Powered-By": "NoContentServer" }); return res.end(); }
  if (host === "flaky.test" && extFetch) return req.socket.destroy(); // only the extension's fetch fails
  if (host === "corp.test") {
    // Like Vaultwarden: blocks no-cors requests from other origins
    res.writeHead(200, { ...STRONG, "Cross-Origin-Resource-Policy": "same-origin" });
    return res.end("<h1>corp</h1>");
  }
  if (host === "cache.test") {
    // Plain HTTP on purpose: Chromium doesn't cache responses when the certificate is invalid
    if (url.pathname === "/other") { res.writeHead(200, { "Content-Type": "text/html" }); return res.end("other"); }
    res.writeHead(200, { ...STRONG, "Cache-Control": "max-age=600", "Set-Cookie": "sid=1; Path=/" });
    return res.end("<h1>cacheable</h1>");
  }
  if (host === "chromewebstore.google.com") { res.writeHead(200, STRONG); return res.end("fake web store"); }
  if (host === "teams.test") {
    res.writeHead(200, { "Content-Type": "text/html" });
    return res.end('<script>setTimeout(() => location.href = "https://chromewebstore.google.com/detail/x", 200)</script>');
  }
  if (host === "login.test") {
    // Session cookie set on the redirect, like many login flows
    res.writeHead(302, { Location: "https://secure.test/welcome", "Set-Cookie": "__Host-session=S3CR3T; Secure; Path=/; HttpOnly; SameSite=Lax" });
    return res.end();
  }
  if (host === "secure.test") {
    if (url.pathname === "/api") { res.writeHead(200, { "Content-Type": "image/gif", "Set-Cookie": "api_token=SUBRESOURCE_SECRET" }); return res.end(); }
    res.writeHead(200, STRONG);
    return res.end('<h1>secure</h1><a id="dl" href="/download">download</a> <a id="nc" href="/nocontent">nothing</a> <a id="bin" href="/binary">binary</a>');
  }
  if (host === "weak.test") {
    res.writeHead(200, { ...WEAK, "Set-Cookie": ["nameless_secret_value; Path=/", "sid=SID_SECRET; Path=/"] });
    return res.end("<h1>weak</h1>");
  }
  if (host === "sub.test") {
    res.writeHead(200, { "Content-Type": "text/html" });
    return res.end('<img src="https://secure.test/api?token=abc">');
  }
  // nohsts.test, hang.test and anything else: HTTPS page without HSTS
  res.writeHead(200, { "Content-Type": "text/html", "X-Content-Type-Options": "nosniff" });
  res.end(`<h1>${host}</h1>`);
}

// Throwaway self-signed certificate (Chromium runs with --ignore-certificate-errors)
function makeCert() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "shi-cert-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=test",
    "-keyout", path.join(dir, "key.pem"), "-out", path.join(dir, "cert.pem")], { stdio: "ignore" });
  return { key: fs.readFileSync(path.join(dir, "key.pem")), cert: fs.readFileSync(path.join(dir, "cert.pem")) };
}

async function start() {
  const servers = [https.createServer(makeCert(), handler), http.createServer(handler)];
  await Promise.all([
    new Promise(r => servers[0].listen(HTTPS_PORT, "127.0.0.1", r)),
    new Promise(r => servers[1].listen(HTTP_PORT, "127.0.0.1", r))
  ]);
  return { close: () => servers.forEach(s => s.close()) };
}

const hostRules = `MAP *.test:443 127.0.0.1:${HTTPS_PORT}, MAP *.test:80 127.0.0.1:${HTTP_PORT}, MAP chromewebstore.google.com:443 127.0.0.1:${HTTPS_PORT}`;

module.exports = { start, log, hostRules };
