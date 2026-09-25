// Unit tests for analysis.js: header parsing, cookie analysis, and grading.
// Run with: npm test
const test = require("node:test");
const assert = require("node:assert/strict");
const A = require("../../analysis.js");

const HTTPS = "https://example.test/";
const HTTP = "http://example.test/";

// A response that earns every point
const STRONG = {
  "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "permissions-policy": "camera=(), microphone=()"
};
const without = (key) => { const h = { ...STRONG }; delete h[key]; return h; };
const withValue = (key, value) => ({ ...STRONG, [key]: value });
const counts = (key, headers, url = HTTPS) => A.scoredHeaderVerdict(key, headers, url).counts;

test("a fully configured response is A+", () => {
  const g = A.computeGrade(STRONG, HTTPS);
  assert.equal(g.letter, "A+");
  assert.equal(g.present, 6);
  assert.equal(g.score, 120);
  assert.equal(g.penalty, null);
});

test("no headers is F", () => {
  assert.equal(A.computeGrade({}, HTTPS).letter, "F");
});

test("breakdown lists every scored header with its points", () => {
  const g = A.computeGrade(without("referrer-policy"), HTTPS);
  assert.equal(g.breakdown.length, 6);
  const rp = g.breakdown.find(b => b.key === "referrer-policy");
  assert.deepEqual([rp.counts, rp.points, rp.reason], [false, 0, "Missing"]);
  assert.equal(g.breakdown.reduce((s, b) => s + b.points, 0), 105);
});

test("CSP: repeated directives use the first one, like browsers", () => {
  const d = A.parseCSP("script-src 'unsafe-inline'; script-src 'self'");
  assert.deepEqual(d["script-src"], ["'unsafe-inline'"]);
});

test("CSP: directive names and keywords are case-insensitive", () => {
  const g = A.computeGrade(withValue("content-security-policy", "default-src 'self'; SCRIPT-SRC 'UNSAFE-INLINE'; frame-ancestors 'none'"), HTTPS);
  assert.notEqual(g.letter, "A+");
  assert.ok(g.penalty && g.penalty.reason.includes("unsafe-inline"));
});

test("CSP: nonce, hash, or strict-dynamic neutralize unsafe-inline", () => {
  for (const extra of ["'nonce-abc'", "'sha256-xyz'", "'strict-dynamic'"]) {
    const g = A.computeGrade(withValue("content-security-policy", `default-src 'self'; script-src 'unsafe-inline' ${extra}; frame-ancestors 'none'`), HTTPS);
    assert.equal(g.penalty, null, extra);
  }
});

test("CSP: script-src-elem is checked for unsafe-inline", () => {
  const w = A.cspScriptWeaknesses(A.parseCSP("script-src 'self'; script-src-elem 'self' 'unsafe-inline'"));
  assert.equal(w.unsafeInline, "script-src-elem");
});

test("CSP: unsafe-eval caps the score", () => {
  const g = A.computeGrade(withValue("content-security-policy", "default-src 'self' 'unsafe-eval'; frame-ancestors 'none'"), HTTPS);
  assert.ok(g.pct <= 82);
});

test("CSP: an empty policy doesn't count", () => {
  assert.equal(counts("content-security-policy", withValue("content-security-policy", " ; ")), false);
});

test("CSP evaluate: suggestions don't make a strong policy a warning, weaknesses do", () => {
  const def = A.SECURITY_HEADERS["content-security-policy"];
  const good = def.evaluate("default-src 'self'; object-src 'none'; base-uri 'none'", {}, { url: HTTPS });
  assert.equal(good.status, "good");
  assert.match(good.msg, /Suggestions/);
  const warn = def.evaluate("default-src 'self' 'unsafe-hashes'; base-uri 'none'", {}, { url: HTTPS });
  assert.equal(warn.status, "warn");
});

test("CSP evaluate: missing object-src and default-src is a warning", () => {
  const r = A.SECURITY_HEADERS["content-security-policy"].evaluate("script-src 'self'; base-uri 'none'", {}, { url: HTTPS });
  assert.match(r.msg, /object-src<\/code> is not restricted/);
});

test("CSP evaluate: mentions a Report-Only policy", () => {
  const r = A.SECURITY_HEADERS["content-security-policy"].evaluate(undefined, { "content-security-policy-report-only": "default-src 'self'" }, { url: HTTPS });
  assert.equal(r.status, "bad");
  assert.match(r.msg, /Report-Only/);
});

test("HSTS: max-age=0, missing max-age, and plain HTTP don't count", () => {
  assert.equal(counts("strict-transport-security", withValue("strict-transport-security", "max-age=0")), false);
  assert.equal(counts("strict-transport-security", withValue("strict-transport-security", "includeSubDomains")), false);
  assert.equal(counts("strict-transport-security", STRONG, HTTP), false);
  assert.equal(counts("strict-transport-security", STRONG, HTTPS), true);
});

test("HSTS: max-age is case-insensitive and may be quoted", () => {
  assert.equal(A.hstsMaxAge('Max-Age="31536000"; preload'), 31536000);
  assert.equal(A.hstsMaxAge("includeSubDomains; max-age=600"), 600);
  assert.equal(A.hstsMaxAge("xmax-age=5"), null);
});

test("HSTS evaluate: preload eligibility and hstspreload.org link", () => {
  const def = A.SECURITY_HEADERS["strict-transport-security"];
  const ok = def.evaluate(STRONG["strict-transport-security"], STRONG, { url: HTTPS, redirects: [] });
  assert.match(ok.msg, /meets the requirements/);
  assert.match(ok.msg, /hstspreload\.org\/\?domain=example\.test/);
  const short = def.evaluate("max-age=600", STRONG, { url: HTTPS, redirects: [] });
  assert.match(short.msg, /needs max-age of at least 31536000, includeSubDomains, preload/);
  const upgraded = def.evaluate(STRONG["strict-transport-security"], STRONG, { url: HTTPS, redirects: [{ internal: true, reason: "HSTS" }] });
  assert.match(upgraded.msg, /already has an HSTS policy/);
});

test("X-Frame-Options: only DENY/SAMEORIGIN, conflicts block, ALLOW-FROM is ignored", () => {
  assert.equal(A.xfoPolicy("DENY"), "deny");
  assert.equal(A.xfoPolicy("sameorigin"), "sameorigin");
  assert.equal(A.xfoPolicy("DENY, SAMEORIGIN"), "deny");
  assert.equal(A.xfoPolicy("ALLOW-FROM https://a.test"), null);
  assert.equal(A.xfoPolicy("ALLOWALL"), null);
  const noFa = { ...STRONG, "content-security-policy": "default-src 'self'" };
  assert.equal(counts("x-frame-options", { ...noFa, "x-frame-options": "ALLOW-FROM https://a.test" }), false);
  assert.equal(counts("x-frame-options", { ...noFa, "x-frame-options": "DENY" }), true);
});

test("X-Frame-Options: CSP frame-ancestors takes precedence", () => {
  const noXfo = without("x-frame-options");
  assert.equal(counts("x-frame-options", noXfo), true);
  const anyFramer = { ...STRONG, "content-security-policy": "default-src 'self'; frame-ancestors *" };
  assert.equal(counts("x-frame-options", anyFramer), false, "frame-ancestors * overrides DENY");
});

test("X-Content-Type-Options: only nosniff (first value) counts", () => {
  assert.equal(counts("x-content-type-options", withValue("x-content-type-options", "NoSniff")), true);
  assert.equal(counts("x-content-type-options", withValue("x-content-type-options", "nosniff, nosniff")), true);
  assert.equal(counts("x-content-type-options", withValue("x-content-type-options", "yes")), false);
});

test("Referrer-Policy: last recognized value wins; leaky values don't count", () => {
  assert.equal(A.effectiveReferrerPolicy("no-referrer, strict-origin-when-cross-origin"), "strict-origin-when-cross-origin");
  assert.equal(A.effectiveReferrerPolicy("strict-origin, made-up-policy"), "strict-origin");
  assert.equal(A.effectiveReferrerPolicy("nonsense"), null);
  assert.equal(counts("referrer-policy", withValue("referrer-policy", "unsafe-url")), false);
  assert.equal(counts("referrer-policy", withValue("referrer-policy", "no-referrer-when-downgrade")), false);
  assert.equal(counts("referrer-policy", withValue("referrer-policy", "origin")), true);
});

test("Permissions-Policy: needs at least one valid directive", () => {
  assert.deepEqual(A.permissionsPolicyFeatures('camera=(), geolocation=(self "https://a.test")'), ["camera", "geolocation"]);
  assert.equal(counts("permissions-policy", withValue("permissions-policy", "garbage")), false);
});

test("Permissions-Policy: syntax errors make browsers ignore the whole header", () => {
  for (const invalid of ["camera=() microphone=()", "Camera=()", "camera=(), , microphone=()", "camera=(),", "camera=(self"]) {
    assert.equal(A.parsePermissionsPolicy(invalid), null, invalid);
    assert.equal(counts("permissions-policy", withValue("permissions-policy", invalid)), false, invalid);
  }
  for (const valid of ["camera=*", "camera=(none)", "camera=(self);report-to=main", 'fullscreen=(self "https://a.test" "https://b.test")']) {
    assert.equal(A.parsePermissionsPolicy(valid).length, 1, valid);
  }
  assert.match(A.SECURITY_HEADERS["permissions-policy"].evaluate("camera=() microphone=()").msg, /separated by commas/);
});

test("CSP: https: in script-src is a warning", () => {
  const r = A.SECURITY_HEADERS["content-security-policy"].evaluate("default-src 'self'; script-src 'self' https:; base-uri 'none'", {}, { url: HTTPS });
  assert.equal(r.status, "warn");
  assert.match(r.msg, /any HTTPS site/);
});

test("cookie helpers tolerate a missing value", () => {
  assert.deepEqual(A.splitCookie(undefined), { namePart: "", valuePart: "", attrsPart: "" });
  assert.equal(A.analyzeCookie(undefined).name, "");
});

// The popup must never show a scored header as fine while the grade gives it 0 points,
// or as a problem while the grade gives it points.
test("popup status is 'bad' exactly when the grade gives no points", () => {
  const variants = {
    "content-security-policy": [undefined, " ", "default-src 'self'", "script-src 'unsafe-inline'", "default-src *"],
    "strict-transport-security": [undefined, "max-age=0", "preload", "max-age=600", "max-age=31536000"],
    "x-frame-options": [undefined, "DENY", "SAMEORIGIN", "ALLOW-FROM https://a.test", "ALLOWALL", "DENY, SAMEORIGIN"],
    "x-content-type-options": [undefined, "nosniff", "yes", "NOSNIFF"],
    "referrer-policy": [undefined, "no-referrer", "origin", "unsafe-url", "no-referrer-when-downgrade", "bogus", "unsafe-url, strict-origin"],
    "permissions-policy": [undefined, "camera=()", "garbage"]
  };
  const cspVariants = [undefined, "default-src 'self'", "default-src 'self'; frame-ancestors 'none'", "frame-ancestors *"];
  for (const url of [HTTPS, HTTP]) {
    for (const [key, values] of Object.entries(variants)) {
      for (const value of values) {
        for (const csp of cspVariants) {
          const headers = { ...STRONG, "content-security-policy": csp };
          if (key !== "content-security-policy") headers[key] = value; else headers[key] = value;
          for (const k of Object.keys(headers)) if (headers[k] === undefined) delete headers[k];
          const verdict = A.scoredHeaderVerdict(key, headers, url);
          const status = A.SECURITY_HEADERS[key].evaluate(headers[key], headers, { url, redirects: [] }).status;
          assert.equal(status === "bad", !verdict.counts, `${key}=${JSON.stringify(value)} csp=${JSON.stringify(csp)} ${url}: status ${status}, counts ${verdict.counts}`);
        }
      }
    }
  }
});

test("evaluate messages escape header values", () => {
  const evil = '<img src=x onerror=alert(1)>';
  for (const [key, def] of Object.entries({ ...A.SECURITY_HEADERS, ...A.ADDITIONAL_HEADERS })) {
    const r = def.evaluate(evil, { [key]: evil }, { url: HTTPS, redirects: [] });
    assert.ok(!r.msg.includes("<img"), `${key} leaks raw HTML`);
  }
  for (const [key, def] of Object.entries({ ...A.DISCLOSURE_HEADERS, ...A.DEPRECATED_HEADERS })) {
    const r = def.check(evil + "/1.0");
    if (r) assert.ok(!r.msg.includes("<img"), `${key} leaks raw HTML`);
  }
});

test("cookies: nameless cookie keeps its value out of the name", () => {
  const parts = A.splitCookie("abc123secret; Path=/");
  assert.deepEqual(parts, { namePart: "", valuePart: "abc123secret", attrsPart: "; Path=/" });
  assert.equal(A.analyzeCookie("abc123secret; Path=/").name, "");
});

test("cookies: attribute parsing doesn't match look-alikes", () => {
  const c = A.analyzeCookie("id=1; SecureFlag=1; HttpOnlyish");
  assert.equal(c.hasSecure, false);
  assert.equal(c.hasHttpOnly, false);
});

test("cookies: prefix rules are enforced", () => {
  assert.equal(A.analyzeCookie("__Host-id=1; Secure; Path=/; HttpOnly; SameSite=Lax").rejected.length, 0);
  assert.ok(A.analyzeCookie("__Host-id=1; Secure; Path=/app").rejected.length > 0, "__Host- needs Path=/");
  assert.ok(A.analyzeCookie("__Host-id=1; Secure; Path=/; Domain=a.test").rejected.length > 0, "__Host- forbids Domain");
  assert.ok(A.analyzeCookie("__Secure-id=1; Path=/").rejected.length > 0, "__Secure- needs Secure");
  assert.equal(A.analyzeCookie("__Secure-id=1; Secure").hasPrefix, true);
});

test("cookies: SameSite=None and Partitioned need Secure", () => {
  assert.ok(A.analyzeCookie("a=1; SameSite=None").rejected.length > 0);
  assert.ok(A.analyzeCookie("a=1; Partitioned").rejected.length > 0);
  const ok = A.analyzeCookie("a=1; Secure; HttpOnly; SameSite=None; Partitioned");
  assert.equal(ok.rejected.length, 0);
  assert.ok(ok.flags.includes("Partitioned"));
});

test("cookies: unrecognized SameSite value is reported", () => {
  const c = A.analyzeCookie("a=1; Secure; HttpOnly; SameSite=Maybe");
  assert.ok(c.issues.some(i => i.includes("Unrecognized")));
});

test("scan target URL drops credentials, query and fragment", () => {
  assert.equal(A.scanTargetUrl("https://u:p@site.test/reset/x?token=SECRET#frag"), "https://site.test/reset/x");
  assert.equal(A.scanTargetUrl("file:///etc/passwd"), null);
  assert.equal(A.scanTargetUrl("chrome://settings"), null);
});

test("default settings", () => {
  assert.deepEqual(A.DEFAULT_SETTINGS, { autoFetch: true, showBadge: true, blurCookies: true });
});
