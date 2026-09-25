// Starts Chromium with the extension loaded and gives the tests handles to the
// background service worker and the real toolbar popup, over the DevTools protocol.
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");
const { hostRules } = require("./server");

const EXTENSION = path.join(__dirname, "..", "..");
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function listTargets(port) {
  return (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
}

// Minimal CDP client for one target
async function connect(target) {
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  let n = 0;
  const pending = new Map();
  const events = [];
  const conn = { closed: false, targetId: target.id, events };
  ws.onmessage = (m) => {
    const d = JSON.parse(m.data);
    if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); } else if (d.method) events.push(d);
  };
  ws.onclose = () => { conn.closed = true; for (const r of pending.values()) r({ closed: true }); };
  conn.send = (method, params = {}) => new Promise(r => { const id = ++n; pending.set(id, r); ws.send(JSON.stringify({ id, method, params })); });
  conn.close = () => ws.close();
  conn.evaluate = async (expression) => {
    const r = await Promise.race([conn.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }), sleep(20000).then(() => ({ closed: true }))]);
    if (r.closed) throw Object.assign(new Error("target closed"), { closed: true });
    if (r.result.exceptionDetails) throw new Error(r.result.exceptionDetails.exception?.description || r.result.exceptionDetails.text);
    return r.result.result.value;
  };
  conn.errors = () => events
    .filter(e => e.method === "Runtime.exceptionThrown" || (e.method === "Log.entryAdded" && e.params.entry.level === "error") || (e.method === "Runtime.consoleAPICalled" && e.params.type === "error"))
    .map(e => JSON.stringify(e.params).slice(0, 300));
  await conn.send("Runtime.enable");
  await conn.send("Log.enable");
  return conn;
}

async function launch() {
  const port = 20000 + Math.floor(Math.random() * 30000);
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "shi-profile-"));
  const args = [
    "--headless=new", `--remote-debugging-port=${port}`, `--user-data-dir=${userDataDir}`,
    "--no-first-run", "--no-default-browser-check", "--no-proxy-server", "--ignore-certificate-errors",
    `--disable-extensions-except=${EXTENSION}`, `--load-extension=${EXTENSION}`,
    `--host-resolver-rules=${hostRules}`, "about:blank"
  ];
  // No Chromium sandbox, like Playwright's default: CI runners (Ubuntu 24.04) don't allow
  // the user namespaces it needs, and root can't use it at all.
  args.unshift("--no-sandbox");
  const proc = spawn(process.env.CHROME_PATH || chromium.executablePath(), args, { stdio: ["ignore", "ignore", "pipe"] });
  // Keep the end of Chromium's error output, to explain a failed start
  let stderr = "";
  proc.stderr.on("data", (chunk) => { stderr = (stderr + chunk).slice(-4000); });

  let browser;
  for (let i = 0; i < 75 && !browser; i++) {
    await sleep(200);
    browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`).catch(() => null);
  }
  if (!browser) { proc.kill("SIGKILL"); throw new Error(`Chromium did not start. Its output:\n${stderr}`); }
  const ctx = browser.contexts()[0];

  // Extension id, from chrome://extensions (works whether or not the worker is running)
  const ext = await ctx.newPage();
  await ext.goto("chrome://extensions");
  let id;
  for (let i = 0; i < 30 && !id; i++) {
    id = await ext.evaluate(() => new Promise(r => chrome.developerPrivate.getExtensionsInfo(l => r(l[0] && l[0].id))));
    if (!id) await sleep(200);
  }
  await ext.close();

  // Service worker handle that reconnects when the worker stops or is replaced
  let swConn = null;
  const wake = async () => {
    const p = await ctx.newPage();
    await p.goto(`chrome-extension://${id}/welcome.html`).catch(() => {});
    await p.close();
  };
  const sw = {
    async evaluate(fn, arg) {
      for (let attempt = 0; attempt < 3; attempt++) {
        if (swConn && !swConn.closed && !(await listTargets(port)).some(t => t.id === swConn.targetId)) swConn = null;
        for (let i = 0; i < 60 && (!swConn || swConn.closed); i++) {
          const t = (await listTargets(port)).find(x => x.type === "service_worker" && x.url === `chrome-extension://${id}/background.js`);
          if (t) swConn = await connect(t);
          else { if (i % 10 === 0) await wake(); await sleep(200); }
        }
        try {
          return await swConn.evaluate(`(${fn})(${arg === undefined ? "" : JSON.stringify(arg)})`);
        } catch (e) {
          if (!e.closed) throw e;
          swConn = null;
        }
      }
      throw new Error("service worker unavailable");
    },
    errors: () => (swConn ? swConn.errors() : [])
  };
  await sw.evaluate(() => 1);
  for (const p of ctx.pages()) if (p.url().includes("welcome.html")) await p.close();

  // Open the real toolbar popup for the focused window's active tab
  async function openPopup() {
    await sw.evaluate(() => chrome.action.openPopup());
    for (let i = 0; i < 50; i++) {
      const t = (await listTargets(port)).find(x => x.type === "page" && x.url.endsWith("/popup.html"));
      if (t) { const c = await connect(t); await sleep(600); return c; }
      await sleep(100);
    }
    throw new Error("popup did not open");
  }

  // chrome://extensions page, for developer-only APIs (incognito access, reload)
  async function extensionsPage() {
    const p = await ctx.newPage();
    await p.goto("chrome://extensions");
    return p;
  }

  async function close() {
    await browser.close().catch(() => {});
    if (proc.exitCode === null && proc.signalCode === null) {
      const exited = new Promise(resolve => proc.once("exit", resolve));
      proc.kill("SIGKILL");
      await exited;
    }
    // Chromium's helper processes can still be writing to the profile for a moment
    try {
      fs.rmSync(userDataDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
    } catch (err) {
      console.warn(`Could not remove ${userDataDir}: ${err.message}`);
    }
  }

  return { ctx, sw, id, port, openPopup, extensionsPage, close };
}

module.exports = { launch, sleep };
