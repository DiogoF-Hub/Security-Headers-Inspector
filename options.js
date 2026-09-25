// Settings page. Values are saved to chrome.storage.local as soon as they change;
// the background and popup pick them up from there.

const form = document.getElementById("settings-form");
const statusEl = document.getElementById("status");
let statusTimer = null;

document.getElementById("version").textContent = `v${chrome.runtime.getManifest().version}`;

chrome.storage.local.get(["settings", "theme"], (data) => {
  if (data.theme === "light") document.body.classList.add("light");
  const settings = { ...DEFAULT_SETTINGS, ...(data.settings || {}) };
  for (const key of Object.keys(DEFAULT_SETTINGS)) {
    document.getElementById(key).checked = !!settings[key];
  }
});

form.addEventListener("change", () => {
  const settings = {};
  for (const key of Object.keys(DEFAULT_SETTINGS)) {
    settings[key] = document.getElementById(key).checked;
  }
  chrome.storage.local.set({ settings }, () => {
    statusEl.textContent = "Saved";
    clearTimeout(statusTimer);
    statusTimer = setTimeout(() => { statusEl.textContent = ""; }, 1500);
  });
});
