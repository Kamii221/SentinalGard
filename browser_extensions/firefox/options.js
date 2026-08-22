const DEFAULT_AGENT_BASE_URL = "http://127.0.0.1:8765/api/v1";

async function load() {
  const { agentToken, agentBaseUrl } = await browser.storage.local.get(["agentToken", "agentBaseUrl"]);
  document.getElementById("token").value = agentToken || "";
  document.getElementById("baseUrl").value = agentBaseUrl || DEFAULT_AGENT_BASE_URL;
}

async function save() {
  const token = document.getElementById("token").value.trim();
  const baseUrl = document.getElementById("baseUrl").value.trim() || DEFAULT_AGENT_BASE_URL;
  await browser.storage.local.set({ agentToken: token, agentBaseUrl: baseUrl });
  const saved = document.getElementById("saved");
  saved.style.display = "block";
  setTimeout(() => (saved.style.display = "none"), 2000);
}

document.getElementById("save").addEventListener("click", save);
load();
