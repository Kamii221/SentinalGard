const BROWSER_NAME = "edge";
const DEFAULT_AGENT_BASE_URL = "http://127.0.0.1:8765/api/v1";
const TOKEN_HEADER = "X-SentinelGuard-Token";

async function getAgentConfig() {
  const { agentToken, agentBaseUrl } = await chrome.storage.local.get(["agentToken", "agentBaseUrl"]);
  return { token: agentToken || "", baseUrl: agentBaseUrl || DEFAULT_AGENT_BASE_URL };
}

function setStatus(text) {
  document.getElementById("status").textContent = text;
}

async function currentTabUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab && tab.url ? tab.url : null;
}

async function refresh() {
  const url = await currentTabUrl();
  const domainEl = document.getElementById("domain");
  if (!url || !(url.startsWith("http://") || url.startsWith("https://"))) {
    domainEl.textContent = "Not a monitored page";
    document.getElementById("risk").textContent = "—";
    return;
  }
  domainEl.textContent = url;

  const { token, baseUrl } = await getAgentConfig();
  if (!token) {
    setStatus("Not paired with the agent yet -- open Options.");
    return;
  }
  try {
    const resp = await fetch(`${baseUrl}/websites/lookup?url=${encodeURIComponent(url)}`, {
      headers: { [TOKEN_HEADER]: token },
    });
    if (!resp.ok) throw new Error(`agent returned ${resp.status}`);
    const data = await resp.json();
    document.getElementById("risk").textContent = `Risk: ${data.risk} (${data.action})`;
    document.getElementById("reason").textContent = data.reason;
  } catch (err) {
    setStatus("Agent unreachable.");
  }
}

async function sendDecision(decision) {
  const url = await currentTabUrl();
  if (!url) return;
  const { token, baseUrl } = await getAgentConfig();
  if (!token) {
    setStatus("Not paired with the agent yet -- open Options.");
    return;
  }
  try {
    const resp = await fetch(`${baseUrl}/websites/decision`, {
      method: "POST",
      headers: { "Content-Type": "application/json", [TOKEN_HEADER]: token },
      body: JSON.stringify({ url, browser: BROWSER_NAME, decision }),
    });
    const data = await resp.json();
    setStatus(data.applied || "Done.");

    if (decision === "always_block" || decision === "block") {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab) {
        const blockedUrl = chrome.runtime.getURL(
          `blocked.html?url=${encodeURIComponent(url)}&reason=${encodeURIComponent("Blocked from the SentinelGuard popup")}&risk=100`
        );
        chrome.tabs.update(tab.id, { url: blockedUrl });
      }
    } else {
      await refresh();
    }
  } catch (err) {
    setStatus("Failed to reach the agent.");
  }
}

document.getElementById("allowOnce").addEventListener("click", () => sendDecision("allow_once"));
document.getElementById("block").addEventListener("click", () => sendDecision("block"));
document.getElementById("alwaysAllow").addEventListener("click", () => sendDecision("always_allow"));
document.getElementById("alwaysBlock").addEventListener("click", () => sendDecision("always_block"));

refresh();
