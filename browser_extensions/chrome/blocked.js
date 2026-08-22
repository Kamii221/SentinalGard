const BROWSER_NAME = "chrome";
const DEFAULT_AGENT_BASE_URL = "http://127.0.0.1:8765/api/v1";
const TOKEN_HEADER = "X-SentinelGuard-Token";

const params = new URLSearchParams(window.location.search);
const originalUrl = params.get("url") || "";
const reason = params.get("reason") || "Blocked";
const risk = params.get("risk") || "?";

document.getElementById("url").textContent = originalUrl;
document.getElementById("risk").textContent = `Risk score: ${risk}`;
document.getElementById("reason").textContent = reason;

document.getElementById("back").addEventListener("click", () => {
  if (history.length > 1) {
    history.back();
  } else {
    window.location.href = "about:blank";
  }
});

async function getAgentConfig() {
  const { agentToken, agentBaseUrl } = await chrome.storage.local.get(["agentToken", "agentBaseUrl"]);
  return { token: agentToken || "", baseUrl: agentBaseUrl || DEFAULT_AGENT_BASE_URL };
}

async function override(decision) {
  const { token, baseUrl } = await getAgentConfig();
  if (!token || !originalUrl) return;
  try {
    await fetch(`${baseUrl}/websites/decision`, {
      method: "POST",
      headers: { "Content-Type": "application/json", [TOKEN_HEADER]: token },
      body: JSON.stringify({ url: originalUrl, browser: BROWSER_NAME, decision }),
    });
    window.location.href = originalUrl;
  } catch (err) {
    alert("Could not reach the SentinelGuard agent.");
  }
}

document.getElementById("allowOnce").addEventListener("click", () => override("allow_once"));
document.getElementById("alwaysAllow").addEventListener("click", () => override("always_allow"));
