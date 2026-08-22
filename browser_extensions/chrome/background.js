// SentinelGuard background service worker (Chrome / MV3).
//
// Watches top-level navigations only (frameId === 0) and asks the local
// agent for an allow/block decision. Nothing about the page's content,
// forms, or cookies is read or sent -- only the URL being navigated to.

const BROWSER_NAME = "chrome";
const DEFAULT_AGENT_BASE_URL = "http://127.0.0.1:8765/api/v1";
const TOKEN_HEADER = "X-SentinelGuard-Token";
const REQUEST_TIMEOUT_MS = 2000;

async function getAgentConfig() {
  const { agentToken, agentBaseUrl } = await chrome.storage.local.get(["agentToken", "agentBaseUrl"]);
  return { token: agentToken || "", baseUrl: agentBaseUrl || DEFAULT_AGENT_BASE_URL };
}

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), ms)),
  ]);
}

function isMonitorableUrl(url) {
  return url.startsWith("http://") || url.startsWith("https://");
}

async function checkUrl(url) {
  const { token, baseUrl } = await getAgentConfig();
  if (!token) {
    return { action: "allow", risk: 0, reason: "SentinelGuard not paired yet -- open extension Options" };
  }
  const resp = await withTimeout(
    fetch(`${baseUrl}/websites/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json", [TOKEN_HEADER]: token },
      body: JSON.stringify({ url, browser: BROWSER_NAME }),
    }),
    REQUEST_TIMEOUT_MS
  );
  if (!resp.ok) {
    throw new Error(`agent returned ${resp.status}`);
  }
  return resp.json();
}

async function setBadgeConnected(connected) {
  await chrome.action.setBadgeText({ text: connected ? "" : "!" });
  if (!connected) {
    await chrome.action.setBadgeBackgroundColor({ color: "#e5484d" });
    await chrome.action.setTitle({ title: "SentinelGuard: agent unreachable" });
  } else {
    await chrome.action.setTitle({ title: "SentinelGuard" });
  }
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // top-level navigations only
  const url = details.url;
  if (!isMonitorableUrl(url)) return;
  if (url.startsWith(chrome.runtime.getURL(""))) return; // ignore our own pages

  try {
    const decision = await checkUrl(url);
    await setBadgeConnected(true);
    if (decision.action === "block") {
      const blockedUrl = chrome.runtime.getURL(
        `blocked.html?url=${encodeURIComponent(url)}&reason=${encodeURIComponent(decision.reason)}&risk=${decision.risk}`
      );
      chrome.tabs.update(details.tabId, { url: blockedUrl });
    }
  } catch (err) {
    // Agent unreachable: fail open so browsing isn't disrupted, and
    // surface it via the toolbar badge so the user knows protection is
    // currently offline.
    await setBadgeConnected(false);
  }
});
