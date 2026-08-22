# SentinelGuard browser extensions

Three near-identical WebExtensions (Chrome/Edge use MV3 `chrome.*`
callbacks-as-promises; Firefox uses MV3 with its native `browser.*`
promise API — no polyfill needed). Each watches top-level page
navigations only and asks the local agent for an allow/block decision.
No page content, form data, cookies, or passwords are ever read.

## Loading for development

* **Chrome**: `chrome://extensions` → enable Developer mode → "Load
  unpacked" → select `browser_extensions/chrome/`.
* **Edge**: `edge://extensions` → enable Developer mode → "Load
  unpacked" → select `browser_extensions/edge/`.
* **Firefox**: `about:debugging#/runtime/this-firefox` → "Load
  Temporary Add-on…" → select any file inside
  `browser_extensions/firefox/` (e.g. `manifest.json`). Temporary
  add-ons are removed when Firefox restarts; for a persistent install
  the extension needs to be signed by Mozilla.

## Pairing (one-time)

Extensions run in a sandbox and can't read files on disk, so they
can't automatically pick up the agent's token from
`agent_token`. Instead:

1. Start the agent (`python main.py --serve` or `--gui`).
2. Open the file `<data_dir>/agent_token` (on Windows:
   `%APPDATA%\SentinelGuard\agent_token`) in a text editor and copy
   its contents.
3. Open the extension's **Options** page (right-click the toolbar
   icon → Options, or via the browser's extension settings) and paste
   the token in.

Every request the extension makes includes this token via the
`X-SentinelGuard-Token` header; without it the agent rejects the
request. If you ever rotate the token (`POST
/api/v1/auth/rotate-token`), repeat step 3 with the new value.

## What each file does

* `manifest.json` — permissions: `webNavigation`, `tabs`, `storage`,
  and `host_permissions` limited to `http://127.0.0.1/*`. No
  `<all_urls>`, no content scripts.
* `background.js` — the only privileged listener: on
  `webNavigation.onBeforeNavigate` for the main frame, POSTs the URL
  to `/api/v1/websites/check` and redirects to `blocked.html` if the
  agent says `block`. Fails open (allows navigation) if the agent is
  unreachable, and shows a red "!" toolbar badge so you know
  protection is temporarily offline.
* `popup.html`/`popup.js` — toolbar popup showing the current tab's
  risk/action and Allow Once / Block / Always Allow / Always Block
  buttons.
* `blocked.html`/`blocked.js` — the interstitial shown when a
  navigation is blocked, with Allow Once / Always Allow overrides.
* `options.html`/`options.js` — the one-time token pairing UI.

## Known limitations (v1)

* Only top-level navigations are checked — SPA route changes
  (`history.pushState`) aren't intercepted.
* Blocking works by redirecting the tab after an async check
  (MV3 has no synchronous blocking `webRequest` API left for this use
  case), so a blocked destination can flash briefly before the
  redirect lands. Acceptable for a personal filter, not a hard
  guarantee.
* Pairing is manual copy-paste; no native messaging host is used to
  keep the install lightweight and dependency-free.
