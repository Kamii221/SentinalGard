# SentinelGuard

A lightweight, local-first personal antivirus / EDR / web filter for
**Windows**, built for a single authorized machine. SentinelGuard
monitors processes, files, the network, persistence locations, and
security logs; watches URLs visited in Chrome, Edge, and Firefox via
browser extensions; scores risk locally; and gives you Allow / Block /
Allow Once / Always Allow / Always Block controls through a desktop GUI.

Everything runs on `127.0.0.1` and stores events in a local SQLite
database. Nothing is uploaded anywhere by default.

> **Status:** Phase 9 of 13 complete (project structure, configuration,
> database schema, logging, local FastAPI agent + authentication,
> PySide6 GUI + dashboard, Chrome/Edge/Firefox URL-monitoring
> extensions, URL detection + allow/block engine, process monitoring,
> file monitoring + hashing + YARA, network monitoring, persistence
> monitoring). See "Build Order" below for what's next.

## Architecture

```text
Browser Extensions (Chrome / Edge / Firefox)
          |
          v
Local FastAPI Agent (127.0.0.1 only)
          |
          +--> URL Detection Engine
          +--> Process Monitor
          +--> File Monitor
          +--> Network Monitor
          +--> Persistence Monitor
          +--> Log Analyzer
          +--> Risk Scoring
          |
          v
SQLite Database
          |
          v
PySide6 Desktop GUI
```

## Project layout

```text
agent/                 bootstrap, logging, (later) the FastAPI service
detection/              URL/behavior detection engine
collectors/              data collectors feeding the event pipeline
monitors/                process/file/network/persistence monitors
response/                block/kill/quarantine actions
api/                     local FastAPI agent
database/                SQLAlchemy models, engine, retention
gui/                     PySide6 desktop GUI
browser_extensions/      chrome/, edge/, firefox/ WebExtensions
rules/                   YAML detection rules (edited without code changes)
yara/                    YARA rules
config/                  settings loader + default_config.yaml
tests/                   unit tests
main.py                  entrypoint
```

## Requirements

* Windows 10/11 (target platform; core modules also run on Linux/macOS
  for development, minus the Windows-only monitors)
* Python 3.12+

## Installation

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Linux/macOS (development only)
pip install -r requirements.txt
```

## Running

```bash
python main.py            # bootstrap only: config, logging, DB schema
python main.py --serve    # start the local agent on 127.0.0.1:8765 (foreground)
python main.py --gui      # launch the desktop app (starts the agent in the background)
```

Bootstrap loads configuration, sets up rotating file + console logging,
and creates the SQLite schema at the platform data directory
(`%APPDATA%\SentinelGuard` on Windows, `~/.sentinelguard` elsewhere).
`--serve` additionally starts the FastAPI agent, bound to loopback only.
The GUI is not started yet — that lands in Phase 3.

Use a custom config file:

```bash
python main.py --config path\to\config.yaml
```

Any subset of `config/default_config.yaml`'s keys can be overridden.

### The desktop GUI (Phase 3)

`python main.py --gui` starts the agent on a background thread and
opens a dark-themed PySide6 window with the full sidebar from spec:
Dashboard, Live Activity, Websites, Alerts, Processes, Network, Files,
Persistence, Logs, Rules, Quarantine, Settings. Only **Dashboard** is
implemented so far — it polls `GET /api/v1/status` every 3 seconds and
shows the required tiles (websites scanned/blocked, threats detected,
suspicious processes, network events, recent alerts, protection
status). Every other section is a labeled placeholder naming the phase
that implements it, so the navigation shell doesn't need rework later.

The GUI never opens the SQLite file directly — it's an HTTP client of
the agent, same as the browser extensions will be, which keeps the
agent as the single writer to the database.

### The local agent (Phase 2)

`python main.py --serve` starts a FastAPI service on
`http://127.0.0.1:8765` (configurable via `api.port`). It:

* Refuses any connection whose TCP peer isn't a loopback address
  (`LoopbackOnlyMiddleware`), independent of the uvicorn bind address.
* Generates a per-install bearer token on first run, stored at
  `<data_dir>/agent_token` with owner-only file permissions. Clients
  send it via the `X-SentinelGuard-Token` header.
* `GET /api/v1/health` — unauthenticated liveness check (app name/version only).
* `GET /api/v1/status` — authenticated dashboard counters (protection
  status, uptime, websites/threats/processes/network/alerts counts).
* `POST /api/v1/auth/rotate-token` — authenticated; rotates the shared
  secret and returns the new value once. Requires the *current* token,
  so an unauthenticated caller can't lock out the real owner. Every
  admin action is written to both the log file and the `events` table.

Browser extensions and the GUI use this same token to talk to the
agent; no data leaves 127.0.0.1.

### Browser extensions (Phase 4)

Chrome, Edge, and Firefox WebExtensions live in `browser_extensions/`
— see `browser_extensions/README.md` for how to load them and pair
them with the agent's token (a one-time manual copy-paste, since
extensions can't read files on disk). Each watches top-level page
navigations, sends only the URL to `POST /api/v1/websites/check`, and
redirects to a blocked page if the agent says so. The popup and
blocked page offer Allow Once / Block / Always Allow / Always Block.

The agent has three endpoints to support this:

* `POST /api/v1/websites/check` — logs the navigation and returns a
  decision.
* `GET /api/v1/websites/lookup?url=...` — same decision logic, used
  by the popup for display; doesn't log a `Website` row.
* `POST /api/v1/websites/decision` — records a manual Allow Once /
  Always Allow / Always Block choice, updating the `allowlist`/
  `blocklist` tables (allow-once entries expire after 1 hour).

The domain used for every decision is always derived server-side from
the validated URL (`urlparse(url).hostname`) rather than trusted from
a client-supplied field, so a request can't send mismatched URL/domain
data.

### URL detection + allow/block engine (Phase 5)

The user's `allowlist`/`blocklist` entries always take priority (exact
domain match). Otherwise every check runs through
`detection/url_analysis.py`, which combines independent local
heuristics (`detection/indicators.py`) into one explainable score:

* IP-address destinations, suspicious TLDs (`.tk`, `.top`, `.xyz`, …),
  IDN/punycode domains, the classic `user@host` disguise trick,
  excessive subdomain chains, brand-name-in-hostname impersonation,
  phishing keyword clusters in the path/query, direct links to
  executables/scripts, embedded open-redirect parameters, unusually
  heavy percent-encoding, and high-entropy (DGA-like) domain labels.

**No single indicator alone ever reaches High/Critical** — each one
only contributes points (10-30), so a block requires several
independent signals to agree, per the spec's rule against overclaiming
from a weak heuristic. A URL that lands in the High or Critical band
is auto-blocked; Medium and below stay `allow` (with the reasons still
visible via `/lookup` and the popup). Unlike system-level response
actions, a URL block here is cheap and instantly reversible from the
blocked page, so it doesn't need extra confirmation.

`detection/reputation.py` defines a pluggable `ReputationProvider`
interface for future threat-intel integrations; the only implementation
today is `NullReputationProvider`, which always returns "no data" and
never makes a network call — SentinelGuard stays fully offline until a
real provider is explicitly configured (none is, yet).

Known calibration point: two indicators alone (e.g. a raw IP host +
direct `.exe` link) score around 35 — still "allow" under the default
thresholds. This is a deliberate conservative default, not an
oversight; revisit the point values in `detection/indicators.py` once
there's real usage data to tune against.

### Process monitoring (Phase 6)

`monitors/process_monitor.py` polls the process table (via `psutil`)
on a background thread at a configurable interval
(`monitoring.process_poll_interval_seconds`, default 2s) and diffs it
against the previous snapshot to detect creation and termination.
Windows doesn't expose a lightweight process-creation event API
without WMI/ETW (that's Phase 10 territory), so polling is the
practical, dependency-light approach here — a known trade-off is that
very short-lived processes between polls can be missed, and a process
created in the exact same instant as the monitor's startup seed can
skip its "creation" event (it's still tracked from the next poll
onward).

For every newly created process it records both a `processes` row and
a normalized `events` row (`event_type=process_create`), capturing
PID/PPID, executable path, command line, user, and — only for new
processes, never a continuous sweep — a SHA-256 hash (skipped above
`monitoring.process_hash_max_bytes`, default 25MB) and, on Windows
with sufficient privileges, the process integrity level via `pywin32`
(`None` everywhere else or when unavailable). Two lightweight built-in
heuristics score each new process: a LOLBin-name check (powershell,
cmd, wscript, regsvr32, rundll32, certutil, …) and a suspicious
PowerShell command-line check (mirroring the spec's own example YAML
rule — `-encodedcommand`, `downloadstring`, `invoke-webrequest`, …).
This is intentionally not the full YAML rule engine (Phase 10-11) —
just real, explainable severity data for the dashboard and later
correlation to build on. No `Alert` rows are created here; Phase 11's
correlation engine decides what becomes a user-facing alert.

DB writes go through `monitors/queue_worker.py`'s `QueueWriter` — a
small reusable queue + batched-write background thread that Phase
7-9's file/network/persistence monitors will reuse, per the
performance spec's queue-based processing and batched-writes
requirements.

The monitor starts automatically whenever the agent runs (`--serve` or
`--gui`), controlled by `monitoring.enabled` (default `true`).

### File monitoring + hashing + YARA (Phase 7)

`monitors/file_monitor.py` uses `watchdog` for OS-level filesystem
events — event-driven, not polling — restricted to a handful of
security-sensitive top-level directories (Downloads, Desktop, Temp,
Startup on Windows; equivalent dev-friendly paths elsewhere) and never
recursive into subdirectories: never a full-disk scan. Only files
whose extension is executable/script/DLL (`detection/file_analysis.py`
`TRACKED_EXTENSIONS`) trigger any hashing or reading — every other
file event is dropped before any I/O happens. Override the watched
locations with `monitoring.file_watch_paths`.

For each new/modified tracked file it records a `files` row and a
normalized `events` row, combining:

* Local heuristics (`detection/file_analysis.py`): base points for a
  new executable/script/DLL appearing, extra points for an existing
  tracked file being *modified* (unusual — legitimate binaries rarely
  get silently rewritten), the double-extension trick
  (`invoice.pdf.exe`), and high-entropy content (sampled — never the
  whole file, capped by `monitoring.file_entropy_sample_bytes`) as a
  signal for packed/encrypted/obfuscated code.
- A known-malicious-hash lookup against the *same* `blocklist` table
  used for domains (`entry_type="hash"`) — an exact match short-circuits
  straight to Critical, same precedence pattern as the website
  blocklist.
* A YARA scan (`detection/yara_engine.py`): compiles every `.yar`
  file under `yara/` once at startup (never per-scan) and adds each
  match's rule name + description directly into the reasons — a
  strong, self-documenting signal. Three starter rules are bundled:
  the industry-standard EICAR test-file signature (safe, not real
  malware — the standard way to verify an AV engine actually detects
  something), a PowerShell/script download-cradle pattern
  (`DownloadString`, `-EncodedCommand`, …), and a heuristic PE
  process-injection-API combination. Degrades gracefully to "no YARA
  signal" if `yara-python` isn't installed or no rules compile —
  never breaks file monitoring.

**A real bug found via live testing, not just unit tests:** dropping a
file under a non-tracked name and then renaming it to a tracked
extension (exactly how browsers land downloads — `.crdownload` →
`.exe`) was invisible to the monitor, because watchdog reports a
rename as `on_moved`, not `on_created`/`on_modified`, and the handler
only listened for those two. Fixed by treating `on_moved` into a
tracked extension as a creation at the destination path, with a
regression test for the exact scenario (verified both at the unit
level and against a real watchdog observer).

`monitors/hashing.py` (hash a file, capped by size; sample the first N
bytes) and `detection/entropy.py` (Shannon entropy) are now shared
utilities — deduped out of Phase 5's URL indicators and Phase 6's
process monitor respectively, since file monitoring needed the same
logic a third time.

### Network monitoring (Phase 8)

`monitors/network_monitor.py` polls `psutil.net_connections()` on a
background thread at a configurable interval
(`monitoring.network_poll_interval_seconds`, default 3s) and diffs
each snapshot against the previous one — same pattern as process
monitoring, since there's no lightweight OS-level connection-event API
without WFP (Windows Filtering Platform) or ETW that stays within the
dependency budget. Only **new** established outbound connections are
recorded — unlike process termination, "a connection closed" isn't a
meaningful security signal on its own and would be pure noise at the
volume real traffic generates. SentinelGuard's own loopback traffic
(the GUI/extensions talking to the agent on 127.0.0.1) is filtered out
entirely so it never pollutes this table.

**DNS activity, "where available"**: `psutil` has no visibility into
DNS queries themselves — genuine visibility needs ETW (Windows) or
packet capture, both out of scope for a dependency-light v1 (Phase 10's
log analyzer is the right place for ETW-based DNS visibility later).
As a practical approximation, each new connection's destination IP
gets a best-effort, cached, timeout-bounded reverse DNS lookup
(`monitoring.network_reverse_dns_timeout_seconds`) to attach a
human-readable domain for correlation/display. This is *not* the same
as seeing the actual DNS query, and a large fraction of legitimate
destinations (CDNs, cloud providers) have no PTR record at all — so
"no reverse DNS" is deliberately never scored as suspicious; doing so
would be pure noise, exactly the kind of weak heuristic the spec warns
against overclaiming from.

`detection/network_analysis.py` scores each new connection: a LOLBin
process (from the same list used in process monitoring) making an
outbound connection is unusual and strongly weighted, a small curated
set of ports historically associated with malware C2 defaults (e.g.
Metasploit's 4444) adds a moderate signal, and a known-malicious-IP
match against the *same* `blocklist` table used for domains/hashes
(`entry_type="ip"`) short-circuits straight to Critical.

Listing all users' connections can require Administrator/root
privileges on some platforms (notably macOS); this degrades to "no
data" rather than crashing if access is denied.

### Persistence monitoring (Phase 9)

`monitors/persistence_monitor.py` polls four persistence locations —
registry `Run`/`RunOnce` keys (HKCU/HKLM, plus the WOW6432Node 32-bit
view), startup folders, scheduled tasks (via the Task Scheduler COM
API), and services (via the Service Control Manager) — at a much
longer interval than the other monitors
(`monitoring.persistence_poll_interval_seconds`, default 30s), since
persistence entries change far less often than processes or
connections. Same diff-based "only new" pattern as process/network
monitoring; a persistence entry whose *command* changes (e.g. an
existing Run key hijacked to point somewhere else while keeping the
same name) is also treated as new, since the identity key includes
the command.

**Most of this is inherently Windows-only** — there's no "Run key"
concept on Linux — so every backend function safely returns an empty
list on any other platform or when the required Windows API isn't
available; the monitor still starts and runs cleanly everywhere, it
just finds nothing off Windows, which is the honest behavior rather
than crashing or fabricating data. Enumerating `HKEY_LOCAL_MACHINE`,
services, and some scheduled tasks can require Administrator
privileges; each backend degrades gracefully (skips what it can't
read) rather than failing the whole scan.

There's no dedicated `persistence` table in the schema — findings go
through the normalized `events` table (`event_type="persistence_new"`),
with source-specific fields (registry key, task path, service name,
…) in `details`. `detection/persistence_analysis.py` scores each entry
using the same shared LOLBin/suspicious-keyword lists as process and
network monitoring (`detection/lolbins.py`, now needed a third time),
plus a suspicious-location check (Temp/Downloads) and a
missing-target check (the referenced executable no longer exists on
disk — a mild signal on its own, since this also happens harmlessly
after an uninstall).

**Caveat**: the registry/scheduled-task/service backends use
`winreg`/`pywin32` APIs that only exist on Windows and could not be
run or verified in this project's Linux development environment.
They're written carefully against documented API behavior and wrapped
defensively throughout, but — unlike every other monitor in this
project — they haven't been exercised against the real APIs and
should be spot-checked on an actual Windows machine before being
relied on. The rest of the pipeline (diffing, scoring, writing to the
database) *was* verified end-to-end using synthetic entries injected
through the same backend-injection interface the real Windows
backends implement.

## Testing

```bash
pytest tests/ -v
```

## Configuration

`config/default_config.yaml` holds the defaults; a user config file at
the platform data directory (or a path passed via `--config`) is
deep-merged on top and validated with Pydantic. Notably:

* `api.host` is restricted to loopback addresses — the agent must never
  be reachable from the LAN.
* `risk.*_max` thresholds must be strictly increasing and map to the
  Informational / Low / Medium / High / Critical bands used everywhere
  in the app.
* `retention.*_days` controls how long each table's rows are kept
  (`database/retention.py` prunes on request; periodic scheduling is
  wired up once the background agent exists).

## Privileges

Some later-phase features (process/persistence monitoring internals,
Windows Event Log/ETW access, network filtering via WFP, quarantine of
system-protected paths) require Administrator privileges on Windows.
Each such feature will be clearly labeled when implemented, with a safe,
reduced-functionality fallback when not running elevated.

## Build order

1. ✅ Project structure + configuration + SQLite + logging
2. ✅ FastAPI localhost agent + authentication
3. ✅ PySide6 GUI + dashboard
4. ✅ Chrome/Edge/Firefox URL-monitoring extensions
5. ✅ URL detection + allow/block engine
6. ✅ Process monitoring
7. ✅ File monitoring + hashing + YARA
8. ✅ Network monitoring
9. ✅ Persistence monitoring
10. Windows log analyzer
11. Behavior correlation + risk scoring
12. Quarantine + response actions
13. Testing, performance optimization, PyInstaller packaging

## Privacy

SentinelGuard never uploads browsing or system data externally by
default. It does not collect passwords, form contents, cookies, or
page contents from browsers — only navigation metadata (URL, domain,
browser, timestamp, scheme) needed for local risk scoring.

## Intended use

For use only on systems you own or are explicitly authorized to
monitor.
