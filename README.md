# SentinelGuard

A lightweight, local-first personal antivirus / EDR / web filter for
**Windows**, built for a single authorized machine. SentinelGuard
monitors processes, files, the network, persistence locations, and
security logs; watches URLs visited in Chrome, Edge, and Firefox via
browser extensions; scores risk locally; and gives you Allow / Block /
Allow Once / Always Allow / Always Block controls through a desktop GUI.

Everything runs on `127.0.0.1` and stores events in a local SQLite
database. Nothing is uploaded anywhere by default.

> **Status:** All 13 phases complete (project structure, configuration,
> database schema, logging, local FastAPI agent + authentication,
> PySide6 GUI + dashboard, Chrome/Edge/Firefox URL-monitoring
> extensions, URL detection + allow/block engine, process monitoring,
> file monitoring + hashing + YARA, network monitoring, persistence
> monitoring, Windows log analyzer, behavior correlation + risk
> scoring, quarantine + response actions, scheduled retention pruning,
> and PyInstaller packaging). See "Build order" below.

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

### Windows log analyzer (Phase 10)

`monitors/log_monitor.py` polls a focused set of security-relevant
Windows Event Log channels — **Security** (process creation, failed/
privileged logons, account/group changes), **System** (service
installs), **Microsoft-Windows-PowerShell/Operational** (script block
logging), and **Microsoft-Windows-Windows Defender/Operational**
(threat detections) — and normalizes matched events into the spec's
exact common event schema
(`timestamp`/`host`/`event_type`/`source`/`process`/`user`/`severity`/
`risk_score`/`details`), which is precisely the existing `events`
table from Phase 1 — no new table was needed.

Each channel is polled independently
(`monitoring.log_poll_interval_seconds`, default 15s) using an XPath
time filter (`TimeCreated[@SystemTime>'...']`) so each poll only asks
the Event Log API for events newer than the last one seen on that
channel — never a full-log rescan. Each channel's cursor starts at the
monitor's launch time, so restarting the agent never replays old
history.

`detection/log_analysis.py` classifies each event: PowerShell script
blocks and process command lines get scanned for the same suspicious
keywords used elsewhere (`detection/lolbins.py`), account/service
changes get a moderate baseline score, and Windows Defender's own
detections (1116/1117) are scored high directly — that's a vendor AV
engine's verdict already, not a weak local heuristic, so it's the one
exception to "never claim malicious from a weak signal."

Some channels — notably Security, and often PowerShell script block
logging and Defender — require specific Windows audit policies /
group policies to be enabled before they populate at all (e.g. "Audit
Process Creation" + "Include command line in process creation events"
for full 4688 visibility, "Turn on PowerShell Script Block Logging"
for 4104). SentinelGuard reads what's there; it doesn't enable these
policies itself. Reading the Security channel typically also requires
Administrator privileges; access failures degrade to "no events from
this channel" rather than crashing.

**Caveat, same as Phase 9's registry/task/service backends**: the
actual `win32evtlog` reading (`read_new_events_win32evtlog`) uses APIs
that only exist on Windows and could not be run in this project's
Linux development environment. It's written against the documented,
stable "Windows Event Log XML" rendering schema, and that XML-parsing
and classification logic *is* thoroughly tested against realistic
sample XML matching the real schema (including both the
`EventData`-based shape most providers use and the `UserData`-based
shape PowerShell's operational log uses) — but the `win32evtlog` call
sequence itself should be spot-checked on a real Windows machine.

Correlating these events with everything else — the spec's own
"Office process → PowerShell → network connection → executable
created → persistence created ⇒ one incident" example — is Phase 11's
job. This phase only classifies one event at a time.

### Behavior correlation + risk scoring (Phase 11)

This phase ties every prior monitor together, sitting entirely on top
of the `events` table each of them already writes to — no monitor from
Phases 6-10 needed to change. (One gap did need fixing: `POST
/websites/check` previously only wrote to the `websites` table, never
`events`, so URL activity was invisible to everything below. It now
writes both.)

**YAML rule engine** (`rules/`, loaded once at agent startup —
picking up an edited rule currently requires restarting the agent).
Two rule shapes share the directory, distinguished by which key is
present:

* **Condition rules** — the spec's own example format, unchanged:
  ```yaml
  name: Suspicious PowerShell
  severity: high
  conditions:
    process: powershell.exe
    indicators:
      - encodedcommand
      - downloadstring
      - invoke-webrequest
  ```
  `event_type` (e.g. `process_create`, `file_created`,
  `network_connection`, `website_check`, `persistence_new`) is how a
  rule targets the spec's "process/command-line/file/network/URL/
  persistence rule" types — one flexible schema instead of six
  separate ones. `indicators` matches against every string value in
  the event's `details` (command lines, script text, paths, URLs,
  …), not just a summary field.
* **Correlation scenarios** (the spec's "Event correlation" rule
  type) — an ordered list of steps, each naming the event type(s) (and
  optionally a process-name substring) that must occur, in order,
  within a rolling window:
  ```yaml
  name: Office document spawns PowerShell, then reaches out and persists
  severity: critical
  window_minutes: 15
  steps:
    - event_types: [process_create]
      process_contains: [winword.exe, excel.exe, outlook.exe]
    - event_types: [process_create]
      process_contains: [powershell.exe, pwsh.exe]
    - event_types: [network_connection]
    - event_types: [file_created]
    - event_types: [persistence_new]
  ```
  This is the literal spec example. A match bundles every matched
  event into **one** `Incident` row (not five separate alerts) plus
  one `Alert` pointing at it.

  **Honest scope**: this is time-window + process-name-substring
  correlation, not strict PID/causal lineage tracing. Reliably proving
  "this exact PowerShell process is a child of this exact Word
  process, and this exact file write came from that PowerShell
  process" needs deeper OS instrumentation (a filesystem minifilter
  driver, ETW process-correlated file events) that's out of scope for
  a dependency-light v1. Documented directly in
  `detection/correlation_engine.py`.

Six starter rule files ship in `rules/`, one per spec-listed rule
type plus the correlation example above (`suspicious_powershell.yaml`,
`persistence_from_temp.yaml`, `network_c2_port.yaml`,
`executable_double_extension.yaml`, `defender_detection.yaml`,
`correlation_office_powershell_chain.yaml`) — illustrative starting
points, not exhaustive threat intel, same spirit as Phase 7's bundled
YARA rules.

**Where it runs**: `monitors/correlation_monitor.py` is a background
worker unlike every other monitor — it doesn't observe the OS, it
polls the `events` table itself (`monitoring.correlation_poll_interval_seconds`,
default 10s). Each poll: condition rules run against events newer
than the last one seen (a simple cursor); correlation scenarios run
against a rolling window (`monitoring.correlation_window_minutes`,
default 15). Already-correlated event IDs are tracked in memory only
(not persisted), so — like every other monitor's "don't replay old
history on restart" behavior — a restart could in theory re-match a
chain whose events are still within the window; a minor, documented
trade-off.

**Risk scoring**: the 0-20/21-40/41-60/61-80/81-100 severity bands
have existed since Phase 4 (`detection/risk.py`), and every monitor's
`reasons` list has always explained its score — that requirement was
already satisfied. What Phase 11 adds is `severity_floor()` (the
inverse of the band mapping: given a rule's declared severity, what's
the minimum risk score consistent with it), used so a YAML rule's
declared severity can only ever raise an event's risk, never lower it
below what the rule demands. The **`alerts` and `incidents` tables
have existed since Phase 1 but sat completely unused until now** — the
`/status` dashboard's `threats_detected`/`recent_alerts` counters have
shown `0` since Phase 2 for exactly that reason, and now reflect real
data.

No automatic remediation happens here — matching an alert/incident
never kills a process, quarantines a file, or blocks anything by
itself. That's Phase 12's job, and the spec is explicit that it needs
its own confirmation step.

### Quarantine + response actions (Phase 12)

Block/Allow/Allow-once for URLs already existed (Phase 4/5, via
`POST /websites/decision`). This phase adds the rest of the spec's
Response section: `response/actions.py` implements the actions
themselves, `api/routes/response.py` is the thin HTTP layer.

**Every destructive action (kill-process, quarantine-file,
disable-persistence) requires an explicit `confirm: true`** in the
request body — omit it and the agent 400s and does nothing. This is
the literal API-level enforcement of "require confirmation before
destructive actions"; a future GUI confirmation dialog is what's
expected to set that flag. Every successful action is logged as an
admin action (`agent/audit.py`) and recorded in `events`, so it's
visible in the same unified stream as everything else — including to
the rule/correlation engine from Phase 11.

* **`POST /response/kill-process`** — `psutil`-based `terminate()`,
  escalating to `kill()` after a 3s timeout. Refuses to kill the
  agent's own process, and refuses a small denylist of protected
  system process names (`lsass.exe`, `csrss.exe`, `wininit.exe`,
  `services.exe`, `svchost.exe`, …) regardless of `confirm` — not an
  explicit spec requirement, but a direct safety consequence of
  "restrict privileged operations": a bad rule or a mistaken PID
  shouldn't be able to crash the OS.
* **`POST /response/quarantine-file`** / **`POST
  /response/restore-quarantine`** — moves a file into
  `<data_dir>/quarantine/` under a random `<uuid>.quarantined` name,
  fully disconnected from the original filename/extension so it can't
  be accidentally re-triggered, with permissions stripped on POSIX.
  Records a `QuarantineItem` row (a table that's existed since Phase 1
  but was unused until now) and restore completes the round trip —
  its `restored`/`restored_at` fields finally get used too. Refuses to
  quarantine a relative path, a missing file, a directory, or a file
  already inside the quarantine directory.
* **`POST /response/disable-persistence`** — dispatches by
  `source_type` (matching Phase 9's `PersistenceEntry` shape):
  registry Run/RunOnce values get deleted via `winreg`, services get
  their start type set to Disabled (not deleted — reversible) via
  `win32service`, scheduled tasks get `Enabled = False` (not deleted)
  via the Task Scheduler COM API, and startup-folder entries get
  quarantined (reusing the mechanism above, since disabling a
  file-based entry just means moving the file). **Same honest caveat
  as Phases 9-10**: the registry/service/task backends are Windows-only
  and could not be run/verified in this Linux dev environment —
  written against documented API behavior and wrapped defensively,
  but flagged as needing a real-Windows spot-check. The
  startup-folder case is plain file operations and *is* genuinely
  tested, including live, end-to-end.
* **`GET /incidents/{id}/export`** — returns the incident plus every
  one of its related events, fully expanded, as JSON.
* **`POST /alerts/{id}/false-positive`** / **`POST
  /incidents/{id}/false-positive`** — sets `status="false_positive"`.
  Not gated by `confirm`: marking something as a false positive isn't
  destructive, it's just triage.

### Testing, retention scheduling, and packaging (Phase 13)

**Retention pruning is now actually scheduled.** `database/retention.py`'s
`prune_old_records` has existed since Phase 1 as a callable, but nothing
ever called it periodically — every table would have grown unbounded.
`monitors/retention_monitor.py` fixes that: a `RetentionMonitor` runs
once immediately at agent startup (so a never-before-pruned database
gets cleaned up right away, not after a full day's wait) and then on
`monitoring.retention_prune_interval_hours` (default 24h — pruning is
cheap and doesn't need to run often, so this is deliberately the
quietest monitor in the agent). Wired into `api/app.py`'s lifespan
alongside every other monitor, starting last and stopping first.

**End-to-end coverage.** Every other test file disables
`settings.monitoring.enabled` for speed and isolation.
`tests/test_end_to_end.py` is the one place that starts the real
FastAPI app with all seven monitors enabled together and confirms the
whole lifespan — startup order, shutdown order, nothing tripping over
anything else — actually works, not just each monitor in isolation.
`tests/test_main.py` adds coverage for `main.py`'s CLI argument parsing
and bootstrap dispatch (`--serve` / `--gui` / bootstrap-only), which had
no dedicated tests before.

**A hardening pass on direct-DB-write monitors.** Writing the new
retention monitor's "survives a broken session" test caught a real bug:
`session = self._session_factory()` sat outside its own `try` block, so
a failure in the session factory itself (e.g. a transient DB error)
would propagate uncaught into the monitor's polling loop — which has no
exception handling of its own — silently killing that background thread
for the rest of the process's life, with no further pruning and no
visible error. `process_monitor.py`, `file_monitor.py`,
`network_monitor.py`, and `log_monitor.py` are naturally immune (they
only ever write through `QueueWriter`, whose own `_flush` already wraps
`write_batch` — session creation included — in a try/except), but
`correlation_monitor.py` writes directly from its own thread the same
way `retention_monitor.py` does, and had the identical gap in both
`_run` (the startup query) and `_poll_once`. Fixed in all three
locations: session creation now happens inside its own guarded block
so a factory failure is logged and the monitor keeps polling on the
next interval, instead of dying silently.

**PyInstaller packaging.** `sentinelguard.spec` builds a onedir bundle
(a folder of an executable plus its dependencies — the standard choice
for an app that runs a background agent thread continuously, since
onefile's per-launch extract-to-temp-dir cost isn't a good fit here):

```bash
pip install -r requirements.txt
pyinstaller sentinelguard.spec
# Output: dist/SentinelGuard/ (SentinelGuard.exe on Windows)
```

It bundles `config/default_config.yaml`, `rules/*.yaml`, and
`yara/*.yar` as data files (the code locates them via
`Path(__file__).resolve().parent`, which still resolves correctly
inside a frozen bundle as long as the data lands at the matching
relative path — which the spec's `datas` list ensures). Hidden imports
cover `watchdog.observers`' platform-specific backend modules (picked
at import time based on the OS, which PyInstaller's static analysis
can't see) and, only when building on Windows, pywin32's
`win32timezone`/`win32com.shell` (imported by name rather than via a
traceable `import` statement, and not installed at all on other
platforms — the spec guards this behind `sys.platform == "win32"` so a
build on another OS doesn't fail trying to resolve a package that isn't
there).

**Honest caveat, same pattern as Phases 9/10/12:** the spec has been
built and smoke-tested on Linux — confirming the packaging mechanics
work end to end (data files land at the right paths, the frozen binary
boots, starts every monitor including the new retention one, serves
`/health` and `/status`, and shuts down cleanly on SIGINT with monitors
stopping in the correct reverse order) — but that only proves the
*packaging* is correct. It does not exercise the Windows-only backends
themselves (registry/service/task persistence enumeration, Windows
Event Log reading), which still need a real-Windows spot-check, same as
their unpackaged counterparts.

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
* `retention.*_days` controls how long each table's rows are kept;
  `monitoring.retention_prune_interval_hours` (default 24h) controls how
  often `monitors/retention_monitor.py` runs the prune.

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
10. ✅ Windows log analyzer
11. ✅ Behavior correlation + risk scoring
12. ✅ Quarantine + response actions
13. ✅ Testing, performance optimization, PyInstaller packaging

## Privacy

SentinelGuard never uploads browsing or system data externally by
default. It does not collect passwords, form contents, cookies, or
page contents from browsers — only navigation metadata (URL, domain,
browser, timestamp, scheme) needed for local risk scoring.

## Intended use

For use only on systems you own or are explicitly authorized to
monitor.
