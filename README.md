# SentinelGuard

A lightweight, local-first personal antivirus / EDR / web filter for
**Windows**, built for a single authorized machine. SentinelGuard
monitors processes, files, the network, persistence locations, and
security logs; watches URLs visited in Chrome, Edge, and Firefox via
browser extensions; scores risk locally; and gives you Allow / Block /
Allow Once / Always Allow / Always Block controls through a desktop GUI.

Everything runs on `127.0.0.1` and stores events in a local SQLite
database. Nothing is uploaded anywhere by default.

> **Status:** Phase 2 of 13 complete (project structure, configuration,
> database schema, logging, local FastAPI agent + authentication). See
> "Build Order" below for what's next.

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
python main.py --serve    # also start the local agent on 127.0.0.1:8765
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

Browser extensions (Phase 4) and the GUI (Phase 3) will use this same
token to talk to the agent; no data leaves 127.0.0.1.

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
3. PySide6 GUI + dashboard
4. Chrome/Edge/Firefox URL-monitoring extensions
5. URL detection + allow/block engine
6. Process monitoring
7. File monitoring + hashing + YARA
8. Network monitoring
9. Persistence monitoring
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
