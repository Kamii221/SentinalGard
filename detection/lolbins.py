"""Shared list of commonly-abused Windows utilities ("LOLBins" --
living-off-the-land binaries) and suspicious command-line indicators.

Used across process (Phase 6), network (Phase 8), and persistence
(Phase 9) detection -- extracted here once it was needed a third time.
"""

from __future__ import annotations

LOLBIN_PROCESS_NAMES = frozenset(
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    }
)

SUSPICIOUS_CMDLINE_KEYWORDS = (
    "-encodedcommand", "-enc ", "downloadstring", "invoke-webrequest",
    "invoke-expression", "iex(", "-nop", "-noni", "-w hidden",
    "-windowstyle hidden", "bypass",
)
