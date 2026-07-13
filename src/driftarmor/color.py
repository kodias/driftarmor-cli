"""ANSI color helpers for human CLI output.

Pad plain text first, then wrap color — never colorize then pad
(ANSI escape codes break width formatting).
"""

from __future__ import annotations

import os
import sys
from typing import Literal

ColorLevel = Literal["green", "yellow", "red"]

_RESET = "\033[0m"
_CODES: dict[ColorLevel, str] = {
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
}

SEVERITY_TO_LEVEL: dict[str, ColorLevel] = {
    "pass": "green",
    "warn": "yellow",
    "manual": "yellow",
    "fail": "red",
}

ACTION_TO_LEVEL: dict[str, ColorLevel] = {
    "create": "green",
    "update": "yellow",
    "delete": "red",
    "replace": "red",
}


def colors_enabled(*, no_color: bool) -> bool:
    """Resolve color enablement once per command invocation."""
    if no_color:
        return False
    if "NO_COLOR" in os.environ:
        return False
    return sys.stdout.isatty()


def colorize(text: str, level: ColorLevel, *, enabled: bool) -> str:
    """Wrap already-padded text in ANSI color when enabled."""
    if not enabled:
        return text
    code = _CODES.get(level)
    if not code:
        return text
    return f"{code}{text}{_RESET}"
