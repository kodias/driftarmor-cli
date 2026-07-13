"""Unit tests for ANSI color helpers."""

from __future__ import annotations

import os

from driftarmor.color import colorize, colors_enabled


def test_colorize_disabled_returns_plain():
    text = f"{'fail':<8}"
    assert colorize(text, "red", enabled=False) == text
    assert "\033[" not in colorize(text, "red", enabled=False)


def test_colorize_enabled_wraps_ansi():
    text = f"{'fail':<8}"
    out = colorize(text, "red", enabled=True)
    assert out.startswith("\033[31m")
    assert out.endswith("\033[0m")
    assert "fail" in out


def test_pad_then_color_keeps_visible_width():
    """Color after pad: visible content still starts with padded field."""
    padded = f"{'pass':<8}"
    out = colorize(padded, "green", enabled=True)
    # Strip ANSI and compare to padded plain
    plain = out.replace("\033[32m", "").replace("\033[0m", "")
    assert plain == padded
    assert len(padded) == 8


def test_colors_enabled_no_color_flag(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    assert colors_enabled(no_color=True) is False
    assert colors_enabled(no_color=False) is True


def test_colors_enabled_no_color_env(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    assert colors_enabled(no_color=False) is False


def test_colors_enabled_non_tty(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)
    assert colors_enabled(no_color=False) is False
