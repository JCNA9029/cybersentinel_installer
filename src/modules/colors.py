# modules/colors.py — Lightweight colorama wrapper for colored terminal output.
# Soft dependency: gracefully degrades to plain text if colorama is not installed.
#
# NOTE: All print() calls are routed through _safe_print() which guards against
# sys.stdout being None. This happens when the app is launched via pythonw.exe
# (the no-console GUI launcher), which sets sys.stdout = None. Without this
# guard, any call to print() — and therefore any colors.*() call — raises:
#     AttributeError: 'NoneType' object has no attribute 'write'

import sys

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    _COLORAMA = True
except ImportError:
    _COLORAMA = False

    class _Noop:
        """Stub that returns empty string for any attribute access."""
        def __getattr__(self, _):
            return ""

    Fore = _Noop()
    Style = _Noop()


def _safe_print(msg: str) -> None:
    """Print safely — silently no-ops if stdout is None (e.g. pythonw.exe)."""
    try:
        if sys.stdout is not None:
            print(msg)
    except Exception:
        pass


def success(msg: str):
    """Green — clean/safe results, successful operations."""
    _safe_print(f"{Fore.GREEN}{msg}{Style.RESET_ALL}")


def error(msg: str):
    """Red — errors, failed operations."""
    _safe_print(f"{Fore.RED}{msg}{Style.RESET_ALL}")


def critical(msg: str):
    """Bright red — MALICIOUS verdicts, containment events."""
    _safe_print(f"{Fore.RED}{Style.BRIGHT}{msg}{Style.RESET_ALL}")


def warning(msg: str):
    """Yellow — suspicious findings, non-fatal warnings."""
    _safe_print(f"{Fore.YELLOW}{msg}{Style.RESET_ALL}")


def info(msg: str):
    """Cyan — informational scan progress messages."""
    _safe_print(f"{Fore.CYAN}{msg}{Style.RESET_ALL}")


def header(msg: str):
    """Bright white — section headers and separators."""
    _safe_print(f"{Style.BRIGHT}{msg}{Style.RESET_ALL}")


def verdict_color(verdict: str) -> str:
    """Returns the verdict string wrapped in appropriate ANSI color codes."""
    v = verdict.upper()
    if any(k in v for k in ("MALICIOUS", "CRITICAL")):
        return f"{Fore.RED}{Style.BRIGHT}{verdict}{Style.RESET_ALL}"
    if "SUSPICIOUS" in v:
        return f"{Fore.YELLOW}{verdict}{Style.RESET_ALL}"
    if "SAFE" in v:
        return f"{Fore.GREEN}{verdict}{Style.RESET_ALL}"
    return verdict
