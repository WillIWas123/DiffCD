"""
Output handling for DiffCD.

All *findings* are written to stdout (or --output file) so they can be piped
or parsed cleanly. All *logs* (calibration notices, progress, errors) go to
stderr via the logger, so the two never mix.

Three output formats are supported:

  * pretty  - human friendly, aligned, colorized when stdout is a TTY (default)
  * json    - one JSON object per line (JSONL), with full detail
  * paths   - just the URL/path of each finding, one per line (minimal)
"""

import json
import sys
import threading
import time


# ANSI colors, only used when colorizing is enabled.
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_COLORS = {
    "green": "\033[32m",
    "cyan": "\033[36m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "grey": "\033[90m",
}


def _status_color(status_code):
    try:
        bucket = int(status_code) // 100
    except (TypeError, ValueError):
        return "grey"
    return {2: "green", 3: "cyan", 4: "yellow", 5: "red"}.get(bucket, "grey")


def parse_headers(raw):
    """Turn the raw header blob (bytes) from httpdiff into an ordered dict."""
    headers = {}
    if not raw:
        return headers
    if isinstance(raw, bytes):
        raw = raw.decode("latin-1", errors="replace")
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip()] = value.strip()
    return headers


class Reporter:
    """Thread-safe sink for findings. One instance per scan."""

    def __init__(self, fmt="pretty", color=True, output=None, logger=None):
        self.fmt = fmt
        self.logger = logger
        self._lock = threading.Lock()
        self._count = 0
        self._start = time.time()

        # Decide where findings go.
        if output and output not in ("-", "/dev/stdout"):
            self._fh = open(output, "w", buffering=1)
            self._owns_fh = True
            self._is_tty = False
        else:
            self._fh = sys.stdout
            self._owns_fh = False
            self._is_tty = sys.stdout.isatty()

        # Color only when asked AND when writing to a real terminal.
        self.color = color and self._is_tty

    # -- helpers ---------------------------------------------------------

    def _c(self, text, color=None, bold=False, dim=False):
        if not self.color:
            return text
        prefix = ""
        if bold:
            prefix += _BOLD
        if dim:
            prefix += _DIM
        if color:
            prefix += _COLORS.get(color, "")
        if not prefix:
            return text
        return f"{prefix}{text}{_RESET}"

    def _write(self, line):
        with self._lock:
            self._fh.write(line + "\n")
            if not self._owns_fh:
                self._fh.flush()

    # -- public API ------------------------------------------------------

    @property
    def count(self):
        return self._count

    def report(self, result):
        """Emit a single finding. `result` is the dict built by main.py."""
        with self._lock:
            self._count += 1

        if self.fmt == "json":
            self._write(json.dumps(result, sort_keys=False))
        elif self.fmt == "paths":
            self._write(result["url"])
        else:
            self._write(self._format_pretty(result))

    def _format_pretty(self, r):
        sc = r["status_code"]
        sc_str = str(sc) if sc is not None else "ERR"
        status = self._c(f"{sc_str:>3}", _status_color(sc), bold=True)

        # Compact "section:count" summary of what changed.
        changes = r.get("changes", {})
        change_str = " ".join(f"{k}={v}" for k, v in changes.items())
        change_str = self._c(change_str, "grey")

        url = self._c(r["url"], bold=True)

        extras = []
        if r.get("content_length") is not None:
            extras.append(self._c(f"{r['content_length']}B", "blue"))
        if r.get("response_time_ms") is not None:
            extras.append(self._c(f"{r['response_time_ms']:.0f}ms", "magenta"))
        if r.get("location"):
            extras.append(self._c(f"-> {r['location']}", "cyan"))
        if r.get("error"):
            extras.append(self._c(f"error={r['error']}", "red"))
        extra_str = "  ".join(extras)

        line = f"  [{status}] {url}"
        if extra_str:
            line += f"  {extra_str}"
        if change_str:
            line += f"\n        {self._c('changed:', 'grey')} {change_str}"
        return line

    def summary(self):
        """Write a short end-of-scan summary to stderr (never to stdout)."""
        elapsed = time.time() - self._start
        msg = (
            f"Scan complete: {self._count} finding(s) in {elapsed:.1f}s"
        )
        if self.logger:
            self.logger.info(msg)
        else:
            sys.stderr.write(msg + "\n")

    def close(self):
        if self._owns_fh:
            self._fh.close()
