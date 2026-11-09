#!/usr/bin/env python3
"""datz.py — DATZ, a single-file terminal security console for authorized testing.

Everything ships in this one file:
  * the scan engine is embedded (webwarden, SHA-256 pinned) and extracted to
    ~/.datz/runtime on first run;
  * a full-screen ANSI terminal UI with a target box, module buttons, presets,
    live console, findings, chains, recon, files and report shortcuts;
  * mouse and keyboard control, plus terminal modes: --cli passthrough,
    --headless streaming scan, --doctor, --list-runs, --snapshot.
  * output folder is selectable inside the dashboard (OUT: KALI ~ or
    DOWNLOAD); the same choice works headless via --output.

Run:
    python3 datz.py                       # terminal dashboard
    python3 datz.py --demo                # dashboard with sample data only
    python3 datz.py --headless --target example.com --i-am-authorized --full
    python3 datz.py --headless --target example.com --i-am-authorized \
        --output downloads                # simpan ke Downloads laptop
    python3 datz.py --cli scan example.com --i-am-authorized
    python3 datz.py --report              # end-of-scan summary in the terminal
    python3 datz.py --disclosure          # vendor-ready draft (evidence + stop line)
    python3 datz.py --diagnose            # why does the dashboard exit?

Only scan domains you own or are explicitly authorized to test. The engine
sends GET/HEAD only, never logs in, never writes, and never runs exploit steps.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import importlib
import json
import locale
import math
import os
import platform
import re
import secrets
import select
import shutil
import signal
import subprocess
import sys
import textwrap
import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path

APP_VERSION = "2.10.0"
ENGINE_NAME = "webwarden"
HOME = Path(os.environ.get("DATZ_HOME") or (Path.home() / ".datz"))
RUNTIME_DIR = HOME / "runtime"
RUNS_DIR = HOME / "runs"
ENGINE_PATH = RUNTIME_DIR / "webwarden.pyz"
LOG_PATH = HOME / "datz.log"
DOWNLOAD_DIRNAME = "datz-runs"

OUTPUT_CHOICES = (
    ("runs", "KALI ~", "~/.datz/runs"),
    ("downloads", "DOWNLOAD", "Downloads laptop"),
)

TARGET_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$"
)
SCOPE_RE = re.compile(
    r"^(?:\*\.)?(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$"
)

MODULES = (
    ("injection", "Injection", "SQLi SSTI XSS LFI SSRF CRLF"),
    ("backdoors", "Backdoors", "web shell paths"),
    ("bypass", "Bypass 401/403", "path + header variants"),
    ("robots", "robots.txt", "GET-only reachability"),
    ("secrets", "Secrets", "HTML/JS credential scan"),
    ("bundles", "Bundles", "build drift, source maps"),
    ("takeover", "Takeover", "dangling CNAME"),
    ("nvd", "NVD CVE", "version candidates"),
    ("nuclei", "Nuclei", "safe template matches"),
)

PRESETS = {
    "quick": {
        "label": "Cepat",
        "modules": {"injection": False, "backdoors": False, "bypass": False,
                    "robots": False, "secrets": True, "bundles": True,
                    "takeover": False, "nvd": False, "nuclei": False},
        "recon_only": False,
    },
    "standard": {
        "label": "Standar",
        "modules": {"injection": True, "backdoors": True, "bypass": False,
                    "robots": False, "secrets": True, "bundles": True,
                    "takeover": True, "nvd": True, "nuclei": False},
        "recon_only": False,
    },
    "full": {
        "label": "Full",
        "modules": {"injection": True, "backdoors": True, "bypass": True,
                    "robots": True, "secrets": True, "bundles": True,
                    "takeover": True, "nvd": True, "nuclei": False},
        "recon_only": False,
    },
    "recon": {
        "label": "Recon",
        "modules": {"injection": False, "backdoors": False, "bypass": False,
                    "robots": False, "secrets": False, "bundles": True,
                    "takeover": True, "nvd": True, "nuclei": False},
        "recon_only": True,
    },
}
PRESET_ORDER = ("quick", "standard", "full", "recon")
PRESET_SHORT = {"quick": "Cepat", "standard": "Std", "full": "Full",
                "recon": "Recon"}
TABS = (
    ("summary", "Ringkasan"),
    ("console", "Console"),
    ("findings", "Temuan"),
    ("chains", "Chains"),
    ("recon", "Recon"),
    ("files", "Files"),
)
TAB_SHORT = {"summary": "Ringkas", "console": "Console", "findings": "Temuan",
             "chains": "Chains", "recon": "Recon", "files": "Files"}
FOCUS_ORDER = ("target", "scopes", "auth", "output", "presets", "modules",
               "advanced", "start", "stop", "doctor", "cmd", "tabs")


# --------------------------------------------------------------------------
# embedded engine
# --------------------------------------------------------------------------

def embedded_sha256() -> str:
    return PAYLOAD_SHA256  # noqa: F821 - filled in by the packaging step


def ensure_engine() -> Path:
    """Extract the embedded engine once and verify it on every run."""
    override = os.environ.get("DATZ_ENGINE")
    if override:
        path = Path(override).expanduser()
        if not path.is_file():
            raise RuntimeError(f"DATZ_ENGINE does not exist: {path}")
        return path
    payload = PAYLOAD_B64  # noqa: F821 - filled in by the packaging step
    if not payload:
        raise RuntimeError(
            "the embedded engine payload is missing; rebuild datz.py with "
            "the packaging script"
        )
    blob = base64.b64decode(payload)
    digest = hashlib.sha256(blob).hexdigest()
    if digest != embedded_sha256():
        raise RuntimeError("embedded engine payload failed its SHA-256 check")
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    if not ENGINE_PATH.is_file() or \
            hashlib.sha256(ENGINE_PATH.read_bytes()).hexdigest() != digest:
        tmp = ENGINE_PATH.with_suffix(".tmp")
        tmp.write_bytes(blob)
        try:
            os.chmod(tmp, 0o700)
        except OSError:
            pass
        os.replace(tmp, ENGINE_PATH)
    return ENGINE_PATH


def engine_version(engine: Path) -> str:
    try:
        out = subprocess.run(
            [sys.executable, str(engine), "--version"],
            capture_output=True, text=True, timeout=30, errors="replace",
        )
        text = (out.stdout or out.stderr).strip().splitlines()
        return text[0] if text else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unavailable"


def load_engine_module(engine: Path, name: str):
    """Import a module straight out of the embedded engine zipapp."""
    if str(engine) not in sys.path:
        sys.path.insert(0, str(engine))
    try:
        return importlib.import_module(f"webwarden.{name}")
    except Exception as exc:
        log_event(f"engine module {name} import failed: {exc}")
        return None


def load_licensing(engine: Path):
    return load_engine_module(engine, "licensing")


def validate_target(engine: Path, target: str) -> str:
    """Apply the engine's own scope rules before launching, so a bad target
    fails with a readable reason instead of a bare exit code 2 mid-scan."""
    util = load_engine_module(engine, "util")
    if util is None:
        return target
    try:
        return util.normalize_target(target)
    except util.ScopeError as exc:
        raise ValueError(str(exc)) from exc


def datz_license_products(module):
    """datz.py drives the webwarden engine, so webwarden keys belong here too."""
    return (module.PRODUCT_WEBWARDEN, module.PRODUCT_DATZ)


def license_gate(engine: Path, command: str, quiet: bool = False) -> tuple[str, int]:
    """Check the trial/licence before a run. Returns (badge, exit code)."""
    module = load_licensing(engine)
    if module is None:
        return ("", 0)
    products = datz_license_products(module)
    try:
        decision = (module.evaluate(products) if quiet else
                    module.enforce(products, command))
    except module.LicenseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return ("", 3)
    return (decision.badge, 0)


def license_flow(engine: Path, value: str) -> int:
    """`--license` with no value prints status; with a key it activates it."""
    module = load_licensing(engine)
    if module is None:
        print("error: modul lisensi tidak tersedia di engine ini", file=sys.stderr)
        return 1
    namespace = argparse.Namespace(
        license_action="activate" if value else "status",
        key=value,
        product=datz_license_products(module),
    )
    return module.run_license_command(namespace)


def log_event(message: str) -> None:
    """Append one line to ~/.datz/datz.log; never raise."""
    try:
        HOME.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(f"[{stamp}] {message}\n")
    except (OSError, ValueError):
        pass


def tail_log(limit: int = 8) -> list[str]:
    try:
        lines = LOG_PATH.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return []
    return lines.splitlines()[-limit:]


# --------------------------------------------------------------------------
# scan options -> engine argv
# --------------------------------------------------------------------------

@dataclass
class ScanOptions:
    target: str = ""
    scopes: list[str] = field(default_factory=list)
    authorized: bool = False
    recon_only: bool = False
    injection: bool = True
    backdoors: bool = True
    bypass: bool = False
    robots: bool = False
    secrets: bool = True
    bundles: bool = True
    takeover: bool = True
    nvd: bool = True
    nuclei: bool = False
    ai: str = "local"
    ai_model: str = ""
    rate: float = 5.0
    threads: int = 6
    timeout: float = 8.0
    max_hosts: int = 150
    max_requests: int = 4000
    ports: str = ""
    no_ports: bool = False
    no_brute: bool = False
    no_passive: bool = False
    allow_intercepted: bool = False
    user_agent: str = ""
    out: str = ""


def _number(payload: dict, key: str, default, kind=float, low=None, high=None):
    value = payload.get(key, default)
    try:
        value = kind(value)
    except (TypeError, ValueError):
        raise ValueError(f"{key} harus berupa angka")
    if low is not None and value < low:
        value = low
    if high is not None and value > high:
        value = high
    return value


def options_from_payload(payload: dict) -> ScanOptions:
    target = str(payload.get("target", "")).strip().lower().rstrip(".")
    if not target:
        raise ValueError("target wajib diisi")
    if not TARGET_RE.match(target):
        raise ValueError(
            "target harus domain seperti example.com (tanpa http://, path, "
            "atau spasi)"
        )
    if all(part.isdigit() for part in target.split(".")):
        raise ValueError("alamat IP tidak didukung; pakai nama domain")
    if not payload.get("authorize"):
        raise ValueError(
            "izin wajib: konfirmasi kamu pemilik target atau punya izin tertulis"
        )
    scopes: list[str] = []
    raw_scopes = payload.get("scopes") or []
    if isinstance(raw_scopes, str):
        raw_scopes = raw_scopes.split(",")
    for item in raw_scopes:
        item = str(item).strip().lower().rstrip(".")
        if not item:
            continue
        if not SCOPE_RE.match(item):
            raise ValueError(f"scope tidak valid: {item}")
        scopes.append(item)
    ai = str(payload.get("ai", "local")).lower()
    if ai not in ("off", "local", "ollama"):
        ai = "local"
    opts = ScanOptions(
        target=target,
        scopes=scopes,
        authorized=True,
        recon_only=bool(payload.get("recon_only")),
        injection=bool(payload.get("injection", True)),
        backdoors=bool(payload.get("backdoors", True)),
        bypass=bool(payload.get("bypass")),
        robots=bool(payload.get("robots")),
        secrets=bool(payload.get("secrets", True)),
        bundles=bool(payload.get("bundles", True)),
        takeover=bool(payload.get("takeover", True)),
        nvd=bool(payload.get("nvd", True)),
        nuclei=bool(payload.get("nuclei")),
        ai=ai,
        ai_model=str(payload.get("ai_model", "")).strip(),
        rate=_number(payload, "rate", 5.0, float, 0.5, 50.0),
        threads=_number(payload, "threads", 6, int, 1, 12),
        timeout=_number(payload, "timeout", 8.0, float, 2.0, 60.0),
        max_hosts=_number(payload, "max_hosts", 150, int, 1, 2000),
        max_requests=_number(payload, "max_requests", 4000, int, 50, 100000),
        ports=str(payload.get("ports", "")).strip(),
        no_ports=bool(payload.get("no_ports")),
        no_brute=bool(payload.get("no_brute")),
        no_passive=bool(payload.get("no_passive")),
        allow_intercepted=bool(payload.get("allow_intercepted")),
        user_agent=str(payload.get("user_agent", "")).strip(),
        out=str(payload.get("out", "")).strip(),
    )
    if opts.ports and not re.fullmatch(r"[0-9,\-]{1,120}", opts.ports):
        raise ValueError("ports harus seperti 80,443,8000-8100")
    if opts.user_agent and len(opts.user_agent) > 200:
        raise ValueError("user agent terlalu panjang")
    return opts


def build_scan_argv(engine: Path, opts: ScanOptions, outdir: Path) -> list[str]:
    argv = [sys.executable, str(engine), "scan", opts.target, "--i-am-authorized"]
    argv += ["--lang", "id"]
    for scope in opts.scopes:
        argv += ["--scope", scope]
    argv += ["--out", str(outdir)]
    argv += ["--rate", str(opts.rate), "--timeout", str(opts.timeout)]
    argv += ["--threads", str(opts.threads),
             "--max-hosts", str(opts.max_hosts),
             "--max-requests", str(opts.max_requests)]
    if opts.ports:
        argv += ["--ports", opts.ports]
    if opts.no_ports:
        argv.append("--no-ports")
    if opts.no_brute:
        argv.append("--no-brute")
    if opts.no_passive:
        argv.append("--no-passive")
    if opts.recon_only:
        argv.append("--recon-only")
    if opts.bypass:
        argv.append("--bypass")
    if opts.robots:
        argv.append("--robots-paths")
    if not opts.injection:
        argv.append("--no-injection")
    if not opts.backdoors:
        argv.append("--no-backdoors")
    if not opts.secrets:
        argv.append("--no-secrets")
    if not opts.bundles:
        argv.append("--no-bundles")
    if not opts.takeover:
        argv.append("--no-takeover")
    if not opts.nvd:
        argv.append("--no-nvd")
    if opts.nuclei:
        argv.append("--nuclei")
    argv += ["--ai-audit", opts.ai]
    if opts.ai_model:
        argv += ["--ai-model", opts.ai_model]
    if opts.allow_intercepted:
        argv.append("--allow-intercepted")
    if opts.user_agent:
        argv += ["--user-agent", opts.user_agent]
    return argv


def shell_join(argv: list[str]) -> str:
    parts = []
    for item in argv:
        if item and re.fullmatch(r"[A-Za-z0-9_@%+=:,./-]+", item):
            parts.append(item)
        else:
            parts.append("'" + item.replace("'", "'\\''") + "'")
    return " ".join(parts)


_downloads_probe: object = False


def config_path() -> Path:
    return HOME / "config.json"


def load_config() -> dict:
    try:
        data = json.loads(config_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_config(**updates) -> None:
    data = load_config()
    data.update({key: value for key, value in updates.items()
                 if value is not None})
    try:
        HOME.mkdir(parents=True, exist_ok=True)
        config_path().write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass


def _probe_windows_downloads() -> Path | None:
    """Folder Downloads milik Windows: C:\\Users\\<user>\\Downloads."""
    if os.name == "nt":
        base = Path.home() / "Downloads"
        return base if base.is_dir() else None
    users = Path("/mnt/c/Users")
    if not users.is_dir():
        return None
    found: list[Path] = []
    for exe in ("cmd.exe", "/mnt/c/Windows/System32/cmd.exe"):
        if "/" not in exe and shutil.which(exe) is None:
            continue
        try:
            out = subprocess.run([exe, "/c", "echo", "%USERPROFILE%"],
                                 capture_output=True, text=True, timeout=4)
        except (OSError, subprocess.SubprocessError):
            continue
        match = re.match(r"^([A-Za-z]):\\(.+)$", out.stdout.strip())
        if out.returncode == 0 and match:
            cand = (Path("/mnt") / match.group(1).lower()
                    / match.group(2).replace("\\", "/") / "Downloads")
            if cand.is_dir():
                found.append(cand)
            break
    if not found:
        skip = {"public", "default", "default user", "all users"}
        for base in sorted(users.iterdir()):
            if base.name.lower() in skip:
                continue
            cand = base / "Downloads"
            if cand.is_dir():
                found.append(cand)
    for cand in found:
        if os.access(cand, os.W_OK):
            return cand
    return found[0] if found else None


def windows_downloads() -> Path | None:
    override = os.environ.get("DATZ_DOWNLOADS", "").strip()
    if override:
        return Path(override).expanduser()
    global _downloads_probe
    if _downloads_probe is False:
        try:
            _downloads_probe = _probe_windows_downloads()
        except Exception:
            _downloads_probe = None
    return _downloads_probe  # type: ignore[return-value]


def downloads_root() -> Path | None:
    base = windows_downloads()
    return None if base is None else base / DOWNLOAD_DIRNAME


def output_root(dest: str = "runs") -> Path:
    if dest == "downloads":
        root = downloads_root()
        if root is None:
            raise OSError("folder Downloads laptop tidak ditemukan "
                          "(set DATZ_DOWNLOADS=/path)")
        root.mkdir(parents=True, exist_ok=True)
        return root
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    return RUNS_DIR


def run_roots() -> list[Path]:
    roots = [RUNS_DIR]
    extra = downloads_root()
    if extra is not None and extra != RUNS_DIR and extra.is_dir():
        roots.append(extra)
    return roots


def new_outdir(target: str, dest: str = "runs") -> Path:
    root = output_root(dest)
    slug = re.sub(r"[^a-z0-9.-]+", "-", target)[:60] or "target"
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for _ in range(50):
        path = root / f"{stamp}-{slug}-{secrets.token_hex(2)}"
        try:
            path.mkdir()
            return path
        except FileExistsError:
            continue
    raise RuntimeError("tidak bisa membuat direktori run")


def read_result(outdir: Path) -> dict:
    def load(name):
        path = outdir / name
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            return None

    files = []
    if outdir.is_dir():
        for path in sorted(outdir.rglob("*")):
            if not path.is_file():
                continue
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            files.append({"path": path.relative_to(outdir).as_posix(),
                          "size": size})
    total = len(files)
    return {
        "scan": load("scan.json"),
        "audit": load("audit.json"),
        "files": files[:500],
        "file_total": total,
        "has_report_html": (outdir / "report.html").is_file(),
        "has_report_md": outdir.joinpath("report.md").is_file(),
        "has_poc": outdir.joinpath("poc.sh").is_file(),
    }


# --------------------------------------------------------------------------
# screen buffer with ANSI styling
# --------------------------------------------------------------------------

RESET = "\x1b[0m"
CLEAR = "\x1b[2J"
HOME_CURSOR = "\x1b[H"

# 256-colour palette: midnight-blue console.
# Four surfaces stack from canvas to chrome, so panels read as cards rather
# than one flat field: BG < PANEL < PANEL2 < TEXT.
BG = 233          # canvas
PANEL = 235       # card surface
TRACK = 236       # input wells
PANEL2 = 237      # chrome: header, tab rail, status bar
EDGE = 238        # hairline rules
TEXT = 153        # primary copy
DIM = 111         # labels
FAINT = 242       # tertiary
ACCENT = 39       # azure
ACCENT2 = 51      # cyan
DEEP = 33
DEEP2 = 27
NIGHT = 24
FOCUS_BG = 17
GOOD = 42
WARN = 214
BAD = 203
CRIT = 203
MED = 215
LOW = 39
INFO = 244
INK = 16
GRAD = (45, 39, 33, 27)
SEV_FG = {"critical": 209, "high": 203, "medium": 215, "low": 45,
          "info": 244}

STYLE_DEFAULT = (TEXT, PANEL, False, False, False)


def sgr(style) -> str:
    if not style:
        return RESET
    fg, bg, bold, dim, rev = style
    parts = []
    if bold:
        parts.append("1")
    if dim:
        parts.append("2")
    if rev:
        parts.append("7")
    if fg is not None:
        parts.append(f"38;5;{fg}")
    if bg is not None:
        parts.append(f"48;5;{bg}")
    return "\x1b[" + ";".join(parts) + "m" if parts else RESET


class Screen:
    def __init__(self, width: int, height: int):
        self.w = max(1, width)
        self.h = max(1, height)
        self.ch = [[" "] * self.w for _ in range(self.h)]
        self.st = [[STYLE_DEFAULT] * self.w for _ in range(self.h)]
        self.regions: list[tuple[str, int, int, int, int]] = []

    def put(self, x: int, y: int, text: str, style=STYLE_DEFAULT) -> None:
        if y < 0 or y >= self.h:
            return
        for i, ch in enumerate(text):
            cx = x + i
            if 0 <= cx < self.w:
                self.ch[y][cx] = ch
                self.st[y][cx] = style

    def fill(self, x: int, y: int, w: int, h: int, style=STYLE_DEFAULT) -> None:
        for yy in range(max(0, y), min(self.h, y + h)):
            for xx in range(max(0, x), min(self.w, x + w)):
                self.ch[yy][xx] = " "
                self.st[yy][xx] = style

    def hline(self, x: int, y: int, w: int, ch="─", style=STYLE_DEFAULT) -> None:
        self.put(x, y, ch * max(0, w), style)

    def vline(self, x: int, y: int, h: int, ch="│", style=STYLE_DEFAULT) -> None:
        for yy in range(y, y + h):
            self.put(x, yy, ch, style)

    def box(self, x: int, y: int, w: int, h: int, style=STYLE_DEFAULT,
            title: str = "", title_style=None) -> None:
        if w < 3 or h < 2:
            return
        self.fill(x, y, w, h, style)
        self.put(x, y, "╭" + "─" * (w - 2) + "╮", style)
        self.put(x, y + h - 1, "╰" + "─" * (w - 2) + "╯", style)
        self.vline(x, y + 1, h - 2, "│", style)
        self.vline(x + w - 1, y + 1, h - 2, "│", style)
        if title:
            label = f" {title} "
            self.put(x + 2, y, label, title_style or style)

    def region(self, name: str, x: int, y: int, w: int, h: int) -> None:
        self.regions.append((name, x, y, w, h))

    def hit(self, x: int, y: int) -> str | None:
        for name, rx, ry, rw, rh in reversed(self.regions):
            if rx <= x < rx + rw and ry <= y < ry + rh:
                return name
        return None

    def render(self, colour: bool = True) -> str:
        rows = []
        for y in range(self.h):
            current = None
            parts = []
            for x in range(self.w):
                style = self.st[y][x]
                if colour and style != current:
                    parts.append(sgr(style))
                    current = style
                parts.append(self.ch[y][x])
            if colour:
                parts.append(RESET)
            rows.append("".join(parts).rstrip())
        return HOME_CURSOR + "\r\n".join(rows) + RESET

    def to_text(self) -> str:
        return "\n".join("".join(row).rstrip() for row in self.ch)


def clip(text: str, width: int) -> str:
    if width <= 0:
        return ""
    return text if len(text) <= width else text[: max(0, width - 1)] + "…"


def sev_style(sev: str):
    fg = {"critical": 231, "high": 231, "medium": INK,
          "low": INK, "info": INK}.get(sev, TEXT)
    bg = {"critical": CRIT, "high": BAD, "medium": MED,
          "low": LOW, "info": INFO}.get(sev, PANEL2)
    return (fg, bg, True, False, False)


# --------------------------------------------------------------------------
# design primitives: gradient type, hairlines, pills, keycaps, meters
# --------------------------------------------------------------------------

def _stop(stops, index: int, length: int):
    return stops[min(len(stops) - 1,
                     (index * len(stops)) // max(1, length))]


def gradient(scr: "Screen", x: int, y: int, text: str, stops=GRAD,
             bg: int = PANEL2, bold: bool = True) -> None:
    """Per-cell colour ramp: one continuous gradient instead of flat colour."""
    for i, ch in enumerate(text):
        scr.put(x + i, y, ch, (_stop(stops, i, len(text)), bg, bold, False,
                               False))


def hairline(scr: "Screen", x: int, y: int, w: int, bg: int = PANEL,
             stops=(EDGE, PANEL2)) -> None:
    for i in range(max(0, w)):
        scr.put(x + i, y, "─", (_stop(stops, i, w), bg, False, False, False))


def pill(scr: "Screen", x: int, y: int, text: str, fg: int, bg: int,
         bold: bool = True) -> int:
    scr.put(x, y, f" {text} ", (fg, bg, bold, False, False))
    return len(text) + 2


def keycap(scr: "Screen", x: int, y: int, key: str, label: str = "",
           bg: int = BG, accent: bool = False) -> int:
    """Inverse key badge plus a dim caption; returns the cells consumed."""
    scr.put(x, y, f" {key} ", (INK, ACCENT if accent else PANEL2, True,
                               False, False))
    used = len(key) + 2
    if label:
        scr.put(x + used, y, " " + label,
                (TEXT if accent else DIM, bg, False, False, False))
        used += len(label) + 1
    return used


def meter(scr: "Screen", x: int, y: int, value, width: int, colour: int,
          bg: int = PANEL, track: int = EDGE) -> None:
    """Heavy-bar meter: solid ━ for the filled span, hairline ─ behind."""
    width = max(1, int(width))
    if value is None:
        scr.put(x, y, "─" * width, (track, bg, False, False, False))
        return
    filled = max(0, min(width, int(round(width * float(value) / 100.0))))
    if filled:
        scr.put(x, y, "━" * filled, (colour, bg, False, False, False))
    if filled < width:
        scr.put(x + filled, y, "─" * (width - filled),
                (track, bg, False, False, False))


def section(scr: "Screen", x: int, y: int, w: int, label: str,
            hue: int = ACCENT, bg: int = PANEL, note: str = "") -> None:
    """`▎ LABEL ────── note` group header used across every panel."""
    scr.put(x, y, "▎", (hue, bg, True, False, False))
    scr.put(x + 2, y, label, (DIM, bg, True, False, False))
    used = 2 + len(label) + 1
    tail = len(note) + 1 if note else 0
    rule_w = w - used - tail
    if rule_w > 0:
        hairline(scr, x + used, y, rule_w, bg, (EDGE, bg))
    if note:
        scr.put(x + w - len(note), y, note, (FAINT, bg, False, False, False))


def equalizer(scr: "Screen", x: int, y: int, width: int, now: float,
              phase: int = 0, bg: int = PANEL2) -> None:
    """Animated VU bars for the tab rail; calm when idle, fast when scanning."""
    glyphs = "▁▂▃▄▅▆▇█"
    live = bool(phase)
    speed = 7.0 if live else 1.1
    for i in range(max(0, width)):
        wave = (math.sin(now * speed + i * 0.9 + phase) + 1.0) / 2.0
        level = min(len(glyphs) - 1, int(wave * (len(glyphs) if live else 4)))
        colour = _stop(GRAD if live else (DEEP, DEEP2), i, width)
        scr.put(x + i, y, glyphs[level], (colour, bg, False, False, False))


def divider(scr: "Screen", x: int, y: int, w: int, bg: int = PANEL) -> None:
    scr.put(x, y, "╌" * max(0, w), (EDGE, bg, False, False, False))



# --------------------------------------------------------------------------
# application state
# --------------------------------------------------------------------------

def default_modules() -> dict[str, bool]:
    mods = {key: key not in ("bypass", "robots", "nuclei") for key, _, _ in MODULES}
    return mods


@dataclass
class RunState:
    argv: list[str]
    outdir: Path
    started: float
    lines: list[str] = field(default_factory=list)
    done: bool = False
    code: int | None = None
    proc: subprocess.Popen | None = None
    error: str = ""
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, line: str) -> None:
        with self.lock:
            self.lines.append(line.rstrip("\r\n"))
            if len(self.lines) > 8000:
                del self.lines[:2000]

    def snapshot(self) -> list[str]:
        with self.lock:
            return list(self.lines)


# --------------------------------------------------------------------------
# host telemetry (best effort: every probe may fail and renders as "n/a")
# --------------------------------------------------------------------------

WEATHER_TTL = 900.0
WEATHER_TIMEOUT = 6.0
WEATHER_URL = "https://wttr.in/?format=%l%7C%C%7C%t%7C%h&m"
SPARK_GLYPHS = "▁▂▃▄▅▆▇█"


class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_uint32),
        ("dwMemoryLoad", ctypes.c_uint32),
        ("ullTotalPhys", ctypes.c_uint64),
        ("ullAvailPhys", ctypes.c_uint64),
        ("ullTotalPageFile", ctypes.c_uint64),
        ("ullAvailPageFile", ctypes.c_uint64),
        ("ullTotalVirtual", ctypes.c_uint64),
        ("ullAvailVirtual", ctypes.c_uint64),
        ("ullAvailExtendedVirtual", ctypes.c_uint64),
    ]


class _SYSTEM_POWER_STATUS(ctypes.Structure):
    _fields_ = [
        ("ACLineStatus", ctypes.c_ubyte),
        ("BatteryFlag", ctypes.c_ubyte),
        ("BatteryLifePercent", ctypes.c_ubyte),
        ("SystemStatusFlag", ctypes.c_ubyte),
        ("BatteryLifeTime", ctypes.c_uint32),
        ("BatteryFullLifeTime", ctypes.c_uint32),
    ]


def clamp_pct(value) -> float | None:
    try:
        pct = float(value)
    except (TypeError, ValueError):
        return None
    if pct != pct:
        return None
    return max(0.0, min(100.0, pct))


def pct_bar(pct, width: int = 5) -> str:
    width = max(1, int(width))
    value = clamp_pct(pct)
    if value is None:
        return "░" * width
    filled = max(0, min(width, int(round(width * value / 100.0))))
    return "█" * filled + "░" * (width - filled)


def sparkline(values, width: int = 10) -> str:
    width = max(1, int(width))
    data = [clamp_pct(v) for v in list(values)[-width:]]
    data = [v for v in data if v is not None]
    if not data:
        return ""
    last = len(SPARK_GLYPHS) - 1
    return "".join(SPARK_GLYPHS[min(last, int(v * len(SPARK_GLYPHS) / 100.0))]
                   for v in data)


def format_uptime(seconds) -> str:
    try:
        total = int(max(0.0, float(seconds)))
    except (TypeError, ValueError):
        return "n/a"
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {mins:02d}m"
    if mins:
        return f"{mins}m"
    return f"{rem}s"


def weather_icon(cond: str) -> str:
    low = (cond or "").lower()
    if any(word in low for word in ("thunder", "storm", "lightning")):
        return "STM"
    if any(word in low for word in ("snow", "sleet", "blizzard", "ice")):
        return "SNW"
    if any(word in low for word in ("rain", "drizzle", "shower")):
        return "RAN"
    if any(word in low for word in ("fog", "mist", "haze")):
        return "FOG"
    if "overcast" in low:
        return "OVC"
    if "cloud" in low:
        return "CLD"
    if "sun" in low or "clear" in low:
        return "SUN"
    return "WX"


def parse_weather(body: str) -> dict:
    raw = " ".join(str(body or "").split())
    if not raw:
        return {}
    low = raw.lower()
    if "unknown location" in low or "<html" in low[:200] or "sorry" in low[:80]:
        return {}
    parts = [part.strip() for part in raw.split("|")]
    if len(parts) >= 3:
        loc, cond, temp = parts[0], parts[1], parts[2]
        hum = parts[3] if len(parts) > 3 else ""
        icon = weather_icon(cond)
        text = " ".join(part for part in (icon, cond, temp) if part)
        return {"loc": loc[:28], "cond": cond[:24], "temp": temp[:10],
                "hum": hum[:8], "icon": icon, "text": text[:64]}
    return {"loc": "", "cond": "", "temp": "", "hum": "",
            "icon": "", "text": raw[:64]}


def fetch_weather(timeout: float = WEATHER_TIMEOUT) -> dict:
    import urllib.request

    request = urllib.request.Request(
        WEATHER_URL,
        headers={"User-Agent": f"datz/{APP_VERSION} (terminal ui widget)"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read(65536)
    return parse_weather(raw.decode("utf-8", "replace"))


def weather_cache_path() -> Path:
    return HOME / "weather.json"


def load_weather_cache() -> dict:
    try:
        data = json.loads(weather_cache_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or not str(data.get("text") or "").strip():
        return {}
    at = data.get("at")
    if not isinstance(at, (int, float)):
        return {}
    return data


def save_weather_cache(data: dict) -> None:
    try:
        HOME.mkdir(parents=True, exist_ok=True)
        path = weather_cache_path()
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        pass


class SysMonitor:
    """Read-only host telemetry for the dashboard.

    Every probe is optional; a failed or unsupported read leaves the value as
    ``None`` and the UI prints ``n/a``. Weather is a UI-only widget against
    wttr.in, kept off for snapshots/tests and switchable with ``--no-weather``;
    it never runs against a scan target.
    """

    def __init__(self, weather: bool = False,
                 weather_ttl: float = WEATHER_TTL):
        self.cpu: float | None = None
        self.ram: float | None = None
        self.ram_used_gb: float | None = None
        self.ram_total_gb: float | None = None
        self.battery: float | None = None
        self.plugged: bool | None = None
        self.uptime: float | None = None
        self.host = ""
        self.os_name = ""
        self.weather = ""
        self.weather_loc = ""
        self.weather_cond = ""
        self.weather_temp = ""
        self.weather_hum = ""
        self.weather_at = 0.0
        self.weather_source = "off"
        self.history: list[float] = []
        self._prev_cpu: tuple[float, float] | None = None
        self._last_at = 0.0
        self._stop = threading.Event()
        self._weather_ttl = max(60.0, float(weather_ttl))
        self._thread: threading.Thread | None = None
        try:
            self.host = platform.node() or ""
            self.os_name = f"{platform.system()} {platform.release()}".strip()
        except Exception:
            self.host = ""
            self.os_name = ""
        self.sample(time.time(), force=True)
        cached = load_weather_cache()
        if cached:
            self._apply_weather(cached)
            self.weather_source = "cache"
        if weather:
            try:
                self.start_weather()
            except Exception:
                self.weather_source = "off"

    # -- sampling --------------------------------------------------------
    def sample(self, now: float | None = None, force: bool = False) -> None:
        now = time.time() if now is None else now
        if not force and now - self._last_at < 1.0:
            return
        self._last_at = now
        for probe in (self._sample_cpu, self._sample_ram,
                      self._sample_battery, self._sample_uptime):
            try:
                probe()
            except Exception:
                continue

    def _sample_cpu(self) -> None:
        current = self._cpu_times()
        if current is None:
            return
        previous = self._prev_cpu
        self._prev_cpu = current
        if previous is None:
            return
        total = current[0] - previous[0]
        idle = current[1] - previous[1]
        if total <= 0:
            return
        pct = clamp_pct(100.0 * (total - idle) / total)
        if pct is None:
            return
        self.cpu = pct
        self.history.append(pct)
        del self.history[:-24]

    def _cpu_times(self) -> tuple[float, float] | None:
        if os.name == "nt":
            try:
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                idle, kernel, user = (ctypes.c_uint64() for _ in range(3))
                if not kernel32.GetSystemTimes(ctypes.byref(idle),
                                               ctypes.byref(kernel),
                                               ctypes.byref(user)):
                    return None
                return (float(kernel.value + user.value), float(idle.value))
            except Exception:
                return None
        try:
            with open("/proc/stat", "r", encoding="utf-8",
                      errors="replace") as handle:
                line = handle.readline()
        except OSError:
            return None
        parts = line.split()
        if not parts or parts[0] != "cpu" or len(parts) < 5:
            return None
        try:
            values = [float(value) for value in parts[1:]]
        except ValueError:
            return None
        idle = values[3] + (values[4] if len(values) > 4 else 0.0)
        return (sum(values), idle)

    def _sample_ram(self) -> None:
        data = self._ram_windows() if os.name == "nt" else self._ram_linux()
        if not data:
            return
        used, total = data
        if total <= 0:
            return
        self.ram = clamp_pct(100.0 * used / total)
        self.ram_used_gb = used / (1024.0 ** 3)
        self.ram_total_gb = total / (1024.0 ** 3)

    def _ram_linux(self) -> tuple[float, float] | None:
        try:
            with open("/proc/meminfo", "r", encoding="utf-8",
                      errors="replace") as handle:
                rows = handle.readlines()
        except OSError:
            return None
        info: dict[str, float] = {}
        for row in rows:
            key, _, rest = row.partition(":")
            chunk = rest.split()
            if chunk:
                try:
                    info[key.strip()] = float(chunk[0]) * 1024.0
                except ValueError:
                    continue
        total = info.get("MemTotal")
        if not total:
            return None
        available = info.get("MemAvailable")
        if available is None:
            available = (info.get("MemFree", 0.0) + info.get("Cached", 0.0)
                         + info.get("Buffers", 0.0))
        return (max(0.0, total - available), total)

    def _ram_windows(self) -> tuple[float, float] | None:
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            status = _MEMORYSTATUSEX()
            status.dwLength = ctypes.sizeof(status)
            if not kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return None
            total = float(status.ullTotalPhys)
            return (max(0.0, total - float(status.ullAvailPhys)), total)
        except Exception:
            return None

    def _sample_battery(self) -> None:
        if os.name == "nt":
            self._battery_windows()
        else:
            self._battery_linux()

    def _battery_windows(self) -> None:
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            status = _SYSTEM_POWER_STATUS()
            if not kernel32.GetSystemPowerStatus(ctypes.byref(status)):
                return
            # BatteryFlag 128 = no system battery, 255 = unknown
            if status.BatteryFlag == 255 or (status.BatteryFlag & 128):
                self.battery = None
            elif status.BatteryLifePercent == 255:
                self.battery = None
            else:
                self.battery = clamp_pct(status.BatteryLifePercent)
            self.plugged = (status.ACLineStatus == 1
                            if status.ACLineStatus in (0, 1) else None)
        except Exception:
            self.battery = None
            self.plugged = None

    def _battery_linux(self) -> None:
        try:
            bases = sorted(Path("/sys/class/power_supply").glob("BAT*"))
        except OSError:
            return
        for base in bases:
            try:
                pct = clamp_pct(float((base / "capacity").read_text(
                    encoding="utf-8", errors="replace").strip()))
            except (OSError, ValueError):
                continue
            if pct is None:
                continue
            self.battery = pct
            try:
                state = (base / "status").read_text(
                    encoding="utf-8", errors="replace").strip().lower()
                self.plugged = state in ("charging", "full", "not charging")
            except OSError:
                self.plugged = None
            return

    def _sample_uptime(self) -> None:
        if os.name == "nt":
            try:
                kernel32 = ctypes.WinDLL("kernel32")
                kernel32.GetTickCount64.restype = ctypes.c_uint64
                self.uptime = kernel32.GetTickCount64() / 1000.0
            except Exception:
                self.uptime = None
            return
        try:
            with open("/proc/uptime", "r", encoding="utf-8") as handle:
                self.uptime = float(handle.read().split()[0])
        except (OSError, ValueError, IndexError):
            self.uptime = None

    # -- weather ---------------------------------------------------------
    def start_weather(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        if not self.weather:
            self.weather_source = "loading"
        self._thread = threading.Thread(target=self._weather_loop,
                                        name="datz-weather", daemon=True)
        self._thread.start()

    def _weather_loop(self) -> None:
        while not self._stop.is_set():
            age = (time.time() - self.weather_at) if self.weather_at else 1e9
            if age < self._weather_ttl:
                self._stop.wait(min(60.0, self._weather_ttl - age))
                continue
            data: dict = {}
            try:
                data = fetch_weather()
            except Exception:
                data = {}
            if data.get("text"):
                self._apply_weather(data)
                self.weather_source = "wttr.in"
                save_weather_cache({**data, "at": time.time()})
            self._stop.wait(90.0)

    def _apply_weather(self, data: dict) -> None:
        text = str(data.get("text") or "").strip()
        if not text:
            return
        self.weather = text[:64]
        self.weather_loc = str(data.get("loc") or "")[:28]
        self.weather_cond = str(data.get("cond") or "")[:24]
        self.weather_temp = str(data.get("temp") or "")[:10]
        self.weather_hum = str(data.get("hum") or "")[:8]
        at = data.get("at")
        if isinstance(at, (int, float)):
            self.weather_at = float(at)
        elif not self.weather_at:
            self.weather_at = time.time()

    def close(self) -> None:
        self._stop.set()


class App:
    def __init__(self, engine: Path, version: str,
                 monitor: SysMonitor | None = None):
        self.engine = engine
        self.engine_version = version
        self.monitor = monitor if monitor is not None else SysMonitor()
        self.target = ""
        self.scopes = ""
        self.authorized = False
        self.preset = "standard"
        self.modules = default_modules()
        self.recon_only = False
        self.ai = "local"
        self.ai_model = ""
        self.rate = "5"
        self.threads = "6"
        self.timeout = "8"
        self.max_hosts = "150"
        self.max_requests = "4000"
        self.ports = ""
        self.no_ports = False
        self.no_brute = False
        self.no_passive = False
        self.allow_intercepted = False
        self.user_agent = ""
        self.focus = "target"
        self.preset_index = 1
        self.module_index = 0
        self.dest = "runs"
        self.license_badge = ""
        self.tab_index = 1
        self.tab = "console"
        self.editing: tuple[str, list[str]] | None = None
        self.edit_pos = 0
        self._adv_edit: tuple[str, list[str]] | None = None
        self.advanced_open = False
        self.adv_index = 0
        self.overlay: tuple[str, str, str] | None = None
        self.overlay_scroll = 0
        self.message: tuple[str, bool, float] | None = None
        self.run: RunState | None = None
        self.result: dict | None = None
        self.parsed = False
        self.demo = False
        self.find_sel = 0
        self.find_scroll = 0
        self.console_off = 0
        self.follow = True
        self.scroll = {"chains": 0, "recon": 0, "files": 0}
        self.running = False
        self.started_at = 0.0
        self.finished_at = 0.0
        self.doctor_proc: subprocess.Popen | None = None
        self.doctor_text = ""
        self.quit = False
        self.quit_armed_until = 0.0
        self.regions: list[tuple[str, int, int, int, int]] = []
        self.spinner = 0
        self.last_draw = 0.0
        self._wrapped_cache: tuple[int, int, list[str]] | None = None

    # -- helpers ---------------------------------------------------------
    def notify(self, text: str, error: bool = False) -> None:
        self.message = (text, error, time.time() + 6)

    def set_dest(self, dest: str) -> None:
        valid = [key for key, _label, _hint in OUTPUT_CHOICES]
        if dest not in valid:
            return
        if self.running:
            self.notify("scan sedang jalan; output mengikuti run yang aktif",
                        True)
            return
        self.dest = dest
        save_config(output=dest)
        try:
            root = output_root(dest)
        except OSError as exc:
            self.notify(str(exc), True)
            return
        win = windows_path(root)
        self.notify(f"output: {win or root}")

    def cycle_dest(self) -> None:
        keys = [key for key, _label, _hint in OUTPUT_CHOICES]
        index = keys.index(self.dest) if self.dest in keys else 0
        self.set_dest(keys[(index + 1) % len(keys)])

    def payload(self) -> dict:
        return {
            "target": self.target,
            "scopes": self.scopes,
            "authorize": self.authorized,
            "recon_only": self.recon_only,
            **self.modules,
            "ai": self.ai,
            "ai_model": self.ai_model,
            "rate": self.rate or 5,
            "threads": self.threads or 6,
            "timeout": self.timeout or 8,
            "max_hosts": self.max_hosts or 150,
            "max_requests": self.max_requests or 4000,
            "ports": self.ports,
            "no_ports": self.no_ports,
            "no_brute": self.no_brute,
            "no_passive": self.no_passive,
            "allow_intercepted": self.allow_intercepted,
            "user_agent": self.user_agent,
        }

    def apply_preset(self, key: str) -> None:
        preset = PRESETS[key]
        self.preset = key
        self.preset_index = PRESET_ORDER.index(key)
        for module, flag in preset["modules"].items():
            self.modules[module] = flag
        self.recon_only = preset["recon_only"]

    def command(self) -> str:
        try:
            opts = options_from_payload(self.payload())
        except ValueError:
            target = self.target.strip().lower() or "example.com"
            opts = ScanOptions(target=target, authorized=True,
                               **{k: v for k, v in self.modules.items()})
        outdir = RUNS_DIR / "<run-dir>"
        argv = build_scan_argv(self.engine, opts, outdir)
        return shell_join([ENGINE_NAME] + argv[2:])

    # -- scan lifecycle --------------------------------------------------
    def start(self) -> None:
        if self.running:
            self.notify("scan masih berjalan; tekan F6 untuk stop", True)
            return
        if self.demo:
            self.notify("mode demo: data contoh. Jalankan `python3 datz.py` "
                        "tanpa --demo untuk scan sungguhan.", True)
            return
        payload = self.payload()
        if not payload["target"].strip():
            self.notify("isi target domain dulu", True)
            self.focus = "target"
            return
        if not payload["authorize"]:
            self.notify("centang izin dulu: pemilik / izin tertulis", True)
            self.focus = "auth"
            return
        try:
            opts = options_from_payload(payload)
        except ValueError as exc:
            self.notify(str(exc), True)
            self.focus = "target"
            return
        try:
            opts.target = validate_target(self.engine, opts.target)
        except ValueError as exc:
            self.notify(str(exc), True)
            self.focus = "target"
            return
        try:
            outdir = new_outdir(opts.target, self.dest)
        except (OSError, RuntimeError) as exc:
            self.notify(f"gagal membuat folder run: {exc}", True)
            return
        argv = build_scan_argv(self.engine, opts, outdir)
        kwargs = {
            "stdout": subprocess.PIPE, "stderr": subprocess.STDOUT,
            "text": True, "bufsize": 1, "errors": "replace",
            "cwd": str(outdir.parent),
        }
        if os.name == "posix":
            kwargs["start_new_session"] = True
        try:
            proc = subprocess.Popen(argv, **kwargs)
        except OSError as exc:
            self.notify(f"gagal menjalankan engine: {exc}", True)
            return
        run = RunState(argv=argv, outdir=outdir, started=time.time(), proc=proc)
        self.run = run
        self.result = None
        self.parsed = False
        self.running = True
        self.started_at = time.time()
        self.finished_at = 0.0
        self.console_off = 0
        self.follow = True
        self.find_sel = 0
        self.find_scroll = 0
        self.scroll = {"chains": 0, "recon": 0, "files": 0}
        self.tab = "console"
        self.tab_index = 1
        self.notify(f"scan dimulai untuk {opts.target}")
        try:
            (outdir / "run.json").write_text(
                json.dumps({"id": outdir.name, "target": opts.target,
                            "started_at": run.started,
                            "argv": argv[2:]}),
                encoding="utf-8")
        except OSError:
            pass
        threading.Thread(target=self._pump, args=(run, proc),
                         daemon=True).start()

    def _pump(self, run: RunState, proc: subprocess.Popen) -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            run.add(line)
        code = proc.wait()
        run.code = code
        run.done = True
        if code != 0 and not run.error:
            reason = ""
            for line in reversed(run.snapshot()):
                stripped = line.strip()
                if stripped.startswith("error:"):
                    reason = stripped[len("error:"):].strip()
                    break
            run.error = (f"{reason} (kode {code})" if reason
                         else f"engine keluar dengan kode {code}")

    def stop(self) -> None:
        if not self.run or self.run.done:
            self.notify("tidak ada scan yang berjalan")
            return
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(self.run.proc.pid), signal.SIGTERM)
            else:
                self.run.proc.terminate()
            self.notify("permintaan stop dikirim")
        except (OSError, AttributeError, ProcessLookupError):
            self.notify("gagal menghentikan proses", True)

    def poll(self) -> None:
        run = self.run
        if not run:
            return
        if run.done and not self.parsed:
            self.parsed = True
            self.running = False
            self.finished_at = time.time()
            try:
                self.result = read_result(run.outdir)
            except OSError as exc:
                self.notify(f"gagal membaca hasil: {exc}", True)
            if run.code == 0:
                self.tab = "summary"
                self.tab_index = 0
                write_disclosure(run.outdir)
                self.notify(f"scan selesai: {short_path(run.outdir)}")
            else:
                self.tab = "console"
                self.tab_index = 1
                self.notify(run.error or f"scan berhenti (kode {run.code})", True)

    def progress(self) -> float | None:
        run = self.run
        if not run:
            return None
        step_total = None
        step_now = None
        for line in reversed(run.snapshot()[-80:]):
            match = re.search(r"\[(\d+)/(\d+)\]", line)
            if match:
                step_now, step_total = int(match.group(1)), int(match.group(2))
                break
        if step_now and step_total:
            return min(1.0, step_now / step_total)
        return None

    def run_doctor(self) -> None:
        if self.doctor_proc and self.doctor_proc.poll() is None:
            self.notify("doctor masih berjalan")
            return
        try:
            self.doctor_proc = subprocess.Popen(
                [sys.executable, str(self.engine), "doctor"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, errors="replace",
            )
        except OSError as exc:
            self.notify(f"doctor gagal: {exc}", True)
            return
        self.notify("doctor berjalan…")
        threading.Thread(target=self._collect_doctor, daemon=True).start()

    def _collect_doctor(self) -> None:
        proc = self.doctor_proc
        if not proc or proc.stdout is None:
            return
        try:
            text = proc.stdout.read() or "(tanpa output)"
        except OSError as exc:
            text = f"doctor error: {exc}"
        text = "\n".join(line for line in text.splitlines()
                         if not (len(line) > 400 and line.startswith("Use webwarden")))
        self.doctor_text = text
        self.overlay = ("doctor", "Doctor: DNS dan tool lokal",
                        text.strip())

    # -- keyboard --------------------------------------------------------
    def handle_key(self, key: str) -> None:
        if self.overlay:
            if key in ("esc", "q", "enter"):
                self.overlay = None
            elif key in ("down", "pgdn"):
                self.overlay_scroll += 3
            elif key in ("up", "pgup"):
                self.overlay_scroll = max(0, self.overlay_scroll - 3)
            return
        if self.editing:
            self._handle_edit(key)
            return
        if self.advanced_open:
            self._handle_advanced(key)
            return
        if key == "q":
            if self.running:
                now = time.time()
                if now < self.quit_armed_until:
                    self.stop()
                    self.quit = True
                else:
                    self.quit_armed_until = now + 4
                    self.notify("scan berjalan: tekan q lagi untuk stop & keluar")
                return
            self.quit = True
            return
        if key in ("f1", "?"):
            self.overlay = ("help", "Bantuan", HELP_TEXT)
            return
        if key == "f5":
            self.start()
            return
        if key in ("f6", "ctrl-c"):
            self.stop()
            return
        if key == "f7":
            self.run_doctor()
            return
        if key == "f8":
            self.overlay = ("command", "Command engine (read-only)",
                            self.command())
            return
        if key == "f2":
            self.advanced_open = True
            self.adv_index = 0
            return
        if key == "f4":
            self.cycle_dest()
            return
        if key == "f9":
            self.tab_index = (self.tab_index + 1) % len(TABS)
            self.tab = TABS[self.tab_index][0]
            return
        if key in ("1", "2", "3", "4", "5", "6"):
            self.tab_index = int(key) - 1
            self.tab = TABS[self.tab_index][0]
            return
        if key == "o":
            self.open_report()
            return
        if key == "tab":
            idx = FOCUS_ORDER.index(self.focus) if self.focus in FOCUS_ORDER else 0
            self.focus = FOCUS_ORDER[(idx + 1) % len(FOCUS_ORDER)]
            if self.focus == "tabs":
                self.tab = TABS[self.tab_index][0]
            return
        if key == "btab":
            idx = FOCUS_ORDER.index(self.focus) if self.focus in FOCUS_ORDER else 0
            self.focus = FOCUS_ORDER[(idx - 1) % len(FOCUS_ORDER)]
            return
        if key == "enter":
            self._activate()
            return
        if key == "space":
            self._toggle_current()
            return
        if key in ("up", "down", "left", "right", "pgup", "pgdn", "home", "end"):
            self._navigate(key)
            return

    def _activate(self) -> None:
        focus = self.focus
        if focus in ("target", "scopes"):
            self.begin_edit(focus)
        elif focus == "output":
            self.cycle_dest()
        elif focus == "presets":
            self.apply_preset(PRESET_ORDER[self.preset_index])
        elif focus == "modules":
            self._toggle_current()
        elif focus == "advanced":
            self.advanced_open = True
            self.adv_index = 0
        elif focus == "start":
            self.start()
        elif focus == "stop":
            self.stop()
        elif focus == "doctor":
            self.run_doctor()
        elif focus == "cmd":
            self.overlay = ("command", "Command engine (read-only)",
                            self.command())
        elif focus == "tabs":
            self.tab = TABS[self.tab_index][0]
            if self.tab == "findings" and self._findings():
                self.overlay = self.finding_detail(self.find_sel)

    def _toggle_current(self) -> None:
        if self.focus == "auth":
            self.authorized = not self.authorized
        elif self.focus == "output":
            self.cycle_dest()
        elif self.focus == "modules":
            key = MODULES[self.module_index][0]
            self.modules[key] = not self.modules[key]
        elif self.focus == "presets":
            self.apply_preset(PRESET_ORDER[self.preset_index])
        elif self.focus == "tabs":
            self.tab = TABS[self.tab_index][0]

    def _navigate(self, key: str) -> None:
        focus = self.focus
        if key in ("pgup", "pgdn"):
            step = -8 if key == "pgup" else 8
            if self.tab == "findings":
                self._scroll_findings(step)
            elif self.tab in self.scroll:
                self.scroll[self.tab] = max(0, self.scroll[self.tab] + step)
            return
        if focus == "presets":
            delta = -1 if key in ("left", "up") else 1
            self.preset_index = (self.preset_index + delta) % len(PRESET_ORDER)
        elif focus == "output" and key in ("left", "right"):
            self.set_dest("runs" if key == "left" else "downloads")
        elif focus == "modules":
            step = {"up": -2, "down": 2, "left": -1, "right": 1}.get(key, 0)
            self.module_index = (self.module_index + step) % len(MODULES)
        elif focus == "tabs" and key in ("left", "right"):
            delta = -1 if key == "left" else 1
            self.tab_index = (self.tab_index + delta) % len(TABS)
            self.tab = TABS[self.tab_index][0]
        elif self.tab == "findings" and key in ("up", "down", "home", "end"):
            count = len(self._findings())
            if key == "home":
                self._scroll_findings(-count)
            elif key == "end":
                self._scroll_findings(count)
            else:
                self._scroll_findings(-1 if key == "up" else 1)
        elif focus == "scopes" and key in ("up", "down"):
            self.focus = "target" if key == "up" else "auth"
        elif key in ("up", "down"):
            order = list(FOCUS_ORDER)
            delta = -1 if key == "up" else 1
            self.focus = order[(order.index(focus) + delta) % len(order)]

    def begin_edit(self, field_name: str) -> None:
        value = {
            "target": self.target,
            "scopes": self.scopes,
        }.get(field_name, "")
        self.editing = (field_name, list(value))
        self.edit_pos = len(value)

    def _handle_edit(self, key: str) -> None:
        assert self.editing
        field_name, buf = self.editing
        if key == "enter":
            text = "".join(buf).strip()
            if field_name == "target":
                self.target = text.lower()
            elif field_name == "scopes":
                self.scopes = text
            elif field_name == "<adv>":
                name = (self._adv_edit or (None,))[0]
                if name:
                    setattr(self, name, text)
            self.editing = None
            return
        if key == "esc":
            self.editing = None
            return
        if key == "backspace":
            if self.edit_pos > 0:
                del buf[self.edit_pos - 1]
                self.edit_pos -= 1
            return
        if key == "delete":
            if self.edit_pos < len(buf):
                del buf[self.edit_pos]
            return
        if key == "left":
            self.edit_pos = max(0, self.edit_pos - 1)
            return
        if key == "right":
            self.edit_pos = min(len(buf), self.edit_pos + 1)
            return
        if key == "home":
            self.edit_pos = 0
            return
        if key == "end":
            self.edit_pos = len(buf)
            return
        if key == "space":
            buf.insert(self.edit_pos, " ")
            self.edit_pos += 1
            return
        if len(key) == 1 and key.isprintable():
            buf.insert(self.edit_pos, key)
            self.edit_pos += 1

    ADV_FIELDS = (
        ("rate", "Rate req/s", "text"),
        ("threads", "Threads", "text"),
        ("timeout", "Timeout s", "text"),
        ("max_hosts", "Max hosts", "text"),
        ("max_requests", "Max requests", "text"),
        ("ports", "Ports", "text"),
        ("ai", "Audit AI", "cycle"),
        ("ai_model", "Model Ollama", "text"),
        ("recon_only", "Recon only", "toggle"),
        ("no_ports", "Skip port scan", "toggle"),
        ("no_brute", "Skip DNS brute", "toggle"),
        ("no_passive", "Skip crt.sh/subfinder", "toggle"),
        ("allow_intercepted", "Allow intercepted DNS", "toggle"),
    )

    def _handle_advanced(self, key: str) -> None:
        if key in ("esc", "f2"):
            self.advanced_open = False
            return
        if key in ("up", "down"):
            delta = -1 if key == "up" else 1
            self.adv_index = (self.adv_index + delta) % len(self.ADV_FIELDS)
            return
        if key == "tab":
            self.adv_index = (self.adv_index + 1) % len(self.ADV_FIELDS)
            return
        if key == "btab":
            self.adv_index = (self.adv_index - 1) % len(self.ADV_FIELDS)
            return
        name, _label, kind = self.ADV_FIELDS[self.adv_index]
        if key in ("enter", "space"):
            if kind == "toggle":
                setattr(self, name, not getattr(self, name))
            elif kind == "cycle":
                order = ("local", "off", "ollama")
                self.ai = order[(order.index(self.ai) + 1) % len(order)]
            else:
                value = getattr(self, name)
                self._adv_edit = (name, list(value))
                self.editing = ("<adv>", list(value))
                self.edit_pos = len(value)

    def _scroll_findings(self, delta: int) -> None:
        findings = self._findings()
        if not findings:
            return
        self.find_sel = max(0, min(len(findings) - 1, self.find_sel + delta))
        if self.find_sel < self.find_scroll:
            self.find_scroll = self.find_sel
        if self.find_sel >= self.find_scroll + 12:
            self.find_scroll = self.find_sel - 11

    def _findings(self) -> list[dict]:
        scan = self.result.get("scan") if self.result else None
        return (scan or {}).get("findings") or []

    def finding_detail(self, index: int) -> tuple[str, str, str] | None:
        findings = self._findings()
        if not 0 <= index < len(findings):
            return None
        f = findings[index]
        lines = [
            f"URL           {f.get('url','')}",
            f"Host          {f.get('host','')}",
            f"Category      {f.get('category','')}",
            f"Confidence    {f.get('confidence','')}",
            "Verified      " + ("yes" if f.get("verified") else "no (manual)"),
            f"Reproductions {f.get('reproductions', 0)}"
            + ("  (unstable)" if f.get("stable") is False else ""),
        ]
        if f.get("decoy_suspected"):
            lines.append(f"Decoy         {f.get('decoy_reason') or 'marker found'}")
        cves = f.get("cves") or []
        if cves:
            lines.append("CVEs          " + ", ".join(
                f"{c.get('id','')} ({c.get('status','candidate')})" for c in cves))
        if f.get("chain_ids"):
            lines.append("Chains        " + ", ".join(f["chain_ids"]))
        lines += ["", "Description", f.get("description") or "-",
                  "", "Remediation", f.get("remediation") or "-"]
        if f.get("evidence"):
            lines += ["", "Evidence", str(f["evidence"])[:1500]]
        if f.get("verification"):
            lines += ["", "Verification", str(f["verification"])[:1200]]
        poc = f.get("poc") or []
        if poc:
            lines += ["", "PoC (read-only, not executed)"]
            lines += ["  " + cmd for cmd in poc]
        title = f"{f.get('title','finding')}  [{f.get('severity','')}]"
        return ("finding", title, "\n".join(lines))

    def open_report(self) -> None:
        if self.demo:
            self.notify("mode demo: tidak ada report nyata di disk", True)
            return
        outdir = self.run.outdir if self.run else None
        report = outdir / "report.html" if outdir else None
        if not report or not report.is_file():
            self.notify("report.html belum ada; jalankan scan dulu", True)
            return
        if open_path(report):
            win = windows_path(report)
            self.notify(f"membuka report.html: {win}" if win
                        else "membuka report.html di browser")
        else:
            self.notify(f"buka manual: {windows_path(report) or report}", True)


HELP_TEXT = """\
F1   bantuan ini          F5   mulai scan
F6   stop scan            F7   doctor DNS/tool
F8   command engine       F9   tab berikutnya
F2   pengaturan lanjutan  F4   ganti folder output
Tab  pindah fokus         1-6  pilih tab
Enter edit / aktifkan     Space pilih modul / toggle izin
↑↓←→ navigasi             PgUp/PgDn scroll kanan
↑↓ di Temuan pilih baris  Home/End awal/akhir
o    buka report.html     q    keluar

Tombol F1-F12 berfungsi di Linux, WSL, Windows Terminal
dan conhost. Mouse: klik tombol/modul/tab, scroll roda.

OUTPUT (OUT, di panel kiri; klik atau F4)
KALI ~      simpan ke ~/.datz/runs di terminal Kali
DOWNLOAD    simpan ke folder Downloads laptop
            (C:\\Users\\<user>\\Downloads\\datz-runs)
Pilihan terakhir disimpan di ~/.datz/config.json. Setiap run
punya folder sendiri berisi report.md, report.html, scan.json,
audit.md, findings.json, poc.sh dan evidence/.

SISTEM
Jam + tanggal ada di header. Bar bawah menampilkan CPU
(sparkline 10 detik), RAM, baterai, cuaca, dan uptime.
Sensor lokal read-only; yang gagal dibaca tampil "n/a".
Cuaca hanya widget UI ke wttr.in (cache ~/.datz/weather.json,
TTL 15 menit) dan tidak pernah memakai target scan. Matikan
dengan --no-weather atau DATZ_NO_WEATHER=1.

ANIMASI
Boot singkat (~1 detik) saat masuk; tombol apa saja
melewatinya (--no-boot untuk langsung masuk). Di dalam UI:
grafik VU berjalan di rail tab, meter risiko dan severity,
kursor berkedip, spinner scan, dan sparkline CPU.

UI
Tema biru malam: header gradien dengan tile DATZ, kartu
KONFIGURASI di kiri, rail tab + chip status di kanan, bar
keycap di bawah, dan bar sistem (CPU/RAM/baterai/cuaca/
uptime) di baris terakhir. Semua warna 256-colour; tetap
terbaca di terminal 256 warna (xterm, gnome-terminal,
Windows Terminal, conhost).

KALAU DASHBOARD LANGSUNG KELUAR
datz.py menulis alasan keluar ke stderr dan mencatat log di
~/.datz/datz.log. Jalankan "python3 datz.py --diagnose" untuk
melihat status TTY, ukuran terminal, TERM, engine, dan sensor.

MODUL (semua read-only, GET/HEAD saja)
Injection    SQLi, SSTI, XSS, LFI, SSRF, CRLF: satu parameter,
             signature benign, harus absen di baseline dan
             terulang dua kali.
Backdoors    daftar path web shell tetap + signature dikenal;
             tidak pernah mengirim parameter perintah.
Bypass       variasi path/header 401/403 tetap; tidak menyerang
             autentikasi.
robots.txt   reachability GET-only dari Disallow path.
Secrets      HTML/JS yang sudah tersaji; tidak divalidasi,
             tidak di-replay, nilai diredaksi di report.
Bundles      drift HTML vs artefak, source map, versi library.
Takeover     CNAME menggantung; tidak mengklaim resource.
NVD CVE      kandidat versi, bukan CVE terkonfirmasi.
Nuclei       opt-in lewat F2/preset Full, exclude tag intrusif.

Preset: Cepat = bundles + secrets, Std = semua kecuali bypass/
robots/nuclei, Full = + bypass + robots, Recon = recon-only.
Hasil tersimpan di ~/.datz/runs/<stamp>-<target>/.
Scan hanya untuk domain milikmu atau dengan izin tertulis."""


def open_path(path: Path) -> bool:
    import shutil as _shutil
    candidates = []
    if "microsoft" in platform.release().lower() and _shutil.which("wslpath"):
        try:
            win = subprocess.run(["wslpath", "-w", str(path)],
                                 capture_output=True, text=True, timeout=5)
            if win.returncode == 0 and win.stdout.strip():
                if _shutil.which("cmd.exe"):
                    candidates.append(["cmd.exe", "/c", "start", "",
                                       win.stdout.strip()])
        except (OSError, subprocess.SubprocessError):
            pass
    if _shutil.which("xdg-open"):
        candidates.append(["xdg-open", str(path)])
    if _shutil.which("wslview"):
        candidates.append(["wslview", str(path)])
    for argv in candidates:
        try:
            subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            return True
        except OSError:
            continue
    return False


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

def draw(app: App, width: int, height: int, now: float | None = None) -> Screen:
    now = time.time() if now is None else now
    scr = Screen(width, height)
    scr.fill(0, 0, width, height, (TEXT, BG, False, False, False))
    if width < 72 or height < 20:
        msg = [
            "Terminal terlalu kecil untuk dashboard.",
            f"Ukuran sekarang {width}x{height}; minimal 72x20.",
            "Perbesar window lalu tekan apa saja.",
        ]
        for i, line in enumerate(msg):
            scr.put(2, 2 + i, clip(line, width - 4), (WARN, BG, True, False, False))
        return scr

    draw_header(scr, app, width, now)
    left_w = 46 if width >= 118 else 40 if width >= 98 else 34
    right_x = left_w
    right_w = width - left_w
    body_y = 1
    body_h = height - 3
    draw_left(scr, app, 0, body_y, left_w, body_h)
    draw_right(scr, app, right_x, body_y, right_w, body_h, now)
    draw_footer(scr, app, width, height, now)
    if app.overlay:
        draw_overlay(scr, app, width, height)
    elif app.advanced_open:
        draw_advanced(scr, app, width, height)
    app.regions = scr.regions
    return scr


def draw_header(scr: Screen, app: App, width: int, now: float) -> None:
    """Top chrome: gradient wordmark tile, breadcrumb, status pill, clock."""
    scr.fill(0, 0, width, 1, (TEXT, PANEL2, False, False, False))
    tile = " DATZ "
    for i, ch in enumerate(tile):
        scr.put(i, 0, ch, (INK, _stop(GRAD, i, len(tile)), True, False, False))
    pos = len(tile)
    if width >= 76:
        scr.put(pos, 0, " ❯ ", (ACCENT2, PANEL2, True, False, False))
        pos += 3
        crumb = dict(TABS).get(app.tab, app.tab)
        scr.put(pos, 0, crumb, (ACCENT, PANEL2, True, False, False))
        pos += len(crumb)
        if width >= 104:
            tail = "  ·  web security console"
            scr.put(pos, 0, tail, (FAINT, PANEL2, False, False, False))
            pos += len(tail)

    clock = time.strftime("%H:%M:%S", time.localtime(now))
    if app.running:
        status = f"{'◐◓◑◒'[app.spinner % 4]} SCANNING"
        chip = (INK, WARN, True)
    elif app.demo:
        status, chip = "● DEMO", (INK, ACCENT2, True)
    elif app.result:
        status, chip = "● SELESAI", (INK, GOOD, True)
    else:
        status, chip = "○ READY", (ACCENT2, DEEP2, True)
    chips: list[tuple[str, int, int, bool]] = [
        (f" {status} ", *chip),
        (f" {clock} ", ACCENT2, PANEL2, True),
    ]
    if app.license_badge:
        chips.append((f" {app.license_badge} ", ACCENT, DEEP2, True))
    if width >= 100 and app.engine_version:
        label = app.engine_version.split()[-1]
        chips.append((f" v{label} ", FAINT, PANEL2, False))
    need = sum(len(text) for text, *_ in chips) + len(chips) - 1
    right_x = width - need
    if right_x > pos + 4:
        hairline(scr, pos + 1, 0, right_x - pos - 2, PANEL2, (NIGHT, PANEL2))
        cursor = right_x
        for text, fg, bg, bold in chips:
            scr.put(cursor, 0, text, (fg, bg, bold, False, False))
            cursor += len(text) + 1
    elif right_x > pos:
        text, fg, bg, bold = chips[0]
        scr.put(right_x, 0, text, (fg, bg, bold, False, False))


def _bar_colour(pct) -> int:
    if pct is None:
        return FAINT
    return GOOD if pct < 60 else WARN if pct < 85 else BAD


def system_segments(app: App) -> list[list[tuple[str, tuple]]]:
    """Compact CPU/RAM/battery/weather/uptime chunks for the status bar."""
    monitor = getattr(app, "monitor", None)
    if monitor is None:
        return []
    label = (DIM, PANEL2, True, False, False)
    faint = (FAINT, PANEL2, False, False, False)
    text = (TEXT, PANEL2, False, False, False)
    segments: list[list[tuple[str, tuple]]] = []

    if monitor.cpu is None:
        segments.append([("CPU", label), (" n/a", faint)])
    else:
        colour = _bar_colour(monitor.cpu)
        parts = [("CPU", label),
                 (f" {monitor.cpu:3.0f}% ", (colour, PANEL2, True, False, False)),
                 (pct_bar(monitor.cpu, 4), (colour, PANEL2, False, False, False))]
        spark = sparkline(monitor.history, 10)
        if spark:
            parts.extend([(" ", text), (spark, (ACCENT2, PANEL2, False, False, False))])
        segments.append(parts)

    if monitor.ram is None:
        segments.append([("RAM", label), (" n/a", faint)])
    else:
        colour = _bar_colour(monitor.ram)
        parts = [("RAM", label),
                 (f" {monitor.ram:3.0f}% ", (colour, PANEL2, True, False, False)),
                 (pct_bar(monitor.ram, 4), (colour, PANEL2, False, False, False))]
        if monitor.ram_used_gb is not None and monitor.ram_total_gb:
            parts.extend([(" ", text),
                          (f"{monitor.ram_used_gb:.1f}/{monitor.ram_total_gb:.1f}G",
                           faint)])
        segments.append(parts)

    if monitor.battery is None:
        segments.append([("BAT", label), (" n/a", faint)])
    else:
        colour = _bar_colour(monitor.battery)
        suffix = "+" if monitor.plugged else ""
        segments.append([("BAT", label),
                         (f" {monitor.battery:3.0f}%{suffix}",
                          (colour, PANEL2, True, False, False)),
                         (" ", text),
                         (pct_bar(monitor.battery, 4),
                          (colour, PANEL2, False, False, False))])

    if monitor.weather:
        cond = monitor.weather_cond or monitor.weather
        temperature = monitor.weather_temp or ""
        chunk = " ".join(part for part in (weather_icon(cond), temperature) if part)
        segments.append([("WX", label),
                         (" " + (chunk or monitor.weather[:20]),
                          (ACCENT2, PANEL2, False, False, False))])
    else:
        segments.append([("WX", label), (" n/a", faint)])

    if monitor.uptime is not None:
        segments.append([("UP", label),
                         (" " + format_uptime(monitor.uptime), text)])
    return segments


def draw_system_bar(scr: Screen, app: App, width: int, height: int,
                    now: float) -> None:
    y = height - 1
    scr.fill(0, y, width, 1, (TEXT, PANEL2, False, False, False))
    prompt = " ❯ root@datz "
    scr.put(0, y, prompt, (ACCENT2, DEEP2, True, False, False))
    clock = time.strftime("%H:%M:%S", time.localtime(now))
    right = f" {clock} "
    right_x = width - len(right)
    if right_x > len(prompt) + 1:
        scr.put(right_x, y, right, (INK, ACCENT, True, False, False))
        limit = right_x - 2
    else:
        limit = width
    x = len(prompt) + 1
    try:
        segments = system_segments(app)
    except Exception:
        segments = []
    first = True
    for parts in segments:
        need = sum(len(text) for text, _style in parts) + (0 if first else 3)
        if x + need > limit:
            continue
        if not first:
            scr.put(x, y, " · ", (EDGE, PANEL2, False, False, False))
            x += 3
        for text, style in parts:
            scr.put(x, y, text, style)
            x += len(text)
        first = False


FOOTER_HINTS = (
    ("F1", "Bantuan"), ("F5", "Mulai"), ("F6", "Stop"),
    ("F7", "Doctor"), ("F2", "Lanjut"), ("F4", "Output"),
    ("o", "Report"), ("q", "Keluar"),
)


def draw_footer(scr: Screen, app: App, width: int, height: int, now: float) -> None:
    y = height - 2
    scr.fill(0, y, width, 1, (TEXT, BG, False, False, False))
    msg = ""
    error = False
    if app.message:
        text, error, until = app.message
        if now < until:
            msg = text
        else:
            app.message = None
    if msg:
        band = 52 if error else DEEP2
        scr.fill(0, y, width, 1, (TEXT, band, False, False, False))
        scr.put(1, y, "✕" if error else "✓",
                (BAD if error else ACCENT2, band, True, False, False))
        scr.put(3, y, clip(msg, width - 4),
                (231 if error else TEXT, band, False, False, False))
    elif app.running:
        prog = app.progress()
        elapsed = int(now - app.started_at)
        scr.put(1, y, "◐", (WARN, BG, True, False, False))
        head = f" scan berjalan {elapsed}s "
        scr.put(3, y, head, (WARN, BG, True, False, False))
        x = 3 + len(head)
        if prog is not None and x + 16 < width:
            meter(scr, x, y, int(prog * 100), 12, WARN, BG, EDGE)
            pct = f" {int(prog * 100):>3}%"
            scr.put(x + 12, y, pct, (WARN, BG, True, False, False))
            x += 12 + len(pct)
        x += 2
        for key, label in (("F6", "stop"), ("q", "keluar")):
            need = len(key) + 3 + len(label) + 2
            if x + need > width - 1:
                break
            x += keycap(scr, x, y, key, label, BG) + 2
    else:
        x = 1
        for key, label in FOOTER_HINTS:
            need = len(key) + 3 + len(label) + 2
            if x + need > width - 1:
                break
            x += keycap(scr, x, y, key, label, BG,
                        accent=(key == "F5")) + 2
    draw_system_bar(scr, app, width, height, now)


def draw_left(scr: Screen, app: App, x: int, y: int, w: int, h: int) -> None:
    focused = app.focus
    scr.box(x, y, w, h, (EDGE, PANEL, False, False, False),
            title="⌁ KONFIGURASI",
            title_style=(ACCENT, PANEL, True, False, False))
    inner_x = x + 2
    inner_w = w - 4
    row = y + 1

    if w >= 38:
        adv = " F2 ▸ "
        ax = x + w - len(adv) - 2
        adv_focus = focused == "advanced"
        scr.put(ax, y, adv,
                (INK if adv_focus else ACCENT2,
                 ACCENT if adv_focus else DEEP2, True, False, False))
        scr.region("advanced", ax, y, len(adv), 1)

    def label(text: str, note: str = "") -> None:
        nonlocal row
        section(scr, inner_x, row, inner_w, text, ACCENT, PANEL, note)
        row += 1

    def field(name: str, glyph: str, value: str, placeholder: str) -> None:
        nonlocal row
        is_focus = focused == name
        editing = app.editing and app.editing[0] == name
        bg = FOCUS_BG if is_focus else TRACK
        scr.put(inner_x, row, "▏",
                (ACCENT if is_focus else EDGE, PANEL, False, False, False))
        scr.fill(inner_x + 1, row, inner_w - 1, 1, (TEXT, bg, False, False, False))
        scr.put(inner_x + 2, row, glyph,
                (ACCENT2 if is_focus else FAINT, bg, True, False, False))
        shown = value
        style = (TEXT, bg, False, False, False)
        if editing:
            buf = app.editing[1]
            shown = "".join(buf)
            pos = app.edit_pos
            shown = shown[:pos] + "▌" + shown[pos:]
        elif not shown:
            shown = placeholder
            style = (FAINT, bg, False, True, False)
        if not editing and is_focus and int(time.time() * 2) % 2 == 0:
            shown += "▌"
        avail = inner_w - 4
        if is_focus and not editing and avail > 10:
            hint = " ⏎ "
            hint_x = inner_x + inner_w - len(hint) - 1
            scr.put(hint_x, row, hint, (ACCENT2, DEEP2, True, False, False))
            avail = hint_x - (inner_x + 4) - 1
        scr.put(inner_x + 4, row, clip(shown, avail), style)
        scr.region(name, inner_x, row, inner_w, 1)
        row += 1

    label("TARGET", "wajib")
    field("target", "›", app.target, "example.com")
    label("SCOPE", "opsional")
    field("scopes", "＋", app.scopes, "*.example.com, api.example.net")
    row += 1

    auth_focus = focused == "auth"
    checked = app.authorized
    if checked:
        bg = 28 if auth_focus else 22
        fg = 231
    else:
        bg = 88 if auth_focus else 52
        fg = 231
    scr.fill(inner_x, row, inner_w, 1, (fg, bg, False, False, False))
    scr.put(inner_x + 1, row, "[✓]" if checked else "[ ]",
            (GOOD if checked else WARN, bg, True, False, False))
    scr.put(inner_x + 5, row, clip("Pemilik / izin tertulis", inner_w - 6),
            (fg, bg, not checked, False, False))
    scr.region("auth", inner_x, row, inner_w, 1)
    row += 2

    prefix = "OUT "
    scr.put(inner_x, row, prefix, (DIM, PANEL, True, False, False))
    seg_w = max(8, (inner_w - len(prefix) - 1) // 2)
    bx = inner_x + len(prefix)
    scr.fill(bx, row, inner_w - len(prefix), 1, (DIM, PANEL2, False, False, False))
    for key, name, _hint in OUTPUT_CHOICES:
        active = app.dest == key
        focus_here = focused == "output"
        text = clip(("● " if active else "○ ") + name, seg_w - 1)
        pad = seg_w - len(text) - 1
        if active:
            fg, bg = INK, ACCENT
        elif focus_here:
            fg, bg = ACCENT2, FOCUS_BG
        else:
            fg, bg = DIM, PANEL2
        scr.put(bx, row, " " + text + " " * pad + " ",
                (fg, bg, active, False, False))
        scr.region(f"out:{key}", bx, row, seg_w, 1)
        bx += seg_w + 1
    row += 1

    label("PRESET")
    btn_w = max(6, (inner_w - 3) // 4)
    scr.fill(inner_x, row, min(inner_w, btn_w * 4 + 3), 1,
             (DIM, PANEL2, False, False, False))
    bx = inner_x
    for idx, key in enumerate(PRESET_ORDER):
        active = app.preset == key
        focus_here = focused == "presets" and app.preset_index == idx
        fg = INK if active else DIM
        bg = ACCENT if active else PANEL2
        if focus_here:
            fg, bg = (INK, ACCENT2) if active else (ACCENT2, FOCUS_BG)
        text = PRESETS[key]["label"]
        if len(text) > btn_w - 1:
            text = PRESET_SHORT[key]
        text = clip(text, btn_w - 1)
        pad = btn_w - len(text) - 1
        scr.put(bx, row, " " + text + " " * pad, (fg, bg, active, False, False))
        scr.region(f"preset:{key}", bx, row, btn_w, 1)
        bx += btn_w + 1
    row += 1

    on = sum(1 for value in app.modules.values() if value)
    label("MODUL", f"{on}/{len(MODULES)}")
    avail = h - (row - y) - 4
    col_w = (inner_w - 1) // 2
    per_col = 5 if avail >= 5 else max(1, avail)
    for idx, (key, name, _desc) in enumerate(MODULES):
        col = idx // per_col
        line_idx = idx % per_col
        if col > 1:
            break
        mx = inner_x + col * (col_w + 1)
        my = row + line_idx
        if my >= y + h - 4:
            break
        checked = app.modules[key]
        focus_here = focused == "modules" and app.module_index == idx
        bg = PANEL2 if focus_here else PANEL
        fg = TEXT if checked else FAINT
        scr.put(mx, my, " " * (col_w - 1), (fg, bg, False, False, False))
        scr.put(mx, my, " " + ("✓" if checked else "·") + " ",
                (ACCENT2 if checked else EDGE, bg, True, False, False))
        scr.put(mx + 3, my, clip(name, col_w - 4), (fg, bg, checked, False, False))
        scr.region(f"mod:{key}", mx, my, col_w - 1, 1)
    row += per_col + 1

    button_y = y + h - 4
    if h >= 26 and button_y - row >= 8:
        section(scr, inner_x, row, inner_w, "KONTRAK", ACCENT, PANEL, "read-only")
        row += 1
        for glyph, text, hue in (
                ("✓", "GET/HEAD saja · tanpa write", GOOD),
                ("✓", "tanpa login · tanpa replay", GOOD),
                ("◆", "batas: domain milikmu", ACCENT2)):
            scr.put(inner_x, row, glyph, (hue, PANEL, True, False, False))
            scr.put(inner_x + 2, row, clip(text, inner_w - 2),
                    (FAINT, PANEL, False, False, False))
            row += 1
        row += 1

    info_y = row + 1
    if button_y - info_y >= 3:
        section(scr, inner_x, info_y, inner_w, "STATUS", ACCENT, PANEL)
        info_y += 1
        if app.running:
            prog = app.progress()
            state = "SCAN BERJALAN" + (f" {int(prog * 100)}%" if prog is not None else "")
            state_fg, state_bg = INK, WARN
        elif app.result:
            state, state_fg, state_bg = "SELESAI", INK, GOOD
        else:
            state, state_fg, state_bg = "SIAP", ACCENT2, DEEP2
        pill(scr, inner_x, info_y, "● " + state, state_fg, state_bg)
        info_y += 1
        findings = app._findings()
        if findings:
            verified = sum(1 for f in findings if f.get("verified"))
            line = f"{len(findings)} temuan · {verified} verified"
        else:
            line = "belum ada temuan"
        audit = (app.result or {}).get("audit") or {}
        if audit.get("risk_score") is not None:
            line += f" · risk {audit.get('risk_score')}"
        scr.put(inner_x, info_y, clip(line, inner_w), (TEXT, PANEL, False, False, False))
        info_y += 1
        if info_y < button_y - 1:
            if app.run:
                where = short_path(app.run.outdir)
            else:
                root = RUNS_DIR if app.dest == "runs" else downloads_root()
                where = (("out " + short_path(root)) if root
                         else "Downloads tidak ditemukan")
            scr.put(inner_x, info_y, clip(where, inner_w),
                    (FAINT, PANEL, False, False, False))

    start_focus = focused == "start"
    if app.running:
        prog = app.progress()
        start_text = "◐ SCAN BERJALAN"
        if prog is not None:
            start_text += f" {int(prog * 100)}%"
        start_bg, key = WARN, "F6"
    elif app.demo:
        start_text = "▶ DEMO MODE"
        start_bg = ACCENT2 if start_focus else ACCENT
        key = "F5"
    else:
        start_text = "▶ MULAI SCAN"
        start_bg = ACCENT2 if start_focus else ACCENT
        key = "F5"
    scr.put(inner_x, button_y, " " * inner_w, (INK, start_bg, True, False, False))
    scr.put(inner_x + 2, button_y, clip(start_text, inner_w - 9),
            (INK, start_bg, True, False, False))
    cap = f" {key} "
    if inner_w > len(cap) + 12:
        scr.put(inner_x + inner_w - len(cap), button_y, cap,
                (ACCENT2 if start_bg == ACCENT else INK, DEEP2, True, False, False))
    scr.region("start", inner_x, button_y, inner_w, 1)

    row2 = button_y + 1
    third = (inner_w - 2) // 3
    items = (("stop", "■ STOP", BAD), ("doctor", "DIAG", ACCENT2),
             ("cmd", "CMD", ACCENT2))
    bx = inner_x
    for name, text, hue in items:
        focus_here = focused == name
        bg = FOCUS_BG if focus_here else PANEL2
        fg = hue if (focus_here or name == "stop") else TEXT
        if name == "stop" and app.running:
            bg, fg = 52, 231
        scr.put(bx, row2, " " + text.ljust(third - 2),
                (fg, bg, focus_here, False, False))
        scr.region(name, bx, row2, third, 1)
        bx += third + 1


def draw_right(scr: Screen, app: App, x: int, y: int, w: int, h: int,
               now: float) -> None:
    scr.box(x, y, w, h, (EDGE, PANEL, False, False, False))
    tab_x = x + 1
    tab_y = y + 1
    tab_w = w - 2
    counts = {
        "findings": len(app._findings()),
        "chains": len(((app.result or {}).get("scan") or {})
                      .get("recon", {}).get("chains", {}).get("items", [])),
    }
    scr.fill(tab_x, tab_y, tab_w, 1, (DIM, PANEL2, False, False, False))
    seg = max(4, tab_w // len(TABS))
    room = seg - 2
    for idx, (key, label) in enumerate(TABS):
        active = app.tab == key
        focus_here = app.focus == "tabs" and app.tab_index == idx
        numbered = f"{idx + 1} {label}"
        short = f"{idx + 1} {TAB_SHORT[key]}"
        options = [numbered, short, f"{idx + 1} {TAB_SHORT[key][:3]}",
                   str(idx + 1)]
        text = next((opt for opt in options if len(opt) <= room), str(idx + 1))
        seg_w = seg if idx < len(TABS) - 1 else tab_w - seg * (len(TABS) - 1)
        if active:
            fg, bg = INK, ACCENT
        elif focus_here:
            fg, bg = ACCENT2, FOCUS_BG
        else:
            fg, bg = DIM, PANEL2
        pad = max(0, seg_w - len(text))
        left = pad // 2
        line = " " * left + text + " " * (seg_w - len(text) - left)
        scr.put(tab_x + idx * seg, tab_y, line,
                (fg, bg, active or focus_here, False, False))
        scr.region(f"tab:{key}", tab_x + idx * seg, tab_y, seg_w, 1)

    strip_y = tab_y + 1
    scr.fill(tab_x, strip_y, tab_w, 1, (TEXT, PANEL2, False, False, False))
    scr.put(tab_x + 1, strip_y, "❯", (ACCENT2, PANEL2, True, False, False))
    name = dict(TABS)[app.tab].upper()
    scr.put(tab_x + 3, strip_y, name, (TEXT, PANEL2, True, False, False))
    used = 3 + len(name) + 1
    chips: list[tuple[str, int, int]] = []
    if app.running:
        chips.append(("◐ scan", INK, WARN))
    elif app.demo:
        chips.append(("◇ demo", ACCENT2, DEEP2))
    elif app.result:
        chips.append(("● live", GOOD, 22))
    else:
        chips.append(("○ idle", ACCENT2, DEEP2))
    if counts["findings"]:
        chips.append((f"{counts['findings']} temuan", ACCENT2, PANEL))
    if counts["chains"]:
        chips.append((f"{counts['chains']} chain", MED, PANEL))
    need = sum(len(text) + 2 for text, *_ in chips) + len(chips) - 1
    right_x = tab_x + tab_w - need
    if right_x > tab_x + used + 3:
        stream_w = min(right_x - (tab_x + used) - 2, 24)
        if stream_w >= 6:
            equalizer(scr, right_x - stream_w - 2, strip_y, stream_w, now,
                      app.spinner if app.running else 0)
        cursor = right_x
        for text, fg, bg in chips:
            scr.put(cursor, strip_y, f" {text} ", (fg, bg, True, False, False))
            cursor += len(text) + 3
    elif right_x > tab_x + used - 2:
        text, fg, bg = chips[0]
        scr.put(tab_x + tab_w - len(text) - 2, strip_y, f" {text} ",
                (fg, bg, True, False, False))

    area_x = x + 2
    area_y = y + 3
    area_w = w - 4
    area_h = h - 4
    scr.region("rightpane", area_x, area_y, area_w, area_h)
    if app.tab == "console":
        draw_console(scr, app, area_x, area_y, area_w, area_h)
    elif app.tab == "summary":
        draw_summary(scr, app, area_x, area_y, area_w, area_h)
    elif app.tab == "findings":
        draw_findings(scr, app, area_x, area_y, area_w, area_h)
    elif app.tab == "chains":
        draw_chains(scr, app, area_x, area_y, area_w, area_h)
    elif app.tab == "recon":
        draw_recon(scr, app, area_x, area_y, area_w, area_h)
    elif app.tab == "files":
        draw_files(scr, app, area_x, area_y, area_w, area_h)


LOGO = (
    "██████╗  █████╗ ████████╗███████╗",
    "██╔══██╗██╔══██╗╚══██╔══╝╚══███╔╝",
    "██║  ██║███████║   ██║     ███╔╝ ",
    "██║  ██║██╔══██║   ██║   ███████╗",
    "██████╔╝██║  ██║   ██║   ███████║",
    "╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝",
)
LOGO_SHADES = (ACCENT2, 45, ACCENT, 39, DEEP, DEEP2)


def _empty(scr: Screen, x: int, y: int, w: int, h: int, text: str) -> None:
    banner_w = max(len(line) for line in LOGO)
    tagline = "SINGLE-FILE // WEB SECURITY CONSOLE"
    cw = min(max(10, w - 4), 92)
    cx = x + max(1, (w - cw) // 2)
    wrapped = textwrap.wrap(text, cw)
    need = len(LOGO) + 4 + len(wrapped)
    if cw >= banner_w + 2 and h >= need:
        top = y + max(0, (h - need) // 2)
        logo_x = cx + (cw - banner_w) // 2
        for i, line in enumerate(LOGO):
            scr.put(logo_x, top + i, line,
                    (LOGO_SHADES[i], PANEL, False, False, False))
        scr.put(cx + max(0, (cw - len(tagline)) // 2), top + len(LOGO),
                clip(tagline, cw), (ACCENT2, PANEL, True, False, False))
        hairline(scr, cx + max(0, (cw - len(tagline)) // 2),
                 top + len(LOGO) + 1, min(cw, len(tagline)), PANEL)
        row = top + len(LOGO) + 3
        for i, line in enumerate(wrapped):
            if row + i >= y + h:
                break
            scr.put(cx, row + i, clip(line, cw),
                    (FAINT, PANEL, False, False, False))
        return
    pad = max(0, (h - 2) // 2)
    for i, line in enumerate(wrapped):
        scr.put(cx, y + pad + i, clip(line, cw),
                (FAINT, PANEL, False, False, False))


def wrapped_console(app: App, width: int) -> list[str]:
    lines = app.run.snapshot() if app.run else []
    key = (len(lines), width)
    if app._wrapped_cache and app._wrapped_cache[0] == len(lines) \
            and app._wrapped_cache[1] == width:
        return app._wrapped_cache[2]
    out: list[str] = []
    for raw in lines:
        if not raw:
            out.append("")
            continue
        out.extend(textwrap.wrap(raw, max(20, width - 2)) or [""])
    app._wrapped_cache = (len(lines), width, out)
    return out


def draw_console(scr: Screen, app: App, x: int, y: int, w: int, h: int) -> None:
    lines = wrapped_console(app, w)
    if not lines:
        _empty(scr, x, y, w, h,
               "Console kosong. Isi target, centang izin, lalu tekan F5 untuk "
               "mulai scan. Output engine muncul di sini secara live.")
        return
    if app.follow:
        app.console_off = 0
    start = max(0, len(lines) - h - app.console_off)
    for i in range(h):
        idx = start + i
        if idx >= len(lines):
            break
        line = lines[idx]
        low = line.lower()
        gutter = None
        if re.search(r"(^|\s)(error|blocked|fail|traceback)", low):
            style, gutter = (BAD, PANEL, False, False, False), BAD
        elif "warn" in low or "invalid" in low or "hint" in low:
            style, gutter = (WARN, PANEL, False, False, False), WARN
        elif re.match(r"\[\d+/\d+\]", low) or low.startswith("preflight"):
            style = (ACCENT2, PANEL, True, False, False)
        elif "verified" in low or "observed" in low or " ok" in low:
            style, gutter = (GOOD, PANEL, False, False, False), GOOD
        else:
            style = (TEXT, PANEL, False, False, False)
        if gutter is not None:
            scr.put(x, y + i, "▏", (gutter, PANEL, True, False, False))
        scr.put(x + 1, y + i, clip(line, w - 2), style)
    flag = "follow" if app.follow else f"+{app.console_off}"
    pill(scr, x + w - len(flag) - 2, y + h - 1, flag,
         ACCENT2 if app.follow else DIM, PANEL2)


def draw_system(scr: Screen, app: App, x: int, y: int, w: int, h: int) -> None:
    monitor = getattr(app, "monitor", None)
    row = y
    section(scr, x, row, w, "// SISTEM", ACCENT, PANEL)
    row += 1
    label = (DIM, PANEL, True, False, False)
    value = (TEXT, PANEL, False, False, False)
    faint = (FAINT, PANEL, False, False, False)

    def line(name: str, parts: list[tuple[str, tuple]]) -> None:
        nonlocal row
        if row >= y + h:
            return
        scr.put(x, row, f"{name:<7}", label)
        px = x + 8
        for text, style in parts:
            scr.put(px, row, text, style)
            px += len(text)
        row += 1

    host = " · ".join(part for part in (
        (monitor.host if monitor else ""),
        (monitor.os_name if monitor else ""),
    ) if part)
    line("HOST", [(clip(host, w - 9) or "n/a", value)])

    uptime = monitor.uptime if monitor else None
    line("UPTIME", [(format_uptime(uptime), value if uptime is not None else faint)])

    if monitor is None or monitor.cpu is None:
        line("CPU", [("n/a", faint)])
    else:
        colour = _bar_colour(monitor.cpu)
        parts = [(pct_bar(monitor.cpu, 6), (colour, PANEL, False, False, False)),
                 (f" {monitor.cpu:3.0f}%", (colour, PANEL, True, False, False))]
        spark = sparkline(monitor.history, 10)
        if spark:
            parts.extend([("  ", value),
                          (spark, (ACCENT2, PANEL, False, False, False))])
        line("CPU", parts)

    if monitor is None or monitor.ram is None:
        line("RAM", [("n/a", faint)])
    else:
        colour = _bar_colour(monitor.ram)
        parts = [(pct_bar(monitor.ram, 6), (colour, PANEL, False, False, False)),
                 (f" {monitor.ram:3.0f}%", (colour, PANEL, True, False, False))]
        if monitor.ram_used_gb is not None and monitor.ram_total_gb:
            parts.append((f"  {monitor.ram_used_gb:.1f}/{monitor.ram_total_gb:.1f} GB",
                          faint))
        line("RAM", parts)

    if monitor is None or monitor.battery is None:
        line("BAT", [("n/a", faint)])
    else:
        colour = _bar_colour(monitor.battery)
        parts = [(pct_bar(monitor.battery, 6), (colour, PANEL, False, False, False)),
                 (f" {monitor.battery:3.0f}%", (colour, PANEL, True, False, False))]
        if monitor.plugged is not None:
            parts.append((" AC" if monitor.plugged else " batere", faint))
        line("BAT", parts)

    if monitor is None or not monitor.weather:
        if monitor is not None and monitor.weather_source == "loading":
            line("CUACA", [("memuat…", faint)])
        else:
            line("CUACA", [("n/a", faint)])
    else:
        cond = monitor.weather_cond or monitor.weather
        head = " ".join(part for part in (
            weather_icon(cond), monitor.weather_cond or "",
            monitor.weather_temp or "") if part)
        tail = " · ".join(part for part in (
            monitor.weather_loc, monitor.weather_hum) if part)
        text = head + (f" · {tail}" if tail else "")
        line("CUACA", [(clip(text or monitor.weather, w - 9),
                        (ACCENT2, PANEL, False, False, False))])


def draw_summary(scr: Screen, app: App, x: int, y: int, w: int, h: int) -> None:
    if h >= 18:
        block_h = 7
        scr.put(x, y + h - block_h - 1, "╌" * max(0, w - 1),
                (EDGE, PANEL, False, False, False))
        draw_system(scr, app, x, y + h - block_h, w, block_h)
        h -= block_h + 1
    if not app.result:
        _empty(scr, x, y, w, h,
               "Belum ada hasil. Jalankan scan (F5) untuk melihat ringkasan "
               "risiko, severity, chain, dan lokasi report.")
        return
    scan = app.result.get("scan") or {}
    audit = app.result.get("audit") or {}
    findings = scan.get("findings") or []
    counts = {sev: 0 for sev in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        sev = finding.get("severity")
        if sev in counts:
            counts[sev] += 1
    score = int(audit.get("risk_score") or (scan.get("stats") or {}).get("risk_score") or 0)
    band = audit.get("risk_band") or (scan.get("stats") or {}).get("risk_band") or "-"
    verified = sum(1 for finding in findings if finding.get("verified"))
    chains = (scan.get("recon") or {}).get("chains") or {}
    stats = scan.get("stats") or {}

    row = y
    scr.put(x, row, "❯", (ACCENT2, PANEL, True, False, False))
    scr.put(x + 2, row, clip(str(scan.get("target", "-")), w - 12),
            (ACCENT, PANEL, True, False, False))
    if app.demo and w >= 40:
        pill(scr, x + w - 8, row, "DEMO", INK, ACCENT2)
    row += 1
    divider(scr, x, row, max(0, w - 1))
    row += 1

    colour = GOOD if score < 25 else WARN if score < 50 else BAD if score < 75 else CRIT
    scr.put(x, row, "RISK", (DIM, PANEL, True, False, False))
    level = f"{score}/100"
    scr.put(x + 6, row, level, (colour, PANEL, True, False, False))
    band_text = str(band).upper()
    band_x = x + w - len(band_text) - 2
    if band_text and band_text not in ("-", "NONE") \
            and band_x > x + 8 + len(level):
        pill(scr, band_x, row, band_text, INK, colour)
    row += 1
    meter(scr, x, row, score, max(6, w - 2), colour, PANEL)
    row += 2

    if row + 2 < y + h:
        section(scr, x, row, w, "SEVERITY", ACCENT, PANEL,
                f"{len(findings)} temuan")
        row += 1
        top = max(1, max(counts.values()))
        bar_w = max(6, min(24, w - 26))
        for sev in ("critical", "high", "medium", "low", "info"):
            count = counts[sev]
            scr.put(x, row, f"{sev.upper():<8}", (SEV_FG[sev], PANEL, True,
                                                 False, False))
            meter(scr, x + 9, row, 100.0 * count / top, bar_w,
                  SEV_FG[sev], PANEL)
            scr.put(x + 10 + bar_w, row, str(count), (TEXT, PANEL, True,
                                                     False, False))
            row += 1
        row += 1

    pairs = [
        ("verified", f"{verified}/{len(findings)}"),
        ("hosts", str(stats.get("live_hosts", 0))),
        ("subdomains", str(stats.get("subdomains", 0))),
        ("chains", f"{chains.get('total', 0)} ({chains.get('observed', 0)} obs)"),
        ("bypass", str(stats.get("bypasses", 0))),
        ("secrets", str(stats.get("secrets", 0))),
    ]
    per_row = 2 if w >= 48 else 1
    col_w = (w - 1) // per_row
    for i, (key, value) in enumerate(pairs):
        col = i % per_row
        line_idx = i // per_row
        px = x + col * col_w
        py = row + line_idx
        if py >= y + h - 3:
            break
        scr.put(px, py, key.upper(), (DIM, PANEL, False, False, False))
        value_x = px + col_w - 2 - len(value)
        if value_x > px + len(key) + 2:
            scr.put(px + len(key) + 1, py, "·" * (value_x - px - len(key) - 2),
                    (EDGE, PANEL, False, False, False))
        scr.put(value_x, py, clip(value, col_w - 2),
                (TEXT, PANEL, True, False, False))
    row += (len(pairs) + per_row - 1) // per_row + 1

    if row < y + h - 1:
        outdir = str(app.run.outdir) if app.run else "-"
        scr.put(x, row, "⌂", (ACCENT2, PANEL, True, False, False))
        scr.put(x + 2, row, clip(outdir, w - 3),
                (FAINT, PANEL, False, False, False))
        row += 1
    if row < y + h:
        keycap(scr, x, row, "o", "report", PANEL)
        x2 = x + 12
        for key, label in (("3", "temuan"), ("5", "recon")):
            need = len(key) + 3 + len(label) + 2
            if x2 + need > x + w:
                break
            x2 += keycap(scr, x2, row, key, label, PANEL) + 2


def draw_findings(scr: Screen, app: App, x: int, y: int, w: int, h: int) -> None:
    findings = app._findings()
    if not findings:
        _empty(scr, x, y, w, h,
               "Tidak ada finding (atau scan belum selesai). Temuan akan muncul "
               "di sini; klik baris atau Enter untuk detail dan PoC.")
        return
    narrow = w < 58
    scr.put(x, y, "SEV", (FAINT, PANEL, True, False, False))
    scr.put(x + 11, y, "TEMUAN", (FAINT, PANEL, True, False, False))
    if not narrow:
        scr.put(x + w - 5, y, "HOST", (FAINT, PANEL, True, False, False))
    hairline(scr, x, y + 1, max(0, w - 1), PANEL)
    top = y + 2
    visible = max(1, h - 3)
    if app.find_sel < app.find_scroll:
        app.find_scroll = app.find_sel
    if app.find_sel >= app.find_scroll + visible:
        app.find_scroll = app.find_sel - visible + 1
    title_x = x + 11
    host_w = 20
    if narrow:
        title_w = max(8, w - title_x - 4)
    else:
        title_w = max(8, (x + w - 2 - host_w) - title_x - 2)
    for i in range(visible):
        idx = app.find_scroll + i
        if idx >= len(findings):
            break
        f = findings[idx]
        sev = f.get("severity", "info")
        selected = idx == app.find_sel
        bg = PANEL2 if selected else PANEL
        row = top + i
        if selected:
            scr.fill(x, row, w - 1, 1, (TEXT, bg, False, False, False))
            scr.put(x, row, "▌", (ACCENT2, bg, True, False, False))
        hue = SEV_FG.get(sev, FAINT)
        scr.put(x + 1, row, "●", (hue, bg, True, False, False))
        scr.put(x + 3, row, f"{sev.upper():<8}", (hue, bg, True, False, False))
        title = clip(f.get("title", ""), title_w)
        scr.put(title_x, row, title, (TEXT, bg, selected, False, False))
        flags = []
        if f.get("verified"):
            flags.append("✓")
        if f.get("decoy_suspected"):
            flags.append("D")
        if narrow:
            flags_x = title_x + len(title) + 1
            if flags and flags_x < x + w - 1:
                scr.put(flags_x, row, "".join(flags),
                        (GOOD if "✓" in flags else WARN, bg, True, False, False))
        else:
            host = clip(f.get("host", ""), host_w)
            host_x = x + w - 2 - len(host)
            scr.put(host_x, row, host, (DIM, bg, False, False, False))
            if flags:
                scr.put(host_x - 2, row, "".join(flags)[:1],
                        (GOOD if "✓" in flags else WARN, bg, True, False, False))
        scr.region(f"find:{idx}", x, row, w, 1)
    counter = f"{app.find_sel + 1}/{len(findings)}"
    scr.put(x, y + h - 1, counter, (ACCENT2, PANEL, True, False, False))
    scr.put(x + len(counter) + 2, y + h - 1,
            clip("↑↓ pilih · Enter detail · PgUp/PgDn", w - len(counter) - 3),
            (FAINT, PANEL, False, False, False))


def draw_chains(scr: Screen, app: App, x: int, y: int, w: int, h: int) -> None:
    scan = (app.result or {}).get("scan") or {}
    items = (scan.get("recon") or {}).get("chains", {}).get("items") or []
    if not items:
        _empty(scr, x, y, w, h,
               "Belum ada chain. Chain dibangun hanya dari finding yang "
               "benar-benar diamati; tidak dieksekusi.")
        return
    blocks: list[list[tuple[str, tuple]]] = []
    for chain in items:
        block: list[tuple[str, tuple]] = []
        sev = str(chain.get("severity", "")).lower()
        block.append((clip("▎ " + str(chain.get("title", "chain")), w - 1),
                      (ACCENT, PANEL, True, False, False)))
        meta = (f"  ● {sev.upper()}   {chain.get('status','')}   "
                f"{chain.get('host','')}")
        block.append((clip(meta, w - 1),
                      (SEV_FG.get(sev, DIM), PANEL, False, False, False)))
        summary = chain.get("summary") or ""
        for line in textwrap.wrap(summary, max(20, w - 6)):
            block.append(("  " + line, (TEXT, PANEL, False, False, False)))
        links = chain.get("links") or []
        for position, link in enumerate(links, start=1):
            role = CHAIN_ROLE_ID.get(str(link.get("role")),
                                     str(link.get("role") or ""))
            connector = "  └─" if position == len(links) else "  ├─"
            repro = link.get("reproductions") or 0
            body = (f" {position} {role} · {link.get('title','')} "
                    f"[{link.get('severity','')}]")
            if repro:
                body += f" {repro}x"
            block.append((clip(connector + body, w - 1),
                          (250, PANEL, False, False, False)))
        impact = chain.get("impact") or ""
        if impact:
            for line in textwrap.wrap("dampak: " + impact, max(20, w - 6)):
                block.append(("  ↳ " + line, (MED, PANEL, False, False, False)))
        proof = chain.get("proof") or []
        if isinstance(proof, str):
            proof = [proof]
        for step in proof[:3]:
            for line in textwrap.wrap("bukti: " + str(step), max(20, w - 6)):
                block.append(("  ◇ " + line, (FAINT, PANEL, False, False, False)))
        limitations = chain.get("limitations") or ""
        if limitations:
            for line in textwrap.wrap("batas: " + limitations, max(20, w - 6)):
                block.append(("  ⚠ " + line, (FAINT, PANEL, False, False, False)))
        block.append(("", STYLE_DEFAULT))
        blocks.append(block)
    flat: list[tuple[str, tuple]] = []
    for block in blocks:
        flat.extend(block)
    off = min(app.scroll.get("chains", 0), max(0, len(flat) - h))
    for i in range(h):
        idx = off + i
        if idx >= len(flat):
            break
        text, style = flat[idx]
        scr.put(x, y + i, clip(text, w - 1), style)


def draw_recon(scr: Screen, app: App, x: int, y: int, w: int, h: int) -> None:
    scan = (app.result or {}).get("scan") or {}
    if not scan:
        _empty(scr, x, y, w, h,
               "Recon belum ada. Setelah scan, subdomain, host live, port, WAF/CDN "
               "fingerprint pasif, dan statistik muncul di sini.")
        return
    stats = scan.get("stats") or {}
    recon = scan.get("recon") or {}
    keys = [k for k in (
        "subdomains", "live_hosts", "open_ports", "urls", "findings",
        "verified", "cves", "cve_candidates", "secrets", "source_maps",
        "bundle_drift", "bypasses", "takeovers", "injection_findings",
    ) if k in stats]
    row = y
    section(scr, x, row, w, "METRIK", ACCENT, PANEL, f"{len(keys)} metrik")
    row += 1
    col_w = max(22, (w - 1) // 2)
    for i, key in enumerate(keys):
        cy = row + i // 2
        if cy >= y + h - 1:
            break
        cx = x + (i % 2) * col_w
        label = clip(key.replace("_", " ").upper(), col_w - 10)
        scr.put(cx, cy, label, (DIM, PANEL, False, False, False))
        value = clip(str(stats[key]), 6)
        scr.put(cx + col_w - 2 - len(value), cy, value,
                (ACCENT2, PANEL, True, False, False))
        if col_w - 3 - len(label) - len(value) > 2:
            scr.put(cx + len(label) + 1, cy, "·" * (col_w - 3 - len(label)
                                                    - len(value) - 1),
                    (EDGE, PANEL, False, False, False))
    row += (len(keys) + 1) // 2 + 1
    if row < y + h - 1:
        section(scr, x, row, w, "WAF / CDN", ACCENT, PANEL, "pasif")
        row += 1
        providers = ((recon.get("waf") or {}).get("providers") or [])
        if providers:
            for provider in providers:
                if row >= y + h:
                    break
                hosts = ", ".join(provider.get("hosts") or [])
                scr.put(x, row, "◆", (GOOD, PANEL, True, False, False))
                scr.put(x + 2, row, clip(str(provider.get("provider", "")), 18),
                        (GOOD, PANEL, True, False, False))
                scr.put(x + 21, row, clip(hosts, w - 21),
                        (FAINT, PANEL, False, False, False))
                row += 1
        else:
            scr.put(x, row, "tidak ada signature terdeteksi",
                    (FAINT, PANEL, False, False, False))


FILE_GLYPHS = (
    (".html", "◈"), (".json", "▤"), (".md", "▥"), (".sh", "⌘"),
    (".txt", "▦"), (".body", "◇"), (".headers", "◇"),
)


def file_glyph(path: str) -> str:
    low = path.lower()
    for suffix, glyph in FILE_GLYPHS:
        if low.endswith(suffix):
            return glyph
    return "▣"


def draw_files(scr: Screen, app: App, x: int, y: int, w: int, h: int) -> None:
    files = (app.result or {}).get("files") or []
    if not files:
        _empty(scr, x, y, w, h,
               "Belum ada file. report.html, report.md, scan.json, poc.sh dan "
               "evidence/ muncul di sini setelah scan.")
        return
    total = (app.result or {}).get("file_total") or len(files)
    off = min(app.scroll.get("files", 0), max(0, len(files) + 1 - h))
    for i in range(h - 1):
        idx = off + i
        if idx >= len(files):
            break
        item = files[idx]
        size = item["size"]
        human = (f"{size / 1048576:.1f} MB" if size > 1048576
                 else f"{size / 1024:.1f} KB" if size > 1024 else f"{size} B")
        scr.put(x, y + i, file_glyph(item["path"]), (ACCENT2, PANEL, True,
                                                    False, False))
        scr.put(x + 2, y + i, clip(item["path"], w - 14),
                (TEXT, PANEL, False, False, False))
        scr.put(x + w - 11, y + i, human.rjust(9), (DIM, PANEL, False, False,
                                                    False))
    extra = f" (+{total - len(files)})" if total > len(files) else ""
    scr.put(x, y + h - 1, clip(f"{len(files)} file · "
                               f"{app.run.outdir if app.run else ''}{extra}", w - 1),
            (FAINT, PANEL, False, False, False))


def draw_advanced(scr: Screen, app: App, width: int, height: int) -> None:
    bw = min(72, width - 8)
    bh = min(len(App.ADV_FIELDS) + 7, height - 4)
    bx = (width - bw) // 2
    by = (height - bh) // 2
    scr.box(bx, by, bw, bh, (EDGE, BG, False, False, False),
            title="▎ PENGATURAN LANJUTAN",
            title_style=(ACCENT, BG, True, False, False))
    section(scr, bx + 2, by + 1, bw - 4,
            "NAVIGASI" if not app.editing else "EDIT",
            ACCENT2 if app.editing else ACCENT, BG,
            "Esc batal" if app.editing else "Esc tutup")
    for i, (name, label, kind) in enumerate(App.ADV_FIELDS):
        row = by + 3 + i
        if row >= by + bh - 2:
            break
        focus_here = i == app.adv_index
        bg = FOCUS_BG if focus_here else BG
        if focus_here:
            scr.fill(bx + 2, row, bw - 4, 1, (TEXT, bg, False, False, False))
            scr.put(bx + 2, row, "▌", (ACCENT2, bg, True, False, False))
        if kind == "text":
            value = getattr(app, name)
            if app.editing and app._adv_edit and app._adv_edit[0] == name:
                buf = "".join(app.editing[1])
                pos = app.edit_pos
                shown = buf[:pos] + "▌" + buf[pos:]
                text = f"{label:<22} {shown}"
            else:
                text = f"{label:<22} [{value}]"
        elif kind == "cycle":
            value = getattr(app, name)
            text = f"{label:<22} ‹ {value} ›"
        else:
            value = getattr(app, name)
            text = f"{label:<22} [{'✓' if value else ' '}]"
        scr.put(bx + 4, row, clip(text, bw - 6),
                (TEXT if focus_here else FAINT, bg, focus_here, False, False))
    hint_y = by + bh - 2
    scr.put(bx + 2, hint_y,
            "↑↓ pilih · Enter/Space ubah" if not app.editing
            else "ketik nilai · Enter simpan · Esc batal",
            (DIM, BG, False, False, False))


def draw_overlay(scr: Screen, app: App, width: int, height: int) -> None:
    kind, title, body = app.overlay
    bw = min(94 if kind != "help" else 70, width - 6)
    inner_w = bw - 6
    lines: list[str] = []
    for raw in body.splitlines():
        if not raw:
            lines.append("")
            continue
        lines.extend(textwrap.wrap(raw, inner_w) or [""])
    bh = min(height - 4, len(lines) + 5)
    bx = (width - bw) // 2
    by = (height - bh) // 2
    scr.box(bx, by, bw, bh, (EDGE, BG, False, False, False),
            title=clip(title, bw - 10),
            title_style=(ACCENT, BG, True, False, False))
    hairline(scr, bx + 1, by + 1, bw - 2, BG, (NIGHT, BG))
    visible = bh - 5
    off = min(app.overlay_scroll, max(0, len(lines) - visible))
    if off != app.overlay_scroll:
        app.overlay_scroll = off
    for i in range(visible):
        idx = off + i
        if idx >= len(lines):
            break
        text = lines[idx]
        if text.startswith(("GET ", "POST ", "HEAD ", "curl ")):
            style = (ACCENT2, BG, False, False, False)
        elif text.startswith(("Remediation", "Verification", "Evidence",
                              "Description", "PoC")):
            style = (TEXT, BG, True, False, False)
        else:
            style = (TEXT, BG, False, False, False)
        scr.put(bx + 2, by + 2 + i, clip(text, bw - 4), style)
    footer_y = by + bh - 2
    scr.put(bx + 2, footer_y, "─" * max(0, bw - 4), (NIGHT, BG, False, False,
                                                    False))
    hint = "↑↓ scroll · Esc tutup"
    if kind == "finding":
        hint = "↑↓ scroll · Esc tutup · [o] buka report"
    elif len(lines) > visible:
        hint += f" · {off + visible}/{len(lines)}"
    scr.put(bx + 2, by + bh - 1, clip(hint, bw - 4),
            (DIM, BG, False, False, False))


# --------------------------------------------------------------------------
# terminal input
# --------------------------------------------------------------------------

CSI_KEYS = {
    "A": "up", "B": "down", "C": "right", "D": "left",
    "H": "home", "F": "end", "Z": "btab",
    "P": "f1", "Q": "f2", "R": "f3", "S": "f4",
}
TILDE_KEYS = {
    "1": "home", "2": "insert", "3": "delete", "4": "end",
    "5": "pgup", "6": "pgdn",
    "11": "f1", "12": "f2", "13": "f3", "14": "f4",
    "15": "f5", "17": "f6", "18": "f7", "19": "f8",
    "20": "f9", "21": "f10", "23": "f11", "24": "f12",
}
SS3_KEYS = {
    "A": "up", "B": "down", "C": "right", "D": "left",
    "H": "home", "F": "end",
    "P": "f1", "Q": "f2", "R": "f3", "S": "f4",
}
WIN_SCAN_KEYS = {
    "H": "up", "P": "down", "K": "left", "M": "right",
    "G": "home", "O": "end", "R": "insert", "S": "delete",
    "I": "pgup", "Q": "pgdn",
    ";": "f1", "<": "f2", "=": "f3", ">": "f4", "?": "f5", "@": "f6",
    "A": "f7", "B": "f8", "C": "f9", "D": "f10",
    "\x85": "f11", "\x86": "f12", "à": "f11", "å": "f12",
}
CONTROL_KEYS = {
    "\x03": "ctrl-c", "\r": "enter", "\n": "enter", "\t": "tab",
    "\x7f": "backspace", "\x08": "backspace", " ": "space", "\x1b": "esc",
}
INCOMPLETE_ESC = re.compile(r"\x1b(?:\[[0-9;?<]*|O)?")


def split_incomplete(text: str) -> tuple[str, str]:
    idx = text.rfind("\x1b")
    if idx < 0:
        return text, ""
    tail = text[idx:]
    if INCOMPLETE_ESC.fullmatch(tail):
        return text[:idx], tail
    return text, ""


def parse_events(text: str) -> list[tuple]:
    events: list[tuple] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch != "\x1b":
            if ch in CONTROL_KEYS:
                events.append(("key", CONTROL_KEYS[ch]))
            else:
                events.append(("key", ch))
            i += 1
            continue
        rest = text[i:]
        mouse = re.match(r"\x1b\[<(\d+);(\d+);(\d+)([Mm])", rest)
        if mouse:
            button = int(mouse.group(1))
            mx = int(mouse.group(2)) - 1
            my = int(mouse.group(3)) - 1
            action = "press" if mouse.group(4) == "M" else "release"
            events.append(("mouse", mx, my, button, action))
            i += mouse.end()
            continue
        seq = re.match(r"\x1b\[([0-9]*)(?:;([0-9]+))?([A-Za-z~])", rest)
        if seq:
            code, _mod, final = seq.group(1), seq.group(2), seq.group(3)
            name = ""
            if final == "~":
                name = TILDE_KEYS.get(code, "")
            elif final in CSI_KEYS:
                # F1-F4 may arrive as CSI P/Q/R/S; with an explicit code it is
                # also what Shift+F1..F4 send, which we accept as F1..F4.
                name = CSI_KEYS[final]
            if name:
                events.append(("key", name))
            i += seq.end()
            continue
        if rest.startswith("\x1bO") and len(rest) >= 3:
            name = SS3_KEYS.get(rest[2], "")
            if name:
                events.append(("key", name))
            i += 3
            continue
        events.append(("key", "esc"))
        i += 1
    return events


class Terminal:
    def __init__(self):
        self.fd = sys.stdin.fileno()
        self.old = None
        self.buf = ""
        self.buf_at = 0.0
        self.is_windows = os.name == "nt"
        self.vt_input = False
        self.old_mode = None
        self.kernel32 = None
        self.eof = False
        self.eof_reads = 0
        self.eof_at = None
        self.read_errors = 0

    def __enter__(self):
        if self.is_windows:
            self.vt_input = self._enable_windows_vt()
        else:
            import termios
            import tty
            self.termios = termios
            self.old = termios.tcgetattr(self.fd)
            tty.setcbreak(self.fd)
            signal.signal(signal.SIGWINCH, self._on_resize)
        self._write("\x1b[?1049h\x1b[?25l\x1b[?1000h\x1b[?1006h\x1b[2J")
        return self

    def __exit__(self, *exc):
        self._write("\x1b[?1006l\x1b[?1000l\x1b[?25h\x1b[?1049l")
        if self.old is not None:
            try:
                self.termios.tcsetattr(self.fd, self.termios.TCSADRAIN,
                                       self.old)
            except Exception:
                pass  # the terminal may already be gone (EIO)
        if self.is_windows and self.old_mode is not None and self.kernel32:
            try:
                handle = self.kernel32.GetStdHandle(-10)
                self.kernel32.SetConsoleMode(ctypes.c_void_p(handle),
                                             self.old_mode)
            except Exception:
                pass

    def _on_resize(self, *_args):
        pass

    def _write(self, text: str) -> None:
        try:
            os.write(sys.stdout.fileno(), text.encode("utf-8", "replace"))
        except OSError:
            pass

    def write(self, text: str) -> None:
        self._write(text)

    def size(self) -> tuple[int, int]:
        size = shutil.get_terminal_size((100, 30))
        return size.columns, size.lines

    def _enable_windows_vt(self) -> bool:
        """Put the Windows console into VT input mode so F-keys, arrows and
        SGR mouse arrive as the same escape sequences as on Linux."""
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.GetStdHandle.restype = ctypes.c_void_p
            handle = kernel32.GetStdHandle(-10)
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(ctypes.c_void_p(handle),
                                           ctypes.byref(mode)):
                return False
            self.old_mode = mode.value
            # processed/line/echo/quick-edit off, extended flags + VT input on
            new = (mode.value | 0x0080 | 0x0200) & ~(0x0001 | 0x0002 | 0x0004 | 0x0040)
            if not kernel32.SetConsoleMode(ctypes.c_void_p(handle), new):
                self.old_mode = None
                return False
            out = kernel32.GetStdHandle(-11)
            omode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(ctypes.c_void_p(out), ctypes.byref(omode)):
                kernel32.SetConsoleMode(ctypes.c_void_p(out), omode.value | 0x0004)
            self.kernel32 = kernel32
            return True
        except Exception:
            self.old_mode = None
            return False

    EOF_READS = 12
    EOF_GRACE = 0.3

    def _empty_read(self, now: float, hard: bool = False) -> None:
        """A zero-byte read is not a keypress. Some terminals report the
        descriptor readable and then hand back EOF; confirm it instead of
        treating it as 'q' so the dashboard cannot vanish silently."""
        if self.eof_at is None:
            self.eof_at = now
        self.eof_reads += 1
        if hard or (self.eof_reads >= self.EOF_READS
                    and now - self.eof_at >= self.EOF_GRACE):
            self.eof = True

    def events(self) -> list[tuple]:
        if self.is_windows:
            return self._events_windows()
        now = time.time()
        ready, _, _ = select.select([self.fd], [], [], 0)
        if ready:
            try:
                chunk = os.read(self.fd, 4096)
            except OSError:
                self.read_errors += 1
                self._empty_read(now, hard=self.read_errors >= 3)
                return []
            if not chunk:
                self._empty_read(now)
                return []
            self.eof_reads = 0
            self.eof_at = None
            self.read_errors = 0
            self.buf += chunk.decode("utf-8", "ignore")
            self.buf_at = now
        text, self.buf = split_incomplete(self.buf)
        if not text and self.buf and now - self.buf_at > 0.25:
            lone_esc = self.buf == "\x1b"
            self.buf = ""
            return [("key", "esc")] if lone_esc else []
        return parse_events(text)

    def _events_windows(self) -> list[tuple]:
        import msvcrt
        out: list[tuple] = []
        got = False
        while msvcrt.kbhit():
            ch = msvcrt.getwch()
            got = True
            if self.vt_input:
                self.buf += ch
            elif ch in ("\x00", "\xe0"):
                code = msvcrt.getwch()
                name = WIN_SCAN_KEYS.get(code, "")
                if name:
                    out.append(("key", name))
            elif ch == "\x1b":
                out.append(("key", "esc"))
            else:
                out.append(("key", CONTROL_KEYS.get(ch, ch)))
        now = time.time()
        if got:
            self.buf_at = now
        if self.vt_input:
            text, rest = split_incomplete(self.buf)
            self.buf = rest
            if not text and rest and now - self.buf_at > 0.25:
                self.buf = ""
                if rest == "\x1b":
                    out.append(("key", "esc"))
            else:
                out.extend(parse_events(text))
        return [ev for ev in out if ev[1]]


# --------------------------------------------------------------------------
# mouse handling
# --------------------------------------------------------------------------

def handle_mouse(app: App, x: int, y: int, button: int) -> None:
    if app.overlay:
        if button == 65:
            app.overlay_scroll += 2
        elif button == 64:
            app.overlay_scroll = max(0, app.overlay_scroll - 2)
        elif button == 0:
            app.overlay = None
        return
    if app.advanced_open:
        if button == 0:
            app.advanced_open = False
        return
    if button in (64, 65):
        if app.tab == "findings":
            app._scroll_findings(-3 if button == 64 else 3)
        elif app.tab in app.scroll:
            step = -3 if button == 64 else 3
            app.scroll[app.tab] = max(0, app.scroll[app.tab] + step)
        elif app.tab == "console":
            app.follow = False
            app.console_off = max(0, app.console_off + (3 if button == 64 else -3))
        return
    if button != 0:
        return
    target = None
    for name, rx, ry, rw, rh in reversed(app.regions):
        if rx <= x < rx + rw and ry <= y < ry + rh:
            target = name
            break
    if not target:
        return
    if target == "advanced":
        app.advanced_open = True
        app.adv_index = 0
    elif target.startswith("preset:"):
        app.apply_preset(target.split(":", 1)[1])
        app.focus = "presets"
    elif target.startswith("mod:"):
        key = target.split(":", 1)[1]
        app.modules[key] = not app.modules[key]
        app.focus = "modules"
        for i, (mk, _n, _d) in enumerate(MODULES):
            if mk == key:
                app.module_index = i
    elif target == "auth":
        app.authorized = not app.authorized
        app.focus = "auth"
    elif target.startswith("out:"):
        app.focus = "output"
        app.set_dest(target.split(":", 1)[1])
    elif target in ("target", "scopes"):
        app.focus = target
        app.begin_edit(target)
    elif target == "start":
        app.focus = "start"
        app.start()
    elif target == "stop":
        app.focus = "stop"
        app.stop()
    elif target == "doctor":
        app.focus = "doctor"
        app.run_doctor()
    elif target == "cmd":
        app.focus = "cmd"
        app.overlay = ("command", "Command engine (read-only)", app.command())
    elif target.startswith("tab:"):
        key = target.split(":", 1)[1]
        app.tab = key
        app.tab_index = [t[0] for t in TABS].index(key)
        app.focus = "tabs"
    elif target.startswith("find:"):
        idx = int(target.split(":", 1)[1])
        app.find_sel = idx
        detail = app.finding_detail(idx)
        if detail:
            app.overlay = detail
    elif target == "rightpane" and app.tab == "findings":
        pass


# --------------------------------------------------------------------------
# boot animation
# --------------------------------------------------------------------------

BOOT_STEPS = (
    ("payload engine", "sha256 1a377ae1… · 604 KB embedded"),
    ("terminal vt", "f1-f12 · mouse · alternate screen"),
    ("sensor host", "cpu · ram · baterai · uptime"),
    ("cuaca", "wttr.in · cache lokal · --no-weather"),
    ("modul read-only", "injeksi · backdoor · bypass · secrets"),
    ("batas izin", "GET/HEAD · tanpa login · tanpa write"),
    ("siap", "tekan F1 untuk bantuan"),
)


def boot_frame(app: App, width: int, height: int, step: int, total: int,
               now: float | None = None) -> Screen:
    now = time.time() if now is None else now
    scr = Screen(width, height)
    scr.fill(0, 0, width, height, (TEXT, BG, False, False, False))
    banner_w = max(len(line) for line in LOGO)
    block_w = max(banner_w + 2, min(72, width - 6))
    left = max(0, (width - block_w) // 2)
    top = max(1, (height - (len(LOGO) + 4 + total)) // 2)

    for row in (top - 1, top + len(LOGO) + 3):
        if 0 <= row < height:
            hairline(scr, left, row, block_w, BG, (NIGHT, BG))

    logo_x = left + max(0, (block_w - banner_w) // 2)
    for i, line in enumerate(LOGO):
        scr.put(logo_x, top + i, line,
                (LOGO_SHADES[i], BG, False, False, False))
    tagline = "SINGLE-FILE // WEB SECURITY CONSOLE"
    scr.put(max(0, (width - len(tagline)) // 2), top + len(LOGO), tagline,
            (ACCENT2, BG, True, False, False))

    bar_w = max(16, min(48, block_w - 16))
    bar_x = left + max(0, (block_w - bar_w - 8) // 2)
    bar_y = top + len(LOGO) + 2
    meter(scr, bar_x, bar_y, 100.0 * step / max(1, total), bar_w, ACCENT2,
          BG, TRACK)
    scr.put(bar_x + bar_w + 2, bar_y, f"{step:>2}/{total}",
            (DIM, BG, True, False, False))

    row = top + len(LOGO) + 4
    spinner = "◐◓◑◒"[int(now * 8) % 4]
    limit = left + block_w
    for idx, (name, detail) in enumerate(BOOT_STEPS):
        if row >= height - 2:
            break
        if idx < step:
            tag, colour = "[ ok ]", GOOD
        elif idx == step:
            tag, colour = f"[{spinner:^4}]", WARN
        else:
            tag, colour = "[    ]", FAINT
        scr.put(left, row, tag, (colour, BG, True, False, False))
        scr.put(left + 7, row, clip(name, block_w - 8),
                (TEXT if idx <= step else FAINT, BG, False, False, False))
        dx = left + 7 + len(name) + 2
        if idx < step and dx < limit - 1:
            scr.put(dx, row, clip(detail, limit - dx - 1),
                    (DIM, BG, False, False, False))
        row += 1

    scr.fill(0, height - 1, width, 1, (TEXT, BG, False, False, False))
    hint = "tekan tombol apa saja untuk lewati"
    hint_x = max(1, (width - len(hint)) // 2)
    scr.put(hint_x, height - 1, clip(hint, width - 2),
            (FAINT, BG, False, False, False))
    scr.put(max(0, width - 9), height - 1, f"v{APP_VERSION} ",
            (ACCENT, BG, False, False, False))
    return scr


def boot_sequence(term: Terminal, app: App,
                  step_seconds: float = 0.11) -> list[tuple]:
    """Play the entry animation; any key/mouse event skips it instantly."""
    try:
        width, height = term.size()
    except Exception:
        return []
    if width < 72 or height < 20:
        return []
    total = len(BOOT_STEPS)
    try:
        app.monitor.sample(time.time(), force=True)
    except Exception:
        pass
    for step in range(total + 1):
        if term.eof:
            return []
        now = time.time()
        try:
            if step == 0:
                term.write("\x1b[2J")
            term.write(boot_frame(app, width, height, step, total, now).render(True))
        except Exception:
            return []
        deadline = time.time() + max(0.05, step_seconds)
        while time.time() < deadline:
            try:
                events = term.events()
            except Exception:
                events = []
            if term.eof:
                return []
            if events:
                return events
            time.sleep(0.012)
    return []


# --------------------------------------------------------------------------
# TUI loop
# --------------------------------------------------------------------------

EOF_NOTICE = """\
datz: dashboard berhenti karena stdin terminal tertutup (EOF).
Ini bukan crash: UI tidak bisa membaca keyboard lagi.
Jalankan langsung di terminal Kali/WSL (bukan lewat pipe atau
tempelan multi-baris):

    python3 datz.py

Kalau keyboard tetap tidak terbaca, dashboard masih bisa
dirender sekali ke layar:

    python3 datz.py --snapshot --demo

Dan kirim hasil diagnosa ini:

    python3 datz.py --diagnose
"""


def final_message(text: str, first=None) -> bool:
    """Print after the alternate screen is gone, even if the TTY is dead.

    A closed terminal makes every write raise EIO; replacing the streams
    with /dev/null keeps Python's shutdown flush from turning the real exit
    code into 120.
    """
    wrote = False
    streams = ([first] if first is not None else []) + [sys.stderr, sys.stdout]
    for stream in streams:
        try:
            stream.write(text)
            stream.flush()
            wrote = True
            break
        except Exception:
            continue
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        try:
            stream.flush()
        except Exception:
            try:
                setattr(sys, name, open(os.devnull, "w"))
            except Exception:
                pass
    return wrote


def run_tui(engine: Path, version: str, demo: bool = False,
            weather: bool = True, boot: bool = True,
            dest: str | None = None, license_badge: str = "") -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("datz: dashboard butuh terminal interaktif (TTY).", file=sys.stderr)
        print("Gunakan --headless untuk scan di pipeline, atau --cli untuk "
              "meneruskan argumen ke engine.", file=sys.stderr)
        return 2
    try:
        locale.setlocale(locale.LC_ALL, "")
    except locale.Error:
        pass
    started = time.time()
    keys = 0
    reason = "quit"
    crash = ""
    app = None
    monitor = None
    try:
        try:
            monitor = SysMonitor(weather=weather)
        except Exception:
            monitor = SysMonitor(weather=False)
        app = App(engine, version + " (demo)" if demo else version, monitor)
        app.license_badge = license_badge
        saved = dest or load_config().get("output")
        if saved in [key for key, _label, _hint in OUTPUT_CHOICES]:
            app.dest = saved
        if demo:
            seed_demo(app, "summary")

        def dispatch(events: list[tuple]) -> None:
            nonlocal keys
            for event in events:
                if event[0] == "key":
                    keys += 1
                    app.handle_key(event[1])
                else:
                    _, mx, my, button, action = event
                    if action == "press":
                        handle_mouse(app, mx, my, button)

        with Terminal() as term:
            width, height = term.size()
            log_event(f"tui start {version} tty={width}x{height} "
                      f"out={app.dest} boot={boot} weather={weather} term="
                      f"{os.environ.get('TERM', '') or 'unset'}")
            if boot:
                dispatch(boot_sequence(term, app))
            while not app.quit:
                events = term.events()
                if term.eof:
                    reason = "eof"
                    break
                dispatch(events)
                app.poll()
                try:
                    monitor.sample(time.time())
                except Exception:
                    pass
                app.spinner = (app.spinner + 1) % 4
                width, height = term.size()
                screen = draw(app, width, height)
                term.write(screen.render(True))
                if app.quit:
                    break
                time.sleep(0.05)
    except KeyboardInterrupt:
        reason = "interrupt"
    except Exception:
        reason = "crash"
        crash = traceback.format_exc()
    finally:
        try:
            if monitor is not None:
                monitor.close()
        except Exception:
            pass
        try:
            if app is not None and app.run and not app.run.done:
                app.stop()
        except Exception:
            pass
    elapsed = time.time() - started
    log_event(f"tui end reason={reason} after {elapsed:.1f}s keys={keys}")
    if reason == "quit" and elapsed < 1.0 and keys <= 2:
        log_event("catatan: keluar sangat cepat; cek tombol nyasar "
                  "(q/esc) atau input tempelan di terminal")
    if reason in ("quit", "interrupt") and app is not None and app.run:
        outdir = app.run.outdir
        if outdir and (outdir / "scan.json").is_file():
            block = run_summary(outdir)
            if block:
                final_message("\n" + block + "\n", first=sys.stdout)
    if reason == "crash":
        log_event("tui crash\n" + crash)
        final_message(
            "datz: dashboard berhenti karena error tak terduga.\n"
            + crash.rstrip() + "\n"
            f"log: {LOG_PATH}\n"
        )
        return 1
    if reason == "eof":
        final_message(EOF_NOTICE + f"log: {LOG_PATH}\n")
        return 3
    return 0


# --------------------------------------------------------------------------
# terminal (non-TUI) modes
# --------------------------------------------------------------------------

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

CHAIN_ROLE_ID = {
    "precondition": "prasyarat",
    "exposure": "paparan",
    "injection": "injeksi",
    "execution": "eksekusi",
    "impact": "dampak",
    "excluded": "dikecualikan",
}


def find_run(which: str = "") -> Path | None:
    """Resolve a run directory from a path/argument, defaulting to the newest."""
    if which:
        path = Path(which).expanduser()
        if path.is_file():
            path = path.parent
        return path if (path / "scan.json").is_file() else None
    runs: list[Path] = []
    for root in run_roots():
        if not root.is_dir():
            continue
        runs += [item for item in root.iterdir()
                 if item.is_dir() and (item / "scan.json").is_file()]
    if not runs:
        return None
    return max(runs, key=lambda item: item.stat().st_mtime)


_WIN_CACHE: dict[str, str] = {}


def windows_path(path: Path) -> str:
    key = str(path)
    if key in _WIN_CACHE:
        return _WIN_CACHE[key]
    result = ""
    if shutil.which("wslpath") is not None:
        try:
            out = subprocess.run(["wslpath", "-w", key],
                                 capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            out = None
        if out is not None and out.returncode == 0:
            result = out.stdout.strip()
    _WIN_CACHE[key] = result
    return result


def short_path(path: Path) -> str:
    text = str(path)
    home = str(Path.home())
    if text.startswith(home):
        return "~" + text[len(home):]
    return windows_path(path) or text



def run_summary(outdir: Path) -> str:
    """Rebuild the end-of-scan block the engine prints, straight from disk."""
    try:
        scan = json.loads((outdir / "scan.json").read_text(
            encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return ""
    findings = scan.get("findings") or []
    stats = scan.get("stats") or {}
    audit = {}
    try:
        audit = json.loads((outdir / "audit.json").read_text(
            encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        pass
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for item in findings:
        sev = str(item.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    tally = ", ".join(f"{counts[sev]} {sev}" for sev in SEVERITY_ORDER
                      if counts[sev])
    lines = [
        f"{'target':<11} {scan.get('target', '?')}",
        f"{'run':<11} {outdir.name}",
        f"{'started':<11} {scan.get('started_at', '?')}",
        f"{'finished':<11} {scan.get('finished_at', '?')}",
        f"{'hosts':<11} {stats.get('live_hosts', 0)} live / "
        f"{stats.get('requests', 0)} requests",
        f"{'findings':<11} {len(findings)}" + (f" ({tally})" if tally else ""),
        f"{'chains':<11} {stats.get('chains_observed', 0)} observed / "
        f"{stats.get('chains_partial', 0)} partial / "
        f"{stats.get('chains_blocked', 0)} blocked",
    ]
    if audit:
        lines.append(f"{'risk':<11} {audit.get('risk_band', '?')} "
                     f"({audit.get('risk_score', '?')}/100)")
    for label, name in (("report", "report.md"), ("html", "report.html"),
                        ("audit", "audit.md"), ("findings", "findings.json"),
                        ("raw scan", "scan.json"), ("poc", "poc.sh")):
        path = outdir / name
        if path.is_file():
            lines.append(f"{label:<11} {path}")
    evidence = outdir / "evidence"
    if evidence.is_dir():
        lines.append(f"{'evidence':<11} {evidence} "
                     f"({len(list(evidence.iterdir()))} file)")
    if findings:
        order = {name: index for index, name in enumerate(SEVERITY_ORDER)}
        ranked = sorted(findings, key=lambda item: order.get(
            str(item.get("severity", "info")).lower(), len(SEVERITY_ORDER)))
        lines += ["", "top findings"]
        for item in ranked[:8]:
            mark = " (verified)" if item.get("verified") else ""
            lines.append(f"  [{str(item.get('severity', 'info')).upper():<8}] "
                         f"{item.get('title', '?')} - "
                         f"{item.get('url', '')}{mark}")
    scan_path = outdir / "scan.json"
    html = outdir / "report.html"
    confirmed, manual = verified_findings(scan)
    lines.append(f"{'access':<11} {len(confirmed)} kondisi terbukti / "
                 f"{len(manual)} perlu verifikasi manual")
    lines += chain_detail_lines(scan)
    lines.append(f"{'proof':<11} {STOP_LINE}")
    contacts = scan_contacts(scan)
    lines.append(f"{'contact':<11} " + (", ".join(contacts) if contacts else
                                        "tidak ada security.txt - pakai "
                                        "kanal resmi program"))
    draft = outdir / "disclosure.md"
    if draft.is_file():
        lines.append(f"{'disclosure':<11} {draft}")
    lines += [
        "",
        "review temuan yang perlu verifikasi manual sebelum submit",
        "",
        "next",
        f"  open report   {html}",
        f"  re-audit      python3 datz.py --cli audit {scan_path} --ai-audit local",
        f"  compare later python3 datz.py --cli diff {scan_path} <new>/scan.json",
        "  all options   python3 datz.py help scan",
    ]
    win = windows_path(outdir)
    if win:
        lines += [
            "",
            f"{'windows':<11} {win}",
            f'  open (windows) cmd.exe /c start "" "{windows_path(html) or win}"',
        ]
    return "\n".join(lines)


def report_run(which: str = "") -> int:
    outdir = find_run(which)
    if outdir is None:
        if which:
            print(f"error: run tidak ditemukan atau tanpa scan.json: {which}",
                  file=sys.stderr)
        else:
            print("belum ada run; jalankan scan dulu, misalnya:\n"
                  "  python3 datz.py --headless --target example.com "
                  "--i-am-authorized", file=sys.stderr)
        return 2
    write_disclosure(outdir)
    text = run_summary(outdir)
    if not text:
        print(f"error: tidak bisa membaca scan.json di {outdir}",
              file=sys.stderr)
        return 2
    print(text)
    return 0

STOP_LINE = (
    "GET/HEAD saja · tidak ada data yang dibuat, diubah, atau dihapus · "
    "pengujian berhenti di bukti pertama"
)

NOT_PERFORMED = (
    "Tidak ada request selain GET/HEAD.",
    "Tidak ada data yang dibuat, diubah, atau dihapus.",
    "Tidak ada login, brute force, upload, atau eksekusi perintah.",
    "Tidak ada token/sesi yang dipakai ulang, diambil, atau di-replay.",
    "Pengujian berhenti begitu kondisi terbukti (proof pertama).",
)


def scan_contacts(scan: dict) -> list[str]:
    recon = scan.get("recon") or {}
    entries = (recon.get("headers") or {}).get("security_txt") or {}
    contacts: set[str] = set()
    for info in entries.values():
        for contact in (info or {}).get("contacts") or []:
            text = str(contact).strip()
            if text:
                contacts.add(text)
    return sorted(contacts)


def verified_findings(scan: dict) -> tuple[list[dict], list[dict]]:
    findings = scan.get("findings") or []
    order = {name: index for index, name in enumerate(SEVERITY_ORDER)}
    ranked = sorted(findings, key=lambda item: order.get(
        str(item.get("severity", "info")).lower(), len(SEVERITY_ORDER)))
    confirmed = [item for item in ranked if item.get("verified")]
    manual = [item for item in ranked if not item.get("verified")]
    return confirmed, manual


def chain_detail_lines(scan: dict, limit: int = 6) -> list[str]:
    """Show every chain with its proof, or why no chain could be built."""
    items = (((scan.get("recon") or {}).get("chains") or {})
             .get("items") or [])
    lines = ["", "chains (exploit chain berbasis evidence - tidak dieksekusi)"]
    if not items:
        counts: dict[str, int] = {}
        for item in scan.get("findings") or []:
            key = str(item.get("category") or "other")
            counts[key] = counts.get(key, 0) + 1
        bahan = ", ".join(f"{count} {key}" for key, count in sorted(
            counts.items())) or "0 temuan"
        lines.append("  0 chain - butuh minimal dua temuan yang bisa "
                     "disambung di host yang sama")
        lines.append(f"  bahan scan: {bahan}")
        return lines
    for item in items[:limit]:
        status = str(item.get("status") or "partial").upper()
        severity = str(item.get("severity") or "").upper()
        lines.append(f"  [{status:<8}] {severity} - {item.get('title')}")
        if item.get("summary"):
            lines.append(f"      ringkas: {item['summary']}")
        for position, link in enumerate(item.get("links") or [], start=1):
            role = CHAIN_ROLE_ID.get(str(link.get("role")),
                                     str(link.get("role") or ""))
            reproduced = link.get("reproductions", 0)
            lines.append(
                f"      langkah {position} [{role}/{link.get('status', '')}] "
                f"{link.get('title', '')} ({reproduced}x reproduksi) "
                f"@ {link.get('host', '')}")
        if item.get("impact"):
            lines.append(f"      dampak bila dikonfirmasi: {item['impact']}")
        for step in (item.get("proof") or [])[:3]:
            lines.append(f"      bukti: {step}")
        if item.get("limitations"):
            lines.append(f"      batas: {item['limitations']}")
    if len(items) > limit:
        lines.append(f"  ... {len(items) - limit} chain lain di report.html")
    return lines


def disclosure_text(outdir: Path, scan: dict) -> str:
    findings = scan.get("findings") or []
    stats = scan.get("stats") or {}
    confirmed, manual = verified_findings(scan)
    counts: dict[str, int] = {}
    for item in findings:
        key = str(item.get("severity", "info")).lower()
        counts[key] = counts.get(key, 0) + 1
    tally = ", ".join(f"{counts[sev]} {sev}" for sev in SEVERITY_ORDER
                      if counts.get(sev)) or "0"
    contacts = scan_contacts(scan)
    lines = [
        f"# Laporan kerentanan - {scan.get('target', '?')}",
        "",
        f"Disusun: {time.strftime('%Y-%m-%d %H:%M:%S')} "
        "(otomatis oleh datz/webwarden, uji read-only)",
        f"Sasaran: {scan.get('target', '?')}",
        f"Run: {outdir.name}",
        f"Mulai/selesai: {scan.get('started_at', '?')} / "
        f"{scan.get('finished_at', '?')}",
        "",
        "## Ringkasan",
        f"- {len(findings)} temuan ({tally}); "
        f"{len(confirmed)} terverifikasi lewat reproduksi independen, "
        f"{len(manual)} perlu verifikasi manual.",
        f"- {stats.get('live_hosts', 0)} host hidup, "
        f"{stats.get('requests', 0)} request GET/HEAD.",
        "",
        "## Kondisi yang terbukti (read-only)",
    ]
    if confirmed:
        for index, item in enumerate(confirmed, start=1):
            repro = item.get("reproductions")
            extra = f", {repro}x direproduksi" if repro else ""
            lines.append(
                f"{index}. [{str(item.get('severity', 'info')).upper()}] "
                f"{item.get('title')} - {item.get('url')}{extra}")
    else:
        lines.append("- Tidak ada kondisi akses yang terbukti pada scan ini.")
    if manual:
        lines += ["", "## Perlu verifikasi manual (belum diklaim terbukti)"]
        for item in manual[:10]:
            lines.append(
                f"- [{str(item.get('severity', 'info')).upper()}] "
                f"{item.get('title')} - {item.get('url')}")
    lines += ["", "## Batas pengujian (yang sengaja tidak dilakukan)"]
    lines += [f"- {item}" for item in NOT_PERFORMED]
    lines += ["", "## Bukti"]
    for name in ("report.html", "report.md", "scan.json", "findings.json"):
        path = outdir / name
        if not path.is_file():
            continue
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            digest = "tidak terbaca"
        lines.append(f"- {name}  sha256 {digest}")
    evidence = outdir / "evidence"
    if evidence.is_dir():
        lines.append(f"- evidence/  {len(list(evidence.iterdir()))} file, "
                     "SHA-256 tercatat di findings.json")
    lines += ["", "## Kontak"]
    if contacts:
        lines += [f"- security.txt: {contact}" for contact in contacts]
    else:
        lines.append("- Tidak ada security.txt yang valid. Gunakan kanal "
                     "pelaporan resmi program (halaman security/contact).")
    lines += [
        "",
        "## Catatan",
        "- Semua request memakai GET/HEAD tanpa autentikasi.",
        "- Tidak ada perubahan data. Kalau ada yang perlu dirotasi, silakan "
        "balas lewat kanal aman.",
        "",
    ]
    return "\n".join(lines)


def write_disclosure(outdir: Path) -> Path | None:
    try:
        scan = json.loads((outdir / "scan.json").read_text(
            encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    try:
        target = outdir / "disclosure.md"
        target.write_text(disclosure_text(outdir, scan), encoding="utf-8")
        return target
    except OSError:
        return None


def disclosure_run(which: str = "") -> int:
    outdir = find_run(which)
    if outdir is None:
        print("error: run tidak ditemukan; jalankan scan dulu",
              file=sys.stderr)
        return 2
    path = write_disclosure(outdir)
    if path is None:
        print(f"error: tidak bisa menulis disclosure di {outdir}",
              file=sys.stderr)
        return 2
    print(path.read_text(encoding="utf-8"))
    print(f"disimpan: {path}")
    return 0


def _print_run_table() -> int:
    rows = []
    for root in run_roots():
        if not root.is_dir():
            continue
        where = "kali" if root == RUNS_DIR else "downloads"
        rows += [(item, where) for item in root.iterdir() if item.is_dir()]
    if not rows:
        print("belum ada run")
        return 0
    rows.sort(reverse=True, key=lambda pair: pair[0].name)
    print(f"{'run':<40} {'target':<28} {'where':<10} {'report'}")
    for item, where in rows[:40]:
        meta = {}
        try:
            meta = json.loads((item / "run.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        report = "yes" if (item / "report.html").is_file() else "no"
        print(f"{item.name:<40} {meta.get('target', '?'):<28} "
              f"{where:<10} {report}")
    return 0


def diagnose() -> int:
    """Print everything that decides whether the dashboard can run."""
    lines: list[str] = []

    def add(text: str = "") -> None:
        lines.append(text)

    add(f"datz {APP_VERSION}")
    add(f"python {platform.python_version()} | {sys.executable}")
    add(f"platform {platform.platform()}")
    add(f"machine {platform.machine()} | os {os.name} | pid {os.getpid()}")
    for name in ("stdin", "stdout", "stderr"):
        stream = getattr(sys, name, None)
        try:
            fd = stream.fileno()
        except Exception:
            fd = "?"
        try:
            isatty = bool(stream.isatty())
        except Exception:
            isatty = False
        add(f"{name}: fd={fd} tty={isatty}")
    try:
        cols, rows = shutil.get_terminal_size((100, 30))
        add(f"terminal {cols}x{rows}")
    except Exception as exc:
        add(f"terminal error: {exc}")
    add(f"TERM={os.environ.get('TERM') or '(unset)'} "
        f"COLORTERM={os.environ.get('COLORTERM') or '(unset)'} "
        f"LANG={os.environ.get('LANG') or '(unset)'}")
    add(f"data dir {HOME}")
    try:
        HOME.mkdir(parents=True, exist_ok=True)
        probe = HOME / ".write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        add("data dir writable: yes")
    except Exception as exc:
        add(f"data dir writable: no ({exc})")
    config = load_config()
    add(f"output pilihan: {config.get('output', 'runs')} "
        f"(config {config_path()})")
    add(f"output kali      {RUNS_DIR} ({'ada' if RUNS_DIR.is_dir() else 'belum'})")
    try:
        dl = downloads_root()
        add(f"output downloads {dl or 'tidak ditemukan'}"
            + (f" ({'ada' if dl.is_dir() else 'belum'})" if dl else ""))
    except Exception as exc:
        add(f"output downloads error: {exc}")
    try:
        engine = ensure_engine()
        blob = engine.read_bytes()
        add(f"engine {engine} ({len(blob)} bytes, "
            f"sha256 {hashlib.sha256(blob).hexdigest()[:16]}...)")
        add(f"engine version {engine_version(engine)}")
    except Exception as exc:
        add(f"engine error: {exc}")
    monitor = None
    try:
        monitor = SysMonitor(weather=False)
        monitor.sample(time.time(), force=True)
        time.sleep(0.12)
        monitor.sample(time.time(), force=True)
        add(f"host {monitor.host or 'n/a'} | os {monitor.os_name or 'n/a'}")
        add(f"cpu {monitor.cpu if monitor.cpu is not None else 'n/a'}"
            f" | ram {monitor.ram if monitor.ram is not None else 'n/a'}"
            f" | battery {monitor.battery if monitor.battery is not None else 'n/a'}"
            f" | uptime {format_uptime(monitor.uptime)}")
    except Exception as exc:
        add(f"sensor error: {exc}")
    finally:
        try:
            if monitor is not None:
                monitor.close()
        except Exception:
            pass
    try:
        cache = weather_cache_path()
        if cache.is_file():
            age = max(0, int(time.time() - cache.stat().st_mtime))
            add(f"weather cache {cache} ({age}s old)")
        else:
            add(f"weather cache {cache} (none)")
    except Exception as exc:
        add(f"weather cache error: {exc}")
    if os.name != "nt":
        try:
            ready, _, _ = select.select([0], [], [], 0.2)
            if not ready:
                add("stdin probe: idle (tidak ada input, normal)")
            else:
                try:
                    chunk = os.read(0, 64)
                except OSError as exc:
                    add(f"stdin probe: ready, read error {exc}")
                else:
                    if chunk:
                        add(f"stdin probe: ready, {len(chunk)} bytes tersedia")
                    else:
                        add("stdin probe: ready tapi EOF (0 byte) — "
                            "TUI akan langsung berhenti")
        except Exception as exc:
            add(f"stdin probe error: {exc}")
    history = tail_log(6)
    if history:
        add(f"log terakhir ({LOG_PATH}):")
        for line in history:
            add(f"  {line}")
    else:
        add(f"log {LOG_PATH} (kosong)")
    text = "\n".join(lines) + "\n"
    sys.stdout.write(text)
    sys.stdout.flush()
    target = HOME / "diagnose.txt"
    try:
        target.write_text(text, encoding="utf-8")
        print(f"disimpan: {target}")
    except OSError as exc:
        print(f"gagal menyimpan {target}: {exc}", file=sys.stderr)
    return 0


def headless(args, engine: Path, dest: str = "runs") -> int:
    payload = {
        "target": args.target,
        "scopes": args.scope or [],
        "authorize": bool(args.i_am_authorized),
        "recon_only": args.recon_only,
        "injection": not args.no_injection,
        "backdoors": not args.no_backdoors,
        "bypass": args.bypass or args.full,
        "robots": args.robots_paths or args.full,
        "secrets": not args.no_secrets,
        "bundles": not args.no_bundles,
        "takeover": not args.no_takeover,
        "nvd": not args.no_nvd,
        "nuclei": args.nuclei,
        "ai": args.ai,
        "ai_model": args.ai_model or "",
        "rate": args.rate,
        "threads": args.threads,
        "timeout": args.timeout,
        "max_hosts": args.max_hosts,
        "max_requests": args.max_requests,
        "ports": args.ports or "",
        "no_ports": args.no_ports,
        "no_brute": args.no_brute,
        "no_passive": args.no_passive,
        "allow_intercepted": args.allow_intercepted,
        "user_agent": args.user_agent or "",
        "out": args.out or "",
    }
    try:
        opts = options_from_payload(payload)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if opts.out:
        outdir = Path(opts.out).expanduser()
    else:
        try:
            root = output_root(dest)
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        outdir = root / f"{time.strftime('%Y%m%d-%H%M%S')}-{opts.target}"
    outdir.mkdir(parents=True, exist_ok=True)
    argv = build_scan_argv(engine, opts, outdir)
    print(f"$ {shell_join(['webwarden'] + argv[2:])}", flush=True)
    try:
        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, errors="replace",
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
        code = proc.wait()
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    print(f"\noutput      {outdir}")
    win = windows_path(outdir)
    if win and win != str(outdir):
        print(f"windows     {win}")
    return code


def demo_result() -> dict:
    target = "example.com"
    findings = [
        {"title": "SSTI evaluation signal", "severity": "high",
         "category": "injection", "host": target,
         "url": f"https://{target}/search?q={{7*7}}",
         "description": "Arithmetic expression was evaluated by the template "
                        "engine; probe was read-only and returns no data.",
         "remediation": "never render user input as a template",
         "confidence": "confirmed", "verified": True, "decoy_suspected": False,
         "reproductions": 3, "cves": [],
         "chain_ids": ["ssti-example.com"],
         "poc": [f"curl -sS 'https://{target}/search?q=%7B7%2A7%7D'"]},
        {"title": "Reflected input in search page", "severity": "high",
         "category": "injection", "host": target,
         "url": f"https://{target}/search?q=wwtest",
         "description": "Reflection observed without markup execution; needs "
                        "manual verification in a browser.",
         "remediation": "context-aware output encoding",
         "confidence": "firm", "verified": False, "decoy_suspected": False,
         "reproductions": 2, "cves": [], "chain_ids": [],
         "poc": [f"curl -sS 'https://{target}/search?q=wwtest'"]},
        {"title": "Debug console exposed", "severity": "medium",
         "category": "exposure", "host": target,
         "url": f"https://{target}/_profiler", "description":
         "Symfony profiler is reachable; it records full requests, SQL and "
         "configuration values.", "remediation": "disable the profiler in prod",
         "confidence": "confirmed", "verified": False, "decoy_suspected": False,
         "reproductions": 2, "cves": [], "chain_ids": ["debug-console-example.com"],
         "poc": [f"curl -sS https://{target}/_profiler"]},
        {"title": "Missing CSP", "severity": "low", "category": "headers",
         "host": target, "url": f"https://{target}/", "description": "no CSP",
         "remediation": "add a Content-Security-Policy",
         "confidence": "firm", "verified": True, "decoy_suspected": False,
         "reproductions": 2, "cves": [], "chain_ids": [],
         "poc": [f"curl -sSI https://{target}/ | grep -i content-security-policy"]},
        {"title": "Server version disclosure", "severity": "info",
         "category": "headers", "host": f"www.{target}",
         "url": f"https://www.{target}/", "description": "Server header "
         "includes a version string.", "remediation": "trim version headers",
         "confidence": "firm", "verified": False, "decoy_suspected": False,
         "reproductions": 1, "cves": [], "chain_ids": [],
         "poc": [f"curl -sSI https://www.{target}/ | grep -i '^server'"]},
    ]
    scan = {
        "target": target, "version": "0.8.4",
        "stats": {"live_hosts": 3, "subdomains": 12, "open_ports": 4,
                  "urls": 42, "bypasses": 0, "secrets": 0, "findings": 5,
                  "verified": 2, "source_maps": 1, "bundle_drift": 2},
        "recon": {
            "waf": {"providers": [{"provider": "Cloudflare", "hosts": [target]}]},
            "chains": {"total": 2, "observed": 0, "partial": 2, "blocked": 0,
                       "items": [
                           {"title": "SSTI to server-side data access",
                            "severity": "high", "status": "partial",
                            "host": target,
                            "summary": "Template evaluation was observed; the "
                                       "data-read step was never performed.",
                            "proof": "GET /search?q={7*7} -> 49 in body (twice)",
                            "links": [
                                {"role": "entry", "title": "SSTI evaluation",
                                 "severity": "high", "status": "observed"},
                                {"role": "hypothesis", "title": "config read",
                                 "severity": "high", "status": "not-performed"}]},
                           {"title": "Exposed debug console", "severity": "medium",
                            "status": "partial", "host": target,
                            "summary": "Profiler reachable plus source exposure",
                            "proof": "GET /_profiler -> 200 (control path 404)",
                            "links": [
                                {"role": "exposure", "title": "/_profiler",
                                 "severity": "medium", "status": "observed"},
                                {"role": "pivot", "title": "build context",
                                 "severity": "low", "status": "partial"}]}]},
        },
        "findings": findings,
    }
    return {
        "scan": scan,
        "audit": {"risk_score": 63, "risk_band": "elevated", "provider": "local"},
        "files": [
            {"path": "audit.json", "size": 2048},
            {"path": "evidence/index.json", "size": 8192},
            {"path": "evidence/www.example.com/index.html", "size": 24576},
            {"path": "findings.json", "size": 4096},
            {"path": "poc.sh", "size": 2048},
            {"path": "report.html", "size": 51200},
            {"path": "report.md", "size": 24576},
            {"path": "scan.json", "size": 65536},
        ],
        "file_total": 8,
        "has_report_html": True, "has_report_md": True, "has_poc": True,
    }


DEMO_LINES = (
    "preflight checking DNS integrity for example.com",
    "[1/7] dns      resolving example.com",
    "[2/7] probe    3 hosts live",
    "[3/7] crawl    42 urls",
    "warn  CSP missing on 2 endpoints",
    "[4/7] checks   injection: 6 endpoints probed",
    "[5/7] bundles  14 artifacts · drift on app.js",
    "[6/7] paths    /_profiler 200 (control path 404)",
    "[7/7] audit    local heuristic provider",
    "done  5 findings (2 verified) · report.html written",
)


def seed_demo(app: App, tab: str = "summary") -> None:
    app.result = demo_result()
    app.demo = True
    app.run = RunState(argv=[], outdir=RUNS_DIR / "demo-run",
                       started=time.time() - 61)
    app.run.done = True
    app.run.code = 0
    for line in DEMO_LINES:
        app.run.add(line)
    app.parsed = True
    app.authorized = True
    app.target = "example.com"
    app.scopes = "*.example.com"
    app.tab = tab
    app.tab_index = [t[0] for t in TABS].index(tab)


def snapshot(args) -> int:
    width = max(72, args.width)
    height = max(20, args.height)
    app = App(Path("webwarden.pyz"),
              "0.8.4 (demo)" if args.demo else "0.8.4")
    app.target = "example.com"
    app.authorized = True
    app.scopes = "*.example.com"
    if args.demo:
        seed_demo(app, args.tab)
        if args.tab == "findings":
            app.find_sel = 1
    screen = draw(app, width, height)
    sys.stdout.write(screen.to_text() + "\n")
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="datz",
        description=(
            "Single-file terminal security console: full-screen dashboard, "
            "streaming headless scan, and CLI passthrough."
        ),
        epilog=(
            "EXAMPLES\n"
            "  Dashboard (tombol modul, input target, console live):\n"
            "      python3 datz.py\n"
            "\n"
            "  Dashboard dengan data contoh, tanpa scan:\n"
            "      python3 datz.py --demo\n"
            "\n"
            "  Dashboard tanpa animasi boot / tanpa widget cuaca:\n"
            "      python3 datz.py --no-boot --no-weather\n"
            "\n"
            "  Satu perintah terminal, semua modul read-only:\n"
            "      python3 datz.py --headless --target example.com \\\n"
            "          --i-am-authorized --full\n"
            "\n"
            "  Pilih folder hasil: ~/.datz/runs (KALI) atau Downloads laptop:\n"
            "      python3 datz.py            # di dashboard: tombol OUT / F4\n"
            "      python3 datz.py --headless --target example.com \\\n"
            "          --i-am-authorized --output downloads\n"
            "\n"
            "  Teruskan argumen ke engine:\n"
            "      python3 datz.py --cli scan example.com --i-am-authorized\n"
            "      python3 datz.py --cli audit ~/.datz/runs/<run>/scan.json\n"
            "      python3 datz.py --cli scan -h\n"
            "\n"
            "  Peta upload read-only untuk web lab lokal (GET/HEAD saja,\n"
            "  menolak host publik walau pakai --lab):\n"
            "      python3 datz.py --cli upload-audit http://127.0.0.1:8081 --lab\n"
            "      python3 datz.py --cli upload-audit -h\n"
            "\n"
            "  Uji IDOR/BOLA dua akun uji milikmu sendiri (GET saja, tanpa\n"
            "  login otomatis, tanpa enumerasi ID, nilai sesi tidak ditulis):\n"
            "      python3 datz.py --cli access-audit https://app.example.com \\\n"
            "          --auth-a 'Cookie: session=TOKEN_A' \\\n"
            "          --auth-b 'Cookie: session=TOKEN_B' \\\n"
            "          --url https://app.example.com/sheets/42 \\\n"
            "          --accounts-owned --i-am-authorized\n"
            "      python3 datz.py --cli access-audit -h\n"
            "\n"
            "  Lisensi dan masa uji coba 20 hari:\n"
            "      python3 datz.py --license\n"
            "      python3 datz.py --license \"DATZ1.…\"\n"
            "\n"
            "  Doctor dan daftar run lama:\n"
            "      python3 datz.py --doctor\n"
            "      python3 datz.py --list-runs\n"
            "\n"
            "  Ringkasan hasil di terminal (format CLI lama):\n"
            "      python3 datz.py --report\n"
            "      python3 datz.py --report ~/.datz/runs/<run>\n"
            "\n"
            "  Draft laporan buat dikirim ke vendor (bukti + batas uji):\n"
            "      python3 datz.py --disclosure\n"
            "\n"
            "  Dashboard langsung keluar / layar kosong (diagnosa):\n"
            "      python3 datz.py --diagnose\n"
            "\n"
            "  Render dashboard ke stdout (tes/CI, tanpa TUI):\n"
            "      python3 datz.py --snapshot --demo --width 110 --height 32\n"
            "      python3 datz.py --snapshot --demo --tab findings\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version",
                        version=f"datz {APP_VERSION}")
    parser.add_argument("--list-runs", action="store_true",
                        help="daftar run sebelumnya lalu keluar")
    parser.add_argument("--doctor", action="store_true",
                        help="jalankan doctor engine lalu keluar")
    parser.add_argument("--license", nargs="?", const="", default=None,
                        metavar="KUNCI",
                        help="tanpa nilai: status uji coba/lisensi; "
                             "dengan nilai: pasang kunci lalu keluar")
    parser.add_argument("--diagnose", action="store_true",
                        help="cetak info TTY/terminal/engine/sensor lalu keluar")
    parser.add_argument("--report", nargs="?", const="", metavar="RUN",
                        help="cetak ringkasan run (default: yang terakhir) "
                             "ke terminal seperti CLI lama")
    parser.add_argument("--disclosure", nargs="?", const="", metavar="RUN",
                        help="tulis draft laporan siap kirim ke vendor "
                             "(disclosure.md) lalu cetak isinya")
    parser.add_argument("--cli", nargs=argparse.REMAINDER, metavar="ARGS",
                        help="teruskan seluruh sisa baris ke engine")
    parser.add_argument("--headless", action="store_true",
                        help="scan langsung di terminal ini (tanpa dashboard)")
    parser.add_argument("--snapshot", action="store_true",
                        help="cetak satu frame dashboard ke stdout lalu keluar")
    parser.add_argument("--demo", action="store_true",
                        help="isi dashboard dengan hasil contoh (tanpa scan)")
    parser.add_argument("--no-weather", action="store_true",
                        help="matikan widget cuaca (wttr.in) di dashboard")
    parser.add_argument("--no-boot", action="store_true",
                        help="lewati animasi boot saat dashboard dibuka")
    parser.add_argument("--output", choices=("runs", "downloads"),
                        default=None,
                        help="folder output: runs (~/.datz/runs) atau "
                             "downloads (folder Downloads laptop)")
    parser.add_argument("--tab", default="findings",
                        choices=[t[0] for t in TABS],
                        help="tab awal untuk --snapshot")
    parser.add_argument("--width", type=int, default=110)
    parser.add_argument("--height", type=int, default=32)
    parser.add_argument("--target", help="target domain untuk --headless")
    parser.add_argument("--scope", action="append", metavar="DOMAIN",
                        help="scope tambahan (boleh diulang)")
    parser.add_argument("--i-am-authorized", action="store_true",
                        help="konfirmasi kamu pemilik target / punya izin")
    parser.add_argument("--full", action="store_true",
                        help="aktifkan bypass dan robots.txt path check")
    parser.add_argument("--bypass", action="store_true")
    parser.add_argument("--robots-paths", action="store_true")
    parser.add_argument("--recon-only", action="store_true")
    parser.add_argument("--no-injection", action="store_true")
    parser.add_argument("--no-backdoors", action="store_true")
    parser.add_argument("--no-secrets", action="store_true")
    parser.add_argument("--no-bundles", action="store_true")
    parser.add_argument("--no-takeover", action="store_true")
    parser.add_argument("--no-nvd", action="store_true")
    parser.add_argument("--nuclei", action="store_true")
    parser.add_argument("--ai", choices=("off", "local", "ollama"), default="local")
    parser.add_argument("--ai-model", default="")
    parser.add_argument("--rate", type=float, default=5.0)
    parser.add_argument("--threads", type=int, default=6)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--max-hosts", type=int, default=150)
    parser.add_argument("--max-requests", type=int, default=4000)
    parser.add_argument("--ports", default="")
    parser.add_argument("--no-ports", action="store_true")
    parser.add_argument("--no-brute", action="store_true")
    parser.add_argument("--no-passive", action="store_true")
    parser.add_argument("--allow-intercepted", action="store_true")
    parser.add_argument("--user-agent", default="")
    parser.add_argument("--out", default="")
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "help":
        rest = argv[1:]
        argv = (["--cli"] + rest + ["-h"]) if rest else ["-h"]
    args = build_cli().parse_args(argv)
    if args.demo and (args.headless or args.cli is not None):
        print("error: --demo hanya untuk dashboard (TUI atau --snapshot)",
              file=sys.stderr)
        return 2
    if args.license is not None:
        try:
            engine = ensure_engine()
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return license_flow(engine, args.license)
    if args.diagnose:
        return diagnose()
    if args.report is not None:
        return report_run(args.report)
    if args.disclosure is not None:
        return disclosure_run(args.disclosure)
    if args.snapshot:
        return snapshot(args)
    if args.cli is not None:
        engine = ensure_engine()
        return subprocess.call([sys.executable, str(engine)] + list(args.cli))
    if args.list_runs:
        return _print_run_table()
    if args.doctor:
        try:
            engine = ensure_engine()
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return subprocess.call([sys.executable, str(engine), "doctor"])
    if args.headless:
        try:
            engine = ensure_engine()
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        _, code = license_gate(engine, "headless")
        if code:
            return code
        return headless(args, engine, dest_of(args))
    try:
        engine = ensure_engine()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    badge = "" if args.demo else license_gate(engine, "tui", quiet=True)[0]
    version = engine_version(engine)
    if os.name == "nt" and not sys.stdin.isatty():
        print("datz: jalankan di terminal Kali/WSL, atau pakai --headless.",
              file=sys.stderr)
        return 2
    weather = not args.no_weather and os.environ.get(
        "DATZ_NO_WEATHER", "").lower() not in ("1", "true", "yes")
    boot = not args.no_boot and os.environ.get(
        "DATZ_NO_BOOT", "").lower() not in ("1", "true", "yes")
    return run_tui(engine, version, demo=args.demo, weather=weather, boot=boot,
                   dest=dest_of(args), license_badge=badge)


def dest_of(args) -> str:
    """--output wins, then the saved preference, then ~/.datz/runs."""
    if args.output:
        return args.output
    saved = load_config().get("output")
    if saved in [key for key, _label, _hint in OUTPUT_CHOICES]:
        return saved
    return "runs"


# >>> DATZ PAYLOAD (generated by the packaging step; do not edit) >>>
PAYLOAD_SHA256 = ""
PAYLOAD_B64 = ""
# <<< DATZ PAYLOAD <<<


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
