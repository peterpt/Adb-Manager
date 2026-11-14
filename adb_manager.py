#!/usr/bin/env python3
"""
adb_manager.py - Android device manager over adb (Tkinter).

Four tabs:
  Files  - dual-pane file manager (left = this computer, right = device).
  Apps   - every installed package, grouped (Google / Android / maker / yours),
           sub-packages nested under their parent. For each app it shows, in
           plain words, what it does, how risky it is to turn off and what it
           can access. Info comes from the built-in list (app_knowledge.py),
           Google Play and - when an app isn't on Play - a web search.
           Apps can be turned OFF / ON (pm disable-user / pm enable). Nothing
           is uninstalled or deleted.
           Install APKs from this computer: .apk (one or several), split-app
           bundles .apks / .xapk / .apkm (parts for other CPU types are left
           out, XAPK game data goes to Android/obb). Also from the Files tab:
           right-click an APK on the computer side -> Install on device.
           Uninstall: apps you installed are deleted (a copy of the APK can be
           saved on the PC first); system apps are removed for your user (they
           stay in the system and show as REMOVED, with Restore); updated system
           apps can go back to their factory version.
  Network - open ports (what is waiting for connections, and whether only the
           device or the whole network can reach it) and live connections,
           each with the app that owns it (from /proc/net + app user IDs, no
           root). Internet servers get their names looked up; auto-refresh
           highlights newly opened ports. Optionally remembers which internet
           destinations each app normally talks to, keeps a log, and warns
           when an app contacts a destination it never used before.
  Security - checkup of the things malware depends on: device protection
           (patch level, encryption, root, ADB over network, proxy), powerful
           access (accessibility, device admin, notification access, overlay,
           usage access, install other apps, SMS app, VPN), where apps came
           from and hidden icons, changes since the last check (new apps,
           permissions, replaced signing certificates), recent camera/mic/
           location use; deep scan adds APK signatures, VirusTotal /
           MalwareBazaar lookups and Exodus tracker reports.
           Optional AI research (Anthropic or OpenAI, with web search): the AI
           compares what the vendor says a package does with independent
           sources and replies in JSON; "Compare AIs" asks both and shows
           where they disagree. Set it up with the "AI settings" button.

Usage:
    python3 adb_manager.py [-s SERIAL] [--local DIR] [--remote DIR]

Files tab keys: F5 copy to other side  F7 new folder  F2 rename  Del delete
                BackSpace parent folder  Ctrl+H hidden files  Ctrl+R refresh

Saved data (in ~/.config/adb_manager/):
    app_info_cache.json   web lookups, so each app is only fetched once
    turned_off.json       apps this program turned off, per device (for Undo)
    actions.log           every turn off / turn on, with the device's answer
    ai_config.json        AI provider, models and API keys (permissions 600)
    ai_research.json      AI answers, so each package is only researched once
    apk_backups/          APK copies saved before uninstalling
    security_config.json  optional VirusTotal / MalwareBazaar / Exodus keys (600)
    snapshots/            one device fingerprint per security check
    network_seen/ network_log/   destinations each app used, and the log

Requires: Python 3 with tkinter (apt install python3-tk) - tested with 3.11 and 3.12 -
          adb in PATH (or ADB=/path/to/adb), Linux (Windows isn't supported).
          app_knowledge.py, ai_research.py and security_audit.py in the same folder.
          Optional: pip install anthropic and/or openai (AI research); Androguard 4.1.4
          in its own venv (code inspector) - see README.md.
"""

import argparse
import copy
import csv
import html
import ipaddress
import json
import os
import posixpath
import pty
import queue
import re
import select
import shlex
import shutil
import signal
import socket
import tempfile
import zipfile
import subprocess
import sys
import threading
import time
import tkinter as tk
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from tkinter import filedialog, font as tkfont, messagebox, simpledialog, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app_knowledge as kb  # noqa: E402
import ai_research as ai
import profiles as pf
import cve_check as cv
import history
import perm_inventory as pi  # noqa: E402
import security_audit as sa  # noqa: E402

ADB = os.environ.get("ADB") or shutil.which("adb") or "adb"


class AdbError(Exception):
    pass


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def run(cmd, timeout=None):
    """Run a command, return (rc, stdout, stderr) as text with \r removed."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           stdin=subprocess.DEVNULL, timeout=timeout)
    except FileNotFoundError:
        raise AdbError("adb not found - install it or set ADB=/path/to/adb")
    except subprocess.TimeoutExpired:
        raise AdbError("adb timed out (device unplugged or busy?)")
    out = p.stdout.decode("utf-8", "replace").replace("\r", "")
    err = p.stderr.decode("utf-8", "replace").replace("\r", "")
    return p.returncode, out, err


def human(n):
    if n is None:
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0
    return str(n)


def last_line(*texts):
    for t in texts:
        lines = [l.strip() for l in t.splitlines() if l.strip()]
        if lines:
            return lines[-1]
    return ""


class Entry:
    __slots__ = ("name", "is_dir", "is_link", "size", "mtime")

    def __init__(self, name, is_dir, is_link=False, size=None, mtime=""):
        self.name = name
        self.is_dir = is_dir
        self.is_link = is_link
        self.size = size
        self.mtime = mtime

    @property
    def folderish(self):
        return self.is_dir or self.is_link


# --------------------------------------------------------------------------
# device side
# --------------------------------------------------------------------------

def list_devices():
    rc, out, err = run([ADB, "devices", "-l"], timeout=30)
    devs = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices") or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        model = ""
        for p in parts[2:]:
            if p.startswith("model:"):
                model = p.split(":", 1)[1]
        devs.append((parts[0], parts[1], model))
    return devs


# Matches both toybox (Android 6+) and old toolbox `ls -la` output:
#   toybox : drwxrwx--x 4 root sdcard_rw 3488 2024-01-01 12:00 Android
#   toolbox: -rw-rw-r-- root sdcard_rw 12345 2013-01-01 00:00 file.txt
#   toolbox: drwxr-xr-x root root 2013-01-01 00:00 dir
LS_RE = re.compile(
    r"^([-dlcbps])[-rwxsStT]{9}\S*\s+(.*?)\s*"
    r"(\d{4}-\d{2}-\d{2})\s+(\d{1,2}:\d{2})\s(.*)$"
)


def parse_ls(text):
    entries, junk = [], []
    for line in text.splitlines():
        if not line.strip():
            continue
        m = LS_RE.match(line)
        if not m:
            if not line.startswith("total"):
                junk.append(line.strip())
            continue
        kind, middle, date, hm, name = m.groups()
        is_link = kind == "l"
        if is_link and " -> " in name:
            name = name.split(" -> ", 1)[0]
        if name in (".", ".."):
            continue
        size = None
        toks = middle.split()
        if kind == "-" and toks and toks[-1].isdigit():
            size = int(toks[-1])
        entries.append(Entry(name, kind == "d", is_link, size, date + " " + hm))
    return entries, junk


class RemoteFS:
    kind = "remote"

    def __init__(self, serial, model=""):
        self.serial = serial
        self.model = model

    def label(self):
        return "Device: %s%s" % (self.model.replace("_", " ") + " " if self.model else "",
                                 "(%s)" % self.serial)

    def adb_cmd(self, *args):
        return [ADB, "-s", self.serial] + list(args)

    def shell(self, cmd, timeout=30):
        return run(self.adb_cmd("shell", cmd), timeout=timeout)

    join = staticmethod(posixpath.join)

    @staticmethod
    def parent(path):
        return posixpath.dirname(path.rstrip("/")) or "/"

    @staticmethod
    def basename(path):
        return posixpath.basename(path.rstrip("/"))

    @staticmethod
    def norm(path):
        p = posixpath.normpath(path.strip() or "/")
        return "/" if p in ("", ".") else p

    def list(self, path):
        target = path if path.endswith("/") else path + "/"
        rc, out, err = self.shell("ls -la " + shlex.quote(target))
        entries, junk = parse_ls(out)
        if not entries:
            msg = ""
            if junk:
                msg = junk[0]
            elif rc != 0:
                msg = last_line(err, out) or "listing failed (rc=%d)" % rc
            if msg:
                raise AdbError(msg)
        return entries

    def _check(self, rc, out, err):
        if rc != 0 or (out + err).strip():
            raise AdbError(last_line(err, out) or "command failed (rc=%d)" % rc)

    def mkdir(self, path):
        self._check(*self.shell("mkdir " + shlex.quote(path)))

    def delete(self, path):
        self._check(*self.shell("rm -rf " + shlex.quote(path), timeout=600))

    def rename(self, src, dst):
        self._check(*self.shell("mv " + shlex.quote(src) + " " + shlex.quote(dst)))


# --------------------------------------------------------------------------
# local side
# --------------------------------------------------------------------------

class LocalFS:
    kind = "local"

    def label(self):
        return "This computer"

    join = staticmethod(os.path.join)

    @staticmethod
    def parent(path):
        return os.path.dirname(path.rstrip(os.sep)) or os.sep

    @staticmethod
    def basename(path):
        return os.path.basename(path.rstrip(os.sep))

    @staticmethod
    def norm(path):
        return os.path.normpath(os.path.expanduser(path.strip() or "~"))

    def list(self, path):
        out = []
        with os.scandir(path) as it:
            for de in it:
                try:
                    is_link = de.is_symlink()
                    is_dir = de.is_dir()
                    st = de.stat(follow_symlinks=False)
                    size = None if is_dir else de.stat().st_size
                    mt = time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime))
                except OSError:
                    is_dir, size, mt = False, None, ""
                out.append(Entry(de.name, is_dir, is_link and not is_dir, size, mt))
        return out

    def mkdir(self, path):
        os.mkdir(path)

    def delete(self, path):
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    def rename(self, src, dst):
        os.rename(src, dst)


# --------------------------------------------------------------------------
# transfer with progress (adb only prints progress to a terminal -> use a pty)
# --------------------------------------------------------------------------

PCT_RE = re.compile(rb"\[\s*(\d{1,3})%\]")


def adb_transfer(cmd, on_pct, cancel):
    """Run adb push/pull, call on_pct(0..100) as it goes.
    Returns (rc, last_message). rc=-1 if cancelled."""
    rc, text = adb_pty(cmd, on_pct, cancel)
    if rc == -1:
        return -1, "cancelled"
    msgs = [l.strip() for l in text.splitlines()
            if l.strip() and not l.strip().startswith("[")]
    return rc, (msgs[-1] if msgs else "")


def adb_pty(cmd, on_pct, cancel):
    """Run an adb command on a pty (adb only prints progress to a terminal).
    Returns (rc, full_output_text). rc=-1 if cancelled."""
    master, slave = pty.openpty()
    try:
        p = subprocess.Popen(cmd, stdout=slave, stderr=slave,
                             stdin=subprocess.DEVNULL, close_fds=True,
                             start_new_session=True)
    except FileNotFoundError:
        os.close(master)
        os.close(slave)
        return 1, "adb not found"
    os.close(slave)
    chunks, tail = [], b""
    cancelled = False
    while True:
        if cancel.is_set() and not cancelled:
            cancelled = True
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except OSError:
                pass
        r, _, _ = select.select([master], [], [], 0.2)
        if r:
            try:
                data = os.read(master, 8192)
            except OSError:  # EIO: child closed the pty
                data = b""
            if not data:
                break
            chunks.append(data)
            tail = (tail + data)[-256:]
            found = PCT_RE.findall(tail)
            if found:
                on_pct(min(100, int(found[-1])))
        elif p.poll() is not None:
            break
    p.wait()
    os.close(master)
    text = b"".join(chunks).decode("utf-8", "replace").replace("\r", "\n")
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)  # strip terminal escapes
    return (-1 if cancelled else p.returncode), text


# --------------------------------------------------------------------------
# apps: device side
# --------------------------------------------------------------------------

def adb_shell(serial, cmd, timeout=60):
    return run([ADB, "-s", serial, "shell", cmd], timeout=timeout)


def parse_pm_list(text):
    """'package:/path/base.apk=com.x' or 'package:com.x' -> {package: path}."""
    res = {}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("package:"):
            continue
        value = line[len("package:"):]
        path, sep, pkg = value.rpartition("=")
        if not sep:
            pkg, path = value, ""
        pkg = pkg.strip()
        if pkg:
            res[pkg] = path.strip()
    return res


def pm_list(serial, flags=""):
    rc, out, err = adb_shell(serial, ("pm list packages " + flags).strip(), timeout=120)
    res = parse_pm_list(out)
    # A real empty list prints nothing. Before Android 7 adb always reports rc=0 and pm
    # prints its errors ("Unknown option: --user", ...) on stdout, so any output that
    # isn't a package line means the command failed - never "no such package".
    if not res and (rc != 0 or err.strip() or out.strip()):
        raise AdbError(last_line(err, out) or "pm list packages failed (rc=%d)" % rc)
    return res


PKG_HDR_RE = re.compile(r"^\s{1,4}Package \[([^\]]+)\]")
PERM_LINE_RE = re.compile(r"^([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+)(?::.*)?$")
GRANTED_RE = re.compile(r"^([A-Za-z0-9_.]+): granted=true")


def parse_dumpsys_packages(text):
    """Parse 'dumpsys package packages' into {package: details}.

    Handles the old (4.x) and new formats; only the first block of each
    package is used ('Hidden system packages' repeats some of them)."""
    info = {}
    cur = None
    in_req = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Hidden system packages:") or s.startswith("Queries:"):
            break
        m = PKG_HDR_RE.match(line)
        if m:
            name = m.group(1)
            if name in info:
                cur = None
            else:
                cur = info[name] = {"perms": [], "granted": [], "flags": ""}
            in_req = False
            continue
        if cur is None or not s:
            continue
        if s == "requested permissions:":
            in_req = True
            continue
        if in_req:
            pm = PERM_LINE_RE.match(s)
            if pm and "=" not in s:
                cur["perms"].append(pm.group(1))
                continue
            in_req = False
        g = GRANTED_RE.match(s)
        if g:
            if g.group(1) not in cur["granted"]:
                cur["granted"].append(g.group(1))
            continue
        for key, pat in (("uid", r"^(?:userId|appId)=(\d+)"),
                         ("version", r"^versionName=(.*)$"),
                         ("version_code", r"^versionCode=(\d+)"),
                         ("installer", r"^installerPackageName=(\S+)"),
                         ("code_path", r"^codePath=(\S+)"),
                         ("first_install", r"^firstInstallTime=(.*)$"),
                         ("last_update", r"^lastUpdateTime=(.*)$")):
            if key not in cur:
                mm = re.match(pat, s)
                if mm:
                    cur[key] = mm.group(1).strip()
        mt = re.search(r"\btargetSdk=(\d+)", s)
        if mt and "target_sdk" not in cur:
            cur["target_sdk"] = mt.group(1)
        if s.startswith("flags=[") and not cur["flags"]:
            cur["flags"] = s[len("flags=["):].rstrip("]").strip()
        if re.match(r"^User 0:", s) and "enabled_state" not in cur:
            me = re.search(r"\benabled=(\d+)", s)
            if me:
                cur["enabled_state"] = int(me.group(1))
            mi = re.search(r"\binstalled=(true|false)", s)
            if mi:
                cur["installed"] = mi.group(1) == "true"
    return info


def device_props(serial):
    props = {}
    for key, prop in (("release", "ro.build.version.release"), ("sdk", "ro.build.version.sdk"),
                      ("model", "ro.product.model"), ("maker", "ro.product.manufacturer")):
        try:
            rc, out, err = adb_shell(serial, "getprop " + prop, timeout=15)
            props[key] = out.strip()
        except AdbError:
            props[key] = ""
    return props


# ---- app names from the phone (see security_audit "App names") ----------------

APK_PATH_RE = re.compile(r"^/[A-Za-z0-9._/~+=,@-]+\.apk$")
LABELS_FILE_NAME = "app_labels.json"


class ShortReadError(AdbError):
    """A read that returned fewer bytes than asked; .received says how many arrived."""

    def __init__(self, msg, received):
        AdbError.__init__(self, msg)
        self.received = received


def remote_read(serial, path, offset, length, timeout=30):
    """Read exactly [offset, offset+length) of a file on the device with dd over
    exec-out (binary-safe). The path must look like an APK path - it's never
    interpolated unquoted, and odd paths are refused outright. A short read raises
    AdbError: callers never work on partial data."""
    if not APK_PATH_RE.match(path or ""):
        raise AdbError("refusing unusual path %r" % (path or "")[:80])
    if offset < 0 or length <= 0:
        return b""
    bs = 4096
    first, last = offset // bs, (offset + length + bs - 1) // bs
    cmd = "dd if=%s bs=%d skip=%d count=%d 2>/dev/null" % (shlex.quote(path), bs, first, last - first)
    try:
        p = subprocess.run([ADB, "-s", serial, "exec-out", cmd], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, timeout=timeout)
    except FileNotFoundError:
        raise AdbError("adb not found")
    except subprocess.TimeoutExpired:
        raise AdbError("reading %s timed out" % path)
    if p.returncode != 0:
        raise AdbError("couldn't read %s" % path)
    start = offset - first * bs
    data = p.stdout[start:start + length]
    if len(data) != length:
        # count only bytes that belong to the requested range - dd's block-aligned
        # output can include bytes before the offset and after the range
        raise ShortReadError("short read from %s (%d of %d bytes)" % (path, len(data), length), len(data))
    return data


def remote_size(serial, path):
    if not APK_PATH_RE.match(path or ""):
        raise AdbError("refusing unusual path")
    rc, out, err = adb_shell(serial, "stat -c %s " + shlex.quote(path), timeout=15)
    if rc != 0 or not out.strip().isdigit():
        raise AdbError("couldn't get the size of %s" % path)
    return int(out.strip())


def read_label_parts(serial, path, workdir, tag, meter=None):
    """Copy ONLY the manifest and (if usable) resources.arsc of one base.apk into
    `workdir`, using exact byte ranges - never the whole APK. Every byte read is
    added to meter["used"] as it arrives, so failed apps count toward the budget
    too. Returns {"manifest": {...}, "arsc": {...}|None}. Raises AdbError or
    sa.LabelError (unusable APK layout)."""
    meter = meter if meter is not None else {"used": 0}

    def rd(off, n):
        try:
            data = remote_read(serial, path, off, n)
        except ShortReadError as e:
            meter["used"] += e.received              # what did arrive still counts
            raise
        meter["used"] += len(data)
        return data
    size = remote_size(serial, path)
    tail_len = min(size, 65535 + 22)
    tail = rd(size - tail_len, tail_len)
    cd_off, cd_size, count = sa.zip_find_cd(tail, size)
    entries = sa.zip_find_entries(rd(cd_off, cd_size), cd_off, count)
    if "AndroidManifest.xml" not in entries:
        raise sa.LabelError("no manifest")
    out = {"manifest": None, "arsc": None}
    for name, key, cap in (("AndroidManifest.xml", "manifest", sa.LABEL_MAX_MANIFEST),
                           ("resources.arsc", "arsc", sa.LABEL_MAX_ARSC)):
        if name not in entries:
            continue
        method, csize, usize, lho = entries[name]
        if csize > cap:
            if key == "manifest":
                raise sa.LabelError("manifest too large")
            continue                                      # oversized table: fall back
        lh = rd(lho, min(30 + 1024, cd_off - lho))
        start = sa.zip_data_offset(lh, lho, name, csize, cd_off)
        data = rd(start, csize) if csize else b""
        fp = os.path.join(workdir, "%s.%s" % (tag, key))
        with open(fp, "wb") as f:
            f.write(data)
        out[key] = {"path": fp, "method": method, "size": usize}
    return out


def label_budget_mb(cfg):
    """app_labels_max_mb parsed safely and clamped to 1..2048 (default 200)."""
    try:
        v = int(float(cfg.get("app_labels_max_mb", 200)))
    except (TypeError, ValueError, OverflowError):
        v = 200
    return max(1, min(2048, v))


def device_locale(serial):
    """{"lang", "region", "script"} of the device UI, best effort ({} if unknown)."""
    for prop in ("persist.sys.locale", "ro.product.locale"):
        try:
            rc, out, err = adb_shell(serial, "getprop " + prop, timeout=15)
        except AdbError:
            continue
        v = out.strip()
        if v:
            parts = re.split(r"[-_]", v)
            loc = {"lang": parts[0].lower(), "region": "", "script": ""}
            for x in parts[1:]:
                if len(x) == 4 and x.isalpha():
                    loc["script"] = x.title()
                elif len(x) in (2, 3):
                    loc["region"] = x.upper()
            return loc
    try:
        lang = adb_shell(serial, "getprop persist.sys.language", timeout=15)[1].strip()
        country = adb_shell(serial, "getprop persist.sys.country", timeout=15)[1].strip()
    except AdbError:
        return {}
    return {"lang": lang.lower(), "region": country.upper(), "script": ""} if lang else {}


def pkg_from_component(text):
    for line in reversed([l.strip() for l in text.splitlines() if l.strip()]):
        if "/" in line and " " not in line and not line.lower().startswith("error"):
            pkg = line.split("/", 1)[0]
            return None if pkg == "android" else pkg
    return None


def in_use_packages(serial):
    """{package: 'keyboard' | 'home screen'} for what the device is using now."""
    used = {}
    try:
        rc, out, err = adb_shell(serial, "settings get secure default_input_method", timeout=15)
        pkg = pkg_from_component(out)
        if pkg:
            used[pkg] = "keyboard"
    except AdbError:
        pass
    for cmd in ("cmd package resolve-activity --brief -a android.intent.action.MAIN "
                "-c android.intent.category.HOME",
                "pm resolve-activity --brief -a android.intent.action.MAIN "
                "-c android.intent.category.HOME"):
        try:
            rc, out, err = adb_shell(serial, cmd, timeout=15)
        except AdbError:
            continue
        pkg = pkg_from_component(out)
        if pkg:
            used.setdefault(pkg, "home screen")
            break
    return used


GROUPS = [("google", "Google apps & services"),
          ("android", "Android system"),
          ("vendor", "Device maker / operator / chip"),
          ("user", "Installed by you")]


def group_of(pkg, system):
    if pkg.startswith("com.google.") or pkg in ("com.android.vending", "com.android.chrome"):
        return "google"
    if not system:
        return "user"
    if pkg == "android" or pkg.startswith("com.android."):
        return "android"
    return "vendor"


def scan_packages(serial):
    """Everything the Apps tab needs, in one go (runs in a worker thread)."""
    paths = pm_list(serial, "-f")
    if not paths:
        raise AdbError("The device returned no packages")
    try:  # -u also lists apps removed for this user (still on the system)
        removed = {p: v for p, v in pm_list(serial, "-f -u").items() if p not in paths}
    except AdbError:
        removed = {}
    try:
        disabled = set(pm_list(serial, "-d"))
    except AdbError:
        disabled = None
    try:
        system = set(pm_list(serial, "-s"))
    except AdbError:
        system = None
    try:
        rc, out, err = adb_shell(serial, "dumpsys package packages", timeout=240)
        details = parse_dumpsys_packages(out)
    except AdbError:
        details = {}
    props = device_props(serial)
    used = in_use_packages(serial)
    # Launcher (icon) discovery: True = has an icon, False = confirmed none,
    # None = couldn't determine. Only meaningful for non-removed packages.
    user_pkgs = [p for p, pa in paths.items()]

    def _launcher_shell(c, t=60):
        # launcher_packages expects stdout TEXT, not the (rc, out, err) tuple.
        # Raise on a non-zero exit so a failed command is treated as "unknown",
        # not as "this package has no launcher icon".
        rc, out, err = adb_shell(serial, c, timeout=t)
        if rc != 0:
            raise AdbError(last_line(err, out) or "command failed (rc=%d)" % rc)
        return out
    try:
        launcher_set, launcher_method = sa.launcher_packages(_launcher_shell, user_pkgs)
        launcher_known = launcher_method is not None   # None => discovery failed
    except Exception:
        launcher_set, launcher_known = set(), False

    apps = {}
    for pkg, path in list(paths.items()) + list(removed.items()):
        d = details.get(pkg, {})
        flags = d.get("flags", "")
        if system is not None:
            is_sys = pkg in system
        else:
            is_sys = "SYSTEM" in flags.split() or path.startswith(("/system/", "/product/", "/vendor/",
                                                                   "/system_ext/", "/odm/", "/oem/", "/apex/"))
        if pkg in removed:
            is_sys = True if system is None or not path.startswith("/data/") else is_sys
        if disabled is not None:
            is_off = pkg in disabled
        else:
            is_off = d.get("enabled_state") in (2, 3, 4)
        apps[pkg] = {
            "package": pkg,
            "path": path,
            "system": is_sys,
            "updated_system": "UPDATED_SYSTEM_APP" in flags.split(),
            "disabled": is_off,
            "uid": d.get("uid", ""),
            "version": d.get("version", ""),
            "version_code": d.get("version_code", ""),
            "target_sdk": d.get("target_sdk", ""),
            "installer": d.get("installer", ""),
            "first_install": d.get("first_install", ""),
            "last_update": d.get("last_update", ""),
            "perms": d.get("perms", []),
            "granted": d.get("granted", []),
            "in_use": used.get(pkg),
            "removed": pkg in removed,
            # icon: True has a launcher icon, False confirmed none, None unknown.
            # Only trusted when discovery worked and the package was in scope.
            "icon": (pkg in launcher_set) if (launcher_known and pkg not in removed) else None,
            "group": group_of(pkg, is_sys),
        }
    return {"apps": apps, "props": props}


def pm_set_enabled(serial, pkg, enable, use_root=False):
    """Turn a package on/off for the main user. Returns (ok, message)."""
    q = shlex.quote(pkg)
    if enable:
        cmds = ["pm enable --user 0 " + q, "pm enable " + q]
    else:
        cmds = ["pm disable-user --user 0 " + q, "pm disable-user " + q]
    if use_root:
        cmds.append("su -c " + shlex.quote(("pm enable " if enable else "pm disable ") + q))
    msgs = []
    for c in cmds:
        try:
            rc, out, err = adb_shell(serial, c, timeout=30)
        except AdbError as e:
            msgs.append((c, str(e)))
            continue
        text = (out + "\n" + err).strip()
        if "new state" in text.lower():
            return True, last_line(text)
        msgs.append((c, last_line(err, out) or ("no answer (rc=%d)" % rc)))
    # The first attempt usually carries the real reason; the fallbacks only
    # exist for old Android versions without "--user".
    normal = [m for c, m in msgs if not c.startswith("su ")]
    reason = next((m for m in normal if "exception" in m.lower()), normal[0] if normal else "")
    root = [m for c, m in msgs if c.startswith("su ")]
    if root:
        reason += "  |  with root: " + root[0]
    return False, reason


def pm_paths(serial, pkg):
    """APK file(s) of an installed package on the device (base + split parts).
    Raises AdbError if 'pm path' fails - a failed command must never look like
    "this app has no files" (same class of bug as the old launcher one)."""
    rc, out, err = adb_shell(serial, "pm path " + shlex.quote(pkg), timeout=30)
    if rc != 0:
        raise AdbError("pm path %s failed: %s" % (pkg, (err or out).strip() or "exit code %d" % rc))
    return [l[len("package:"):].strip() for l in out.splitlines() if l.startswith("package:")]


def read_app_identity(serial, pkg, work, stop, keep=False):
    """Pull EVERY installed APK part of pkg (base + feature + config splits) into
    `work`, fingerprint each one (sha256 + signer), delete the copies, and return
    sa.make_app_identity(...). A part that can't be pulled or read is recorded
    with an "error" (coverage becomes "partial") instead of being skipped.

    Returns None if the user pressed Stop while this app was being read (an
    interrupted read is not "unreadable" and must not be cached), and raises
    AdbError if the device won't say where the app's files are.

    keep=True (code inspector): the copies are NOT deleted - each readable part
    gets "local": its path inside `work` (a private folder the caller removes)."""
    paths = pm_paths(serial, pkg)
    if not paths:
        raise AdbError("the device listed no files for %s" % pkg)
    parts = []
    for i, remote in enumerate(paths):
        if stop.is_set():
            return None
        name = posixpath.basename(remote)
        part = {"path": remote, "name": name, "kind": sa.apk_part_kind(name)}
        local = os.path.join(work, "%03d_%s" % (i, re.sub(r"[^A-Za-z0-9._-]+", "_", name) or "part.apk"))
        try:
            rc, msg = adb_transfer([ADB, "-s", serial, "pull", remote, local], lambda x: None, stop)
            if stop.is_set():
                return None
            if rc != 0 or not os.path.exists(local):
                part["error"] = "copy failed: %s" % ((msg or "").strip().splitlines()[-1:] or
                                                    ["exit code %d" % rc])[0]
            else:
                try:
                    part.update(sa.apk_identity(local))
                    if keep:
                        part["local"] = local
                except OSError as e:
                    part["error"] = "couldn't read the copied file: %s" % (e.strerror or e)
        finally:
            if not part.get("local"):
                try:
                    os.remove(local)
                except OSError:
                    pass
        parts.append(part)
    return sa.make_app_identity(pkg, parts)


def save_apk_copy(serial, pkg, version, dest_root, cancel):
    """Pull the APK(s) of a package to the PC. Returns (ok, path or error).
    One file -> <dest_root>/<pkg>-<version>.apk ; split app -> a folder with all parts."""
    try:
        remote = pm_paths(serial, pkg)
    except AdbError as e:
        return False, str(e)
    if not remote:
        return False, "the device didn't say where the app's file is"
    tag = re.sub(r"[^A-Za-z0-9._-]+", "_", "%s-%s" % (pkg, version or "unknown"))
    try:
        ours = os.path.abspath(dest_root).startswith(os.path.abspath(BACKUP_DIR) + os.sep)
        if ours:                                             # the app's own backups: private
            sa.ensure_dir(BACKUP_DIR, private=True)
            os.makedirs(dest_root, mode=0o700, exist_ok=True)
            os.chmod(dest_root, 0o700)                       # also an older, existing folder
        else:                                                # a folder the user picked: left as it is
            os.makedirs(dest_root, exist_ok=True)
        if len(remote) == 1:
            dest = os.path.join(dest_root, tag + ".apk")
        else:
            dest = os.path.join(dest_root, tag)
            os.makedirs(dest, exist_ok=True)
    except OSError as e:
        return False, str(e)
    for r in remote:
        target = dest if len(remote) == 1 else os.path.join(dest, posixpath.basename(r))
        rc, msg = adb_transfer([ADB, "-s", serial, "pull", r, target], lambda p: None, cancel)
        if rc != 0:
            return False, "copying it to the PC failed: %s" % (msg or "rc=%d" % rc)
    return True, dest


def pm_uninstall(serial, pkg, mode, keep_data=False):
    """mode: 'full' (user app), 'user' (remove for user 0), 'updates' (system app
    back to factory version). Returns (ok, plain message)."""
    k = "-k " if keep_data else ""
    q = shlex.quote(pkg)
    if mode == "user":
        cmds = ["pm uninstall %s--user 0 %s" % (k, q)]
    else:
        cmds = ["pm uninstall %s%s" % (k, q)]
    last = ""
    for c in cmds:
        try:
            rc, out, err = adb_shell(serial, c, timeout=120)
        except AdbError as e:
            last = str(e)
            continue
        ok, msg = explain_install(out + "\n" + err)
        if ok:
            return True, {"full": "uninstalled", "user": "removed for this user",
                          "updates": "updates removed - back to the factory version"}[mode]
        last = msg
    return False, last


def pm_restore(serial, pkg):
    """Bring back a system app that was removed for this user."""
    q = shlex.quote(pkg)
    last = ""
    for c in ("cmd package install-existing " + q, "pm install-existing " + q):
        try:
            rc, out, err = adb_shell(serial, c, timeout=60)
        except AdbError as e:
            last = str(e)
            continue
        text = (out + "\n" + err).strip()
        if "installed for user" in text.lower() or re.search(r"(?m)^\s*Success\s*$", text):
            return True, "restored"
        last = last_line(err, out) or last
    if "unknown command" in last.lower() or "not found" in last.lower() or "error: unknown" in last.lower():
        return False, ("this Android version has no restore command - only a factory reset "
                       "brings it back")
    return False, last or "the device didn't confirm"


def describe_pm_error(msg):
    """Turn a pm error into something readable."""
    main, _, root = msg.partition("  |  with root: ")
    if root:
        return describe_pm_error(main) + "; root didn't help either (%s)" % describe_pm_error(root)
    m = msg.lower()
    if re.search(r"\bsu: (not found|inaccessible)|/su: |permission denied.*\bsu\b", m):
        return "root (su) isn't available on the device"
    if "securityexception" in m or "permission denial" in m or "not allowed" in m:
        return ("the device refused (this Android version doesn't let ADB turn off this "
                "app; root may be needed)")
    if "unknown package" in m:
        return "the app is no longer on the device"
    if "cannot disable" in m or "protected" in m:
        return "Android protects this app and won't let it be turned off"
    return msg or "no answer from the device"


# --------------------------------------------------------------------------
# apps: web lookups
# --------------------------------------------------------------------------

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


def http_get(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept-Language": "en-US,en;q=0.8"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(4000000)
        charset = r.headers.get_content_charset() or "utf-8"
    return data.decode(charset, "replace")


def clean_text(s):
    s = html.unescape(s or "")  # Play sometimes double-encodes its HTML
    s = re.sub(r"<br\s*/?>", "\n", s, flags=re.I)
    s = re.sub(r"<[^>]+>", "", s)
    s = html.unescape(s)
    s = re.sub(r"[ \t\r\f\v]+", " ", s)
    s = re.sub(r"\n\s*\n+", "\n", s)
    return s.strip()


def meta_content(page, key):
    k = re.escape(key)
    for pat in (r'<meta[^>]+(?:property|name|itemprop)="%s"[^>]*content="([^"]*)"' % k,
                r'<meta[^>]+content="([^"]*)"[^>]*(?:property|name|itemprop)="%s"' % k):
        m = re.search(pat, page, re.I)
        if m:
            return clean_text(m.group(1))
    return ""


def parse_play_page(page):
    data = {}
    for blob in re.findall(r'<script[^>]*type="application/ld\+json"[^>]*>(.*?)</script>',
                           page, re.S | re.I):
        try:
            j = json.loads(blob)
        except ValueError:
            continue
        for it in (j if isinstance(j, list) else [j]):
            if isinstance(it, dict) and it.get("@type") in ("SoftwareApplication",
                                                            "MobileApplication", "VideoGame"):
                data = it
                break
        if data:
            break
    name = clean_text(data.get("name", "")) or re.sub(
        r"\s*-\s*Apps on Google Play\s*$", "", meta_content(page, "og:title"))
    desc = clean_text(data.get("description", "")) or meta_content(page, "description")
    author = data.get("author") or {}
    author = clean_text(author.get("name", "")) if isinstance(author, dict) else ""
    cat = data.get("applicationCategory") or ""
    if isinstance(cat, str) and cat:
        cat = cat.replace("_", " ").capitalize()
    rating = data.get("aggregateRating") or {}
    rating = rating.get("ratingValue", "") if isinstance(rating, dict) else ""
    if not (name or desc):
        return {"found": False}
    return {"found": True, "name": name, "description": desc[:4000], "author": author,
            "category": cat, "rating": str(rating)}


def play_lookup(pkg):
    url = ("https://play.google.com/store/apps/details?" +
           urllib.parse.urlencode({"id": pkg, "hl": "en", "gl": "US"}))
    try:
        page = http_get(url)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"found": False}
        raise
    res = parse_play_page(page)
    if res.get("found"):
        res["url"] = "https://play.google.com/store/apps/details?id=" + pkg
    return res


def parse_ddg_lite(page, limit=3):
    links = re.findall(r"<a([^>]*class=['\"]result-link['\"][^>]*)>(.*?)</a>", page, re.S | re.I)
    snippets = re.findall(r"<td[^>]*class=['\"]result-snippet['\"][^>]*>(.*?)</td>",
                          page, re.S | re.I)
    out = []
    for i, (attrs, title) in enumerate(links):
        hm = re.search(r"href=['\"]([^'\"]+)['\"]", attrs)
        href = html.unescape(hm.group(1)) if hm else ""
        if "uddg=" in href:
            q = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
            href = q.get("uddg", [href])[0]
        if href.startswith("//"):
            href = "https:" + href
        if "duckduckgo.com/y.js" in href:  # ads
            continue
        out.append({"title": clean_text(title), "url": href,
                    "snippet": clean_text(snippets[i]) if i < len(snippets) else ""})
        if len(out) >= limit:
            break
    return out


def web_lookup(pkg):
    url = "https://lite.duckduckgo.com/lite/?" + urllib.parse.urlencode(
        {"q": '"%s" android package' % pkg})
    return parse_ddg_lite(http_get(url))


def lookup_online(pkg, use_web=True):
    """Fetch what the web knows about a package. Never raises."""
    res = {"fetched": time.strftime("%Y-%m-%d %H:%M"), "play": None, "web": [], "error": ""}
    try:
        res["play"] = play_lookup(pkg)
    except Exception as e:  # network down, blocked, odd page...
        res["error"] = "Google Play: %s" % e
    play_ok = bool(res["play"] and res["play"].get("found"))
    if use_web and not play_ok:
        try:
            res["web"] = web_lookup(pkg)
        except Exception as e:
            res["error"] = (res["error"] + "; " if res["error"] else "") + "web search: %s" % e
    return res


# --------------------------------------------------------------------------
# apps: saved data
# --------------------------------------------------------------------------

CONFIG_DIR = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
                          "adb_manager")
CACHE_FILE = os.path.join(CONFIG_DIR, "app_info_cache.json")
LABELS_FILE = os.path.join(CONFIG_DIR, LABELS_FILE_NAME)
TURNED_OFF_FILE = os.path.join(CONFIG_DIR, "turned_off.json")
BACKUP_DIR = os.path.join(CONFIG_DIR, "apk_backups")
ACTIONS_LOG = os.path.join(CONFIG_DIR, "actions.log")
HISTORY_FILE = os.path.join(CONFIG_DIR, "history.jsonl")
PENDING_FILE = os.path.join(CONFIG_DIR, "pending_ops.json")
AI_CACHE_FILE = os.path.join(CONFIG_DIR, "ai_research.json")


class JsonStoreError(OSError):
    """Raised internally when the file on disk must not be overwritten."""


class JsonStore:
    """Small JSON dict kept in memory and saved to disk after every change.

    How a change is saved (the important part):
      every put()/update() is queued as a PENDING OPERATION. A save takes an
      exclusive lock file (shared by every copy of the app), reads the CURRENT
      file, replays all pending operations onto it IN ORDER, writes the result
      atomically, then releases the lock. So update() always runs its function on
      the latest data on disk - never on a stale copy this process loaded earlier -
      and two running copies of the app can change different entries under the
      same key (e.g. two packages of one device) without erasing each other.

    Other rules:
      - private: file 0600, folder 0700; an older looser file is tightened on load
        (if that fails it is reported, not ignored);
      - atomic: unique temp file + fsync + rename (sa.atomic_write_json);
      - thread-safe: one re-entrant lock; get() hands out deep copies;
      - fail closed: ONLY a missing file counts as a new empty store. A file that
        is unreadable, empty (0 bytes - likely truncated), not valid JSON or not a
        dict - at start-up OR later - is never overwritten. At start-up it is
        moved aside (under the shared lock) to a unique, private .corrupt-* name;
        if that's not possible the store is read-only;
      - errors are reported: put()/update() return False when the change couldn't
        be written, last_error says why, and the change stays pending in memory
        (visible to get()) and is retried on the next save.

    update() functions may run more than once (once for the in-memory view, and
    again on each save attempt against the latest disk data), so they must be
    pure: build the new value only from the value they are given."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.RLock()
        self.last_error = None      # why the most recent save failed (None = fine)
        self.load_problem = None    # what was wrong with the file at start-up
        self.read_only = False
        self._pending = []          # ("put", key, value) / ("update", key, fn, default)
        self.data = self._load()

    # ---- loading -----------------------------------------------------------

    def _note_load(self, msg):
        self.load_problem = msg if not self.load_problem else self.load_problem + "; " + msg

    def _open_lock(self):
        """Take the exclusive lock file shared by every copy of the app (the same
        one _save uses). Returns the fd to close (closing releases it).
        The store's folder is created (0700) if needed: stores always live in our
        private config folder."""
        sa.ensure_dir(os.path.dirname(os.path.abspath(self.path)), private=True)
        fd = os.open(self.path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
        except ImportError:   # not on Linux/macOS: in-process lock still applies
            pass
        except OSError:
            os.close(fd)
            raise
        return fd

    def _load(self):
        """Read the store at start-up. A missing file is a new, empty store; nothing
        else gets that treatment. When a file exists, the check AND any recovery of
        a damaged file happen under the shared lock, so two copies of the app
        starting at once never fight over the same damaged file: the second one
        simply finds it already moved aside (missing -> new empty store)."""
        if not os.path.lexists(self.path):
            return {}                      # nothing to protect; no lock needed
        lockf = None
        try:
            lockf = self._open_lock()
        except OSError as e:
            self.read_only = True
            self._note_load("can't lock %s (%s) - changes won't be saved this session" % (
                self.path, e.strerror or e))
            # still read it (read-only) so the session can show what's saved
        try:
            return self._load_locked(recover=lockf is not None)
        finally:
            if lockf is not None:
                try:
                    os.close(lockf)
                except OSError:
                    pass

    def _load_locked(self, recover):
        try:
            with open(self.path, encoding="utf-8") as f:
                raw = f.read()
        except FileNotFoundError:
            return {}                      # another copy already moved it aside
        except (OSError, UnicodeDecodeError) as e:
            self.read_only = True
            self._note_load("can't read %s (%s) - changes won't be saved this session" % (
                self.path, getattr(e, "strerror", None) or e))
            return {}
        try:
            os.chmod(self.path, 0o600)   # tighten files written by older versions
        except OSError as e:
            self._note_load("couldn't make %s private (0600): %s - other users on this "
                            "computer may be able to read it" % (self.path, e.strerror or e))
        try:
            # an EXISTING empty file is NOT an empty store: it is most likely a
            # store that got truncated, so it is treated as damaged like any other.
            data = json.loads(raw)
        except ValueError:
            data = None
        if isinstance(data, dict):
            return data
        what = "empty (0 bytes)" if not raw else "damaged"
        if not recover:
            self.read_only = True
            self._note_load("%s is %s; it was left as it is" % (self.path, what))
            return {}
        aside = self._move_aside()
        if aside:
            self._note_load("%s was %s; it was kept as %s and a fresh one started" % (
                os.path.basename(self.path), what, aside))
        else:
            self.read_only = True
            self._note_load("%s is %s and couldn't be moved aside (%s) - it was left as it "
                            "is and changes won't be saved this session" % (
                                self.path, what, self._aside_error or "unknown error"))
        return {}

    def _move_aside(self):
        """Move the damaged file to a .corrupt-* name. Order matters:
          1. hard-link it under a name that never replaces an earlier backup
             (os.link fails if the name exists);
          2. make that backup private (0600 - the link shares the original's inode);
             if this fails, remove the new link and leave the original untouched;
          3. only then remove the original name.
        Returns the backup path, or None (with self._aside_error set) on failure -
        the caller then keeps the store read-only."""
        self._aside_error = None
        stamp = time.strftime("%Y%m%d-%H%M%S")
        for n in range(1000):
            aside = "%s.corrupt-%s-%d%s" % (self.path, stamp, os.getpid(), "" if not n else "-%d" % n)
            try:
                os.link(self.path, aside)
            except FileExistsError:
                continue
            except OSError as e:
                self._aside_error = "couldn't create a backup copy (%s)" % (e.strerror or e)
                return None
            try:
                os.chmod(aside, 0o600)
            except OSError as e:
                self._aside_error = "couldn't make the backup private (%s)" % (e.strerror or e)
                try:
                    os.unlink(aside)
                except OSError:
                    self._aside_error += "; an unprotected backup was left at %s" % aside
                return None
            try:
                os.unlink(self.path)
            except OSError as e:
                self._aside_error = "couldn't remove the damaged file (%s)" % (e.strerror or e)
                try:
                    os.unlink(aside)
                except OSError:
                    pass
                return None
            return aside
        self._aside_error = "no free backup name"
        return None

    def _read_disk(self):
        """Current file contents under the save lock. Missing -> {}. Anything else
        that isn't a readable JSON dict raises JsonStoreError (fail closed)."""
        try:
            with open(self.path, encoding="utf-8") as f:
                raw = f.read()
        except FileNotFoundError:
            return {}
        except (OSError, UnicodeDecodeError) as e:
            raise JsonStoreError("%s can't be read (%s); it was left untouched" % (
                os.path.basename(self.path), getattr(e, "strerror", None) or e))
        if not raw:
            raise JsonStoreError("%s is empty (0 bytes) on disk - probably truncated; it was "
                                 "left untouched" % os.path.basename(self.path))
        try:
            data = json.loads(raw)
        except ValueError:
            data = None
        if not isinstance(data, dict):
            raise JsonStoreError("%s on disk is damaged (not valid data); it was left untouched"
                                 % os.path.basename(self.path))
        return data

    # ---- reading -----------------------------------------------------------

    def get(self, key, default=None):
        with self.lock:
            if key not in self.data:
                return default
            return copy.deepcopy(self.data[key])

    def keys(self):
        with self.lock:
            return list(self.data)

    # ---- writing -----------------------------------------------------------

    @staticmethod
    def _apply(data, op):
        if op[0] == "put":
            data[op[1]] = copy.deepcopy(op[2])
        elif op[0] == "del":
            data.pop(op[1], None)
        else:
            _, key, fn, default = op
            data[key] = copy.deepcopy(fn(copy.deepcopy(data.get(key, default))))

    def put(self, key, value):
        """Replace one key and save. Returns True only if it is safely on disk."""
        with self.lock:
            op = ("put", key, copy.deepcopy(value))
            self._apply(self.data, op)
            self._pending.append(op)
            return self._save()

    def delete(self, key):
        """Remove one key and save. Returns True only if it is safely on disk."""
        with self.lock:
            op = ("del", key)
            self._apply(self.data, op)
            self._pending.append(op)
            return self._save()

    def update(self, key, fn, default=None):
        """Cross-process atomic read-modify-write of one key: on save, fn is applied
        to the value currently ON DISK (under the lock). Returns True if saved."""
        with self.lock:
            op = ("update", key, fn, copy.deepcopy(default))
            self._apply(self.data, op)       # immediate in-memory view
            self._pending.append(op)
            return self._save()

    def _save(self):
        """Replay pending operations onto the latest disk data and write it.
        Caller holds self.lock. On any failure nothing on disk changes and the
        pending operations are kept for the next attempt."""
        if self.read_only:
            self.last_error = self.load_problem or "store is read-only"
            return False
        lockf = None
        try:
            lockf = self._open_lock()
            merged = self._read_disk()
            for op in self._pending:
                self._apply(merged, op)
            sa.atomic_write_json(self.path, merged, private=True)
            self._pending = []
            self.data = merged            # now matches disk, incl. other copies' changes
            self.last_error = None
            return True
        except OSError as e:              # JsonStoreError is an OSError too
            self.last_error = str(e) if isinstance(e, JsonStoreError) else "%s: %s" % (
                os.path.basename(self.path), e.strerror or e)
            return False
        finally:
            if lockf is not None:
                try:
                    os.close(lockf)       # closing releases the flock
                except OSError:
                    pass


def log_action(serial, verb, pkg, ok, msg, outcome=None, user=None, target="", source="apps"):
    """Record one change: in the append-only history (what the History window shows)
    and, as before, one line in actions.log. Never raises."""
    history.append(HISTORY_FILE, history.make_event(serial, verb, pkg, outcome or ("done" if ok else "failed"),
                                                    msg, user=user, target=target, source=source))
    try:
        sa.ensure_dir(CONFIG_DIR, private=True)
        with open(os.open(ACTIONS_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600), "a", encoding="utf-8") as f:
            os.fchmod(f.fileno(), 0o600)                            # also an older, existing log
            f.write("%s  %s  %-8s %s  %s  %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), serial,
                                                    verb, pkg, "OK" if ok else "FAILED", msg))
    except OSError:
        pass


# --------------------------------------------------------------------------
# Pending-operation journal: every phone change is recorded BEFORE it's sent and
# cleared after it returns. A record left behind (crash, timeout, error) is later
# settled ONLY by reading the phone - never by sending the command again and never
# by undoing anything - and only for the same phone and Android user.
# --------------------------------------------------------------------------

_pending_stores = {}
_pending_lock = threading.Lock()
NOOP = "noop"


def pending_store():
    with _pending_lock:
        st = _pending_stores.get(PENDING_FILE)
        if st is None:
            st = _pending_stores[PENDING_FILE] = JsonStore(PENDING_FILE)
        return st


def journal_begin(serial, user, pkg, what, original, desired, target="", source=""):
    """Record an operation as pending. Returns its id, NOOP when the phone already has
    the desired state (nothing worth recording), or False when the record couldn't be
    saved - then the caller must NOT change the phone."""
    if original is not None and original == desired:
        return NOOP
    op_id = "%d-%d-%s" % (time.time_ns(), os.getpid(), threading.get_ident())
    rec = {"serial": str(serial), "user": user if isinstance(user, int) else None, "pkg": pkg, "what": what,
           "target": target or "", "original": original, "desired": desired, "source": source,
           "started": time.strftime("%Y-%m-%d %H:%M:%S")}
    st = pending_store()
    if st.put(op_id, rec):
        return op_id
    st.delete(op_id)                       # roll back the unsaved record (it must never appear later)
    return False


def journal_end(op_id):
    """The operation returned (whatever its outcome): it's no longer pending."""
    if op_id and op_id != NOOP:
        pending_store().delete(op_id)


def journal_finish(serial, op_id, ok):
    """End a pending record after a command that has no read-back of its own. A clear
    success ends it. Otherwise the phone is read back first: if its state can't be read
    (e.g. the cable came out mid-command), the record stays pending and the next scan
    settles it. Records with nothing to read back (removed updates) just end.
    Returns False only when the record was kept."""
    if not op_id or op_id == NOOP or ok:
        journal_end(op_id)
        return True
    rec = pending_store().get(op_id)
    if not isinstance(rec, dict) or rec.get("desired") is None:
        journal_end(op_id)
        return True
    if read_op_state(serial, rec) is None:
        return False
    journal_end(op_id)
    return True


KEPT_MSG = " - the phone couldn't be read afterwards, so this will be checked on the next scan"


def journal_close(op_id, res):
    """Close an operation whose result came with a read-back: only when the outcome is
    actually known (verified / refused / unsupported, or the phone's state could be read
    afterwards). If the connection dropped and nothing could be read, it stays pending
    and is settled by read-back on the next scan."""
    obs = [res.get(k) for k in ("state", "pkg_state") if k in res]
    rb = res.get("readback")
    if isinstance(rb, dict):
        obs += list(rb.values())
    unknown = not obs or any(v in (None, "UNKNOWN") for v in obs)
    if res.get("outcome") in ("verified", "refused", "unsupported") or not unknown:
        journal_end(op_id)
    return res


ALREADY_MSG = "already in that state - nothing was sent"


def journal_refusal(what):
    return {"outcome": "failed", "message": "the record of this change couldn't be saved to disk first, so "
                                            "nothing was changed on the phone (%s)" % what}


def pending_for(serial):
    st = pending_store()
    return {k: v for k, v in ((k, st.get(k)) for k in st.keys()) if isinstance(v, dict) and v.get("serial") == serial}


def read_op_state(serial, rec):
    """The phone's CURRENT state for what a pending record changed, or None."""
    what, pkg, user = rec.get("what"), rec.get("pkg", ""), rec.get("user")
    if not isinstance(user, int) or isinstance(user, bool):
        return None                                     # unknown user: never assumed to be user 0
    try:
        if what in ("app-off", "app-on"):
            ps = (receiver_states(serial, user, {pkg}).get(pkg) or {}).get("pkg_state")
            return "off" if ps in (2, 3, 4) else "on" if ps in (0, 1) else None
        if what in ("remove-for-user", "restore"):
            st = profile_removed_state(serial, pkg)
            return None if st is None else ("removed" if st else "installed")
        if what == "uninstall-full":
            # the INSTALLED list for that user - '-u' also lists packages that are gone but still known
            return "installed" if pkg in set(pm_list(serial, "--user %d %s" % (user, shlex.quote(pkg)))) else "absent"
        if what in ("receiver-off", "receiver-back"):
            st = receiver_states(serial, user, {pkg}).get(pkg)
            word = receiver_state_word(rec.get("target", ""), st)
            return None if word == "UNKNOWN" else word
        if what in ("bg-restrict", "bg-allow"):
            want = rec.get("desired") if isinstance(rec.get("desired"), dict) else {}
            return read_background_modes(serial, appops_prefix(serial), pkg, user, sorted(want)) if want else None
    except (AdbError, OSError, ValueError):
        return None
    return None                                         # e.g. 'removed updates': can't be read back


def settle(rec, observed):
    """Read-back-only resolution of one pending record."""
    if observed is not None and observed == rec.get("desired"):
        return "verified"
    if observed is not None and observed == rec.get("original"):
        return "not_applied"
    return "uncertain"


def reconcile_pending(serial, user, user_verified):
    """Settle this phone's leftover records by reading it. Returns [(rec, outcome)], where
    outcome is verified / not_applied / uncertain / user_unverified (the phone's current
    user couldn't be established) / unknown_user (the record has no user) / other_user.
    Only records for the verified, matching user are read; the rest stay untouched until
    the user decides."""
    out = []
    for op_id, rec in sorted(pending_for(serial).items()):
        ru = rec.get("user")
        if not user_verified:
            out.append((dict(rec, id=op_id), "user_unverified"))
            continue
        if not isinstance(ru, int) or isinstance(ru, bool):
            out.append((dict(rec, id=op_id), "unknown_user"))
            continue
        if ru != user:
            out.append((dict(rec, id=op_id), "other_user"))
            continue
        outcome = settle(rec, read_op_state(serial, rec))
        if outcome != "uncertain":
            log_action(serial, rec.get("what"), rec.get("pkg"), outcome == "verified",
                       "found after an interruption (started %s)" % rec.get("started", "?"),
                       outcome=outcome, user=rec.get("user"), target=rec.get("target", ""), source="recovery")
            journal_end(op_id)
        out.append((dict(rec, id=op_id), outcome))
    return out


def forget_pending(op_ids):
    """The user decided: these uncertain records are logged as uncertain and dropped."""
    st = pending_store()
    for op_id in op_ids:
        rec = st.get(op_id)
        if isinstance(rec, dict):
            log_action(rec.get("serial"), rec.get("what"), rec.get("pkg"), False,
                       "couldn't be confirmed after an interruption; dismissed by the user",
                       outcome="uncertain", user=rec.get("user"), target=rec.get("target", ""), source="recovery")
        st.delete(op_id)


# --------------------------------------------------------------------------
# installing APKs from this computer
# --------------------------------------------------------------------------

APK_EXTS = (".apk", ".apks", ".xapk", ".apkm")

# Android's install failure codes, in plain words.
INSTALL_ERRORS = {
    "INSTALL_FAILED_ALREADY_EXISTS": "it's already installed - tick 'update if already installed'",
    "INSTALL_FAILED_VERSION_DOWNGRADE": "the device has a newer version - tick 'allow an older version'",
    "INSTALL_FAILED_UPDATE_INCOMPATIBLE": ("the installed copy was signed by a different developer - "
                                           "uninstall the old one first (that deletes its data)"),
    "INSTALL_FAILED_INCONSISTENT_CERTIFICATES": ("the installed copy was signed by a different "
                                                 "developer - uninstall the old one first"),
    "INSTALL_FAILED_OLDER_SDK": "this app needs a newer Android version than the device has",
    "INSTALL_FAILED_NEWER_SDK": "this app is too old for this Android version",
    "INSTALL_FAILED_NO_MATCHING_ABIS": "this app is built for a different type of processor (CPU)",
    "INSTALL_FAILED_INSUFFICIENT_STORAGE": "not enough free space on the device",
    "INSTALL_FAILED_INVALID_APK": "the APK file is damaged or incomplete",
    "INSTALL_PARSE_FAILED_NOT_APK": "this isn't a valid APK file",
    "INSTALL_PARSE_FAILED_NO_CERTIFICATES": "the APK isn't signed, so Android refuses it",
    "INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION": "Android couldn't read the APK (damaged?)",
    "INSTALL_PARSE_FAILED_MANIFEST_MALFORMED": "the APK is broken inside",
    "INSTALL_FAILED_TEST_ONLY": "it's a developer test build",
    "INSTALL_FAILED_USER_RESTRICTED": ("the device blocked it - accept the prompt on the screen; on "
                                       "Xiaomi turn on 'Install via USB' in Developer options"),
    "INSTALL_FAILED_VERIFICATION_FAILURE": "Play Protect / verification on the device blocked it",
    "INSTALL_FAILED_ABORTED": "the install was cancelled on the device",
    "INSTALL_FAILED_DUPLICATE_PERMISSION": "another installed app already uses one of its permissions",
    "INSTALL_FAILED_CONFLICTING_PROVIDER": "another installed app already uses one of its parts",
    "INSTALL_FAILED_MISSING_SPLIT": "parts of this split app are missing",
    "INSTALL_FAILED_MISSING_SHARED_LIBRARY": "it needs a system library this device doesn't have",
    "INSTALL_FAILED_CPU_ABI_INCOMPATIBLE": "this app is built for a different type of processor (CPU)",
    "INSTALL_FAILED_MEDIA_UNAVAILABLE": "the storage it should go to isn't available",
    "INSTALL_FAILED_INTERNAL_ERROR": "Android hit an internal error while installing",
    "DELETE_FAILED_INTERNAL_ERROR": ("Android refused - system apps can only be removed for this "
                                     "user, and there may be no updates to remove"),
    "DELETE_FAILED_DEVICE_POLICY_MANAGER": ("it's a device administrator - switch that off first in "
                                            "Settings > Security > Device admin apps"),
    "DELETE_FAILED_OWNER_BLOCKED": "the device owner / work profile blocks removing it",
    "DELETE_FAILED_USER_RESTRICTED": "removing apps is restricted on this device",
    "DELETE_FAILED_ABORTED": "the removal was cancelled",
    "DELETE_FAILED_SYSTEM_APP": "it's a system app - it can only be removed for this user",
}

ABI_TOKENS = ["arm64_v8a", "armeabi_v7a", "armeabi", "x86_64", "x86", "mips64", "mips"]


def explain_install(text):
    """(ok, plain message) from adb install output (old adb returns 0 even on failure)."""
    if re.search(r"(?m)^\s*Success\s*$", text) and "Failure" not in text:
        return True, "installed"
    m = re.search(r"\b((?:INSTALL|DELETE)_[A-Z_]+)\b", text)
    if m:
        code = m.group(1)
        return False, "%s (%s)" % (INSTALL_ERRORS.get(code, "Android refused it"), code)
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("[")]
    return False, lines[-1] if lines else "no answer from the device"


def device_abis(serial):
    for prop in ("ro.product.cpu.abilist", "ro.product.cpu.abi"):
        try:
            rc, out, err = adb_shell(serial, "getprop " + prop, timeout=15)
        except AdbError:
            continue
        abis = [a.strip().replace("-", "_") for a in out.strip().split(",") if a.strip()]
        if abis:
            return abis
    return []


def split_abi(name):
    """CPU type a split APK is built for, from its file name ('' = not CPU specific)."""
    n = os.path.basename(name).lower().replace("-", "_")
    for tok in ABI_TOKENS:
        if re.search(r"(?:^|[._])%s(?:[._]|$)" % tok, n):
            return tok
    return ""


def looks_like_split(name):
    n = os.path.basename(name).lower()
    return n == "base.apk" or n.startswith("split_") or ".config." in n or n.startswith("config.")


def unpack_bundle(path, abis, workdir):
    """Unpack a .apks/.xapk/.apkm. Returns (apk_paths, obb_list[(local, remote)], package, skipped)."""
    try:
        z = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        raise ValueError("not a valid bundle (or an encrypted .apkm - those need APKMirror's own installer)")
    try:
        return _unpack_bundle(z, abis, workdir)
    finally:
        z.close()


PKG_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")


def safe_obb_path(remote):
    """True only for a plain relative path under Android/obb/ (no '..', no absolute path)."""
    if not isinstance(remote, str) or "\\" in remote or remote.startswith("/"):
        return False
    parts = remote.split("/")
    return (len(parts) >= 3 and parts[0] == "Android" and parts[1] == "obb"
            and all(x not in ("", ".", "..") for x in parts))


def _unpack_bundle(z, abis, workdir):
    names = z.namelist()
    package = ""
    install_paths = {}
    for meta in ("manifest.json", "meta.sai_v2.json", "info.json"):
        if meta in names:
            try:
                info = json.loads(z.read(meta).decode("utf-8", "replace"))
                package = info.get("package_name") or info.get("package") or info.get("pname") or package
                for ex in info.get("expansions") or []:
                    if isinstance(ex, dict) and ex.get("file"):
                        install_paths[ex["file"]] = ex.get("install_path") or ex["file"]
            except (ValueError, AttributeError):
                pass
    apk_names = [n for n in names if n.lower().endswith(".apk") and not n.endswith("/")]
    nonstandalone = [n for n in apk_names if not n.lower().startswith(("standalones/", "standalone/"))]
    if nonstandalone:
        apk_names = nonstandalone
    keep, skipped = [], []
    for n in apk_names:
        abi = split_abi(n)
        if abi and abis and abi not in abis:
            skipped.append(os.path.basename(n))
        else:
            keep.append(n)
    if not keep:
        raise ValueError("no APK inside fits this device's processor (%s)" % ", ".join(abis) or "?")
    apks = []
    for i, n in enumerate(keep):
        dest = os.path.join(workdir, "%02d_%s" % (i, os.path.basename(n)))
        with z.open(n) as src, open(dest, "wb") as dst:
            shutil.copyfileobj(src, dst)
        apks.append(dest)
    obbs = []
    for i, n in enumerate(names):
        if n.lower().endswith(".obb"):
            remote = install_paths.get(n, n)
            if not safe_obb_path(remote):
                if not package or not PKG_NAME_RE.match(package):
                    continue
                remote = "Android/obb/%s/%s" % (package, posixpath.basename(n.replace("\\", "/")))
                if not safe_obb_path(remote):
                    continue
            dest = os.path.join(workdir, "obb%02d_%s" % (i, os.path.basename(n)))
            with z.open(n) as src, open(dest, "wb") as dst:
                shutil.copyfileobj(src, dst)
            obbs.append((dest, "/sdcard/" + remote))
    return apks, obbs, package, skipped


def plan_installs(paths):
    """Group the chosen files: each bundle is one job; loose split parts
    (base.apk, split_*.apk ...) go together; other APKs one by one."""
    bundles = [p for p in paths if p.lower().endswith((".apks", ".xapk", ".apkm"))]
    loose = [p for p in paths if p.lower().endswith(".apk")]
    jobs = [{"label": os.path.basename(p), "bundle": p} for p in bundles]
    if len(loose) > 1 and any(looks_like_split(p) for p in loose):
        jobs.append({"label": "%s (+%d parts)" % (os.path.basename(loose[0]), len(loose) - 1),
                     "apks": loose})
    else:
        jobs += [{"label": os.path.basename(p), "apks": [p]} for p in loose]
    return jobs


# --------------------------------------------------------------------------
# network: open ports and connections (from /proc/net, no root needed)
# --------------------------------------------------------------------------

TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
              "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
              "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}

# Android's fixed user IDs for system services (app IDs below 10000).
SYSTEM_UIDS = {0: "Android core (root services)", 1000: "Android system", 1001: "Phone / radio service",
               1002: "Bluetooth service", 1010: "Wi-Fi service", 1013: "Media server",
               1020: "Network discovery service (mDNS)", 1021: "GPS service", 1027: "NFC service",
               2000: "ADB shell", 9999: "nobody (unprivileged service)"}

PORT_INFO = {
    5555: "ADB over the network - whoever reaches it can control the device",
    5037: "ADB server",
    53: "DNS - looking up website names", 853: "private DNS (encrypted name lookups)",
    67: "DHCP - getting a network address", 68: "DHCP - getting a network address",
    123: "time sync (NTP)", 80: "plain web (HTTP, not encrypted)", 443: "secure web (HTTPS)",
    8080: "web / proxy (alternative port)", 8443: "secure web (alternative port)",
    5228: "Google push notifications (Play services)", 5229: "Google push notifications",
    5230: "Google push notifications", 5353: "mDNS - finding devices on your network (printers, Cast)",
    1900: "UPnP/SSDP - finding devices on your network", 8008: "Google Cast / Chromecast",
    8009: "Google Cast / Chromecast", 5222: "chat messaging (XMPP - e.g. WhatsApp)",
    3478: "voice/video calls (STUN)", 19302: "voice/video calls (Google STUN)",
    993: "e-mail (IMAP, encrypted)", 465: "sending e-mail (SMTP)", 587: "sending e-mail (SMTP)",
    22: "SSH remote login", 2222: "SSH remote login (alternative port)", 21: "FTP file transfer",
    1080: "SOCKS proxy", 4070: "Spotify Connect", 7000: "AirPlay", 9100: "printing",
    631: "printing (IPP)", 139: "Windows file sharing", 445: "Windows file sharing",
}


def hex_ip(h):
    """Address from /proc/net hex (each 32-bit word is little-endian)."""
    b = bytes.fromhex(h)
    if len(b) == 4:
        return str(ipaddress.IPv4Address(b[::-1]))
    ip = ipaddress.IPv6Address(b"".join(b[i:i + 4][::-1] for i in range(0, 16, 4)))
    return str(ip.ipv4_mapped) if ip.ipv4_mapped else str(ip)


# Linux's default range of temporary ("ephemeral") ports handed out for outgoing
# traffic; read from the device when possible (ip_local_port_range).
EPHEMERAL_DEFAULT = (32768, 60999)


def parse_port_range(text):
    m = re.match(r"\s*(\d+)\s+(\d+)\s*$", text or "")
    if m and 0 < int(m.group(1)) <= int(m.group(2)) <= 65535:
        return int(m.group(1)), int(m.group(2))
    return None


def parse_proc_net(text):
    """Parse '==tcp' / '==udp6' ... sections of /proc/net files (and an optional
    '==portrange' section). Returns (sockets, errors).

    TCP: state 0A = listening (an open port), 01 = connected.
    UDP has NO listening state. An unconnected UDP socket shows state 07 (CLOSE):
      - on a FIXED port (outside the temporary range) it receives on that port,
        like a server does (mDNS 5353, DHCP 68 ...)      -> kind "listen";
      - on a TEMPORARY port it's almost always the client side of DNS, QUIC
        (HTTP/3) and similar, not a service waiting for others -> kind
        "udp_temp", which is not counted as an open port and raises no alerts."""
    socks, errors, proto = [], [], None
    lines = text.splitlines()
    eph = None
    for i, line in enumerate(lines):
        if line.strip() == "==portrange" and i + 1 < len(lines):
            eph = parse_port_range(lines[i + 1])
    low, high = eph or EPHEMERAL_DEFAULT
    for line in lines:
        line = line.strip()
        if line.startswith("=="):
            proto = line[2:]
            continue
        if proto == "portrange":
            continue
        parts = line.split()
        if not proto or not parts:
            continue
        if len(parts) < 10 or parts[0] == "sl" or ":" not in parts[1]:
            if "denied" in line.lower() or "no such file" in line.lower():
                errors.append("%s: %s" % (proto, line))
            continue
        try:
            lip, lport = parts[1].split(":")
            rip, rport = parts[2].split(":")
            st = parts[3].upper()
            rec = {"proto": "tcp" if proto.startswith("tcp") else "udp", "v6": proto.endswith("6"),
                   "local_ip": hex_ip(lip), "local_port": int(lport, 16),
                   "remote_ip": hex_ip(rip), "remote_port": int(rport, 16),
                   "uid": int(parts[7]), "inode": parts[9]}
        except (ValueError, IndexError):
            continue
        if rec["proto"] == "tcp":
            rec["state"] = TCP_STATES.get(st, st)
            rec["kind"] = "listen" if st == "0A" else ("connected" if st == "01" else "other")
        elif st == "01":
            rec["state"], rec["kind"] = "CONNECTED", "connected"
        elif st == "07" and low <= rec["local_port"] <= high:
            rec["state"], rec["kind"] = "TEMPORARY", "udp_temp"
        elif st == "07":
            rec["state"], rec["kind"] = "OPEN", "listen"
        else:
            rec["state"], rec["kind"] = st, "other"
        rec["eph_range"] = "%d-%d%s" % (low, high, "" if eph else " (default)")
        socks.append(rec)
    return socks, errors


def read_sockets(serial):
    rc, out, err = adb_shell(serial, "for f in tcp tcp6 udp udp6; do echo ==$f; "
                                     "cat /proc/net/$f 2>&1; done; echo ==portrange; "
                                     "cat /proc/sys/net/ipv4/ip_local_port_range 2>&1", timeout=30)
    socks, errors = parse_proc_net(out)
    if not socks and (errors or err.strip()):
        raise AdbError("the device won't show its network table: %s"
                       % (errors[0] if errors else last_line(err)))
    return socks, errors


def uid_packages(serial):
    """{app_id: [packages]} straight from the device (when the Apps tab hasn't scanned)."""
    m = {}
    try:
        rc, out, err = adb_shell(serial, "pm list packages -U", timeout=60)
        for line in out.splitlines():
            mm = re.match(r"\s*package:(\S+)\s+uid:([\d,]+)", line)
            if mm:
                for u in mm.group(2).split(","):
                    m.setdefault(int(u) % 100000, []).append(mm.group(1))
    except AdbError:
        pass
    if not m:
        try:
            rc, out, err = adb_shell(serial, "dumpsys package packages", timeout=240)
            for pkg, d in parse_dumpsys_packages(out).items():
                if d.get("uid", "").isdigit():
                    m.setdefault(int(d["uid"]) % 100000, []).append(pkg)
        except AdbError:
            pass
    return m


def addr_kind(ip):
    """'device' | 'local' | 'internet' | 'any' for an address."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "internet"
    if a.is_unspecified:
        return "any"
    if a.is_loopback:
        return "device"
    if a.is_private or a.is_link_local or a.is_multicast:
        return "local"
    return "internet"

NET_SEEN_DIR = os.path.join(CONFIG_DIR, "network_seen")
NEWDEST_SECONDS = 120   # how long a connection to a new destination stays red
NET_LOG_DIR = os.path.join(CONFIG_DIR, "network_log")


def dest_key(ip, name):
    """What counts as 'the same destination': the site's domain, or the address block."""
    if name:
        labels = name.lower().rstrip(".").split(".")
        if len(labels) >= 3 and labels[-2] in ("co", "com", "net", "org", "gov", "ac", "edu") \
                and len(labels[-1]) == 2:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])
    if ":" in ip:
        return ":".join(ip.split(":")[:3]) + "::/48"
    return ".".join(ip.split(".")[:3]) + ".*"



def reverse_name(ip, timeout=3.0):
    """Reverse-DNS name of an address, or '' (runs the lookup with a time limit)."""
    box = []
    t = threading.Thread(target=lambda: box.append(_gethost(ip)), daemon=True)
    t.start()
    t.join(timeout)
    return box[0] if box else ""


def _gethost(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


# --------------------------------------------------------------------------
# GUI: one file pane
# --------------------------------------------------------------------------

class FilePane(ttk.Frame):
    def __init__(self, master, app, fs, path):
        super().__init__(master, padding=4)
        self.app = app
        self.fs = fs
        self.path = path
        self.entries = []
        self.items = {}  # tree iid -> Entry
        self.sort_col, self.sort_rev = "name", False

        top = ttk.Frame(self)
        top.pack(fill="x")
        self.title = ttk.Label(top, text="", font=("TkDefaultFont", 10, "bold"))
        self.title.pack(side="left")

        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(4, 4))
        ttk.Button(bar, text="\u2191 Up", width=5, command=self.go_up).pack(side="left")
        ttk.Button(bar, text="\u27f3", width=3, command=self.refresh).pack(side="left", padx=2)
        self.path_var = tk.StringVar(value=path)
        ent = ttk.Entry(bar, textvariable=self.path_var)
        ent.pack(side="left", fill="x", expand=True, padx=(2, 0))
        ent.bind("<Return>", lambda e: self.load(self.path_var.get()))

        frame = ttk.Frame(self)
        frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(frame, columns=("size", "mtime"), selectmode="extended")
        self.tree.heading("#0", text="Name", command=lambda: self.sort_by("name"))
        self.tree.heading("size", text="Size", command=lambda: self.sort_by("size"))
        self.tree.heading("mtime", text="Modified", command=lambda: self.sort_by("mtime"))
        self.tree.column("#0", width=260, stretch=True)
        self.tree.column("size", width=80, anchor="e", stretch=False)
        self.tree.column("mtime", width=130, stretch=False)
        self.tree.tag_configure("dir", foreground="#1f5fbf")
        self.tree.tag_configure("link", foreground="#138a8a")
        self.tree.tag_configure("up", foreground="#777777")
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", self.on_open)
        self.tree.bind("<Return>", self.on_open)
        self.tree.bind("<BackSpace>", lambda e: self.go_up())
        self.tree.bind("<FocusIn>", lambda e: app.set_active(self))
        self.tree.bind("<Button-1>", lambda e: app.set_active(self), add="+")
        self.tree.bind("<Button-3>", self.on_menu)
        self.update_title()

    # ---- data ------------------------------------------------------------

    def update_title(self):
        self.title.configure(text=self.fs.label() if self.fs else "No device")

    def set_fs(self, fs, path):
        self.fs = fs
        self.update_title()
        self.load(path)

    def load(self, path=None, select=None):
        """List a folder. Returns True on success. Pane is unchanged on failure."""
        if not self.fs:
            return False
        path = self.fs.norm(path or self.path)
        self.app.busy(True)
        try:
            entries = self.fs.list(path)
        except (AdbError, OSError) as e:
            self.app.error("Cannot open %s: %s" % (path, e))
            self.path_var.set(self.path)
            return False
        finally:
            self.app.busy(False)
        self.path = path
        self.path_var.set(path)
        self.entries = entries
        self.populate(select)
        return True

    def refresh(self, select=None):
        keep = select or [e.name for e in self.selected()]
        if self.load(select=keep):
            self.app.info("Refreshed")

    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self.items.clear()
        self.entries = []

    def sort_by(self, col):
        if self.sort_col == col:
            self.sort_rev = not self.sort_rev
        else:
            self.sort_col, self.sort_rev = col, False
        self.populate([e.name for e in self.selected()])

    def populate(self, select=None):
        if isinstance(select, str):
            select = [select]
        select = set(select or [])
        self.tree.delete(*self.tree.get_children())
        self.items.clear()
        show_hidden = self.app.show_hidden.get()
        ents = [e for e in self.entries if show_hidden or not e.name.startswith(".")]
        keyf = {
            "name": lambda e: e.name.lower(),
            "size": lambda e: e.size or 0,
            "mtime": lambda e: e.mtime,
        }[self.sort_col]
        dirs = sorted([e for e in ents if e.folderish], key=keyf, reverse=self.sort_rev)
        files = sorted([e for e in ents if not e.folderish], key=keyf, reverse=self.sort_rev)

        if self.fs.parent(self.path) != self.path:
            self.tree.insert("", "end", iid="..", text="..  (parent folder)", tags=("up",))
        first_sel = None
        for i, e in enumerate(dirs + files):
            iid = "e%d" % i
            if e.is_dir:
                text, tag = e.name + "/", "dir"
            elif e.is_link:
                text, tag = e.name + "  \u2192", "link"
            else:
                text, tag = e.name, ""
            self.tree.insert("", "end", iid=iid, text=text,
                             values=(human(e.size), e.mtime), tags=(tag,))
            self.items[iid] = e
            if e.name in select:
                self.tree.selection_add(iid)
                first_sel = first_sel or iid
        kids = self.tree.get_children()
        if first_sel:
            self.tree.focus(first_sel)
            self.tree.see(first_sel)
        elif kids:
            self.tree.focus(kids[0])
        arrow = " \u25bc" if self.sort_rev else " \u25b2"
        for col, label in (("#0", "Name"), ("size", "Size"), ("mtime", "Modified")):
            key = "name" if col == "#0" else col
            self.tree.heading(col, text=label + (arrow if key == self.sort_col else ""))

    def selected(self):
        return [self.items[i] for i in self.tree.selection() if i in self.items]

    def names(self):
        return {e.name for e in self.entries}

    # ---- navigation ------------------------------------------------------

    def on_open(self, event=None):
        iid = self.tree.focus()
        if event is not None and getattr(event, "y", None) is not None and event.type == tk.EventType.ButtonPress:
            iid = self.tree.identify_row(event.y) or iid
        if not iid:
            return "break"
        if iid == "..":
            self.go_up()
            return "break"
        e = self.items.get(iid)
        if e and e.folderish:
            self.load(self.fs.join(self.path, e.name))
        elif e:
            other = "device" if self.fs.kind == "local" else "computer"
            self.app.info("%s is a file - use the arrow buttons (or F5) to copy it to the %s"
                          % (e.name, other))
        return "break"

    def go_up(self):
        if not self.fs:
            return
        parent = self.fs.parent(self.path)
        if parent != self.path:
            self.load(parent, select=self.fs.basename(self.path))

    def on_menu(self, event):
        self.app.set_active(self)
        iid = self.tree.identify_row(event.y)
        if iid and iid not in self.tree.selection():
            self.tree.selection_set(iid)
            self.tree.focus(iid)
        m = tk.Menu(self, tearoff=0)
        to = "Upload to device" if self.fs.kind == "local" else "Download to computer"
        has = bool(self.selected())
        m.add_command(label="Open", command=self.on_open,
                      state="normal" if iid else "disabled")
        m.add_command(label=to, command=self.app.copy_from_active,
                      state="normal" if has else "disabled")
        apks = [self.fs.join(self.path, e.name) for e in self.selected()
                if not e.folderish and e.name.lower().endswith(APK_EXTS)]
        if self.fs.kind == "local" and apks:
            m.add_command(label="Install on device" + (" (%d)" % len(apks) if len(apks) > 1 else ""),
                          command=lambda: self.app.install_apks(apks))
        m.add_separator()
        m.add_command(label="New folder", command=self.app.mkdir)
        m.add_command(label="Rename", command=self.app.rename,
                      state="normal" if len(self.selected()) == 1 else "disabled")
        m.add_command(label="Delete", command=self.app.delete,
                      state="normal" if has else "disabled")
        m.add_separator()
        m.add_command(label="Refresh", command=self.refresh)
        try:
            m.tk_popup(event.x_root, event.y_root)
        finally:
            m.grab_release()


# --------------------------------------------------------------------------
# GUI: Apps tab
# --------------------------------------------------------------------------

SHOW_CHOICES = ["All apps", "Only ON", "Only OFF", "Only removed", "Only Google", "Only system",
                "Only installed by me", "Not looked up yet", "No built-in notes",
                "Checked by AI", "AIs disagree"]

def source_check_note(answer):
    """(text, tag) said once above an AI answer's sources, or None."""
    sc = answer.get("source_check") if isinstance(answer, dict) else None
    if not isinstance(sc, dict):
        return ("Older answer: it wasn't recorded which sources came from a real web search.\n", "dim")
    if not sc.get("searches"):
        return ("No web search was done for this answer: it's based on the AI's own knowledge, which "
                "may be out of date, and its sources may be written from memory.\n", "warn")
    return None


def source_mark(answer, url):
    """Short note after one source address: where it came from, if that was recorded."""
    sc = answer.get("source_check") if isinstance(answer, dict) else None
    if isinstance(sc, dict) and not sc.get("searches"):
        return ""                 # no search was done: the warning above says so; nothing to attribute
    urls = sc.get("urls") if isinstance(sc, dict) and isinstance(sc.get("urls"), dict) else None
    hit = urls.get(url) if urls is not None else None
    if hit is True:
        return "  (found by the AI's web search - shows where it came from, not that it backs the answer)"
    if hit is False:
        return "  (NOT among the pages the AI's search returned - may be from memory)"
    return ""                                      # not recorded (or damaged): say nothing


AI_VERDICT_TEXT = {"safe": "\u2705 safe to turn off", "careful": "\u26a0 be careful",
                   "keep_on": "\u26d4 keep it on", "unknown": "? doesn't know"}
AI_VERDICT_TAG = {"safe": "safe", "careful": "caution", "keep_on": "critical", "unknown": "dim"}
BACKING_TEXT = {"research": "researched", "users": "reported by users",
                "unconfirmed": "unconfirmed"}


class AppsTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master, padding=4)
        self.app = app
        self.serial = None
        self.scanned_serial = None
        self.props = {}
        self.apps = {}
        self.parent_of = {}
        self.kids = {}
        self.cache = JsonStore(CACHE_FILE)
        self.turned_off = JsonStore(TURNED_OFF_FILE)
        self.ai_cache = JsonStore(AI_CACHE_FILE)
        self.labels = JsonStore(LABELS_FILE)       # real app names read from the phone
        self.label_gen = 0                         # bumps on every device change / rescan
        self.label_stop = threading.Event()
        self.label_locale = {}
        self.read_names = tk.BooleanVar(value=bool(sa.load_sec_config().get("app_labels_enabled", True)))
        self._store_warned = set()   # stores whose save failure we already showed
        # (store problems are reported by App once every tab - Autorun included - exists)
        self.job = None              # name of the running background job
        self.stop = threading.Event()
        self.fetching = set()        # packages being looked up right now
        self.shown_pkg = None
        self.first_fill = True
        self.select_after_scan = []
        self.select_quietly = False
        self.message_after_scan = None
        self.show_tech = tk.BooleanVar(value=False)
        self.use_root = tk.BooleanVar(value=False)
        self.use_web = tk.BooleanVar(value=True)
        self.search_var = tk.StringVar()
        self.show_var = tk.StringVar(value=SHOW_CHOICES[0])

        # --- top row
        top = ttk.Frame(self)
        top.pack(fill="x")
        self.scan_btn = ttk.Button(top, text="Scan apps", command=self.scan)
        self.scan_btn.pack(side="left")
        self.install_btn = ttk.Button(top, text="Install APK from PC", command=self.choose_apks)
        self.install_btn.pack(side="left", padx=(4, 0))
        self.uninstall_btn = ttk.Button(top, text="Uninstall selected", command=self.uninstall_selected)
        self.uninstall_btn.pack(side="left", padx=(4, 0))
        self.restore_btn = ttk.Button(top, text="Restore removed", command=self.restore_selected)
        self.restore_btn.pack(side="left", padx=4)
        self.inspect_btn = ttk.Button(top, text="Inspect code\u2026", command=self.inspect_selected)
        self.inspect_btn.pack(side="left", padx=4)
        self.profile_btn = ttk.Button(top, text="Profiles\u2026", command=self.open_profiles)
        self.profile_btn.pack(side="left")
        self.history_btn = ttk.Button(top, text="History\u2026", command=self.open_history)
        self.history_btn.pack(side="left", padx=4)
        self.perms_btn = ttk.Button(top, text="Permissions\u2026", command=self.open_permissions)
        self.perms_btn.pack(side="left")
        self._inspect_wins = {}
        ttk.Label(top, text="  Search:").pack(side="left")
        ent = ttk.Entry(top, textvariable=self.search_var, width=20)
        ent.pack(side="left", padx=4)
        self.search_var.trace_add("write", lambda *a: self.populate())
        ttk.Label(top, text="Show:").pack(side="left", padx=(8, 0))
        cb = ttk.Combobox(top, textvariable=self.show_var, values=SHOW_CHOICES,
                          state="readonly", width=20)
        cb.pack(side="left", padx=4)
        cb.bind("<<ComboboxSelected>>", lambda e: self.populate())
        srow = ttk.Frame(self)
        srow.pack(fill="x", pady=(3, 0))
        self.summary = ttk.Label(srow, text="", foreground="#555555")
        self.summary.pack(side="left")

        # --- middle: list | details
        pw = ttk.PanedWindow(self, orient="horizontal")
        pw.pack(fill="both", expand=True, pady=(4, 4))

        left = ttk.Frame(pw)
        self.tree = ttk.Treeview(left, columns=("state", "safety", "package"),
                                 selectmode="extended")
        self.tree.heading("#0", text="App")
        self.tree.heading("state", text="State")
        self.tree.heading("safety", text="Turn off?")
        self.tree.heading("package", text="Package")
        self.tree.column("#0", width=250, stretch=True)
        self.tree.column("state", width=70, anchor="center", stretch=False)
        self.tree.column("safety", width=90, stretch=False)
        self.tree.column("package", width=270, stretch=True)
        self.tree.tag_configure("group", font=("TkDefaultFont", 10, "bold"))
        self.tree.tag_configure("safe", foreground="#2e7d32")
        self.tree.tag_configure("caution", foreground="#b26a00")
        self.tree.tag_configure("critical", foreground="#c62828")
        self.tree.tag_configure("unknown", foreground="#5a6b7b")
        self.tree.tag_configure("off", background="#e6e6e6")
        sb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Button-3>", self.on_menu)
        pw.add(left, weight=3)

        right = ttk.Frame(pw)
        self.details = tk.Text(right, wrap="word", width=50, relief="flat",
                               padx=8, pady=6, cursor="arrow")
        dsb = ttk.Scrollbar(right, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=dsb.set)
        self.details.pack(side="left", fill="both", expand=True)
        dsb.pack(side="right", fill="y")
        base = ("TkDefaultFont", 10)
        self.details.tag_configure("h1", font=("TkDefaultFont", 14, "bold"))
        self.details.tag_configure("h2", font=("TkDefaultFont", 11, "bold"),
                                   spacing1=10, spacing3=2)
        self.details.tag_configure("dim", foreground="#777777")
        self.details.tag_configure("mono", font=("TkFixedFont", 9))
        self.details.tag_configure("safe", foreground="#2e7d32", font=("TkDefaultFont", 12, "bold"))
        self.details.tag_configure("caution", foreground="#b26a00", font=("TkDefaultFont", 12, "bold"))
        self.details.tag_configure("critical", foreground="#c62828", font=("TkDefaultFont", 12, "bold"))
        self.details.tag_configure("unknown", foreground="#5a6b7b", font=("TkDefaultFont", 12, "bold"))
        self.details.tag_configure("warn", foreground="#c62828")
        self.details.tag_configure("b", font=("TkDefaultFont", 10, "bold"))
        self.details.tag_configure("bk_research", foreground="#2e7d32")
        self.details.tag_configure("bk_users", foreground="#b26a00")
        self.details.tag_configure("bk_unconfirmed", foreground="#777777")
        self.details.configure(font=base)
        pw.add(right, weight=2)

        # --- bottom rows
        row1 = ttk.Frame(self)
        row1.pack(fill="x")
        self.off_btn = ttk.Button(row1, text="Turn OFF selected", command=lambda: self.change(False))
        self.off_btn.pack(side="left")
        self.on_btn = ttk.Button(row1, text="Turn ON selected", command=lambda: self.change(True))
        self.on_btn.pack(side="left", padx=4)
        self.undo_btn = ttk.Button(row1, text="Turn back ON everything I turned off",
                                   command=self.undo_all)
        self.undo_btn.pack(side="left", padx=4)
        ttk.Separator(row1, orient="vertical").pack(side="left", fill="y", padx=8)
        self.look_btn = ttk.Button(row1, text="Look up selected online",
                                   command=self.lookup_selected)
        self.look_btn.pack(side="left")
        self.lookall_btn = ttk.Button(row1, text="Look up all (slow)", command=self.lookup_all)
        self.lookall_btn.pack(side="left", padx=4)
        self.stop_btn = ttk.Button(row1, text="Stop", command=self.stop.set)

        rowai = ttk.Frame(self)
        rowai.pack(fill="x", pady=(4, 0))
        ttk.Label(rowai, text="AI research:").pack(side="left")
        self.ask_btn = ttk.Button(rowai, text="Ask AI about selected",
                                  command=lambda: self.ask_ai(False))
        self.ask_btn.pack(side="left", padx=4)
        self.compare_btn = ttk.Button(rowai, text="Compare AIs", command=lambda: self.ask_ai(True))
        self.compare_btn.pack(side="left")
        self.ai_set_btn = ttk.Button(rowai, text="AI settings", command=self.open_ai_settings)
        self.ai_set_btn.pack(side="left", padx=4)
        self.ai_label = ttk.Label(rowai, text="", foreground="#555555")
        self.ai_label.pack(side="left", padx=8)
        self.update_ai_label()

        row2 = ttk.Frame(self)
        row2.pack(fill="x", pady=(4, 0))
        ttk.Checkbutton(row2, text="Search the web when an app isn't on Google Play",
                        variable=self.use_web).pack(side="left")
        ttk.Checkbutton(row2, text="Read app names from the phone", variable=self.read_names,
                        command=self._read_names_toggled).pack(side="left", padx=(8, 0))
        ttk.Checkbutton(row2, text="Use root (su) if the device refuses",
                        variable=self.use_root).pack(side="left", padx=12)
        ttk.Checkbutton(row2, text="Show technical details", variable=self.show_tech,
                        command=lambda: self.render(self.shown_pkg)).pack(side="right")

        self.render(None)

    # ---- device ----------------------------------------------------------

    def set_device(self, serial):
        if serial == self.serial:
            return
        self.stop_label_reader()             # results for the old device are dropped
        self.serial = serial
        self.apps, self.parent_of, self.kids = {}, {}, {}
        self.scanned_serial = None
        self.first_fill = True
        self.populate()
        self.render(None)

    def on_shown(self):
        """Called when the Apps tab is opened."""
        if self.serial and self.scanned_serial != self.serial and not self.job:
            self.scan()

    # ---- background jobs -------------------------------------------------

    # ---- unfinished operations (read-back only) ----------------------------

    def _reconcile_work(self, serial):
        try:
            user, src = current_user(serial)
            res = reconcile_pending(serial, user, src in ("detected", "single-user"))
        except Exception as e:                       # never let this break a scan
            res = [({"what": "?", "pkg": "?"}, "error: %s" % e)]
        self.post(self._reconciled, serial, res)

    def _reconciled(self, serial, results):
        if not results:
            return
        # an Apps-tab OFF confirmed only now still belongs in the 'turn back ON' list
        offs = tuple(r["pkg"] for r, o in results if o == "verified" and r.get("what") == "app-off"
                     and r.get("source") == "apps")
        if offs:
            stamp = time.strftime("%Y-%m-%d %H:%M")

            def add(mine, offs=offs, stamp=stamp):
                mine = mine if isinstance(mine, dict) else {}
                for p in offs:
                    mine[p] = stamp
                return mine
            self._store_saved(self.turned_off, self.turned_off.update(serial, add, {}),
                              "the list of apps this program turned off (used for Undo)")
        words = {"verified": "it did happen", "not_applied": "it didn't happen",
                 "uncertain": "couldn't be confirmed",
                 "other_user": "belongs to another Android user - left alone",
                 "unknown_user": "it isn't known which Android user it was for - left alone",
                 "user_unverified": "this phone's current Android user couldn't be established - left alone"}
        lines = ["\u2022 %s - %s: %s" % (self.label(r.get("pkg", "?")) if r.get("pkg") in self.apps else r.get("pkg"),
                                          HISTORY_WHAT.get(r.get("what"), r.get("what")), words.get(o, o))
                 for r, o in results]
        unsure = [r["id"] for r, o in results if o in ("uncertain", "unknown_user") and r.get("id")]
        text = ("The last time, %d change(s) on this phone were interrupted before the app could finish. "
                "The phone was only READ to see what happened - nothing was sent again or undone:\n\n%s"
                % (len(results), "\n".join(lines[:20])))
        if unsure:
            if messagebox.askyesno("Interrupted changes", text + "\n\n%d couldn't be confirmed. Check those apps "
                                   "yourself. Forget them now?\n(No = ask again next time)" % len(unsure),
                                   parent=self.app.root):
                forget_pending(unsure)
        else:
            messagebox.showinfo("Interrupted changes", text, parent=self.app.root)
        # no re-scan: the scan that triggered this has just read the phone's real state

    def open_permissions(self):
        if not self.serial:
            self.app.error("No device connected - pick one at the top")
            return
        win = getattr(self, "_perm_win", None)
        if win is not None and win.winfo_exists():
            win.lift()
            return
        self._perm_win = PermissionsWindow(self.app.root, self.app)

    def open_history(self):
        win = getattr(self, "_history_win", None)
        if win is not None and win.winfo_exists():
            win.refresh()
            win.lift()
            return
        self._history_win = HistoryWindow(self.app.root, self.app)

    def open_profiles(self):
        win = getattr(self, "_profile_win", None)
        if win is not None and win.winfo_exists():
            win.lift()
            return
        self._profile_win = ProfileWindow(self.app.root, self.app)

    def start_job(self, name, fn, *args):
        if self.job:
            self.app.info("Busy: %s - wait for it to finish or press Stop" % self.job)
            return False
        self.job = name
        self.stop.clear()
        for b in (self.scan_btn, self.off_btn, self.on_btn, self.undo_btn,
                  self.look_btn, self.lookall_btn, self.ask_btn, self.compare_btn,
                  self.install_btn, self.uninstall_btn, self.restore_btn):
            b.state(["disabled"])
        self.stop_btn.pack(side="left", padx=4)
        self._job_token = token = getattr(self, "_job_token", 0) + 1

        def guarded():
            try:
                fn(*args)
            except Exception as e:                       # a bug or an unexpected error: free the tab
                self.post(self._job_crashed, token, name, "%s: %s" % (type(e).__name__, e))
        threading.Thread(target=guarded, daemon=True).start()
        return True

    def _job_crashed(self, token, name, err):
        if token == getattr(self, "_job_token", None) and self.job:
            self.end_job()
        self.app.error("Something went wrong while %s (%s) - the buttons are usable again" % (name, err))

    def end_job(self):
        self.job = None
        for b in (self.scan_btn, self.off_btn, self.on_btn, self.undo_btn,
                  self.look_btn, self.lookall_btn, self.ask_btn, self.compare_btn,
                  self.install_btn, self.uninstall_btn, self.restore_btn):
            b.state(["!disabled"])
        self.stop_btn.pack_forget()

    def post(self, fn, *args):
        self.app.q.put(("call", fn) + args)

    # ---- scan ------------------------------------------------------------

    def scan(self):
        if not self.serial:
            self.app.error("No device connected - pick one at the top")
            return
        self.app.info("Reading the app list from the device (can take a minute on old devices) ...")
        self.start_job("reading apps", self._scan_worker, self.serial)

    def _scan_worker(self, serial):
        try:
            res = scan_packages(serial)
        except AdbError as e:
            self.post(self._scan_failed, str(e))
            return
        self.post(self._scan_done, serial, res)

    def _scan_failed(self, msg):
        self.end_job()
        self.app.error("Could not read the app list: %s" % msg)

    def _scan_done(self, serial, res):
        self.end_job()
        if serial != self.serial:
            return
        self.apps = res["apps"]
        self.props = res["props"]
        self.scanned_serial = serial
        self.build_family()
        self.populate()
        self.start_label_reader()            # names fill in afterwards; the list is already shown
        ar = getattr(self.app, "autorun_tab", None)
        if ar is not None and ar.data is not None:
            ar.populate()                    # system/user classification is now known
        self.render(self.shown_pkg if self.shown_pkg in self.apps else None)
        if pending_for(serial):
            threading.Thread(target=self._reconcile_work, args=(serial,), daemon=True).start()
        off = sum(1 for a in self.apps.values() if a["disabled"])
        self.app.info("Found %d apps (%d turned off). Click one to see what it does."
                      % (len(self.apps), off))
        if self.message_after_scan:  # keep the install/remove outcome visible
            kind, text = self.message_after_scan
            (self.app.error if kind == "error" else self.app.info)(text)
            self.message_after_scan = None
        new = [p for p in self.select_after_scan if p in self.apps]
        self.select_after_scan = []
        if new:
            iids = ["p:" + p for p in new if self.tree.exists("p:" + p)]
            for iid in iids:
                parent = self.tree.parent(iid)
                while parent:
                    self.tree.item(parent, open=True)
                    parent = self.tree.parent(parent)
            if iids:
                self.tree.selection_set(iids)
                self.tree.focus(iids[0])
                self.tree.see(iids[0])
                self.render(new[0])
            if not self.select_quietly:
                self.app.info("Newly installed: %s" % ", ".join(self.label(p) for p in new))
        self.select_quietly = False

    def build_family(self):
        """Nest packages under the longest installed package that prefixes them."""
        self.parent_of, self.kids = {}, {}
        for pkg, a in self.apps.items():
            parts = pkg.split(".")
            for i in range(len(parts) - 1, 1, -1):
                cand = ".".join(parts[:i])
                if cand in self.apps and self.apps[cand]["group"] == a["group"]:
                    self.parent_of[pkg] = cand
                    self.kids.setdefault(cand, []).append(pkg)
                    break

    def descendants(self, pkg):
        out, todo = [], list(self.kids.get(pkg, []))
        while todo:
            p = todo.pop()
            out.append(p)
            todo.extend(self.kids.get(p, []))
        return out

    # ---- describing apps -------------------------------------------------

    def label(self, pkg):
        """Display name only - every action keeps using the package id.
        Priority: name read from the app's own APK (what Android shows) -> Google Play
        name (if already looked up) -> curated built-in name -> the package id.
        A name is never made up from the package id."""
        got = self.apk_label(pkg)
        if got:
            return got
        info = self.cache.get(pkg) or {}
        play = info.get("play") or {}
        if play.get("found") and play.get("name"):
            return play["name"]
        k = kb.lookup(pkg)
        if k and k.get("name"):
            return k["name"]
        return pkg

    def apk_label(self, pkg):
        e = self.labels.get(pkg)
        a = self.apps.get(pkg)
        if a and self.label_entry_valid(e, a, self.label_locale):
            return e.get("label")
        return None

    @staticmethod
    def label_entry_valid(e, a, locale):
        """A saved name is reused only for the same version, install time, APK path
        and phone language. (Practical invalidation signals - not proof the file is
        byte-identical.)"""
        return (isinstance(e, dict) and e.get("version_code") == str(a.get("version_code") or "")
                and e.get("last_update") == str(a.get("last_update") or "")
                and e.get("apk_path") == a.get("path") and e.get("locale") == locale)

    # ---- reading app names in the background ------------------------------

    def _read_names_toggled(self):
        cfg = sa.load_sec_config()
        cfg["app_labels_enabled"] = bool(self.read_names.get())
        try:
            sa.save_sec_config(cfg)
        except Exception:
            pass
        if self.read_names.get() and self.apps:
            self.start_label_reader()
        else:
            self.stop_label_reader()

    def stop_label_reader(self):
        self.label_stop.set()
        self.label_gen += 1

    def start_label_reader(self):
        """Fill in real names after the list is shown. One reader per connection;
        results from an older one are ignored (label_gen + serial check)."""
        self.stop_label_reader()
        if not self.read_names.get() or not self.serial or self.scanned_serial != self.serial:
            return
        self.label_stop = stop = threading.Event()
        gen, serial = self.label_gen, self.serial
        # last known phone language: saved names show at once, before getprop answers
        self.label_locale = self.labels.get("__locale__:" + serial) or {}
        snapshot = {p: {"path": a.get("path"), "system": a["system"], "version_code": str(a.get("version_code") or ""),
                        "last_update": str(a.get("last_update") or "")}
                    for p, a in self.apps.items() if not a.get("removed") and APK_PATH_RE.match(a.get("path") or "")}
        budget = label_budget_mb(sa.load_sec_config()) << 20
        self._label_thread = threading.Thread(target=self._label_worker_thread,
                                              args=(gen, serial, snapshot, budget, stop), daemon=True)
        self._label_thread.start()

    def _label_worker_thread(self, gen, serial, snapshot, budget, stop):
        """Thread entry point: whatever happens inside, exactly one completion (or
        error) message is posted, so the reader can never die silently."""
        try:
            named, note = self._label_worker_run(gen, serial, snapshot, budget, stop)
        except Exception as e:
            named, note = 0, "stopped by an unexpected problem (%s: %s)" % (type(e).__name__, str(e)[:120])
        self.post(self._labels_finished, gen, serial, named, note)

    def _label_worker_run(self, gen, serial, snapshot, budget, stop):
        locale = device_locale(serial)
        self.post(self._label_locale_ready, gen, serial, locale)
        done, named, meter = set(), 0, {"used": 0}
        while not stop.is_set():
            todo = [p for p in snapshot if p not in done and not self.label_entry_valid(
                self.labels.get(p), snapshot[p], locale)]
            if not todo:
                break
            shown = self.shown_pkg                                      # selected app first
            todo.sort(key=lambda p: (p != shown, snapshot[p]["system"], p))  # then mine, then system
            batch = todo[:8]
            work = tempfile.mkdtemp(prefix="adbm_names_")
            os.chmod(work, 0o700)
            try:
                items, fails = [], {}
                for i, p in enumerate(batch):
                    if stop.is_set() or meter["used"] >= budget:
                        break
                    done.add(p)
                    try:
                        parts = read_label_parts(serial, snapshot[p]["path"], work, "a%d" % i, meter)
                        items.append({"id": p, "manifest": parts["manifest"], "arsc": parts["arsc"]})
                    except sa.LabelError as e:          # the APK itself can't be read: remember it
                        fails[p] = {"label": None, "match": None, "error": str(e)[:200]}
                    except (AdbError, OSError):
                        pass                             # connection/disk trouble: try again next time
                if stop.is_set():
                    return named, ""
                results = dict(fails)
                if items:
                    results.update(sa.run_label_worker(items, locale))
                named += sum(1 for r in results.values() if r.get("label"))
                if results:
                    self.post(self._labels_ready, gen, serial, locale,
                              {p: dict(r, **snapshot[p]) for p, r in results.items()})
            finally:
                shutil.rmtree(work, ignore_errors=True)
            if meter["used"] >= budget:
                return named, ("stopped at the %d MB limit for this connection - the rest continue next time"
                               % (budget >> 20))
        return named, ""

    def _label_locale_ready(self, gen, serial, locale):
        if gen != self.label_gen or serial != self.serial:
            return
        changed = locale != self.label_locale
        self.label_locale = locale
        if changed:
            self.labels.put("__locale__:" + serial, locale)
            for p in list(self.apps):
                self.refresh_row(p)

    def _labels_ready(self, gen, serial, locale, results):
        """GUI thread. Ignores anything from an older connection or a changed app."""
        if gen != self.label_gen or serial != self.serial:
            return
        for p, r in results.items():
            a = self.apps.get(p)
            if not a or a.get("path") != r.get("path") or str(a.get("version_code") or "") != r["version_code"] \
                    or str(a.get("last_update") or "") != r["last_update"]:
                continue                                           # app changed meanwhile
            entry = {"label": r.get("label"), "match": r.get("match"), "error": r.get("error", ""),
                     "version_code": r["version_code"], "last_update": r["last_update"],
                     "apk_path": r["path"], "locale": locale, "source": "apk",
                     "read": time.strftime("%Y-%m-%d %H:%M")}
            self.labels.put(p, entry)
            self.refresh_row(p)
            if self.shown_pkg == p:
                self.render(p)

    def _labels_finished(self, gen, serial, named, note):
        if gen != self.label_gen or serial != self.serial:
            return
        if named or note:
            self.app.info("App names read from the phone: %d%s" % (named, (" - " + note) if note else ""))

    @staticmethod
    def origin_state(a):
        """Three-state install origin: True store, False sideload, None unknown.
        Absence of an installer is NOT proof of sideloading -> None."""
        if a["system"]:
            return None
        inst = (a.get("installer") or "").strip()
        if not inst:
            return None
        if inst in sa.STORES:
            return True
        if inst in sa.FILE_INSTALLERS:
            return False
        return None

    @staticmethod
    def hidden_state(a):
        """Three-state hidden: True no icon, False has icon, None unknown."""
        icon = a.get("icon")
        return (not icon) if icon is not None else None

    def app_warnings(self, a):
        """Independent evidence worth flagging REGARDLESS of built-in knowledge.
        Returns a list of (level, text). Used so a known package name can't hide a
        suspicious installer, a missing launcher icon, or failed inspection."""
        if a["system"] or a.get("removed"):
            return []
        warns = []
        origin = self.origin_state(a)
        hidden = self.hidden_state(a)
        known = kb.lookup(a["package"])
        is_known_exact = bool(known and known.get("exact"))
        if origin is False:
            warns.append((kb.CAUTION, "Installed from an APK/ADB rather than a recognised store - "
                                      "verify the source if you don't recognise it."))
        elif origin is None and a.get("installer", "") == "":
            warns.append((kb.UNKNOWN, "Its installation source couldn't be determined."))
        if hidden is True:
            warns.append((kb.CAUTION, "It has no icon in the app drawer. Normal for keyboards, "
                                      "plugins and some tools, but worth confirming."))
        elif hidden is None:
            warns.append((kb.UNKNOWN, "Couldn't check whether it has a launcher icon."))
        # A KNOWN package name arriving from an unexpected route is the impersonation
        # case - call it out explicitly, since the built-in label would look reassuring.
        if is_known_exact and (origin is False or hidden is True):
            warns.insert(0, (kb.CAUTION, "This package name is a known app, but the installed copy "
                                         "arrived in an unexpected way (see below). If you didn't "
                                         "install it from the usual place, it may be impersonating "
                                         "the real app - check it in the Security tab."))
        return warns

    def assess(self, a):
        """(risk, what, if_off) from built-in knowledge + origin/hidden evidence.
        Independent warnings are returned separately by app_warnings()."""
        k = kb.lookup(a["package"])
        if k:
            risk, what, if_off = k["risk"], k["what"], k["if_off"]
        else:
            risk, if_off = kb.guess(a["package"], a["system"],
                                    from_store=self.origin_state(a), hidden=self.hidden_state(a))
            what = None
        # NOTE: no blanket CRITICAL->CAUTION downgrade for user apps. A user-
        # installed app can genuinely be critical/high-risk; the built-in list
        # and in_use logic set risk on evidence, not on system-vs-user status.
        if a["in_use"]:
            risk = kb.CRITICAL
            if_off = ("This is the %s you are using right now. Turning it off could leave "
                      "you without one. Switch to another %s first."
                      % (a["in_use"], a["in_use"]))
        return risk, what, if_off

    # ---- list ------------------------------------------------------------

    def matches(self, a, q, mode):
        if q and q not in a["package"].lower() and q not in self.label(a["package"]).lower():
            return False
        if mode == "Only ON":
            return not a["disabled"] and not a.get("removed")
        if mode == "Only OFF":
            return a["disabled"] and not a.get("removed")
        if mode == "Only removed":
            return bool(a.get("removed"))
        if mode == "Only Google":
            return a["group"] == "google"
        if mode == "Only system":
            return a["system"]
        if mode == "Only installed by me":
            return not a["system"]
        if mode == "Not looked up yet":
            return self.cache.get(a["package"]) is None
        if mode == "No built-in notes":
            k = kb.lookup(a["package"])
            return not (k and k.get("exact"))
        if mode == "Checked by AI":
            return bool(self.ai_answers(a["package"]))
        if mode == "AIs disagree":
            return self.ai_disagree(a["package"])
        return True

    def row_values(self, a):
        risk = self.assess(a)[0]
        gone = a.get("removed")
        tags = [risk] + (["off"] if a["disabled"] or gone else [])
        state = "REMOVED" if gone else ("OFF" if a["disabled"] else "on")
        return (state, kb.RISK_SHORT[risk], a["package"]), tags

    def populate(self):
        keep = set(self.tree.selection())
        was_open = {iid for iid in self.tree.get_children() if self.tree.item(iid, "open")}
        self.tree.delete(*self.tree.get_children())
        q = self.search_var.get().strip().lower()
        mode = self.show_var.get()
        shown = 0
        for gkey, gname in GROUPS:
            pkgs = [p for p, a in self.apps.items() if a["group"] == gkey and self.matches(a, q, mode)]
            if not pkgs:
                continue
            gid = "g:" + gkey
            is_open = bool(q) or mode != "All apps" or gid in was_open or \
                (self.first_fill and gkey == "google")
            self.tree.insert("", "end", iid=gid, text="%s  (%d)" % (gname, len(pkgs)),
                             open=is_open, tags=("group",))
            visible = set(pkgs)
            roots = [p for p in pkgs if self.parent_of.get(p) not in visible]

            def add(pkg, parent):
                vals, tags = self.row_values(self.apps[pkg])
                iid = "p:" + pkg
                self.tree.insert(parent, "end", iid=iid, text=self.label(pkg),
                                 values=vals, tags=tags, open=bool(q))
                kids = [c for c in self.kids.get(pkg, []) if c in visible]
                for c in sorted(kids, key=lambda x: self.label(x).lower()):
                    add(c, iid)

            for p in sorted(roots, key=lambda x: self.label(x).lower()):
                add(p, gid)
            shown += len(pkgs)
        if self.apps:
            self.first_fill = False
        for iid in keep:
            if self.tree.exists(iid):
                self.tree.selection_add(iid)
        self.update_summary(shown)

    def update_summary(self, shown=None):
        if not self.apps:
            self.summary.configure(text="No apps loaded" if self.serial else "No device")
            return
        p = self.props
        dev = " ".join(x for x in (p.get("maker", "").capitalize(), p.get("model", "")) if x)
        off = sum(1 for a in self.apps.values() if a["disabled"] and not a.get("removed"))
        gone = sum(1 for a in self.apps.values() if a.get("removed"))
        txt = "%s  ·  Android %s  ·  %d apps, %d off" % (dev or self.serial, p.get("release", "?"),
                                                        len(self.apps) - gone, off)
        if gone:
            txt += ", %d removed" % gone
        if shown is not None and shown != len(self.apps):
            txt += "  ·  showing %d" % shown
        self.summary.configure(text=txt)

    def refresh_row(self, pkg):
        iid = "p:" + pkg
        if pkg in self.apps and self.tree.exists(iid):
            vals, tags = self.row_values(self.apps[pkg])
            self.tree.item(iid, text=self.label(pkg), values=vals, tags=tags)

    def inspect_selected(self):
        """Open the static code inspector for ONE selected app (nothing runs until
        the user presses 'Inspect now' in that window)."""
        pkgs = self.selected_pkgs()
        if len(pkgs) != 1:
            self.app.info("Select exactly one app to inspect (not a group heading)")
            return
        pkg = pkgs[0]
        if not self.serial:
            self.app.error("No device connected - pick one at the top")
            return
        if self.apps[pkg].get("removed"):
            self.app.info("That app is removed for this user - there's nothing installed to inspect")
            return
        win = self._inspect_wins.get(pkg)
        if win is not None and win.alive():
            win.lift()
            return
        self._inspect_wins[pkg] = InspectWindow(self.app.root, self.app, self.serial, pkg,
                                                dict(self.apps[pkg]), self.label(pkg))

    def selected_pkgs(self):
        return [iid[2:] for iid in self.tree.selection() if iid.startswith("p:")
                and iid[2:] in self.apps]

    def on_select(self, event=None):
        pkgs = self.selected_pkgs()
        if not pkgs:
            return
        pkg = self.tree.focus()[2:] if self.tree.focus().startswith("p:") else pkgs[0]
        if pkg not in self.apps:
            pkg = pkgs[0]
        self.render(pkg)
        if self.cache.get(pkg) is None and pkg not in self.fetching:
            self.fetch_one(pkg)

    def on_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if iid and iid not in self.tree.selection():
            self.tree.selection_set(iid)
            self.tree.focus(iid)
        has = bool(self.selected_pkgs())
        st = "normal" if has and not self.job else "disabled"
        m = tk.Menu(self, tearoff=0)
        m.add_command(label="Turn OFF", command=lambda: self.change(False), state=st)
        m.add_command(label="Turn ON", command=lambda: self.change(True), state=st)
        m.add_separator()
        m.add_command(label="Uninstall ...", command=self.uninstall_selected, state=st)
        m.add_command(label="Restore removed", command=self.restore_selected, state=st)
        m.add_command(label="Save APK to this PC ...", command=self.save_apks, state=st)
        m.add_separator()
        m.add_command(label="Look up online again", command=self.lookup_selected, state=st)
        m.add_command(label="Copy package name", command=self.copy_name,
                      state="normal" if has else "disabled")
        try:
            m.tk_popup(event.x_root, event.y_root)
        finally:
            m.grab_release()

    def show_package(self, pkg):
        """Select one package in the list (used by the Network tab)."""
        if pkg not in self.apps:
            if self.scanned_serial != self.serial or self.job:
                self.select_after_scan = [pkg]   # select it once the list is read
                self.select_quietly = True
                if not self.job:
                    self.scan()
            else:
                self.app.info("%s isn't in the app list" % pkg)
            return
        self.search_var.set("")
        self.show_var.set(SHOW_CHOICES[0])
        self.populate()
        iid = "p:" + pkg
        parent = self.tree.parent(iid)
        while parent:
            self.tree.item(parent, open=True)
            parent = self.tree.parent(parent)
        self.tree.selection_set(iid)
        self.tree.focus(iid)
        self.tree.see(iid)
        self.render(pkg)

    def copy_name(self):
        pkgs = self.selected_pkgs()
        if pkgs:
            self.clipboard_clear()
            self.clipboard_append("\n".join(pkgs))
            self.app.info("Copied %s" % (pkgs[0] if len(pkgs) == 1 else "%d names" % len(pkgs)))

    # ---- details panel ---------------------------------------------------

    def render(self, pkg):
        self.shown_pkg = pkg
        t = self.details
        t.configure(state="normal")
        t.delete("1.0", "end")
        w = lambda text, tag=(): t.insert("end", text, tag)  # noqa: E731
        a = self.apps.get(pkg) if pkg else None
        if not a:
            if not self.serial:
                w("No device connected.\n\n", "h2")
                w("Plug the device in with USB debugging on, then pick it at the top.")
            elif not self.apps:
                w("Press 'Scan apps' to read the list of apps on the device.", "h2")
            else:
                w("Click an app on the left.\n\n", "h2")
                w("Colours in the list:\n")
                w(kb.RISK_TEXT[kb.SAFE] + "\n", "safe")
                w("   only that app's own features go away\n")
                w(kb.RISK_TEXT[kb.CAUTION] + "\n", "caution")
                w("   other things may stop working - read the note\n")
                w(kb.RISK_TEXT[kb.CRITICAL] + "\n", "critical")
                w("   the device may misbehave or not start - leave it on\n")
                w(kb.RISK_TEXT[kb.UNKNOWN] + "\n", "unknown")
                w("   not enough is known to vouch for it - look it up before trusting it\n\n")
                w("Grey rows are apps that are turned off.\n"
                  "Turning an app off never deletes it or its data; you can turn it back on here.",
                  "dim")
            t.configure(state="disabled")
            return

        risk, what, if_off = self.assess(a)
        info = self.cache.get(pkg)
        play = (info or {}).get("play") or {}

        w(self.label(pkg) + "\n", "h1")
        w(pkg + "\n\n", "dim")
        state = "OFF (turned off)" if a["disabled"] else "ON"
        if a.get("removed"):
            state = "REMOVED for your user"
        origin = "came with the device" if a["system"] else "installed by you"
        if a["system"] and a["updated_system"]:
            origin += " (updated since)"
        line = "It is %s  ·  %s" % (state, origin)
        if a["version"]:
            line += "  ·  version %s" % a["version"]
        w(line + "\n")
        if a["in_use"]:
            w("This is the %s you are using right now.\n" % a["in_use"], "warn")
        if a.get("removed"):
            w("It's still inside the system - 'Restore removed' brings it back.\n", "dim")
        w("\n")
        w(kb.RISK_TEXT[risk] + "\n", risk)
        warns = self.app_warnings(a)
        if warns:
            w("\nWorth checking\n", "h2")
            for lvl, text in warns:
                w(("\u26a0 " if lvl == kb.CAUTION else "\u2753 ") + text + "\n",
                  "caution" if lvl == kb.CAUTION else "unknown")

        w("What it does\n", "h2")
        if what:
            w(what + "\n")
        if play.get("found"):
            src = "From Google Play"
            extra = [x for x in (play.get("category"), ("by " + play["author"])
                                 if play.get("author") else "") if x]
            if extra:
                src += " (" + ", ".join(extra) + ")"
            w(("\n" if what else "") + src + ":\n", "dim")
            w(self.short_desc(play.get("description", "")) + "\n")
        elif info and info.get("web"):
            w(("\n" if what else "") + "Not on Google Play. What the web says (not checked):\n", "dim")
            for r in info["web"]:
                w("• " + r["title"] + "\n")
                if r.get("snippet"):
                    w("   " + r["snippet"] + "\n")
                w("   " + r["url"] + "\n", "dim")
        elif pkg in self.fetching:
            w(("\n" if what else "") + "Looking it up online ...\n", "dim")
        elif info:
            if info.get("error"):
                w(("\n" if what else "") + "Couldn't look it up: %s\n" % info["error"], "dim")
            elif not what:
                w("Not on Google Play and the web search found nothing.\n", "dim")
        elif not what:
            w("Not looked up yet.\n", "dim")

        self.render_ai(pkg, risk, w)

        w("If you turn it off\n", "h2")
        w(if_off + "\n")
        w("It is not deleted - you can turn it back on here anytime.\n", "dim")

        nice = [kb.PERM_TEXT[p] for p in a["perms"] if p in kb.PERM_TEXT]
        w("It asks permission to\n", "h2")
        if nice:
            for n in sorted(set(nice)):
                w("• " + n + "\n")
        elif a["perms"]:
            w("Only technical/system permissions (nothing personal).\n")
        else:
            w("Nothing listed.\n", "dim")

        if self.show_tech.get():
            w("Technical details\n", "h2")
            rows = [("Package", pkg), ("UID", a["uid"]), ("Version name", a["version"]),
                    ("Version code", a["version_code"]), ("Target SDK", a["target_sdk"]),
                    ("APK path", a["path"]), ("Installer", a["installer"]),
                    ("First installed", a["first_install"]), ("Last updated", a["last_update"]),
                    ("Group", a["group"]), ("Parent package", self.parent_of.get(pkg, "")),
                    ("Sub-packages", ", ".join(sorted(self.kids.get(pkg, []))))]
            if info:
                rows.append(("Looked up", info.get("fetched", "")))
                if play.get("url"):
                    rows.append(("Play page", play["url"]))
            for k, v in rows:
                if v:
                    w("%-16s %s\n" % (k + ":", v), "mono")
            for prov, r in sorted((self.ai_cache.get(pkg) or {}).items()):
                u = r.get("usage") or {}
                w("%-16s %s, %s, %s searches, %s in / %s out tokens%s\n" % (
                    "AI (" + prov + "):", r.get("model", ""), r.get("when", ""),
                    u.get("searches", "?"), u.get("input_tokens", "?"),
                    u.get("output_tokens", "?"),
                    ", ERROR: " + r["error"] if r.get("error") else ""), "mono")
                if r.get("raw"):
                    w("  raw reply: %s\n" % r["raw"][:1500], "mono")
            if a["perms"]:
                w("\nRequested permissions (%d):\n" % len(a["perms"]), "mono")
                granted = set(a["granted"])
                for p in sorted(a["perms"]):
                    w("  %s%s\n" % (p, "  [granted]" if p in granted else ""), "mono")
        t.configure(state="disabled")

    # ---- installing APKs -------------------------------------------------

    def choose_apks(self):
        if not self.serial:
            self.app.error("No device connected - pick one at the top")
            return
        paths = filedialog.askopenfilenames(
            parent=self.app.root, title="Choose APK files to install on the device",
            initialdir=self.app.left.path if self.app.left.fs else os.path.expanduser("~"),
            filetypes=[("Android apps", "*.apk *.apks *.xapk *.apkm"), ("All files", "*")])
        if paths:
            self.install_files(list(paths))

    def install_files(self, paths):
        if not self.serial:
            self.app.error("No device connected - pick one at the top")
            return
        if self.job:
            self.app.info("Busy: %s - wait for it to finish or press Stop" % self.job)
            return
        paths = [p for p in paths if p.lower().endswith(APK_EXTS)]
        if not paths:
            self.app.info("Pick .apk, .apks, .xapk or .apkm files")
            return
        jobs = plan_installs(paths)
        try:
            sdk = int(self.props.get("sdk") or 0)
        except ValueError:
            sdk = 0
        if not sdk:
            try:
                sdk = int(adb_shell(self.serial, "getprop ro.build.version.sdk", timeout=15)[1].strip() or 0)
            except (AdbError, ValueError):
                sdk = 0
        InstallDialog(self.app.root, jobs, sdk,
                      lambda opts: self.start_job("installing apps", self._install_worker,
                                                  self.serial, jobs, opts, sdk))

    def _install_worker(self, serial, jobs, opts, sdk):
        flags = []
        if opts.get("replace"):
            flags.append("-r")
        if opts.get("downgrade"):
            flags.append("-d")
        if opts.get("grant") and sdk >= 23:
            flags.append("-g")
        try:
            before = set(pm_list(serial, "-3"))
        except AdbError:
            before = None
        abis = device_abis(serial)
        work = tempfile.mkdtemp(prefix="adbmgr_apk_")
        results = []
        try:
            for i, job in enumerate(jobs):
                if self.stop.is_set():
                    results.append((job["label"], False, "stopped before starting"))
                    continue
                head = "Installing %d/%d: %s" % (i + 1, len(jobs), job["label"])
                self.post(self.app.info, head + " ...")
                obbs, notes = [], []
                if job.get("bundle"):
                    self.post(self.app.info, head + " - unpacking ...")
                    sub = tempfile.mkdtemp(dir=work)
                    try:
                        apks, obbs, pkg, skipped = unpack_bundle(job["bundle"], abis, sub)
                    except (ValueError, OSError, zipfile.BadZipFile, KeyError) as e:
                        results.append((job["label"], False, str(e)))
                        continue
                    if skipped:
                        notes.append("left out %d part(s) for other processors" % len(skipped))
                else:
                    apks = job["apks"]
                    if len(apks) > 1 and abis:  # loose split parts: drop other CPU types
                        fit = [a for a in apks if not split_abi(a) or split_abi(a) in abis]
                        if len(fit) < len(apks):
                            notes.append("left out %d part(s) for other processors"
                                         % (len(apks) - len(fit)))
                        apks = fit
                if len(apks) > 1 and sdk and sdk < 21:
                    results.append((job["label"], False,
                                    "split apps need Android 5 or newer"))
                    continue
                verb = "install-multiple" if len(apks) > 1 else "install"
                cmd = [ADB, "-s", serial, verb] + flags + apks

                def on_pct(p, head=head):
                    self.post(self.app.info, "%s  (%d%%)" % (head, p))
                rc, text = adb_pty(cmd, on_pct, self.stop)
                if rc == -1:
                    results.append((job["label"], False, "stopped (it may or may not have installed)"))
                    continue
                ok, msg = explain_install(text)
                if ok and obbs:
                    for local, remote in obbs:
                        self.post(self.app.info, head + " - copying game data ...")
                        try:
                            adb_shell(serial, "mkdir -p " + shlex.quote(posixpath.dirname(remote)))
                        except AdbError as e:
                            notes.append("game data copy failed: %s" % e)
                            break
                        prc, pmsg = adb_transfer([ADB, "-s", serial, "push", local, remote],
                                                 on_pct, self.stop)
                        if prc != 0:
                            notes.append("game data copy failed: %s" % pmsg)
                            break
                    else:
                        notes.append("game data copied")
                if notes:
                    msg += " - " + "; ".join(notes)
                log_action(serial, "install", job["label"], ok, msg)
                results.append((job["label"], ok, msg))
        finally:
            shutil.rmtree(work, ignore_errors=True)
        new = []
        if before is not None:
            try:
                new = sorted(set(pm_list(serial, "-3")) - before)
            except AdbError:
                pass
        self.post(self._install_done, results, new)

    def _install_done(self, results, new):
        self.end_job()
        good = [r for r in results if r[1]]
        bad = [r for r in results if not r[1]]
        if bad:
            self.app.error("%d installed, %d failed - %s: %s"
                           % (len(good), len(bad), bad[0][0], bad[0][2]))
            if len(results) > 1 or len(bad[0][2]) > 80:
                messagebox.showinfo(
                    "Install results",
                    "\n\n".join("%s %s\n   %s" % ("\u2705" if ok else "\u26d4", lbl, msg)
                                for lbl, ok, msg in results), parent=self.app.root)
        else:
            self.app.info("Done: %s" % "; ".join("%s %s" % (lbl, msg) for lbl, ok, msg in results))
        if good and self.scanned_serial == self.serial:
            self.select_after_scan = new
            self.message_after_scan = ("error", self.app.status.cget("text")) if bad else \
                ("info", "Done: %s" % "; ".join("%s %s" % (lbl, msg) for lbl, ok, msg in results))
            self.scan()

    # ---- uninstalling / restoring ----------------------------------------

    def uninstall_selected(self):
        pkgs = [p for p in self.selected_pkgs() if not self.apps[p].get("removed")]
        if not pkgs:
            self.app.info("Select one or more installed apps first (not removed ones or headings)")
            return
        items = []
        for p in pkgs:
            a = self.apps[p]
            risk, _, if_off = self.assess(a)
            items.append({"pkg": p, "label": self.label(p), "system": a["system"],
                          "updated": a["system"] and a["updated_system"], "risk": risk,
                          "if_off": if_off, "version": a["version"]})
        try:
            sdk = int(self.props.get("sdk") or 0)
        except ValueError:
            sdk = 0
        UninstallDialog(self.app.root, items, sdk,
                        lambda opts: self.start_job("removing apps", self._uninstall_worker,
                                                    self.serial, items, opts))

    def _uninstall_worker(self, serial, items, opts):
        results = []
        backup_root = os.path.join(BACKUP_DIR, re.sub(r"[^A-Za-z0-9._-]+", "_", serial))
        for i, it in enumerate(items):
            if self.stop.is_set():
                break
            p = it["pkg"]
            head = "Removing %d/%d: %s" % (i + 1, len(items), it["label"])
            self.post(self.app.info, head + " ...")
            note = ""
            if not it["system"]:
                mode = "full"
                if opts.get("backup"):
                    self.post(self.app.info, head + " - saving a copy on this PC ...")
                    ok, where = save_apk_copy(serial, p, it["version"], backup_root, self.stop)
                    if not ok:
                        results.append((p, False, "not removed, because saving the copy failed: "
                                        + where))
                        continue
                    note = " - copy saved in " + where
            elif it["updated"] and opts.get("updated_mode") == "updates":
                mode = "updates"
            else:
                mode = "user"
            what, orig, want = {"full": ("uninstall-full", "installed", "absent"),
                                "user": ("remove-for-user", "installed", "removed"),
                                "updates": ("uninstall-updates", None, None)}[mode]
            op = journal_begin(serial, 0, p, what, orig, want, source="apps")
            if op is False:
                results.append((p, False, journal_refusal(p)["message"]))
                continue
            if op == NOOP:
                results.append((p, True, ALREADY_MSG))
                continue
            ok, msg = pm_uninstall(serial, p, mode, opts.get("keep_data", False))
            if not journal_finish(serial, op, ok):
                msg += KEPT_MSG
            log_action(serial, "uninstall-" + mode, p, ok, msg + (note if ok else ""))
            results.append((p, ok, msg + (note if ok else "")))
        self.post(self._uninstall_done, serial, results)

    def _uninstall_done(self, serial, results):
        self.end_job()
        good = [r for r in results if r[1]]
        bad = [r for r in results if not r[1]]
        lines = "\n\n".join("%s %s\n   %s" % ("\u2705" if ok else "\u26d4", self.label(p), m)
                            for p, ok, m in results)
        if bad:
            self.app.error("%d removed, %d failed - %s: %s" % (len(good), len(bad),
                                                               self.label(bad[0][0]), bad[0][2]))
        else:
            self.app.info("Done: %d app(s) removed" % len(good))
        if len(results) > 1 or bad or any("copy saved" in m for p, ok, m in results):
            messagebox.showinfo("Uninstall results", lines, parent=self.app.root)
        if good and serial == self.serial:
            self.message_after_scan = (("error" if bad else "info"), self.app.status.cget("text"))
            self.scan()

    def restore_selected(self):
        pkgs = [p for p in self.selected_pkgs() if self.apps[p].get("removed")]
        if not pkgs:
            removed = sorted(p for p, a in self.apps.items() if a.get("removed"))
            if not removed:
                self.app.info("No removed apps on this device - nothing to restore")
                return
            if not messagebox.askyesno(
                    "Restore", "Nothing removed is selected. Restore all %d removed app(s)?\n\n%s"
                    % (len(removed), "\n".join("\u2022 " + self.label(p) for p in removed[:25])
                       + ("\n..." if len(removed) > 25 else "")), parent=self.app.root):
                return
            pkgs = removed
        self.start_job("restoring apps", self._restore_worker, self.serial, pkgs)

    def _restore_worker(self, serial, pkgs):
        results = []
        for i, p in enumerate(pkgs):
            if self.stop.is_set():
                break
            self.post(self.app.info, "Restoring %d/%d: %s ..." % (i + 1, len(pkgs), p))
            op = journal_begin(serial, 0, p, "restore", "removed", "installed", source="apps")
            if op is False:
                results.append((p, False, journal_refusal(p)["message"]))
                continue
            if op == NOOP:
                results.append((p, True, ALREADY_MSG))
                continue
            ok, msg = pm_restore(serial, p)
            if not journal_finish(serial, op, ok):
                msg += KEPT_MSG
            log_action(serial, "restore", p, ok, msg)
            results.append((p, ok, msg))
        self.post(self._restore_done, serial, results)

    def _restore_done(self, serial, results):
        self.end_job()
        good = [r for r in results if r[1]]
        bad = [r for r in results if not r[1]]
        if bad:
            self.app.error("%d restored, %d failed - %s: %s" % (len(good), len(bad),
                                                                self.label(bad[0][0]), bad[0][2]))
            if len(bad) > 1:
                messagebox.showerror("Some apps could not be restored",
                                     "\n".join("%s: %s" % (self.label(p), m) for p, ok, m in bad),
                                     parent=self.app.root)
        else:
            self.app.info("Done: %d app(s) restored" % len(good))
        if good and serial == self.serial:
            self.message_after_scan = (("error" if bad else "info"), self.app.status.cget("text"))
            self.scan()

    def save_apks(self):
        pkgs = [p for p in self.selected_pkgs() if not self.apps[p].get("removed")]
        if not pkgs:
            self.app.info("Select one or more installed apps first")
            return
        dest = filedialog.askdirectory(parent=self.app.root, title="Save the APK file(s) where?",
                                       initialdir=self.app.left.path)
        if dest:
            self.start_job("saving APKs", self._save_worker, self.serial, pkgs, dest)

    def _save_worker(self, serial, pkgs, dest):
        results = []
        for i, p in enumerate(pkgs):
            if self.stop.is_set():
                break
            self.post(self.app.info, "Saving %d/%d: %s ..." % (i + 1, len(pkgs), p))
            ok, where = save_apk_copy(serial, p, self.apps[p]["version"], dest, self.stop)
            results.append((p, ok, where))
        self.post(self._save_done, results, dest)

    def _save_done(self, results, dest):
        self.end_job()
        bad = [r for r in results if not r[1]]
        if bad:
            self.app.error("%d saved, %d failed - %s: %s" % (len(results) - len(bad), len(bad),
                                                             bad[0][0], bad[0][2]))
        else:
            self.app.info("Saved %d app(s) in %s" % (len(results), dest))
        if self.app.left.fs and os.path.abspath(self.app.left.path) == os.path.abspath(dest):
            self.app.left.refresh()

    # ---- AI research -----------------------------------------------------

    def update_ai_label(self):
        cfg = ai.load_config()
        main = cfg.get("provider", "anthropic")
        if main not in ai.PROVIDERS:
            main = "anthropic"
        other = self.second_provider(cfg)

        def one(p):
            return "%s %s%s" % (p.capitalize() if p != "openai" else "OpenAI",
                                ai.model_of(cfg, p), "" if ai.api_key(cfg, p) else " (no key)")
        self.ai_label.configure(text="Main: %s   \u00b7   2nd opinion: %s" % (one(main), one(other)))

    @staticmethod
    def second_provider(cfg):
        main = cfg.get("provider", "anthropic")
        second = cfg.get("second_opinion")
        if second not in ai.PROVIDERS or second == main:
            second = [p for p in ai.PROVIDERS if p != main][0]
        return second

    def ai_answers(self, pkg):
        """{provider: result} for the providers that gave a usable answer."""
        return {p: r for p, r in (self.ai_cache.get(pkg) or {}).items()
                if isinstance(r, dict) and r.get("answer")}

    def ai_disagree(self, pkg):
        verdicts = {r["answer"]["verdict"] for r in self.ai_answers(pkg).values()
                    if r["answer"]["verdict"] != "unknown"}
        return len(verdicts) > 1

    def open_ai_settings(self):
        win = getattr(self, "_ai_win", None)
        if win is not None and win.winfo_exists():
            win.lift()
            return
        self._ai_win = AISettings(self.app.root, self.update_ai_label)

    def _has_cached_answer(self, pkg, provider):
        """True if there's already a usable saved answer for this package+provider."""
        r = (self.ai_cache.get(pkg) or {}).get(provider)
        return isinstance(r, dict) and bool(r.get("answer"))

    def ask_ai(self, compare, refresh=False):
        pkgs = self.selected_pkgs()
        if not pkgs:
            self.app.info("Select one or more apps first (not the group headings)")
            return
        cfg = ai.load_config()
        main = cfg.get("provider", "anthropic")
        if main not in ai.PROVIDERS:
            main = "anthropic"
        provs = [main] + ([self.second_provider(cfg)] if compare else [])
        missing = [p for p in provs if not ai.api_key(cfg, p)]
        if missing:
            messagebox.showinfo("API key needed",
                                "There's no API key for %s yet.\n\nAdd it in the AI settings window."
                                % " and ".join(ai.PROVIDERS[p]["label"] for p in missing),
                                parent=self.app.root)
            self.open_ai_settings()
            return
        # Build only the (pkg, provider) pairs that actually need an API call.
        # Unless this is an explicit refresh, reuse any usable cached answer.
        tasks = {}
        reused = 0
        for pkg in pkgs:
            need = [p for p in provs if refresh or not self._has_cached_answer(pkg, p)]
            reused += len(provs) - len(need)
            if need:
                tasks[pkg] = need
        if not tasks:
            self.app.info("Already researched - showing the saved answer%s (use 'Refresh' to "
                          "re-ask)" % ("s" if len(pkgs) > 1 else ""))
            self.render(self.shown_pkg)
            return
        n = sum(len(v) for v in tasks.values())
        note = ("" if not reused else "  (%d already cached, skipped)" % reused)
        verb = "Refresh" if refresh else "Ask AI"
        if n > 2 and not messagebox.askyesno(
                verb, "This sends %d request(s)%s.\n\nEach runs several web searches and is billed "
                "to your API account. Answers are saved, so you only pay once per app unless you "
                "refresh.\n\nGo ahead?" % (n, note), parent=self.app.root):
            return
        task_pkgs = list(tasks)
        apps = {p: dict(self.apps[p]) for p in task_pkgs}
        self.start_job("asking the AI", self._ai_worker, task_pkgs, tasks, cfg, dict(self.props), apps)

    def refresh_ai(self):
        self.ask_ai(False, refresh=True)

    def _ai_worker(self, pkgs, tasks, cfg, props, apps):
        failed = done = 0
        for i, pkg in enumerate(pkgs):
            if self.stop.is_set():
                break
            provs = tasks[pkg]   # only the providers that actually need calling
            names = " and ".join(ai.PROVIDERS[p]["label"] for p in provs)
            self.post(self.app.info, "Asking %s about %s (%d/%d) - this can take a minute or two ..."
                      % (names, pkg, i + 1, len(pkgs)))
            results = {}
            threads = []
            for prov in provs:  # both AIs work at the same time
                def run(prov=prov):
                    results[prov] = ai.research(prov, cfg, apps[pkg], props)
                t = threading.Thread(target=run, daemon=True)
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
            for prov in provs:
                res = results.get(prov) or {"provider": prov, "error": "no result"}
                if res.get("error"):
                    failed += 1
                self.post(self._ai_result, pkg, prov, res)
            done += 1
        self.post(self._ai_done, done, len(pkgs), failed)

    def _report_store_problems(self):
        """Tell the user once if a saved-data file was damaged or unreadable at start."""
        stores = [self.cache, self.turned_off, self.ai_cache, self.labels]
        ar = getattr(self.app, "autorun_tab", None)
        if ar is not None:
            stores.append(ar.saved)
        for st in stores:
            if st.load_problem:
                self.app.error("Saved data problem: " + st.load_problem)

    def _store_saved(self, store, ok, what):
        """Report a failed save (once per store until it works again)."""
        if ok:
            self._store_warned.discard(store.path)
            return True
        if store.path not in self._store_warned:
            self._store_warned.add(store.path)
            self.app.error("Couldn't save %s to disk (%s). It's kept for this session only."
                           % (what, store.last_error or "unknown error"))
        return False

    def _ai_result(self, pkg, prov, res):
        # merge() may be replayed later (JsonStore pending op), so it must only use
        # frozen values: a private copy of the result, never the caller's object.
        res = copy.deepcopy(res)

        def merge(entry):
            entry = entry if isinstance(entry, dict) else {}
            old = entry.get(prov)
            if res.get("error") and isinstance(old, dict) and old.get("answer"):
                old = dict(old)              # keep the older good answer
                old["last_error"] = res["error"]
                entry[prov] = old
            else:
                entry[prov] = copy.deepcopy(res)
            return entry
        self._store_saved(self.ai_cache, self.ai_cache.update(pkg, merge, {}),
                          "the AI answer for %s" % pkg)
        if self.shown_pkg == pkg:
            self.render(pkg)

    def _ai_done(self, done, n, failed):
        self.end_job()
        if self.show_var.get() in ("Checked by AI", "AIs disagree"):
            self.populate()
        if failed:
            self.app.error("AI research finished for %d of %d app(s), %d answer(s) failed - "
                           "click the app to see why" % (done, n, failed))
        else:
            self.app.info("AI research finished for %d of %d app(s)%s"
                          % (done, n, " (stopped)" if done < n else ""))

    def render_ai(self, pkg, risk, w):
        results = {p: r for p, r in (self.ai_cache.get(pkg) or {}).items() if isinstance(r, dict)}
        if not results:
            return
        cfg = ai.load_config()
        main = cfg.get("provider", "anthropic")
        label = lambda p: ai.PROVIDERS.get(p, {}).get("label", p)  # noqa: E731
        w("What the AI research found\n", "h2")
        answers = self.ai_answers(pkg)
        if len(answers) > 1:
            if self.ai_disagree(pkg):
                w("The AIs disagree: " + "; ".join(
                    "%s says %s" % (label(p), AI_VERDICT_TEXT[r["answer"]["verdict"]])
                    for p, r in sorted(answers.items())) +
                  ". Read their sources before deciding.\n", "warn")
            else:
                w("Both AIs reached the same verdict.\n", "dim")
        if risk == kb.CRITICAL and any(r["answer"]["verdict"] == "safe" for r in answers.values()):
            w("The built-in safety check says to keep this on. An AI opinion doesn't change that.\n",
              "warn")
        for prov in sorted(results, key=lambda p: (p != main, p)):
            r = results[prov]
            w("\n%s  \u00b7  %s  \u00b7  asked %s\n" % (label(prov), r.get("model", ""),
                                                        r.get("when", "")), "dim")
            if not r.get("answer"):
                w("No answer: %s\n" % (r.get("error") or "unknown problem"), "warn")
                continue
            a = r["answer"]
            note = source_check_note(a)
            has_sources = a["sources"] or any(f["source"] for f in a["independent_findings"])
            if note and (has_sources or note[1] == "warn"):
                w(*note)
            w("AI says: ", "b")
            w(AI_VERDICT_TEXT[a["verdict"]], AI_VERDICT_TAG[a["verdict"]])
            w("   (how sure: %s)\n" % a["confidence"])
            if a["summary"]:
                w(a["summary"] + "\n")
            if a["vendor_says"]:
                w("What %s says it does: " % (a["vendor"] or "the vendor"), "b")
                w(a["vendor_says"] + "\n")
            if a["independent_findings"]:
                w("What independent sources found:\n", "b")
                for f in a["independent_findings"]:
                    w("\u2022 [%s] " % BACKING_TEXT[f["backing"]], "bk_" + f["backing"])
                    w(f["finding"] + "\n")
                    if f["source"]:
                        w("    " + f["source"] + source_mark(a, f["source"]) + "\n", "dim")
            w("Data it collects or sends: ", "b")
            w(a["data_collection"] + "\n")
            if a["disagreements"] and a["disagreements"].lower().strip(". ") != "none found":
                w("Where the vendor and others differ: ", "b")
                w(a["disagreements"] + "\n")
            w("When people turned it off: ", "b")
            w(a["when_disabled"] + "\n")
            listed = {f["source"] for f in a["independent_findings"]}
            extra = [s for s in a["sources"] if s not in listed]
            if extra:
                w("Other sources:\n", "b")
                for s in extra[:8]:
                    w("    " + s + source_mark(a, s) + "\n", "dim")
            if r.get("last_error"):
                w("(Asking again failed, so this is the older answer: %s)\n" % r["last_error"], "dim")
        w("\n")

    @staticmethod
    def short_desc(text, limit=700):
        text = text.strip()
        if len(text) <= limit:
            return text
        cut = text[:limit]
        dot = max(cut.rfind(". "), cut.rfind(".\n"))
        return (cut[:dot + 1] if dot > 200 else cut.rstrip()) + " ..."

    # ---- online lookups --------------------------------------------------

    def fetch_one(self, pkg):
        """Look one app up in the background (when you click it)."""
        self.fetching.add(pkg)
        use_web = self.use_web.get()

        def work():
            res = lookup_online(pkg, use_web)
            self.post(self._fetched, pkg, res)
        threading.Thread(target=work, daemon=True).start()

    def _fetched(self, pkg, res):
        self.fetching.discard(pkg)
        if not res.get("error") or res.get("play") or res.get("web"):
            self._store_saved(self.cache, self.cache.put(pkg, res), "the lookup for %s" % pkg)
        self.refresh_row(pkg)
        if self.shown_pkg == pkg:
            if res.get("error") and not (res.get("play") or res.get("web")):
                self.render(pkg)
                self.details.configure(state="normal")
                self.details.insert("end", "\nCouldn't look it up: %s\n" % res["error"], "warn")
                self.details.configure(state="disabled")
            else:
                self.render(pkg)

    def lookup_selected(self):
        pkgs = self.selected_pkgs()
        if not pkgs:
            self.app.info("Select one or more apps first")
            return
        self.start_job("looking up apps", self._lookup_worker, pkgs, self.use_web.get())

    def lookup_all(self):
        todo = sorted(p for p in self.apps if self.cache.get(p) is None)
        if not todo:
            self.app.info("Every app has already been looked up")
            return
        if not messagebox.askyesno(
                "Look up all", "Look up %d apps online?\n\nThis takes about %d minutes "
                "(it waits between requests so Google doesn't block you). You can keep "
                "using the program and press Stop anytime. Results are saved, so it "
                "never needs to fetch the same app twice." % (len(todo), max(1, len(todo) * 3 // 60)),
                parent=self.app.root):
            return
        self.start_job("looking up apps", self._lookup_worker, todo, self.use_web.get())

    def _lookup_worker(self, pkgs, use_web):
        n = len(pkgs)
        done = 0
        for i, pkg in enumerate(pkgs):
            if self.stop.is_set():
                break
            self.post(self.app.info, "Looking up %d/%d: %s" % (i + 1, n, pkg))
            self.fetching.add(pkg)
            res = lookup_online(pkg, use_web)
            self.post(self._fetched, pkg, res)
            done += 1
            for _ in range(15):  # ~1.5 s between requests, stoppable
                if self.stop.is_set() or i == n - 1:
                    break
                time.sleep(0.1)
        self.post(self._lookup_done, done, n)

    def _lookup_done(self, done, n):
        self.end_job()
        if self.show_var.get() == "Not looked up yet":
            self.populate()
        self.app.info("Looked up %d of %d apps%s" % (done, n, " (stopped)" if done < n else ""))

    # ---- turning apps on / off -------------------------------------------

    def change(self, enable):
        pkgs = self.selected_pkgs()
        if not pkgs:
            self.app.info("Select one or more apps first (not the group headings)")
            return
        verb = "ON" if enable else "OFF"
        if not enable:
            subs = []
            for p in pkgs:
                for c in self.descendants(p):
                    if c not in pkgs and c not in subs and not self.apps[c]["disabled"]:
                        subs.append(c)
            if subs:
                ans = messagebox.askyesnocancel(
                    "Sub-packages",
                    "The selected app(s) have %d sub-package(s) that are still on, e.g.\n\n  %s\n\n"
                    "Turn those OFF too?\n\nYes = them too   No = only what I selected"
                    % (len(subs), "\n  ".join(subs[:6]) + ("\n  ..." if len(subs) > 6 else "")),
                    parent=self.app.root)
                if ans is None:
                    return
                if ans:
                    pkgs = pkgs + subs
        if any(self.apps[p].get("removed") for p in pkgs):
            pkgs = [p for p in pkgs if not self.apps[p].get("removed")]
            if not pkgs:
                self.app.info("Removed apps can't be turned on/off - use 'Restore removed' first")
                return
        pkgs = [p for p in pkgs if self.apps[p]["disabled"] == enable]  # only what needs changing
        if not pkgs:
            self.app.info("Already %s" % verb)
            return

        lines, crit = [], []
        for p in pkgs:
            risk, _, if_off = self.assess(self.apps[p])
            if not enable and risk == kb.CRITICAL:
                crit.append(p)
            mark = kb.RISK_SHORT[risk].split()[0] if not enable else "\u2022"
            lines.append("%s %s" % (mark, self.label(p)))
            if not enable and risk != kb.SAFE:
                lines.append("      " + if_off)
        if len(lines) > 24:
            lines = lines[:24] + ["... and more"]
        text = "Turn %s %s?\n\n%s\n\n" % (
            verb, "this app" if len(pkgs) == 1 else "%d apps" % len(pkgs), "\n".join(lines))
        if not enable:
            text += "Nothing is deleted. You can turn them back on here anytime."
        if crit:
            ans = simpledialog.askstring(
                "Are you sure?",
                text + "\n\n\u26d4 %d of these should stay on. Turning them off can make the "
                "device misbehave or fail to start, and you might not be able to undo it.\n\n"
                "Type YES to turn them off anyway:" % len(crit), parent=self.app.root)
            if ans != "YES":
                self.app.info("Cancelled - nothing was changed")
                return
        elif not messagebox.askyesno("Turn %s" % verb, text, parent=self.app.root,
                                     icon="question" if enable else "warning"):
            return
        self.start_job("turning apps %s" % verb, self._change_worker, self.serial, pkgs,
                       enable, self.use_root.get())

    def undo_all(self):
        mine = self.turned_off.get(self.serial or "", {}) or {}
        pkgs = [p for p in mine if p in self.apps and self.apps[p]["disabled"]]
        if not pkgs:
            self.app.info("Nothing to undo - no app this program turned off is still off")
            return
        if not messagebox.askyesno(
                "Turn back on", "Turn these %d apps back ON?\n\n%s" % (
                    len(pkgs), "\n".join("\u2022 " + self.label(p) for p in pkgs[:25]) +
                    ("\n..." if len(pkgs) > 25 else "")), parent=self.app.root):
            return
        self.start_job("turning apps ON", self._change_worker, self.serial, pkgs, True,
                       self.use_root.get())

    def _change_worker(self, serial, pkgs, enable, use_root):
        verb = "ON" if enable else "OFF"
        results = []
        for i, p in enumerate(pkgs):
            if self.stop.is_set():
                break
            self.post(self.app.info, "Turning %s %d/%d: %s" % (verb, i + 1, len(pkgs), p))
            try:
                ps = (receiver_states(serial, 0, {p}).get(p) or {}).get("pkg_state")
            except Exception:
                ps = None
            now = "off" if ps in (2, 3, 4) else "on" if ps in (0, 1) else None
            if now is None:                              # never record an assumed original
                results.append((p, False, "its current state couldn't be read, so nothing was changed"))
                continue
            op = journal_begin(serial, 0, p, "app-on" if enable else "app-off", now,
                               "on" if enable else "off", source="apps")
            if op is False:
                results.append((p, False, journal_refusal(p)["message"]))
                continue
            if op == NOOP:
                results.append((p, True, ALREADY_MSG))
                continue
            ok, msg = pm_set_enabled(serial, p, enable, use_root)
            if not journal_finish(serial, op, ok):
                msg += KEPT_MSG
            log_action(serial, "enable" if enable else "disable", p, ok, msg)
            results.append((p, ok, msg))
        try:
            disabled = set(pm_list(serial, "-d"))
        except AdbError:
            disabled = None
        self.post(self._change_done, serial, enable, results, disabled)

    def _change_done(self, serial, enable, results, disabled):
        self.end_job()
        if serial != self.serial:
            return
        # apply() may be replayed later (JsonStore pending op), so everything it
        # needs is frozen NOW: which packages changed, and the timestamp. It must
        # not read self.apps or the clock when it runs.
        stamp = time.strftime("%Y-%m-%d %H:%M")
        changed = tuple(p for p, ok, msg in results if ok and msg != ALREADY_MSG and p in self.apps)

        def apply(mine, changed=changed, stamp=stamp, enable=bool(enable)):
            mine = mine if isinstance(mine, dict) else {}
            for p in changed:
                if enable:
                    mine.pop(p, None)
                else:
                    mine[p] = stamp
            return mine
        self._store_saved(self.turned_off, self.turned_off.update(serial, apply, {}),
                          "the list of apps this program turned off (used for Undo)")
        if disabled is not None:
            for p, a in self.apps.items():
                a["disabled"] = p in disabled
        else:
            for p, ok, msg in results:
                if ok and p in self.apps:
                    self.apps[p]["disabled"] = not enable
        self.populate()
        self.render(self.shown_pkg)
        good = [p for p, ok, m in results if ok]
        bad = [(p, describe_pm_error(m)) for p, ok, m in results if not ok]
        verb = "on" if enable else "off"
        if bad:
            self.app.error("%d turned %s, %d failed - %s: %s"
                           % (len(good), verb, len(bad), self.label(bad[0][0]), bad[0][1]))
            if len(bad) > 1:
                messagebox.showerror("Some apps could not be changed",
                                     "\n".join("%s: %s" % (self.label(p), m) for p, m in bad),
                                     parent=self.app.root)
        else:
            self.app.info("Done: %d app(s) turned %s" % (len(good), verb))


# --------------------------------------------------------------------------
# Debloat profiles (v1): save this phone's OFF / removed / background state, and
# apply someone's profile one reviewed action at a time through the app's existing
# verified operations (Autorun's whole-app OFF and background restriction, with
# their write-ahead records; the Apps tab's remove-for-user).
# --------------------------------------------------------------------------

def profile_removed_state(serial, pkg):
    """True = removed for the main user (known to Android, not installed), False =
    installed, None = can't tell. Decided from BOTH package lists, never one alone."""
    try:
        installed = set(pm_list(serial, "--user 0 " + shlex.quote(pkg)))
        known = set(pm_list(serial, "-u " + shlex.quote(pkg)))
    except AdbError:
        return None
    if pkg in installed:
        return False
    return True if pkg in known else None


def profile_removal_check(serial, pkg):
    """Fresh, right-before-removal check that 'Remove for user' can be undone:
    still installed for the main user, listed by Android as a SYSTEM package, factory
    copy still on the phone, and the restore command available. -> (True|False|None, why).
    Anything that can't be read gives None (= don't remove)."""
    try:
        rc, out, err = adb_shell(serial, "pm list packages -f -s --user 0 " + shlex.quote(pkg), timeout=60)
        rc2, sdk_out, _ = adb_shell(serial, "getprop ro.build.version.sdk", timeout=15)
    except AdbError:
        return None, "the phone couldn't be asked"
    if rc != 0 or query_error(out + err):
        return None, "the system-app list couldn't be read"
    path = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("package:") and "=" in line:
            p_, name = line[len("package:"):].rsplit("=", 1)
            if name == pkg:
                path = p_
    if path is None:
        return False, "it's not (or no longer) an installed system app"
    sdk = _int_or_none(sdk_out) if rc2 == 0 else None
    if not sdk:
        return None, "the Android version couldn't be read"
    # a system package whose file is under /data is an updated preinstalled app:
    # its factory copy is still in the system partition
    return pf.restorable({"system": True, "path": path, "updated_system": path.startswith("/data/")}, sdk)


def profile_background_state(serial, pref, pkg, user, sdk, target_sdk):
    """True = restricted (every op 'ignore'), False = not, None = unknown/unsupported -
    the same ops and reads as the Autorun tab."""
    if not pref:
        return None
    ops = background_ops(sdk, target_sdk)
    if not ops:
        return None
    modes = read_background_modes(serial, pref, pkg, user, ops)
    if modes is None:
        return None
    return all(v == "ignore" for v in modes.values())


def _int_or_none(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


PROFILE_OUTCOME = {"verified": "✅ done - checked on the phone", "unverified": "⚠ sent, but not confirmed",
                   "refused": "⛔ the phone refused", "failed": "⛔ failed",
                   "unsupported": "⛔ not possible here", "changed": "↻ changed since the review - skipped",
                   "skipped": "– skipped (couldn't re-read it)", "stopped": "– not done (stopped)",
                   "already": "– already that way"}


class ProfileWindow(tk.Toplevel):
    COLS = ("off", "removed", "background", "risk", "signer")

    def __init__(self, master, app):
        super().__init__(master)
        self.app, self.at = app, app.apps_tab
        self.title("Debloat profiles")
        self.transient(master)
        self.minsize(640, 420)
        self.doc = self.rows = None
        self.ctx = None                       # serial / user / sdk the review was made for
        self.ticked = set()                   # (pkg, action)
        self.results = {}
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)
        intro = ttk.Label(frm, justify="left", foreground="#555555", text=(
            "A profile records which apps are turned OFF, removed for the user, or kept from running in the "
            "background on a phone. Open one to compare it with THIS phone: you tick each change yourself, every "
            "change is checked again just before it's made and verified afterwards. Nothing happens on its own."))
        intro.pack(fill="x")
        intro.bind("<Configure>", lambda e: intro.configure(wraplength=max(200, e.width - 4)))
        row = ttk.Frame(frm)
        row.pack(fill="x", pady=(8, 4))
        self.save_btn = ttk.Button(row, text="Save this phone's profile…", command=self.export)
        self.save_btn.pack(side="left")
        self.open_btn = ttk.Button(row, text="Open a profile…", command=self.import_)
        self.open_btn.pack(side="left", padx=6)
        self.head = ttk.Label(frm, text="", font=("TkDefaultFont", 10, "bold"))
        self.head.pack(fill="x")
        mid = ttk.Frame(frm)
        mid.pack(fill="both", expand=True, pady=(4, 0))
        self.tree = ttk.Treeview(mid, columns=self.COLS, selectmode="browse")
        for c, t, wdt in (("#0", "App", 210), ("off", "Turn OFF", 150), ("removed", "Remove for user", 140),
                          ("background", "Restrict background", 160), ("risk", "Risk here", 90),
                          ("signer", "Same app?", 100)):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=wdt, stretch=c == "#0")
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<Button-1>", self.on_click)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.note = ttk.Label(frm, text="Click a ☐ / ☑ box to choose that change.", foreground="#555555",
                              justify="left")
        self.note.pack(fill="x", pady=(4, 0))
        self.note.bind("<Configure>", lambda e: self.note.configure(wraplength=max(200, e.width - 4)))
        bot = ttk.Frame(frm)
        bot.pack(fill="x", pady=(6, 0))
        self.summary = ttk.Label(bot, text="")
        self.summary.pack(side="left")
        ttk.Button(bot, text="Close", command=self.destroy).pack(side="right")
        self.apply_btn = ttk.Button(bot, text="Apply the ticked changes", command=self.apply)
        self.apply_btn.pack(side="right", padx=6)
        self.apply_btn.state(["disabled"])

    # ---- shared checks ----------------------------------------------------

    def ready(self):
        at = self.at
        if not at.serial:
            self.app.error("No device connected - pick one at the top")
            return False
        if at.scanned_serial != at.serial or not at.apps:
            messagebox.showinfo("Scan first", "Scan the apps on this phone first (Apps tab > Scan apps).", parent=self)
            return False
        if at.job:
            self.app.info("Busy: %s - wait for it to finish or press Stop" % at.job)
            return False
        return True

    @staticmethod
    def user_problem(user, source):
        if source not in ("detected", "single-user"):
            return ("the phone's current Android user couldn't be established, so a change might hit the wrong "
                    "user")
        if user != 0:
            return "this version of profiles only supports the phone's main user (you're using user %d)" % user
        return None

    # ---- export -------------------------------------------------------------

    def export(self):
        if not self.ready():
            return
        at = self.at
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", "%s_%s" % (at.props.get("model") or "phone",
                                                           time.strftime("%Y%m%d"))) + ".adbprofile.json"
        path = filedialog.asksaveasfilename(parent=self, title="Save this phone's profile",
                                            initialfile=name, defaultextension=".json",
                                            filetypes=[("ADB Manager profile", "*.json"), ("All files", "*")])
        if not path:
            return
        apps = copy.deepcopy(at.apps)
        props = dict(at.props)
        at.start_job("saving a profile", self._export_work, at.serial, path, apps, props)

    def _export_work(self, serial, path, apps, props):
        try:
            user, src = current_user(serial)
            problem = self.user_problem(user, src)
            if problem:
                return self.at.post(self._export_done, None, "Nothing was saved: " + problem, [])
            sdk = _int_or_none(props.get("sdk")) or 0
            notes = []
            try:
                rc, out, err = adb_shell(serial, "dumpsys appops", timeout=120)
            except AdbError:
                rc, out = 1, ""
            if rc != 0 or not out.strip():
                bg = {}
                notes.append("the background settings couldn't be read, so none were saved")
            else:
                bg = pf.background_from_appops(
                    out, user, lambda p: background_ops(sdk, _int_or_none((apps.get(p) or {}).get("target_sdk")))
                    if p in apps else None)
            doc = pf.build_profile(apps, props, user, bg, sa.load_json(sa.IDENTITY_FILE, {}), sa.identity_key)
            pf.dump_profile(doc)                                   # validated before it's written
            sa.atomic_write_json(path, doc, private=True, folder_private=False)
            self.at.post(self._export_done, doc, path, notes)
        except (OSError, pf.ProfileError) as e:
            self.at.post(self._export_done, None, "Nothing was saved: %s" % e, [])
        except Exception as e:                                       # always report back
            self.at.post(self._export_done, None, "Nothing was saved: %s: %s" % (type(e).__name__, e), [])

    def _export_done(self, doc, msg, notes):
        self.at.end_job()
        if doc is None:
            self.app.error(msg)
            if self.winfo_exists():
                messagebox.showwarning("Profile not saved", msg, parent=self)
            return
        n = {a: sum(1 for e in doc["apps"].values() if a in e["actions"]) for a in pf.ACTIONS}
        text = ("Saved %d app(s): %d turned OFF, %d removed for the user, %d with background restricted.\n\n%s\n\n"
                "The file lists your installed apps' names, so it's saved readable only by you."
                % (len(doc["apps"]), n["off"], n["removed"], n["background"], msg))
        if notes:
            text += "\n\nNote: " + "; ".join(notes) + "."
        self.app.info("Profile saved: %s" % msg)
        if self.winfo_exists():
            messagebox.showinfo("Profile saved", text, parent=self)

    # ---- import + review ------------------------------------------------------

    def import_(self):
        if not self.ready():
            return
        path = filedialog.askopenfilename(parent=self, title="Open a profile",
                                          filetypes=[("ADB Manager profile", "*.json"), ("All files", "*")])
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read(pf.MAX_BYTES + 1)
            doc = pf.load_profile(data)
        except (OSError, pf.ProfileError) as e:
            messagebox.showerror("Can't use this profile", str(e), parent=self)
            return
        at = self.at
        apps = copy.deepcopy(at.apps)
        at.start_job("reading this phone for the profile", self._review_work, at.serial, doc, apps,
                     _int_or_none(at.props.get("sdk")) or 0, path)

    def _review_work(self, serial, doc, apps, sdk, path):
        try:
            user, src = current_user(serial)
            problem = self.user_problem(user, src)
            bg = {}
            want_bg = [p for p, e in doc["apps"].items() if "background" in e["actions"]
                       and p in apps and not apps[p].get("removed")]
            if want_bg and not problem:
                pref = appops_prefix(serial)
                for i, p in enumerate(want_bg):
                    self.at.post(self.app.info, "Reading background settings %d/%d ..." % (i + 1, len(want_bg)))
                    bg[p] = profile_background_state(serial, pref, p, user, sdk,
                                                     _int_or_none(apps[p].get("target_sdk")))
            idc = sa.load_json(sa.IDENTITY_FILE, {})
            signers = {p: pf.signer_evidence(p, apps[p], idc, sa.identity_key)
                       for p in doc["apps"] if p in apps and not apps[p].get("removed")}
            ctx = {"serial": serial, "user": user, "problem": problem, "sdk": sdk, "path": path}
            self.at.post(self._review_done, doc, ctx, bg, {p: s for p, s in signers.items() if s}, None)
        except Exception as e:                                       # always report back
            self.at.post(self._review_done, None, None, None, None, "%s: %s" % (type(e).__name__, e))

    def _review_done(self, doc, ctx, bg, signers, error):
        self.at.end_job()
        if not self.winfo_exists():
            return
        if error:
            messagebox.showerror("Couldn't compare", error, parent=self)
            return
        at = self.at
        if ctx["serial"] != at.serial:
            return
        self.doc, self.ctx, self.results = doc, ctx, {}
        self.rows = pf.compare(doc, {"apps": at.apps, "sdk": ctx["sdk"], "user": ctx["user"], "background": bg,
                                     "signers": signers, "critical": kb.CRITICAL,
                                     "risk_of": lambda p: at.assess(at.apps[p])[0]})
        self.ticked = {(r["pkg"], a) for r in self.rows for a, v in r["actions"].items()
                       if v["preselect"]} if not ctx["problem"] else set()
        src = doc.get("source") or {}
        self.head.configure(text="Profile from %s (Android %s, saved %s) compared with this phone%s" % (
            " ".join(x for x in (src.get("maker", ""), src.get("model", "")) if x) or "an unknown phone",
            src.get("release", "?"), doc.get("created", "?"),
            "" if not ctx["problem"] else " - CAN'T APPLY: " + ctx["problem"]))
        self.populate()

    def cell(self, r, act):
        v = r["actions"].get(act)
        if v is None:
            return ""
        done = self.results.get((r["pkg"], act))
        if done:
            return PROFILE_OUTCOME.get(done[0], done[0]).split(" - ")[0]
        if v["status"] == pf.WILL_CHANGE and not self.ctx["problem"]:
            return ("☑ " if (r["pkg"], act) in self.ticked else "☐ ") + pf.STATUS_WORDS[v["status"]]
        return "— " + pf.STATUS_WORDS[v["status"]]

    def populate(self):
        self.tree.delete(*self.tree.get_children())
        for r in self.rows or []:
            risk = kb.RISK_SHORT.get(r["risk"], "") if r["risk"] else ""
            self.tree.insert("", "end", iid=r["pkg"], text=self.at.label(r["pkg"]) if r["pkg"] in self.at.apps
                             else r["pkg"], values=tuple(self.cell(r, a) for a in pf.ACTIONS) +
                             (risk, {"match": "yes", pf.CONFLICT: "⛔ NO", pf.UNKNOWN: "unknown"}[r["signer"]]))
        c = pf.counts(self.rows or [])
        crit = sum(1 for p, a in self.ticked if self.row(p)["risk"] == kb.CRITICAL)
        self.summary.configure(text="%d ticked%s  ·  %d already done  ·  %d not possible / unknown / "
                                    "missing" % (len(self.ticked), " (%d should stay on!)" % crit if crit else "",
                                                 c.get(pf.ALREADY, 0),
                                                 sum(c.get(k, 0) for k in (pf.UNSUPPORTED, pf.UNKNOWN, pf.MISSING,
                                                                           pf.CONFLICT, pf.NOT_APPLICABLE))))
        self.apply_btn.state(["!disabled"] if self.ticked and not self.ctx["problem"] else ["disabled"])

    def row(self, pkg):
        return next(r for r in self.rows if r["pkg"] == pkg)

    def on_click(self, event):
        if not self.rows or self.ctx["problem"] or self.at.job:
            return
        pkg, col = self.tree.identify_row(event.y), self.tree.identify_column(event.x)
        if not pkg or not col.startswith("#") or col == "#0":
            return
        idx = int(col[1:]) - 1
        if idx >= len(pf.ACTIONS):
            return
        self.toggle(pkg, pf.ACTIONS[idx])

    def toggle(self, pkg, act):
        """Tick / untick one change. Only 'will change' items can be ticked."""
        if not self.rows or self.ctx["problem"] or self.at.job:
            return False
        v = self.row(pkg)["actions"].get(act)
        if not v or v["status"] != pf.WILL_CHANGE or (pkg, act) in self.results:
            return False
        self.ticked ^= {(pkg, act)}
        self.populate()
        self.tree.selection_set(pkg)
        return True

    def on_select(self, event=None):
        sel = self.tree.selection()
        if not sel or not self.rows:
            return
        r = self.row(sel[0])
        lines = ["%s: %s" % (pf.ACTION_WORDS[a], v["why"]) for a, v in r["actions"].items()]
        if r["version"] == "different":
            lines.append("The app's version here differs from the one in the profile.")
        if r["risk"] == kb.CRITICAL:
            lines.append("⛔ On THIS phone this app should stay on - it's never ticked for you.")
        self.note.configure(text="  ·  ".join(lines))

    # ---- apply ------------------------------------------------------------------

    def apply(self):
        if not self.ticked or self.ctx["problem"] or not self.ready():
            return
        at = self.at
        if self.ctx["serial"] != at.serial:
            messagebox.showwarning("Different phone", "The review was made for another phone - open the profile "
                                   "again.", parent=self)
            return
        plan = sorted(self.ticked, key=lambda pa: (pa[0], pf.ACTIONS.index(pa[1])))
        n = {a: sum(1 for p, x in plan if x == a) for a in pf.ACTIONS}
        crit = [p for p, a in plan if self.row(p)["risk"] == kb.CRITICAL]
        text = ("Make %d change(s) on this phone?\n\n  %s: %d\n  %s: %d\n  %s: %d\n\nEach one is checked again "
                "right before it's made (if something changed since this review, it's skipped) and verified "
                "afterwards. Removed apps come back with 'Restore removed'; OFF apps with 'Turn ON'; background "
                "with the Autorun tab's 'Allow background again'." % (
                    len(plan), pf.ACTION_WORDS["off"], n["off"], pf.ACTION_WORDS["removed"], n["removed"],
                    pf.ACTION_WORDS["background"], n["background"]))
        if crit:
            ans = simpledialog.askstring("Are you sure?", text + "\n\n⛔ %d of these apps should stay on, on "
                                         "this phone: %s\n\nType YES to include them anyway:" % (
                                             len(set(crit)), ", ".join(sorted(set(crit))[:6])), parent=self)
            if ans != "YES":
                self.app.info("Cancelled - nothing was changed")
                return
        elif not messagebox.askyesno("Apply profile", text, parent=self, icon="warning"):
            return
        frozen = {"serial": self.ctx["serial"], "user": self.ctx["user"], "sdk": self.ctx["sdk"],
                  "want_root": bool(at.use_root.get()),
                  "target_sdk": {p: _int_or_none((at.apps.get(p) or {}).get("target_sdk")) for p, _ in plan}}
        at.start_job("applying a profile", self._apply_work, plan, frozen)

    def apply_one(self, pkg, act, f):
        """Recheck, then change one thing through the existing operation. -> (outcome, message)."""
        serial, user = f["serial"], f["user"]
        if act == "removed":
            now = profile_removed_state(serial, pkg)
            if now is None:
                return "skipped", "its current state couldn't be read"
            if now:
                return "changed", "it's already removed now"
            eligible, why = profile_removal_check(serial, pkg)      # re-checked NOW, not from the review
            if eligible is None:
                return "skipped", "couldn't confirm it can be brought back (%s)" % why
            if not eligible:
                return "changed", "it can no longer be removed safely: %s" % why
            op = journal_begin(serial, 0, pkg, "remove-for-user", "installed", "removed", source="profile")
            if op is False:
                return "failed", journal_refusal(pkg)["message"]
            if op == NOOP:
                return "changed", ALREADY_MSG
            ok, msg = pm_uninstall(serial, pkg, "user")
            after = profile_removed_state(serial, pkg)              # read back BEFORE closing the record
            if after is None:
                msg += KEPT_MSG                                      # state unknown: next scan settles it
            else:
                journal_end(op)
            log_action(serial, "remove-for-user", pkg, after is True, msg, user=0, source="profile",
                       outcome="verified" if after is True else "unverified" if ok else "failed")
            if after is True:
                return "verified", msg
            return ("unverified" if ok else "failed"), msg
        auto = self.app.autorun_tab
        ctx = {"serial": serial, "user": user, "user_verified": True, "pkg": pkg, "cls": None, "before": None,
               "target_sdk": f["target_sdk"].get(pkg), "key": AutorunTab.record_key(serial, user, pkg),
               "want_root": f["want_root"]}
        if act == "off":
            st = receiver_states(serial, user, {pkg}).get(pkg)
            ps = (st or {}).get("pkg_state")
            if ps is None:
                return "skipped", "its current state couldn't be read"
            if ps in (2, 3, 4):
                return "changed", "it's already OFF now"
            res = auto._act_run("app_off", ctx)
        else:
            now = profile_background_state(serial, appops_prefix(serial), pkg, user, f["sdk"], ctx["target_sdk"])
            if now is None:
                return "skipped", "its background settings couldn't be read"
            if now:
                return "changed", "background is already restricted now"
            res = auto._act_run("bg_restrict", ctx)
        log_action(serial, {"off": "app-off", "background": "bg-restrict"}[act], pkg, res["outcome"] == "verified",
                   res.get("message", ""), outcome=res["outcome"], user=user, source="profile")
        return res["outcome"], res.get("message", "")

    def _apply_work(self, plan, f):
        results = []
        for i, (pkg, act) in enumerate(plan):
            if self.at.stop.is_set():                    # only BETWEEN operations
                results.extend((p, a, "stopped", "") for p, a in plan[i:])
                break
            self.at.post(self.app.info, "Profile %d/%d: %s - %s ..." % (i + 1, len(plan), pf.ACTION_WORDS[act], pkg))
            try:
                outcome, msg = self.apply_one(pkg, act, f)
            except Exception as e:                       # one failure never stops the report
                outcome, msg = "failed", "%s: %s" % (type(e).__name__, e)
            results.append((pkg, act, outcome, msg))
        self.at.post(self._apply_done, f["serial"], results)

    def _apply_done(self, serial, results):
        at = self.at
        at.end_job()
        offs = tuple(p for p, a, o, m in results if a == "off" and o == "verified")
        if offs and serial == at.serial:                 # also offered by the Apps tab's "turn back ON"
            stamp = time.strftime("%Y-%m-%d %H:%M")

            def add(mine, offs=offs, stamp=stamp):
                mine = mine if isinstance(mine, dict) else {}
                for p in offs:
                    mine[p] = stamp
                return mine
            at._store_saved(at.turned_off, at.turned_off.update(serial, add, {}),
                            "the list of apps this program turned off (used for Undo)")
        done = sum(1 for r in results if r[2] == "verified")
        self.app.info("Profile: %d of %d change(s) done and verified" % (done, len(results)))
        if self.winfo_exists():
            for p, a, o, m in results:
                self.results[(p, a)] = (o, m)
                self.ticked.discard((p, a))
            self.populate()
            lines = ["%s - %s: %s%s" % (at.label(p) if p in at.apps else p, pf.ACTION_WORDS[a],
                                        PROFILE_OUTCOME.get(o, o), (" (%s)" % m) if m and o != "verified" else "")
                     for p, a, o, m in results]
            (messagebox.showinfo if done == len(results) else messagebox.showwarning)(
                "Profile applied", "\n".join(lines[:40]) + ("\n..." if len(lines) > 40 else ""), parent=self)
        if serial == at.serial and any(r[2] in ("verified", "unverified") for r in results):
            at.scan()


class TimelineWindow(tk.Toplevel):
    """The saved security checks of one phone, newest first. Each check is compared with
    the one before it (the same comparison as 'changes since the last check'); what a
    check couldn't read is listed with it, so 'nothing found' is never mistaken for
    'nothing changed'. Read-only, nothing here touches the phone."""

    def __init__(self, master, app, serial):
        super().__init__(master)
        self.app, self.serial = app, serial
        self.title("Timeline of security checks")
        self.transient(master)
        self.minsize(680, 420)
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)
        self.head = ttk.Label(frm, text="", foreground="#555555", justify="left")
        self.head.pack(fill="x")
        self.head.bind("<Configure>", lambda e: self.head.configure(wraplength=max(200, e.width - 4)))
        body = ttk.Frame(frm)
        body.pack(fill="both", expand=True, pady=(6, 0))
        left = ttk.Frame(body)
        left.pack(side="left", fill="y")
        self.list = ttk.Treeview(left, columns=("n",), selectmode="browse", show="tree headings")
        self.list.heading("#0", text="Check")
        self.list.heading("n", text="Changes")
        self.list.column("#0", width=175, minwidth=160)
        self.list.column("n", width=170, minwidth=120)
        self.list.pack(fill="y", expand=True)
        self.list.bind("<<TreeviewSelect>>", self.on_select)
        self.text = tk.Text(body, wrap="word", relief="flat", padx=8, pady=6, cursor="arrow", font=("TkDefaultFont", 10))
        for tag, color in (("bad", "#b3261e"), ("warn", "#9a6700"), ("dim", "#777777")):
            self.text.tag_configure(tag, foreground=color)
        self.text.tag_configure("h", font=("TkDefaultFont", 11, "bold"))
        self.text.pack(side="left", fill="both", expand=True, padx=(8, 0))
        self.load()

    def load(self):
        snaps = sa.list_snapshots(self.serial)
        self.snaps = snaps
        self.results = {}
        self.list.delete(*self.list.get_children())
        label = self.app.apps_tab.label
        for i in range(len(snaps) - 1, -1, -1):
            f, snap = snaps[i]
            prev = snaps[i - 1][1] if i else None
            found = sa.compare_snapshots(prev, snap, label)
            changes = [x for x in found if x["level"] != sa.OK and x["key"] not in ("changes:first",
                                                                                   "changes:none-partial")]
            self.results[str(i)] = (snap, prev, found)
            worst = min((sa.LEVEL_RANK[x["level"]] for x in changes), default=None)
            mark = "" if worst is None else {0: "⛔ ", 1: "⚠ "}.get(worst, "")
            n = "first check" if prev is None else ("%s%d change(s)" % (mark, len(changes)) if changes else "none")
            if sa.snapshot_gaps(snap):
                n += " · partial"
            self.list.insert("", "end", iid=str(i), text=snap.get("time", f), values=(n,))
        self.head.configure(text=("%d saved check(s) of this phone (the newest %d are kept). Each is compared with "
                                  "the check before it. 'partial' = that check couldn't read everything - see its "
                                  "details." % (len(snaps), sa.KEEP_SNAPSHOTS)) if snaps else
                            "No saved checks of this phone yet - run a checkup in the Security tab.")
        kids = self.list.get_children()
        if kids:
            self.list.selection_set(kids[0])
            self.on_select()

    def on_select(self, event=None):
        sel = self.list.selection()
        if not sel or sel[0] not in self.results:
            return
        snap, prev, found = self.results[sel[0]]
        t = self.text
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", "Check of %s\n" % snap.get("time", "?"), "h")
        t.insert("end", ("compared with %s\n\n" % prev.get("time", "?")) if prev else "the first saved check\n\n", "dim")
        for x in found:
            tag = {sa.BAD: "bad", sa.WARN: "warn"}.get(x["level"], ())
            t.insert("end", "• " + x["title"] + "\n", tag)
            if x.get("detail"):
                t.insert("end", "   " + x["detail"].replace("\n", "\n   ") + "\n", "dim")
        gaps = sa.snapshot_gaps(snap)
        if gaps:
            t.insert("end", "\nThis check couldn't read: %s.\n" % "; ".join(gaps), "warn")
        t.configure(state="disabled")


class PermissionsWindow(tk.Toplevel):
    """Read-only: which apps hold which permissions, for the phone's current Android user.
    Nothing here changes anything on the phone."""

    def __init__(self, master, app):
        super().__init__(master)
        self.app, self.at = app, app.apps_tab
        self.title("Permissions (read-only)")
        self.transient(master)
        self.minsize(680, 440)
        self.apps = None
        self.serial = self.at.serial
        self.note = ""
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)
        intro = ttk.Label(frm, justify="left", foreground="#555555", text=(
            "What each app is allowed to do, as the phone reports it for the current Android user. Read-only: "
            "nothing is changed here. Runtime permissions (camera, location...) are shown by group. 'Special "
            "access' (draw over apps, all files access...) is decided by separate settings, so it's listed but "
            "never called allowed or not; accessibility, notification access and device admin are in the Security "
            "tab."))
        intro.pack(fill="x")
        intro.bind("<Configure>", lambda e: intro.configure(wraplength=max(200, e.width - 4)))
        row = ttk.Frame(frm)
        row.pack(fill="x", pady=(6, 4))
        self.view = tk.StringVar(value="group")
        ttk.Radiobutton(row, text="By permission", variable=self.view, value="group",
                        command=self.populate).pack(side="left")
        ttk.Radiobutton(row, text="By app", variable=self.view, value="app",
                        command=self.populate).pack(side="left", padx=6)
        self.mine = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="Only apps I installed", variable=self.mine,
                        command=self.populate).pack(side="left", padx=(12, 0))
        self.denied = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="Also show 'not allowed'", variable=self.denied,
                        command=self.populate).pack(side="left", padx=6)
        self.refresh_btn = ttk.Button(row, text="Refresh", command=self.load)
        self.refresh_btn.pack(side="right")
        self.status = ttk.Label(frm, text="", foreground="#555555", justify="left")
        self.status.pack(fill="x")
        self.status.bind("<Configure>", lambda e: self.status.configure(wraplength=max(200, e.width - 4)))
        mid = ttk.Frame(frm)
        mid.pack(fill="both", expand=True, pady=(4, 0))
        self.tree = ttk.Treeview(mid, columns=("state", "notes"), selectmode="browse")
        for c, t, w_ in (("#0", "Permission / app", 300), ("state", "Allowed?", 150), ("notes", "Notes", 300)):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w_, stretch=c != "state")
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.detail = ttk.Label(frm, text="", foreground="#555555", justify="left")
        self.detail.pack(fill="x", pady=(4, 0))
        self.detail.bind("<Configure>", lambda e: self.detail.configure(wraplength=max(200, e.width - 4)))
        self.rows = {}
        self.load()

    def load(self):
        self.refresh_btn.state(["disabled"])
        self.status.configure(text="Reading the permissions from the phone ...")
        threading.Thread(target=self._work, args=(self.serial,
                                                  _int_or_none(self.at.props.get("sdk"))), daemon=True).start()

    def _work(self, serial, sdk):
        try:
            if sdk is None:                    # the Apps tab hasn't read it yet: ask the phone
                try:
                    rc0, o0, _ = adb_shell(serial, "getprop ro.build.version.sdk", timeout=15)
                    sdk = int(o0.strip()) if o0.strip().isdigit() else None
                except AdbError:
                    sdk = None
            user, src = current_user(serial)
            verified = src in ("detected", "single-user")
            rc, out, err = adb_shell(serial, "dumpsys package packages", timeout=240)
            if rc != 0 or query_error(out + err) or not out.strip():
                raise AdbError("the phone didn't return its package list (%s)" % (err.strip()[:120] or rc))
            parsed = pi.parse(out, user)
            if not parsed:                     # non-empty output with no package records: not an empty phone
                raise AdbError("the phone's answer contained no package records - the output wasn't in a format "
                               "this version understands, or it was incomplete")
            apps = pi.inventory(parsed, sdk, verified)
            self.app.q.put(("call", self._loaded, serial, apps, user, verified, sdk, None))
        except Exception as e:
            self.app.q.put(("call", self._loaded, serial, None, None, False, sdk, "%s" % e))

    def _loaded(self, serial, apps, user, verified, sdk, error):
        if not self.winfo_exists():
            return
        self.refresh_btn.state(["!disabled"])
        if error:
            self.apps = None
            self.status.configure(text="Couldn't read the permissions: %s" % error)
            self.tree.delete(*self.tree.get_children())
            return
        self.apps = apps
        if sdk is not None and sdk < 23:
            self.note = ("This phone runs Android older than 6: apps get ALL their permissions when installed, "
                         "so there are no runtime permissions to show - see 'By app' for what each app has.")
        elif not verified:
            self.note = ("The phone's current Android user couldn't be confirmed, so runtime permissions (which are "
                         "per user) are shown as unknown - not as 'not allowed'.")
        else:
            self.note = "Android user %d." % user
        self.populate()

    def wanted(self, pkg):
        return not self.mine.get() or not (self.at.apps.get(pkg) or {}).get("system", False)

    def name(self, pkg):
        return self.at.label(pkg) if pkg in self.at.apps else pkg

    def populate(self):
        self.tree.delete(*self.tree.get_children())
        self.rows = {}
        if not self.apps:
            return
        apps = {p: a for p, a in self.apps.items() if self.wanted(p)}
        if self.view.get() == "group":
            groups = pi.by_group(apps, self.denied.get())
            for g in pi.GROUP_ORDER:
                items = groups.get(g)
                if not items:
                    continue
                n_ok = len({p for p, perm, ok, f in items if ok})
                gid = self.tree.insert("", "end", text="%s  (%d app%s allowed)" % (g, n_ok, "" if n_ok == 1 else "s"),
                                       open=False)
                for i, (pkg, perm, ok, flags) in enumerate(sorted(items, key=lambda x: (not x[2], self.name(x[0]).lower(),
                                                                                         x[1]))):
                    st, notes, change = pi.explain(ok, flags)
                    iid = self.tree.insert(gid, "end", text="%s - %s" % (self.name(pkg), pi.short(perm)),
                                           values=(st, ("⛔ can't be changed; " if not change else "") +
                                                   "; ".join(notes)))
                    self.rows[iid] = (pkg, perm, ok, flags)
            special = sorted((p, sp) for p, a in apps.items() for sp in a["special"])
            if special:
                sid = self.tree.insert("", "end", text="Special access  (%d request%s)" % (
                    len(special), "" if len(special) == 1 else "s"))
                for pkg, sp in special:
                    iid = self.tree.insert(sid, "end", text="%s - %s" % (self.name(pkg), pi.SPECIAL_ACCESS[sp]),
                                           values=("asks for it", "decided by special-access settings, not shown here"))
                    self.rows[iid] = (pkg, sp, None, frozenset())
        else:
            for pkg in sorted(apps, key=lambda p: self.name(p).lower()):
                a = apps[pkg]
                allowed = sum(1 for ok, f in a["runtime"].values() if ok)
                mode = {"ok": "%d allowed" % allowed, "install_time": "all at install (Android < 6)",
                        "user_unknown": "unknown (user not confirmed)",
                        "no_user_block": "no record for this user"}[a["runtime_mode"]]
                ig = sum(1 for g, f in a["install"].values() if g)
                ing = len(a["install"]) - ig
                inst = ("install-time: %d granted%s" % (ig, ", %d not granted" % ing if ing else "")
                        if a["install"] else "install-time: %d granted at install" % len(a["legacy"]))
                pid = self.tree.insert("", "end", text=self.name(pkg), values=(mode, inst + (
                    "; asks for special access" if a["special"] else "")))
                self.rows[pid] = (pkg, None, None, None)
                for perm, (ok, flags) in sorted(a["runtime"].items(), key=lambda kv: (not kv[1][0], kv[0])):
                    if ok or self.denied.get():
                        st, notes, change = pi.explain(ok, flags)
                        iid = self.tree.insert(pid, "end", text="%s (%s)" % (pi.short(perm), pi.group_of(perm)),
                                               values=(st, ("⛔ can't be changed; " if not change else "") +
                                                       "; ".join(notes)))
                        self.rows[iid] = (pkg, perm, ok, flags)
                for sp in a["special"]:
                    iid = self.tree.insert(pid, "end", text="Special access: %s" % pi.SPECIAL_ACCESS[sp],
                                           values=("asks for it", "decided by special-access settings"))
                    self.rows[iid] = (pkg, sp, None, frozenset())
                if a["install"]:                  # their own sub-list: never mixed with runtime permissions
                    nid = self.tree.insert(pid, "end", text="Install-time permissions", values=(
                        "%d granted" % ig, "%d not granted" % ing if ing else ""))
                    self.rows[nid] = (pkg, None, None, None)
                    for perm, (ok, flags) in sorted(a["install"].items(), key=lambda kv: (not kv[1][0], kv[0])):
                        if ok or self.denied.get():
                            st, notes, change = pi.explain(ok, flags)
                            iid = self.tree.insert(nid, "end", text="%s (install-time)" % pi.short(perm),
                                                   values=("granted" if ok else "not granted", "; ".join(notes)))
                            self.rows[iid] = (pkg, perm, ok, flags)
        total = sum(1 for a in apps.values() for ok, f in a["runtime"].values() if ok)
        self.status.configure(text="%s  %d app(s), %d runtime permission(s) allowed.%s" % (
            self.note, len(apps), total, "  (Only apps you installed.)" if self.mine.get() else ""))

    def on_select(self, event=None):
        sel = self.tree.selection()
        if not sel or sel[0] not in self.rows:
            self.detail.configure(text="")
            return
        pkg, perm, ok, flags = self.rows[sel[0]]
        if perm is None:
            a = self.apps[pkg]
            if a["install"]:                   # the modern records win whenever they exist
                granted = sorted(pi.short(p) for p, (g, f) in a["install"].items() if g)
            else:                              # only then the old 'grantedPermissions' list
                granted = sorted(pi.short(p) for p in a["legacy"])
            denied = sorted(pi.short(p) for p, (g, f) in a["install"].items() if not g)
            self.detail.configure(text="%s  ·  install-time granted: %s%s" % (
                pkg, ", ".join(granted) or "none", ("  ·  NOT granted: " + ", ".join(denied)) if denied else ""))
        elif ok is None:
            self.detail.configure(text="%s asks for %s (%s). Whether it's switched on is a special-access setting, "
                                       "which this list doesn't show." % (pkg, pi.short(perm), pi.SPECIAL_ACCESS[perm]))
        else:
            st, notes, change = pi.explain(ok, flags)
            self.detail.configure(text="%s  ·  %s: %s.%s  Android flags: %s" % (
                pkg, perm, st, (" " + "; ".join(notes) + ".") if notes else "",
                " ".join(sorted(flags)) or "none"))


HISTORY_WHAT = {"disable": "Turned OFF", "enable": "Turned ON", "app-off": "Turned OFF", "app-on": "Turned ON",
                "uninstall-full": "Uninstalled", "uninstall-user": "Removed for the user",
                "uninstall-updates": "Removed updates", "remove-for-user": "Removed for the user",
                "restore": "Brought back", "install": "Installed", "receiver-off": "Start-up receiver off",
                "receiver-back": "Start-up receiver put back", "bg-restrict": "Background restricted",
                "bg-allow": "Background allowed again"}
HISTORY_OUTCOME = {"verified": "✅ checked on the phone", "done": "✔ phone said OK",
                   "unverified": "⚠ not confirmed", "refused": "⛔ phone refused", "failed": "⛔ failed",
                   "unsupported": "– not possible", "changed": "↻ skipped (changed)",
                   "skipped": "– skipped", "stopped": "– stopped", "not_applied": "– not applied",
                   "uncertain": "⚠ uncertain", "restored": "↩ restored",
                   "already": "– already that way"}


class HistoryWindow(tk.Toplevel):
    """Everything this program changed on phones, newest first (read-only)."""

    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        self.title("History of changes")
        self.transient(master)
        self.minsize(640, 360)
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)
        row = ttk.Frame(frm)
        row.pack(fill="x")
        self.only_this = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text="Only the connected phone", variable=self.only_this,
                        command=self.refresh).pack(side="left")
        self.summary = ttk.Label(row, text="", foreground="#555555")
        self.summary.pack(side="left", padx=12)
        ttk.Button(row, text="Refresh", command=self.refresh).pack(side="right")
        self.tree = ttk.Treeview(frm, columns=("what", "app", "result", "from"), selectmode="browse")
        for c, t, w_ in (("#0", "When", 140), ("what", "What", 190), ("app", "App", 220),
                         ("result", "Result", 170), ("from", "From", 70)):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w_, stretch=c == "app")
        sb = ttk.Scrollbar(frm, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True, pady=(6, 0))
        sb.pack(side="left", fill="y", pady=(6, 0))
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.detail = ttk.Label(self, text="", foreground="#555555", justify="left", padding=(10, 0, 10, 8))
        self.detail.pack(fill="x")
        self.detail.bind("<Configure>", lambda e: self.detail.configure(wraplength=max(200, e.width - 4)))
        self.events = []
        self.refresh()

    def refresh(self):
        events, bad = history.read(HISTORY_FILE)
        serial = self.app.apps_tab.serial
        if self.only_this.get() and serial:
            events = [e for e in events if e.get("serial") == serial]
        self.events = events
        self.tree.delete(*self.tree.get_children())
        label = self.app.apps_tab.label
        for i, e in enumerate(events):
            what = HISTORY_WHAT.get(e["what"], e["what"])
            if e.get("target"):
                what += " (%s)" % e["target"].rsplit(".", 1)[-1]
            pkg = e.get("pkg", "")
            self.tree.insert("", "end", iid=str(i), text=e["t"], values=(
                what, label(pkg) if pkg in self.app.apps_tab.apps else pkg,
                HISTORY_OUTCOME.get(e.get("outcome"), e.get("outcome", "")), e.get("source", "")))
        self.summary.configure(text="%d change(s)%s" % (len(events), "  ·  %d unreadable line(s) skipped" % bad
                                                         if bad else ""))

    def on_select(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        e = self.events[int(sel[0])]
        self.detail.configure(text="%s  ·  phone %s%s  ·  %s%s" % (
            e.get("pkg", ""), e.get("serial", "?"), (", user %d" % e["user"]) if isinstance(e.get("user"), int) else "",
            e.get("t", ""), ("\n" + e["msg"]) if e.get("msg") else ""))


# --------------------------------------------------------------------------
# GUI: Network tab
# --------------------------------------------------------------------------

NET_SHOW = ["Open ports", "Open ports reachable from the network", "Internet connections",
            "All connections", "Everything (incl. closing)"]
REACH_TEXT = {"any": "anyone on the network", "device": "only this device",
              "local": "local network", "internet": "the internet"}


class NetworkTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master, padding=4)
        self.app = app
        self.serial = None
        self.socks = []
        self.uid_map = {}
        self.uid_map_serial = None
        self.names = {}            # ip -> reverse DNS name ('' = none)
        self.resolving = set()
        self.prev_listen = None    # listening sockets of the previous refresh
        self.new_keys = set()
        self.busy = False
        self.rows = {}             # iid -> ('owner', key) | ('sock', rec)
        self.auto = tk.BooleanVar(value=False)
        self.lookup_names = tk.BooleanVar(value=True)
        self.remember = tk.BooleanVar(value=False)
        self.seen, self.seen_serial, self.learn_until = {}, None, 0.0
        self.logged = set()        # (uid, ip, port) already written to the log this session
        self.newdest = {}          # (uid, ip) -> when it first went to a never-seen destination
        self.show_var = tk.StringVar(value=NET_SHOW[0])
        self.search_var = tk.StringVar()

        top = ttk.Frame(self)
        top.pack(fill="x")
        self.refresh_btn = ttk.Button(top, text="Refresh", command=self.refresh)
        self.refresh_btn.pack(side="left")
        ttk.Checkbutton(top, text="Auto-refresh every 5 s", variable=self.auto,
                        command=self.schedule).pack(side="left", padx=8)
        ttk.Label(top, text="Show:").pack(side="left", padx=(8, 0))
        cb = ttk.Combobox(top, textvariable=self.show_var, values=NET_SHOW, state="readonly", width=34)
        cb.pack(side="left", padx=4)
        cb.bind("<<ComboboxSelected>>", lambda e: self.populate())
        ttk.Label(top, text="Search:").pack(side="left", padx=(8, 0))
        ttk.Entry(top, textvariable=self.search_var, width=18).pack(side="left", padx=4)
        self.search_var.trace_add("write", lambda *a: self.populate())
        ttk.Checkbutton(top, text="Look up names of internet servers",
                        variable=self.lookup_names).pack(side="right")
        self.summary = ttk.Label(self, text="", foreground="#555555")
        self.summary.pack(fill="x", pady=(3, 0))

        pw = ttk.PanedWindow(self, orient="horizontal")
        pw.pack(fill="both", expand=True, pady=(4, 0))
        left = ttk.Frame(pw)
        self.tree = ttk.Treeview(left, columns=("reach", "proto", "local", "remote", "state"),
                                 selectmode="browse")
        for col, text, wdt, st in (("#0", "Who / what", 240, True), ("reach", "Who can reach it", 165, False),
                                   ("proto", "Type", 50, False), ("local", "On the device", 145, False),
                                   ("remote", "Other side", 155, False), ("state", "State", 95, False)):
            self.tree.heading(col, text=text)
            self.tree.column(col, width=wdt, stretch=st)
        self.tree.tag_configure("owner", font=("TkDefaultFont", 10, "bold"))
        self.tree.tag_configure("safe", foreground="#2e7d32")
        self.tree.tag_configure("caution", foreground="#b26a00")
        self.tree.tag_configure("critical", foreground="#c62828")
        self.tree.tag_configure("new", background="#fff3c4")
        self.tree.tag_configure("newdest", background="#ffd6d6")
        sb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.render())
        pw.add(left, weight=3)

        right = ttk.Frame(pw)
        self.details = tk.Text(right, wrap="word", width=38, relief="flat", padx=8, pady=6,
                               cursor="arrow", font=("TkDefaultFont", 10))
        dsb = ttk.Scrollbar(right, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=dsb.set)
        self.details.pack(side="left", fill="both", expand=True)
        dsb.pack(side="right", fill="y")
        self.details.tag_configure("h1", font=("TkDefaultFont", 13, "bold"))
        self.details.tag_configure("h2", font=("TkDefaultFont", 11, "bold"), spacing1=8, spacing3=2)
        self.details.tag_configure("dim", foreground="#777777")
        self.details.tag_configure("warn", foreground="#c62828")
        self.details.tag_configure("ok", foreground="#2e7d32")
        self.details.tag_configure("mono", font=("TkFixedFont", 9))
        pw.add(right, weight=2)
        bottom = ttk.Frame(self)
        bottom.pack(fill="x", pady=(4, 0))
        self.goto_btn = ttk.Button(bottom, text="Show this app in the Apps tab", command=self.goto_app)
        self.goto_btn.pack(side="left")
        ttk.Checkbutton(bottom, text="Remember where apps connect and warn about new destinations",
                        variable=self.remember, command=self.toggle_remember).pack(side="left", padx=12)
        self.log_label = ttk.Label(bottom, text="", foreground="#777777")
        self.log_label.pack(side="left")
        ttk.Label(bottom, text="A snapshot of this moment - very short connections can be missed.",
                  foreground="#777777").pack(side="right")
        self.render()

    # ---- device / visibility ---------------------------------------------

    def set_device(self, serial):
        if serial == self.serial:
            return
        self.serial = serial
        self.socks, self.prev_listen, self.new_keys = [], None, set()
        self.uid_map_serial = None
        self.seen_serial, self.logged, self.newdest = None, set(), {}
        if self.remember.get():
            self.toggle_remember()
        self.populate()
        self.render()

    def visible(self):
        try:
            return self.app.nb.index(self.app.nb.select()) == 2
        except tk.TclError:
            return False

    def on_shown(self):
        if self.serial and not self.socks and not self.busy:
            self.refresh()
        self.schedule()

    def schedule(self):
        if getattr(self, "_timer", None):
            self.after_cancel(self._timer)
            self._timer = None
        if self.auto.get():
            self._timer = self.after(5000, self._tick)

    def _tick(self):
        self._timer = None
        if self.auto.get() and self.visible() and self.serial and not self.busy:
            self.refresh(quiet=True)
        self.schedule()

    # ---- reading ----------------------------------------------------------

    def refresh(self, quiet=False):
        if not self.serial:
            self.app.error("No device connected - pick one at the top")
            return
        if self.busy:
            return
        self.busy = True
        self.refresh_btn.state(["disabled"])
        if not quiet:
            self.app.info("Reading the device's network table ...")
        at = self.app.apps_tab
        apps_map = None
        if at.scanned_serial == self.serial and at.apps:
            apps_map = {}
            for p, a in at.apps.items():
                if str(a.get("uid", "")).isdigit():
                    apps_map.setdefault(int(a["uid"]) % 100000, []).append(p)
        need_map = apps_map is None and self.uid_map_serial != self.serial
        threading.Thread(target=self._worker, args=(self.serial, apps_map, need_map, quiet),
                         daemon=True).start()

    def _worker(self, serial, apps_map, need_map, quiet):
        try:
            socks, errors = read_sockets(serial)
            umap = apps_map if apps_map is not None else (uid_packages(serial) if need_map else None)
        except Exception as e:                       # AdbError or anything unexpected: never stay busy
            self.app.q.put(("call", self._failed, str(e)))
            return
        self.app.q.put(("call", self._done, serial, socks, errors, umap, quiet))

    def _failed(self, msg):
        self.busy = False
        self.refresh_btn.state(["!disabled"])
        self.app.error("Network table: %s" % msg)

    def _done(self, serial, socks, errors, umap, quiet):
        self.busy = False
        self.refresh_btn.state(["!disabled"])
        if serial != self.serial:
            return
        if umap is not None:
            self.uid_map, self.uid_map_serial = umap, serial
        keys = {self.key(s) for s in socks if s["kind"] == "listen"}
        self.new_keys = (keys - self.prev_listen) if self.prev_listen is not None else set()
        self.prev_listen = keys
        self.socks = socks
        self.populate()
        self.render()
        if self.new_keys:
            first = next(s for s in socks if self.key(s) in self.new_keys)
            self.app.error("New open port: %s %d by %s" % (first["proto"].upper(), first["local_port"],
                                                           self.owner_name(first["uid"])))
        elif not quiet:
            self.app.info("Network table read: %d open ports, %d connections" % (
                sum(1 for s in socks if s["kind"] == "listen"),
                sum(1 for s in socks if s["kind"] == "connected")))
        if self.remember.get():
            now = time.time()
            self.newdest = {k: t for k, t in self.newdest.items() if now - t < NEWDEST_SECONDS}
            for s in socks:
                if s["kind"] == "connected" and addr_kind(s["remote_ip"]) == "internet" and \
                        (not self.lookup_names.get() or s["remote_ip"] in self.names):
                    self.note_destination(s)
            self.populate()
        if self.lookup_names.get():
            todo = sorted({s["remote_ip"] for s in socks if s["kind"] == "connected"
                           and addr_kind(s["remote_ip"]) == "internet"
                           and s["remote_ip"] not in self.names and s["remote_ip"] not in self.resolving})
            if todo:
                self.resolving.update(todo)
                threading.Thread(target=self._resolve, args=(todo,), daemon=True).start()

    def _resolve(self, ips):
        for ip in ips:
            name = reverse_name(ip)
            self.app.q.put(("call", self._resolved, ip, name))

    def _resolved(self, ip, name):
        self.resolving.discard(ip)
        self.names[ip] = name
        if self.remember.get():
            flagged = False
            for s in self.socks:
                if s["kind"] == "connected" and s["remote_ip"] == ip:
                    flagged = self.note_destination(s) or flagged
            if flagged:
                self.populate()
        if name:
            for iid, (kind, rec) in self.rows.items():
                if kind == "sock" and rec["remote_ip"] == ip and self.tree.exists(iid):
                    self.tree.item(iid, text=self.sock_text(rec),
                                   values=self.sock_values(rec))
            self.render()

    # ---- remembering destinations ------------------------------------------

    def seen_path(self):
        return os.path.join(NET_SEEN_DIR, re.sub(r"[^A-Za-z0-9._-]+", "_", self.serial or "none") + ".json")

    def log_path(self):
        return os.path.join(NET_LOG_DIR, re.sub(r"[^A-Za-z0-9._-]+", "_", self.serial or "none") + ".csv")

    def toggle_remember(self):
        if not self.remember.get() or not self.serial:
            self.log_label.configure(text="")
            return
        if self.seen_serial != self.serial:
            path = self.seen_path()
            self.seen = sa.load_json(path, {})
            self.seen_serial = self.serial
            # nothing remembered yet: learn quietly for a minute instead of alarming
            self.learn_until = time.time() + 60 if not os.path.exists(path) else 0.0
        self.log_label.configure(text=("learning the normal destinations ... " if self.learn_until > time.time()
                                       else "") + "log: " + self.log_path())
        if not self.auto.get():
            self.auto.set(True)
            self.schedule()
        if self.show_var.get() == NET_SHOW[0]:   # connections are what this is about
            self.show_var.set("All connections")
            self.populate()
        if self.socks and not self.busy:
            self.refresh(quiet=True)

    def is_newdest(self, s):
        t = self.newdest.get((s["uid"], s["remote_ip"]))
        return t is not None and time.time() - t < NEWDEST_SECONDS

    def owner_key(self, uid):
        # stable key for the destination log: package set + Android user, so the
        # same app in different profiles is tracked separately
        pkgs = self.owner_pkgs(uid)
        user = self.android_user(uid)
        base = "+".join(sorted(pkgs)) if pkgs and self.app_id(uid) >= 10000 else "uid:%d" % self.app_id(uid)
        return base if user == 0 else "%s@user%d" % (base, user)

    def note_destination(self, s):
        """Log one internet connection; True if it is a destination this app never used."""
        name = self.names.get(s["remote_ip"], "")
        owner = self.owner_key(s["uid"])
        dest = dest_key(s["remote_ip"], name)
        known = self.seen.setdefault(owner, [])
        is_new = dest not in known
        learning = time.time() < self.learn_until
        if is_new:
            known.append(dest)
            if not sa.save_json(self.seen_path(), self.seen):
                if not getattr(self, "_seen_save_warned", False):
                    self._seen_save_warned = True
                    self.app.error("Couldn't save the list of known destinations to disk - new "
                                   "destinations are remembered for this session only")
            else:
                self._seen_save_warned = False
        alert = is_new and not learning
        sig = (s["uid"], s["remote_ip"], s["remote_port"])
        if sig not in self.logged or alert:
            self.logged.add(sig)
            try:
                sa.ensure_dir(NET_LOG_DIR, private=True)
                fresh = not os.path.exists(self.log_path())
                with open(os.open(self.log_path(), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600),
                          "a", newline="", encoding="utf-8") as f:
                    os.fchmod(f.fileno(), 0o600)                    # also an older, existing log
                    wr = csv.writer(f)
                    if fresh:
                        wr.writerow(["time", "app", "packages", "remote_ip", "remote_name", "port",
                                     "type", "new_destination"])
                    wr.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), self.owner_name(s["uid"]), owner,
                                 s["remote_ip"], name, s["remote_port"], s["proto"],
                                 "yes" if alert else ("learning" if is_new else "no")])
            except OSError:
                pass
        if not learning and self.log_label.cget("text").startswith("learning"):
            self.log_label.configure(text="log: " + self.log_path())
        if alert:
            self.newdest[(s["uid"], s["remote_ip"])] = time.time()
            self.app.error("New destination: %s contacted %s (port %d) for the first time"
                           % (self.owner_name(s["uid"]), name or s["remote_ip"], s["remote_port"]))
        return alert

    # ---- describing --------------------------------------------------------

    @staticmethod
    def key(s):
        return (s["proto"], s["local_ip"], s["local_port"], s["uid"])

    @staticmethod
    def android_user(uid):
        """The Android user/profile id a UID belongs to (0 = owner, 10+ = profiles)."""
        return uid // 100000

    @staticmethod
    def app_id(uid):
        """The per-user app id (same app shares this across profiles)."""
        return uid % 100000

    def owner_pkgs(self, uid):
        # package name is the same app across profiles, so look up by app-id
        return self.uid_map.get(self.app_id(uid), [])

    def owner_name(self, uid):
        app_id = self.app_id(uid)
        user = self.android_user(uid)
        pkgs = self.owner_pkgs(uid)
        lbl = self.app.apps_tab.label
        # suffix shown only for non-owner profiles, so normal phones are unchanged
        usuffix = "" if user == 0 else "  [user %d]" % user
        if app_id < 10000:
            return SYSTEM_UIDS.get(app_id, "Android system service (UID %d)" % app_id) + usuffix
        if not pkgs:
            return "Unknown app (UID %d)" % uid
        if len(pkgs) == 1:
            return lbl(pkgs[0]) + usuffix
        return "%s + %d more (shared ID)%s" % (lbl(sorted(pkgs)[0]), len(pkgs) - 1, usuffix)

    @staticmethod
    def fmt(ip, port):
        return ("[%s]:%d" % (ip, port)) if ":" in ip else ("%s:%d" % (ip, port))

    def remote_label(self, s):
        name = self.names.get(s["remote_ip"]) or ""
        return name or s["remote_ip"]

    def reach(self, s):
        if s["kind"] == "listen":
            return addr_kind(s["local_ip"]) if addr_kind(s["local_ip"]) != "internet" else "local"
        return addr_kind(s["remote_ip"])

    def risk(self, s):
        if s["kind"] != "listen" or self.reach(s) == "device":
            return "safe" if s["kind"] == "listen" else ""
        if s["local_port"] == 5555 and s["proto"] == "tcp":
            return "critical"
        if s["proto"] == "tcp":
            return "caution"
        return ""

    def sock_text(self, s):
        if s["kind"] == "listen":
            return "Open port %s %d" % (s["proto"].upper(), s["local_port"])
        if s["kind"] == "udp_temp":
            return "Temporary UDP socket on port %d (likely client side)" % s["local_port"]
        if s["kind"] == "connected":
            return "Connected to %s:%d" % (self.remote_label(s), s["remote_port"])
        return "%s %s:%d" % (s["state"].lower().replace("_", " "), self.remote_label(s), s["remote_port"])

    def sock_values(self, s):
        reach = "" if s["kind"] == "udp_temp" else REACH_TEXT.get(self.reach(s), "")
        remote = "" if s["kind"] in ("listen", "udp_temp") else self.fmt(s["remote_ip"], s["remote_port"])
        return (reach, s["proto"].upper() + ("6" if s["v6"] else ""),
                self.fmt(s["local_ip"], s["local_port"]), remote, s["state"])

    def wanted(self, s, mode):
        if mode == "Open ports":
            return s["kind"] == "listen"
        if mode == "Open ports reachable from the network":
            return s["kind"] == "listen" and self.reach(s) != "device"
        if mode == "Internet connections":
            return s["kind"] == "connected" and self.reach(s) == "internet"
        if mode == "All connections":
            return s["kind"] in ("listen", "connected")
        return True

    # ---- list --------------------------------------------------------------

    def populate(self):
        sel = self.tree.selection()
        keep = self.rows.get(sel[0]) if sel else None
        self.tree.delete(*self.tree.get_children())
        self.rows = {}
        mode = self.show_var.get()
        q = self.search_var.get().strip().lower()
        groups = {}
        for s in self.socks:
            if not self.wanted(s, mode):
                continue
            owner = self.owner_name(s["uid"])
            if q and q not in owner.lower() and q not in " ".join(self.owner_pkgs(s["uid"])).lower() \
                    and q not in str(s["local_port"]) and q not in s["remote_ip"] \
                    and q not in self.names.get(s["remote_ip"], "").lower():
                continue
            groups.setdefault(s["uid"], []).append(s)   # full UID: keep profiles distinct
        rank = {"critical": 0, "caution": 1, "unknown": 2, "safe": 3, "": 4}

        def worst(items):
            return min((self.risk(s) for s in items), key=lambda r: rank[r])
        order = sorted(groups.items(), key=lambda kv: (rank[worst(kv[1])],
                                                      self.owner_name(kv[1][0]["uid"]).lower()))
        reselect = None
        for guid, items in order:
            n_open = sum(1 for s in items if s["kind"] == "listen")
            n_conn = sum(1 for s in items if s["kind"] == "connected")
            bits = []
            if n_open:
                bits.append("%d open" % n_open)
            if n_conn:
                bits.append("%d connection%s" % (n_conn, "" if n_conn == 1 else "s"))
            oid = "o:%d" % guid
            w = worst(items)
            self.tree.insert("", "end", iid=oid, open=True,
                             text="%s  (%s)" % (self.owner_name(items[0]["uid"]), ", ".join(bits) or "other"),
                             tags=("owner",) + ((w,) if w in ("critical", "caution") else ()))
            self.rows[oid] = ("owner", guid)
            if keep == ("owner", guid):
                reselect = oid
            items.sort(key=lambda s: (s["kind"] != "listen", s["local_port"] if s["kind"] == "listen"
                                      else 0, self.remote_label(s)))
            for i, s in enumerate(items):
                iid = "%s:%d" % (oid, i)
                tags = tuple(t for t in (self.risk(s), "new" if self.key(s) in self.new_keys else "",
                                         "newdest" if self.is_newdest(s) else "") if t)
                self.tree.insert(oid, "end", iid=iid, text=self.sock_text(s),
                                 values=self.sock_values(s), tags=tags)
                self.rows[iid] = ("sock", s)
                if keep and keep[0] == "sock" and keep[1]["inode"] == s["inode"] and keep[1]["inode"] != "0":
                    reselect = iid
        if reselect:
            self.tree.selection_set(reselect)
            self.tree.see(reselect)
        n_open = sum(1 for s in self.socks if s["kind"] == "listen")
        n_net = sum(1 for s in self.socks if s["kind"] == "listen" and self.reach(s) != "device")
        n_inet = sum(1 for s in self.socks if s["kind"] == "connected" and self.reach(s) == "internet")
        self.summary.configure(text=("%d open ports (%d reachable from the network)  \u00b7  "
                                     "%d internet connections  \u00b7  read at %s"
                                     % (n_open, n_net, n_inet, time.strftime("%H:%M:%S")))
                               if self.socks else ("No device" if not self.serial else
                                                   "Press Refresh to read the network table"))

    # ---- details -----------------------------------------------------------

    def selected_row(self):
        sel = self.tree.selection()
        return self.rows.get(sel[0]) if sel else None

    def render(self):
        t = self.details
        t.configure(state="normal")
        t.delete("1.0", "end")
        w = lambda text, tag=(): t.insert("end", text, tag)  # noqa: E731
        row = self.selected_row()
        if not row:
            w("Network ports and connections\n", "h1")
            w("\nOpen port", "h2")
            w("\nAn app is waiting for others to connect to it. What matters is who can reach it:\n")
            w("\u2022 only this device - harmless, apps talking to each other\n", "ok")
            w("\u2022 anyone on the network - other devices on the same Wi-Fi can try to connect\n", "warn")
            w("\nConnection", "h2")
            w("\nAn app is talking to something right now: another app, a device on your network, "
              "or a server on the internet.\n")
            w("\nClick a line for details. Tick 'Auto-refresh' to watch it live; new open ports "
              "turn yellow.\n", "dim")
            t.configure(state="disabled")
            return
        kind, data = row
        if kind == "owner":
            items = [s for s in self.socks if s["uid"] == data]     # data = full UID (work profiles too)
            self.render_owner(w, data, items)
        else:
            self.render_sock(w, data)
        t.configure(state="disabled")

    def render_owner(self, w, uid, items):
        app_id = self.app_id(uid)
        w(self.owner_name(uid) + "\n", "h1")
        pkgs = self.owner_pkgs(uid)
        if app_id < 10000:
            w("A part of Android itself (user ID %d), not a normal app.\n" % app_id, "dim")
            if app_id == 0:
                w("Without root, Android doesn't say which of its core services this is.\n", "dim")
        if pkgs:
            w("Packages with this ID: " + ", ".join(sorted(pkgs)[:12]) +
              (" ..." if len(pkgs) > 12 else "") + "\n", "dim")
        opens = [s for s in items if s["kind"] == "listen"]
        conns = [s for s in items if s["kind"] == "connected"]
        if opens:
            w("Open ports\n", "h2")
            for s in opens:
                r = self.reach(s)
                w("\u2022 %s %d - reachable by %s\n" % (s["proto"].upper(), s["local_port"],
                                                        REACH_TEXT.get(r, r)),
                  "warn" if self.risk(s) in ("caution", "critical") else ())
        if conns:
            w("Connected to\n", "h2")
            for s in conns:
                w("\u2022 %s:%d  (%s)\n" % (self.remote_label(s), s["remote_port"],
                                            REACH_TEXT.get(self.reach(s), "")))
        temps = [s for s in items if s["kind"] == "udp_temp"]
        if temps:
            w("Temporary UDP sockets: %d (normal client traffic like name lookups)\n" % len(temps), "dim")
        if not opens and not conns and not temps:
            w("\nOnly sockets that are closing right now.\n", "dim")

    def render_sock(self, w, s):
        owner = self.owner_name(s["uid"])
        port = s["local_port"] if s["kind"] == "listen" else s["remote_port"]
        meaning = PORT_INFO.get(port)
        if s["kind"] == "listen":
            w("Open port %s %d\n" % (s["proto"].upper(), s["local_port"]), "h1")
            w("Opened by: %s\n" % owner)
            r = self.reach(s)
            w("Who can reach it\n", "h2")
            if r == "device":
                w("Only apps on this device (address %s). Nothing on the network can connect.\n"
                  % s["local_ip"], "ok")
            elif r == "any":
                w("Anyone who can reach the device over the network - other devices on the same "
                  "Wi-Fi, and possibly more if the network allows it.\n", "warn")
            else:
                w("Devices on the network that this address belongs to (%s).\n" % s["local_ip"], "warn")
            if self.risk(s) == "critical":
                w("\n\u26d4 This is ADB over the network. Anyone who reaches this port can install apps "
                  "and read data. Turn off 'Wireless debugging' / 'ADB over network' when you don't "
                  "need it.\n", "warn")
            if s["proto"] == "udp":
                w("\nUDP has no 'waiting for connections' state like TCP. 'Open' here means the app "
                  "can receive messages on this fixed port. Many system services do this to find "
                  "devices on the network or get an address.\n", "dim")
        elif s["kind"] == "udp_temp":
            w("%s\n" % self.sock_text(s), "h1")
            w("Opened by: %s\n" % owner)
            w("What this is\n", "h2")
            w("A UDP socket on a temporary port that isn't tied to one other side. Apps get these "
              "for things like looking up website names (DNS) or fast web traffic (QUIC / HTTP/3). "
              "It is the app's own end of outgoing traffic, not a service waiting for others, so "
              "it isn't counted as an open port.\n", "ok")
            w("\nTemporary ports on this device: %s. A program could deliberately listen on one of "
              "these, so this is a strong hint, not proof.\n" % s.get("eph_range", "?"), "dim")
        else:
            w("%s\n" % self.sock_text(s), "h1")
            w("Opened by: %s\n" % owner)
            w("The other side\n", "h2")
            r = self.reach(s)
            name = self.names.get(s["remote_ip"])
            if r == "device":
                w("Another app on this same device.\n")
            elif r == "local":
                w("A device on your local network (router, PC, TV, printer ...).\n")
            else:
                w("A server on the internet: %s\n" % s["remote_ip"])
                if name:
                    w("Its name: %s\n" % name)
                    if name.endswith(("1e100.net", "google.com", "googleusercontent.com")):
                        w("(1e100.net and these names belong to Google.)\n", "dim")
                elif s["remote_ip"] in self.resolving:
                    w("Looking up its name ...\n", "dim")
                elif s["remote_ip"] in self.names:
                    w("It has no public name.\n", "dim")
            w("State: %s\n" % s["state"].replace("_", " ").lower(), "dim")
            if self.is_newdest(s):
                w("\nFirst time this app was seen talking to this destination (%s).\n"
                  % dest_key(s["remote_ip"], name), "warn")
        if meaning:
            w("Port %d usually means\n" % port, "h2")
            w(meaning + "\n")
        w("\nTechnical\n", "h2")
        w("type %s%s  local %s  remote %s  UID %d  inode %s\n" % (
            s["proto"].upper(), "6" if s["v6"] else "", self.fmt(s["local_ip"], s["local_port"]),
            self.fmt(s["remote_ip"], s["remote_port"]), s["uid"], s["inode"]), "mono")

    def goto_app(self):
        row = self.selected_row()
        if not row:
            self.app.info("Select an app or a line first")
            return
        uid = row[1] if row[0] == "owner" else row[1]["uid"]
        app_id = self.app_id(uid)
        pkgs = self.uid_map.get(app_id, [])
        if app_id < 10000 and not pkgs:
            self.app.info("That's a part of Android itself, not an app in the list")
            return
        if not pkgs:
            self.app.info("That app isn't in the app list")
            return
        self.app.nb.select(1)
        self.app.apps_tab.show_package(sorted(pkgs)[0])


# --------------------------------------------------------------------------
# GUI: Security tab
# --------------------------------------------------------------------------

LEVEL_MARK = {sa.OK: "\u2705", sa.INFO: "\u2139", sa.WARN: "\u26a0", sa.BAD: "\u26d4"}
LEVEL_WORD = {sa.OK: "fine", sa.INFO: "for your info", sa.WARN: "look at it", sa.BAD: "problem"}
LEVEL_TAG = {sa.OK: "safe", sa.INFO: "", sa.WARN: "caution", sa.BAD: "critical"}


# ---- Autorun: what can start at boot (milestone 1: read-only) -------------------
#
# A boot receiver in an app's manifest means the app CAN be woken when the phone
# finishes starting - not that it will definitely run. Detection is established
# per device at run time (never from the Android version alone):
#   1. Package Manager query, including disabled receivers where supported:
#      --query-flags 0x8200 = MATCH_DISABLED_COMPONENTS (0x200) | MATCH_DISABLED_
#      UNTIL_USED_COMPONENTS (0x8000). query-receivers exists only on Android 7+,
#      where both bits have exactly these meanings; asking for both covers packages
#      in the "off until used" state whether or not 0x200 alone already matches them.
#   2. fallback: the receiver resolver table in dumpsys package (older Android)
# Whatever couldn't be established is reported as partial, never as complete.

BOOT_ACTIONS = ("android.intent.action.BOOT_COMPLETED", "android.intent.action.LOCKED_BOOT_COMPLETED",
                "android.intent.action.QUICKBOOT_POWERON", "com.htc.intent.action.QUICKBOOT_POWERON")
BOOT_ACTION_WORDS = {"android.intent.action.BOOT_COMPLETED": "after start-up",
                     "android.intent.action.LOCKED_BOOT_COMPLETED": "after start-up, before unlocking",
                     "android.intent.action.QUICKBOOT_POWERON": "after quick start-up (maker-specific)",
                     "com.htc.intent.action.QUICKBOOT_POWERON": "after quick start-up (HTC)"}
_COMPONENT_RE = re.compile(r"^([A-Za-z0-9_.]+)/([A-Za-z0-9_.$]+)$")
QUERY_FLAGS = "0x8200"     # MATCH_DISABLED_COMPONENTS | MATCH_DISABLED_UNTIL_USED_COMPONENTS
PKG_STATE_WORDS = {0: "DEFAULT (manifest decides)", 1: "ENABLED (explicitly)", 2: "OFF", 3: "OFF (by user)",
                   4: "OFF until used"}


def full_component(comp):
    """'pkg/.Cls' -> ('pkg', 'pkg.Cls'); 'pkg/a.b.Cls' -> ('pkg', 'a.b.Cls'). None if malformed."""
    m = _COMPONENT_RE.match(comp.strip())
    if not m:
        return None
    pkg, cls = m.groups()
    return pkg, (pkg + cls if cls.startswith(".") else cls)


def parse_query_receivers(text):
    """Components from 'cmd package query-receivers --brief' (each entry: a 'Receiver #N'
    header line, then 'pkg/component'). Returns a list of (pkg, class)."""
    out = []
    for line in text.splitlines():
        fc = full_component(line)
        if fc:
            out.append(fc)
    return out


# a genuine section heading, not the words appearing somewhere in the output; used
# both to decide that a table was found and by the parser, so they can't disagree
RESOLVER_HEADING_RE = re.compile(r"^\s*Receiver Resolver Table\s*:")


def has_receiver_resolver(dumpsys_text):
    return any(RESOLVER_HEADING_RE.match(l) for l in (dumpsys_text or "").splitlines())


def parse_receiver_resolver(dumpsys_text, actions=BOOT_ACTIONS):
    """Fallback for older Android: 'Receiver Resolver Table' in dumpsys package.
    Returns {(pkg, class): set(actions)}."""
    found, in_table, action = {}, False, None
    for line in dumpsys_text.splitlines():
        s = line.strip()
        if RESOLVER_HEADING_RE.match(line):
            in_table = True
            continue
        if in_table and line and not line.startswith(" "):
            break                                         # next top-level section
        if not in_table:
            continue
        m = re.match(r'^(?:Action:\s*)?"?([A-Za-z0-9_.]+)"?:$', s)     # quoted or bare action header
        if m:
            action = m.group(1) if m.group(1) in actions else None
            continue
        if action:
            for tok in s.split():
                fc = full_component(tok)
                if fc:
                    found.setdefault(fc, set()).add(action)
                    break
    return found


_QUERY_ERROR_RE = re.compile(r"(?im)^\s*(error\b|exception occurred|java\.lang\.\w*exception|"
                             r"unknown (option|command)|usage:|.*: not found$|.*: inaccessible)")


def query_error(text):
    """True only for real command-error LINES - never for a component that merely
    contains such a word (com.example/.ExceptionReceiver)."""
    return bool(_QUERY_ERROR_RE.search(text or ""))


def current_user(serial):
    """(user, source) for the user whose apps are being managed. source:
    "detected" (am get-current-user), "single-user" (that failed, but pm list users
    shows user 0 is the only one), "unverified" (failed and several users exist, or
    users couldn't be listed) - then states are NOT verified current-user states."""
    try:
        rc, out, err = adb_shell(serial, "am get-current-user", timeout=15)
        if rc == 0 and out.strip().isdigit():
            return int(out.strip()), "detected"
    except AdbError:
        pass
    try:
        rc, out, err = adb_shell(serial, "pm list users", timeout=15)
        ids = {int(x) for x in re.findall(r"UserInfo\{(\d+):", out)} if rc == 0 else set()
    except AdbError:
        ids = set()
    if ids == {0}:
        return 0, "single-user"
    try:                                     # multi-user arrived in Android 4.2 (SDK 17)
        rc, out, err = adb_shell(serial, "getprop ro.build.version.sdk", timeout=15)
        if out.strip().isdigit() and 0 < int(out.strip()) < 17:
            return 0, "single-user"
    except AdbError:
        pass
    return 0, "unverified"


def parse_package_user_state(dumpsys_pkg_text, user):
    """From 'dumpsys package <pkg>': the package's enabled state and the explicit
    component overrides for ONE user. Returns {"pkg_state": int|None,
    "disabled": set, "enabled": set, "found": bool}."""
    res = {"pkg_state": None, "disabled": set(), "enabled": set(), "found": False}
    lines = dumpsys_pkg_text.splitlines()
    i, n = 0, len(lines)
    while i < n:
        m = re.match(r"^(\s*)User (\d+):(.*)$", lines[i])
        if not m or int(m.group(2)) != user:
            i += 1
            continue
        res["found"] = True
        indent = len(m.group(1))
        e = re.search(r"\benabled=(\d+)", m.group(3))
        if e:
            res["pkg_state"] = int(e.group(1))
        i += 1
        current = None
        while i < n:
            line = lines[i]
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                break                                     # next user / section
            s = line.strip()
            if s in ("disabledComponents:", "enabledComponents:"):
                current = "disabled" if s.startswith("disabled") else "enabled"
            elif current and re.match(r"^[A-Za-z0-9_.$]+$", s):
                res[current].add(s)
            elif s:
                e = re.search(r"\benabled=(\d+)", s)
                if e and res["pkg_state"] is None:
                    res["pkg_state"] = int(e.group(1))
                current = None if not s.endswith(":") else current
            i += 1
        break
    return res


def detect_boot_receivers(serial, user):
    """Read-only inventory. Returns {"receivers": {(pkg, cls): {"actions": set}},
    "method", "complete", "disabled_included", "user_scoped", "notes": [..]}.
    "complete" = the RECEIVER INVENTORY was fully established by a user-scoped
    Package Manager query that included switched-off receivers. It says nothing
    about whether the current user was verified (that's reported separately)."""
    res = {"receivers": {}, "method": "", "disabled_included": None, "user_scoped": None,
           "inventory_scope": None, "complete": False, "notes": []}
    ok_actions = 0
    for action in BOOT_ACTIONS:
        out = None
        # both options tried independently: a device may support one but not the other
        for args in (("--user", str(user), "--query-flags", QUERY_FLAGS), ("--user", str(user)),
                     ("--query-flags", QUERY_FLAGS), ()):
            cmd = "cmd package query-receivers %s --brief -a %s" % (" ".join(args), action)
            try:
                rc, o, err = adb_shell(serial, cmd, timeout=30)
            except AdbError:
                continue
            if rc == 0 and not query_error(o + err):
                out, flag, scoped = o, QUERY_FLAGS in args, "--user" in args
                break
        if out is None:
            continue
        ok_actions += 1
        res["disabled_included"] = flag if res["disabled_included"] is None else res["disabled_included"] and flag
        res["user_scoped"] = scoped if res["user_scoped"] is None else res["user_scoped"] and scoped
        for fc in parse_query_receivers(out):
            res["receivers"].setdefault(fc, {"actions": set()})["actions"].add(action)
    if ok_actions:
        if not res["disabled_included"]:
            res["notes"].append("this phone's Package Manager couldn't include receivers that are already "
                                "switched off, so those may be missing")
        if not res["user_scoped"]:
            res["notes"].append("some receiver queries couldn't be scoped to the selected Android user - "
                                "results may reflect the Package Manager's default user")
    if ok_actions:
        res["inventory_scope"] = "user" if res["user_scoped"] else "unscoped"
    if ok_actions == len(BOOT_ACTIONS):
        res["method"] = "Package Manager query"
        res["complete"] = bool(res["disabled_included"] and res["user_scoped"])
        return res
    # fallback for older Android, or when the query didn't answer for every action
    cmd_ok, table_found, table = False, False, {}
    for cmd, tmo in (("dumpsys package r", 60), ("dumpsys package", 120)):   # 2nd runs if 1st fails / has no table
        try:
            rc, o, err = adb_shell(serial, cmd, timeout=tmo)
        except AdbError:
            continue
        if rc != 0:
            continue
        cmd_ok = True
        if has_receiver_resolver(o):
            table_found = True
            table = parse_receiver_resolver(o)
            break
    for fc, acts in table.items():
        res["receivers"].setdefault(fc, {"actions": set()})["actions"].update(acts)
    pm = "Package Manager query (some start-up events only)" if ok_actions else ""
    if table_found:
        res["method"] = (pm + " + " if pm else "") + "dumpsys receiver table"
        res["inventory_scope"] = "resolver"
        res["notes"].append("part of the list comes from an older receiver table that may miss receivers "
                            "that are switched off" + ("" if table else " (that table lists no start-up receivers)"))
        res["notes"].append("read from the resolver table; per-user inventory scope not established (the "
                            "states shown are still read for the selected user)")
    elif cmd_ok:
        res["method"] = pm or "nothing usable"
        res["notes"].append("dumpsys answered but contained no receiver table, so the older fallback "
                            "couldn't be used")
    else:
        res["method"] = pm or "nothing worked"
        res["notes"].append("the older dumpsys fallback was unavailable" + (
            "" if pm else " and the Package Manager query didn't answer either - the list is empty because "
                          "it couldn't be read, not because no app starts at boot"))
    return res


def receiver_states(serial, user, pkgs, on_progress=None):
    """Per package: package state + component overrides for `user` (+ target SDK)."""
    out = {}
    for i, p in enumerate(sorted(pkgs)):
        if on_progress:
            on_progress(i, len(pkgs))
        try:
            rc, o, err = adb_shell(serial, "dumpsys package " + shlex.quote(p), timeout=30)
            out[p] = parse_package_user_state(o, user) if rc == 0 else None
            if out[p] is not None:
                m = re.search(r"\btargetSdk=(\d+)", o)
                out[p]["target_sdk"] = int(m.group(1)) if m else None      # None = couldn't be read
        except AdbError:
            out[p] = None
    return out


def boot_signals(det, states, user_verified):
    """Start-at-boot per package, for the Security tab's spyware-pattern check.
    Returns None when the inventory couldn't be read at all, else {"complete": bool,
    "pkgs": {pkg: True if any start-up receiver may run, False if all are switched
    off}}. "complete" = every start-up event answered by a Package Manager query
    scoped to the verified current user; only then does "not listed" mean "no
    start-up receiver". (Queries that leave out switched-off receivers are still
    complete for this purpose: a switched-off receiver can't start the app.)"""
    if not det or not det.get("receivers") and det.get("method") in ("nothing usable", "nothing worked", ""):
        return None
    by = {}
    for pkg, cls in det["receivers"]:
        by.setdefault(pkg, []).append(cls)
    pkgs = {pkg: not all(receiver_state_word(c, (states or {}).get(pkg)) == "DISABLED" for c in classes)
            for pkg, classes in by.items()}
    complete = det.get("method") == "Package Manager query" and bool(det.get("user_scoped")) and user_verified
    return {"complete": complete, "pkgs": pkgs}


def receiver_state_word(cls, st):
    """DEFAULT / ENABLED / DISABLED / UNKNOWN for one receiver, plus whether the whole
    package is off."""
    if st is None or not st.get("found"):
        return "UNKNOWN"
    if cls in st["disabled"]:
        return "DISABLED"
    if cls in st["enabled"]:
        return "ENABLED"
    return "DEFAULT"


# ---- Autorun milestone 2: controls (each one confirmed, applied, then VERIFIED) --
#
# Three separate actions, never substituted for one another:
#   A. one boot receiver off / back  (pm disable-user / enable / default-state on
#      that component; Android often refuses this for the adb shell - then nothing
#      changes and we say so; with the user's root option it goes through su)
#   B. restrict / allow background execution (AppOps; the ops depend on the
#      Android version and the app's target SDK, like AOSP's battery restriction)
#   C. the whole app OFF / ON (pm disable-user / enable for the package)
# Every change is read back from the phone before it's reported as done.

REFUSAL_RE = re.compile(r"(?i)securityexception|shell cannot change component state|permission denial|"
                        r"not allowed to")
UNSUPPORTED_RE = re.compile(r"(?i)unknown command|unknown option|^error: unknown|not found$", re.M)
COMPONENT_TARGET = {"disabled": ("disable-user", "DISABLED"), "enabled": ("enable", "ENABLED"),
                    "default": ("default-state", "DEFAULT")}
OUTCOME_WORDS = {"verified": "Done - checked on the phone",
                 "refused": "Not changed - Android refused it",
                 "unsupported": "Not changed - this phone doesn't support that command",
                 "unverified": "Unknown - the command ran, but the phone doesn't show the expected state",
                 "failed": "Not changed - the command failed",
                 "already": "Nothing to do - it was already in that state, so nothing was sent"}


def root_available(serial):
    """True only if su really gives uid 0 (an su binary alone proves nothing)."""
    try:
        rc, out, err = adb_shell(serial, "su -c id", timeout=20)
    except AdbError:
        return False
    return rc == 0 and "uid=0(" in out


def device_fingerprint(serial):
    try:
        return adb_shell(serial, "getprop ro.build.fingerprint", timeout=15)[1].strip() or "?"
    except AdbError:
        return "?"


def _shell_maybe_root(serial, cmd, use_root):
    full = "su -c " + shlex.quote(cmd) if use_root else cmd
    try:
        rc, out, err = adb_shell(serial, full, timeout=30)
    except AdbError as e:
        return None, str(e)
    return rc, (out + "\n" + err).strip()


def _classify(rc, text):
    if rc is None:
        return "failed"
    if REFUSAL_RE.search(text):
        return "refused"
    if UNSUPPORTED_RE.search(text):
        return "unsupported"
    return None


def set_component_state(serial, user, pkg, cls, target, use_root=False):
    """Set ONE component to disabled / enabled / default for `user`, then read it back.
    Returns {"outcome", "message", "state"} - the state actually read afterwards."""
    verb, expect = COMPONENT_TARGET[target]
    comp = shlex.quote("%s/%s" % (pkg, cls))
    rc, text = _shell_maybe_root(serial, "pm %s --user %d %s" % (verb, user, comp), use_root)
    bad = _classify(rc, text)
    st = receiver_states(serial, user, {pkg}).get(pkg)
    now = receiver_state_word(cls, st)
    if bad:
        return {"outcome": bad, "message": last_line(text) or "", "state": now}
    if now == expect:
        return {"outcome": "verified", "message": last_line(text) or "", "state": now}
    return {"outcome": "unverified" if rc == 0 else "failed", "message": last_line(text) or "", "state": now}


def set_package_state(serial, user, pkg, enable, use_root=False):
    """The WHOLE app on/off for `user`, then read back. Never used as a fallback."""
    cmd = ("pm enable --user %d %s" if enable else "pm disable-user --user %d %s") % (user, shlex.quote(pkg))
    rc, text = _shell_maybe_root(serial, cmd, use_root)
    bad = _classify(rc, text)
    st = receiver_states(serial, user, {pkg}).get(pkg) or {}
    ps = st.get("pkg_state")
    ok = (ps in (0, 1)) if enable else (ps in (2, 3))
    if bad:
        return {"outcome": bad, "message": last_line(text) or "", "pkg_state": ps}
    return {"outcome": "verified" if ok else ("unverified" if rc == 0 else "failed"),
            "message": last_line(text) or "", "pkg_state": ps}


APPOPS_PROBE_OP = "RUN_IN_BACKGROUND"
APPOPS_PROBE = "get android " + APPOPS_PROBE_OP      # a harmless read of one Android setting


def appops_answer_ok(out, err, op=APPOPS_PROBE_OP):
    """True when the text IS a real AppOps answer for `op` ("No operations." or
    "OP: mode"). Judged by content, not exit code: on some phones (seen on a Redmi,
    Android 15) the appops commands return exit code 255 even when they work."""
    text = (out or "") + (err or "")
    return not UNSUPPORTED_RE.search(text) and not query_error(text) and parse_appops_mode(out, op) is not None


def appops_prefix(serial):
    """'cmd appops' (Android 7+), else the older 'appops' tool, else None - found
    by a harmless real read, not by the help text (whose exit code isn't reliable)."""
    for pref in ("cmd appops", "appops"):
        try:
            rc, out, err = adb_shell(serial, "%s %s" % (pref, APPOPS_PROBE), timeout=15)
        except AdbError:
            continue
        if appops_answer_ok(out, err):
            return pref
    return None


def background_ops(sdk, target_sdk):
    """AppOps a background restriction uses, following AOSP: Android 9+ sets
    RUN_ANY_IN_BACKGROUND, plus RUN_IN_BACKGROUND for apps targeting < 26;
    Android 7-8 has only RUN_IN_BACKGROUND; older Android has none."""
    if sdk >= 28:
        if not target_sdk:
            return None              # unknown target SDK: can't tell whether the legacy op applies
        return ["RUN_ANY_IN_BACKGROUND"] + (["RUN_IN_BACKGROUND"] if target_sdk < 26 else [])
    if sdk >= 24:
        return ["RUN_IN_BACKGROUND"]
    return []


def parse_appops_mode(text, op):
    """'implicit' when the app has no entry ('No operations.'), else the mode word."""
    m = re.search(r"(?m)^\s*%s:\s*([a-z_]+)" % re.escape(op), text or "")
    if m:
        return m.group(1)
    if "No operations" in (text or ""):
        return "implicit"
    return None


def _appops(serial, pref, args, user, accept):
    """Run an appops command for `user`; `accept(out, err)` decides whether it
    worked (by content - the exit code isn't reliable on every phone). The
    unscoped form is only acceptable for user 0 (older tools without --user act on
    it); for any other user a missing --user would read or change the WRONG user's
    settings, so it isn't tried."""
    cmds = ["%s %s --user %d %s" % (pref, args[0], user, args[1])]
    if user == 0:
        cmds.append("%s %s %s" % (pref, args[0], args[1]))
    for cmd in cmds:
        try:
            rc, out, err = adb_shell(serial, cmd, timeout=20)
        except AdbError:
            continue
        if accept(out, err):
            return out
    return None


def appops_get(serial, pref, pkg, op, user):
    """The mode, or None - only a real AppOps answer counts."""
    out = _appops(serial, pref, ("get", "%s %s" % (shlex.quote(pkg), op)), user,
                  lambda o, e: appops_answer_ok(o, e, op))
    return None if out is None else parse_appops_mode(out, op)


def appops_set(serial, pref, pkg, op, mode, user):
    """True if the phone didn't reject the command. That does NOT mean it took
    effect: callers always read the mode back, and only that read decides."""
    return _appops(serial, pref, ("set", "%s %s %s" % (shlex.quote(pkg), op, mode)), user,
                   lambda o, e: not UNSUPPORTED_RE.search(o + e) and not query_error(o + e)) is not None


def read_background_modes(serial, pref, pkg, user, ops):
    """Current mode of every op, or None if ANY can't be read (then nothing may change)."""
    originals = {op: appops_get(serial, pref, pkg, op, user) for op in ops}
    return None if not ops or any(v is None for v in originals.values()) else originals


def restrict_background(serial, pref, pkg, user, ops, originals=None):
    """Set 'ignore' on each op and read back. `originals` must already be read AND
    saved by the caller (write-ahead); if not given they're read here.
    Returns {"outcome", "originals", "readback"}."""
    if originals is None:
        originals = read_background_modes(serial, pref, pkg, user, ops)
    if not originals:
        return {"outcome": "unsupported", "originals": {}, "readback": {}}
    for op in ops:
        if not appops_set(serial, pref, pkg, op, "ignore", user):
            break
    readback = {op: appops_get(serial, pref, pkg, op, user) for op in ops}
    ok = all(v == "ignore" for v in readback.values())
    return {"outcome": "verified" if ok else "unverified", "originals": originals, "readback": readback}


def allow_background(serial, pref, pkg, user, originals):
    """Put every saved op back. An original 'no entry' can only be restored as an
    explicit 'default' entry - functionally the same, reported as such."""
    readback, approx = {}, []
    for op, orig in originals.items():
        target = "default" if orig in ("implicit", None) else orig
        if orig == "implicit":
            approx.append(op)
        appops_set(serial, pref, pkg, op, target, user)
        readback[op] = appops_get(serial, pref, pkg, op, user)
    ok = all(readback[op] == ("default" if o in ("implicit", None) else o) for op, o in originals.items())
    return {"outcome": "verified" if ok else "unverified", "readback": readback, "approximate": approx}


# ---- opening an interactive adb shell in the user's terminal ------------------

# how each terminal is told what to run: "argv" = program and arguments follow as
# separate words after the flag; "string" = one command string after the flag.
TERMINALS = [("x-terminal-emulator", "-e", "argv"), ("gnome-terminal", "--", "argv"),
             ("konsole", "-e", "argv"), ("xfce4-terminal", "-x", "argv"), ("mate-terminal", "-x", "argv"),
             ("lxterminal", "-e", "string"), ("tilix", "-e", "string"), ("terminator", "-x", "argv"),
             ("kitty", "", "argv"), ("alacritty", "-e", "argv"), ("xterm", "-e", "argv")]


def find_terminal():
    """(path, flag, style, extra_args) of a terminal emulator, or None.
    $TERMINAL wins when set; it may carry its own arguments ("kitty --single-instance",
    '"/opt/my term/term" -x'), split with shlex - never run through a shell. Then the
    system default, then common terminals."""
    import shutil as _sh
    env = (os.environ.get("TERMINAL") or "").strip()
    if env:
        try:
            words = shlex.split(env)
        except ValueError:
            words = []
        if words:
            exe = words[0]
            if os.path.isabs(exe):
                path = exe if (os.path.isfile(exe) and os.access(exe, os.X_OK)) else None   # not a directory
            else:
                path = _sh.which(exe)
            if path:
                known = next((t for t in TERMINALS if t[0] == os.path.basename(path)), None)
                flag, style = (known[1], known[2]) if known else ("-e", "argv")
                extra = words[1:]
                if extra and flag and extra[-1] == flag:
                    extra = extra[:-1]               # "xterm -e": the flag is added once, by us
                return path, flag, style, extra
    for name, flag, style in TERMINALS:
        path = _sh.which(name)
        if path:
            return path, flag, style, []
    return None


def shell_command(term, serial):
    """argv that opens `<configured adb> -s SERIAL shell` in that terminal. The serial
    is never interpolated unquoted: separate argv words, or shlex-quoted in string
    mode. The user's own terminal arguments come right after the terminal program."""
    path, flag, style = term[:3]
    extra = list(term[3]) if len(term) > 3 else []
    inner = [ADB, "-s", serial, "shell"]
    if style == "string":
        return [path] + extra + [flag, " ".join(shlex.quote(x) for x in inner)]
    return [path] + extra + ([flag] if flag else []) + inner


def safe_open_url(url):
    """Open a link in the browser only if it's a plain http(s) web address - never file://,
    custom app handlers or anything else (links can come from AI answers or downloaded data).
    Returns True if it was handed to the browser."""
    u = (url or "").strip() if isinstance(url, str) else ""
    try:
        parts = urllib.parse.urlsplit(u)
    except ValueError:
        return False
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc or any(c in u for c in "\r\n\t "):
        return False
    try:
        webbrowser.open(u)
    except Exception:
        return False
    return True


def manual_shell_hint(serial):
    """The command a user can paste themselves - same adb the app uses, quoted."""
    return "%s -s %s shell" % (shlex.quote(ADB), shlex.quote(serial or ""))


def open_device_shell(serial):
    """Start the terminal (detached). Returns None on success or an error message."""
    if not serial:
        return "No device connected - pick one at the top"
    term = find_terminal()
    if not term:
        return ("No terminal program was found. Install one (e.g. xterm) or set the TERMINAL "
                "environment variable - or run this yourself: %s" % manual_shell_hint(serial))
    try:
        subprocess.Popen(shell_command(term, serial), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError as e:
        return "Couldn't start %s: %s" % (os.path.basename(term[0]), e.strerror or e)
    return None


class AutorunTab(ttk.Frame):
    """Read-only view of apps that can start at boot (milestone 1)."""
    # an unset override does NOT mean "on": the manifest may say android:enabled="false"
    STATE_WORDS = {"DEFAULT": "DEFAULT - manifest decides", "ENABLED": "ENABLED - explicitly",
                   "DISABLED": "DISABLED - explicitly", "UNKNOWN": "UNKNOWN - couldn't be read"}

    def __init__(self, master, app):
        super().__init__(master)
        self.app, self.serial, self.busy, self.gen = app, None, False, 0
        self.data = None
        top = ttk.Frame(self, padding=(6, 6, 6, 2))
        top.pack(fill="x")
        self.refresh_btn = ttk.Button(top, text="Refresh", command=self.refresh)
        self.refresh_btn.pack(side="left")
        self.show_sys = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Show system apps", variable=self.show_sys,
                        command=self.populate).pack(side="left", padx=8)
        self.shell_btn = ttk.Button(top, text="Open shell", command=self.open_shell)
        self.shell_btn.pack(side="right")
        self.status = ttk.Label(self, text="", foreground="#555555", padding=(6, 0))
        self.status.pack(fill="x")
        self.saved = JsonStore(os.path.join(CONFIG_DIR, "autorun_saved.json"))   # originals, for exact restore
        self.denied = set()                   # (serial, build, privilege) where Android refused receivers
        self.sel_pkg = self.sel_cls = None
        ctl = ttk.LabelFrame(self, text="Change - you confirm first, and every change is checked on the phone "
                                        "afterwards", padding=6)
        ctl.pack(side="bottom", fill="x", padx=6, pady=(0, 6))
        self.btns = {}
        for r, (label, items) in enumerate((
                ("This start-up receiver:", (("rx_off", "Switch it off"), ("rx_back", "Put it back"))),
                ("Background (the app keeps working):", (("bg_restrict", "Restrict background"),
                                                         ("bg_allow", "Allow background again"))),
                ("The WHOLE app:", (("app_off", "Turn app OFF"), ("app_on", "Turn app ON"))))):
            ttk.Label(ctl, text=label).grid(row=r, column=0, sticky="w", padx=(0, 8), pady=1)
            for c, (key, text) in enumerate(items):
                b = ttk.Button(ctl, text=text, command=lambda k=key: self.act(k))
                b.grid(row=r, column=c + 1, sticky="w", padx=2, pady=1)
                self.btns[key] = b
        ttk.Checkbutton(ctl, text="Use root (su) for this operation", variable=self.app.apps_tab.use_root) \
            .grid(row=0, column=3, sticky="w", padx=(16, 0))
        self.update_buttons()
        pane = ttk.PanedWindow(self, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=6, pady=6)
        left = ttk.Frame(pane)
        pane.add(left, weight=3)
        self.tree = ttk.Treeview(left, columns=("when", "state", "package"), show="tree headings",
                                 selectmode="browse")
        for c, h, w in (("#0", "App / start-up receiver", 300), ("when", "Can start", 200),
                        ("state", "State", 160), ("package", "Package", 220)):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.tag_configure("off", foreground="#777777")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.detail = tk.Text(pane, wrap="word", width=40, relief="flat", padx=8, pady=6, cursor="arrow")
        self.detail.tag_configure("h1", font=("TkDefaultFont", 12, "bold"))
        self.detail.tag_configure("dim", foreground="#777777")
        pane.add(self.detail, weight=2)
        self._detail([("Apps that can start when the phone finishes starting up are listed here. "
                       "Press Refresh after connecting a phone.", "dim")])

    def post(self, fn, *args):
        self.app.q.put(("call", fn) + args)

    def open_shell(self):
        """An interactive adb shell for the selected phone, in a terminal window."""
        err = open_device_shell(self.serial)
        if err:
            self.app.error(err)
        else:
            # Popen only proves the terminal was started; adb errors show up in that terminal
            self.app.info("Started a terminal for an ADB shell on %s" % self.serial)

    def _detail(self, chunks):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        for t, tag in chunks:
            self.detail.insert("end", t, tag)
        self.detail.configure(state="disabled")

    def set_device(self, serial):
        if serial == self.serial:
            return
        self.serial, self.data = serial, None
        self.gen += 1                                     # drop late results for the old device ...
        self.busy = False                                 # ... and free the tab for the new one
        self.refresh_btn.state(["!disabled"])
        self.populate()

    def on_shown(self):
        if self.serial and self.data is None and not self.busy:
            self.refresh()

    def refresh(self):
        if not self.serial or self.busy:
            return
        self.busy = True
        self.refresh_btn.state(["disabled"])
        self.status.configure(text="Reading which apps can start at boot ...")
        threading.Thread(target=self._work, args=(self.gen, self.serial), daemon=True).start()

    def _work(self, gen, serial):
        try:
            t0 = time.time()
            user, usrc = current_user(serial)
            det = detect_boot_receivers(serial, user)
            states = receiver_states(serial, user, {p for p, _ in det["receivers"]},
                                     lambda i, n: self.post(self._progress, gen, "Reading app states %d/%d ..."
                                                            % (i + 1, n)))
            self.post(self._done, gen, serial, dict(det, user=user, user_source=usrc, states=states,
                                                    user_verified=usrc in ("detected", "single-user"),
                                                    seconds=round(time.time() - t0, 1)), None)
        except Exception as e:                            # always report back
            self.post(self._done, gen, serial, None, "%s: %s" % (type(e).__name__, e))

    def _progress(self, gen, text):
        if gen == self.gen and self.busy:
            self.status.configure(text=text)

    def _done(self, gen, serial, data, error):
        if gen != self.gen or serial != self.serial:
            return
        self.busy = False
        self.refresh_btn.state(["!disabled"])
        if error:
            self.status.configure(text="Couldn't read the start-up list: " + error)
            return
        self.data = data
        self.populate()

    def label(self, pkg):
        try:
            return self.app.apps_tab.label(pkg)
        except Exception:
            return pkg

    def is_system(self, pkg):
        """True / False when the Apps list knows this package, None while it doesn't
        (e.g. the Apps scan hasn't finished) - unknown is never treated as 'user app'."""
        a = getattr(self.app.apps_tab, "apps", {}).get(pkg)
        if not a or a.get("system") is None:
            return None                                   # no record, or no classification in it
        return bool(a["system"])

    def populate(self):
        self.tree.delete(*self.tree.get_children())
        self.sel_pkg = self.sel_cls = None               # the old selection is gone with the old rows
        self.update_buttons()
        d = self.data
        if not d:
            self.status.configure(text="")
            return
        by_pkg = {}
        for (pkg, cls), info in d["receivers"].items():
            by_pkg.setdefault(pkg, []).append((cls, info))
        shown, unclassified = 0, 0
        for pkg in sorted(by_pkg, key=lambda p: self.label(p).lower()):
            kind = self.is_system(pkg)
            if kind is None:
                unclassified += 1                         # shown, and said honestly
            elif kind and not self.show_sys.get():
                continue
            st = d["states"].get(pkg)
            pstate = (st or {}).get("pkg_state")
            off = pstate in (2, 3, 4)
            words = sorted({BOOT_ACTION_WORDS.get(a, a) for _, i in by_pkg[pkg] for a in i["actions"]})
            # " · " joins them: the words themselves contain commas
            pid = "p:" + pkg
            self.tree.insert("", "end", iid=pid, text=self.label(pkg), open=False,
                             values=(" · ".join(words), "app OFF" if off else
                                     ("system or user: not known yet" if kind is None else ""), pkg),
                             tags=("off",) if off else ())
            for cls, info in sorted(by_pkg[pkg]):
                state = receiver_state_word(cls, st)
                sword = self.STATE_WORDS[state] + ("" if d.get("user_verified", d.get("user_source") in
                                                                ("detected", "single-user"))
                                                   else " (user 0, not verified)")
                self.tree.insert(pid, "end", iid="r:%s/%s" % (pkg, cls), text=cls.rsplit(".", 1)[-1],
                                 values=(" · ".join(BOOT_ACTION_WORDS.get(a, a) for a in sorted(info["actions"])),
                                         sword, pkg),
                                 tags=("off",) if off or state == "DISABLED" else ())
            shown += 1
        hidden = len(by_pkg) - shown
        usrc = {"detected": "detected", "single-user": "the only user"}.get(d.get("user_source"), "NOT verified")
        text = "%d app(s) can start at boot (user %d, %s) - found by: %s" % (len(by_pkg), d["user"], usrc,
                                                                          d["method"])
        if hidden:
            text += " - %d system app(s) hidden" % hidden
        if unclassified:
            text += " - %d not yet known as system or user (the Apps list is still loading)" % unclassified
        text += "  |  Receiver inventory: " + (
            "complete Package Manager query for this user, including switched-off and off-until-used "
            "receivers (APK manifests not yet cross-checked)" if d["complete"] else
            "PARTIAL - " + "; ".join(d["notes"]))
        if not d.get("user_verified", d.get("user_source") in ("detected", "single-user")):
            text += "  |  Current user: NOT VERIFIED - component states shown for user 0 and may not be yours"
        if d.get("seconds") is not None:
            text += "  |  read in %.1f s" % d["seconds"]
        self.status.configure(text=text)

    # ---- controls ------------------------------------------------------------

    @staticmethod
    def record_key(serial, user, pkg):
        return "%s|%s|%s" % (serial, user, pkg)

    def saved_key(self, pkg):
        return self.record_key(self.serial, (self.data or {}).get("user", 0), pkg)

    def update_buttons(self):
        st = ((self.data or {}).get("states") or {}).get(self.sel_pkg) or {}
        saved = self.saved.get(self.saved_key(self.sel_pkg)) or {} if self.sel_pkg else {}
        off = st.get("pkg_state") in (2, 3, 4)
        can = {"rx_off": bool(self.sel_cls), "rx_back": bool(self.sel_cls and self.sel_cls in
                                                              saved.get("components", {})),
               "bg_restrict": bool(self.sel_pkg), "bg_allow": bool(saved.get("appops")),
               "app_off": bool(self.sel_pkg) and not off, "app_on": bool(self.sel_pkg) and off}
        verified = bool(self.data) and self.user_verified()
        for k, b in self.btns.items():
            b.state(["!disabled"] if can[k] and not self.busy and verified else ["disabled"])

    def user_verified(self):
        d = self.data or {}
        return bool(d.get("user_verified", d.get("user_source") in ("detected", "single-user")))

    def confirm_text(self, kind, pkg, cls):
        label = self.label(pkg)
        sysapp = self.is_system(pkg)
        warn = ("\n\nThis is a SYSTEM app - changing it can affect how the phone works." if sysapp
                else "\n\nIt isn't known yet whether this is a system app." if sysapp is None else "")
        if kind == "rx_off":
            key = (self.serial, getattr(self, "_fp", "?"), "root" if self.app.apps_tab.use_root.get() else "shell")
            again = ("\n\nAndroid refused this on this phone before. Try again?" if key in self.denied else "")
            return ("Switch off only this start-up receiver?\n\n%s\n(%s)\n\nThe app itself keeps working; "
                    "Android just won't wake it through this receiver. Many phones refuse this over adb - if "
                    "so, nothing is changed.%s%s" % (cls, label, warn, again))
        if kind == "rx_back":
            return "Put this receiver back exactly as it was before?\n\n%s\n(%s)" % (cls, label)
        if kind == "bg_restrict":
            return ("Restrict background execution for %s?\n\nThe app keeps working when you open it, but "
                    "can't keep running in the background (like Android's battery 'Restricted' setting). "
                    "It does NOT remove its start-up receivers.%s" % (label, warn))
        if kind == "bg_allow":
            return "Allow %s to run in the background again, as it was before?" % label
        if kind == "app_off":
            return ("Turn the WHOLE app OFF?\n\n%s\n\nIt can't be used at all until you turn it back on - "
                    "its icon disappears. This is NOT the same as switching off one receiver.%s" % (label, warn))
        return "Turn %s back ON?" % label

    def act(self, kind):
        if self.busy or not self.data or not self.sel_pkg:
            return
        if not self.user_verified():                     # second guard, not only the disabled buttons
            messagebox.showwarning("Can't change anything", "The current Android user couldn't be "
                                   "established, so a change might hit the wrong user. Nothing was changed.",
                                   parent=self)
            return
        pkg, cls = self.sel_pkg, self.sel_cls
        if not messagebox.askyesno("Please confirm", self.confirm_text(kind, pkg, cls), parent=self):
            return
        st = (self.data.get("states") or {}).get(pkg)
        ctx = {"serial": self.serial, "user": self.data["user"], "user_verified": True, "pkg": pkg, "cls": cls,
               "before": receiver_state_word(cls, st) if cls else None,
               "target_sdk": (st or {}).get("target_sdk"), "key": self.saved_key(pkg),
               "want_root": bool(self.app.apps_tab.use_root.get())}       # frozen for the worker
        self.busy = True
        self.update_buttons()
        self.status.configure(text="Applying the change and checking it on the phone ...")
        threading.Thread(target=self._act_work, args=(self.gen, kind, ctx), daemon=True).start()

    def _act_work(self, gen, kind, ctx):
        try:
            res = self._act_run(kind, ctx)
        except Exception as e:                            # always report back
            res = {"outcome": "failed", "message": "%s: %s" % (type(e).__name__, e)}
        log_action(ctx["serial"], {"rx_off": "receiver-off", "rx_back": "receiver-back", "bg_restrict": "bg-restrict",
                                   "bg_allow": "bg-allow", "app_off": "app-off", "app_on": "app-on"}.get(kind, kind),
                   ctx["pkg"], res.get("outcome") == "verified", res.get("message", ""), outcome=res.get("outcome"),
                   user=ctx["user"], target=ctx["cls"] or "", source="autorun")
        try:
            res["fresh"] = receiver_states(ctx["serial"], ctx["user"], {ctx["pkg"]}).get(ctx["pkg"])
        except Exception:
            res["fresh"] = None
        self.post(self._act_done, gen, ctx["serial"], kind, ctx["pkg"], ctx["cls"], res)

    def _save_record(self, key, saved):
        """True only if the restore record is safely on disk."""
        return bool(self.saved.put(key, saved))

    def _persist_before_change(self, key, saved, previous):
        """Write the record and confirm it's on disk BEFORE any change - every time,
        even if a record already exists (a failed write leaves it in memory only).
        On failure the in-memory record is rolled back to what it was, so the GUI
        never offers to restore a change that never happened."""
        if self._save_record(key, saved):
            return True
        if previous is None:                 # in-memory rollback (disk may still fail; that's fine)
            self.saved.delete(key)
        else:
            self.saved.put(key, previous)
        return False

    def _act_run(self, kind, ctx):
        """Runs in the worker using ONLY the frozen context - never live GUI state.
        Restore records are written BEFORE the phone is changed (write-ahead)."""
        serial, user, pkg, cls, key = ctx["serial"], ctx["user"], ctx["pkg"], ctx["cls"], ctx["key"]
        root = ctx["want_root"] and root_available(serial)
        if ctx["want_root"] and not root and kind in ("rx_off", "rx_back"):
            return {"outcome": "failed", "message": "root (su) isn't available - su didn't return uid 0, "
                                                    "so nothing was tried"}
        previous = self.saved.get(key)
        saved = copy.deepcopy(previous) if previous else {}
        nosave = {"outcome": "failed", "message": "the restore record couldn't be saved to disk, so nothing "
                                                  "was changed on the phone"}
        if kind == "rx_off":
            self._fp = device_fingerprint(serial)
            before = ctx["before"]
            if before in (None, "UNKNOWN"):
                return {"outcome": "failed", "message": "its current state couldn't be read, so it couldn't be "
                                                        "restored exactly - nothing was changed"}
            if before == "DISABLED":                    # already off: no record, no command
                return {"outcome": "already", "message": ALREADY_MSG, "state": before}
            new_record = cls not in saved.get("components", {})
            saved.setdefault("components", {}).setdefault(cls, before)     # keep the FIRST original
            if not self._persist_before_change(key, saved, previous):
                return nosave
            op = journal_begin(serial, user, pkg, "receiver-off", before, "DISABLED", cls, "autorun")
            if op is False:
                return journal_refusal(pkg)
            if op == NOOP:
                return {"outcome": "already", "message": ALREADY_MSG, "state": before}
            res = journal_close(op, set_component_state(serial, user, pkg, cls, "disabled", root))
            if res["outcome"] == "refused":
                self.denied.add((serial, self._fp, "root" if root else "shell"))
            if new_record:
                # decided ONLY by the read-back, whatever the outcome: discard the new
                # record exactly when the phone provably still has the original state
                # (e.g. "off" pressed on a receiver that was already off)
                if res.get("state") == before:
                    saved["components"].pop(cls, None)
                    if not self._save_record(key, saved):
                        res["message"] = (res.get("message", "") + " (the unneeded restore record couldn't be "
                                          "removed from disk)").strip()
                elif res["outcome"] != "verified":
                    res["message"] = (res.get("message", "") + " - it couldn't be confirmed that the receiver is "
                                      "unchanged, so its original state was kept: 'Put it back' can restore it"
                                      ).strip(" -")
            return res
        if kind == "rx_back":
            before = saved.get("components", {}).get(cls)
            if not isinstance(before, str) or before.lower() not in COMPONENT_TARGET:
                return {"outcome": "failed", "message": "the saved original state for this receiver is missing "
                                                        "or damaged, so it can't be put back exactly - nothing "
                                                        "was changed"}
            op = journal_begin(serial, user, pkg, "receiver-back", None, COMPONENT_TARGET[before.lower()][1], cls,
                               "autorun")
            if op is False:
                return journal_refusal(pkg)
            if op == NOOP:
                return {"outcome": "already", "message": ALREADY_MSG}
            res = journal_close(op, set_component_state(serial, user, pkg, cls, before.lower(), root))
            if res["outcome"] == "verified":
                saved["components"].pop(cls, None)
                if not self._save_record(key, saved):
                    res["message"] = "restored on the phone, but the restore record couldn't be removed from disk"
            return res
        if kind in ("bg_restrict", "bg_allow"):
            pref = appops_prefix(serial)
            if not pref:
                return {"outcome": "unsupported", "message": "this phone has no AppOps command"}
            if kind == "bg_allow":
                orig = saved.get("appops", {})
                op = journal_begin(serial, user, pkg, "bg-allow", None,
                                   {o: ("default" if v in ("implicit", None) else v) for o, v in orig.items()} or None,
                                   "", "autorun")
                if op is False:
                    return journal_refusal(pkg)
                if op == NOOP:
                    return {"outcome": "already", "message": ALREADY_MSG}
                res = journal_close(op, allow_background(serial, pref, pkg, user, orig))
                if res["outcome"] == "verified":
                    saved.pop("appops", None)
                    if not self._save_record(key, saved):
                        res["message"] = "restored on the phone, but the restore record couldn't be removed"
                return res
            try:
                sdk = int(adb_shell(serial, "getprop ro.build.version.sdk", timeout=15)[1].strip())
            except (AdbError, ValueError):
                sdk = 0
            ops = background_ops(sdk, ctx["target_sdk"])
            if ops is None:
                return {"outcome": "unsupported", "message": "the app's target Android version couldn't be read, "
                                                             "so it isn't known which background settings apply - "
                                                             "nothing was changed"}
            if not ops:
                return {"outcome": "unsupported", "message": "background restriction needs Android 7 or newer"}
            originals = read_background_modes(serial, pref, pkg, user, ops)
            if originals is None:
                return {"outcome": "unsupported", "message": "the current background settings couldn't be read "
                                                             "for this user - nothing was changed"}
            if all(v == "ignore" for v in originals.values()):     # already restricted: no record, no command
                return {"outcome": "already", "message": ALREADY_MSG, "originals": originals, "readback": originals}
            saved.setdefault("appops", originals)        # keep the FIRST originals
            if not self._persist_before_change(key, saved, previous):   # every time, not only the first
                return nosave
            op = journal_begin(serial, user, pkg, "bg-restrict", originals, {o: "ignore" for o in ops}, "", "autorun")
            if op is False:
                return journal_refusal(pkg)
            if op == NOOP:
                return {"outcome": "already", "message": ALREADY_MSG, "originals": originals, "readback": originals}
            return journal_close(op, restrict_background(serial, pref, pkg, user, ops, originals))
        op = journal_begin(serial, user, pkg, "app-on" if kind == "app_on" else "app-off", None,
                           "on" if kind == "app_on" else "off", "", "autorun")
        if op is False:
            return journal_refusal(pkg)
        if op == NOOP:
            return {"outcome": "already", "message": ALREADY_MSG}
        return journal_close(op, set_package_state(serial, user, pkg, kind == "app_on", root))

    def _act_done(self, gen, serial, kind, pkg, cls, res):
        if gen != self.gen or serial != self.serial:
            return
        self.busy = False
        if res.get("fresh") is not None and self.data:
            self.data["states"][pkg] = res["fresh"]
        if kind in ("app_off", "app_on") and res["outcome"] == "verified":
            a = self.app.apps_tab.apps.get(pkg)
            if a is not None:
                a["disabled"] = kind == "app_off"
        sel = ("r:%s/%s" % (pkg, cls)) if cls and kind.startswith("rx") else "p:" + pkg
        self.populate()
        if self.tree.exists(sel):
            self.tree.selection_set(sel)
            self.on_select()
        lines = [OUTCOME_WORDS.get(res["outcome"], res["outcome"])]
        if kind.startswith("rx") and res.get("state"):
            lines.append("This receiver now: " + self.STATE_WORDS.get(res["state"], res["state"]))
        if kind.startswith("app") and "pkg_state" in res:
            lines.append("The app now: " + PKG_STATE_WORDS.get(res["pkg_state"], "unknown"))
        if kind.startswith("bg") and res.get("readback"):
            lines.append("Now on the phone: " + ", ".join("%s = %s" % kv for kv in res["readback"].items()))
        if res.get("approximate"):
            lines.append("Note: these had no setting before and are now set to 'default', which behaves the "
                         "same: " + ", ".join(res["approximate"]))
        if res["outcome"] == "refused" and kind == "rx_off":
            lines.append("Nothing else was changed. Options: 'Restrict background', or turn the whole app OFF, "
                         "or root (su) if your phone has it.")
        if res.get("message") and res["outcome"] != "verified":
            lines.append("\nDetails: " + res["message"])
        (messagebox.showinfo if res["outcome"] in ("verified", "already") else messagebox.showwarning)(
            OUTCOME_WORDS.get(res["outcome"], "Result"), "\n".join(lines), parent=self)
        self.update_buttons()

    def on_select(self, event=None):
        sel = self.tree.selection()
        if not sel or not self.data:
            self.sel_pkg = self.sel_cls = None
            self.update_buttons()
            return
        iid = sel[0]
        if iid.startswith("p:"):
            self.sel_pkg, self.sel_cls = iid[2:], None
        else:
            self.sel_pkg, self.sel_cls = iid[2:].split("/", 1)
        self.update_buttons()
        d = self.data
        if iid.startswith("p:"):
            pkg = iid[2:]
            st = d["states"].get(pkg)
            pstate = (st or {}).get("pkg_state")
            self._detail([(self.label(pkg) + "\n", "h1"), (pkg + "\n\n", "dim"),
                          ("This app declares that Android may wake it when the phone finishes starting up. "
                           "That's a capability - it doesn't prove the app actually runs every time.\n\n", ()),
                          ("Whole app: %s\n" % PKG_STATE_WORDS.get(pstate, "unknown"), ())])
        else:
            pkg, cls = iid[2:].split("/", 1)
            st = d["states"].get(pkg)
            state = receiver_state_word(cls, st)
            info = d["receivers"].get((pkg, cls), {"actions": set()})
            expl = {"DEFAULT": "No explicit override. Whether it's active is decided by the app's manifest, "
                               "which this version doesn't read yet - so it may be on or off.",
                    "ENABLED": "Explicitly switched on.",
                    "DISABLED": "Explicitly switched off - Android won't wake it for these events.",
                    "UNKNOWN": "Its state couldn't be read on this phone."}[state]
            self._detail([(cls.rsplit(".", 1)[-1] + "\n", "h1"), (pkg + "/" + cls + "\n\n", "dim"),
                          ("Wakes up: %s\n" % " · ".join(BOOT_ACTION_WORDS.get(a, a) for a in sorted(info["actions"])), ()),
                          ("State: %s\n%s\n" % (self.STATE_WORDS[state], expl), ()),
                          ("\nUse the buttons below to change it - you'll confirm first, and the result is "
                           "checked on the phone.\n", "dim")])


class SecurityTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master, padding=4)
        self.app = app
        self.serial = None
        self.findings = []
        self.busy = None
        self.stop = threading.Event()
        self.rows = {}
        self.checked_at = ""
        self.show_tech = tk.BooleanVar(value=False)

        top = ttk.Frame(self)
        top.pack(fill="x")
        self.run_btn = ttk.Button(top, text="Run checkup", command=lambda: self.run(False))
        self.run_btn.pack(side="left")
        self.deep_btn = ttk.Button(top, text="Deep scan", command=lambda: self.run(True))
        self.deep_btn.pack(side="left", padx=4)
        self.stop_btn = ttk.Button(top, text="Stop", command=self.stop.set)
        self.info_btn = ttk.Button(top, text="Info about this device", command=self.device_info)
        self.info_btn.pack(side="left", padx=(12, 0))
        self.set_btn = ttk.Button(top, text="Security settings", command=self.open_settings)
        self.set_btn.pack(side="left", padx=4)
        self.timeline_btn = ttk.Button(top, text="Timeline\u2026", command=self.open_timeline)
        self.timeline_btn.pack(side="left")
        ttk.Checkbutton(top, text="Show technical details", variable=self.show_tech,
                        command=self.render).pack(side="right")
        expl = ttk.Label(self, text="Checkup: quick, nothing leaves your computer.   Deep scan: also copies "
                         "the apps you installed to this PC to read their signatures, and asks VirusTotal / "
                         "MalwareBazaar / Exodus if you added keys.", foreground="#777777", justify="left")
        expl.pack(fill="x", pady=(3, 0))
        expl.bind("<Configure>", lambda e: expl.configure(wraplength=max(200, e.width - 4)))
        self.summary = ttk.Label(self, text="", font=("TkDefaultFont", 10, "bold"))
        self.summary.pack(fill="x", pady=(3, 0))

        pw = ttk.PanedWindow(self, orient="horizontal")
        pw.pack(fill="both", expand=True, pady=(4, 0))
        left = ttk.Frame(pw)
        self.tree = ttk.Treeview(left, columns=("level",), selectmode="browse")
        self.tree.heading("#0", text="What was checked")
        self.tree.heading("level", text="")
        self.tree.column("#0", width=520, stretch=True)
        self.tree.column("level", width=110, stretch=False)
        self.tree.tag_configure("section", font=("TkDefaultFont", 10, "bold"))
        self.tree.tag_configure("safe", foreground="#2e7d32")
        self.tree.tag_configure("caution", foreground="#b26a00")
        self.tree.tag_configure("critical", foreground="#c62828")
        sb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.render())
        pw.add(left, weight=3)
        right = ttk.Frame(pw)
        self.details = tk.Text(right, wrap="word", width=44, relief="flat", padx=8, pady=6,
                               cursor="arrow", font=("TkDefaultFont", 10))
        dsb = ttk.Scrollbar(right, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=dsb.set)
        self.details.pack(side="left", fill="both", expand=True)
        dsb.pack(side="right", fill="y")
        self.details.tag_configure("h1", font=("TkDefaultFont", 12, "bold"))
        self.details.tag_configure("h2", font=("TkDefaultFont", 11, "bold"), spacing1=8, spacing3=2)
        self.details.tag_configure("dim", foreground="#777777")
        self.details.tag_configure("mono", font=("TkFixedFont", 9))
        for lvl, color in ((sa.OK, "#2e7d32"), (sa.INFO, "#555555"), (sa.WARN, "#b26a00"), (sa.BAD, "#c62828")):
            self.details.tag_configure("lvl_" + lvl, foreground=color, font=("TkDefaultFont", 11, "bold"))
        pw.add(right, weight=2)
        bottom = ttk.Frame(self)
        bottom.pack(fill="x", pady=(4, 0))
        self.goto_btn = ttk.Button(bottom, text="Show this app in the Apps tab", command=self.goto_app)
        self.goto_btn.pack(side="left")
        ttk.Label(bottom, text="A clean result means nothing suspicious is visible - not a guarantee.",
                  foreground="#777777").pack(side="right")
        self.populate()
        self.render()

    # ---- device ------------------------------------------------------------

    def set_device(self, serial):
        if serial == self.serial:
            return
        self.serial = serial
        self.findings = []
        self.populate()
        self.render()

    def on_shown(self):
        pass

    def open_timeline(self):
        serial = self.app.apps_tab.serial
        if not serial:
            self.app.error("No device connected - pick one at the top")
            return
        win = getattr(self, "_timeline_win", None)
        if win is not None and win.winfo_exists():
            win.lift()
            return
        self._timeline_win = TimelineWindow(self.app.root, self.app, serial)

    def device_info(self):
        if not self.serial:
            self.app.error("No device connected - pick one at the top")
            return
        win = getattr(self, "_info_win", None)
        if win is not None and win.winfo_exists():
            win.lift()
            return
        serial = self.serial
        self.app.info("Reading the device identity ...")
        self.info_btn.state(["disabled"])

        def work():
            try:
                info = sa.device_info(lambda cmd, t=15: adb_shell(serial, cmd, timeout=t)[1])
            except Exception as e:
                msg = str(e)
                self.post(lambda: (self.info_btn.state(["!disabled"]),
                                   self.app.error("Could not read device info: %s" % msg)))
                return
            self.post(self._show_info, serial, info)
        threading.Thread(target=work, daemon=True).start()

    def _show_info(self, serial, info):
        self.info_btn.state(["!disabled"])
        if serial != self.serial:
            return
        self.app.info("Device identity read")
        self._info_win = DeviceInfoWindow(self.app.root, info, self.app)

    def open_settings(self):
        win = getattr(self, "_set_win", None)
        if win is not None and win.winfo_exists():
            win.lift()
            return
        self._set_win = SecuritySettings(self.app.root)

    # ---- running -----------------------------------------------------------

    def run(self, deep):
        if not self.serial:
            self.app.error("No device connected - pick one at the top")
            return
        if self.busy:
            return
        cfg = sa.load_sec_config()
        at = self.app.apps_tab
        apps = {p: dict(a) for p, a in at.apps.items()} if at.scanned_serial == self.serial and at.apps else None
        if deep:
            n = len([a for a in (apps or {}).values() if not a["system"] and not a.get("removed")])
            keys = [k for k, v in (("VirusTotal", cfg["virustotal_key"]), ("MalwareBazaar", cfg["malwarebazaar_key"]),
                                   ("Exodus", cfg["exodus_token"])) if v]
            msg = ("The deep scan copies %s you installed to this computer - every part of each app, "
                   "not just the main file - into a temporary folder (deleted afterwards) to read their "
                   "signature and fingerprint.\n\n" % (
                       "the %d apps" % n if apps is not None else "the apps"))
            msg += (("Then it asks %s about them - only the fingerprint (hash) and package name are sent, never "
                     "the apps themselves." % " and ".join(keys)) if keys else
                    "No lookup service is set up, so it only reads signatures. Add free keys in Security "
                    "settings to check apps against malware databases and tracker reports.")
            if cfg["virustotal_key"]:
                msg += ("\n\nVirusTotal's free key allows 4 lookups a minute, and apps made of several "
                        "parts need one lookup per part, so this can take a while. Results are remembered, "
                        "so the next deep scan only looks up what changed.")
            if not messagebox.askyesno("Deep scan", msg + "\n\nStart?", parent=self.app.root):
                return
        self.busy = "deep scan" if deep else "checkup"
        self.stop.clear()
        self.run_btn.state(["disabled"])
        self.deep_btn.state(["disabled"])
        self.stop_btn.pack(side="left", padx=4, after=self.deep_btn)
        threading.Thread(target=self._worker, args=(self.serial, deep, cfg, apps), daemon=True).start()

    def post(self, fn, *args):
        self.app.q.put(("call", fn) + args)

    def say(self, text):
        self.post(self.app.info, text)

    def _worker(self, serial, deep, cfg, apps):
        try:
            res = self._do_check(serial, deep, cfg, apps)
        except Exception as e:  # never leave the tab stuck
            self.post(self._failed, "%s: %s" % (type(e).__name__, e))
            return
        self.post(self._done, serial, res)

    def _do_check(self, serial, deep, cfg, apps):
        label = self.app.apps_tab.label

        def shell(cmd, timeout=60):
            # a failed command must RAISE (sa.collect records it as "couldn't check");
            # returning its empty output would read as an all-clear
            rc, out, err = adb_shell(serial, cmd, timeout=timeout)
            if rc != 0:
                raise AdbError(last_line(err, out) or "exit code %d" % rc)
            return out
        if apps is None:
            self.say("Security: reading the app list ...")
            apps = scan_packages(serial)["apps"]
        self.say("Security: reading the device settings ...")
        try:
            socks = read_sockets(serial)[0]
        except AdbError:
            socks = []
        facts = sa.collect(shell, apps, socks)
        users = sorted(p for p, a in apps.items() if not a["system"] and not a.get("removed"))
        self.say("Security: checking which apps hide their icon ...")
        if users:
            lset, lmethod = sa.launcher_packages(shell, users)
            launcher = lset if lmethod is not None else None   # None => unknown, not "all hidden"
        else:
            launcher = set()
        access = sa.access_lists(facts)
        self.say("Security: checking which apps start at boot ...")
        user, usrc = None, None
        try:
            user, usrc = current_user(serial)
            det = detect_boot_receivers(serial, user)
            mine = {p for p, _ in det["receivers"]} & set(users)
            boot = boot_signals(det, receiver_states(serial, user, mine) if mine else {},
                                usrc in ("detected", "single-user"))
        except Exception:                                  # unreadable -> "couldn't check", never "none"
            boot = None
        found = (sa.check_patterns(facts, access, launcher, label, boot) +
                 sa.check_device(facts) + sa.check_access(facts, access, launcher, label) +
                 sa.check_origin(facts, launcher, label) + sa.check_usage(facts, launcher, label))

        idcache = sa.load_json(sa.IDENTITY_FILE, {})
        save_problems = []           # cache files that couldn't be written this run
        targets = users + ([p for p, a in apps.items() if a["system"] and a.get("updated_system")
                            and not a.get("removed")] if cfg.get("deep_include_updated_system") else [])
        if deep:
            work = tempfile.mkdtemp(prefix="adbmgr_sec_")
            try:
                for i, p in enumerate(targets):
                    if self.stop.is_set():
                        break
                    k = sa.identity_key(p, apps[p])
                    if sa.identity_complete(idcache.get(k)):
                        continue     # every part already fingerprinted for this exact version
                    self.say("Deep scan: reading %d/%d %s (all its parts) ..." % (i + 1, len(targets), p))
                    try:
                        ident = read_app_identity(serial, p, work, self.stop)
                    except AdbError as e:
                        # keep an older (even partial) record if there is one; else record why
                        if k not in idcache:
                            idcache[k] = sa.make_app_identity(p, [{"path": "", "name": "base.apk",
                                                                  "kind": "base", "error": str(e)}])
                        continue
                    if ident is not None:
                        idcache[k] = ident
                if not sa.save_json(sa.IDENTITY_FILE, idcache):
                    save_problems.append("app fingerprints (%s)" % os.path.basename(sa.IDENTITY_FILE))
            finally:
                shutil.rmtree(work, ignore_errors=True)

        prev_snap = sa.last_snapshot(serial)
        verified = usrc in ("detected", "single-user")
        bg = None
        if verified and "appops" not in facts["failed"] and facts.get("appops_raw", "").strip():
            sdk = _int_or_none((facts.get("props") or {}).get("sdk")) or _int_or_none(self.app.apps_tab.props.get("sdk"))
            if sdk:                  # unknown Android version: the ops can't be chosen -> unread (None), not empty
                tsdk = {p: _int_or_none(a.get("target_sdk")) for p, a in apps.items()}
                bg = pf.background_from_appops(facts["appops_raw"], user,
                                               lambda p: background_ops(sdk, tsdk.get(p)) if p in tsdk else None)
        snap = sa.build_snapshot(serial, facts, access, launcher, idcache, prev=prev_snap,
                                 boot=boot if verified else None, bg=bg, user=user if verified else None)
        found += sa.compare_snapshots(prev_snap, snap, label)
        if not self.stop.is_set() and not sa.save_snapshot(serial, snap):
            found.append(sa.finding(
                "changes", sa.WARN, "Couldn't save this check as the new reference",
                "The results below are fine, but they could not be written to disk (%s). "
                "Next time, 'changes since last check' will compare against the older saved "
                "check instead. Check free space and permissions of that folder." % sa.SNAP_DIR,
                key="changes:save-failed"))

        idents = {p: idcache[sa.identity_key(p, apps[p])] for p in targets
                  if sa.identity_key(p, apps[p]) in idcache}
        rep = sa.load_json(sa.REPUTATION_FILE, {})
        if deep and (cfg["virustotal_key"] or cfg["malwarebazaar_key"]):
            # every readable part of every app, each distinct file looked up once
            work_items, seen_hash = [], set()
            for p, ident in sorted(idents.items()):
                for part in sa.identity_parts(ident):
                    h = part.get("sha256")
                    if h and h not in seen_hash:
                        seen_hash.add(h)
                        work_items.append((p, part, h))
            vt_ok, last_vt, rep_save_failed = bool(cfg["virustotal_key"]), 0.0, False
            n = len(work_items)
            for i, (p, part, h) in enumerate(work_items):
                if self.stop.is_set():
                    break
                what = "%s - %s" % (p, sa.apk_part_label(part))
                entry = dict(rep.get(h, {}))
                fresh = time.time() - entry.get("time", 0) < 7 * 86400
                if vt_ok and not (fresh and entry.get("vt") and not entry["vt"].get("error")):
                    wait = 15.5 - (time.time() - last_vt)
                    while wait > 0 and not self.stop.is_set():
                        self.say("Deep scan: VirusTotal %d/%d (free key: waiting %ds) ..." % (i + 1, n, wait))
                        time.sleep(min(1.0, wait))
                        wait -= 1.0
                    if self.stop.is_set():
                        break
                    self.say("Deep scan: VirusTotal %d/%d %s ..." % (i + 1, n, what))
                    entry["vt"] = sa.virustotal(cfg["virustotal_key"], h)
                    last_vt = time.time()
                    if entry["vt"].get("quota") or "rejected" in entry["vt"].get("error", ""):
                        vt_ok = False
                if cfg["malwarebazaar_key"] and not (fresh and entry.get("mb") and not entry["mb"].get("error")):
                    self.say("Deep scan: MalwareBazaar %d/%d %s ..." % (i + 1, n, what))
                    entry["mb"] = sa.malwarebazaar(cfg["malwarebazaar_key"], h)
                entry["time"] = time.time()
                rep[h] = entry
                # each write holds the WHOLE cache, so only the latest write's outcome
                # matters: a later success also saves the results of an earlier failure
                rep_save_failed = not sa.save_json(sa.REPUTATION_FILE, rep)
            if rep_save_failed:
                save_problems.append("virus-scanner results (%s)" % os.path.basename(sa.REPUTATION_FILE))
        mal = sa.reputation_findings(apps, label, idents, rep) if idents else []
        if not mal:
            mal = [sa.finding("malware", sa.INFO, "Not checked yet - run a deep scan%s" % (
                "" if cfg["virustotal_key"] or cfg["malwarebazaar_key"] else
                " (and add a free VirusTotal or MalwareBazaar key in Security settings)"), key="malware:none")]
        found += mal

        tcache = sa.load_json(sa.TRACKERS_FILE, {})
        reports = {}
        for p in users:
            c = tcache.get(p)
            if isinstance(c, dict) and c.get("vc") == apps[p].get("version_code") and \
                    time.time() - c.get("time", 0) < 30 * 86400 and not c["result"].get("error"):
                reports[p] = c["result"]
            elif deep and cfg["exodus_token"] and not self.stop.is_set():
                self.say("Deep scan: tracker report for %s ..." % p)
                r = sa.exodus_report(cfg, p, apps[p].get("version_code"))
                reports[p] = r
                tcache = sa.load_json(sa.TRACKERS_FILE, {})
                tcache[p] = {"vc": apps[p].get("version_code"), "time": time.time(), "result": r}
                if not sa.save_json(sa.TRACKERS_FILE, tcache):
                    msg = "tracker reports (%s)" % os.path.basename(sa.TRACKERS_FILE)
                    if msg not in save_problems:
                        save_problems.append(msg)
        trk = sa.tracker_findings(apps, label, reports) if reports else []
        if not trk:
            trk = [sa.finding("trackers", sa.INFO, "Not checked yet - %s" % (
                "run a deep scan" if cfg["exodus_token"] else
                "add a free Exodus Privacy token in Security settings, then run a deep scan"),
                key="trackers:none")]
        found += trk
        if save_problems:
            found.append(sa.finding(
                "changes", sa.WARN, "Some scan results couldn't be saved",
                "The results shown are fine, but these couldn't be written to disk: %s. Next time "
                "they will be fetched again (slower, and uses more of your free lookup quota). "
                "Check free space and permissions of %s." % (", ".join(save_problems), sa.CONFIG_DIR),
                key="changes:cache-save-failed"))
        return {"findings": found, "stopped": self.stop.is_set(), "deep": deep}

    def _failed(self, msg):
        self.busy = None
        self.run_btn.state(["!disabled"])
        self.deep_btn.state(["!disabled"])
        self.stop_btn.pack_forget()
        self.app.error("Security check failed: %s" % msg)

    def _done(self, serial, res):
        self.busy = None
        self.run_btn.state(["!disabled"])
        self.deep_btn.state(["!disabled"])
        self.stop_btn.pack_forget()
        if serial != self.serial:
            return
        self.findings = res["findings"]
        self.checked_at = time.strftime("%H:%M")
        self.populate()
        self.render()
        bad = sum(1 for f in self.findings if f["level"] == sa.BAD)
        warn = sum(1 for f in self.findings if f["level"] == sa.WARN)
        what = "Deep scan" if res["deep"] else "Checkup"
        text = "%s finished%s: %d problem(s), %d thing(s) to look at" % (
            what, " (stopped early)" if res["stopped"] else "", bad, warn)
        (self.app.error if bad else self.app.info)(text)

    # ---- list --------------------------------------------------------------

    def populate(self):
        self.tree.delete(*self.tree.get_children())
        self.rows = {}
        if not self.findings:
            self.summary.configure(text="No device" if not self.serial else
                                   "Press 'Run checkup' to check this device", foreground="")
            return
        by = {}
        for f in self.findings:
            by.setdefault(f["section"], []).append(f)
        for skey, sname in sa.SECTIONS:
            items = sorted(by.get(skey, []), key=lambda f: (sa.LEVEL_RANK[f["level"]], f["title"].lower()))
            worst = min((f["level"] for f in items), key=lambda l: sa.LEVEL_RANK[l]) if items else sa.OK
            n_bad = sum(1 for f in items if f["level"] in (sa.BAD, sa.WARN))
            sid = "s:" + skey
            self.tree.insert("", "end", iid=sid, text=sname, open=worst in (sa.BAD, sa.WARN),
                             values=("%s %d" % (LEVEL_MARK[worst], n_bad) if n_bad else LEVEL_MARK[worst],),
                             tags=("section",) + ((LEVEL_TAG[worst],) if LEVEL_TAG[worst] else ()))
            for i, f in enumerate(items):
                iid = "%s:%d" % (sid, i)
                self.tree.insert(sid, "end", iid=iid, text="%s  %s" % (LEVEL_MARK[f["level"]], f["title"]),
                                 values=(LEVEL_WORD[f["level"]],),
                                 tags=(LEVEL_TAG[f["level"]],) if LEVEL_TAG[f["level"]] else ())
                self.rows[iid] = f
        bad = sum(1 for f in self.findings if f["level"] == sa.BAD)
        warn = sum(1 for f in self.findings if f["level"] == sa.WARN)
        if bad:
            txt, color = "\u26d4 %d problem(s) and %d thing(s) to look at" % (bad, warn), "#c62828"
        elif warn:
            txt, color = "\u26a0 No problems, %d thing(s) to look at" % warn, "#b26a00"
        else:
            txt, color = "\u2705 Nothing suspicious found", "#2e7d32"
        self.summary.configure(text="%s  \u00b7  checked at %s" % (txt, self.checked_at), foreground=color)

    def selected(self):
        sel = self.tree.selection()
        return self.rows.get(sel[0]) if sel else None

    def render(self):
        t = self.details
        t.configure(state="normal")
        t.delete("1.0", "end")
        w = lambda text, tag=(): t.insert("end", text, tag)  # noqa: E731
        f = self.selected()
        if not f:
            w("Security checkup\n", "h1")
            w("\nIt looks at the things real Android malware and spyware depend on: powerful switches "
              "like accessibility and device admin, apps from outside the stores, apps hiding their "
              "icon, what changed since the last check, and who used the camera or microphone.\n")
            w("\n\u26d4 problem   \u26a0 look at it   \u2139 for your info   \u2705 fine\n")
            w("\nRun it now and then: the 'Changes' section compares every check with the one before.\n", "dim")
            t.configure(state="disabled")
            return
        w(f["title"] + "\n", "h1")
        w(LEVEL_MARK[f["level"]] + " " + LEVEL_WORD[f["level"]].capitalize() + "\n", "lvl_" + f["level"])
        if f.get("detail"):
            w("\n" + f["detail"] + "\n")
        if f.get("advice"):
            w("What you can do\n", "h2")
            w(f["advice"] + "\n")
        if f.get("pkg"):
            w("\nApp: %s\n" % f["pkg"], "dim")
        if self.show_tech.get() and f.get("tech"):
            w("Technical\n", "h2")
            w(f["tech"] + "\n", "mono")
        t.configure(state="disabled")

    def goto_app(self):
        f = self.selected()
        if not f or not f.get("pkg"):
            self.app.info("Select a line about an app first")
            return
        self.app.nb.select(1)
        self.app.apps_tab.show_package(f["pkg"])


class DeviceInfoWindow(tk.Toplevel):
    def __init__(self, master, info, app):
        super().__init__(master)
        self.title("Info about this device")
        self.transient(master)
        self.info = info
        self.app = app
        self.ai_busy = False
        self.ai_stop = threading.Event()
        self.minsize(560, 460)
        frm = ttk.Frame(self, padding=14)
        frm.pack(fill="both", expand=True)
        txt = tk.Text(frm, wrap="word", width=70, height=24, relief="flat", padx=8, pady=6,
                      cursor="arrow", font=("TkDefaultFont", 10))
        sb = ttk.Scrollbar(frm, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        txt.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        txt.tag_configure("h1", font=("TkDefaultFont", 13, "bold"))
        txt.tag_configure("h2", font=("TkDefaultFont", 11, "bold"), spacing1=10, spacing3=2)
        txt.tag_configure("label", font=("TkDefaultFont", 10, "bold"))
        txt.tag_configure("key", foreground="#1f5fbf", font=("TkFixedFont", 11, "bold"))
        txt.tag_configure("dim", foreground="#777777")
        txt.tag_configure("warn", foreground="#c62828")
        txt.tag_configure("ok", foreground="#2e7d32")
        txt.tag_configure("link", foreground="#1f5fbf", underline=True)
        self._links = {}
        self.txt = txt
        w = lambda t, tag=(): txt.insert("end", t, tag)  # noqa: E731

        name = info.get("marketname") or "This device"
        w(name + "\n", "h1")
        if info.get("is_xiaomi"):
            w("Xiaomi / Redmi / POCO device\n", "dim")
        w("\n")
        for group, rows in info["groups"]:
            w(group + "\n", "h2")
            for label, value, note in rows:
                w("%-20s " % (label + ":"), "label")
                tag = "key" if label == "Internal codename" else (
                    "warn" if (label == "Bootloader" and value == "LOCKED")
                    or label == "Anti-rollback index" else (
                        "ok" if label == "Bootloader" and value == "UNLOCKED" else ()))
                w(value + "\n", tag)
                if note:
                    w("    %s\n" % note, "warn" if note.startswith("\u26d4") else "dim")
            w("\n")

        w("Rooting on this device\n", "h2")
        mark = {sa.OK: "\u2705 ", sa.INFO: "", sa.WARN: "\u26a0 ", sa.BAD: "\u26d4 "}
        tagmap = {sa.OK: "ok", sa.INFO: (), sa.WARN: "warn", sa.BAD: "warn"}
        lines, links = sa.rooting_guidance(info)
        for lvl, text in lines:
            w(mark[lvl] + text + "\n", tagmap[lvl])
        if links:
            w("\nOfficial sources (click to open)\n", "label")
            for text, url in links:
                w("\u2022 " + text + "\n")
                self.add_link(txt, url)
        txt.insert("end", "\n")
        self._ai_mark = txt.index("end-1c")   # cached/live AI answer goes here
        txt.configure(state="disabled")

        entry = sa.rooting_db_get(info)
        if entry:
            self.render_db_entry(entry)
        btns = ttk.Frame(self, padding=(14, 0, 14, 14))
        btns.pack(fill="x")
        ttk.Button(btns, text="Close", command=self.destroy).pack(side="right")
        ttk.Button(btns, text="Copy all", command=lambda: self.copy(txt)).pack(side="right", padx=6)
        self.ai_btn = ttk.Button(btns, text="Research rooting with AI", command=self.research_rooting)
        self.ai_btn.pack(side="left")
        self.refresh_btn = ttk.Button(btns, text="Refresh this model", command=self.refresh_model)
        self.refresh_btn.pack(side="left", padx=4)
        self.db_btn = ttk.Button(btns, text="Database ...", command=self.open_db)
        self.db_btn.pack(side="left")
        ttk.Button(btns, text="Known security issues\u2026", command=self.open_issues).pack(side="left", padx=4)
        self.ai_note = ttk.Label(btns, text="", foreground="#777777")
        self.ai_note.pack(side="left", padx=8)

    def add_link(self, txt, url):
        tag = "url:%d" % len(self._links)
        self._links[tag] = url
        start = txt.index("end-1c linestart")
        txt.insert("end", "    " + url + "\n", ("link", tag))
        txt.tag_bind(tag, "<Button-1>", lambda e, u=url: self.open_url(u))
        txt.tag_bind(tag, "<Enter>", lambda e: txt.configure(cursor="hand2"))
        txt.tag_bind(tag, "<Leave>", lambda e: txt.configure(cursor="arrow"))
        _ = start

    def open_url(self, url):
        safe_open_url(url)

    def research_rooting(self):
        if self.ai_busy:
            return
        cfg = ai.load_config()
        have = [p for p in ai.PROVIDERS if ai.api_key(cfg, p)]
        if not have:
            messagebox.showinfo("No AI key", "No AI provider has an API key yet.\n\nAdd one in the "
                                "Apps tab > AI settings, then try again.", parent=self)
            return
        if len(have) == 1:
            self._start_ai(have[0], cfg)
            return
        # more than one key: let the user pick which AI answers
        self._ask_provider(have, cfg)

    def _ask_provider(self, have, cfg):
        win = tk.Toplevel(self)
        win.title("Which AI?")
        win.transient(self)
        win.resizable(False, False)
        frm = ttk.Frame(win, padding=14)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Which AI should research rooting for this device?",
                  font=("TkDefaultFont", 10, "bold")).pack(anchor="w")
        main = cfg.get("provider", "anthropic")
        choice = tk.StringVar(value=main if main in have else have[0])
        for pkey in have:
            ttk.Radiobutton(frm, text=ai.PROVIDERS[pkey]["label"] + "  (%s)" % ai.model_of(cfg, pkey),
                            value=pkey, variable=choice).pack(anchor="w", pady=(6, 0))
        ttk.Label(frm, text="Tip: the two providers can answer differently on this kind of topic.",
                  foreground="#777777").pack(anchor="w", pady=(8, 0))
        row = ttk.Frame(frm)
        row.pack(fill="x", pady=(12, 0))
        ttk.Button(row, text="Cancel", command=win.destroy).pack(side="right")

        def go():
            pkey = choice.get()
            win.destroy()
            self._start_ai(pkey, cfg)
        ttk.Button(row, text="Ask this AI", command=go).pack(side="right", padx=6)
        win.grab_set()

    def refresh_model(self):
        # same as researching, but makes clear it overwrites the stored entry
        self.research_rooting()

    def _start_ai(self, provider, cfg):
        self.ai_busy = True
        self.ai_stop.clear()
        self.ai_btn.state(["disabled"])
        self.refresh_btn.state(["disabled"])
        self.ai_note.configure(text="Asking %s (web search, a minute or two) ..."
                               % ai.PROVIDERS[provider]["label"])
        self.render_ai_placeholder(provider)

        def work():
            res = ai.research_rooting(provider, cfg, self.info)
            self.app.q.put(("call", self._ai_done, res))
        threading.Thread(target=work, daemon=True).start()

    def _ai_done(self, res):
        self.ai_busy = False
        self.ai_btn.state(["!disabled"])
        self.refresh_btn.state(["!disabled"])
        self.ai_note.configure(text="")
        saved = sa.rooting_db_put(self.info, res) if res.get("answer") else False
        if res.get("answer") and not saved:
            res = dict(res, save_failed=True)
        if not self.winfo_exists():
            return
        self.render_ai(res)

    def _ai_section_start(self):
        t = self.txt
        t.configure(state="normal")
        if hasattr(self, "_ai_mark"):
            t.delete(self._ai_mark, "end")
        else:
            t.insert("end", "\n")
            self._ai_mark = t.index("end-1c")
        return t

    def render_ai_placeholder(self, provider):
        t = self._ai_section_start()
        t.insert("end", "\nAI rooting research (%s)\n" % ai.PROVIDERS[provider]["label"], "h2")
        t.insert("end", "Searching the web for this exact model ...\n", "dim")
        t.configure(state="disabled")
        t.see("end")

    @staticmethod
    def _identity_line(ident):
        bits = [ident.get(k, "") for k in ("maker", "codename", "model", "platform", "region")]
        return " / ".join(b for b in bits if b) or "(identity unknown)"

    def render_db_entry(self, entry):
        """Show a stored answer from the rooting database (no AI call).

        Ambiguous matches NEVER auto-display device-specific instructions: the user
        must pick the variant. Firmware compatibility is shown only once the
        hardware identity is established (exact match or manual selection)."""
        t = self._ai_section_start()
        w = lambda text, tag=(): t.insert("end", text, tag)  # noqa: E731
        w("\nAI rooting research \u2014 saved\n", "h2")
        match = entry.get("match", "exact")

        # --- ambiguous: show candidate identities and a chooser, NOT instructions
        if match == "ambiguous":
            cands = entry.get("candidates", [])
            grade = entry.get("ambiguous_grade", "codename")
            w("\u26a0 Several saved variants could match this device (%d), by %s. The exact variant "
              "isn't established, so no device-specific steps are shown. Choose the one that matches "
              "your phone:\n" % (len(cands), {"exact": "hardware identity", "partial": "partial "
              "identity", "codename": "codename"}.get(grade, grade)), "warn")
            self._cand_buttons = []
            for key in cands[:8]:
                e = sa.rooting_db_get_key(key)
                ident = sa._entry_identity(e) if e else {}
                w("    \u2022 " + self._identity_line(ident) + "\n", "dim")
                self._add_choose_button(t, key, self._identity_line(ident))
            w("\nOr press 'Refresh this model' to research this device's exact identity now.\n", "dim")
            t.configure(state="disabled")
            t.see(self._ai_mark)
            return

        # --- single match (exact / partial / codename / selected)
        hardware_confirmed = match in ("exact", "selected")
        if match == "selected":
            w("You picked this saved variant by hand. It is shown as-is; compatibility with the "
              "connected phone is computed below but not assumed.\n", "dim")
        elif match == "partial":
            w("\u26a0 Partial identity match: the codename agrees and some of maker/model/platform/"
              "region agree, but not enough to fully establish the exact variant. Treat "
              "device-specific steps as needing confirmation.\n", "warn")
        elif match == "codename":
            w("\u26a0 Matched by codename only. The full hardware identity could not be confirmed, "
              "so this saved answer might belong to a different variant. Treat it as a guide and "
              "verify before flashing.\n", "warn")
        w("Saved identity: %s\n" % self._identity_line(sa._entry_identity(entry)), "dim")
        w("Researched %s by %s%s, for Android %s%s.\n" % (
            entry.get("when", "?"), ai.PROVIDERS.get(entry.get("provider"), {}).get("label",
            entry.get("provider", "?")), (" " + entry["model"]) if entry.get("model") else "",
            entry.get("researched_release") or "?",
            (" build " + entry["researched_build"]) if entry.get("researched_build") else ""), "dim")
        # firmware compatibility - only once hardware identity is established
        if not hardware_confirmed:
            w("Firmware comparison isn't shown because the hardware identity isn't confirmed - "
              "confirm the exact model first (Refresh, or pick it in the Database).\n", "dim")
        else:
            status, cmsg, _ = sa.rooting_compatibility(entry, self.info)
            if status == "match":
                w("\u2705 Same hardware, and firmware matches what was researched (%s).\n" % cmsg, "ok")
            elif status == "hardware":
                w("\u26a0 Same phone model, but %s. The unlock/hardware research still applies; any "
                  "firmware-specific flashing step (which boot.img, which firmware package) must be "
                  "re-checked. Press 'Refresh this model' to update.\n" % cmsg, "warn")
            else:
                w("\u26d4 REQUIRES VERIFICATION: %s. Don't rely on the firmware-specific steps "
                  "until you've confirmed them. Press 'Refresh this model'.\n" % cmsg, "warn")
        self._render_answer_fields(w, entry["answer"])
        w("\nPress 'Refresh this model' to ask the AI again and update this entry.\n", "dim")
        t.configure(state="disabled")
        t.see(self._ai_mark)

    def _add_choose_button(self, t, key, label):
        """Inline 'Use this variant' button in the ambiguous candidate list."""
        btn = ttk.Button(t, text="Use this variant",
                         command=lambda k=key: self._choose_variant(k))
        t.window_create("end", window=btn)
        t.insert("end", "  " + label + "\n", "dim")

    def _choose_variant(self, key):
        entry = sa.rooting_db_get_key(key)   # match="selected"
        if not entry:
            self.app.info("That saved variant is no longer in the database")
            return
        self.txt.configure(state="normal")
        self.txt.delete(self._ai_mark, "end")
        self.render_db_entry(entry)

    def _render_answer_fields(self, w, a):
        if a.get("summary"):
            w(a["summary"] + "\n")
        risk = (a.get("brick_risk") or "").lower()
        rtag = "warn" if risk.startswith(("high", "medium")) else ()
        pairs = [("Can it be unlocked?", a.get("can_unlock"), "ok" if a.get("can_unlock") == "yes"
                  else "warn" if a.get("can_unlock") in ("no", "difficult") else ()),
                 ("Unlock method", a.get("unlock_method"), ()),
                 ("Needs Windows?", a.get("needs_windows"), ()),
                 ("Waiting period", a.get("wait_time"), ()),
                 ("TWRP / OrangeFox", a.get("twrp"), ()),
                 ("Root method", a.get("root_method"), ()),
                 ("Brick risk", a.get("brick_risk"), rtag),
                 ("Anti-rollback", a.get("anti_rollback"), ()),
                 ("Device", a.get("device"), ())]
        for label, value, tag in pairs:
            if value:
                w("\n" + label + ": ", "label")
                w(value + "\n", tag)
        if a.get("confidence"):
            w("\nAI confidence: %s\n" % a["confidence"], "dim")
        note = source_check_note(a)
        if note and note[1] == "warn":
            w(note[0], note[1])
        if a.get("sources"):
            w("Sources (click to open)\n", "label")
            if note and note[1] != "warn":
                w(note[0], note[1])
            for u in a["sources"][:10]:
                self.add_link(self.txt, u)
                mark = source_mark(a, u)
                if mark:
                    w("     " + mark.strip() + "\n", "dim")

    def render_ai(self, res):
        t = self._ai_section_start()
        w = lambda text, tag=(): t.insert("end", text, tag)  # noqa: E731
        w("\nAI rooting research (%s, %s)\n" % (ai.PROVIDERS[res["provider"]]["label"],
                                                res.get("model", "")), "h2")
        if res.get("error"):
            w("Couldn't get an answer: %s\n" % res["error"], "warn")
            if res.get("raw"):
                w(res["raw"][:1500] + "\n", "dim")
            t.configure(state="disabled")
            t.see(self._ai_mark)
            return
        a = res["answer"]
        if res.get("save_failed"):
            w("Fresh AI research (could NOT be saved to the database - check disk/permissions). "
              "Verify against the sources before flashing.\n", "warn")
        else:
            w("Fresh AI research - saved to the database. Verify against the sources before flashing.\n",
              "dim")
        self._render_answer_fields(w, a)
        t.configure(state="disabled")
        t.see(self._ai_mark)

    def open_issues(self):
        win = getattr(self, "_issues_win", None)
        if win is not None and win.winfo_exists():
            win.lift()
            return
        self._issues_win = KnownIssuesWindow(self, self.info, self.app)

    def open_db(self):
        win = getattr(self, "_db_win", None)
        if win is not None and win.winfo_exists():
            win.lift()
            return
        self._db_win = RootingDBWindow(self, self.app)

    def copy(self, txt):
        self.clipboard_clear()
        self.clipboard_append(txt.get("1.0", "end").strip())


CVE_STATE_WORDS = {cv.POTENTIAL: "⚠ may be affected", cv.UNKNOWN: "? can't tell",
                   cv.FIXED: "✔ fixed (by reported patch)", cv.NOT_AFFECTED: "– not affected"}
CVE_SHOW = ["May be affected", "Can't tell", "Fixed by reported patch", "Everything", "Chip maker's notices"]


class KnownIssuesWindow(tk.Toplevel):
    """Known Android security issues vs. this phone - information only. Uses the saved
    bulletin data; the network is used only when the user presses a button."""

    def __init__(self, master, info, app):
        super().__init__(master)
        self.title("Known security issues")
        self.transient(master)
        self.minsize(720, 480)
        self.info, self.app = info, app
        self.props = dict(info.get("props") or {})
        self.data = sa.load_cve_data()
        self.assessment = None
        self.maker = None                     # chip maker's notices (list of findings) once searched
        self.maker_note = ""
        self.busy = False
        self.stop = threading.Event()
        self.rows = {}
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)
        intro = ttk.Label(frm, justify="left", foreground="#555555", text=(
            "Publicly known Android security issues, compared with this phone's Android version and the security "
            "patch it REPORTS. Information only: nothing is tested or run on the phone. 'May be affected' means "
            "the issue is newer than your patch - not that your phone was attacked, nor that an attack exists for "
            "it."))
        intro.pack(fill="x")
        intro.bind("<Configure>", lambda e: intro.configure(wraplength=max(200, e.width - 4)))
        self.head = ttk.Label(frm, text="", font=("TkDefaultFont", 10, "bold"), justify="left")
        self.head.pack(fill="x", pady=(6, 0))
        self.head.bind("<Configure>", lambda e: self.head.configure(wraplength=max(200, e.width - 4)))
        row = ttk.Frame(frm)
        row.pack(fill="x", pady=(6, 4))
        self.dl_btn = ttk.Button(row, text="Download / update the bulletin data", command=self.download)
        self.dl_btn.pack(side="left")
        self.maker_btn = ttk.Button(row, text="Search the chip maker's notices", command=self.search_maker)
        self.maker_btn.pack(side="left", padx=6)
        self.stop_btn = ttk.Button(row, text="Stop", command=self.stop.set)
        ttk.Label(row, text="Show:").pack(side="left", padx=(12, 0))
        self.show = tk.StringVar(value=CVE_SHOW[0])
        cb = ttk.Combobox(row, textvariable=self.show, values=CVE_SHOW, state="readonly", width=22)
        cb.pack(side="left", padx=4)
        cb.bind("<<ComboboxSelected>>", lambda e: self.populate())
        self.status = ttk.Label(frm, text="", foreground="#555555")
        self.status.pack(fill="x")
        pw = ttk.PanedWindow(frm, orient="vertical")
        pw.pack(fill="both", expand=True, pady=(4, 0))
        top = ttk.Frame(pw)
        self.tree = ttk.Treeview(top, columns=("state", "wild", "fix", "sev"), selectmode="browse", height=9)
        for c, t, w_ in (("#0", "Issue", 170), ("state", "This phone", 190), ("wild", "Used in attacks?", 130),
                         ("fix", "Fixed in patch", 110), ("sev", "Severity", 80)):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w_, stretch=c == "#0")
        sb = ttk.Scrollbar(top, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        pw.add(top, weight=3)
        self.details = tk.Text(pw, wrap="word", height=9, relief="flat", padx=8, pady=6, cursor="arrow",
                               font=("TkDefaultFont", 10))
        self.details.tag_configure("h", font=("TkDefaultFont", 11, "bold"))
        self.details.tag_configure("dim", foreground="#777777")
        self.details.tag_configure("link", foreground="#1f5fbf", underline=True)
        pw.add(self.details, weight=2)
        bot = ttk.Frame(frm)
        bot.pack(fill="x", pady=(6, 0))
        ttk.Button(bot, text="Close", command=self.destroy).pack(side="right")
        self.recompute()

    # ---- assessment ---------------------------------------------------------

    def recompute(self):
        d = self.data
        if d:
            self.assessment = cv.assess(d["osv_records"], self.props, d["kev"])
        else:
            self.assessment = None
        self.populate()

    def headline(self):
        rel = self.props.get("ro.build.version.release", "?")
        spl = self.props.get("ro.build.version.security_patch") or "unknown"
        if not self.data:
            return ("Your phone: Android %s, security patch %s. No bulletin data yet - press 'Download / update "
                    "the bulletin data' (about 10 MB from Google and CISA; nothing about your phone is sent)."
                    % (rel, spl))
        c = self.assessment["counts"]
        text = ("Your phone: Android %s, security patch %s.  Bulletin data checked %s.\n"
                "%d serious issue(s) may affect it (fixed only in newer patches)%s; %d can't be told; "
                "%d fixed by the patch it reports." % (
                    rel, spl, self.data["checked"], c[cv.POTENTIAL],
                    ", %d known to be used in real attacks" % c["potential_and_exploited"]
                    if c["potential_and_exploited"] else "", c[cv.UNKNOWN], c[cv.FIXED]))
        notes = list(self.assessment["notes"])
        if self.data.get("osv_skipped"):
            notes.append("%d record(s) in the download couldn't be read." % self.data["osv_skipped"])
        return text + ("\n" + " ".join(notes) if notes else "")

    def populate(self):
        self.head.configure(text=self.headline())
        self.tree.delete(*self.tree.get_children())
        self.rows = {}
        show = self.show.get()
        if show == "Chip maker's notices":
            for i, f in enumerate(self.maker or []):
                iid = "m%d" % i
                if f["source"] == "bulletin":
                    state = ("see bulletin: " + CVE_STATE_WORDS[f["bulletin_state"]]) if f["bulletin_state"] \
                        else "in the bulletin data"
                elif f["source"] == "mention":
                    state = "only mentions the maker"
                else:
                    state = {"listed": "chip listed", "family": "chip family listed", "unmatched": "chip not matched",
                             "unknown": "chips not stated"}[f["chip"]] + (
                        ", Android listed" if f["android"] == "listed" else
                        ", Android not listed" if f["android"] == "not_listed" else "")
                self.tree.insert("", "end", iid=iid, text=f["cve"], values=(
                    state, "CISA list (via CIRCL)" if f["kev_listed"] else "-", "unknown", f["severity"] or "-"))
                self.rows[iid] = ("maker", f)
            self.status.configure(text=self.maker_note or "Press 'Search the chip maker's notices' to search.")
            return
        if not self.assessment:
            return
        want = {"May be affected": (cv.POTENTIAL,), "Can't tell": (cv.UNKNOWN,),
                "Fixed by reported patch": (cv.FIXED,)}.get(show)
        for i, f in enumerate(self.assessment["findings"]):
            if want and f["state"] not in want:
                continue
            iid = "b%d" % i
            wild = {True: "⛔ yes (CISA list)", False: "not on CISA's list", None: "unknown"}[f["exploited_in_wild"]]
            self.tree.insert("", "end", iid=iid, text=", ".join(f["cves"]) or f["id"],
                             values=(CVE_STATE_WORDS[f["state"]], wild, f["fix_spl"] or "?", f["severity"] or "-"))
            self.rows[iid] = ("bulletin", f)

    def on_select(self, event=None):
        sel = self.tree.selection()
        if not sel or sel[0] not in self.rows:
            return
        kind, f = self.rows[sel[0]]
        t = self.details
        t.configure(state="normal")
        t.delete("1.0", "end")
        w = lambda text, tag=(): t.insert("end", text, tag)  # noqa: E731
        if kind == "bulletin":
            w((", ".join(f["cves"]) or f["id"]) + "\n", "h")
            w(CVE_STATE_WORDS[f["state"]] + ": " + f["reason"] + "\n")
            if f["applies"] is None and f["state"] == cv.FIXED:
                w("(It isn't known whether this issue applies to your phone at all.)\n", "dim")
            w("\n" + (f["details"] or "") + "\n\n")
            w("Four separate questions:\n", "h")
            w("• Could your phone have this issue?  %s\n" % CVE_STATE_WORDS[f["state"]])
            w("• Used in real attacks?  %s\n" % {True: "yes - on CISA's known-exploited list",
                                                     False: "not on CISA's known-exploited list",
                                                     None: "unknown"}[f["exploited_in_wild"]])
            w("• Public exploit available?  not tracked here (unknown)\n")
            w("• Root shown on similar phones?  not tracked here (unknown)\n")
            w("Impact: %s.  Confidence: %s.\n" % (f["impact"], f["confidence"]), "dim")
            links = f["advisories"]
        else:
            w(f["cve"] + "\n", "h")
            w(f["summary"] + ".\n", ())
            if f["source"] == "bulletin":
                w("The Android bulletin data covers this issue%s.\n" % (
                    ": see it under 'Everything'" if f["bulletin_state"] else
                    " (it isn't one of the serious issues listed there)"), "dim")
            w("\n" + (f["desc"] or "") + "\n\n")
            w("Published %s.  Severity: %s.%s\n" % (f["published"] or "?", f["severity"] or "not given",
                                                    "  Listed on CISA's exploited list (per CIRCL's record)."
                                                    if f["kev_listed"] else ""), "dim")
            if f["source"] == "maker":
                w("This comes from the chip maker's own notice (via CIRCL Vulnerability-Lookup). It names chips "
                  "and Android versions, but not patch dates.\n", "dim")
            elif f["source"] == "mention":
                w("Found by searching for the maker's name, but published by someone else - it's not the maker's "
                  "notice, so it isn't matched against your phone.\n", "dim")
            links = f["refs"]
        for i, u in enumerate(links):
            tag = "u%d" % i
            w(u + "\n", ("link", tag))
            t.tag_bind(tag, "<Button-1>", lambda e, u=u: safe_open_url(u))
        t.configure(state="disabled")

    # ---- network (only on a click) -------------------------------------------

    def set_busy(self, on):
        self.busy = on
        for b in (self.dl_btn, self.maker_btn):
            b.state(["disabled"] if on else ["!disabled"])
        if on:
            self.stop.clear()
            self.stop_btn.pack(side="left", padx=4, after=self.maker_btn)
        else:
            self.stop_btn.pack_forget()

    def post(self, fn, *args):
        self.app.q.put(("call", fn) + args)

    def download(self):
        if self.busy:
            return
        self.set_busy(True)

        def work():
            try:
                res = sa.refresh_cve_data(self.stop, lambda m: self.post(self._status, m))
            except Exception as e:                   # never leave the window stuck busy
                res = {"ok": False, "message": "unexpected error (%s: %s)" % (type(e).__name__, e)}
            self.post(self._downloaded, res)
        threading.Thread(target=work, daemon=True).start()

    def _status(self, text):
        if self.winfo_exists():
            self.status.configure(text=text)

    def _downloaded(self, res):
        if not self.winfo_exists():
            return
        self.set_busy(False)
        self.status.configure(text=("Done: " if res["ok"] else "Not updated: ") + res["message"])
        if res["ok"]:
            self.data = sa.load_cve_data()
            self.recompute()

    def search_maker(self, refresh=False):
        if self.busy:
            return
        vendor = sa.circl_vendor(self.props)
        if not vendor:
            messagebox.showinfo("Chip maker unknown", "This phone doesn't say who made its chip in a way this "
                                "search understands, so there's nothing to search for.", parent=self)
            return
        cached = load_circl_cache_entry(vendor)
        if cached and not refresh:
            if messagebox.askyesno("Search again?", "%s's notices were fetched %s. Fetch them again now?\n\n"
                                   "No = use the saved copy." % (vendor, cached.get("fetched", "?")), parent=self):
                refresh = True
        elif not cached and not messagebox.askyesno(
                "Search the chip maker's notices",
                "This asks CIRCL Vulnerability-Lookup (a public service run by CIRCL, Luxembourg) for %s's security "
                "notices. Only the word \"%s\" is sent - nothing about your phone. Up to 10 requests.\n\nGo ahead?"
                % (vendor, vendor), parent=self):
            return
        self.set_busy(True)
        self.status.configure(text="Searching CIRCL for %s's notices ..." % vendor)

        def work():
            try:
                # "No, use the saved copy" means no network at all, however old the copy is
                res = sa.circl_search(vendor, refresh=refresh, cancel=self.stop,
                                      max_age=float("inf") if cached and not refresh else sa.CIRCL_MAX_AGE)
                self.post(self._searched, vendor, res, None)
            except sa.CirclError as e:
                self.post(self._searched, vendor, None, e)
        threading.Thread(target=work, daemon=True).start()

    def _searched(self, vendor, res, err):
        if not self.winfo_exists():
            return
        self.set_busy(False)
        if err is not None:
            self.maker_note = "Search unavailable: %s. (That's not the same as 'no issues'.)" % err
            self.show.set("Chip maker's notices")
            self.populate()
            return
        bulletin = {}
        for f in (self.assessment or {}).get("findings", []):
            for c in f["cves"]:
                bulletin[c] = f
        known = {c for r in (self.data or {}).get("osv_records", []) for c in r.get("cves", [])}   # ALL of it
        self.maker = sa.circl_assess(res["records"], self.props, bulletin, known, vendor)
        how = "loaded from the saved copy (%s)" % res["fetched"] if res["from_cache"] else "retrieved just now"
        self.maker_note = ("%s: %d notice(s) %s%s. Matched on your PC against your chip (%s) and Android %s." % (
            vendor, len(res["records"]), how,
            "" if res["complete"] else " - PARTIAL (%s; %d exist)" % (res.get("partial_reason") or "incomplete",
                                                                     res["count"]),
            self.props.get("ro.soc.model") or self.props.get("ro.board.platform") or "?",
            self.props.get("ro.build.version.release", "?")))
        if not res["records"]:
            if res.get("stopped"):
                self.maker_note = "%s: the search was stopped before any notices arrived." % vendor
            elif res["complete"]:
                self.maker_note = "%s: no notices found (the search completed)." % vendor
            else:
                self.maker_note = "%s: the search didn't complete (%s) - nothing can be said." % (
                    vendor, res.get("partial_reason") or "incomplete")
        self.show.set("Chip maker's notices")
        self.populate()


def load_circl_cache_entry(vendor):
    c = sa.load_json(sa.CIRCL_CACHE_FILE, {})
    e = c.get(vendor)
    return e if isinstance(e, dict) and e.get("complete") is True and isinstance(e.get("records"), list) else None


class RootingDBWindow(tk.Toplevel):
    """The saved rooting database: one row per codename, with refresh and delete."""

    def __init__(self, parent, app):
        super().__init__(parent)
        self.title("Rooting database")
        self.transient(parent)
        self.app = app
        self.minsize(640, 360)
        self.busy = False
        self.stop = threading.Event()

        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Rooting info saved per device identity (maker + codename + model + "
                  "platform). Opening a known device shows its saved answer with no AI call; a "
                  "different variant that shares a codename is matched only as a labelled fallback.",
                  foreground="#555555", wraplength=620, justify="left").pack(fill="x")
        cols = ("codename", "name", "maker", "model", "unlock", "risk", "by", "when", "android")
        self.tree = ttk.Treeview(frm, columns=cols, show="headings", selectmode="browse", height=10)
        for c, head, wdt in (("codename", "Codename", 100), ("name", "Marketing name", 120),
                             ("maker", "Maker", 80), ("model", "Model", 100),
                             ("unlock", "Unlock?", 70), ("risk", "Brick risk", 100),
                             ("by", "Researched by", 100), ("when", "When", 90),
                             ("android", "Android", 60)):
            self.tree.heading(c, text=head)
            self.tree.column(c, width=wdt, stretch=(c == "name"))
        sb = ttk.Scrollbar(frm, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True, pady=(6, 0))
        sb.pack(side="right", fill="y", pady=(6, 0))

        row = ttk.Frame(self, padding=(10, 0, 10, 10))
        row.pack(fill="x")
        self.refresh_one_btn = ttk.Button(row, text="Refresh selected", command=self.refresh_selected)
        self.refresh_one_btn.pack(side="left")
        self.refresh_all_btn = ttk.Button(row, text="Refresh whole database", command=self.refresh_all)
        self.refresh_all_btn.pack(side="left", padx=4)
        self.del_btn = ttk.Button(row, text="Delete selected", command=self.delete_selected)
        self.del_btn.pack(side="left")
        self.stop_btn = ttk.Button(row, text="Stop", command=self.stop.set)
        self.status = ttk.Label(row, text="", foreground="#555555")
        self.status.pack(side="left", padx=10)
        ttk.Button(row, text="Close", command=self.destroy).pack(side="right")
        self.populate()

    def populate(self):
        self.tree.delete(*self.tree.get_children())
        db = sa.load_rooting_db()
        for key in sorted(db):
            e = db[key]
            ident = e.get("identity", {})
            a = e.get("answer", {})
            self.tree.insert("", "end", iid=key, values=(
                ident.get("codename", "") or e.get("codename", "") or "?",
                e.get("marketname", "") or "-",
                ident.get("maker", "") or e.get("maker", "") or "-",
                ident.get("model", "") or e.get("model_number", "") or "-",
                a.get("can_unlock", "?"), (a.get("brick_risk", "") or "?")[:18],
                ai.PROVIDERS.get(e.get("provider"), {}).get("label", e.get("provider", "?")),
                (e.get("when", "") or "")[:10], e.get("researched_release", "") or "-"))
        self.status.configure(text="%d model(s) saved" % len(db))

    def _lock(self, busy):
        self.busy = busy
        for b in (self.refresh_one_btn, self.refresh_all_btn, self.del_btn):
            b.state(["disabled"] if busy else ["!disabled"])
        if busy:
            self.stop_btn.pack(side="left", padx=4, after=self.del_btn)
        else:
            self.stop_btn.pack_forget()

    def _provider(self):
        cfg = ai.load_config()
        have = [p for p in ai.PROVIDERS if ai.api_key(cfg, p)]
        if not have:
            messagebox.showinfo("No AI key", "No AI provider has an API key yet.\n\nAdd one in the "
                                "Apps tab > AI settings.", parent=self)
            return None, None
        main = cfg.get("provider", "anthropic")
        return (main if main in have else have[0]), cfg

    def refresh_selected(self):
        sel = self.tree.selection()
        if not sel:
            self.app.info("Select a model first")
            return
        provider, cfg = self._provider()
        if not provider:
            return
        self._run([sel[0]], provider, cfg)

    def refresh_all(self):
        db = sa.load_rooting_db()
        if not db:
            self.app.info("The database is empty")
            return
        provider, cfg = self._provider()
        if not provider:
            return
        if not messagebox.askyesno("Refresh whole database",
                                   "Re-ask %s about all %d saved model(s)? That's %d AI call(s), billed "
                                   "to your API account.\n\nThis researches the saved models - it "
                                   "doesn't need those phones connected." % (
                                       ai.PROVIDERS[provider]["label"], len(db), len(db)), parent=self):
            return
        self._run(sorted(db), provider, cfg)

    def _run(self, codenames, provider, cfg):
        if self.busy:
            return
        self.stop.clear()
        self._lock(True)
        threading.Thread(target=self._worker, args=(codenames, provider, cfg), daemon=True).start()

    def _worker(self, keys, provider, cfg):
        done = saved_fail = ai_fail = errored = 0
        try:
            db = sa.load_rooting_db()
            for i, key in enumerate(keys):
                if self.stop.is_set():
                    break
                try:
                    entry = db.get(key)
                    if not entry:
                        continue
                    ident = sa._entry_identity(entry)
                    name = entry.get("marketname") or ident.get("codename") or key
                    self.app.q.put(("call", self._progress, "Refreshing %d/%d: %s ..." % (
                        i + 1, len(keys), name)))
                    # rebuild the FULL stored identity + firmware context so nothing is lost
                    info = {"codename": ident.get("codename", ""),
                            "marketname": entry.get("marketname", ""), "miui": "", "bootloader": "",
                            "region": entry.get("region", ""),
                            "props": {"ro.product.manufacturer": ident.get("maker", ""),
                                      "ro.product.model": ident.get("model", ""),
                                      "ro.board.platform": ident.get("platform", "") or entry.get("soc", ""),
                                      "ro.product.board": ident.get("board", ""),
                                      "ro.soc.model": ident.get("soc_model", ""),
                                      "ro.soc.manufacturer": ident.get("soc_manufacturer", ""),
                                      "ro.miui.region": entry.get("region", ""),
                                      "ro.build.version.release": entry.get("researched_release", ""),
                                      "ro.build.version.sdk": entry.get("researched_sdk", ""),
                                      "ro.build.version.security_patch": entry.get("researched_patch", ""),
                                      "ro.build.fingerprint": entry.get("researched_fingerprint", ""),
                                      "ro.build.version.incremental": entry.get("researched_build", "")},
                            "arb": False}
                    res = ai.research_rooting(provider, cfg, info)
                    if not res.get("answer"):
                        ai_fail += 1
                        self.app.q.put(("call", self._note_error, name, res.get("error", "no answer")))
                        continue
                    # count success ONLY if persistence actually succeeded
                    if sa.rooting_db_put(info, res):
                        done += 1
                    else:
                        saved_fail += 1
                        self.app.q.put(("call", self._note_error, name, "AI answered but saving failed"))
                except Exception as e:   # one bad model must not kill the whole run
                    errored += 1
                    self.app.q.put(("call", self._note_error, key, "%s: %s" % (type(e).__name__, e)))
        finally:
            # completion is always delivered, even on cancel or unexpected failure
            self.app.q.put(("call", self._finished, done, len(keys), ai_fail, saved_fail, errored))

    def _progress(self, text):
        self.status.configure(text=text)
        self.app.info(text)

    def _note_error(self, cn, err):
        self.app.error("%s: %s" % (cn, err))

    def _finished(self, done, total, ai_fail=0, saved_fail=0, errored=0):
        self._lock(False)
        self.populate()
        parts = ["Refreshed %d of %d model(s)" % (done, total)]
        if ai_fail:
            parts.append("%d AI-failed" % ai_fail)
        if saved_fail:
            parts.append("%d save-failed" % saved_fail)
        if errored:
            parts.append("%d errored" % errored)
        if self.stop.is_set():
            parts.append("stopped")
        msg = parts[0] + (" (" + ", ".join(parts[1:]) + ")" if len(parts) > 1 else "")
        self.status.configure(text=msg)
        (self.app.error if (ai_fail or saved_fail or errored) else self.app.info)(msg)

    def delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        if messagebox.askyesno("Delete", "Remove '%s' from the rooting database?" % sel[0], parent=self):
            sa.rooting_db_delete(sel[0])
            self.populate()


INSPECT_MODES = [("Automatic (recommended)", "auto"), ("Quick - faster, less detail", "quick"),
                 ("Full - shows which code uses each address", "full")]
CLASS_WORDS = {"malicious": "Known bad", "suspicious": "Worth a look", "unknown": "Not known",
               "expected": "Expected"}
SEVERITY_WORDS = {"bad": "Serious", "warn": "Worth a look", "info": "For your information"}
STAGE_MARK = {sa.STAGE_DONE: "\u2705", sa.STAGE_SKIPPED: "\u2013", sa.STAGE_PARTIAL: "\u26a0",
              sa.STAGE_FAILED: "\u26d4", sa.STAGE_TIMEOUT: "\u26d4", "running": "\u2026", "waiting": "\u00b7"}
STAGE_ORDER = ["copy", "container", "manifest", "code", "resources", "native", "classify"]
STAGE_NAMES = {"copy": "copying the app from the phone", "container": "checking the APK files",
               "manifest": "reading the manifest", "code": "reading the code",
               "resources": "reading resources and bundled files", "native": "reading native libraries",
               "classify": "classifying what was found"}
SOURCE_WORDS = {"dex": "app code", "resource": "app resources", "asset": "bundled file",
                "native": "native library", "manifest": "manifest"}


_LIVE_INSPECT_WINDOWS = set()    # see InspectWindow.close()


class SendPreview(tk.Toplevel):
    """Shows the COMPLETE text that would be sent to an AI provider, scrollable,
    with Send / Cancel. result is True only if the user pressed Send."""

    def __init__(self, master, provider_label, text):
        super().__init__(master)
        self.title("Send this to %s?" % provider_label)
        self.transient(master)
        self.result = False
        self.minsize(560, 420)
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, wraplength=620, justify="left",
                  text="This is the complete text that will be sent to %s - scroll to read all of it. The "
                       "app's fixed instructions to the AI are added separately; nothing else is sent. "
                       "Query strings, passwords and token-like values were removed. It's billed to your "
                       "API account." % provider_label).pack(anchor="w")
        box = ttk.Frame(frm)
        box.pack(fill="both", expand=True, pady=8)
        self.txt = tk.Text(box, wrap="word", width=80, height=18, font=("TkFixedFont", 9))
        sb = ttk.Scrollbar(box, orient="vertical", command=self.txt.yview)
        self.txt.configure(yscrollcommand=sb.set)
        self.txt.insert("1.0", text)
        self.txt.configure(state="disabled")
        self.txt.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        ttk.Label(frm, text="%d characters" % len(text), foreground="#777777").pack(anchor="w")
        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=(6, 0))
        self.send_btn = ttk.Button(btns, text="Send", command=self.send)
        self.send_btn.pack(side="right")
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right", padx=6)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def send(self):
        self.result = True
        self.destroy()


def _dex_bytes(path):
    try:
        with zipfile.ZipFile(path) as z:
            return sum(i.file_size for i in z.infolist() if re.match(r"^classes\d*\.dex$", i.filename))
    except (zipfile.BadZipFile, OSError):
        return 0


class InspectWindow(tk.Toplevel):
    """Static code inspection of ONE installed app (phase 1b UI).

    Never runs the app, never asks an AI on its own: the only AI call is the
    'Ask AI about this' button, for the one finding that is selected."""

    def __init__(self, master, app, serial, pkg, appinfo, label):
        super().__init__(master)
        self.app, self.serial, self.pkg, self.appinfo, self.label = app, serial, pkg, appinfo, label
        self.vc = str(appinfo.get("version_code") or "")
        self.title("Inspect code - %s" % label)
        self.transient(master)
        self.minsize(820, 600)
        self.res, self.key, self.env = None, None, None
        self.busy, self.ai_busy = False, False
        self.stop = threading.Event()
        self._threads = []
        _LIVE_INSPECT_WINDOWS.add(self)
        self.items = {}                  # tree iid -> (kind, item)
        self.current = None              # (kind, item) shown in the evidence pane
        self.stage = {k: "waiting" for k in STAGE_ORDER}
        self.show_tech = tk.BooleanVar(value=False)
        self.mode_var = tk.StringVar(value=INSPECT_MODES[0][0])
        self.protocol("WM_DELETE_WINDOW", self.close)

        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text=label, font=("TkDefaultFont", 14, "bold")).pack(anchor="w")
        ttk.Label(frm, text="%s  \u00b7  version %s (%s)" % (pkg, appinfo.get("version") or "?", self.vc or "?"),
                  foreground="#555555").pack(anchor="w")
        self.summary = tk.Text(frm, height=5, wrap="word", relief="flat", padx=6, pady=4, cursor="arrow",
                               font=("TkDefaultFont", 10))
        self.summary.pack(fill="x", pady=(6, 4))
        for t, kw in (("big", {"font": ("TkDefaultFont", 12, "bold")}), ("ok", {"foreground": "#2e7d32"}),
                      ("warn", {"foreground": "#b26a00"}), ("bad", {"foreground": "#c62828"}),
                      ("dim", {"foreground": "#777777"}), ("mono", {"font": ("TkFixedFont", 9)})):
            self.summary.tag_configure(t, **kw)

        row = ttk.Frame(frm)
        row.pack(fill="x")
        ttk.Label(row, text="How deep:").pack(side="left")
        ttk.Combobox(row, textvariable=self.mode_var, values=[m[0] for m in INSPECT_MODES], state="readonly",
                     width=40).pack(side="left", padx=4)
        self.go_btn = ttk.Button(row, text="Inspect now", command=lambda: self.inspect(force=False))
        self.go_btn.pack(side="left", padx=4)
        self.again_btn = ttk.Button(row, text="Inspect again", command=lambda: self.inspect(force=True))
        self.check_btn = ttk.Button(row, text="Check again", command=self.check_again)
        self.stop_btn = ttk.Button(row, text="Stop", command=self.stop.set)
        ttk.Checkbutton(row, text="Show technical details", variable=self.show_tech,
                        command=self.rerender).pack(side="right")
        self.progress = ttk.Label(frm, text="", foreground="#555555")
        self.progress.pack(fill="x", pady=(4, 0))
        self.stage_lbl = ttk.Label(frm, text="", foreground="#555555", font=("TkFixedFont", 9))
        self.stage_lbl.pack(fill="x")

        pane = ttk.PanedWindow(frm, orient="vertical")
        pane.pack(fill="both", expand=True, pady=(6, 0))
        self.nb = ttk.Notebook(pane)
        pane.add(self.nb, weight=3)
        self.ep_tree = self._tree(("what", "address", "used_by", "note"),
                                  (("What", 110), ("Address", 300), ("Used by", 170), ("Note", 220)), "Addresses")
        self.ind_tree = self._tree(("level", "what"), (("How serious", 150), ("What", 600)), "Code warnings")
        self.parts_txt = self._text_tab("App parts")
        self.limits_txt = self._text_tab("What couldn't be checked")
        low = ttk.Frame(pane)
        pane.add(low, weight=2)
        self.ev = tk.Text(low, height=10, wrap="word", relief="flat", padx=8, pady=6, cursor="arrow",
                          font=("TkDefaultFont", 10))
        sb = ttk.Scrollbar(low, orient="vertical", command=self.ev.yview)
        self.ev.configure(yscrollcommand=sb.set)
        btns = ttk.Frame(low)
        btns.pack(side="bottom", fill="x", pady=(4, 0))
        self.ask_btn = ttk.Button(btns, text="Ask AI about this", command=lambda: self.ask_ai(False),
                                  state="disabled")
        self.ask_btn.pack(side="left")
        self.ask_again_btn = ttk.Button(btns, text="Ask AI again", command=lambda: self.ask_ai(True))
        self.ai_note = ttk.Label(btns, text="Only the selected finding is sent - never the app's code.",
                                 foreground="#777777")
        self.ai_note.pack(side="left", padx=8)
        self.ev.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        for t, kw in (("h1", {"font": ("TkDefaultFont", 12, "bold")}),
                      ("h2", {"font": ("TkDefaultFont", 10, "bold"), "spacing1": 8}),
                      ("ok", {"foreground": "#2e7d32"}), ("warn", {"foreground": "#b26a00"}),
                      ("bad", {"foreground": "#c62828"}), ("dim", {"foreground": "#777777"}),
                      ("mono", {"font": ("TkFixedFont", 9)})):
            self.ev.tag_configure(t, **kw)
        self.go_btn.state(["disabled"])
        self._say_summary([("Checking what's needed and whether this exact version was inspected before ...",
                            "dim")])
        self._spawn(self._prepare)

    # ---- small helpers -----------------------------------------------------

    def _spawn(self, target, *args):
        t = threading.Thread(target=target, args=args, daemon=True)
        self._threads.append(t)
        t.start()

    def post(self, fn, *args):
        self.app.q.put(("call", fn) + args)

    def alive(self):
        try:
            return bool(self.winfo_exists())
        except tk.TclError:
            return False

    def _tree(self, cols, heads, tab):
        f = ttk.Frame(self.nb)
        tree = ttk.Treeview(f, columns=cols, show="headings", selectmode="browse")
        for c, (h, w) in zip(cols, heads):
            tree.heading(c, text=h)
            tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(f, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        for t, color in (("bad", "#c62828"), ("warn", "#b26a00"), ("ok", "#2e7d32"), ("dim", "#5a6b7b")):
            tree.tag_configure(t, foreground=color)
        tree.bind("<<TreeviewSelect>>", self.on_select)
        self.nb.add(f, text=tab)
        return tree

    def _text_tab(self, tab):
        f = ttk.Frame(self.nb)
        t = tk.Text(f, wrap="word", relief="flat", padx=8, pady=6, cursor="arrow", font=("TkDefaultFont", 10))
        sb = ttk.Scrollbar(f, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        t.tag_configure("h2", font=("TkDefaultFont", 10, "bold"), spacing1=6)
        t.tag_configure("dim", foreground="#777777")
        t.tag_configure("warn", foreground="#b26a00")
        self.nb.add(f, text=tab)
        return t

    def _say_summary(self, chunks):
        self.summary.configure(state="normal")
        self.summary.delete("1.0", "end")
        for text, tag in chunks:
            self.summary.insert("end", text, tag)
        self.summary.configure(state="disabled")

    def _set_text(self, widget, chunks):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        for text, tag in chunks:
            widget.insert("end", text, tag)
        widget.configure(state="disabled")

    def _show_stages(self):
        self.stage_lbl.configure(text="   ".join("%s %s" % (STAGE_MARK.get(self.stage[k], "\u00b7"), k)
                                                for k in STAGE_ORDER))

    # ---- opening: tools + cached result -----------------------------------

    def _prepare(self):
        try:
            cfg = sa.load_sec_config()
            env = sa.inspector_env(cfg)
            ident = sa.load_json(sa.IDENTITY_FILE, {}).get(sa.identity_key(self.pkg, self.appinfo))
            key = sa.inspection_key_from_identity(self.pkg, self.vc, ident)
            saved = sa.load_inspection(key)
        except Exception as e:      # never leave the window stuck in "checking ..."
            self.post(self._prepare_failed, "%s: %s" % (type(e).__name__, e))
            return
        self.post(self._prepared, env, key, saved)

    def _prepare_failed(self, why):
        if not self.alive():
            return
        self._say_summary([("Couldn't check the inspector's tools or saved results.\n", ("big", "bad")),
                           ("%s\n" % why, "dim"),
                           ("Press 'Check again' to retry.\n", ())])
        self.go_btn.pack_forget()
        self.check_btn.pack(side="left", padx=4)

    def check_again(self):
        self.check_btn.pack_forget()
        self.go_btn.pack(side="left", padx=4)
        self.go_btn.state(["disabled"])
        self._say_summary([("Checking again ...", "dim")])
        self._spawn(self._prepare)

    def _prepared(self, env, key, saved):
        if not self.alive():
            return
        self.env = env
        if not env["ok"]:
            self._say_summary([("The code inspector isn't set up on this computer yet.\n", "big"),
                               ("It needs a free tool called Androguard. Nothing is installed automatically "
                                "- run these commands once in a terminal, then open this window again:\n", ()),
                               ("\n" + env["help"] + "\n", "mono")])
            self.summary.configure(height=14)
            return
        self.go_btn.state(["!disabled"])
        if saved:
            self.key, self.res = key, saved
            self.render(how="saved")
        else:
            notes = [("Nothing inspected yet for this version.\n", "big"),
                     ("'Inspect now' copies the app's files from the phone to a private temporary folder, "
                      "reads them WITHOUT running anything, and deletes the copies afterwards. Nothing is "
                      "sent anywhere.\n", ())]
            if env["problems"]:
                notes.append(("Note: " + "; ".join(env["problems"]) + "\n", "dim"))
            self._say_summary(notes)

    # ---- inspecting ---------------------------------------------------------

    def mode(self):
        return dict(INSPECT_MODES)[self.mode_var.get()]

    def inspect(self, force):
        if self.busy or not self.env or not self.env["ok"]:
            return
        if not self.serial:
            self.app.error("No device connected - pick one at the top")
            return
        self.busy = True
        self.stop.clear()
        self.stage = {k: "waiting" for k in STAGE_ORDER}
        self.stage["copy"] = "running"
        self._show_stages()
        self.go_btn.state(["disabled"])
        self.again_btn.state(["disabled"])
        self.stop_btn.pack(side="left", padx=4)
        self.progress.configure(text="Copying the app's files from the phone ...")
        self._spawn(self._work, force, self.mode())

    def _work(self, force, mode):
        """Background job. EVERY way out reports back to the window (so it never
        stays busy), the copied APKs are always deleted, and nothing incomplete
        is saved as a reusable result."""
        work = None
        try:
            work = tempfile.mkdtemp(prefix="adbm_apk_")
            os.chmod(work, 0o700)
            self._work_inner(force, mode, work)
        except Exception as e:
            self.post(self._finished, None, None, "The inspection failed unexpectedly (%s: %s) - nothing "
                                                  "was saved. You can try again." % (type(e).__name__, e))
        finally:
            if work:
                self._remove_copies(work)

    def _remove_copies(self, work):
        """Delete the private APK copies - and SAY so if that didn't work, since
        that's the one case where copies would stay on disk."""
        why = ""
        try:
            shutil.rmtree(work)
        except OSError as e:
            why = e.strerror or str(e)
        if os.path.exists(work):
            self.post(self.app.error, "Couldn't delete the temporary copies of the app at %s (%s). They're "
                                      "private to your user, but please delete that folder yourself."
                      % (work, why or "unknown reason"))

    def _work_inner(self, force, mode, work):
        try:
            ident = read_app_identity(self.serial, self.pkg, work, self.stop, keep=True)
        except AdbError as e:
            self.post(self._finished, None, None, "Couldn't read the app from the phone: %s" % e)
            return
        if ident is None or self.stop.is_set():
            self.post(self._finished, None, None, "Stopped - nothing was saved.")
            return
        readable = [x for x in ident["parts"] if x.get("local")]
        key = sa.inspection_key(self.pkg, self.vc, [x["sha256"] for x in ident["parts"]]) \
            if ident.get("coverage") == "full" else None
        if key and not force:
            saved = sa.load_inspection(key)
            if saved:
                self.post(self._finished, saved, key, None, True)
                return
        if not readable:
            self.post(self._finished, None, None, "None of the app's files could be copied from the phone.")
            return
        self.post(self._stage, {"stage": "copy", "done": True})
        cfg = dict(sa.load_sec_config(), inspector_mode=mode)
        lim = sa.inspector_limits(sum(os.path.getsize(x["local"]) for x in readable),
                                  sum(_dex_bytes(x["local"]) for x in readable), cfg)
        job = {"package": self.pkg, "version_code": self.vc,
               "parts": [{"name": x["name"], "kind": x["kind"], "path": x["local"]} for x in readable],
               "signatures": sa.inspector_signatures(sa.cached_exodus_trackers())}
        res = sa.run_inspection(job, self.env["python"], lim,
                                on_progress=lambda p: self.post(self._stage, p), stop=self.stop)
        for x in ident["parts"]:
            if not x.get("local"):
                res["parts"].append({"name": x["name"], "kind": x.get("kind"), "analysed": False,
                                     "problems": ["couldn't be copied from the phone: %s"
                                                  % (x.get("error") or "unknown reason")]})
                res.setdefault("limitations", []).append("%s couldn't be copied from the phone, so it "
                                                         "wasn't inspected" % x["name"])
        res["summary"] = sa.summarize_inspection(res)
        res["label"], res["inspected"] = self.label, time.strftime("%Y-%m-%d %H:%M")
        res["part_hashes"] = {x["name"]: x.get("sha256") for x in ident["parts"]}
        note = None
        interrupted = any(s["id"] == "worker" for s in res.get("stages", []))
        if key and not interrupted:
            try:
                sa.save_inspection(key, res)
            except OSError as e:
                note = "The result couldn't be saved (%s) - it's shown for now only." % (e.strerror or e)
        elif not key:
            note = "Not every part of the app could be copied, so this result isn't saved."
        self.post(self._finished, res, key if key and not interrupted else None, note)

    def _stage(self, p):
        if not self.alive():
            return
        st = p.get("stage")
        if st == "copy" and p.get("done"):
            self.stage["copy"] = sa.STAGE_DONE
        elif st in self.stage:
            for k in STAGE_ORDER:
                if k == st:
                    break
                if self.stage[k] in ("waiting", "running"):
                    self.stage[k] = sa.STAGE_DONE
            self.stage[st] = "running"
        if p.get("msg"):
            self.progress.configure(text=p["msg"][:150] + " ...")
        self._show_stages()

    def _finished(self, res, key, note, from_cache=False):
        if not self.alive():
            return
        self.busy = False
        self.stop_btn.pack_forget()
        self.go_btn.state(["!disabled"])
        self.again_btn.state(["!disabled"])
        self.progress.configure(text=note or "")
        if res is None:
            self.stage = {k: ("waiting" if self.stage[k] == "running" else self.stage[k]) for k in STAGE_ORDER}
            self._show_stages()
            if note:
                self.app.error(note)
            return
        self.res = res
        self.key = key
        self.render(how="saved" if from_cache else "new")

    # ---- showing a result ---------------------------------------------------

    def rerender(self):
        if self.res:
            self.render(how=None)

    def render(self, how=None):
        res = self.res
        sm = res.get("summary") or sa.summarize_inspection(res)
        tag = {sa.OK: "ok", sa.INFO: "warn", sa.WARN: "warn", sa.BAD: "bad"}[sm["level"]]
        chunks = [(sm["text"] + "\n", ("big", tag)), (sm["coverage"] + "\n", "dim")]
        for n in sm.get("notes", []):
            chunks.append(("\u2022 " + n + "\n", ()))
        if how == "saved":
            chunks.append(("Saved result for this exact version, inspected %s. 'Inspect again' runs it anew.\n"
                           % (res.get("inspected") or "earlier"), "dim"))
        if sm["level"] == sa.OK:
            chunks.append(("This means nothing worrying was FOUND in what could be read. It isn't a promise the "
                           "app is safe: things it downloads or decrypts while running can't be seen this way.\n",
                           "dim"))
        self._say_summary(chunks)
        for s in res.get("stages", []):
            if s["id"] in self.stage:
                self.stage[s["id"]] = s["status"]
        if any(s["id"] == "worker" for s in res.get("stages", [])):
            for k in STAGE_ORDER[1:]:
                if self.stage[k] in ("waiting", "running"):
                    self.stage[k] = sa.STAGE_FAILED
        self._show_stages()
        self.go_btn.pack_forget()
        if self.busy:
            self.again_btn.pack(side="left", padx=4, before=self.stop_btn)
        else:
            self.again_btn.pack(side="left", padx=4)
        # addresses
        self.items.clear()
        tech = self.show_tech.get()
        for tree in (self.ep_tree, self.ind_tree):
            tree.delete(*tree.get_children())
        for i, e in enumerate(res.get("endpoints", [])):
            locs = e.get("locations") or [{}]
            l0 = locs[0]
            used = e.get("owner") or ("the app itself" if l0.get("own_code") else
                                      SOURCE_WORDS.get(l0.get("source"), "?"))
            if tech and l0.get("cls"):
                used += " (%s)" % l0["cls"].rsplit(".", 1)[-1]
            note = "not encrypted" if e.get("issues") else (e.get("evidence") or [""])[0]
            iid = "ep%d" % i
            self.ep_tree.insert("", "end", iid=iid, values=(CLASS_WORDS[e["classification"]], e["value"], used,
                                                            note[:120]),
                                tags=({"malicious": "bad", "suspicious": "warn", "expected": "ok"}
                                      .get(e["classification"], "dim"),))
            self.items[iid] = ("endpoint", e)
        for i, it in enumerate(res.get("indicators", [])):
            iid = "in%d" % i
            self.ind_tree.insert("", "end", iid=iid, values=(SEVERITY_WORDS.get(it["severity"], it["severity"]),
                                                             it["title"]),
                                 tags=({"bad": "bad", "warn": "warn"}.get(it["severity"], "dim"),))
            self.items[iid] = ("indicator", it)
        self.nb.tab(0, text="Addresses (%d)" % len(res.get("endpoints", [])))
        self.nb.tab(1, text="Code warnings (%d)" % len(res.get("indicators", [])))
        # parts
        chunks = []
        for p in res.get("parts", []):
            chunks.append(("%s  %s\n" % ("\u2705" if p.get("analysed") else "\u26a0", p["name"]), "h2"))
            chunks.append(("  %s\n" % {"base": "main app file", "config": "extra part for this phone",
                                       "feature": "optional feature"}.get(p.get("kind"), p.get("kind") or ""), "dim"))
            if p.get("dex"):
                chunks.append(("  code files: %s\n" % ", ".join(p["dex"]), ()))
            if p.get("native"):
                chunks.append(("  native libraries: %s\n" % ", ".join(p["native"]), ()))
            for pr in p.get("problems", []):
                chunks.append(("  \u26a0 %s\n" % pr, "warn"))
            if tech and (res.get("part_hashes") or {}).get(p["name"]):
                chunks.append(("  sha256 %s\n" % res["part_hashes"][p["name"]], "dim"))
        if res.get("sdks"):
            chunks.append(("\nLibraries recognised inside the app\n", "h2"))
            for s_ in res["sdks"]:
                chunks.append(("\u2022 %s (%d pieces of code; from the %s)\n" % (s_["name"], s_["classes"],
                                                                                 s_["source"]), ()))
        if res.get("network_apis"):
            chunks.append(("\nWays the app can connect to the network\n", "h2"))
            chunks.append((", ".join(a["api"] for a in res["network_apis"]) + "\n", ()))
        self._set_text(self.parts_txt, chunks)
        # limitations
        chunks = []
        bad_st = [s for s in res.get("stages", []) if s["status"] not in (sa.STAGE_DONE, sa.STAGE_SKIPPED)]
        if bad_st:
            chunks.append(("Steps that didn't finish\n", "h2"))
            for s in bad_st:
                chunks.append(("\u26a0 %s: %s\n" % (s["name"], s.get("detail") or s["status"]), "warn"))
        chunks.append(("Limits of this kind of check\n", "h2"))
        for l_ in res.get("limitations", []):
            chunks.append(("\u2022 %s\n" % l_, ()))
        if tech and res.get("worker_stderr"):
            chunks.append(("\nAnalysis program output\n", "h2"))
            chunks.append((res["worker_stderr"][-3000:] + "\n", "dim"))
        self._set_text(self.limits_txt, chunks)
        self.show_evidence(None)

    def on_select(self, event=None):
        tree = event.widget if event else self.ep_tree
        sel = tree.selection()
        if sel and sel[0] in self.items:
            self.show_evidence(self.items[sel[0]])

    def ai_answers(self, kind, item):
        return ((self.res or {}).get("ai") or {}).get(sa.finding_id(kind, item), {})

    def show_evidence(self, sel):
        self.current = sel
        tech = self.show_tech.get()
        if not sel:
            self._set_text(self.ev, [("Click an address or a code warning above to see why it's listed.", "dim")])
            self.ask_btn.state(["disabled"])
            self.ask_again_btn.pack_forget()
            return
        kind, it = sel
        c = []
        if kind == "endpoint":
            cls = it["classification"]
            c.append((it["value"] + "\n", "h1"))
            c.append(("%s  (confidence: %s)\n" % (CLASS_WORDS[cls], it.get("confidence")),
                      {"malicious": "bad", "suspicious": "warn", "expected": "ok"}.get(cls, "dim")))
            if it.get("evidence"):
                c.append(("Why\n", "h2"))
                c += [("\u2022 %s\n" % x, ()) for x in it["evidence"]]
            if it.get("issues"):
                c.append(("Problem\n", "h2"))
                c += [("\u2022 %s\n" % x, "warn") for x in it["issues"]]
        else:
            c.append((it["title"] + "\n", "h1"))
            c.append(("%s  (confidence: %s)\n" % (SEVERITY_WORDS.get(it["severity"], it["severity"]),
                                                  it.get("confidence")),
                      {"bad": "bad", "warn": "warn"}.get(it["severity"], "dim")))
            c.append((it.get("detail", "") + "\n", ()))
        locs = it.get("locations") or []
        if locs:
            c.append(("Where it was found\n", "h2"))
            for l_ in locs[:8 if tech else 4]:
                who = l_.get("owner") or ("the app's own code" if l_.get("own_code") else
                                          SOURCE_WORDS.get(l_.get("source"), "?"))
                line = "\u2022 in %s, part %s" % (who, l_.get("part"))
                if tech:
                    line += "  [%s%s%s]" % (l_.get("file") or "", (" " + l_["cls"]) if l_.get("cls") else "",
                                           ("." + l_["method"]) if l_.get("method") else "")
                c.append((line + "\n", ()))
            if len(locs) > (8 if tech else 4):
                c.append(("  ... and %d more places\n" % (len(locs) - (8 if tech else 4)), "dim"))
        answers = self.ai_answers(kind, it)
        for prov, r in sorted(answers.items()):
            label = ai.PROVIDERS.get(prov, {}).get("label", prov)
            c.append(("\nAI explanation (%s, %s)\n" % (label, r.get("when", "")), "h2"))
            a = r.get("answer")
            if a and not r.get("searches"):
                c.append(("No web search was done for this answer: it's based on the AI's own knowledge, "
                          "which may be out of date.\n", "warn"))
            if a:
                c.append(({"likely_normal": "Probably normal", "unclear": "Unclear",
                           "concerning": "Concerning"}[a["assessment"]] + "\n",
                          {"likely_normal": "ok", "unclear": "warn", "concerning": "bad"}[a["assessment"]]))
                for k, title in (("summary", None), ("who_runs_it", "Who runs it"), ("why", "Why"),
                                 ("what_to_do", "What you can do")):
                    if a.get(k):
                        c.append((("%s: " % title if title else "") + a[k] + "\n", ()))
                for s_ in a.get("sources", []):
                    c.append(("\u2022 %s - %s  (%s)\n" % (s_["title"], s_["url"], (
                        "this address matches a page the AI's search returned - that shows where it came "
                        "from, not that the page backs up the answer") if s_.get("matched") else
                        "NOT among the pages the AI's search returned - the AI may have written it from "
                        "memory"), "dim"))
            if r.get("error"):
                c.append(("Last attempt failed: %s\n" % r["error"], "warn"))
        if tech:
            c.append(("\nRaw data\n", "h2"))
            c.append((json.dumps(it, indent=1, ensure_ascii=False)[:4000] + "\n", "mono"))
        self._set_text(self.ev, c)
        if answers and any(r.get("answer") for r in answers.values()):
            self.ask_btn.state(["disabled"])
            self.ask_again_btn.pack(side="left", padx=4, before=self.ai_note)
        else:
            self.ask_btn.state(["!disabled"] if not self.ai_busy else ["disabled"])
            self.ask_again_btn.pack_forget()

    # ---- AI, only on request ----------------------------------------------

    def ask_ai(self, again):
        if not self.current or self.ai_busy or not self.res:
            return
        kind, it = self.current
        cfg = ai.load_config()
        prov = cfg.get("provider", "anthropic")
        if prov not in ai.PROVIDERS:
            prov = "anthropic"
        if not ai.api_key(cfg, prov):
            messagebox.showinfo("API key needed", "There's no API key for %s yet.\n\nAdd it in the AI settings "
                                "window (Apps tab)." % ai.PROVIDERS[prov]["label"], parent=self)
            return
        fid = sa.finding_id(kind, it)
        if not again and (self.ai_answers(kind, it).get(prov) or {}).get("answer"):
            self.show_evidence(self.current)      # already explained: show the saved answer, no call
            return
        ctx = sa.finding_context(self.res, kind, it, self.label)
        if not self.confirm_send(ai.PROVIDERS[prov]["label"], ai.build_finding_request(ctx)):
            return
        self.ai_busy = True
        self.ask_btn.state(["disabled"])
        self.ai_note.configure(text="Asking %s about this one finding ..." % ai.PROVIDERS[prov]["label"])

        def job():
            try:
                r = ai.explain_finding(prov, cfg, ctx)
            except Exception as e:      # explain_finding shouldn't raise; never strand the button anyway
                r = {"provider": prov, "when": time.strftime("%Y-%m-%d %H:%M"),
                     "error": "unexpected problem: %s: %s" % (type(e).__name__, e)}
            self.post(self._ai_done, fid, prov, r)
        self._spawn(job)

    def confirm_send(self, provider_label, text):
        """Modal preview of the complete request; True only if the user presses Send."""
        dlg = SendPreview(self, provider_label, text)
        try:
            dlg.grab_set()
        except tk.TclError:
            pass
        self.wait_window(dlg)
        return dlg.result

    def _ai_done(self, fid, prov, r):
        self.ai_busy = False
        if not self.alive():
            return
        self.ai_note.configure(text="Only the selected finding is sent - never the app's code.")
        slot = self.res.setdefault("ai", {}).setdefault(fid, {})
        old = slot.get(prov)
        if r.get("error") and isinstance(old, dict) and old.get("answer"):
            old = dict(old)
            old["error"] = r["error"]                     # keep the earlier good answer
            slot[prov] = old
        else:
            slot[prov] = r
        if self.key:
            try:
                sa.save_inspection(self.key, self.res)
            except OSError as e:
                self.app.error("Couldn't save the AI answer (%s) - it's shown for now only" % (e.strerror or e))
        if r.get("error"):
            self.app.error("AI: %s" % r["error"])
        if self.current and sa.finding_id(*self.current) == fid:
            self.show_evidence(self.current)

    def close(self):
        """Stop any work and close. The object stays registered until its worker
        threads have finished, and is released from the GUI thread - so Tk
        objects are never cleaned up from a background thread."""
        self.stop.set()
        root = self.app.root
        self.destroy()

        def reap():
            if any(t.is_alive() for t in self._threads):
                try:
                    root.after(500, reap)
                except tk.TclError:
                    pass
                return
            self._threads = []
            # drop the Tk variables HERE, on the GUI thread: if they were left to
            # the garbage collector, it could free them from any thread and Tk
            # would complain ("main thread is not in main loop")
            self.show_tech = self.mode_var = None
            _LIVE_INSPECT_WINDOWS.discard(self)
        reap()


class SecuritySettings(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Security settings")
        self.transient(master)
        self.resizable(False, False)
        self.cfg = sa.load_sec_config()
        frm = ttk.Frame(self, padding=14)
        frm.pack(fill="both", expand=True)
        bold = ("TkDefaultFont", 10, "bold")
        ttk.Label(frm, text="All optional. Each key only unlocks its own part of the deep scan.",
                  foreground="#555555").grid(row=0, column=0, columnspan=2, sticky="w")
        self.vars = {}
        r = 1
        for key, name, hint in (
                ("virustotal_key", "VirusTotal API key",
                 "Free at virustotal.com (sign up > API key). 4 lookups/minute, 500/day."),
                ("malwarebazaar_key", "MalwareBazaar Auth-Key",
                 "Free at auth.abuse.ch (sign in > Auth-Key)."),
                ("exodus_token", "Exodus Privacy API token",
                 "Free account at reports.exodus-privacy.eu.org (for the tracker reports).")):
            ttk.Label(frm, text=name, font=bold).grid(row=r, column=0, sticky="w", pady=(10, 0))
            v = tk.StringVar(value=self.cfg.get(key, ""))
            ttk.Entry(frm, textvariable=v, show="\u2022", width=56).grid(row=r + 1, column=0, columnspan=2,
                                                                         sticky="w")
            ttk.Label(frm, text=hint, foreground="#777777").grid(row=r + 2, column=0, columnspan=2, sticky="w")
            self.vars[key] = v
            r += 3
        ttk.Label(frm, text="Exodus server", font=bold).grid(row=r, column=0, sticky="w", pady=(10, 0))
        self.vars["exodus_url"] = tk.StringVar(value=self.cfg.get("exodus_url"))
        ttk.Entry(frm, textvariable=self.vars["exodus_url"], width=56).grid(row=r + 1, column=0,
                                                                          columnspan=2, sticky="w")
        r += 2
        self.sysvar = tk.BooleanVar(value=bool(self.cfg.get("deep_include_updated_system")))
        ttk.Checkbutton(frm, text="Deep scan also checks updated system apps (more to download)",
                        variable=self.sysvar).grid(row=r, column=0, columnspan=2, sticky="w", pady=(10, 0))
        r += 1
        ttk.Label(frm, text="Saved in %s (only your user can read it). Only file fingerprints and "
                  "package names are ever sent." % sa.SEC_CONFIG_FILE, foreground="#777777",
                  wraplength=460, justify="left").grid(row=r, column=0, columnspan=2, sticky="w", pady=(10, 0))
        btns = ttk.Frame(frm)
        btns.grid(row=r + 1, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(btns, text="Save", command=self.save).pack(side="right", padx=6)

    def save(self):
        cfg = dict(self.cfg)
        for k, v in self.vars.items():
            cfg[k] = v.get().strip()
        cfg["exodus_url"] = cfg["exodus_url"] or sa.DEFAULT_SEC_CONFIG["exodus_url"]
        cfg["deep_include_updated_system"] = self.sysvar.get()
        try:
            sa.save_sec_config(cfg)
        except OSError as e:
            messagebox.showerror("Could not save", str(e), parent=self)
            return
        self.destroy()


# --------------------------------------------------------------------------
# GUI: install options window
# --------------------------------------------------------------------------

class InstallDialog(tk.Toplevel):
    def __init__(self, master, jobs, sdk, on_ok):
        super().__init__(master)
        self.title("Install on the device")
        self.transient(master)
        self.resizable(False, False)
        self.on_ok = on_ok
        frm = ttk.Frame(self, padding=14)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Install %s:" % ("this app" if len(jobs) == 1 else "%d apps" % len(jobs)),
                  font=("TkDefaultFont", 10, "bold")).pack(anchor="w")
        for j in jobs[:12]:
            kind = "bundle" if j.get("bundle") else ("split app" if len(j.get("apks", [])) > 1 else "")
            ttk.Label(frm, text="\u2022 " + j["label"] + ("   (%s)" % kind if kind else "")).pack(
                anchor="w", padx=(8, 0))
        if len(jobs) > 12:
            ttk.Label(frm, text="   ... and %d more" % (len(jobs) - 12)).pack(anchor="w")
        ttk.Separator(frm).pack(fill="x", pady=10)
        self.replace = tk.BooleanVar(value=True)
        self.downgrade = tk.BooleanVar(value=False)
        self.grant = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="Update it if it's already installed (keeps its data)",
                        variable=self.replace).pack(anchor="w")
        ttk.Checkbutton(frm, text="Allow installing an older version than the one on the device",
                        variable=self.downgrade).pack(anchor="w")
        g = ttk.Checkbutton(frm, text="Give it all the permissions it asks for, right away",
                            variable=self.grant)
        g.pack(anchor="w")
        if sdk and sdk < 23:
            g.state(["disabled"])
            ttk.Label(frm, text="   (only on Android 6 and newer)", foreground="#777777").pack(anchor="w")
        ttk.Label(frm, text="Some devices show a confirmation on their screen - watch the device.",
                  foreground="#777777").pack(anchor="w", pady=(10, 0))
        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=(12, 0))
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(btns, text="Install", command=self.ok).pack(side="right", padx=6)

    def ok(self):
        opts = {"replace": self.replace.get(), "downgrade": self.downgrade.get(),
                "grant": self.grant.get()}
        self.destroy()
        self.on_ok(opts)


# --------------------------------------------------------------------------
# GUI: uninstall window
# --------------------------------------------------------------------------

class UninstallDialog(tk.Toplevel):
    def __init__(self, master, items, sdk, on_ok):
        super().__init__(master)
        self.title("Uninstall")
        self.transient(master)
        self.resizable(False, False)
        self.on_ok = on_ok
        self.items = items
        bold = ("TkDefaultFont", 10, "bold")
        frm = ttk.Frame(self, padding=14)
        frm.pack(fill="both", expand=True)
        users = [i for i in items if not i["system"]]
        systems = [i for i in items if i["system"]]
        updated = [i for i in systems if i["updated"]]
        mark = {kb.SAFE: "\u2705", kb.CAUTION: "\u26a0", kb.CRITICAL: "\u26d4", kb.UNKNOWN: "\u2753"}

        def listing(rows):
            for i in rows[:10]:
                ttk.Label(frm, text="%s %s" % (mark[i["risk"]], i["label"]),
                          foreground="#c62828" if i["risk"] == kb.CRITICAL else "").pack(
                    anchor="w", padx=(8, 0))
            if len(rows) > 10:
                ttk.Label(frm, text="   ... and %d more" % (len(rows) - 10)).pack(anchor="w")

        self.backup = tk.BooleanVar(value=True)
        self.keep = tk.BooleanVar(value=False)
        self.mode = tk.StringVar(value="user")
        if users:
            ttk.Label(frm, text="Apps you installed - these get deleted:", font=bold).pack(anchor="w")
            listing(users)
            ttk.Checkbutton(frm, text="Save a copy of the app (APK) on this PC first, so it can "
                            "be installed again", variable=self.backup).pack(anchor="w", pady=(6, 0))
            ttk.Label(frm, text="   Saved in %s" % BACKUP_DIR, foreground="#777777").pack(anchor="w")
        if systems:
            if users:
                ttk.Separator(frm).pack(fill="x", pady=10)
            ttk.Label(frm, text="System apps - removed for your user:", font=bold).pack(anchor="w")
            listing(systems)
            ttk.Label(frm, text="Android doesn't allow deleting system apps without root. They "
                      "disappear and their data is erased,\nbut the app stays inside the system and "
                      "can be restored here with 'Restore removed'.",
                      foreground="#555555", justify="left").pack(anchor="w", pady=(6, 0))
            if sdk and sdk < 26:
                ttk.Label(frm, text="\u26a0 On this Android version restoring may not work (it can "
                          "need a factory reset).\n   Turning the app OFF is the safer choice here.",
                          foreground="#c62828", justify="left").pack(anchor="w", pady=(6, 0))
            if updated:
                ttk.Label(frm, text="%d of them have updates installed. For those:" % len(updated)).pack(
                    anchor="w", pady=(8, 0))
                ttk.Radiobutton(frm, text="Remove them for my user", value="user",
                                variable=self.mode).pack(anchor="w", padx=(8, 0))
                ttk.Radiobutton(frm, text="Only remove the updates (back to the factory version)",
                                value="updates", variable=self.mode).pack(anchor="w", padx=(8, 0))
        ttk.Separator(frm).pack(fill="x", pady=10)
        ttk.Checkbutton(frm, text="Keep the app's data on the device (a reinstall continues where it "
                        "left off; the space stays used)", variable=self.keep).pack(anchor="w")
        self.crit = [i for i in items if i["risk"] == kb.CRITICAL]
        if self.crit:
            ttk.Label(frm, text="\u26d4 %d of these should stay installed: removing them can make the "
                      "device misbehave\n   or not start. Type YES to remove them anyway:"
                      % len(self.crit), foreground="#c62828", justify="left").pack(anchor="w",
                                                                                    pady=(10, 0))
            self.yes = tk.StringVar()
            ttk.Entry(frm, textvariable=self.yes, width=10).pack(anchor="w", padx=(18, 0))
        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=(12, 0))
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(btns, text="Uninstall", command=self.ok).pack(side="right", padx=6)

    def ok(self):
        if self.crit and self.yes.get().strip() != "YES":
            messagebox.showinfo("Not confirmed", "Type YES in the box to remove the \u26d4 apps, "
                                "or unselect them.", parent=self)
            return
        opts = {"backup": self.backup.get(), "keep_data": self.keep.get(),
                "updated_mode": self.mode.get()}
        self.destroy()
        self.on_ok(opts)


# --------------------------------------------------------------------------
# GUI: AI settings window
# --------------------------------------------------------------------------

class AISettings(tk.Toplevel):
    def __init__(self, master, on_saved):
        super().__init__(master)
        self.title("AI settings")
        self.transient(master)
        self.resizable(False, False)
        self.on_saved = on_saved
        self.cfg = ai.load_config()
        self.fields = {}
        self.combos = {}
        bold = ("TkDefaultFont", 10, "bold")

        frm = ttk.Frame(self, padding=14)
        frm.pack(fill="both", expand=True)
        r = 0
        ttk.Label(frm, text="Main AI (answers \"Ask AI\"):", font=bold).grid(
            row=r, column=0, sticky="w")
        main = self.cfg.get("provider", "anthropic")
        self.main_var = tk.StringVar(value=main if main in ai.PROVIDERS else "anthropic")
        for i, (key, p) in enumerate(ai.PROVIDERS.items()):
            ttk.Radiobutton(frm, text=p["label"], value=key, variable=self.main_var).grid(
                row=r, column=1 + i, sticky="w", padx=(0, 10))
        r += 1
        ttk.Label(frm, text="\"Compare AIs\" asks the other one too.", foreground="#777777").grid(
            row=r, column=0, columnspan=3, sticky="w")
        r += 1

        for key, p in ai.PROVIDERS.items():
            ttk.Separator(frm).grid(row=r, column=0, columnspan=3, sticky="ew", pady=10)
            r += 1
            ttk.Label(frm, text=p["label"], font=bold).grid(row=r, column=0, sticky="w")
            r += 1
            ttk.Label(frm, text="API key:").grid(row=r, column=0, sticky="w")
            kv = tk.StringVar(value=(self.cfg.get(key) or {}).get("api_key", ""))
            ttk.Entry(frm, textvariable=kv, show="\u2022", width=52).grid(
                row=r, column=1, columnspan=2, sticky="w")
            r += 1
            env = p["env"]
            hint = "Leave empty to use the %s environment variable%s." % (
                env, " (it is set)" if os.environ.get(env) else " (it isn't set)")
            ttk.Label(frm, text=hint, foreground="#777777").grid(row=r, column=1, columnspan=2,
                                                                 sticky="w")
            r += 1
            ttk.Label(frm, text="Model:").grid(row=r, column=0, sticky="w", pady=(4, 0))
            mv = tk.StringVar(value=ai.model_of(self.cfg, key))
            cb = ttk.Combobox(frm, textvariable=mv, values=p["models"], width=30)
            cb.grid(row=r, column=1, sticky="w", pady=(4, 0))
            bb = ttk.Frame(frm)
            bb.grid(row=r, column=2, sticky="w", pady=(4, 0))
            ttk.Button(bb, text="Load models", command=lambda k=key: self.load_models(k)).pack(
                side="left")
            ttk.Button(bb, text="Test", command=lambda k=key: self.test(k)).pack(
                side="left", padx=(4, 0))
            r += 1
            sv = None
            if key == "anthropic":
                ttk.Label(frm, text="Max web searches:").grid(row=r, column=0, sticky="w",
                                                             pady=(4, 0))
                sv = tk.StringVar(value=str((self.cfg.get(key) or {}).get("max_searches", 5)))
                tk.Spinbox(frm, from_=1, to=20, textvariable=sv, width=5).grid(
                    row=r, column=1, sticky="w", pady=(4, 0))
                r += 1
            st = ttk.Label(frm, text="", wraplength=430)
            st.grid(row=r, column=1, columnspan=2, sticky="w")
            r += 1
            self.fields[key] = (kv, mv, sv, st)
            self.combos[key] = cb

        ttk.Separator(frm).grid(row=r, column=0, columnspan=3, sticky="ew", pady=10)
        r += 1
        ttk.Label(frm, text="Saved in %s (only your user can read it)." % ai.CONFIG_FILE,
                  foreground="#777777").grid(row=r, column=0, columnspan=3, sticky="w")
        r += 1
        btns = ttk.Frame(frm)
        btns.grid(row=r, column=0, columnspan=3, sticky="e", pady=(10, 0))
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(btns, text="Save", command=self.save).pack(side="right", padx=6)

    def collect(self):
        cfg = json.loads(json.dumps(self.cfg))
        cfg["provider"] = self.main_var.get()
        cfg["second_opinion"] = [p for p in ai.PROVIDERS if p != cfg["provider"]][0]
        for key, (kv, mv, sv, st) in self.fields.items():
            sect = dict(cfg.get(key) or {})
            sect["api_key"] = kv.get().strip()
            sect["model"] = mv.get().strip() or ai.DEFAULT_CONFIG[key]["model"]
            if sv is not None:
                try:
                    sect["max_searches"] = max(1, min(20, int(sv.get())))
                except ValueError:
                    sect["max_searches"] = 5
            cfg[key] = sect
        return cfg

    def background(self, key, busy_text, fn, done):
        """Run fn() in a thread; call done(result) back on the GUI thread."""
        st = self.fields[key][3]
        st.configure(text=busy_text, foreground="")
        box = []
        threading.Thread(target=lambda: box.append(fn()), daemon=True).start()

        def check():
            if not self.winfo_exists():
                return
            if not box:
                self.after(200, check)
                return
            done(box[0])
        self.after(200, check)

    def show_result(self, key, ok, msg):
        self.fields[key][3].configure(text=("\u2705 " if ok else "\u26d4 ") + msg,
                                      foreground="#2e7d32" if ok else "#c62828")

    def test(self, key):
        cfg = self.collect()
        self.background(key, "Testing ...", lambda: ai.test_connection(key, cfg),
                        lambda res: self.show_result(key, *res))

    def load_models(self, key):
        cfg = self.collect()

        def done(res):
            ok, data = res
            if not ok:
                self.show_result(key, False, data)
                return
            self.combos[key]["values"] = data
            current = self.fields[key][1].get().strip()
            note = "%d models loaded - pick one from the list" % len(data)
            if current and current not in data:
                note += " (the current '%s' isn't among them)" % current
            self.show_result(key, True, note)
        self.background(key, "Loading the model list ...", lambda: ai.list_models(key, cfg), done)

    def save(self):
        try:
            ai.save_config(self.collect())
        except OSError as e:
            messagebox.showerror("Could not save", str(e), parent=self)
            return
        self.on_saved()
        self.destroy()


# --------------------------------------------------------------------------
# GUI: main window
# --------------------------------------------------------------------------

# ==========================================================================
# Look & feel: window fitted to the screen, wrapping toolbars, icons
# ==========================================================================
#
# Icons are drawn by the program itself (small line drawings rasterised at the
# desktop's scale), so there are no image files to ship, no icon-pack licences
# and no extra dependency. Text labels stay next to them.

def _seg(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    t = 0.0 if dx == dy == 0 else max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return ((px - ax - t * dx) ** 2 + (py - ay - t * dy) ** 2) ** 0.5


def _poly(pts, closed=False):
    pairs = list(zip(pts, pts[1:])) + ([(pts[-1], pts[0])] if closed else [])
    return lambda x, y: min(_seg(x, y, a[0], a[1], b[0], b[1]) for a, b in pairs)


def _ring(cx, cy, r, a0=None, a1=None):
    """Circle outline; with a0/a1 (degrees, 0 = right, clockwise, y down) an arc."""
    import math

    def f(x, y):
        if a0 is not None:
            ang = math.degrees(math.atan2(y - cy, x - cx)) % 360
            inside = (a0 <= ang <= a1) if a0 <= a1 else (ang >= a0 or ang <= a1)
            if not inside:
                ends = [(cx + r * math.cos(math.radians(a)), cy + r * math.sin(math.radians(a))) for a in (a0, a1)]
                return min(((x - ex) ** 2 + (y - ey) ** 2) ** 0.5 for ex, ey in ends)
        return abs(((x - cx) ** 2 + (y - cy) ** 2) ** 0.5 - r)
    return f


def _fill_rect(x0, y0, x1, y1):
    return lambda x, y: 0.0 if (x0 <= x <= x1 and y0 <= y <= y1) else 9.0


def _fill_circle(cx, cy, r):
    return lambda x, y: 0.0 if (x - cx) ** 2 + (y - cy) ** 2 <= r * r else 9.0


def _fill_tri(a, b, c):
    def f(x, y):
        def side(p, q):
            return (x - q[0]) * (p[1] - q[1]) - (p[0] - q[0]) * (y - q[1])
        d1, d2, d3 = side(a, b), side(b, c), side(c, a)
        neg, pos = (d1 < 0) or (d2 < 0) or (d3 < 0), (d1 > 0) or (d2 > 0) or (d3 > 0)
        return 0.0 if not (neg and pos) else 9.0
    return f


def _ellipse(cx, cy, rx, ry):
    return lambda x, y: abs((((x - cx) / rx) ** 2 + ((y - cy) / ry) ** 2) ** 0.5 - 1) * min(rx, ry)


_FOLDER = [(.08, .28), (.38, .28), (.46, .37), (.92, .37), (.92, .84), (.08, .84)]
ICON_SHAPES = {
    "files": [_poly(_FOLDER, True)],
    "apps": [_fill_rect(.12, .12, .43, .43), _fill_rect(.57, .12, .88, .43),
             _fill_rect(.12, .57, .43, .88), _fill_rect(.57, .57, .88, .88)],
    "network": [_ring(.5, .5, .38), _poly([(.12, .5), (.88, .5)]), _ellipse(.5, .5, .17, .38)],
    "security": [_poly([(.5, .08), (.86, .2), (.82, .56), (.5, .92), (.18, .56), (.14, .2)], True),
                 _poly([(.33, .5), (.46, .63), (.68, .38)])],
    "autorun": [_ring(.5, .56, .32, 300, 240), _poly([(.5, .1), (.5, .5)])],
    "refresh": [_ring(.5, .52, .32, 330, 250), _fill_tri((.62, .06), (.86, .2), (.6, .34))],
    "terminal": [_poly([(.08, .16), (.92, .16), (.92, .84), (.08, .84)], True),
                 _poly([(.24, .36), (.40, .5), (.24, .64)]), _poly([(.46, .66), (.72, .66)])],
    "install": [_poly([(.5, .1), (.5, .6)]), _poly([(.3, .42), (.5, .62), (.7, .42)]),
                _poly([(.12, .62), (.12, .88), (.88, .88), (.88, .62)])],
    "trash": [_poly([(.14, .24), (.86, .24)]), _poly([(.38, .24), (.4, .12), (.6, .12), (.62, .24)]),
              _poly([(.24, .24), (.3, .9), (.7, .9), (.76, .24)]), _poly([(.44, .38), (.44, .78)]),
              _poly([(.56, .38), (.56, .78)])],
    "off": [_ring(.5, .5, .36), _poly([(.25, .75), (.75, .25)])],
    "on": [_ring(.5, .5, .36), _poly([(.32, .5), (.45, .63), (.68, .38)])],
    "undo": [_ring(.54, .56, .3, 180, 90), _fill_tri((.06, .56), (.40, .56), (.23, .32))],
    "pause": [_fill_rect(.26, .2, .42, .8), _fill_rect(.58, .2, .74, .8)],
    "search": [_ring(.42, .42, .26), _poly([(.61, .61), (.88, .88)])],
    "ai": [_poly([(.5, .1), (.5, .9)]), _poly([(.1, .5), (.9, .5)]), _poly([(.24, .24), (.76, .76)]),
           _poly([(.76, .24), (.24, .76)])],
    "settings": [_poly([(.1, .25), (.9, .25)]), _poly([(.1, .5), (.9, .5)]), _poly([(.1, .75), (.9, .75)]),
                 _fill_circle(.32, .25, .1), _fill_circle(.66, .5, .1), _fill_circle(.42, .75, .1)],
    "info": [_ring(.5, .5, .38), _fill_circle(.5, .3, .07), _poly([(.5, .45), (.5, .72)])],
    "code": [_poly([(.36, .22), (.12, .5), (.36, .78)]), _poly([(.64, .22), (.88, .5), (.64, .78)])],
    "newfolder": [_poly(_FOLDER, True), _poly([(.5, .48), (.5, .74)]), _poly([(.37, .61), (.63, .61)])],
    "rename": [_poly([(.2, .8), (.24, .62), (.7, .16), (.86, .32), (.4, .78), (.2, .8)])],
    "stop": [_fill_rect(.24, .24, .76, .76)],
    "copy": [_poly([(.3, .3), (.86, .3), (.86, .88), (.3, .88)], True),
             _poly([(.14, .7), (.14, .12), (.7, .12)])],
    "database": [_ellipse(.5, .22, .34, .1), _poly([(.16, .22), (.16, .78)]), _poly([(.84, .22), (.84, .78)]),
                 _ring(.5, .78, .34, 0, 180)],
}

# button label -> icon. Buttons are matched by their text, so a button added
# later with one of these labels gets the same icon automatically.
ICON_FOR_TEXT = {
    "Refresh": "refresh", "Refresh selected": "refresh", "Rescan": "refresh",
    "Refresh this model": "refresh", "Refresh whole database": "refresh", "Check again": "refresh",
    "Scan apps": "refresh", "Load models": "refresh",
    "Open shell": "terminal",
    "Install APK from PC": "install", "Install": "install",
    "Uninstall selected": "trash", "Uninstall": "trash", "Delete selected": "trash", "Delete": "trash",
    "Turn OFF selected": "off", "Turn app OFF": "off", "Switch it off": "off",
    "Turn ON selected": "on", "Turn app ON": "on", "Turn back ON everything I turned off": "on",
    "Restore removed": "undo", "Put it back": "undo", "Allow background again": "undo",
    "Restrict background": "pause",
    "Look up selected online": "search", "Look up all (slow)": "search", "Deep scan": "search",
    "Ask AI about selected": "ai", "Ask AI about this": "ai", "Ask AI again": "ai", "Ask this AI": "ai",
    "Compare AIs": "ai", "Research rooting with AI": "ai",
    "AI settings": "settings", "Security settings": "settings",
    "About": "info", "Info about this device": "info",
    "Run checkup": "security",
    "Inspect code…": "code", "Inspect now": "code", "Inspect again": "code",
    # (Up / Upload / Download / the refresh arrow already show a symbol in their text)
    "New folder": "newfolder", "Rename": "rename", "Stop": "stop", "Copy all": "copy",
    "Database ...": "database",
    "Profiles\u2026": "copy", "Save this phone's profile\u2026": "copy", "Open a profile\u2026": "copy",
    "Apply the ticked changes": "on",
    "Known security issues\u2026": "security", "History\u2026": "database", "Permissions\u2026": "security",
    "Timeline\u2026": "database", "Download / update the bulletin data": "refresh",
    "Search the chip maker's notices": "search",
}
TAB_ICONS = ("files", "apps", "network", "security", "autorun")


def raster_icon(name, size, stroke=0.11, samples=3):
    """size x size boolean mask for an icon (pure Python, no Tk): a pixel is on
    when at least ~45% of its sub-samples fall on the drawing."""
    shapes = ICON_SHAPES[name]
    half = stroke / 2
    rows = []
    for py in range(size):
        row = []
        for px in range(size):
            hits = 0
            for sy in range(samples):
                for sx in range(samples):
                    x = (px + (sx + 0.5) / samples) / size
                    y = (py + (sy + 0.5) / samples) / size
                    if any(f(x, y) <= half for f in shapes):
                        hits += 1
            row.append(hits >= 0.45 * samples * samples)
        rows.append(row)
    return rows


def ui_scale(root):
    """Desktop scale factor (1.0 at 96 dpi) from Tk's own scaling."""
    try:
        return max(1.0, float(root.tk.call("tk", "scaling")) / (96 / 72.0))
    except (tk.TclError, ValueError):
        return 1.0


def make_icon(root, name, size, color):
    img = tk.PhotoImage(master=root, width=size, height=size)
    mask = raster_icon(name, size)
    img.put(" ".join("{%s}" % " ".join(color if on else "#000000" for on in row) for row in mask), to=(0, 0))
    for y, row in enumerate(mask):
        for x, on in enumerate(row):
            if not on:
                img.transparency_set(x, y, True)
    return img


class Icons:
    """All icons for one Tk root, made once, in a normal and a dimmed (disabled) look."""
    NORMAL, DIMMED = "#3c4450", "#a3a8b0"

    def __init__(self, root):
        self.root = root
        self.size = max(16, int(round(16 * ui_scale(root))))
        self.cache = {}

    def get(self, name, dimmed=False):
        key = (name, dimmed)
        if key not in self.cache:
            self.cache[key] = make_icon(self.root, name, self.size, self.DIMMED if dimmed else self.NORMAL)
        return self.cache[key]

    def image_spec(self, name):
        """For ttk widgets: the normal image, and the dimmed one when disabled."""
        return (self.get(name), "disabled", self.get(name, True))


def apply_icons(root, icons, notebook=None):
    """Put icons on the tabs and on every ttk.Button whose label is known. Safe to
    run more than once (buttons that already have an image are left alone)."""
    if notebook is not None:
        for i, tab in enumerate(notebook.tabs()):
            if i < len(TAB_ICONS):
                notebook.tab(tab, image=icons.get(TAB_ICONS[i]), compound="left")

    def walk(w):
        for c in w.winfo_children():
            if isinstance(c, ttk.Button):
                try:
                    text = str(c.cget("text"))
                    if text in ICON_FOR_TEXT and not str(c.cget("image")):
                        c.configure(image=icons.image_spec(ICON_FOR_TEXT[text]), compound="left")
                except tk.TclError:
                    pass
            walk(c)
    walk(root)


# ---- window size from the screen ---------------------------------------------

def initial_window_size(screen_w, screen_h, scale=1.0, want=(1250, 780), least=(860, 480)):
    """(w, h, x, y, min_w, min_h): the wanted size scaled for the desktop, but never
    more than ~92% x 88% of the screen (panels, taskbars); a minimum that shrinks
    on small screens so it can never push controls off-screen; centred."""
    max_w, max_h = int(screen_w * 0.92), int(screen_h * 0.88)
    w = min(int(want[0] * scale), max_w)
    h = min(int(want[1] * scale), max_h)
    min_w = min(int(least[0] * scale), int(screen_w * 0.7), w)
    min_h = min(int(least[1] * scale), int(screen_h * 0.7), h)
    x, y = max(0, (screen_w - w) // 2), max(0, (screen_h - h) // 3)
    return w, h, x, y, min_w, min_h


# ---- which monitor: with two screens, winfo_screenwidth() is BOTH of them -----

_MONITORS = None
XRANDR_RE = re.compile(r"^\s*\d+:\s+\S+\s+(\d+)/\d+x(\d+)/\d+([+-]\d+)([+-]\d+)")


def parse_xrandr_monitors(text):
    """'xrandr --listactivemonitors' -> [(x, y, w, h)]."""
    out = []
    for line in (text or "").splitlines():
        m = XRANDR_RE.match(line)
        if m:
            w, h, x, y = (int(g) for g in m.groups())
            if w > 0 and h > 0:
                out.append((x, y, w, h))
    return out


def _windows_monitors():
    import ctypes
    from ctypes import wintypes
    found = []

    class MONITORINFO(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("rcMonitor", wintypes.RECT), ("rcWork", wintypes.RECT),
                    ("dwFlags", wintypes.DWORD)]

    def cb(hmon, hdc, rect, data):
        mi = MONITORINFO()
        mi.cbSize = ctypes.sizeof(MONITORINFO)
        if ctypes.windll.user32.GetMonitorInfoW(hmon, ctypes.byref(mi)):
            r = mi.rcWork                                  # minus the taskbar
            found.append((r.left, r.top, r.right - r.left, r.bottom - r.top))
        return 1
    proto = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_double)
    ctypes.windll.user32.EnumDisplayMonitors(None, None, proto(cb), 0)
    return found


def list_monitors():
    """The physical monitors (x, y, w, h), or [] when they can't be listed. Cached."""
    global _MONITORS
    if _MONITORS is None:
        mons = []
        try:
            if sys.platform.startswith("win"):
                mons = _windows_monitors()
            elif os.environ.get("DISPLAY") and shutil.which("xrandr"):
                r = subprocess.run(["xrandr", "--listactivemonitors"], capture_output=True, text=True, timeout=3)
                mons = parse_xrandr_monitors(r.stdout) if r.returncode == 0 else []
        except Exception:
            mons = []
        _MONITORS = mons
    return _MONITORS


def pick_monitor(mons, px, py, screen_w, screen_h):
    """The monitor containing point (px, py); the nearest one if none does. Without a
    monitor list, a very wide 'screen' is treated as side-by-side monitors of 16:9."""
    if mons:
        inside = [m for m in mons if m[0] <= px < m[0] + m[2] and m[1] <= py < m[1] + m[3]]
        if inside:
            return inside[0]
        return min(mons, key=lambda m: (max(m[0] - px, 0, px - m[0] - m[2]) ** 2 +
                                        max(m[1] - py, 0, py - m[1] - m[3]) ** 2))
    n = max(1, round(screen_w / (screen_h * 16 / 9))) if screen_h else 1
    if n > 1 and screen_w / screen_h > 2.2:
        part = screen_w // n
        i = min(n - 1, max(0, px // part))
        return (i * part, 0, part, screen_h)
    return (0, 0, screen_w, screen_h)


def monitor_for(widget, px=None, py=None):
    """(x, y, w, h) of the monitor at a point (default: the middle of the widget)."""
    try:
        if px is None:
            widget.update_idletasks()
            px = widget.winfo_rootx() + widget.winfo_width() // 2
            py = widget.winfo_rooty() + widget.winfo_height() // 2
        return pick_monitor(list_monitors(), px, py, widget.winfo_screenwidth(), widget.winfo_screenheight())
    except tk.TclError:
        return (0, 0, 1024, 768)


def fit_rect(req_w, req_h, mon, anchor=None, max_frac=(0.92, 0.88)):
    """(w, h, x, y, max_w, max_h): a window of the requested size shrunk to fit the
    monitor, centred on `anchor` (x, y) when given, always fully on that monitor."""
    mx, my, mw, mh = mon
    max_w, max_h = int(mw * max_frac[0]), int(mh * max_frac[1])
    w, h = max(200, min(req_w, max_w)), max(150, min(req_h, max_h))
    ax, ay = anchor if anchor else (mx + mw // 2, my + mh // 3)
    x = min(max(mx, ax - w // 2), mx + mw - w)
    y = min(max(my, ay - h // 3), my + mh - h)
    return w, h, x, y, mw, mh


def fit_toplevel(win, root):
    """Once, when a window first opens: never wider or taller than the monitor the main
    window is on, placed fully on it, and not stretchable past it. Long wrapping labels
    get a sane width first so they can't request one screen-wide line."""
    if getattr(win, "_fitted", False) or not isinstance(win, tk.Toplevel):
        return
    win._fitted = True
    try:
        mon = monitor_for(root)
        limit = int(mon[2] * 0.92)

        def tame(w):
            for c in w.winfo_children():
                if isinstance(c, (ttk.Label, tk.Label)):
                    try:
                        if not int(str(c.cget("wraplength") or 0)) and len(str(c.cget("text"))) > 80:
                            c.configure(wraplength=min(limit - 60, 900))
                    except (tk.TclError, ValueError):
                        pass
                tame(c)
        tame(win)
        win.update_idletasks()
        req_w = max(win.winfo_reqwidth(), win.winfo_width() if win.winfo_ismapped() else 0)
        req_h = max(win.winfo_reqheight(), win.winfo_height() if win.winfo_ismapped() else 0)
        anchor = (root.winfo_rootx() + root.winfo_width() // 2, root.winfo_rooty() + root.winfo_height() // 3)
        w, h, x, y, max_w, max_h = fit_rect(req_w, req_h, mon, anchor)
        try:
            mn_w, mn_h = (int(v) for v in win.minsize())
            win.minsize(min(mn_w, w), min(mn_h, h))      # a minimum can never push it past the screen
        except (tk.TclError, ValueError):
            pass
        win.maxsize(max_w, max_h)
        win.geometry("%dx%d+%d+%d" % (w, h, x, y))
    except tk.TclError:
        pass


# ---- toolbars that wrap, status lines that wrap ------------------------------

class WrapRow:
    """Makes a packed row of buttons flow onto more lines when the window is too
    narrow, instead of pushing buttons off the right edge. Widgets keep their
    order; right-packed ones go last."""

    def __init__(self, frame):
        self.frame = frame
        self.items = []
        for w in frame.pack_slaves():
            info = w.pack_info()
            self.items.append((w, info.get("padx", 0), info.get("side") == "right", info.get("fill", "none")))
            w.pack_forget()
        self.items = [i for i in self.items if not i[2]] + [i for i in self.items if i[2]]
        self.rows, self.width = [], None
        frame.bind("<Configure>", self._on_configure, add="+")
        self.layout(frame.winfo_width() if frame.winfo_width() > 1 else 10 ** 6)

    def _on_configure(self, event):
        if event.width > 1 and event.width != self.width:
            self.layout(event.width)

    @staticmethod
    def _pad(p):
        if isinstance(p, (tuple, list)):
            return sum(int(float(str(x))) for x in p)
        try:
            return 2 * int(float(str(p)))
        except ValueError:
            return 0

    def layout(self, width):
        self.width = width
        lines, cur, used = [], [], 0
        for item in self.items:
            need = item[0].winfo_reqwidth() + self._pad(item[1]) + 4
            if cur and used + need > width:
                lines.append(cur)
                cur, used = [], 0
            cur.append(item)
            used += need
        if cur:
            lines.append(cur)
        while len(self.rows) < len(lines):
            self.rows.append(ttk.Frame(self.frame))
        for w, *_ in self.items:
            w.pack_forget()
        for i, row in enumerate(self.rows):
            if i < len(lines):
                row.pack(fill="x", side="top")
            else:
                row.pack_forget()
        for row, line in zip(self.rows, lines):
            for w, padx, _, fill in line:
                w.pack(in_=row, side="left", padx=padx, pady=1, fill=fill)
                w.lift(row)       # row frames are created after the buttons: raise or they'd be hidden

    def line_count(self):
        return sum(1 for r in self.rows if r.winfo_manager())


def wrap_label(label, margin=12):
    """Let a status line wrap at the window edge instead of being cut off."""
    label.bind("<Configure>", lambda e: label.configure(wraplength=max(100, e.width - margin)), add="+")


def protect_bottom_bars(root):
    """Controls packed BELOW a stretching widget (a list, a text pane) are squeezed
    out of a short window, because pack serves widgets in order and the stretching
    one asks for its full height first. Re-pack those trailing controls from the
    bottom up, ahead of the stretching widget, so the list shrinks instead and the
    buttons always stay visible. Same look on a big screen."""
    moved = []

    def walk(w):
        kids = w.pack_slaves()
        for i, k in enumerate(kids):
            info = k.pack_info()
            if str(info.get("expand")) in ("1", "True", "true") and info.get("side", "top") == "top":
                tail = [t for t in kids[i + 1:] if t.pack_info().get("side", "top") == "top"
                        and str(t.pack_info().get("expand")) not in ("1", "True", "true")]
                for t in reversed(tail):
                    opts = {key: v for key, v in t.pack_info().items() if key in ("fill", "padx", "pady", "ipadx",
                                                                                  "ipady", "anchor")}
                    t.pack_configure(side="bottom", before=k, **opts)
                    moved.append(t)
                break
        for c in w.winfo_children():
            walk(c)
    walk(root)
    return moved


def make_responsive(root):
    """Find packed button rows and full-width status labels everywhere, and make
    them wrap. A button row = a frame packed full-width whose children are all
    packed left/right, with at least three of them, and no big content widgets."""
    rows, labels = [], []

    def walk(w):
        for c in w.winfo_children():
            if isinstance(c, (ttk.Frame, tk.Frame)) and not isinstance(c, ttk.LabelFrame):
                kids = c.pack_slaves()
                try:
                    fill = c.pack_info().get("fill") if c.winfo_manager() == "pack" else None
                except tk.TclError:
                    fill = None
                if fill in ("x", "both") and len(kids) >= 3 and all(
                        k.pack_info().get("side") in ("left", "right") for k in kids) and \
                        not any(isinstance(k, (ttk.Treeview, tk.Text, ttk.PanedWindow, ttk.Notebook,
                                               ttk.Frame, tk.Frame, ttk.Progressbar)) for k in kids):
                    rows.append(c)
            elif isinstance(c, ttk.Label) and c.winfo_manager() == "pack":
                try:
                    if c.pack_info().get("fill") in ("x", "both"):
                        labels.append(c)
                except tk.TclError:
                    pass
            walk(c)
    walk(root)
    wrappers = [WrapRow(f) for f in rows]
    for lab in labels:
        wrap_label(lab)
    protect_bottom_bars(root)
    return wrappers, labels


class App:
    def __init__(self, root, args):
        self.root = root
        self.args = args
        self.devices = []
        self.transferring = False
        self.cancel = threading.Event()
        self.q = queue.Queue()
        self.show_hidden = tk.BooleanVar(value=False)

        root.title("ADB Manager")
        # size from THIS screen: never larger than the desktop, minimum shrinks on
        # small screens, everything scaled with the desktop's DPI
        try:
            px, py = root.winfo_pointerxy()               # the screen the user is looking at
        except tk.TclError:
            px, py = 0, 0
        mon = monitor_for(root, px, py)                   # ONE monitor - not both screens together
        w, h, x, y, mw, mh = initial_window_size(mon[2], mon[3], ui_scale(root))
        root.geometry("%dx%d+%d+%d" % (w, h, x + mon[0], y + mon[1]))
        root.minsize(mw, mh)
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
        # tree rows follow the font size (large fonts / HiDPI) instead of a fixed 22 px
        style.configure("Treeview", rowheight=max(22, tkfont.nametofont("TkDefaultFont").metrics("linespace") + 6))

        # --- device bar
        top = ttk.Frame(root, padding=(6, 6, 6, 0))
        top.pack(fill="x")
        ttk.Label(top, text="Device:").pack(side="left")
        self.dev_var = tk.StringVar()
        self.dev_combo = ttk.Combobox(top, textvariable=self.dev_var, state="readonly", width=55)
        self.dev_combo.pack(side="left", padx=4)
        self.dev_combo.bind("<<ComboboxSelected>>", self.on_device_selected)
        ttk.Button(top, text="Rescan", command=self.scan_devices).pack(side="left")
        ttk.Button(top, text="About", command=self.show_about).pack(side="right")

        # --- tabs
        self.nb = ttk.Notebook(root)
        self.nb.pack(fill="both", expand=True, padx=4, pady=(4, 0))

        files_tab = ttk.Frame(self.nb)
        self.nb.add(files_tab, text="  Files  ")
        frow = ttk.Frame(files_tab, padding=(4, 4, 4, 0))
        frow.pack(fill="x")
        ttk.Checkbutton(frow, text="Show hidden files", variable=self.show_hidden,
                        command=self.repopulate).pack(side="right")

        body = ttk.Frame(files_tab, padding=4)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(2, weight=1)
        body.rowconfigure(0, weight=1)

        local_start = os.path.expanduser(args.local)
        self.left = FilePane(body, self, LocalFS(), local_start)
        self.left.grid(row=0, column=0, sticky="nsew")

        mid = ttk.Frame(body, padding=(4, 0))
        mid.grid(row=0, column=1, sticky="ns")
        ttk.Frame(mid).pack(expand=True)
        self.btn_up = ttk.Button(mid, text="Upload \u2192", width=12,
                                 command=lambda: self.copy(self.left, self.right))
        self.btn_up.pack(pady=4)
        self.btn_down = ttk.Button(mid, text="\u2190 Download", width=12,
                                   command=lambda: self.copy(self.right, self.left))
        self.btn_down.pack(pady=4)
        ttk.Separator(mid).pack(fill="x", pady=10)
        ttk.Button(mid, text="New folder", width=12, command=self.mkdir).pack(pady=2)
        ttk.Button(mid, text="Rename", width=12, command=self.rename).pack(pady=2)
        ttk.Button(mid, text="Delete", width=12, command=self.delete).pack(pady=2)
        ttk.Label(mid, text="(acts on the\nhighlighted side)", justify="center",
                  foreground="#777777").pack(pady=2)
        ttk.Frame(mid).pack(expand=True)

        self.right = FilePane(body, self, None, args.remote)
        self.right.grid(row=0, column=2, sticky="nsew")
        self.active = self.left

        self.apps_tab = AppsTab(self.nb, self)
        self.nb.add(self.apps_tab, text="  Apps  ")
        self.net_tab = NetworkTab(self.nb, self)
        self.nb.add(self.net_tab, text="  Network  ")
        self.sec_tab = SecurityTab(self.nb, self)
        self.nb.add(self.sec_tab, text="  Security  ")
        self.autorun_tab = AutorunTab(self.nb, self)
        root.after(800, self.apps_tab._report_store_problems)   # all stores exist now
        self.nb.add(self.autorun_tab, text="  Autorun  ")
        self.nb.bind("<<NotebookTabChanged>>", self.on_tab_changed)

        # --- status bar
        bottom = ttk.Frame(root, padding=(6, 2, 6, 6))
        bottom.pack(fill="x", side="bottom", before=self.nb)   # keeps its place when the window is small
        self.status = ttk.Label(bottom, text="", anchor="w")
        self.status.pack(side="left", fill="x", expand=True)
        self.cancel_btn = ttk.Button(bottom, text="Cancel", command=self.cancel.set)
        self.progress = ttk.Progressbar(bottom, length=260, maximum=100)

        # --- keys (file-manager keys only act on the Files tab, and not while
        #     typing in a text box)
        root.bind("<F5>", self.files_key(self.copy_from_active))
        root.bind("<F7>", self.files_key(self.mkdir))
        root.bind("<F2>", self.files_key(self.rename))
        root.bind("<Delete>", self.files_key(self.delete))
        root.bind("<Control-h>", self.files_key(
            lambda: (self.show_hidden.set(not self.show_hidden.get()), self.repopulate())))
        root.bind("<Control-r>", self.files_key(lambda: self.active.refresh()))
        root.protocol("WM_DELETE_WINDOW", self.on_close)

        # --- look & feel: icons (tabs, buttons, and windows opened later) and
        #     toolbars / status lines that wrap instead of disappearing
        self.icons = Icons(root)
        apply_icons(root, self.icons, self.nb)
        root.bind_class("Toplevel", "<Map>", lambda e: apply_icons(e.widget, self.icons)
                        if isinstance(e.widget, tk.Toplevel) else None, add="+")
        root.bind_class("Toplevel", "<Map>", lambda e: fit_toplevel(e.widget, root)
                        if isinstance(e.widget, tk.Toplevel) else None, add="+")
        self.wrappers, _ = make_responsive(root)

        self.left.load(local_start) or self.left.load("~")
        self.set_active(self.left)
        root.after(100, self.scan_devices)
        root.after(100, self.poll_queue)

    def install_apks(self, paths):
        """Files tab -> Apps tab installer."""
        self.apps_tab.install_files(paths)

    def files_tab_active(self):
        try:
            return self.nb.index(self.nb.select()) == 0
        except tk.TclError:
            return False

    def files_key(self, fn):
        def handler(event):
            if not self.files_tab_active():
                return
            if isinstance(event.widget, (tk.Entry, ttk.Entry, tk.Text)):
                return
            fn()
            return "break"
        return handler

    def on_tab_changed(self, event=None):
        try:
            idx = self.nb.index(self.nb.select())
        except tk.TclError:
            return
        if idx == 1:
            self.apps_tab.on_shown()
        elif idx == 2:
            self.net_tab.on_shown()
        elif idx == 3:
            self.sec_tab.on_shown()
        elif idx == 4:
            self.autorun_tab.on_shown()

    # ---- status ----------------------------------------------------------

    def info(self, msg):
        self.status.configure(text=msg, foreground="")

    def error(self, msg):
        self.status.configure(text=msg, foreground="#c62828")

    def busy(self, on):
        self.root.configure(cursor="watch" if on else "")
        self.root.update_idletasks()

    def set_active(self, pane):
        self.active = pane
        for p in (self.left, self.right):
            p.title.configure(foreground="#1f5fbf" if p is pane else "#555555")

    def repopulate(self):
        for p in (self.left, self.right):
            if p.fs:
                p.populate([e.name for e in p.selected()])

    # ---- devices ---------------------------------------------------------

    def scan_devices(self):
        self.info("Looking for devices ...")
        self.busy(True)
        try:
            self.devices = list_devices()
        except AdbError as e:
            self.devices = []
            self.busy(False)
            self.error(str(e))
            return
        self.busy(False)
        labels = []
        for serial, state, model in self.devices:
            note = {"device": "", "unauthorized": "  - accept the prompt on the phone, then Rescan",
                    "offline": "  - offline"}.get(state, "  - " + state)
            labels.append("%s  %s%s" % (model.replace("_", " ") or "Android", serial, note))
        self.dev_combo["values"] = labels
        ready = [i for i, d in enumerate(self.devices) if d[1] == "device"]

        want = self.args.serial or (self.right.fs.serial if self.right.fs else None)
        idx = next((i for i, d in enumerate(self.devices) if d[0] == want), None)
        if idx is None and len(ready) == 1:
            idx = ready[0]
        if not self.devices:
            self.dev_var.set("")
            self.error("No device found. Plug it in with USB debugging enabled, then Rescan.")
        elif idx is not None:
            self.dev_combo.current(idx)
            if not self.right.fs or self.right.fs.serial != self.devices[idx][0]:
                self.connect(idx)
            else:
                self.info("Device list updated")
        else:
            self.dev_var.set("")
            self.info("%d device(s) found - pick one from the list" % len(self.devices))

    def on_device_selected(self, event=None):
        idx = self.dev_combo.current()
        if idx >= 0:
            self.connect(idx)

    def connect(self, idx):
        serial, state, model = self.devices[idx]
        if state != "device":
            self.error("%s is %s - it can't be used yet" % (serial, state))
            return
        fs = RemoteFS(serial, model)
        self.right.fs = fs
        self.right.update_title()
        self.apps_tab.set_device(serial)
        self.net_tab.set_device(serial)
        self.sec_tab.set_device(serial)
        self.autorun_tab.set_device(serial)
        self.on_tab_changed()
        for start in (self.args.remote, "/sdcard", "/storage/emulated/0", "/"):
            if self.right.load(start):
                self.info("Connected to %s" % serial)
                return
        self.right.clear()
        self.error("Connected to %s but cannot list any folder" % serial)

    # ---- actions ---------------------------------------------------------

    def other(self, pane):
        return self.right if pane is self.left else self.left

    def copy_from_active(self):
        self.copy(self.active, self.other(self.active))

    def copy(self, src, dst):
        if self.transferring:
            return
        if not self.right.fs:
            self.error("No device connected")
            return
        items = src.selected()
        if not items:
            self.info("Select one or more items in the %s pane first"
                      % ("left" if src is self.left else "right"))
            return
        clash = [e.name for e in items if e.name in dst.names()]
        if clash:
            what = clash[0] if len(clash) == 1 else "%d of the items" % len(clash)
            ans = messagebox.askyesnocancel(
                "Already there",
                "%s already exist(s) in the destination.\n\n"
                "Yes = overwrite\nNo = skip those\nCancel = do nothing" % what,
                parent=self.root)
            if ans is None:
                return
            if ans is False:
                items = [e for e in items if e.name not in clash]
                if not items:
                    self.info("Nothing to copy")
                    return

        upload = src.fs.kind == "local"
        serial = self.right.fs.serial
        jobs = []
        for e in items:
            s = src.fs.join(src.path, e.name)
            # folders: target is the parent folder (adb creates <name> inside it)
            d = dst.path if e.is_dir else dst.fs.join(dst.path, e.name)
            cmd = [ADB, "-s", serial, "push" if upload else "pull", s, d]
            jobs.append((e.name, cmd))

        self.transferring = True
        self.cancel.clear()
        self.btn_up.state(["disabled"])
        self.btn_down.state(["disabled"])
        self.progress["value"] = 0
        self.cancel_btn.pack(side="right", padx=(6, 0))
        self.progress.pack(side="right")
        t = threading.Thread(target=self.worker, args=(jobs, upload, dst,
                                                       [e.name for e in items]), daemon=True)
        t.start()

    def worker(self, jobs, upload, dst, names):
        verb = "Uploading" if upload else "Downloading"
        n = len(jobs)
        ok, failed, last = 0, [], ""
        t0 = time.time()
        for i, (name, cmd) in enumerate(jobs):
            if self.cancel.is_set():
                break
            self.q.put(("status", "%s %d/%d: %s" % (verb, i + 1, n, name), i * 100.0 / n))

            def on_pct(p, i=i, name=name):
                self.q.put(("status", "%s %d/%d: %s  (%d%%)" % (verb, i + 1, n, name, p),
                            (i + p / 100.0) * 100.0 / n))

            rc, msg = adb_transfer(cmd, on_pct, self.cancel)
            if rc == 0:
                ok += 1
                last = msg
            elif rc == -1:
                failed.append("%s: cancelled (a partial copy may be left behind)" % name)
                break
            else:
                failed.append("%s: %s" % (name, msg or "adb exit code %d" % rc))
        self.q.put(("done", ok, failed, last, time.time() - t0, dst, names))

    def poll_queue(self):
        try:
            while True:
                msg = self.q.get_nowait()
                if msg[0] == "status":
                    self.info(msg[1])
                    self.progress["value"] = msg[2]
                elif msg[0] == "done":
                    self.transfer_done(*msg[1:])
                elif msg[0] == "call":
                    try:
                        msg[1](*msg[2:])
                    except Exception as e:  # keep the GUI alive whatever happens
                        self.error("Internal error: %s" % e)
        except queue.Empty:
            pass
        self.root.after(100, self.poll_queue)

    def transfer_done(self, ok, failed, last, secs, dst, names):
        self.transferring = False
        self.btn_up.state(["!disabled"])
        self.btn_down.state(["!disabled"])
        self.progress["value"] = 100 if not failed else self.progress["value"]
        self.cancel_btn.pack_forget()
        self.progress.pack_forget()
        dst.load(select=names)
        if failed:
            self.error("%d copied, %d failed - %s" % (ok, len(failed), failed[0]))
            if len(failed) > 1:
                messagebox.showerror("Some copies failed", "\n".join(failed), parent=self.root)
        elif ok == 1:
            self.info("Done in %.1fs - %s" % (secs, last))
        else:
            self.info("Done: %d items copied in %.1fs" % (ok, secs))

    def mkdir(self):
        pane = self.active
        if not pane.fs or self.transferring:
            return
        where = "on the device" if pane.fs.kind == "remote" else "on this computer"
        name = simpledialog.askstring("New folder", "Folder name (%s, in %s):"
                                      % (where, pane.path), parent=self.root)
        if not name:
            return
        try:
            pane.fs.mkdir(pane.fs.join(pane.path, name))
        except (AdbError, OSError) as e:
            self.error("Could not create folder: %s" % e)
            return
        pane.load(select=name)
        self.info("Created %s" % name)

    def rename(self):
        pane = self.active
        if not pane.fs or self.transferring:
            return
        sel = pane.selected()
        if len(sel) != 1:
            self.info("Select exactly one item to rename")
            return
        old = sel[0].name
        new = simpledialog.askstring("Rename", "New name:", initialvalue=old, parent=self.root)
        if not new or new == old:
            return
        try:
            pane.fs.rename(pane.fs.join(pane.path, old), pane.fs.join(pane.path, new))
        except (AdbError, OSError) as e:
            self.error("Could not rename: %s" % e)
            return
        pane.load(select=new)
        self.info("Renamed to %s" % new)

    def delete(self):
        pane = self.active
        if not pane.fs or self.transferring:
            return
        sel = pane.selected()
        if not sel:
            return
        what = sel[0].name if len(sel) == 1 else "%d items" % len(sel)
        where = "from the DEVICE" if pane.fs.kind == "remote" else "from this computer"
        if not messagebox.askyesno("Delete", "Permanently delete %s %s?\n\n"
                                   "Folders are deleted with everything inside."
                                   % (what, where), icon="warning", parent=self.root):
            return
        errors = []
        self.busy(True)
        for e in sel:
            try:
                pane.fs.delete(pane.fs.join(pane.path, e.name))
            except (AdbError, OSError) as ex:
                errors.append("%s: %s" % (e.name, ex))
        self.busy(False)
        pane.load()
        if errors:
            self.error("Delete failed - " + errors[0])
        else:
            self.info("Deleted %s" % what)

    def show_diagnostics(self):
        """Collect the diagnostics in the background, then show them - the window IS
        the preview of exactly what gets copied."""
        win = tk.Toplevel(self.root)
        win.title("Diagnostics for a bug report")
        win.transient(self.root)
        self._diag_win = win
        frm = ttk.Frame(win, padding=10)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="This is everything that will be copied. No serial number, no app names, nothing "
                            "personal.", wraplength=520, justify="left").pack(anchor="w")
        txt = tk.Text(frm, width=80, height=18, wrap="word")
        txt.insert("1.0", "Collecting ...")
        txt.configure(state="disabled")
        btns = ttk.Frame(frm)
        btns.pack(side="bottom", fill="x", pady=(8, 0))
        txt.pack(fill="both", expand=True, pady=(6, 0))
        ttk.Button(btns, text="Close", command=win.destroy).pack(side="right")
        copy_btn = ttk.Button(btns, text="Copy all", state="disabled")
        copy_btn.pack(side="right", padx=6)

        def copy():
            self.root.clipboard_clear()
            self.root.clipboard_append(txt.get("1.0", "end-1c"))
            self.info("Diagnostics copied - paste them into your bug report")

        def show(text):
            if not win.winfo_exists():
                return
            txt.configure(state="normal")
            txt.delete("1.0", "end")
            txt.insert("1.0", text)
            txt.configure(state="disabled")
            copy_btn.configure(state="normal", command=copy)

        serial = self.apps_tab.serial          # the connected phone, or None

        def work():
            try:
                text = diagnostics_text(serial)
            except Exception as e:                      # always report back
                text = "Couldn't collect the diagnostics: %s: %s" % (type(e).__name__, e)
            self.q.put(("call", show, text))
        threading.Thread(target=work, daemon=True).start()

    def show_about(self):
        win = getattr(self, "_about_win", None)
        if win is not None and win.winfo_exists():
            win.lift()
            return
        self._about_win = win = tk.Toplevel(self.root)
        win.title("About ADB Manager")
        win.transient(self.root)
        win.resizable(False, False)
        frm = ttk.Frame(win, padding=16)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="ADB Manager", font=("TkDefaultFont", 14, "bold")).pack(anchor="w")
        ttk.Label(frm, text="Android device manager: files, apps, network and security, over ADB.",
                  foreground="#555555").pack(anchor="w", pady=(0, 10))
        # credits - kept identical to the "Credits" section of README.md
        sections = [
            ("Project concept & vision",
             [("Pedro", "https://github.com/peterpt", " - original idea, product direction and requirements")]),
            ("Code implementation",
             [("Claude Opus 5.5 (Anthropic)", None, " - primary code builder and implementation")]),
            ("Architecture & security review",
             [("ChatGPT, GPT-6 (OpenAI)", None,
               " - architecture guidance, independent code review and security analysis"),
              ("Gemini 3.1 Pro (Google)", None, " - second independent code reviewer")]),
            ("Testing",
             [("Automated test suite", None, " (written by Claude, reviewed by ChatGPT and Gemini), with "
                                             "results documented per development round"),
              ("Real-device testing", None, " - Pedro")]),
        ]
        for title, lines in sections:
            ttk.Label(frm, text=title, font=("TkDefaultFont", 10, "bold")).pack(anchor="w", pady=(6, 0))
            for name, url, rest in lines:
                row = ttk.Frame(frm)
                row.pack(anchor="w", fill="x")
                if url:
                    link = tk.Label(row, text=name, foreground="#1f5fbf", cursor="hand2")
                    f = tkfont.Font(link, link.cget("font"))
                    f.configure(underline=True)
                    link.configure(font=f)
                    link.pack(side="left")
                    link.bind("<Button-1>", lambda e, u=url: self._open_url(u))
                    ttk.Label(row, text=" (%s)" % url, foreground="#555555").pack(side="left")
                else:
                    ttk.Label(row, text=name).pack(side="left")
                ttk.Label(row, text=rest, wraplength=440, justify="left").pack(side="left")
        ttk.Separator(frm).pack(fill="x", pady=12)
        ttk.Label(frm, text="Gemini (Google) was deliberately excluded from package research: "
                  "because Android and most of the inspected packages are Google's own, a Google "
                  "model would have a structural conflict of interest assessing them. Reviewing this "
                  "app's code doesn't involve judging Google's packages.",
                  foreground="#555555", wraplength=460, justify="left").pack(anchor="w")
        ttk.Label(frm, text="Built through human creativity and collaboration between AI systems. Technology "
                  "is most powerful when used responsibly, transparently and for the benefit of people.",
                  font=("TkDefaultFont", 9, "italic"), wraplength=460, justify="left").pack(anchor="w",
                                                                                         pady=(10, 0))
        ttk.Button(frm, text="Close", command=win.destroy).pack(side="right", pady=(12, 0))
        ttk.Button(frm, text="Copy diagnostics", command=self.show_diagnostics).pack(side="right", padx=6,
                                                                                    pady=(12, 0))

    def _open_url(self, url):
        try:
            safe_open_url(url)
        except Exception:
            pass

    def on_close(self):
        if self.transferring:
            if not messagebox.askyesno("Transfer running",
                                       "A transfer is still running. Cancel it and quit?",
                                       parent=self.root):
                return
            self.cancel.set()
        if self.apps_tab.job:
            if not messagebox.askyesno("Still working",
                                       "The Apps tab is still %s. Quit anyway?" % self.apps_tab.job,
                                       parent=self.root):
                return
            self.apps_tab.stop.set()
        if self.sec_tab.busy:
            if not messagebox.askyesno("Still working", "The Security tab is still running a %s. Quit anyway?"
                                       % self.sec_tab.busy, parent=self.root):
                return
            self.sec_tab.stop.set()
        self.root.destroy()


# ==========================================================================
# Device capture (developer tool) and Copy diagnostics
# ==========================================================================
#
#   python3 adb_manager.py --capture [-s SERIAL]
#
# Runs a FIXED list of READ-ONLY commands on the phone, sanitises the answers
# before anything touches the disk, and writes one JSON file (0600, in a 0700
# folder) under ~/.config/adb_manager/captures/. The file is plain readable JSON:
# opening it is the preview before sharing it. It feeds two things:
#   - the compatibility record (which commands this phone accepts, and what the
#     output actually shows - "accepted" is not "observed");
#   - real-output parser tests (app_tests.py loads captures put in fixtures/).
#
# Privacy boundaries:
#   - the serial is never stored, and is scrubbed from every captured string;
#   - only allowlisted system properties are kept;
#   - packages that Package Manager doesn't confirm as system packages (third-party
#     or unknown) become stable placeholders user.app.N everywhere: names,
#     component references, paths, resolver output;
#   - user names become user<N>; e-mail / phone / MAC-like strings are masked;
#   - no accounts, IMEI, Wi-Fi, contacts, SMS or network connections are read;
#   - package dumps are trimmed to the few lines the parsers need.

CAPTURE_SCHEMA = "adbm-capture"
CAPTURE_VERSION = 1
CAPTURE_DIR = os.path.join(CONFIG_DIR, "captures")
CAPTURE_PROBE_CAP = 512 * 1024          # bytes kept per probe (more is read only for big dumps)
CAPTURE_TOTAL_CAP = 8 * 1024 * 1024     # all probes together
CAPTURE_ERR_CAP = 2048
CAPTURE_TIMEOUT = 30
CAPTURE_SAMPLE_SYSTEM = 8
CAPTURE_SAMPLE_USER = 3
CAPTURE_PROPS = (
    "ro.build.version.release", "ro.build.version.sdk", "ro.build.version.security_patch",
    "ro.build.version.incremental", "ro.build.id", "ro.build.type", "ro.build.fingerprint",
    "ro.build.characteristics", "ro.product.manufacturer", "ro.product.brand", "ro.product.model",
    "ro.product.device", "ro.product.cpu.abi", "ro.boot.verifiedbootstate", "ro.boot.flash.locked",
    "ro.boot.vbmeta.device_state", "ro.boot.slot_suffix", "ro.build.ab_update",
    "ro.boot.dynamic_partitions", "persist.sys.locale", "ro.product.locale", "ro.miui.ui.version.name",
    "ro.build.version.emui", "ro.config.low_ram")
DIAG_PROPS = ("ro.build.version.release", "ro.build.version.sdk", "ro.product.manufacturer",
              "ro.product.model", "ro.build.characteristics", "ro.config.low_ram")
QUERY_FORMS = (("user+flags", True, True), ("user", True, False), ("flags", False, True), ("plain", False, False))


def capture_run(serial, cmd, cap=CAPTURE_PROBE_CAP, timeout=CAPTURE_TIMEOUT):
    """Run one read-only shell command with hard bounds: output is read in chunks
    and the process is killed once `cap` bytes have arrived or `timeout` passes, so
    memory stays bounded however much the phone sends. Returns
    {"rc", "out", "err", "truncated", "timed_out", "ms"}."""
    import selectors
    t0 = time.time()
    res = {"rc": None, "out": "", "err": "", "truncated": False, "err_truncated": False, "timed_out": False,
           "ms": 0}
    try:
        p = subprocess.Popen([ADB, "-s", serial, "shell", cmd], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, start_new_session=True)
    except OSError as e:
        res["err"] = "couldn't run adb: %s" % (e.strerror or e)
        return res
    out, err = bytearray(), bytearray()
    sel = selectors.DefaultSelector()
    sel.register(p.stdout, selectors.EVENT_READ, out)
    sel.register(p.stderr, selectors.EVENT_READ, err)
    open_streams = 2
    try:
        while open_streams:
            left = timeout - (time.time() - t0)
            if left <= 0:
                res["timed_out"] = True
                break
            for key, _ in sel.select(timeout=min(left, 1.0)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    sel.unregister(key.fileobj)
                    open_streams -= 1
                    continue
                buf = key.data
                room = (cap if buf is out else CAPTURE_ERR_CAP) - len(buf)
                buf += chunk[:max(0, room)]
                if len(chunk) > room:
                    res["truncated" if buf is out else "err_truncated"] = True
            if res["truncated"]:
                break
    finally:
        sel.close()
        if p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except OSError:
                pass
        p.wait()
        p.stdout.close()
        p.stderr.close()
    res["rc"] = None if (res["timed_out"] or res["truncated"]) else p.returncode
    res["out"] = out.decode("utf-8", "replace")
    res["err"] = err.decode("utf-8", "replace")[:CAPTURE_ERR_CAP]
    res["ms"] = int((time.time() - t0) * 1000)
    return res


def filter_props(text, allow):
    keep = []
    for line in text.splitlines():
        m = re.match(r"^\[([^\]]+)\]: \[(.*)\]$", line.strip())
        if m and m.group(1) in allow:
            keep.append(line.strip())
    return "\n".join(keep) + ("\n" if keep else "")


def props_dict(text):
    return {m.group(1): m.group(2) for m in (re.match(r"^\[([^\]]+)\]: \[(.*)\]$", l.strip())
                                             for l in text.splitlines()) if m}


def trim_package_dump(text):
    """Keep only what the parsers use from 'dumpsys package <pkg>': the package
    header, its key=value identity lines, and each 'User N:' line with its
    disabled/enabled component lists. Permissions, timestamps and the rest go."""
    keep, in_user, in_list, user_indent = [], False, False, 0
    key_re = re.compile(r"^\s+(versionCode|versionName|targetSdk|minSdk|flags|pkgFlags|codePath|"
                        r"userId|appId)=")
    for line in text.splitlines():
        s = line.strip()
        ind = len(line) - len(line.lstrip())
        if PKG_HDR_RE.match(line) or line.startswith("Packages:"):
            keep.append(line)
            in_user = in_list = False
            continue
        m = re.match(r"^(\s*)User (\d+):", line)
        if m:
            keep.append(line)
            in_user, in_list, user_indent = True, False, len(m.group(1))
            continue
        if in_user:
            if s and ind <= user_indent:
                in_user = in_list = False
            elif s in ("disabledComponents:", "enabledComponents:"):
                keep.append(line)
                in_list = True
                continue
            elif in_list and re.match(r"^[A-Za-z0-9_.$]+$", s):
                keep.append(line)
                continue
            else:
                in_list = False
                continue
        if key_re.match(line) or re.match(r"^\s+(versionCode|targetSdk)=", line):
            keep.append(line)
    return "\n".join(keep) + ("\n" if keep else "")


def resolver_section(text):
    """Only the 'Receiver Resolver Table' section of a package dump."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if RESOLVER_HEADING_RE.match(line):
            out = [line]
            for l2 in lines[i + 1:]:
                if l2 and not l2.startswith(" "):
                    break
                out.append(l2)
            return "\n".join(out) + "\n"
    return ""


class CaptureSanitizer:
    """Replaces identifying strings consistently across a whole capture."""

    def __init__(self, serial, system, third, all_pkgs):
        self.serial = serial or ""
        self.system = set(system)
        anon = sorted(p for p in all_pkgs if p not in self.system or p in third)   # unknown or 3rd -> anon
        self.anon = {p: "user.app.%d" % (i + 1) for i, p in enumerate(anon)}
        self.patterns = []
        for p in sorted(self.anon, key=len, reverse=True):
            # never touch a SYSTEM package that merely starts with this name
            longer = sorted({s[len(p) + 1:] for s in self.system if s.startswith(p + ".")}, key=len, reverse=True)
            guard = "".join(r"(?!\.%s(?![A-Za-z0-9_]))" % re.escape(x) for x in longer)
            self.patterns.append((re.compile(r"(?<![A-Za-z0-9_.])%s(?![A-Za-z0-9_])%s" % (re.escape(p), guard)),
                                  self.anon[p]))

    def __call__(self, text):
        if not text:
            return text
        if self.serial:
            text = text.replace(self.serial, "<serial>")
        text = re.sub(r"/data/app/~~[A-Za-z0-9_\-]+==/", "/data/app/~~X==/", text)
        text = re.sub(r"/mnt/expand/[^/\s]+/", "/mnt/expand/X/", text)           # SD-card volume id
        text = re.sub(r"(/data/app/(?:~~X==/)?[A-Za-z0-9_.]+)-[A-Za-z0-9_\-]+==", r"\1-X==", text)
        for rx, rep in self.patterns:
            text = rx.sub(rep, text)
        text = re.sub(r"UserInfo\{(\d+):[^:}]*", r"UserInfo{\1:user\1", text)
        text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<email>", text)
        text = re.sub(r"\+\d[\d \-]{7,}\d", "<phone>", text)
        text = re.sub(r"(?<![\w.=:/])(?:\(\d{2,4}\)\s?|\d{2,4}[ \-])\d{3}[ \-]\d{3,4}(?![\w.])", "<phone>", text)
        text = re.sub(r"(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", "<mac>", text)
        return text


def pick_sample(receiver_pkgs, system, third, disabled, evidence=()):
    """Which packages get a (trimmed) dumpsys: first the owners of receivers that
    only the disabled-matching query returned (the evidence for that claim), then
    a few system ones with boot receivers, a few user ones, and one switched-off app."""
    total = CAPTURE_SAMPLE_SYSTEM + CAPTURE_SAMPLE_USER + 1           # 12, the agreed maximum
    pick = sorted(set(evidence))[:4]                                   # evidence first
    for p in sorted(p for p in receiver_pkgs if p in third and p not in pick)[:CAPTURE_SAMPLE_USER]:
        pick.append(p)                                                 # then a few user apps
    for p in sorted(disabled):                                         # and one switched-off app
        if p not in pick:
            pick.append(p)
            break
    for p in sorted(p for p in receiver_pkgs if p in system and p != "android" and p not in pick):
        if len(pick) >= total:
            break
        pick.append(p)                                                 # system ones fill the rest
    return pick[:total]


def capture_summary(probes):
    """Compatibility summary. Every capability is "accepted" (the phone took the
    command), "observed" (the output itself shows the behaviour) or "unknown"."""
    by = {p["id"]: p for p in probes}

    def complete(p):
        return p.get("rc") == 0 and not (p.get("truncated") or p.get("err_truncated") or p.get("timed_out"))

    def ok(pid):
        p = by.get(pid)
        return bool(p) and complete(p) and not p.get("command_error") and not query_error(p["out"] + p["err"])
    s = {"truncated": sorted(p["id"] for p in probes
                             if p.get("truncated") or p.get("err_truncated") or p.get("timed_out"))}
    props = props_dict(by.get("props", {}).get("out", ""))
    s["android"] = props.get("ro.build.version.release", "?")
    s["sdk"] = props.get("ro.build.version.sdk", "?")
    s["device"] = "%s %s" % (props.get("ro.product.manufacturer", "?"), props.get("ro.product.model", "?"))
    forms = {}
    for name, _, _ in QUERY_FORMS:
        forms[name] = all(ok("query:%s:%s" % (name, a)) for a in BOOT_ACTIONS)
    s["query_forms_accepted"] = [n for n, v in forms.items() if v]
    a0 = BOOT_ACTIONS[0]

    def rx(pid):            # receivers from a probe - None unless the probe itself succeeded completely
        return set(parse_query_receivers(by[pid]["out"])) if ok(pid) else None
    plain = rx("query:plain:%s" % a0)
    flag_pid = next((pid for pid in ("query:user+flags:%s" % a0, "query:flags:%s" % a0) if ok(pid)), None)
    flagged = rx(flag_pid) if flag_pid else None              # chosen by SUCCESS, never by emptiness
    scoped = rx("query:user+flags:%s" % a0)
    cu_out = by.get("current_user", {}).get("out", "").strip()
    detected = ok("current_user") and cu_out.isdigit()
    user = int(cu_out) if detected else 0
    users = {int(x) for x in re.findall(r"UserInfo\{(\d+):", by.get("users", {}).get("out", ""))} \
        if ok("users") else set()
    user_known = detected or users == {0}
    if not (forms["user+flags"] or forms["flags"]):
        s["disabled_matching"] = "unknown"
    else:
        # "observed" only if a receiver returned ONLY with the flag is confirmed
        # disabled by its complete package dump, for a user we actually know
        s["disabled_matching"] = "accepted"
        if user_known and flagged is not None and plain is not None:
            for pkg, cls in sorted(flagged - plain):
                d = by.get("pkg:" + pkg)
                if d and ok("pkg:" + pkg) and cls in parse_package_user_state(d["out"], user)["disabled"]:
                    s["disabled_matching"] = "observed"
                    break
    if not (forms["user+flags"] or forms["user"]):
        s["user_scoping"] = "unknown"
    else:
        # "observed" only from a real comparison: the same query for another user
        # succeeded and returned a different set
        s["user_scoping"] = "accepted"
        # compare EQUIVALENT queries: this user's --user+flags result vs the other
        # user's, both complete; an empty set on either side is a valid answer
        other = [pid for pid in by if pid.startswith("query:other_user:")]
        theirs = rx(other[0]) if other else None
        other_id = int(other[0].rsplit(":", 1)[1]) if other and other[0].rsplit(":", 1)[1].isdigit() else None
        # both users must be CONFIRMED by a complete user list, and different
        confirmed = ok("users") and user in users and other_id in users and other_id != user
        if confirmed and scoped is not None and theirs is not None and scoped != theirs:
            s["user_scoping"] = "observed"
    s["users"] = len(users) if users else None
    cu = by.get("current_user", {})
    s["current_user"] = "detected" if detected else "single-user" if users == {0} else "unverified"
    def runs(pid):          # help text often contains "usage:" - for these, the exit code decides
        p = by.get(pid)
        return bool(p) and complete(p)
    def answers(pid):       # a real AppOps answer, whatever the exit code
        p = by.get(pid)
        return bool(p) and not (p.get("truncated") or p.get("err_truncated") or p.get("timed_out")
                                or p.get("command_error")) and appops_answer_ok(p["out"], p["err"])
    s["appops_tool"] = "cmd appops" if answers("appops_tool:cmd") else "appops" if answers("appops_tool:old") \
        else "none"
    res = by.get("resolver")
    s["resolver_table"] = ("unknown" if not res or not complete(res) or res.get("command_error")
                           or query_error(res["out"] + res["err"])
                           else                                                   # failed: we don't know
                           "present" if has_receiver_resolver(res["out"]) else "absent")
    s["boot_receivers"] = len(flagged if flagged is not None else plain or set())
    return s


def run_capture(serial, out_dir=CAPTURE_DIR, runner=None):
    """Collect, sanitise and save one capture. Returns (path, summary). Only
    read-only commands are ever sent."""
    run_ = runner or capture_run
    raw = []                                                    # (id, cmd, result) before sanitising
    total = [0]

    def probe(pid, cmd, cap=CAPTURE_PROBE_CAP, post=None):
        cap = max(0, min(cap, CAPTURE_TOTAL_CAP - total[0]))
        r = run_(serial, cmd, cap) if cap else {"rc": None, "out": "", "err": "", "truncated": True,
                                                "timed_out": False, "ms": 0}
        r = dict(r, command_error=query_error(r["out"] + r["err"]))   # BEFORE filtering
        if post:
            r = dict(r, out=post(r["out"]))
        total[0] += len(r["out"]) + len(r["err"])
        raw.append({"id": pid, "cmd": cmd, **r})
        return r

    probe("props", "getprop", post=lambda t: filter_props(t, CAPTURE_PROPS))
    probe("current_user", "am get-current-user")
    probe("users", "pm list users")
    lists = {}
    for pid, flags in (("pkgs_all", "-f -u"), ("pkgs_system", "-s -u"), ("pkgs_third", "-3 -u"),
                       ("pkgs_disabled", "-d")):
        lists[pid] = parse_pm_list(probe(pid, "pm list packages " + flags, cap=2 * CAPTURE_PROBE_CAP)["out"])
    m = re.match(r"\s*(\d+)", raw[1]["out"])
    user = int(m.group(1)) if m and raw[1]["rc"] == 0 else 0
    receiver_pkgs = set()
    for name, with_user, with_flags in QUERY_FORMS:
        for action in BOOT_ACTIONS:
            args = (["--user", str(user)] if with_user else []) + (["--query-flags", QUERY_FLAGS] if with_flags else [])
            r = probe("query:%s:%s" % (name, action),
                      "cmd package query-receivers %s --brief -a %s" % (" ".join(args), action))
            receiver_pkgs.update(p for p, _ in parse_query_receivers(r["out"]))
    u = raw[2]
    users_ok = u["rc"] == 0 and not (u["truncated"] or u.get("err_truncated") or u["timed_out"]) \
        and not query_error(u["out"] + u["err"])
    users = sorted({int(x) for x in re.findall(r"UserInfo\{(\d+):", u["out"])} - {user}) if users_ok else []
    if users:                                    # a real comparison needs a confirmed second user
        probe("query:other_user:%d" % users[0], "cmd package query-receivers --user %d --query-flags %s --brief -a %s"
              % (users[0], QUERY_FLAGS, BOOT_ACTIONS[0]))
    res_out = probe("resolver", "dumpsys package r", cap=4 * CAPTURE_PROBE_CAP, post=resolver_section)["out"]

    def good(pid):          # same rule as the summary's ok(): exit 0, complete, no error line
        r = next(x for x in raw if x["id"] == pid)
        return r["rc"] == 0 and not (r["truncated"] or r.get("err_truncated") or r["timed_out"]) \
            and not r.get("command_error") and not query_error(r["out"] + r["err"])
    # system means CONFIRMED system: if that list couldn't be read completely,
    # nothing counts as system and every package name is anonymised
    system = set(lists["pkgs_system"]) if good("pkgs_system") else set()
    third = set(lists["pkgs_third"])
    a0 = BOOT_ACTIONS[0]

    def rx(pid):
        if not good(pid):
            return None
        return set(parse_query_receivers(next(x for x in raw if x["id"] == pid)["out"]))
    plain_rx = rx("query:plain:%s" % a0)
    flag_rx = next((r for r in (rx("query:user+flags:%s" % a0), rx("query:flags:%s" % a0)) if r is not None), None)
    evidence = {pk for pk, _ in flag_rx - plain_rx} if flag_rx is not None and plain_rx is not None else set()
    for p in pick_sample(receiver_pkgs, system, third, set(lists["pkgs_disabled"]), evidence=evidence):
        probe("pkg:" + p, "dumpsys package " + shlex.quote(p), cap=2 * CAPTURE_PROBE_CAP, post=trim_package_dump)
    probe("appops_tool:cmd", "cmd appops " + APPOPS_PROBE, cap=8192)
    probe("appops_tool:old", "appops " + APPOPS_PROBE, cap=8192)
    def answers(pid):       # same rule as the app: a real AppOps answer, whatever the exit code
        r = next(x for x in raw if x["id"] == pid)
        return not (r["truncated"] or r.get("err_truncated") or r["timed_out"] or r.get("command_error")) \
            and appops_answer_ok(r["out"], r["err"])
    tool = "cmd appops" if answers("appops_tool:cmd") else "appops" if answers("appops_tool:old") else None
    if tool:                                     # the tool this phone actually has
        for p in (sorted(receiver_pkgs & third) or sorted(receiver_pkgs))[:2]:
            for op in ("RUN_ANY_IN_BACKGROUND", "RUN_IN_BACKGROUND"):
                probe("appops:%s:%s" % (p, op), "%s get %s %s" % (tool, shlex.quote(p), op), cap=8192)

    # every package-like name anywhere in the capture is either confirmed system or
    # anonymised - an incomplete inventory never lets an unknown name through
    seen = set(lists["pkgs_all"]) | set(lists["pkgs_system"]) | third | receiver_pkgs
    for r in raw:
        seen.update(re.findall(r"(?<![A-Za-z0-9_.])([a-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)/", r["out"] + r["err"]))
        seen.update(re.findall(r"Package \[([^\]]+)\]", r["out"]))
    seen.update(pk for pk, _ in parse_receiver_resolver(res_out))
    clean = CaptureSanitizer(serial, system, third, seen)
    probes = []
    for r in raw:
        probes.append({"id": clean(r["id"]), "cmd": clean(r["cmd"]), "rc": r["rc"], "out": clean(r["out"]),
                       "err": clean(r["err"])[:CAPTURE_ERR_CAP], "truncated": bool(r["truncated"]),
                       "err_truncated": bool(r.get("err_truncated")), "timed_out": bool(r["timed_out"]),
                       "command_error": bool(r.get("command_error")), "ms": r["ms"]})
    props = props_dict(probes[0]["out"])
    doc = fit_capture({"schema": CAPTURE_SCHEMA, "version": CAPTURE_VERSION,
                       "created": time.strftime("%Y-%m-%dT%H:%M:%S"), "device": props, "probes": probes})
    summary = doc["summary"]
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(out_dir, 0o700)
    except OSError:
        pass
    base = "%s-%s-sdk%s-%s" % (props.get("ro.product.manufacturer", "device"), props.get("ro.product.model", ""),
                               props.get("ro.build.version.sdk", "x"), time.strftime("%Y%m%d"))
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("_")[:80] or "capture"
    path, n = os.path.join(out_dir, base + ".json"), 1
    while os.path.exists(path):
        n += 1
        path = os.path.join(out_dir, "%s-%d.json" % (base, n))
    sa.atomic_write_json(path, doc, private=True)
    return path, summary


def capture_bytes(doc):
    """Size of the file exactly as atomic_write_json will write it."""
    return len(sa.json_payload(doc, indent=1).encode("utf-8"))


def fit_capture(doc, cap=None):
    """Enforce the limit on the FINAL saved bytes (JSON structure, escaping and
    multibyte text included): shorten the biggest probe output, marking it
    truncated, until the file fits. The summary is computed afterwards, so cut
    probes are reported as incomplete."""
    cap = CAPTURE_TOTAL_CAP if cap is None else cap
    doc["summary"] = capture_summary(doc["probes"])
    while capture_bytes(doc) > cap:
        big = max(doc["probes"], key=lambda p: len(p["out"]) + len(p["err"]))
        if big["out"]:
            big["out"] = big["out"][:len(big["out"]) // 2]
            big["truncated"], big["rc"] = True, None
        elif big["err"]:
            big["err"], big["err_truncated"], big["rc"] = "", True, None
        else:
            raise OSError("the capture can't fit in %d bytes even with every probe output removed - "
                          "nothing was saved" % cap)
        doc["summary"] = capture_summary(doc["probes"])
    return doc


def capture_summary_text(summary):
    words = {"observed": "yes (seen in the output)", "accepted": "command accepted (behaviour not proven)",
             "unknown": "not supported / unknown"}
    lines = ["Device:            %s, Android %s (SDK %s)" % (summary["device"], summary["android"], summary["sdk"]),
             "Receiver query:    %s" % (", ".join(summary["query_forms_accepted"]) or "not available"),
             "Disabled matching: %s" % words[summary["disabled_matching"]],
             "Per-user query:    %s" % words[summary["user_scoping"]],
             "Current user:      %s" % summary["current_user"],
             "AppOps tool:       %s" % summary["appops_tool"],
             "Old receiver table: %s" % {"present": "present", "absent": "not on this phone",
                                         "unknown": "couldn't be checked"}[summary["resolver_table"]],
             "Boot receivers:    %d" % summary["boot_receivers"]]
    if summary["truncated"]:
        lines.append("INCOMPLETE probes (cut at the size/time limit): " + ", ".join(summary["truncated"]))
    return "\n".join(lines)


def pick_capture_serial(explicit=None):
    """The serial to capture: the one given, or the only connected device."""
    if explicit:
        return explicit, None
    try:
        rc, out, err = run([ADB, "devices"], timeout=20)
    except AdbError as e:
        return None, str(e)
    devs = [l.split()[0] for l in out.splitlines()[1:] if l.strip().endswith("\tdevice")]
    if len(devs) != 1:
        return None, ("no device connected" if not devs else
                      "%d devices connected - choose one with -s SERIAL" % len(devs))
    return devs[0], None


def capture_main(serial_arg):
    serial, err = pick_capture_serial(serial_arg)
    if not serial:
        print("Capture not made: %s" % err, file=sys.stderr)
        return 1
    print("Reading the phone (read-only commands only) ...")
    try:
        path, summary = run_capture(serial)
    except Exception as e:                              # e.g. the file couldn't be written
        print("Capture not saved: %s: %s" % (type(e).__name__, e), file=sys.stderr)
        return 1
    print(capture_summary_text(summary))
    print("\nSaved (private file): %s" % path)
    print("Open it to see exactly what it contains before sharing it.")
    return 0


# ---- Copy diagnostics (a small allowlisted subset, for bug reports) -----------

def diagnostics_text(serial, runner=None):
    """Plain text for a GitHub issue: versions, tools found, and - if a phone is
    connected - its Android version, maker, model and what it supports. No serial,
    no package names, nothing personal."""
    import platform
    lines = ["ADB Manager diagnostics", ""]
    try:
        osr = platform.freedesktop_os_release().get("PRETTY_NAME", "")
    except (OSError, AttributeError):
        osr = ""
    lines.append("Computer: %s %s" % (osr or platform.system(), platform.machine()))
    lines.append("Python %s, Tk %s" % (platform.python_version(), tk.TkVersion))
    try:
        rc, out, _ = run([ADB, "version"], timeout=15)
        lines.append("adb: %s" % (out.splitlines()[0].strip() if rc == 0 and out.strip() else "not working"))
    except AdbError:
        lines.append("adb: not found")
    env = sa.inspector_env(sa.load_sec_config())
    lines.append("Code inspector: %s" % ("Androguard %s" % env["androguard"] if env["ok"] else "Androguard not installed"))
    lines.append("readelf: %s" % ("found" if env["readelf"] else "not found"))
    lines.append("Terminal for Open shell: %s" % ("found" if find_terminal() else "not found"))
    if not serial:
        lines += ["", "No phone connected."]
        return "\n".join(lines)
    run_ = runner or capture_run
    probes = []

    def probe(pid, cmd, post=None):
        r = run_(serial, cmd, 65536)
        probes.append({"id": pid, "cmd": cmd, "rc": r["rc"], "out": post(r["out"]) if post else r["out"],
                       "command_error": query_error(r["out"] + r["err"]),
                       "err": r["err"], "truncated": r["truncated"], "err_truncated": r.get("err_truncated", False),
                       "timed_out": r["timed_out"]})
    probe("props", "getprop", post=lambda t: filter_props(t, DIAG_PROPS))
    probe("current_user", "am get-current-user")
    probe("users", "pm list users", post=lambda t: re.sub(r"UserInfo\{(\d+):[^:}]*", r"UserInfo{\1:user\1", t))
    cu = probes[1]["out"].strip()
    user = int(cu) if probes[1]["rc"] == 0 and cu.isdigit() else 0
    for name, with_user, with_flags in QUERY_FORMS:
        for action in BOOT_ACTIONS:
            args = (["--user", str(user)] if with_user else []) + (["--query-flags", QUERY_FLAGS] if with_flags else [])
            # only component names are kept (to compare the queries), never shown
            probe("query:%s:%s" % (name, action), "cmd package query-receivers %s --brief -a %s"
                  % (" ".join(args), action),
                  post=lambda t: "\n".join("%s/%s" % c for c in parse_query_receivers(t)) + "\n")
    r = run_(serial, "dumpsys package r", 4 * CAPTURE_PROBE_CAP)
    probes.append({"id": "resolver", "cmd": "dumpsys package r", "rc": r["rc"], "out": resolver_section(r["out"]),
                   "command_error": query_error(r["out"] + r["err"]),
                   "err": r["err"], "truncated": r["truncated"], "err_truncated": r.get("err_truncated", False),
                   "timed_out": r["timed_out"]})
    probe("appops_tool:cmd", "cmd appops " + APPOPS_PROBE)
    probe("appops_tool:old", "appops " + APPOPS_PROBE)
    s = capture_summary(probes)
    p = props_dict(probes[0]["out"])

    def category(pr):
        if pr["id"].startswith("appops_tool"):           # reported on its own line ("AppOps tool:")
            return None
        if pr.get("timed_out"):
            return "timed out"
        if pr.get("truncated"):
            return "cut at the size limit"
        if pr.get("err_truncated"):
            return "error output cut at the size limit"
        if pr.get("command_error") and pr.get("rc") == 0:
            return "reported an error"
        if pr.get("rc") != 0:
            return "not supported" if re.search(r"(?i)not found|unknown (option|command)", pr["err"] + pr["out"]) \
                else "failed (exit %s)" % pr.get("rc")
        return None
    failed = ["%s: %s" % (pr["id"], category(pr)) for pr in probes if category(pr)]
    words = {"observed": "seen in the output", "accepted": "accepted, not proven", "unknown": "not supported"}
    lines += ["", "Phone: %s %s, Android %s (SDK %s)%s" % (
        p.get("ro.product.manufacturer", "?"), p.get("ro.product.model", "?"), p.get("ro.build.version.release", "?"),
        p.get("ro.build.version.sdk", "?"), ", Go/low-RAM" if p.get("ro.config.low_ram") == "true" else ""),
        "Checked for Android user %d (%s)" % (user, s["current_user"]),
        "Receiver query forms accepted: %s" % (", ".join(s["query_forms_accepted"]) or "none"),
        "Switched-off receivers included: %s" % words[s["disabled_matching"]],
        "Old receiver table: %s" % {"present": "present", "absent": "not on this phone",
                                    "unknown": "couldn't be checked"}[s["resolver_table"]],
        "AppOps tool: %s" % s["appops_tool"],
        "Checks that didn't work: %s" % ("; ".join(failed) if failed else "none")]
    text = "\n".join(lines)
    return text.replace(serial, "<serial>") if serial else text


def main():
    ap = argparse.ArgumentParser(description="Android device manager over adb (GUI)")
    ap.add_argument("-s", "--serial", help="device serial to connect to")
    ap.add_argument("--local", default=os.getcwd(), help="start folder on this computer")
    ap.add_argument("--remote", default="/sdcard", help="start folder on the device")
    ap.add_argument("--capture", action="store_true",
                    help="developer tool: read the phone with read-only commands and save a sanitised "
                         "capture file (no GUI)")
    args = ap.parse_args()
    if args.capture:
        sys.exit(capture_main(args.serial))

    root = tk.Tk()
    if not (shutil.which(ADB) or os.path.isfile(ADB)):
        root.withdraw()
        messagebox.showerror("adb not found",
                             "adb was not found.\n\nInstall it (e.g. apt install adb) "
                             "or run with ADB=/path/to/adb")
        sys.exit(1)
    App(root, args)
    root.mainloop()


if __name__ == "__main__":
    main()
