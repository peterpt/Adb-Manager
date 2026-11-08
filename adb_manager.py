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

Requires: Python 3.6+ with tkinter (apt install python3-tk), adb in PATH
          (or ADB=/path/to/adb), Linux/macOS. app_knowledge.py and
          ai_research.py and security_audit.py in the same folder. For AI research: pip install
          anthropic and/or openai.
"""

import argparse
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
from tkinter import filedialog, messagebox, simpledialog, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app_knowledge as kb  # noqa: E402
import ai_research as ai  # noqa: E402
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
    if not res and (rc != 0 or err.strip()):
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

    apps = {}
    for pkg, path in list(paths.items()) + list(removed.items()):
        d = details.get(pkg, {})
        flags = d.get("flags", "")
        if system is not None:
            is_sys = pkg in system
        else:
            is_sys = "SYSTEM" in flags.split() or path.startswith(("/system", "/product",
                                                                   "/vendor", "/apex"))
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
    """APK file(s) of an installed package on the device (base + split parts)."""
    rc, out, err = adb_shell(serial, "pm path " + shlex.quote(pkg), timeout=30)
    return [l[len("package:"):].strip() for l in out.splitlines() if l.startswith("package:")]


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
TURNED_OFF_FILE = os.path.join(CONFIG_DIR, "turned_off.json")
BACKUP_DIR = os.path.join(CONFIG_DIR, "apk_backups")
ACTIONS_LOG = os.path.join(CONFIG_DIR, "actions.log")
AI_CACHE_FILE = os.path.join(CONFIG_DIR, "ai_research.json")


class JsonStore:
    """Small thread-safe JSON dict saved to disk after every change."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        try:
            with open(path, encoding="utf-8") as f:
                self.data = json.load(f)
            if not isinstance(self.data, dict):
                self.data = {}
        except (OSError, ValueError):
            self.data = {}

    def get(self, key, default=None):
        with self.lock:
            return self.data.get(key, default)

    def put(self, key, value):
        with self.lock:
            self.data[key] = value
            self._save()

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=1, ensure_ascii=False)
            os.replace(tmp, self.path)
        except OSError:
            pass


def log_action(serial, verb, pkg, ok, msg):
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(ACTIONS_LOG, "a", encoding="utf-8") as f:
            f.write("%s  %s  %-8s %s  %s  %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), serial,
                                                    verb, pkg, "OK" if ok else "FAILED", msg))
    except OSError:
        pass


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
            if not remote.startswith("Android/obb/"):
                if not package:
                    continue
                remote = "Android/obb/%s/%s" % (package, os.path.basename(n))
            dest = os.path.join(workdir, "obb%02d_%s" % (i, os.path.basename(n)))
            with z.open(n) as src, open(dest, "wb") as dst:
                shutil.copyfileobj(src, dst)
            obbs.append((dest, "/sdcard/" + remote))
    z.close()
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


def parse_proc_net(text):
    """Parse '==tcp' / '==udp6' ... sections of /proc/net files. Returns (sockets, errors)."""
    socks, errors, proto = [], [], None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("=="):
            proto = line[2:]
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
        else:
            rec["state"] = "CONNECTED" if st == "01" else ("OPEN" if st == "07" else st)
            rec["kind"] = "connected" if st == "01" else ("listen" if st == "07" else "other")
        socks.append(rec)
    return socks, errors


def read_sockets(serial):
    rc, out, err = adb_shell(serial, "for f in tcp tcp6 udp udp6; do echo ==$f; "
                                     "cat /proc/net/$f 2>&1; done", timeout=30)
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
        ttk.Checkbutton(row2, text="Use root (su) if the device refuses",
                        variable=self.use_root).pack(side="left", padx=12)
        ttk.Checkbutton(row2, text="Show technical details", variable=self.show_tech,
                        command=lambda: self.render(self.shown_pkg)).pack(side="right")

        self.render(None)

    # ---- device ----------------------------------------------------------

    def set_device(self, serial):
        if serial == self.serial:
            return
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
        threading.Thread(target=fn, args=args, daemon=True).start()
        return True

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
        self.render(self.shown_pkg if self.shown_pkg in self.apps else None)
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
        k = kb.lookup(pkg)
        if k and k.get("name"):
            return k["name"]
        info = self.cache.get(pkg) or {}
        play = info.get("play") or {}
        if play.get("found") and play.get("name"):
            return play["name"]
        return pkg

    def assess(self, a):
        """(risk, what, if_off) for an app record."""
        k = kb.lookup(a["package"])
        if k:
            risk, what, if_off = k["risk"], k["what"], k["if_off"]
        else:
            risk, if_off = kb.guess(a["package"], a["system"])
            what = None
        if not a["system"] and risk == kb.CRITICAL:
            risk = kb.CAUTION
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
                w("   the device may misbehave or not start - leave it on\n\n")
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
                        adb_shell(serial, "mkdir -p " + shlex.quote(posixpath.dirname(remote)))
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
            ok, msg = pm_uninstall(serial, p, mode, opts.get("keep_data", False))
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
            ok, msg = pm_restore(serial, p)
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

    def ask_ai(self, compare):
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
        n = len(pkgs) * len(provs)
        if n > 2 and not messagebox.askyesno(
                "Ask AI", "This sends %d request(s): %d app(s) x %d AI(s).\n\nEach request runs "
                "several web searches and is billed to your API account. Answers are saved, "
                "so you only pay once per app.\n\nGo ahead?" % (n, len(pkgs), len(provs)),
                parent=self.app.root):
            return
        apps = {p: dict(self.apps[p]) for p in pkgs}
        self.start_job("asking the AI", self._ai_worker, pkgs, provs, cfg, dict(self.props), apps)

    def _ai_worker(self, pkgs, provs, cfg, props, apps):
        failed = done = 0
        for i, pkg in enumerate(pkgs):
            if self.stop.is_set():
                break
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

    def _ai_result(self, pkg, prov, res):
        entry = dict(self.ai_cache.get(pkg) or {})
        old = entry.get(prov)
        if res.get("error") and isinstance(old, dict) and old.get("answer"):
            old = dict(old)              # keep the older good answer
            old["last_error"] = res["error"]
            entry[prov] = old
        else:
            entry[prov] = res
        self.ai_cache.put(pkg, entry)
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
                        w("    " + f["source"] + "\n", "dim")
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
                    w("    " + s + "\n", "dim")
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
            self.cache.put(pkg, res)
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
            ok, msg = pm_set_enabled(serial, p, enable, use_root)
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
        mine = dict(self.turned_off.get(serial, {}) or {})
        for p, ok, msg in results:
            if not ok or p not in self.apps:
                continue
            if enable:
                mine.pop(p, None)
            else:
                mine[p] = time.strftime("%Y-%m-%d %H:%M")
        self.turned_off.put(serial, mine)
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
        except AdbError as e:
            self.app.q.put(("call", self._failed, str(e)))
            return
        umap = apps_map if apps_map is not None else (uid_packages(serial) if need_map else None)
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
        app_id = uid % 100000
        pkgs = self.owner_pkgs(uid)
        return "+".join(sorted(pkgs)) if pkgs and app_id >= 10000 else "uid:%d" % app_id

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
            sa.save_json(self.seen_path(), self.seen)
        alert = is_new and not learning
        sig = (s["uid"], s["remote_ip"], s["remote_port"])
        if sig not in self.logged or alert:
            self.logged.add(sig)
            try:
                os.makedirs(NET_LOG_DIR, exist_ok=True)
                fresh = not os.path.exists(self.log_path())
                with open(self.log_path(), "a", newline="", encoding="utf-8") as f:
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

    def owner_pkgs(self, uid):
        return self.uid_map.get(uid % 100000, [])

    def owner_name(self, uid):
        app_id = uid % 100000
        pkgs = self.owner_pkgs(uid)
        lbl = self.app.apps_tab.label
        if app_id < 10000:
            base = SYSTEM_UIDS.get(app_id, "Android system service (UID %d)" % app_id)
            return base
        if not pkgs:
            return "Unknown app (UID %d)" % uid
        if len(pkgs) == 1:
            return lbl(pkgs[0])
        return "%s + %d more (shared ID)" % (lbl(sorted(pkgs)[0]), len(pkgs) - 1)

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
        if s["kind"] == "connected":
            return "Connected to %s:%d" % (self.remote_label(s), s["remote_port"])
        return "%s %s:%d" % (s["state"].lower().replace("_", " "), self.remote_label(s), s["remote_port"])

    def sock_values(self, s):
        reach = REACH_TEXT.get(self.reach(s), "")
        remote = "" if s["kind"] == "listen" else self.fmt(s["remote_ip"], s["remote_port"])
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
            groups.setdefault(s["uid"] % 100000, []).append(s)
        rank = {"critical": 0, "caution": 1, "safe": 2, "": 3}

        def worst(items):
            return min((self.risk(s) for s in items), key=lambda r: rank[r])
        order = sorted(groups.items(), key=lambda kv: (rank[worst(kv[1])],
                                                      self.owner_name(kv[1][0]["uid"]).lower()))
        reselect = None
        for app_id, items in order:
            n_open = sum(1 for s in items if s["kind"] == "listen")
            n_conn = sum(1 for s in items if s["kind"] == "connected")
            bits = []
            if n_open:
                bits.append("%d open" % n_open)
            if n_conn:
                bits.append("%d connection%s" % (n_conn, "" if n_conn == 1 else "s"))
            oid = "o:%d" % app_id
            w = worst(items)
            self.tree.insert("", "end", iid=oid, open=True,
                             text="%s  (%s)" % (self.owner_name(items[0]["uid"]), ", ".join(bits) or "other"),
                             tags=("owner",) + ((w,) if w in ("critical", "caution") else ()))
            self.rows[oid] = ("owner", app_id)
            if keep == ("owner", app_id):
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
            items = [s for s in self.socks if s["uid"] % 100000 == data]
            self.render_owner(w, data, items)
        else:
            self.render_sock(w, data)
        t.configure(state="disabled")

    def render_owner(self, w, app_id, items):
        uid = items[0]["uid"] if items else app_id
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
        if not opens and not conns:
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
                w("\nUDP 'open' means the app can receive messages on this port. Many system "
                  "services do this to find devices on the network or get an address.\n", "dim")
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
        app_id = row[1] if row[0] == "owner" else row[1]["uid"] % 100000
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
            msg = ("The deep scan copies %s you installed to this computer (into a temporary folder, deleted "
                   "afterwards) to read their signature and fingerprint.\n\n" % (
                       "the %d apps" % n if apps is not None else "the apps"))
            msg += (("Then it asks %s about them - only the fingerprint (hash) and package name are sent, never "
                     "the apps themselves." % " and ".join(keys)) if keys else
                    "No lookup service is set up, so it only reads signatures. Add free keys in Security "
                    "settings to check apps against malware databases and tracker reports.")
            if cfg["virustotal_key"]:
                msg += "\n\nVirusTotal's free key allows 4 lookups a minute, so this can take a while."
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
            return adb_shell(serial, cmd, timeout=timeout)[1]
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
        launcher = sa.launcher_packages(shell, users)[0] if users else set()
        access = sa.access_lists(facts)
        found = (sa.check_device(facts) + sa.check_access(facts, access, launcher, label) +
                 sa.check_origin(facts, launcher, label) + sa.check_usage(facts, launcher, label))

        idcache = sa.load_json(sa.IDENTITY_FILE, {})
        targets = users + ([p for p, a in apps.items() if a["system"] and a.get("updated_system")
                            and not a.get("removed")] if cfg.get("deep_include_updated_system") else [])
        if deep:
            work = tempfile.mkdtemp(prefix="adbmgr_sec_")
            try:
                for i, p in enumerate(targets):
                    if self.stop.is_set():
                        break
                    k = sa.identity_key(p, apps[p])
                    if k in idcache:
                        continue
                    self.say("Deep scan: reading %d/%d %s ..." % (i + 1, len(targets), p))
                    try:
                        paths = pm_paths(serial, p)
                    except AdbError:
                        continue
                    base = next((x for x in paths if x.endswith("/base.apk")), paths[0] if paths else "")
                    if not base:
                        continue
                    local = os.path.join(work, "a.apk")
                    rc, msg = adb_transfer([ADB, "-s", serial, "pull", base, local], lambda x: None, self.stop)
                    if rc != 0 or not os.path.exists(local):
                        continue
                    try:
                        ident = sa.apk_identity(local)
                        ident["pkg"] = p
                        idcache[k] = ident
                    except OSError:
                        pass
                    finally:
                        try:
                            os.remove(local)
                        except OSError:
                            pass
                sa.save_json(sa.IDENTITY_FILE, idcache)
            finally:
                shutil.rmtree(work, ignore_errors=True)

        snap = sa.build_snapshot(serial, facts, access, launcher, idcache)
        found += sa.compare_snapshots(sa.last_snapshot(serial), snap, label)
        if not self.stop.is_set():
            sa.save_snapshot(serial, snap)

        idents = {p: idcache[sa.identity_key(p, apps[p])] for p in targets
                  if sa.identity_key(p, apps[p]) in idcache}
        rep = sa.load_json(sa.REPUTATION_FILE, {})
        if deep and (cfg["virustotal_key"] or cfg["malwarebazaar_key"]):
            vt_ok, last_vt = bool(cfg["virustotal_key"]), 0.0
            for i, (p, ident) in enumerate(sorted(idents.items())):
                if self.stop.is_set():
                    break
                entry = dict(rep.get(ident["sha256"], {}))
                fresh = time.time() - entry.get("time", 0) < 7 * 86400
                if vt_ok and not (fresh and entry.get("vt") and not entry["vt"].get("error")):
                    wait = 15.5 - (time.time() - last_vt)
                    while wait > 0 and not self.stop.is_set():
                        self.say("Deep scan: VirusTotal %d/%d (free key: waiting %ds) ..." % (i + 1, len(idents), wait))
                        time.sleep(min(1.0, wait))
                        wait -= 1.0
                    if self.stop.is_set():
                        break
                    self.say("Deep scan: VirusTotal %d/%d %s ..." % (i + 1, len(idents), p))
                    entry["vt"] = sa.virustotal(cfg["virustotal_key"], ident["sha256"])
                    last_vt = time.time()
                    if entry["vt"].get("quota") or "rejected" in entry["vt"].get("error", ""):
                        vt_ok = False
                if cfg["malwarebazaar_key"] and not (fresh and entry.get("mb") and not entry["mb"].get("error")):
                    self.say("Deep scan: MalwareBazaar %d/%d %s ..." % (i + 1, len(idents), p))
                    entry["mb"] = sa.malwarebazaar(cfg["malwarebazaar_key"], ident["sha256"])
                entry["time"] = time.time()
                rep[ident["sha256"]] = entry
                sa.save_json(sa.REPUTATION_FILE, rep)
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
                sa.save_json(sa.TRACKERS_FILE, tcache)
        trk = sa.tracker_findings(apps, label, reports) if reports else []
        if not trk:
            trk = [sa.finding("trackers", sa.INFO, "Not checked yet - %s" % (
                "run a deep scan" if cfg["exodus_token"] else
                "add a free Exodus Privacy token in Security settings, then run a deep scan"),
                key="trackers:none")]
        found += trk
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

        txt.configure(state="disabled")
        btns = ttk.Frame(self, padding=(14, 0, 14, 14))
        btns.pack(fill="x")
        self.txt = txt
        ttk.Button(btns, text="Close", command=self.destroy).pack(side="right")
        ttk.Button(btns, text="Copy all", command=lambda: self.copy(txt)).pack(side="right", padx=6)
        self.ai_btn = ttk.Button(btns, text="Research rooting with AI", command=self.research_rooting)
        self.ai_btn.pack(side="left")
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
        try:
            webbrowser.open(url)
        except Exception:
            pass

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

    def _start_ai(self, provider, cfg):
        self.ai_busy = True
        self.ai_stop.clear()
        self.ai_btn.state(["disabled"])
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
        self.ai_note.configure(text="")
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
        w("This is the AI's research - verify against the sources before flashing anything.\n", "dim")
        if a["summary"]:
            w(a["summary"] + "\n")
        risk = a["brick_risk"].lower()
        rtag = "warn" if risk.startswith(("high", "medium")) else ()
        pairs = [("Can it be unlocked?", a["can_unlock"], "ok" if a["can_unlock"] == "yes"
                  else "warn" if a["can_unlock"] in ("no", "difficult") else ()),
                 ("Unlock method", a["unlock_method"], ()),
                 ("Needs Windows?", a["needs_windows"], ()),
                 ("Waiting period", a["wait_time"], ()),
                 ("TWRP / OrangeFox", a["twrp"], ()),
                 ("Root method", a["root_method"], ()),
                 ("Brick risk", a["brick_risk"], rtag),
                 ("Anti-rollback", a["anti_rollback"], ()),
                 ("Device", a["device"], ())]
        for label, value, tag in pairs:
            if value:
                w("\n" + label + ": ", "label")
                w(value + "\n", tag)
        w("\nAI confidence: %s\n" % a["confidence"], "dim")
        if a["sources"]:
            w("Sources (click to open)\n", "label")
            for u in a["sources"][:10]:
                self.add_link(t, u)
        t.configure(state="disabled")
        t.see(self._ai_mark)

    def copy(self, txt):
        self.clipboard_clear()
        self.clipboard_append(txt.get("1.0", "end").strip())


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
        mark = {kb.SAFE: "\u2705", kb.CAUTION: "\u26a0", kb.CRITICAL: "\u26d4"}

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
        root.geometry("1250x780")
        root.minsize(860, 480)
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Treeview", rowheight=22)

        # --- device bar
        top = ttk.Frame(root, padding=(6, 6, 6, 0))
        top.pack(fill="x")
        ttk.Label(top, text="Device:").pack(side="left")
        self.dev_var = tk.StringVar()
        self.dev_combo = ttk.Combobox(top, textvariable=self.dev_var, state="readonly", width=55)
        self.dev_combo.pack(side="left", padx=4)
        self.dev_combo.bind("<<ComboboxSelected>>", self.on_device_selected)
        ttk.Button(top, text="Rescan", command=self.scan_devices).pack(side="left")

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
        self.nb.bind("<<NotebookTabChanged>>", self.on_tab_changed)

        # --- status bar
        bottom = ttk.Frame(root, padding=(6, 2, 6, 6))
        bottom.pack(fill="x")
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


def main():
    ap = argparse.ArgumentParser(description="Android device manager over adb (GUI)")
    ap.add_argument("-s", "--serial", help="device serial to connect to")
    ap.add_argument("--local", default=os.getcwd(), help="start folder on this computer")
    ap.add_argument("--remote", default="/sdcard", help="start folder on the device")
    args = ap.parse_args()

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
