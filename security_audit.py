"""
security_audit.py - privacy and malware checks for one Android device over ADB.

Used by adb_manager.py (the Security tab). Nothing here needs root. Device
access goes through a `shell(cmd, timeout)` callable that returns the command's
output, so every check can be tested without a phone.

What it checks:
  device     - patch level, encryption, SELinux, bootloader / verified boot,
               root, ADB over network, unknown sources, Wi-Fi proxy
  access     - the switches malware abuses: accessibility, device admin,
               notification access, draw over apps, usage access, install
               other apps, default SMS app, VPN
  origin     - where each app came from, apps hiding their icon, apps posing
               with system-like names
  changes    - what changed since the previous check (new apps, new
               permissions, new powerful access, a changed signing certificate)
  usage      - which apps recently used the camera, microphone, location ...
  malware    - SHA-256 of the APK checked on VirusTotal / MalwareBazaar
  trackers   - tracking libraries inside apps (Exodus Privacy reports)

Saved data (in ~/.config/adb_manager/):
  security_config.json     optional API keys (permissions 600)
  snapshots/<serial>/      one fingerprint of the device per check
  apk_identity.json        APK hash + signing certificate per app version
  reputation.json          malware lookups per APK hash
  trackers.json            Exodus reports per app
"""

import base64
import hashlib
import json
import os
import re
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

CONFIG_DIR = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
                          "adb_manager")
SEC_CONFIG_FILE = os.path.join(CONFIG_DIR, "security_config.json")
SNAP_DIR = os.path.join(CONFIG_DIR, "snapshots")
IDENTITY_FILE = os.path.join(CONFIG_DIR, "apk_identity.json")
REPUTATION_FILE = os.path.join(CONFIG_DIR, "reputation.json")
TRACKERS_FILE = os.path.join(CONFIG_DIR, "trackers.json")
ROOTING_DB_FILE = os.path.join(CONFIG_DIR, "rooting_db.json")
KEEP_SNAPSHOTS = 30

DEFAULT_SEC_CONFIG = {"virustotal_key": "", "malwarebazaar_key": "", "exodus_token": "",
                      "exodus_url": "https://reports.exodus-privacy.eu.org",
                      "deep_include_updated_system": False,
                      "app_labels_enabled": True,       # read real app names from the phone
                      "app_labels_max_mb": 200}         # max data read for names per connection

OK, INFO, WARN, BAD = "ok", "info", "warn", "bad"
LEVEL_RANK = {BAD: 0, WARN: 1, INFO: 2, OK: 3}

SECTIONS = [("pattern", "Spyware pattern (several warning signs on one app)"),
            ("device", "Device protection"),
            ("access", "Powerful access (what malware abuses)"),
            ("origin", "Where apps came from"),
            ("changes", "Changes since the last check"),
            ("usage", "Recent use of camera, microphone, location ..."),
            ("malware", "Malware lookup"),
            ("trackers", "Trackers inside apps")]

STORES = {"com.android.vending": "Google Play", "org.fdroid.fdroid": "F-Droid",
          "org.fdroid.basic": "F-Droid", "com.aurora.store": "Aurora Store",
          "com.amazon.venezia": "Amazon Appstore", "com.sec.android.app.samsungapps": "Samsung Galaxy Store",
          "com.huawei.appmarket": "Huawei AppGallery", "com.xiaomi.market": "Xiaomi GetApps",
          "com.xiaomi.mipicks": "Xiaomi GetApps", "com.heytap.market": "OPPO App Market",
          "com.oppo.market": "OPPO App Market", "com.bbk.appstore": "vivo App Store",
          "dev.imranr.obtainium": "Obtainium", "com.machiav3lli.fdroid": "Neo Store",
          "com.looker.droidify": "Droid-ify"}
FILE_INSTALLERS = ("com.android.packageinstaller", "com.google.android.packageinstaller",
                   "com.samsung.android.packageinstaller", "com.miui.packageinstaller")

# appops names -> plain words (for "recent use")
USAGE_OPS = {"CAMERA": "camera", "RECORD_AUDIO": "microphone", "FINE_LOCATION": "exact location",
             "COARSE_LOCATION": "rough location", "READ_CONTACTS": "contacts",
             "READ_SMS": "text messages", "READ_CALL_LOG": "call history",
             "READ_CLIPBOARD": "clipboard", "BODY_SENSORS": "body sensors"}
# permissions whose new grant is worth reporting in "changes"
SENSITIVE_PERMS = {
    "android.permission.CAMERA": "camera", "android.permission.RECORD_AUDIO": "microphone",
    "android.permission.ACCESS_FINE_LOCATION": "exact location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "location in the background",
    "android.permission.ACCESS_COARSE_LOCATION": "rough location",
    "android.permission.READ_CONTACTS": "contacts", "android.permission.READ_SMS": "text messages",
    "android.permission.RECEIVE_SMS": "receiving texts", "android.permission.SEND_SMS": "sending texts",
    "android.permission.READ_CALL_LOG": "call history", "android.permission.CALL_PHONE": "making calls",
    "android.permission.READ_PHONE_STATE": "phone identity",
    "android.permission.READ_EXTERNAL_STORAGE": "your files",
    "android.permission.WRITE_EXTERNAL_STORAGE": "changing your files",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "all files",
    "android.permission.BODY_SENSORS": "body sensors", "android.permission.READ_CALENDAR": "calendar",
    "android.permission.GET_ACCOUNTS": "accounts on the device",
}

ACCESS_INFO = {
    "accessibility": ("Accessibility service",
                      "It can read everything on the screen and tap buttons for you. Screen readers "
                      "need this - and it is the favourite tool of banking trojans and stalkerware.",
                      "If you don't know why this app needs it: Settings > Accessibility > switch it off."),
    "admin": ("Device administrator",
              "It can lock or wipe the device, enforce password rules, and stop itself from being "
              "uninstalled.",
              "If you don't recognise it: Settings > Security > Device administrators > untick it."),
    "notifications": ("Notification access",
                      "It reads every notification - messages, e-mails and two-factor login codes.",
                      "Settings > Apps > Special access > Notification access > switch it off if unneeded."),
    "overlay": ("Draw over other apps",
                "It can put windows on top of other apps. Chat bubbles use this; malware uses it for "
                "fake login screens over your banking app.",
                "Settings > Apps > Special access > Display over other apps."),
    "usage": ("Usage access",
              "It sees which apps you use, when and for how long.",
              "Settings > Apps > Special access > Usage access."),
    "install": ("Can install other apps",
                "It may install APK files without going through an app store. Browsers and file "
                "managers ask for this; malware uses it to drop more malware.",
                "Settings > Apps > Special access > Install unknown apps."),
    "sms": ("Default SMS app",
            "It receives all your text messages, including bank codes.",
            "Settings > Apps > Default apps > SMS app."),
}


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def finding(section, level, title, detail="", advice="", tech="", pkg=None, key=None):
    return {"section": section, "level": level, "title": title, "detail": detail,
            "advice": advice, "tech": tech, "pkg": pkg, "key": key or title}


def _clean(s):
    s = (s or "").strip()
    return "" if s in ("null", "None") else s


def components(value):
    """'pkg/cls:pkg2/cls2' -> ['pkg', 'pkg2'] (settings lists of components)."""
    out = []
    for part in re.split(r"[:,]", _clean(value)):
        part = part.strip()
        if "/" in part:
            p = part.split("/", 1)[0].strip()
            if p and p not in out:
                out.append(p)
    return out


def parse_duration(text):
    """'+1d2h3m4s56ms' / '-1h20m5s321ms' -> seconds (float), or None."""
    if not text:
        return None
    total, found = 0.0, False
    for num, unit in re.findall(r"(\d+)(ms|d|h|m|s)", text):
        found = True
        total += int(num) * {"d": 86400, "h": 3600, "m": 60, "s": 1, "ms": 0.001}[unit]
    return total if found else None


def ago_text(seconds):
    if seconds is None:
        return "some time ago"
    if seconds < 90:
        return "just now"
    if seconds < 3600:
        return "%d min ago" % (seconds // 60)
    if seconds < 86400:
        return "%d h ago" % (seconds // 3600)
    return "%d days ago" % (seconds // 86400)


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, type(default)) else default
    except (OSError, ValueError):
        return default


def ensure_dir(path, private=False):
    """Create a directory (and parents). With private=True the directory itself is
    forced to 0700. Raises OSError if it can't be created or made private."""
    os.makedirs(path, mode=0o700 if private else 0o777, exist_ok=True)
    if private:
        os.chmod(path, 0o700)


def json_payload(data, indent=1):
    """The exact text atomic_write_json writes (callers measuring file size use this
    too, so the two can never disagree)."""
    return json.dumps(data, indent=indent, ensure_ascii=False)


def atomic_write_json(path, data, private=True, indent=1, folder_private=None):
    """Write JSON so the file is either the complete old version or the complete
    new one - never half-written, never left with loose permissions.

      - the temp file has a UNIQUE name (mkstemp) in the same folder, so two
        writers can't trample each other's temp file;
      - private=True (the default): file 0600 from the moment it exists, folder 0700;
        folder_private=False keeps the file 0600 but leaves the folder's permissions
        alone (for files saved into a folder the USER picked, e.g. Downloads);
      - data is flushed + fsync'd before the rename, and the rename is atomic: a
        reader sees either the whole old file or the whole new one;
      - the folder is fsync'd afterwards to make the rename survive a power cut,
        but only BEST EFFORT (errors there are ignored for portability), so crash
        durability of the rename itself is not guaranteed - atomicity is;
      - on any failure the temp file is removed and OSError is RAISED (callers
        decide how to report it - nothing is silently swallowed here).
    Values that JSON can't encode raise OSError too (wrapping the TypeError)."""
    import tempfile
    folder = os.path.dirname(os.path.abspath(path))
    ensure_dir(folder, private=private if folder_private is None else folder_private)
    try:
        payload = json_payload(data, indent=indent)
    except (TypeError, ValueError) as e:
        raise OSError("can't encode data for %s: %s" % (path, e))
    fd, tmp = tempfile.mkstemp(dir=folder, prefix="." + os.path.basename(path) + ".",
                               suffix=".tmp")
    try:
        os.fchmod(fd, 0o600 if private else 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)   # the mode was set on the temp file, before this
        tmp = None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    try:   # best effort only: see docstring (atomic yes, crash-durable not guaranteed)
        dfd = os.open(folder, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def save_json(path, data, private=True):
    """atomic_write_json() for callers that want True/False instead of an exception.
    Private (0600/0700) by default: everything we keep describes the user's devices."""
    try:
        atomic_write_json(path, data, private=private)
        return True
    except OSError:
        return False


def load_sec_config():
    cfg = dict(DEFAULT_SEC_CONFIG)
    cfg.update(load_json(SEC_CONFIG_FILE, {}))
    return cfg


def save_sec_config(cfg):
    if not save_json(SEC_CONFIG_FILE, cfg, private=True):
        raise OSError("could not write %s" % SEC_CONFIG_FILE)


# --------------------------------------------------------------------------
# appops: who used what, and which special switches are on
# --------------------------------------------------------------------------

def parse_appops(text):
    """Parse 'dumpsys appops' (old 'OP: mode=x; time=+.. ago' and new 'OP (mode):'
    + 'Access: ... (-1h2m)' formats) -> {pkg: {op: {"mode": str, "ago": seconds|None}}}."""
    res = {}
    pkg, cur = None, None
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if re.match(r"^Uid \S+:$", s):
            pkg, cur = None, None
            continue
        m = re.match(r"^Package (\S+):$", s)
        if m:
            pkg, cur = m.group(1), None
            res.setdefault(pkg, {})
            continue
        if pkg is None:
            continue
        m = re.match(r"^([A-Z][A-Z0-9_]+): mode=(\w+)(.*)$", s)  # old format
        if m:
            op, mode, rest = m.groups()
            t = re.search(r"\btime=([+\-]?[\dhmsd]+) ago", rest)
            res[pkg][op] = {"mode": mode, "ago": parse_duration(t.group(1)) if t else None}
            cur = None
            continue
        m = re.match(r"^([A-Z][A-Z0-9_]+) \((\w+)", s)  # new format header
        if m:
            cur = m.group(1)
            res[pkg][cur] = {"mode": m.group(2), "ago": None}
            continue
        if cur and s.startswith("Access:"):
            t = re.search(r"\(-([\dhmsd]+)\)", s)
            ago = parse_duration(t.group(1)) if t else None
            old = res[pkg][cur]["ago"]
            if ago is not None and (old is None or ago < old):
                res[pkg][cur]["ago"] = ago
    return res


def ops_with_mode(appops, op, mode="allow"):
    return sorted(p for p, ops in appops.items() if (ops.get(op) or {}).get("mode") == mode)


# --------------------------------------------------------------------------
# reading the device
# --------------------------------------------------------------------------

SU_PATHS = ("/system/xbin/su", "/system/bin/su", "/sbin/su", "/su/bin/su", "/system/sbin/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/debug_ramdisk/su")
SU_SENTINEL = "__ADBM_SU_DONE__"
# Root managers, by package name. Magisk can hide its own app under a random
# name, so NOT finding one of these is never proof of "no root".
ROOT_MANAGER_APPS = ("com.topjohnwu.magisk", "io.github.vvb2060.magisk", "io.github.huskydg.magisk",
                     "eu.chainfire.supersu", "com.koushikdutta.superuser", "me.weishu.kernelsu",
                     "me.bmax.apatch")

# which facts["failed"] keys each access category is read from
ACCESS_SOURCES = {"accessibility": ("setting:accessibility",), "notifications": ("setting:notifications",),
                  "sms": ("setting:sms",), "admin": ("admins",),
                  "overlay": ("appops",), "usage": ("appops",), "install": ("appops",)}


def unread(facts, *keys):
    """Which of these reads failed (facts from older callers have no 'failed')."""
    f = facts.get("failed") or {}
    return [k for k in keys if k in f]


def root_signals(facts):
    """Root evidence, shared by the checkup AND the snapshot so they always agree.

    Returns (evidence, complete, manager_apps):
      evidence     - positive root evidence: an su program present on the device
                     (still not proof that root works - stated in the wording);
      complete     - False if the su check couldn't run: then "no evidence" means
                     "don't know", never "not rooted";
      manager_apps - root manager packages installed. Kept SEPARATE on purpose: an
                     installed manager doesn't prove root is installed or active
                     (it can be inactive, and a package name can be faked), so it is
                     never counted as root evidence."""
    evidence = ["su program at " + x for x in facts.get("su") or []]
    managers = [x for x in ROOT_MANAGER_APPS if x in (facts.get("apps") or {})]
    return evidence, not unread(facts, "su"), managers


def boot_state(vb, flash_locked, vbmeta):
    """One interpretation of verified boot, used by the checkup AND device info.

    ro.boot.verifiedbootstate is authoritative when present:
      green  -> locked bootloader, system verified with the maker's key
      yellow -> locked bootloader, system verified with a CUSTOM key the owner
                enrolled (custom ROM, re-locked) - NOT the same as unlocked
      orange -> bootloader unlocked, verification not enforced
      red    -> verification FAILED (corrupt or tampered system)
    Without it, ro.boot.flash.locked / ro.boot.vbmeta.device_state decide.
    Precedence when signals disagree (security-sensitive - keep it this way):
      - red always wins ("failed"): a failed integrity check is the most serious
        state, and lock flags can't make it better;
      - flash.locked and vbmeta.device_state are evaluated independently; if
        either says unlocked, the lock properties say unlocked - even when the
        other says locked (that contradiction is recorded too);
      - green/yellow + flash.locked=0 or vbmeta=unlocked -> "unlocked" (the less
        safe reading wins), conflict recorded;
      - orange + flash.locked=1 or vbmeta=locked -> stays "unlocked" (orange is
        the less safe reading), conflict recorded.
    Returns {"state": locked|custom_key|unlocked|failed|unknown, "conflict": text}."""
    vb, fl, vm = (vb or "").strip().lower(), (flash_locked or "").strip(), (vbmeta or "").strip().lower()
    # each lock property is evaluated on its own; if they contradict each other,
    # "unlocked" wins (the less safe reading) and the contradiction is recorded
    said = {}
    if fl in ("0", "1"):
        said["flash.locked=" + fl] = "locked" if fl == "1" else "unlocked"
    if vm in ("locked", "unlocked"):
        said["vbmeta.device_state=" + vm] = vm
    votes = set(said.values())
    lock_says = "unlocked" if "unlocked" in votes else ("locked" if votes else "")
    flags = ", ".join(sorted(said))
    notes = []
    if len(votes) > 1:
        notes.append("lock properties contradict each other (%s) - treated as unlocked" % flags)
    state = {"green": "locked", "yellow": "custom_key", "orange": "unlocked", "red": "failed"}.get(vb)
    if state is None:
        state = lock_says or "unknown"
    elif state == "failed":
        if said:            # red always wins; say exactly what the flags claimed
            notes.append("verifiedbootstate=red wins over %s" % flags)
    elif lock_says == "unlocked" and state in ("locked", "custom_key"):
        notes.append("verifiedbootstate=%s but %s says unlocked" % (
            vb, ", ".join(k for k, v in sorted(said.items()) if v == "unlocked")))
        state = "unlocked"          # the less safe reading wins when signals disagree
    elif lock_says == "locked" and state == "unlocked":
        notes.append("verifiedbootstate=orange but %s says locked" % flags)
    return {"state": state, "conflict": "; ".join(notes)}

def collect(shell, apps, sockets=None):
    """Everything the quick checkup needs from the device, in one place.
    apps = the Apps tab's records (package -> dict). Returns a dict of raw facts.

    shell(cmd, timeout) must RAISE when a command fails (non-zero exit, adb error,
    timeout). Every read that fails is recorded in facts["failed"] {key: reason},
    so the checks can say "couldn't check" instead of turning an empty result into
    an all-clear. Keys: "prop:<name>", "setting:<name>", "selinux", "su", "nets",
    "admins", "appops"."""
    failed = {}

    def get(key, cmd, timeout=30, sentinel=None):
        try:
            out = shell(cmd, timeout) or ""
        except Exception as e:
            failed[key] = (str(e) or e.__class__.__name__).strip().splitlines()[-1][:200]
            return ""
        if sentinel is not None:
            if sentinel not in out:
                failed[key] = "the command's output was incomplete"
                return ""
            out = out.replace(sentinel, "")
        return out
    props = {}
    for key, prop in (("release", "ro.build.version.release"), ("sdk", "ro.build.version.sdk"),
                      ("patch", "ro.build.version.security_patch"), ("crypto", "ro.crypto.state"),
                      ("vbstate", "ro.boot.verifiedbootstate"), ("flash_locked", "ro.boot.flash.locked"),
                      ("vbmeta", "ro.boot.vbmeta.device_state"), ("debuggable", "ro.debuggable"),
                      ("adb_tcp", "service.adb.tcp.port"), ("adb_tcp2", "persist.adb.tcp.port"),
                      ("model", "ro.product.model"), ("maker", "ro.product.manufacturer")):
        props[key] = get("prop:" + key, "getprop " + prop).strip()
    settings = {}
    for key, ns, name in (("accessibility", "secure", "enabled_accessibility_services"),
                          ("notifications", "secure", "enabled_notification_listeners"),
                          ("sms", "secure", "sms_default_application"),
                          ("unknown_sources", "secure", "install_non_market_apps"),
                          ("unknown_sources_g", "global", "install_non_market_apps"),
                          ("http_proxy", "global", "http_proxy"),
                          ("proxy_host", "global", "global_http_proxy_host"),
                          ("proxy_port", "global", "global_http_proxy_port"),
                          ("private_dns_mode", "global", "private_dns_mode"),
                          ("private_dns_host", "global", "private_dns_specifier"),
                          ("always_on_vpn", "secure", "always_on_vpn_app"),
                          ("adb_wifi", "global", "adb_wifi_enabled"),
                          ("dev_options", "global", "development_settings_enabled"),
                          ("verify_adb", "global", "verifier_verify_adb_installs"),
                          ("package_verifier", "global", "package_verifier_enable")):
        settings[key] = _clean(get("setting:" + key, "settings get %s %s" % (ns, name)))
    selinux = get("selinux", "getenforce").strip()
    # A shell loop exits with its LAST step's status, which is "not found" for almost
    # every device - so success is proven by a sentinel, not by the exit code.
    su = get("su", "for p in " + " ".join(SU_PATHS) + "; do [ -e $p ] && echo $p; done; "
             "echo " + SU_SENTINEL, sentinel=SU_SENTINEL).split()
    nets = get("nets", "ls /sys/class/net").split()
    admins_raw = get("admins", "dumpsys device_policy", 60)
    admins = []
    for m in re.finditer(r"ComponentInfo\{([\w.]+)/", admins_raw):
        if m.group(1) not in admins:
            admins.append(m.group(1))
    appops_raw = get("appops", "dumpsys appops", 120)
    if "appops" not in failed and not appops_raw.strip():
        failed["appops"] = "the device returned nothing"
    return {"failed": failed, "props": props, "settings": settings, "selinux": selinux, "su": su,
            "vpn_ifaces": [n for n in nets if n.startswith(("tun", "ppp", "ipsec", "wg"))],
            "admins": admins, "appops": parse_appops(appops_raw), "apps": apps,
            "sockets": sockets or [], "appops_raw": appops_raw}


def launcher_packages(shell, pkgs):
    """Which of `pkgs` have an icon in the app drawer.

    Returns (set, method). method is the discovery technique that worked
    ("query-activities" or "per-package"), or None if discovery FAILED entirely
    (every command errored). Callers must treat method is None as "unknown" and
    NOT as "every app is hidden" - an empty set with a non-None method does mean
    "none of these have a launcher icon"."""
    try:
        out = shell("cmd package query-activities --brief -a android.intent.action.MAIN "
                    "-c android.intent.category.LAUNCHER", 60) or ""
    except Exception:
        out = ""
    found = set(m.group(1) for m in re.finditer(r"(?m)^\s*([A-Za-z][\w.]*)/[\w.$]+\s*$", out))
    if found:
        return found & set(pkgs), "query-activities"
    # query-activities produced nothing usable. It may have genuinely returned no
    # rows, OR failed WITHOUT raising (the shell wrapper can hide the exit code and
    # Android prints errors to stdout). Don't trust error-shaped output as an
    # authoritative "none" - fall back to per-package dumps, and only treat a dump
    # as evidence when it actually looks like a package dump.
    have, any_ok = set(), False
    for p in pkgs:
        try:
            dump = shell("dumpsys package " + p, 30) or ""
        except Exception:
            continue
        if _looks_like_cmd_error(dump) or not _looks_like_pkg_dump(dump):
            continue   # failed or empty/unusable output -> not evidence of "no icon"
        any_ok = True
        if "android.intent.category.LAUNCHER" in dump:
            have.add(p)
    if have:
        return have, "per-package"
    if any_ok:
        return set(), "per-package"       # at least one real dump, none had a launcher
    return set(), None                     # discovery failed entirely -> caller: unknown


def _looks_like_cmd_error(text):
    """True if shell output looks like a command failure rather than real data
    (Android/toybox print these to stdout, so a non-raising shell hides them)."""
    t = (text or "").strip()
    if not t:
        return False
    head = t[:200].lower()
    return any(s in head for s in ("error:", "exception", "not found", "unknown command",
                                   "no such", "usage:", "permission denial", "can't find",
                                   "cannot find", "inaccessible or not found"))


def _looks_like_pkg_dump(text):
    """True if a 'dumpsys package <pkg>' output looks like a genuine package dump."""
    t = text or ""
    return ("Package [" in t) or ("codePath=" in t) or ("versionName=" in t)


# --------------------------------------------------------------------------
# turning facts into findings
# --------------------------------------------------------------------------

def label_of(apps, labeler, pkg):
    try:
        return labeler(pkg)
    except Exception:
        return pkg


def installer_text(inst):
    inst = _clean(inst)
    if inst in STORES:
        return STORES[inst], "store"
    if inst in FILE_INSTALLERS:
        return "installed from an APK file", "file"
    if not inst:
        return "installed by a computer (ADB) or unknown source", "unknown"
    return "installed by the app %s" % inst, "other"


def _yesno(v, yes, no, unknown="not reported by the device"):
    v = _clean(v).lower()
    if v in ("1", "true", "yes", "locked", "green"):
        return yes
    if v in ("0", "false", "no", "unlocked", "orange"):
        return no
    return unknown


# Per-device rooting notes, keyed by codename. Each entry is what we actually
# know for that model; anything not listed falls back to chip/maker heuristics.
# Sources are shown to the user so they can verify before doing anything.
ROOT_NOTES = {
    "serenity": {
        "names": "Redmi A5, Redmi A7, POCO C71 (they share this codename)",
        "soc": "Unisoc T7250 (ums9230e)",
        # the codename alone isn't enough (several models share it): the notes are
        # only presented as applying when the device ALSO reports this chip
        "chip_tokens": ("ums9230",),
        "mi_unlock": "blocked",
        "method": "unisoc_cve",
        "pc_os": "Windows",       # what the documented tools for this method run on
        "twrp": "none known",
        "risk": "high",
        "notes": [
            "Xiaomi's normal unlock does NOT work here: Mi Unlock reports 'device not supported' "
            "and 'fastboot oem unlock' fails (Err:0xffffffff).",
            "The working route is a PC exploit of the Unisoc chip (CVE-2022-38694): a Windows tool "
            "writes a patched bootloader over a low-level download mode.",
            "Root afterwards is Magisk: extract boot.img from the stock firmware, patch it in the "
            "Magisk app, flash the patched boot.img.",
            "No TWRP/OrangeFox build is confirmed for this codename - people stay on a "
            "Magisk-patched boot image, not a custom recovery.",
            "This is recent and most reports are for the Redmi A5 sibling. Confirm your exact model "
            "on the A5 threads before trusting any step.",
        ],
        "links": [
            ("CVE-2022-38694 Unisoc unlock tools (TomKing062)",
             "https://github.com/TomKing062/CVE-2022-38694_unlock_bootloader/releases"),
            ("Redmi A5 'serenity' unlock + GSI writeup",
             "https://gist.github.com/yetanotherf0rked/5de83f4178f0aa20daf03012b9baf0a9"),
            ("XDA: Unisoc T606/ums9230 bootloader unlock threads",
             "https://xdaforums.com/tags/unisoc/"),
            ("Magisk (official)", "https://github.com/topjohnwu/Magisk/releases"),
        ],
    },
}

# Unisoc/Spreadtrum chip-name prefixes, matched against whole chip-name tokens
# (not anywhere inside a word).
UNISOC_PLATFORMS = ("ums", "sc98", "sc77", "sc96", "t606", "t612", "t616", "t610", "t618",
                    "t620", "t700", "t7250", "sp98", "sharkl")


def chip_tokens(info):
    """Lower-case chip identifiers the device reported (platform, board, SoC model)."""
    pr = info.get("props", {}) or {}
    text = " ".join(pr.get(k, "") for k in ("ro.board.platform", "ro.product.board", "ro.soc.model"))
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def is_unisoc_chip(info):
    pr = info.get("props", {}) or {}
    if (pr.get("ro.soc.manufacturer") or "").strip().lower() in ("unisoc", "spreadtrum", "sprd"):
        return True
    return any(t.startswith(UNISOC_PLATFORMS) for t in chip_tokens(info))


def rooting_guidance(info):
    """A plain-words rooting summary for THIS device. Returns (lines, links).
    lines = [(level, text)]; link = (text, url). Never does anything - advice only.

    Claims are gated on evidence from the device itself:
      - a per-codename note is presented as applying only if the device ALSO
        reports the note's chip; otherwise it's shown as "may not apply";
      - for an unlisted Unisoc chip, CVE-2022-38694 is mentioned as something to
        CHECK (affects certain Unisoc chips), never as the way to unlock this one;
      - a PC operating system is named only where the specific method calls for it."""
    codename = (info.get("codename") or "").lower()
    pr = info.get("props", {}) or {}
    chip = pr.get("ro.board.platform", "") or pr.get("ro.product.board", "") or pr.get("ro.soc.model", "")
    toks = chip_tokens(info)
    is_unisoc = is_unisoc_chip(info)
    boot = info.get("bootloader")
    lines, links = [], []
    note = ROOT_NOTES.get(codename)
    note_applies = bool(note) and any(t.startswith(c) for c in note.get("chip_tokens", ()) for t in toks)
    pc_os = ""

    if boot == "UNLOCKED":
        lines.append((OK, "The bootloader is already UNLOCKED. You can install Magisk to root: "
                           "extract boot.img from the stock firmware for this exact build, patch it in "
                           "the Magisk app, and flash the patched image."))
    elif boot == "LOCKED":
        lines.append((WARN, "The bootloader is LOCKED - it must be unlocked first, and unlocking "
                            "erases everything on the phone."))
    else:
        lines.append((INFO, "The bootloader lock state couldn't be read here - check it in fastboot "
                            "mode (fastboot getvar unlocked)."))

    if note and not note_applies:
        lines.append((WARN, "The codename '%s' matches a known entry (%s, %s), but this device reports "
                            "a different or unknown chip (%s). Several phones can share a codename, so "
                            "the notes for that entry may NOT apply here - they are not shown as advice."
                      % (codename, note["names"], note["soc"], chip or "not reported")))
        links = [("Magisk (official)", "https://github.com/topjohnwu/Magisk/releases")]
    elif note:
        pc_os = note.get("pc_os", "")
        lines.append((INFO, "Known device: %s - %s (codename and chip both match)." % (note["names"], note["soc"])))
        if note["mi_unlock"] == "blocked" and boot != "UNLOCKED":
            lines.append((BAD, "Xiaomi's official Mi Unlock does NOT work on this model."))
        for n in note["notes"]:
            lvl = WARN if n.lower().startswith(("xiaomi's normal", "this is recent", "no twrp")) else INFO
            lines.append((lvl, n))
        if note["risk"] == "high":
            lines.append((BAD, "This method writes low-level partitions with an exploit tool. A "
                               "mistake or wrong firmware can permanently brick the phone. Download the "
                               "correct stock firmware for '%s' FIRST, as your recovery safety net."
                          % codename))
        links = list(note["links"])
    else:
        # no specific entry: fall back to what the chip/maker implies
        if is_unisoc:
            text = ("This is a Unisoc (Spreadtrum) chip (%s). There are no notes for this exact model. "
                    "Some Unisoc chips have a known boot-ROM flaw (CVE-2022-38694) that community tools "
                    "use to unlock the bootloader - but whether it applies to THIS chip isn't known here. "
                    "Check the tool's list of supported chips before anything; if yours isn't listed, "
                    "don't try it. Exploit-based unlocking is higher-risk than a normal unlock."
                    % (chip or "model not reported"))
            links = []
            if info.get("is_xiaomi"):
                pc_os = "Windows"     # the official route below: Xiaomi's Mi Unlock tool
                text += (" Xiaomi's official Mi Unlock tool (Windows) may or may not support this model - "
                         "try that official route first.")
                links.append(("Xiaomi Mi Unlock (official) - try this first", "https://en.miui.com/unlock/"))
            lines.append((WARN, text))
            links += [("CVE-2022-38694 Unisoc unlock tools (TomKing062) - check the supported chips",
                       "https://github.com/TomKing062/CVE-2022-38694_unlock_bootloader/releases"),
                      ("XDA: Unisoc unlock threads", "https://xdaforums.com/tags/unisoc/"),
                      ("Magisk (official)", "https://github.com/topjohnwu/Magisk/releases")]
        elif info.get("is_xiaomi"):
            pc_os = "Windows"     # Xiaomi's official Mi Unlock tool
            lines.append((INFO, "On Xiaomi, unlocking normally uses Xiaomi's Mi Unlock tool (Windows) "
                               "with your Mi account and a waiting period Xiaomi sets."))
            links = [("Xiaomi Mi Unlock (official)", "https://en.miui.com/unlock/"),
                     ("Magisk (official)", "https://github.com/topjohnwu/Magisk/releases")]
        else:
            lines.append((INFO, "No device-specific notes. Look up the codename '%s' plus 'bootloader "
                               "unlock' and 'Magisk' before doing anything." % (codename or "?")))
            links = [("Magisk (official)", "https://github.com/topjohnwu/Magisk/releases")]

    if info.get("arb"):
        lines.append((BAD, "Anti-rollback is active: never flash firmware older than what's on the "
                           "phone, or it can brick permanently."))
    tail = ("This app only shows this guidance and can check the bootloader state. It never unlocks, "
            "flashes or roots - those are done with separate PC tools")
    if pc_os:
        tail += "; the tools for this method run on %s" % pc_os
    lines.append((INFO, tail + "."))
    return lines, links


def device_info(shell):
    """Read the device's real identity + rooting-relevant facts. shell(cmd,timeout)->str.
    Returns a list of (group, [(label, value, note)]) and a raw {prop: value} map."""
    def g(prop):
        try:
            return (shell("getprop " + prop, 15) or "").strip()
        except Exception:
            return ""
    props = {}
    for prop in ("ro.product.manufacturer", "ro.product.brand", "ro.product.model",
                 "ro.product.name", "ro.product.device", "ro.product.marketname",
                 "ro.product.odm.marketname", "ro.boot.product.hardware.sku", "ro.boot.hardware.sku",
                 "ro.product.board", "ro.board.platform", "ro.product.cpu.abi",
                 "ro.soc.model", "ro.soc.manufacturer",
                 "ro.build.version.release", "ro.build.version.sdk", "ro.build.version.incremental",
                 "ro.build.id", "ro.build.display.id", "ro.build.version.security_patch",
                 "ro.build.date", "ro.build.type", "ro.build.tags", "ro.build.fingerprint",
                 "ro.miui.ui.version.name", "ro.mi.os.version.name", "ro.mi.os.version.incremental",
                 "ro.build.version.opporom", "ro.vivo.os.version", "ro.build.version.emui",
                 "ro.boot.flash.locked", "ro.boot.verifiedbootstate", "ro.boot.vbmeta.device_state",
                 "ro.boot.warranty_bit", "ro.warranty_bit", "ro.secureboot.lockstate",
                 "ro.boot.cross_region", "ro.boot.hwc", "ro.boot.hwcountry",
                 "ro.miui.region", "ro.product.locale", "ro.boot.dynamic_partitions",
                 "ro.boot.slot_suffix", "ro.build.ab_update", "ro.virtual_ab.enabled",
                 "ro.boot.bootloader", "ro.bootloader",
                 "ro.boot.ara_version", "ro.boot.arb_version", "ro.minarb"):
        v = g(prop)
        if v:
            props[prop] = v

    maker = props.get("ro.product.manufacturer") or props.get("ro.product.brand") or ""
    is_xiaomi = maker.lower() in ("xiaomi", "redmi", "poco") or \
        "xiaomi" in (props.get("ro.product.brand", "") + props.get("ro.build.tags", "")).lower()
    codename = props.get("ro.product.device") or props.get("ro.boot.product.hardware.sku") or ""
    marketname = (props.get("ro.product.marketname") or props.get("ro.product.odm.marketname")
                  or props.get("ro.product.model") or "")
    miui = (props.get("ro.mi.os.version.name") and "HyperOS " + props["ro.mi.os.version.name"]) or \
           (props.get("ro.miui.ui.version.name") and "MIUI " + props["ro.miui.ui.version.name"]) or ""
    miui_build = props.get("ro.mi.os.version.incremental") or props.get("ro.build.version.incremental") or ""

    # bootloader locked state - same interpretation as the security checkup
    bs = boot_state(props.get("ro.boot.verifiedbootstate"), props.get("ro.boot.flash.locked"),
                    props.get("ro.boot.vbmeta.device_state"))
    if bs["state"] == "unknown":
        bootloader = _yesno(props.get("ro.secureboot.lockstate", ""), "LOCKED", "UNLOCKED")
    else:
        bootloader = {"locked": "LOCKED", "custom_key": "LOCKED", "unlocked": "UNLOCKED",
                      "failed": "VERIFICATION FAILED"}[bs["state"]]
    arb = props.get("ro.boot.arb_version") or props.get("ro.boot.ara_version") or props.get("ro.minarb") or ""

    identity = [("Maker", maker or "?", ""),
                ("Marketing name", marketname or "?",
                 "the name on the box - several phones can share it, so it isn't enough on its own"),
                ("Internal codename", codename or "?",
                 "THIS is what rooting guides and TWRP/firmware are keyed to - use this, not the box name"),
                ("Model number", props.get("ro.product.model", "?"), ""),
                ("Android version", "%s (API %s)" % (props.get("ro.build.version.release", "?"),
                                                     props.get("ro.build.version.sdk", "?")), ""),
                ("System software", miui or "stock Android", ""),
                ("Software build", miui_build or props.get("ro.build.display.id", "?"), ""),
                ("Security patch", props.get("ro.build.version.security_patch", "?"), ""),
                ("Chipset", props.get("ro.board.platform") or props.get("ro.product.board", "?"), ""),
                ("CPU", props.get("ro.product.cpu.abi", "?"), "")]

    region = props.get("ro.miui.region") or props.get("ro.boot.hwcountry") or props.get("ro.boot.hwc") or ""
    rooting = []
    rooting.append(("Bootloader", bootloader + (" (custom key - yellow)" if bs["state"] == "custom_key" else ""),
                    ("locked, but the system is signed with the owner's own key (custom ROM that was "
                     "re-locked)" if bs["state"] == "custom_key" else
                     "the system failed its integrity check at boot - don't flash anything until you know "
                     "why" if bs["state"] == "failed" else
                     "must be UNLOCKED before any root is possible; unlocking wipes the phone")
                    + ("  [signals disagree: %s]" % bs["conflict"] if bs["conflict"] else "")))
    if region:
        rooting.append(("Region", region,
                        "Xiaomi's unlock wait and rules differ by region" if is_xiaomi else ""))
    if arb:
        rooting.append(("Anti-rollback index", arb,
                        "\u26d4 set on this device - flashing older firmware can PERMANENTLY brick it. "
                        "Only ever flash firmware for this exact codename, same or newer."))
    warranty = props.get("ro.boot.warranty_bit") or props.get("ro.warranty_bit")
    if warranty == "1":
        rooting.append(("Warranty bit", "already tripped", "the bootloader was unlocked at some point"))
    # A/B slots and dynamic partitions are DIFFERENT things: many non-A/B phones
    # have dynamic partitions. Only a slot suffix / ab_update says A/B.
    suffix = props.get("ro.boot.slot_suffix", "")
    if suffix or props.get("ro.build.ab_update") == "true":
        slots = "yes (A/B)" + (", running slot %s" % suffix.lstrip("_") if suffix else "")
        if props.get("ro.virtual_ab.enabled") == "true":
            slots += ", virtual A/B"
    else:
        slots = "not detected"
    rooting.append(("A/B slots", slots,
                    "affects how TWRP/Magisk are installed (patched boot image vs recovery)"))
    if props.get("ro.boot.dynamic_partitions") == "true":
        rooting.append(("Dynamic partitions", "yes",
                        "system/vendor live inside one 'super' partition - flash them with fastbootd, "
                        "not plain fastboot. This does NOT mean the phone has A/B slots"))

    groups = [("What this device is", identity), ("Rooting-relevant facts", rooting)]
    return {"groups": groups, "props": props, "is_xiaomi": is_xiaomi, "codename": codename,
            "marketname": marketname, "miui": miui, "bootloader": bootloader,
            "arb": bool(arb and arb not in ("0", "")), "region": region}


def check_device(facts):
    out = []
    p, st = facts["props"], facts["settings"]
    sdk = int(p["sdk"]) if p.get("sdk", "").isdigit() else 0
    # security patch age
    patch = p.get("patch", "")
    m = re.match(r"(\d{4})-(\d{2})(?:-(\d{2}))?", patch)
    if m:
        y, mo = int(m.group(1)), int(m.group(2))
        now = time.localtime()
        months = (now.tm_year - y) * 12 + (now.tm_mon - mo)
        if months > 12:
            out.append(finding("device", BAD, "Security updates are %d years old (%s)" % (months // 12, patch),
                               "Known security holes found since then are not fixed on this device, and "
                               "won't be. This is a bigger risk than any single app.",
                               "Avoid banking/sensitive apps on it, don't install apps from unknown "
                               "sources, or consider a maintained custom ROM (e.g. LineageOS) if your model "
                               "is supported.", "ro.build.version.security_patch=%s" % patch, key="patch"))
        elif months > 3:
            out.append(finding("device", WARN, "Security update is %d months old (%s)" % (months, patch),
                               "Recent fixes are missing.", "Settings > System > System update.",
                               "ro.build.version.security_patch=%s" % patch, key="patch"))
        else:
            out.append(finding("device", OK, "Security updates are recent (%s)" % patch, key="patch",
                               tech="ro.build.version.security_patch=%s" % patch))
    elif unread(facts, "prop:patch"):
        out.append(finding("device", INFO, "Couldn't read the security patch level",
                           "The device didn't answer this question, so it isn't known how old its "
                           "security updates are.", "Run the checkup again.",
                           "getprop ro.build.version.security_patch failed: %s" % facts["failed"]["prop:patch"],
                           key="patch"))
    else:
        out.append(finding("device", WARN if sdk and sdk < 23 else INFO,
                           "Security patch level unknown (Android %s)" % (p.get("release") or "?"),
                           "This Android version doesn't report a patch date - it is most likely very old.",
                           key="patch"))
    # encryption
    crypto = p.get("crypto", "")
    if crypto == "encrypted":
        out.append(finding("device", OK, "Storage is encrypted", key="crypto", tech="ro.crypto.state=encrypted"))
    elif crypto == "unencrypted":
        out.append(finding("device", BAD, "Storage is NOT encrypted",
                           "Anyone who gets the device can read its data by connecting it to a computer.",
                           "Settings > Security > Encrypt tablet/phone (needs a screen lock, takes about "
                           "an hour, keep it charging).", "ro.crypto.state=unencrypted", key="crypto"))
    elif unread(facts, "prop:crypto"):
        out.append(finding("device", INFO, "Couldn't check storage encryption",
                           "The device didn't answer this question, so it isn't known whether its storage "
                           "is encrypted.", "Run the checkup again.",
                           "getprop ro.crypto.state failed: %s" % facts["failed"]["prop:crypto"], key="crypto"))
    # SELinux
    se = facts["selinux"]
    if se.lower() == "enforcing":
        out.append(finding("device", OK, "SELinux protection is on (enforcing)", key="selinux"))
    elif se.lower() == "permissive":
        out.append(finding("device", BAD, "SELinux protection is OFF (permissive)",
                           "Android's main wall between apps and the system is not enforced. Usually "
                           "caused by rooting or a modified system.", "", "getenforce=Permissive", key="selinux"))
    elif unread(facts, "selinux"):
        out.append(finding("device", INFO, "Couldn't check SELinux protection",
                           "The device didn't answer, so it isn't known whether this protection is on.",
                           "Run the checkup again.", "getenforce failed: %s" % facts["failed"]["selinux"],
                           key="selinux"))
    # root - same evidence the snapshot uses (root_signals). A root manager APP is
    # reported separately and never counts as confirmed root.
    evidence, complete, managers = root_signals(facts)
    if evidence:
        out.append(finding("device", WARN, "Signs of root: an su program is present",
                           "An su program can be used to request root access. Its presence is a sign of "
                           "root-related configuration, although this check does not establish that root "
                           "access currently works. Apps that do get root can do anything, invisibly - "
                           "including hiding from this checkup. Fine if you rooted it yourself on purpose.",
                           "Only grant root to apps you trust completely.", "; ".join(evidence), key="root"))
    elif not complete:
        out.append(finding("device", INFO, "Couldn't fully check for root",
                           "The check for root tools didn't finish, so this is NOT an all-clear.",
                           "Run the checkup again.", "su check failed: %s" % facts["failed"]["su"], key="root"))
    elif managers:
        out.append(finding("device", INFO, "No su program found - root not confirmed",
                           "None of the usual su programs is present. A root manager app IS installed "
                           "(see below), so root may still be active in a hidden form, or the app may be "
                           "installed without root.", key="root",
                           tech="su paths checked: %s" % " ".join(SU_PATHS)))
    else:
        out.append(finding("device", OK, "No common signs of root",
                           "No su program and no known root manager app were found. Root can still be "
                           "hidden (for example Magisk with its app renamed), so this checks the usual "
                           "signs only.", key="root",
                           tech="su paths checked: %s; root manager apps: %s" % (
                               " ".join(SU_PATHS), " ".join(ROOT_MANAGER_APPS))))
    if managers:
        out.append(finding("device", WARN, "Root manager app installed: %s" % ", ".join(managers),
                           "This kind of app manages root access. Having it installed does NOT confirm "
                           "the device is rooted - root may be inactive, or this may be a different app "
                           "using the same name. But it's worth knowing about: if you didn't install it, "
                           "find out who did.",
                           "If you don't use root, uninstall it.",
                           "matched package names: %s" % " ".join(managers), key="root-manager"))
    # bootloader / verified boot - same interpretation as device info (boot_state)
    vb = p.get("vbstate", "")
    bs = boot_state(vb, p.get("flash_locked"), p.get("vbmeta"))
    tech = "verifiedbootstate=%s flash.locked=%s vbmeta=%s%s" % (
        vb or "-", p.get("flash_locked") or "-", p.get("vbmeta") or "-",
        ("  conflict: " + bs["conflict"]) if bs["conflict"] else "")
    if bs["state"] == "failed":
        out.append(finding("device", BAD, "Verified boot FAILED (red)",
                           "At start-up the system didn't pass its integrity check - it is damaged or was "
                           "modified. The device may not be trustworthy.",
                           "Reinstall the official firmware for this exact model before using it for "
                           "anything sensitive.", tech, key="boot"))
    elif bs["state"] == "unlocked":
        out.append(finding("device", WARN, "The bootloader is unlocked",
                           "The system can be replaced without wiping data, so someone with the device in "
                           "hand could plant a modified system. Normal on custom-ROM devices.",
                           tech=tech, key="boot"))
    elif bs["state"] == "custom_key":
        out.append(finding("device", INFO, "Bootloader locked with a custom key (yellow)",
                           "The bootloader is locked and the system IS verified at every start - but "
                           "against a key the owner installed, not the maker's. This is what a custom ROM "
                           "that was re-locked looks like. Fine if you did that yourself; if you didn't, "
                           "someone replaced the system.", tech=tech, key="boot"))
    elif bs["state"] == "locked":
        out.append(finding("device", OK, "Bootloader locked / verified boot OK", key="boot", tech=tech))
    elif unread(facts, "prop:vbstate", "prop:flash_locked", "prop:vbmeta") == \
            ["prop:vbstate", "prop:flash_locked", "prop:vbmeta"]:
        out.append(finding("device", INFO, "Couldn't check the bootloader",
                           "The device didn't answer, so it isn't known whether it's locked.",
                           "Run the checkup again.", tech, key="boot"))
    # ADB over network
    tcp = [x for x in (p.get("adb_tcp"), p.get("adb_tcp2")) if x and x not in ("0", "-1")]
    listen5555 = any(s.get("kind") == "listen" and s.get("local_port") == 5555 and s.get("proto") == "tcp"
                     and not s.get("local_ip", "").startswith("127.") and s.get("local_ip") != "::1"
                     for s in facts.get("sockets", []))
    if tcp or listen5555 or st.get("adb_wifi") == "1":
        out.append(finding("device", BAD, "ADB over the network is ON",
                           "Anyone on the same network can try to connect and fully control the device.",
                           "Turn off 'Wireless debugging' in Developer options, or run 'adb usb'.",
                           "service.adb.tcp.port=%s adb_wifi_enabled=%s listening:5555=%s"
                           % (p.get("adb_tcp") or "-", st.get("adb_wifi") or "-", listen5555), key="adbnet"))
    out.append(finding("device", INFO, "USB debugging is on (this program needs it)",
                       "While it's on, a computer you have approved can control the device over USB.",
                       "Switch it off in Developer options when you're done.", key="usbdebug"))
    # unknown sources (Android 7 and older: one global switch)
    if sdk and sdk < 26 and (st.get("unknown_sources") == "1" or st.get("unknown_sources_g") == "1"):
        out.append(finding("device", WARN, "'Unknown sources' is allowed",
                           "Any app can install APK files that didn't come from an app store.",
                           "Settings > Security > Unknown sources > off (turn it on only while installing).",
                           key="unknown"))
    if st.get("package_verifier") == "0":
        out.append(finding("device", INFO, "App verification (Play Protect scan of installs) is off",
                           key="verifier", tech="package_verifier_enable=0"))
    # proxy
    if unread(facts, "setting:http_proxy", "setting:proxy_host"):
        out.append(finding("device", INFO, "Couldn't check for a network proxy",
                           "The device didn't answer, so a proxy can't be ruled out.", "Run the checkup again.",
                           "failed: %s" % ", ".join(unread(facts, "setting:http_proxy", "setting:proxy_host")),
                           key="proxy-unread"))
    proxy = st.get("http_proxy") or ""
    if (proxy and proxy not in (":0", "0")) or st.get("proxy_host"):
        shown = proxy if proxy and proxy != ":0" else "%s:%s" % (st.get("proxy_host"), st.get("proxy_port"))
        out.append(finding("device", BAD, "A network proxy is set: %s" % shown,
                           "Web traffic goes through that computer first. Fine if you set it up yourself; "
                           "malware and spyware use this to watch traffic.",
                           "If you don't know it: Settings > Wi-Fi > long-press the network > Modify > "
                           "Proxy: none.", "http_proxy=%s global_http_proxy_host=%s" % (proxy, st.get("proxy_host")),
                           key="proxy"))
    # private DNS
    mode = st.get("private_dns_mode")
    if mode == "hostname" and st.get("private_dns_host"):
        out.append(finding("device", INFO, "Private DNS: %s" % st["private_dns_host"],
                           "Website name lookups are encrypted and go to that provider.", key="dns"))
    return out


def access_lists(facts):
    """{category: [packages]} for the special switches."""
    ao = facts["appops"]
    st = facts["settings"]
    sms = components(st.get("sms")) or ([st["sms"]] if st.get("sms") and "/" not in st["sms"] else [])
    return {"accessibility": components(st.get("accessibility")),
            "admin": list(facts["admins"]),
            "notifications": components(st.get("notifications")),
            "overlay": ops_with_mode(ao, "SYSTEM_ALERT_WINDOW"),
            "usage": ops_with_mode(ao, "GET_USAGE_STATS"),
            "install": ops_with_mode(ao, "REQUEST_INSTALL_PACKAGES"),
            "sms": sms}


def check_access(facts, access, launcher, labeler):
    out = []
    apps = facts["apps"]
    for cat, pkgs in access.items():
        name, what, how = ACCESS_INFO[cat]
        for p in pkgs:
            a = apps.get(p, {})
            unknown = not a                          # not in the app list: unknown, never assumed system
            system = bool(a.get("system", False))
            inst_text, inst_kind = installer_text(a.get("installer", ""))
            hidden = (not system) and not unknown and launcher is not None and p not in launcher
            flags = []
            if not system and not unknown and inst_kind != "store":
                flags.append(inst_text)
            if hidden:
                flags.append("it has no icon in the app drawer")
            if unknown:
                level = WARN
            elif system:
                level = INFO
            elif flags and cat in ("accessibility", "admin", "notifications", "sms", "overlay"):
                level = BAD
            elif cat in ("overlay", "install", "sms"):
                level = INFO
            else:
                level = WARN
            detail = what
            if flags:
                detail += "\n\nAlso: " + "; ".join(flags) + "."
            if unknown:
                detail += ("\n\nThis app wasn't in the app list read from the phone (for example it belongs "
                           "to another user or work profile), so whether it's a system app couldn't be checked.")
            elif system:
                detail += "\n\nIt's a system app, which is normal for this kind of access."
            out.append(finding("access", level, "%s: %s" % (name, label_of(apps, labeler, p)), detail,
                               how, "category=%s package=%s installer=%s" % (cat, p, a.get("installer", "-")),
                               pkg=p, key="access:%s:%s" % (cat, p)))
    if facts["vpn_ifaces"] or facts["settings"].get("always_on_vpn"):
        out.append(finding("access", INFO, "A VPN is active%s" % (
            " (always-on: %s)" % facts["settings"]["always_on_vpn"] if facts["settings"].get("always_on_vpn") else ""),
            "All traffic goes through the VPN app and its servers. Good if it's yours; spyware sometimes "
            "uses a VPN to watch traffic.", "Settings > Network > VPN.",
            "interfaces: %s" % " ".join(facts["vpn_ifaces"]), key="vpn"))
    missing = sorted({ACCESS_INFO[c][0] for c, keys in ACCESS_SOURCES.items() if unread(facts, *keys)})
    if missing:
        out.append(finding("access", INFO, "Couldn't check some powerful switches",
                           "The device didn't answer for: %s. Apps holding those can't be listed, so "
                           "this section is NOT complete." % ", ".join(missing), "Run the checkup again.",
                           "failed reads: %s" % ", ".join(sorted({k for ks in ACCESS_SOURCES.values()
                                                                  for k in unread(facts, *ks)})),
                           key="access:unread"))
    elif not out:
        out.append(finding("access", OK, "No app holds any of these powerful switches", key="access:none"))
    return out


# --------------------------------------------------------------------------
# "connect the dots": several stalkerware signs on the SAME app
# --------------------------------------------------------------------------

# access that stalkerware relies on (reading the screen, notifications, messages,
# drawing over apps, staying impossible to uninstall, watching app usage)
PATTERN_ACCESS = ("accessibility", "notifications", "admin", "sms", "overlay", "usage")
_MARK = {True: "\u2714 yes", False: "\u2718 no", None: "? couldn't be checked"}


def _recent_use(facts, pkg, days=7):
    ops = (facts.get("appops") or {}).get(pkg) or {}
    used = []
    for op, word in USAGE_OPS.items():
        o = ops.get(op)
        if o and o.get("ago") is not None and o["ago"] <= days * 86400 and o.get("mode") != "ignore":
            used.append((o["ago"], word))
    return [w + " " + ago_text(t) for t, w in sorted(used)]


def _pattern_level(access, outside, hidden, boots):
    """BAD / WARN / None for one app's signs (True/False/None each). Only real
    combinations count: powerful access plus ONE other sign is already reported in
    the 'Powerful access' section, and starting at boot alone is very common."""
    persist = sum(1 for v in (outside, hidden, boots) if v is True)
    if access and persist >= 2:
        return BAD
    if not access and persist == 3:
        return WARN
    return None


def check_patterns(facts, access, launcher, labeler, boot):
    """One finding per user app that shows SEVERAL stalkerware signs at once:
    powerful access + installed outside a store + no launcher icon + starts at boot.
    Each sign alone is common and harmless; together they are the usual shape of
    stalkerware. Recent camera/microphone/location use is shown as supporting detail.

    launcher: set of packages with an icon, or None if that couldn't be read.
    boot: None if start-at-boot couldn't be read at all, else
          {"complete": bool, "pkgs": {pkg: True (can start at boot) / False (its
          start-up receivers are all switched off)}}. A package missing from "pkgs"
          has no start-up receiver - but only when "complete" is True.
    A sign that couldn't be read is never counted as absent: if it could raise the
    level, the app is still reported, as 'couldn't fully check'."""
    out = []
    apps = facts["apps"]
    access_unread = sorted({ACCESS_INFO[c][0] for c in PATTERN_ACCESS
                            if unread(facts, *ACCESS_SOURCES[c])})
    uncertain_origin = []        # apps where an unrecorded installer could change the result
    for p in sorted(pp for pp, a in apps.items() if not a.get("system") and not a.get("removed")):
        a = apps[p]
        inst_text, kind = installer_text(a.get("installer", ""))
        # no recorded installer (often 'adb install', but it can't be proven) is UNKNOWN, not sideloading
        outside = None if kind == "unknown" else kind != "store"
        hidden = None if launcher is None else p not in launcher
        if boot is None:
            boots = None
        elif p in boot["pkgs"]:
            boots = boot["pkgs"][p]
        else:
            boots = False if boot["complete"] else None
        held = [ACCESS_INFO[c][0] for c in PATTERN_ACCESS if p in (access.get(c) or ())]
        level = _pattern_level(held, outside, hidden, boots)
        # what it could be if every sign we couldn't read turned out to be present
        worst = _pattern_level(held or bool(access_unread), True if outside is None else outside,
                               True if hidden is None else hidden, True if boots is None else boots)
        if level is None and worst is None:
            continue
        lbl = label_of(apps, labeler, p)
        unknown_signs = [n for n, v in (("where it came from", outside), ("icon", hidden),
                                        ("start at boot", boots)) if v is None]
        if access_unread and not held:
            unknown_signs.append("powerful access")
        if level is None or worst != level:
            uncertain_origin += [p] if outside is None else []
        dots = ["Installed outside an app store: %s" % (
                    "? unknown - no installer was recorded (often an install from a computer)" if outside is None
                    else _MARK[outside] + (" (%s)" % inst_text if outside else "")),
                "No icon in the app drawer: %s" % _MARK[hidden],
                "Starts by itself when the phone boots: %s" % (
                    _MARK[boots] if boots is not False or p not in (boot or {}).get("pkgs", {})
                    else "\u2718 no (its start-up receivers are switched off)"),
                "Powerful access: %s" % (", ".join(held) if held else
                                         "? couldn't be checked" if access_unread else "\u2718 none")]
        used = _recent_use(facts, p)
        if used:
            dots.append("Used recently: " + ", ".join(used[:5]))
        if a.get("disabled"):
            dots.append("The whole app is currently turned OFF, so it can't run until it's turned on again.")
        if level is None:
            title = "Couldn't fully check: %s" % lbl
            sev = INFO
            lead = ("Some signs couldn't be read (%s). With them, this app could match the spyware "
                    "pattern - check it by hand." % ", ".join(unknown_signs))
        else:
            sev = level
            title = ("Looks like stalkerware: %s" if level == BAD else "Several warning signs: %s") % lbl
            lead = ("This app has powerful access AND hides or starts itself the way stalkerware does."
                    if level == BAD else
                    "Each sign alone is common, but together they are worth a look.")
            if unknown_signs and worst != level:
                lead += " Some signs couldn't be read (%s), so it could be more serious." % ", ".join(unknown_signs)
        detail = lead + "\n\n" + "\n".join("\u2022 " + d for d in dots)
        detail += ("\n\nKeyboards, launchers, parental-control and backup apps can legitimately have some "
                   "of these signs. What matters is whether YOU installed it and know what it does.")
        advice = ("If you don't recognise it: look it up (Apps tab > Ask AI) and remove it. If it's a device "
                  "administrator, take that away first (Settings > Security > Device admin apps). If you "
                  "think someone put it there to watch you, removing it may alert them - think about your "
                  "safety first and consider getting support before you act.")
        tech = "package=%s installer=%s hidden=%s boots=%s access=%s" % (
            p, a.get("installer") or "-", hidden, boots, ",".join(c for c in PATTERN_ACCESS
                                                                 if p in (access.get(c) or ())) or "-")
        out.append(finding("pattern", sev, title, detail, advice, tech, pkg=p, key="pattern:%s" % p))
    out.sort(key=lambda f: (LEVEL_RANK[f["level"]], f["title"].lower()))
    gaps = []
    if launcher is None:
        gaps.append("which apps hide their icon")
    if boot is None:
        gaps.append("which apps start at boot")
    elif not boot["complete"]:
        gaps.append("the full list of apps that start at boot")
    if access_unread:
        gaps.append("some powerful access (%s)" % ", ".join(access_unread))
    if uncertain_origin:
        gaps.append("where %d app(s) came from (no installer recorded)" % len(uncertain_origin))
    if gaps:
        out.append(finding("pattern", INFO, "This check is incomplete",
                           "The phone didn't answer for: %s. Apps can only be matched on what could be "
                           "read, so this is NOT an all-clear." % "; ".join(gaps),
                           "Run the checkup again; the Autorun tab shows the start-up list on its own.",
                           key="pattern:incomplete"))
    elif not out:
        out.append(finding("pattern", OK, "No app shows the spyware pattern",
                           "No app you installed combines powerful access with hiding its icon, coming "
                           "from outside a store or starting itself at boot.", key="pattern:none"))
    return out


SYSTEM_WORDS = ("system", "android", "service", "update", "settings", "security", "google")


def check_origin(facts, launcher, labeler):
    out = []
    apps = facts["apps"]
    users = sorted(p for p, a in apps.items() if not a.get("system") and not a.get("removed"))
    counts = {}
    for p in users:
        a = apps[p]
        text, kind = installer_text(a.get("installer", ""))
        counts[text] = counts.get(text, 0) + 1
        lbl = label_of(apps, labeler, p)
        hidden = launcher is not None and p not in launcher
        poses = p.startswith(("com.android.", "android.", "com.google.android.")) and kind != "store"
        word = any(w in lbl.lower() for w in SYSTEM_WORDS) and kind != "store" and lbl != p
        if poses:
            out.append(finding("origin", BAD, "Poses as a system part: %s" % lbl,
                               "Its name looks like Android or Google, but it was %s, not shipped with the "
                               "device or installed from a store. Malware does this to look harmless." % text,
                               "Look it up (Apps tab > Ask AI) and uninstall it if it isn't yours.",
                               "package=%s installer=%s" % (p, a.get("installer") or "-"), pkg=p,
                               key="origin:poses:%s" % p))
        elif hidden and kind != "store":
            out.append(finding("origin", WARN, "Hidden app from outside a store: %s" % lbl,
                               "It has no icon in the app drawer and was %s. Keyboards, plugins and "
                               "wallpapers legitimately have no icon - spyware hides the same way." % text,
                               "If you don't recognise it, check it in the Apps tab and remove it.",
                               "package=%s installer=%s" % (p, a.get("installer") or "-"), pkg=p,
                               key="origin:hidden:%s" % p))
        elif hidden:
            out.append(finding("origin", INFO, "No icon in the app drawer: %s" % lbl,
                               "From %s. Usually a keyboard, plugin, widget or service app." % text,
                               tech="package=%s" % p, pkg=p, key="origin:hidden:%s" % p))
        elif kind != "store":
            out.append(finding("origin", WARN if word else INFO, "Not from an app store: %s" % lbl,
                               "It was %s. That's not bad by itself, but these apps were never checked by "
                               "any store.%s" % (text, " Its name sounds like a system app." if word else ""),
                               "The 'Malware lookup' of a deep scan checks its file against virus databases.",
                               "package=%s installer=%s" % (p, a.get("installer") or "-"), pkg=p,
                               key="origin:outside:%s" % p))
    summary = ", ".join("%d %s" % (n, t if t.startswith("installed") else "from " + t)
                        for t, n in sorted(counts.items(), key=lambda kv: -kv[1]))
    out.insert(0, finding("origin", OK if not any(f["level"] in (WARN, BAD) for f in out) else INFO,
                          "%d app%s installed by you: %s" % (len(users), "" if len(users) == 1 else "s",
                                                             summary or "none"), key="origin:summary"))
    if launcher is None:
        out.append(finding("origin", INFO, "Couldn't check which apps hide their icon", key="origin:nolauncher"))
    return out


def check_usage(facts, launcher, labeler):
    out = []
    apps = facts["apps"]
    for p, ops in facts["appops"].items():
        used = []
        for op, word in USAGE_OPS.items():
            o = ops.get(op)
            if o and o.get("ago") is not None and o["ago"] <= 7 * 86400 and o.get("mode") != "ignore":
                used.append((o["ago"], word))
        if not used:
            continue
        used.sort()
        a = apps.get(p, {})
        system = a.get("system", True)
        hidden = (not system) and launcher is not None and p not in launcher
        _, kind = installer_text(a.get("installer", ""))
        sensors = any(w in ("camera", "microphone") for _, w in used)
        level = WARN if (not system and sensors and (hidden or kind != "store")) else INFO
        title = "%s - %s" % (label_of(apps, labeler, p),
                             ", ".join("%s %s" % (w, ago_text(t)) for t, w in used[:4]))
        detail = "\n".join("\u2022 used your %s %s" % (w, ago_text(t)) for t, w in used)
        detail += "\n\nIf you weren't using this app at that moment, ask yourself why it needed it."
        if level == WARN:
            detail += ("\n\nIt used the camera or microphone and %s."
                       % ("has no icon in the app drawer" if hidden else "isn't from an app store"))
        out.append(finding("usage", level, title, detail,
                           "Settings > Apps > (the app) > Permissions to take it away.",
                           "; ".join("%s ago=%ds" % (op, int(o["ago"])) for op, o in ops.items()
                                     if op in USAGE_OPS and o.get("ago") is not None),
                           pkg=p, key="usage:%s" % p))
    out.sort(key=lambda f: (LEVEL_RANK[f["level"]], f["title"].lower()))
    if unread(facts, "appops"):
        out.append(finding("usage", INFO, "Couldn't read recent camera, microphone and location use",
                           "The device didn't return its usage history, so this is NOT an all-clear.",
                           "Run the checkup again.", "dumpsys appops: %s" % facts["failed"]["appops"],
                           key="usage:unread"))
    elif not out:
        out.append(finding("usage", OK, "No camera, microphone, location or contacts use recorded "
                           "in the last 7 days", key="usage:none"))
    return out


# --------------------------------------------------------------------------
# snapshots: fingerprint the device, compare with the previous check
# --------------------------------------------------------------------------

def build_snapshot(serial, facts, access, launcher, identities, prev=None, boot=None, bg=None, user=None):
    """Snapshot of the device for 'changes since last check'.

    Signing certificate: taken from this version's identity when known. When it
    ISN'T known (no deep scan of this version yet - e.g. right after any app
    update - or base.apk couldn't be read), the last KNOWN cert from the previous
    snapshot is carried forward and marked "cert_unverified". So an unknown cert
    is never treated as a changed one, and the known signer is never forgotten:
    the next time the real cert is read it's compared against that last known
    one, so a replacement that happened in between is still caught."""
    apps = {}
    prev_apps = (prev or {}).get("apps", {})
    for p, a in facts["apps"].items():
        if a.get("removed"):
            continue
        ident = identities.get(identity_key(p, a)) or {}
        cert, unverified = ident.get("cert", ""), False
        if not cert and (prev_apps.get(p) or {}).get("cert"):
            cert, unverified = prev_apps[p]["cert"], True
        apps[p] = {"v": a.get("version", ""), "vc": a.get("version_code", ""), "sys": bool(a.get("system")),
                   "inst": a.get("installer", ""), "cert": cert, "cert_unverified": unverified,
                   "perms": sorted(x for x in a.get("granted", []) if x in SENSITIVE_PERMS),
                   "icon": None if launcher is None or a.get("system") else (p in launcher)}
    p = facts["props"]
    evidence, complete, managers = root_signals(facts)
    device = {"patch": p.get("patch", ""), "release": p.get("release", ""),
              "selinux": facts["selinux"],
              # root = positive evidence only (True), checked and none (False), unknown (None)
              "root": True if evidence else (False if complete else None),
              # manager apps tracked separately - comes from the app list, so always known
              "root_apps": sorted(managers),
              "crypto": p.get("crypto", "")}
    # A failed read is not "nothing": keep the previous value, marked unverified, so
    # the next good read is compared against what was really known (no false
    # "became rooted" / "was given access" alarms, and no missed changes).
    pdev, pacc = (prev or {}).get("device", {}), (prev or {}).get("access", {})
    dev_unverified = []
    for field, keys in (("patch", ("prop:patch",)), ("release", ("prop:release",)),
                        ("selinux", ("selinux",)), ("crypto", ("prop:crypto",))):
        if unread(facts, *keys) and field in pdev:
            device[field] = pdev[field]
            dev_unverified.append(field)
    if device["root"] is None and "root" in pdev:
        device["root"] = pdev["root"]
        dev_unverified.append("root")
    device["unverified"] = dev_unverified
    acc, acc_unverified = {}, []
    for k, v in access.items():
        if unread(facts, *ACCESS_SOURCES.get(k, ())):
            if k in pacc:
                acc[k] = list(pacc[k])
                acc_unverified.append(k)
            # else: never read and nothing known before -> left out (unknown), never saved as "none"
        else:
            acc[k] = sorted(v)
    # start at boot (from the checkup's boot detection) and background restriction (per
    # verified user). Unreadable -> the previous value, marked unverified, never "none".
    pboot, pbg = (prev or {}).get("boot"), (prev or {}).get("bg")
    if boot is None:
        boot_s = dict(pboot, unverified=True) if isinstance(pboot, dict) else None
    else:
        boot_s = {"pkgs": sorted(p for p, v in boot["pkgs"].items() if v), "complete": bool(boot["complete"]),
                  "user": user, "unverified": False}
    if bg is None:
        bg_s = dict(pbg, unverified=True) if isinstance(pbg, dict) else None
    else:
        bg_s = {"pkgs": {p: bool(v) for p, v in bg.items()}, "user": user, "unverified": False}
    return {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "serial": serial, "device": device,
            "apps": apps, "access": acc, "access_unverified": acc_unverified, "boot": boot_s, "bg": bg_s}


def snap_dir(serial):
    return os.path.join(SNAP_DIR, re.sub(r"[^A-Za-z0-9._-]+", "_", serial))


def last_snapshot(serial):
    d = snap_dir(serial)
    try:
        files = sorted(f for f in os.listdir(d) if f.endswith(".json"))
    except OSError:
        return None
    return load_json(os.path.join(d, files[-1]), {}) if files else None


def list_snapshots(serial):
    """All saved checks of this device, oldest first: [(file name, snapshot)]. Unreadable
    files are skipped (and counted by the caller from the difference)."""
    d = snap_dir(serial)
    try:
        files = sorted(f for f in os.listdir(d) if f.endswith(".json"))
    except OSError:
        return []
    out = []
    for f in files:
        snap = load_json(os.path.join(d, f), {})
        if isinstance(snap, dict) and isinstance(snap.get("apps"), dict) and snap.get("time"):
            out.append((f, snap))
    return out


def snapshot_gaps(snap):
    """What this check couldn't read (shown in the timeline - an unread item is not 'no change')."""
    gaps = ["%s (kept from before)" % f for f in (snap.get("device") or {}).get("unverified", [])]
    gaps += ["%s access (kept from before)" % ACCESS_INFO.get(k, (k,))[0] for k in snap.get("access_unverified", [])]
    # a field MISSING from a snapshot = an older version didn't track it (not a gap);
    # present but None / unverified = this check couldn't read it
    if "boot" in snap:
        b = snap["boot"]
        if b is None or b.get("unverified"):
            gaps.append("which apps start at boot")
        elif not b.get("complete"):
            gaps.append("the full start-at-boot list")
    if "bg" in snap:
        g = snap["bg"]
        if g is None or g.get("unverified"):
            gaps.append("background restrictions")
    return gaps


def save_snapshot(serial, snap):
    """Save a device snapshot privately (0600 file, 0700 folders). Returns True only
    if the new snapshot is safely on disk. Old snapshots are pruned ONLY after a
    successful save, so a failed write never costs us the previous reference."""
    d = snap_dir(serial)
    try:
        ensure_dir(os.path.dirname(d), private=True)   # snapshots/ itself
        atomic_write_json(os.path.join(d, time.strftime("%Y%m%d-%H%M%S") + ".json"),
                          snap, private=True)
    except OSError:
        return False
    try:
        files = sorted(f for f in os.listdir(d) if f.endswith(".json"))
        for f in files[:-KEEP_SNAPSHOTS]:
            os.remove(os.path.join(d, f))
    except OSError:
        pass   # pruning is housekeeping; the new snapshot is already saved
    return True


def compare_snapshots(prev, cur, labeler):
    out = []
    if not prev:
        out.append(finding("changes", INFO, "First check of this device - saved as the reference",
                           "Next time, this section lists everything that changed since now: new apps, "
                           "new permissions, new powerful access, and replaced apps.", key="changes:first"))
        return out
    when = prev.get("time", "the last check")
    pa, ca = prev.get("apps", {}), cur.get("apps", {})
    lbl = lambda p: labeler(p) if labeler else p  # noqa: E731
    for p in sorted(set(ca) - set(pa)):
        a = ca[p]
        text, kind = installer_text(a.get("inst", ""))
        level = INFO if a.get("sys") or kind == "store" else WARN
        out.append(finding("changes", level, "New app: %s" % lbl(p), "Installed since %s (%s)." % (when, text),
                           "If you didn't install it, check it in the Apps tab.", "package=%s" % p, pkg=p,
                           key="changes:new:%s" % p))
    gone = sorted(set(pa) - set(ca))
    if gone:
        out.append(finding("changes", INFO, "%d app(s) gone since %s" % (len(gone), when),
                           "\n".join("\u2022 " + p for p in gone), key="changes:gone"))
    updated = []
    for p in sorted(set(pa) & set(ca)):
        a, b = pa[p], ca[p]
        if a.get("cert") and b.get("cert") and a["cert"] != b["cert"]:
            out.append(finding("changes", BAD, "Signing certificate CHANGED: %s" % lbl(p),
                               "The app was replaced by a build signed by someone else. Android normally "
                               "refuses such updates - this usually means it was uninstalled and a different "
                               "copy (possibly tampered) was installed.",
                               "Unless you did that yourself, uninstall it and reinstall from the official store.",
                               "old cert %s\nnew cert %s" % (a["cert"], b["cert"]), pkg=p,
                               key="changes:cert:%s" % p))
        if a.get("vc") != b.get("vc"):
            updated.append("%s %s \u2192 %s" % (lbl(p), a.get("v") or a.get("vc"), b.get("v") or b.get("vc")))
        new_perms = [SENSITIVE_PERMS[x] for x in b.get("perms", []) if x not in a.get("perms", [])]
        if new_perms:
            out.append(finding("changes", WARN if not b.get("sys") else INFO,
                               "%s got new permission(s): %s" % (lbl(p), ", ".join(new_perms)),
                               "Granted since %s." % when, "Settings > Apps > (the app) > Permissions.",
                               pkg=p, key="changes:perms:%s" % p))
        if a.get("icon") is True and b.get("icon") is False:
            out.append(finding("changes", WARN, "%s hid its icon" % lbl(p),
                               "It had an icon in the app drawer at the last check and now it doesn't. "
                               "Some malware hides itself after the first start.", pkg=p,
                               key="changes:hid:%s" % p))
    if updated:
        out.append(finding("changes", INFO, "%d app(s) updated since %s" % (len(updated), when),
                           "\n".join("\u2022 " + u for u in updated[:60]), key="changes:updated"))
    for cat, (name, _, how) in ACCESS_INFO.items():
        if cat not in prev.get("access", {}):
            continue                                 # no baseline for this kind of access: nothing to compare
        before = set(prev.get("access", {}).get(cat, []))
        for p in sorted(set(cur.get("access", {}).get(cat, [])) - before):
            sysapp = ca.get(p, {}).get("sys", False)
            out.append(finding("changes", INFO if sysapp else WARN, "%s was given: %s" % (lbl(p), name),
                               "Not there at %s." % when, how, pkg=p, key="changes:access:%s:%s" % (cat, p)))
    dp, dc = prev.get("device", {}), cur.get("device", {})
    if dc.get("root") is True and dp.get("root") is False:   # unknown (None) never counts
        out.append(finding("changes", BAD, "Signs of root appeared since %s" % when,
                           "An su program is present now and wasn't at the last check.", key="changes:root"))
    if "root_apps" in dp:      # older snapshots didn't track manager apps: no baseline, no alarm
        for x in sorted(set(dc.get("root_apps", [])) - set(dp["root_apps"])):
            out.append(finding("changes", WARN, "Root manager app installed since %s: %s" % (when, x),
                               "This doesn't confirm the device is rooted, but if you didn't install it, "
                               "find out who did.", pkg=x, key="changes:root-app:%s" % x))
    if dp.get("selinux", "").lower() == "enforcing" and dc.get("selinux", "").lower() == "permissive":
        out.append(finding("changes", BAD, "SELinux was switched to permissive since %s" % when,
                           key="changes:selinux"))
    if dp.get("patch") and dc.get("patch") and dp["patch"] != dc["patch"]:
        out.append(finding("changes", INFO, "Security patch changed: %s \u2192 %s" % (dp["patch"], dc["patch"]),
                           key="changes:patch"))
    out += compare_boot_bg(prev, cur, ca, lbl, when)
    gaps = snapshot_gaps(cur)
    if not out and gaps:                 # not an all-clear: part of the phone couldn't be read this time
        out.append(finding("changes", INFO, "No change found in what could be checked since %s" % when,
                           "Not checked this time: %s." % "; ".join(gaps), key="changes:none-partial"))
    elif not out:
        out.append(finding("changes", OK, "Nothing changed since %s" % when, key="changes:none"))
    return out


def compare_boot_bg(prev, cur, ca, lbl, when):
    """Start-at-boot and background changes - only where BOTH checks could see them."""
    out = []
    pb, cb = prev.get("boot"), cur.get("boot")
    if isinstance(pb, dict) and isinstance(cb, dict) and not pb.get("unverified") and not cb.get("unverified") \
            and pb.get("user") == cb.get("user"):
        before, now = set(pb.get("pkgs", [])), set(cb.get("pkgs", []))
        if pb.get("complete"):                       # otherwise it may just have been missed last time
            for p in sorted(now - before):
                if p in ca:
                    sysapp = ca[p].get("sys", False)
                    out.append(finding("changes", INFO if sysapp else WARN, "%s now starts by itself at boot" % lbl(p),
                                       "It didn't at %s." % when, "The Autorun tab can switch that off.",
                                       pkg=p, key="changes:boot:%s" % p))
        if cb.get("complete"):                       # otherwise it may just be unread now
            stopped = sorted(p for p in before - now if p in ca)
            if stopped:
                out.append(finding("changes", INFO, "%d app(s) no longer start at boot" % len(stopped),
                                   "\n".join("\u2022 " + lbl(p) for p in stopped[:60]), key="changes:boot-off"))
    pg, cg = prev.get("bg"), cur.get("bg")
    if isinstance(pg, dict) and isinstance(cg, dict) and not pg.get("unverified") and not cg.get("unverified") \
            and pg.get("user") == cg.get("user"):
        a, b = pg.get("pkgs", {}), cg.get("pkgs", {})
        lifted = sorted(p for p in set(a) & set(b) if a[p] is True and b[p] is False and p in ca)
        added = sorted(p for p in set(a) & set(b) if a[p] is False and b[p] is True and p in ca)
        for p in lifted:
            out.append(finding("changes", INFO if ca[p].get("sys") else WARN,
                               "%s may run in the background again" % lbl(p),
                               "Its background restriction was lifted since %s." % when,
                               "If you didn't do that, restrict it again in the Autorun tab.", pkg=p,
                               key="changes:bg-lifted:%s" % p))
        if added:
            out.append(finding("changes", INFO, "%d app(s) restricted from running in the background" % len(added),
                               "\n".join("\u2022 " + lbl(p) for p in added[:60]), key="changes:bg-added"))
    return out


# --------------------------------------------------------------------------
# APK identity: file hash + signing certificate
# --------------------------------------------------------------------------

def identity_key(pkg, app):
    return "%s|%s|%s" % (pkg, app.get("version_code", ""), app.get("last_update", ""))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _lp(buf, off):
    n = struct.unpack_from("<I", buf, off)[0]
    if off + 4 + n > len(buf):
        raise ValueError("bad length")
    return buf[off + 4:off + 4 + n], off + 4 + n


def certs_from_signing_block(path):
    """SHA-256 of the signer certificates in the APK Signature Scheme v2/v3 block, or []."""
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        f.seek(max(0, size - 65557))
        tail = f.read()
        i = tail.rfind(b"PK\x05\x06")
        if i < 0 or len(tail) < i + 22:
            return []
        cd_offset = struct.unpack_from("<I", tail, i + 16)[0]
        if cd_offset < 32:
            return []
        f.seek(cd_offset - 24)
        footer = f.read(24)
        if footer[8:] != b"APK Sig Block 42":
            return []
        block_size = struct.unpack_from("<Q", footer, 0)[0]
        start = cd_offset - block_size - 8
        if start < 0 or block_size < 24:           # forged size: never read "the rest of the file"
            return []
        f.seek(start + 8)
        pairs = f.read(block_size - 24)
    off, found = 0, {}
    while off + 12 <= len(pairs):
        ln = struct.unpack_from("<Q", pairs, off)[0]
        pid = struct.unpack_from("<I", pairs, off + 8)[0]
        found[pid] = pairs[off + 12:off + 8 + ln]
        off += 8 + ln
    for pid in (0xf05368c0, 0x1b93ad61, 0x7109871a):   # v3, v3.1, v2
        value = found.get(pid)
        if not value:
            continue
        try:
            signers, _ = _lp(value, 0)
            o, out = 0, []
            while o < len(signers):
                signer, o = _lp(signers, o)
                signed, _ = _lp(signer, 0)
                _digests, so = _lp(signed, 0)
                certs, _ = _lp(signed, so)
                co = 0
                while co < len(certs):
                    cert, co = _lp(certs, co)
                    out.append(hashlib.sha256(cert).hexdigest())
            if out:
                return out
        except (ValueError, struct.error):
            continue
    return []


def certs_from_v1(path):
    """SHA-256 of the certificates in a v1 (JAR) signature, via cryptography or openssl."""
    try:
        with zipfile.ZipFile(path) as z:                 # closed promptly, even on errors
            blocks = [n for n in z.namelist()
                      if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))]
            if not blocks:
                return []
            data = z.read(blocks[0])
    except (zipfile.BadZipFile, OSError, KeyError):
        return []
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7, Encoding
        return [hashlib.sha256(c.public_bytes(Encoding.DER)).hexdigest()
                for c in pkcs7.load_der_pkcs7_certificates(data)]
    except Exception:
        pass
    try:
        p = subprocess.run(["openssl", "pkcs7", "-inform", "DER", "-print_certs"], input=data,
                           capture_output=True, timeout=20)
        pems = re.findall(rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", p.stdout, re.S)
        return [hashlib.sha256(base64.b64decode(b"".join(x.split()))).hexdigest() for x in pems]
    except (OSError, subprocess.SubprocessError, ValueError):
        return []


def apk_identity(path):
    certs = certs_from_signing_block(path) or certs_from_v1(path)
    return {"sha256": sha256_file(path), "size": os.path.getsize(path),
            "cert": certs[0] if certs else "", "certs": certs}


# ---- whole-app identity: base + every installed split ----------------------
#
# An installed app can be several APK files: base.apk plus "split" APKs - config
# splits (split_config.arm64_v8a.apk: native code for this CPU; ...xxhdpi.apk:
# screen-density resources; ...pt.apk: language) and feature splits
# (split_<feature>.apk: optional modules). Code can live in ANY of them, so a
# deep scan must fingerprint and look up every part, not just base.apk.

def apk_part_kind(name):
    """'base', 'config' or 'feature' from an installed APK file name."""
    n = os.path.basename(name)
    if n == "base.apk":
        return "base"
    if n.startswith("split_config.") or ".config." in n:
        return "config"
    return "feature"


def apk_part_label(part):
    """Plain-language name of one part, for the results screen."""
    n = os.path.basename(part.get("name") or part.get("path") or "")
    kind = part.get("kind") or apk_part_kind(n)
    if kind == "base":
        return "main app file"
    stem = n[:-4] if n.endswith(".apk") else n
    if kind == "config":
        what = stem.split("config.", 1)[-1]
        if re.match(r"^(arm|x86|mips)", what):
            return "processor-specific code (%s)" % what
        if what.endswith("dpi"):
            return "screen-size pictures (%s)" % what
        return "extra part for this phone (%s)" % what
    return "optional feature '%s'" % (stem[len("split_"):] if stem.startswith("split_") else stem)


def make_app_identity(pkg, parts):
    """Combine per-part results into one identity record.

    parts: [{"path", "name", "kind", and EITHER "sha256","size","cert","certs"
             OR "error": why that part couldn't be read}]

    Returns a record that keeps the old top-level fields (sha256/size/cert/certs
    of base.apk, so snapshots and cert-change detection keep working) plus:
      parts      - every part, read or not
      coverage   - "full" only if EVERY part was read and hashed; else "partial"
      unread     - names of parts that couldn't be read
      signers    - evidence-based, in this order of precedence:
                   "different" - base's signer set is known and at least one
                                 readable part has a DIFFERENT known set. One
                                 confirmed mismatch is enough, even if some other
                                 part's signer couldn't be read;
                   "unknown"   - no mismatch found, but base's signer or some
                                 readable part's signer couldn't be read;
                   "same"      - every readable part has the base's signer set.
      signers_unknown - names of readable parts whose signer couldn't be read
                   (so a "different" verdict never implies every signer is known)"""
    base = next((x for x in parts if x.get("kind") == "base"), None)
    unread = [x["name"] for x in parts if x.get("error") or not x.get("sha256")]
    ok = base is not None and base.get("sha256")
    ident = {"pkg": pkg, "parts": parts,
             "coverage": "full" if parts and ok and not unread else "partial",
             "unread": unread,
             "sha256": base.get("sha256", "") if base else "",
             "size": base.get("size", 0) if base else 0,
             "cert": base.get("cert", "") if base else "",
             "certs": base.get("certs", []) if base else []}
    base_set = set(ident["certs"])
    readable = [x for x in parts if x.get("sha256")]
    no_signer = [x["name"] for x in readable if not x.get("certs")]
    if base_set and any(x.get("certs") and set(x["certs"]) != base_set for x in readable):
        signers = "different"          # confirmed evidence wins
    elif not base_set or no_signer:
        signers = "unknown"
    else:
        signers = "same"
    ident["signers"] = signers
    ident["signers_unknown"] = no_signer
    return ident


def identity_complete(ident):
    """True if a cached identity covers ALL parts (old base-only records don't)."""
    return isinstance(ident, dict) and isinstance(ident.get("parts"), list) and \
        ident.get("coverage") == "full"


def identity_parts(ident):
    """The parts of an identity; an old base-only record becomes one base part."""
    if isinstance(ident.get("parts"), list):
        return ident["parts"]
    return [{"name": "base.apk", "kind": "base", "sha256": ident.get("sha256", ""),
             "size": ident.get("size", 0), "cert": ident.get("cert", ""),
             "certs": ident.get("certs", [])}]


# --------------------------------------------------------------------------
# outside services (all optional)
# --------------------------------------------------------------------------

UA = "adb_manager-security-check/1.0"


def _http(url, headers=None, data=None, timeout=30):
    req = urllib.request.Request(url, data=data, headers=dict({"User-Agent": UA}, **(headers or {})))
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


# --------------------------------------------------------------------------
# Known Android security issues: bulletin data (OSV) + CISA's exploited list.
# Downloaded ONLY when the user presses the button; read from the local cache
# otherwise. The comparison itself is cve_check.py (pure, no network).
# --------------------------------------------------------------------------

CVE_DATA_FILE = os.path.join(CONFIG_DIR, "cve_data.json")
CVE_DATA_SCHEMA = 1
OSV_ANDROID_URL = "https://osv-vulnerabilities.storage.googleapis.com/Android/all.zip"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_UA = "ADB-Manager/1.0 (+https://github.com/peterpt/Adb-Manager)"
OSV_ZIP_CAP = 60 << 20           # the real file is ~10 MB
OSV_MEMBER_CAP = 16 << 20        # one record can carry MBs of code signatures (dropped)
OSV_MAX_MEMBERS = 50000
KEV_CAP = 20 << 20


def download_capped(url, cap, timeout=60, headers=None):
    """GET url -> bytes, refusing to read past `cap` whatever the server claims.
    Raises urllib.error.URLError / HTTPError / OSError / ValueError."""
    req = urllib.request.Request(url, headers=dict({"User-Agent": CVE_UA}, **(headers or {})))
    with urllib.request.urlopen(req, timeout=timeout) as r:
        declared = r.headers.get("Content-Length")
        if declared and declared.isdigit() and int(declared) > cap:
            raise ValueError("the download is larger than the %d MB limit" % (cap >> 20))
        buf, total = [], 0
        while True:
            chunk = r.read(1 << 16)
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                raise ValueError("the download is larger than the %d MB limit" % (cap >> 20))
            buf.append(chunk)
    return b"".join(buf)


def parse_osv_zip(raw, cancel=None):
    """OSV's Android all.zip (bytes) -> (compact records, number of unusable records).
    Nothing is extracted to disk; each member is read with a size cap."""
    import io
    import cve_check as cv
    records, skipped = [], 0
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        names = [n for n in z.namelist() if n.endswith(".json")]
        if not names:
            raise ValueError("the bulletin archive contains no records")
        if len(names) > OSV_MAX_MEMBERS:
            raise ValueError("the bulletin archive has too many entries (%d)" % len(names))
        for n in names:
            if cancel is not None and cancel.is_set():
                raise InterruptedError("stopped")
            try:
                rec = cv.compact_record(json.loads(read_member_capped(z, n, OSV_MEMBER_CAP)))
            except (ValueError, KeyError, zipfile.BadZipFile, RecursionError):
                rec = None
            if rec is None:
                skipped += 1
            else:
                records.append(rec)
    return records, skipped


def refresh_cve_data(cancel=None, say=lambda text: None, fetch=download_capped):
    """Download both sources and replace the cache. The old cache is only replaced
    after the bulletin data was fully read; if the exploited list fails, the cache
    says so (exploited = unknown). Returns {"ok": bool, "message", "data"}."""
    import cve_check as cv
    say("Downloading the Android security bulletin data (about 10 MB) ...")
    try:
        raw = fetch(OSV_ANDROID_URL, OSV_ZIP_CAP, 120)
        say("Reading the bulletin data ...")
        records, skipped = parse_osv_zip(raw, cancel)
    except InterruptedError:
        return {"ok": False, "message": "stopped - the saved data (if any) was kept", "data": None}
    except (urllib.error.URLError, OSError, ValueError, zipfile.BadZipFile) as e:
        return {"ok": False, "message": "couldn't get the bulletin data (%s) - the saved data (if any) "
                                        "was kept" % (str(e)[:200] or type(e).__name__), "data": None}
    if not records:
        return {"ok": False, "message": "the bulletin data had no usable records - the saved data was kept",
                "data": None}
    say("Downloading CISA's list of exploited vulnerabilities ...")
    kev, kev_error = None, ""
    try:
        kev = cv.compact_kev(json.loads(fetch(KEV_URL, KEV_CAP, 60)))
        if kev is None:
            kev_error = "the exploited list wasn't in the expected format"
    except (urllib.error.URLError, OSError, ValueError, RecursionError) as e:
        kev_error = "couldn't get the exploited list (%s)" % (str(e)[:200] or type(e).__name__)
    data = {"schema": CVE_DATA_SCHEMA, "checked": time.strftime("%Y-%m-%d %H:%M"), "osv_records": records,
            "osv_skipped": skipped, "kev": kev, "kev_error": kev_error}
    try:
        atomic_write_json(CVE_DATA_FILE, data, indent=None)
    except OSError as e:
        return {"ok": False, "message": "downloaded, but couldn't save it (%s)" % e, "data": data}
    msg = "%d issues from the Android bulletins%s; %s" % (
        len(records), " (%d unreadable, skipped)" % skipped if skipped else "",
        "%d on CISA's exploited list" % len(kev) if kev is not None else kev_error)
    return {"ok": True, "message": msg, "data": data}


def load_cve_data():
    """The saved data, or None if there is none / it's damaged / from a newer app."""
    d = load_json(CVE_DATA_FILE, {})
    if not isinstance(d, dict) or d.get("schema") != CVE_DATA_SCHEMA or not isinstance(d.get("osv_records"), list):
        return None
    recs = [r for r in d["osv_records"] if isinstance(r, dict) and isinstance(r.get("affected"), list)
            and isinstance(r.get("cves"), list) and isinstance(r.get("id"), str)]
    if not recs:
        return None
    kev = d.get("kev") if isinstance(d.get("kev"), dict) else None
    return {"checked": str(d.get("checked", "?")), "osv_records": recs,
            "osv_skipped": int(d.get("osv_skipped") or 0) + (len(d["osv_records"]) - len(recs)),
            "kev": kev, "kev_error": str(d.get("kev_error") or ("" if kev is not None else "not downloaded"))}


# ---- CIRCL Vulnerability-Lookup: the chip maker's own security notices -------
# Only the chip MAKER's name is sent (e.g. "Unisoc") - never the serial, model,
# fingerprint or app list. Matching against the phone happens locally.

CIRCL_BASE = "https://vulnerability.circl.lu/api"
CIRCL_CACHE_FILE = os.path.join(CONFIG_DIR, "circl_cache.json")
CIRCL_PER_PAGE = 100
CIRCL_MAX_PAGES = 10              # at most 1000 notices per maker; the server allows 20 requests a minute
CIRCL_CAP = 8 << 20
CIRCL_MAX_AGE = 7 * 86400
CIRCL_MAX_QUERIES = 6
# chip maker as the phone reports it -> the name its own notices use
CIRCL_VENDORS = {"unisoc": "Unisoc", "spreadtrum": "Unisoc", "sprd": "Unisoc", "mediatek": "MediaTek",
                 "mtk": "MediaTek", "qti": "Qualcomm", "qualcomm": "Qualcomm", "samsung": "Samsung"}
# a chip's internal name -> the marketing names its maker's notices use. Only entries
# with a public source; letter variants (UMS9230E, ...) aren't pinned to one name.
#   UMS9230 = Unisoc Tiger T606/T616 (postmarketOS wiki "Unisoc Tiger T606/T616 (UMS9230)")
CHIP_FAMILIES = {"ums9230": ("T606", "T616")}
# names under which a maker publishes its own CVE records (CNA short name / vendor field)
VENDOR_ALIASES = {"Unisoc": ("unisoc", "spreadtrum"), "MediaTek": ("mediatek",), "Qualcomm": ("qualcomm",),
                  "Samsung": ("samsung",)}


class CirclError(Exception):
    """kind: 'unavailable' (503), 'rate_limited' (429, retry_after s), 'bad_request', 'network', 'format'."""

    def __init__(self, kind, message, retry_after=None):
        super().__init__(message)
        self.kind, self.retry_after = kind, retry_after


def circl_vendor(props):
    """The chip maker's name for the search, from the phone's own report (or None)."""
    for k in ("ro.soc.manufacturer", "ro.hardware.chipname"):
        v = (props.get(k) or "").strip().lower()
        for key, name in CIRCL_VENDORS.items():
            if v.startswith(key):
                return name
    return None


def _circl_get(path, params, fetch):
    url = CIRCL_BASE + path + "?" + urllib.parse.urlencode(params)
    try:
        raw = fetch(url, CIRCL_CAP, 30, {"Accept": "application/json"})
    except urllib.error.HTTPError as e:
        if e.code == 429:
            ra = (e.headers or {}).get("Retry-After", "")
            ra = int(ra) if str(ra).isdigit() else None
            raise CirclError("rate_limited", "the service asks to slow down%s" % (
                " - try again in %d s" % ra if ra else ""), ra)
        if e.code == 503:
            raise CirclError("unavailable", "the search service is unavailable right now (HTTP 503)")
        if e.code == 400:
            raise CirclError("bad_request", "the service rejected the search (HTTP 400)")
        raise CirclError("network", "the service answered HTTP %d" % e.code)
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise CirclError("network", "couldn't reach the service (%s)" % (str(e)[:160] or type(e).__name__))
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        raise CirclError("format", "the service's answer wasn't valid JSON")


def _txt(v, n=600):
    return v[:n] if isinstance(v, str) else ""


def compact_circl(rec):
    """One CVE 5.x record -> the fields shown and matched, or None if it isn't one."""
    if not isinstance(rec, dict):
        return None
    meta = rec.get("cveMetadata") if isinstance(rec.get("cveMetadata"), dict) else {}
    cve = meta.get("cveId")
    if not isinstance(cve, str) or not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
        return None
    cont = rec.get("containers") if isinstance(rec.get("containers"), dict) else {}
    cna = cont.get("cna") if isinstance(cont.get("cna"), dict) else {}
    adp = [a for a in cont.get("adp") or [] if isinstance(a, dict)] if isinstance(cont.get("adp"), list) else []
    desc = next((_txt(d.get("value")) for d in cna.get("descriptions") or []
                 if isinstance(d, dict) and str(d.get("lang", "")).startswith("en")), "")
    vendors, products, versions, damaged, ranges = [], [], [], False, False
    aff = cna.get("affected")
    if not isinstance(aff, list):
        damaged = True
        aff = []
    for a in aff:
        if not isinstance(a, dict):
            damaged = True
            continue
        if isinstance(a.get("vendor"), str):
            vendors.append(a["vendor"][:120])
        if isinstance(a.get("product"), str):
            products += [t.strip()[:60] for t in re.split(r"[/,;]", a["product"]) if t.strip()][:80]
        if a.get("defaultStatus") == "affected":
            ranges = True                 # everything NOT listed is affected: a list can't rule anything out
        for v in a.get("versions") or []:
            if not isinstance(v, dict):
                continue
            if any(k in v for k in ("lessThan", "lessThanOrEqual", "changes")):
                ranges = True             # a version RANGE: not interpreted here -> Android version unknown
            if v.get("status") == "affected" and isinstance(v.get("version"), str):
                versions.append(v["version"][:120])
    severity, kev = "", False
    for block in [cna] + adp:
        for m in block.get("metrics") or [] if isinstance(block.get("metrics"), list) else []:
            if not isinstance(m, dict):
                continue
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                c = m.get(key)
                if isinstance(c, dict) and isinstance(c.get("baseSeverity"), str) and not severity:
                    severity = c["baseSeverity"].capitalize()[:12]
            o = m.get("other")
            if isinstance(o, dict) and o.get("type") == "kev":
                kev = True
    refs = [r["url"][:300] for r in cna.get("references") or []
            if isinstance(r, dict) and isinstance(r.get("url"), str) and r["url"].startswith("https://")][:3]
    prov = cna.get("providerMetadata") if isinstance(cna.get("providerMetadata"), dict) else {}
    return {"cve": cve, "published": _txt(meta.get("datePublished"), 10), "desc": desc,
            "vendor": vendors[0] if vendors else "", "vendors": vendors[:10], "products": products,
            "versions": versions[:20], "ranges": ranges, "severity": severity, "kev_listed": kev, "refs": refs,
            "damaged": damaged, "assigner": _txt(meta.get("assignerShortName"), 80),
            "provider": _txt(prov.get("shortName"), 80)}


def circl_attributed(rec, vendor):
    """True only if `vendor` PUBLISHED the record: its CNA assigner short name or the CNA
    container's provider. Being the affected vendor (e.g. a MITRE-assigned CVE about a
    Unisoc chip) doesn't make it the maker's own notice."""
    names = VENDOR_ALIASES.get(vendor, (vendor.lower(),))
    return any(n in (f or "").lower() for f in (rec.get("assigner", ""), rec.get("provider", "")) for n in names)


def circl_search(vendor, refresh=False, fetch=download_capped, cancel=None, now=None, max_age=CIRCL_MAX_AGE):
    """The maker's notices, from the cache when fresh (unless refresh), else from
    CIRCL. Returns {"records", "count", "complete", "stopped", "fetched", "from_cache"};
    raises CirclError when nothing usable could be got (a failure is never 'no results').
    Only COMPLETE searches are cached; partial ones are returned once, marked partial."""
    now = now or time.time()
    cache = load_json(CIRCL_CACHE_FILE, {})
    hit = cache.get(vendor) if isinstance(cache.get(vendor), dict) else None
    if hit and not refresh and hit.get("complete") is True and isinstance(hit.get("records"), list) \
            and now - float(hit.get("time") or 0) < max_age:
        return dict(hit, from_cache=True)
    seen, records, count, complete, error, stopped, raw_rows, bad_rows = set(), [], None, False, None, False, 0, 0
    for page in range(1, CIRCL_MAX_PAGES + 1):
        if cancel is not None and cancel.is_set():
            stopped = True
            break
        try:
            doc = _circl_get("/vulnerability/fulltext", {"q": vendor, "page": page, "per_page": CIRCL_PER_PAGE,
                                                         "sources": "cvelistv5"}, fetch)
        except CirclError as e:
            if not records:
                raise
            error = e                                # keep what was read, say it's partial
            break
        if not isinstance(doc, dict) or not isinstance(doc.get("data"), list):
            if not records:
                raise CirclError("format", "the service's answer had an unexpected shape")
            break
        md = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
        if isinstance(md.get("count"), int):
            count = md["count"]
        raw_rows += len(doc["data"])
        for rec in doc["data"]:
            c = compact_circl(rec)
            if c is None:
                bad_rows += 1                       # counted, never silently dropped
            elif c["cve"] not in seen:              # de-duplicated by CVE id
                seen.add(c["cve"])
                records.append(c)
        if len(doc["data"]) < CIRCL_PER_PAGE or (count is not None and page * CIRCL_PER_PAGE >= count):
            complete = True
            break
    if raw_rows and not records:
        raise CirclError("format", "the service returned %d record(s), but none could be read as a CVE "
                                   "record - that's a data problem, not 'no issues'" % raw_rows)
    short = count is not None and complete and raw_rows < count     # the service said more than it sent
    ok = complete and error is None and not stopped and not bad_rows and not short
    reason = ("stopped" if stopped else str(error) if error else
              "%d record(s) in the answer couldn't be read" % bad_rows if bad_rows else
              "the service reported %d result(s) but sent %d" % (count, raw_rows) if short else
              "" if complete else "page limit reached")
    result = {"records": records, "count": count if count is not None else len(records), "complete": ok,
              "stopped": stopped, "fetched": time.strftime("%Y-%m-%d %H:%M"), "time": now,
              "partial_reason": reason, "bad_rows": bad_rows}
    if ok:                                            # only complete searches are reused later
        cache[vendor] = result
        for k in sorted(cache, key=lambda k: float(cache[k].get("time") or 0) if isinstance(cache[k], dict) else 0
                        )[:-CIRCL_MAX_QUERIES]:
            cache.pop(k, None)                        # bounded
        save_json(CIRCL_CACHE_FILE, cache)
    return dict(result, from_cache=False)


def _android_majors(versions):
    """'Android10/Android11', 'Android 12.0', '15', '16-qpr2' -> {10, 11, 12, 15, 16}; None if none readable."""
    out = set()
    for v in versions:
        v = v.strip().lower()
        if "android" in v:
            nums = [int(n) for n in re.findall(r"android\s*(\d{1,2})", v)]
        else:
            m = re.fullmatch(r"(\d{1,2})(?:\.\d+)*(?:-qpr\d)?", v)
            nums = [int(m.group(1))] if m else []
        out |= {n for n in nums if 1 <= n <= 30}
    return out or None


def circl_assess(records, props, bulletin=None, known=None, vendor=None):
    """Each notice vs. the phone, locally.
    bulletin: {cve: cve_check finding} - verdicts already made from the Android bulletin data,
              reused, never recomputed;
    known:    every CVE in the downloaded bulletin data (shown or not) - such a CVE never gets a
              second, independent verdict here;
    vendor:   the maker searched for - only its OWN records are matched as its notices.
    Fix state is never decided here: these notices carry no patch dates."""
    pr = props or {}
    chip_tokens = {t for t in re.split(r"[^a-z0-9]+", " ".join(pr.get(k, "") for k in (
        "ro.soc.model", "ro.board.platform", "ro.product.board")).lower()) if t}
    family = set()
    for tok in chip_tokens:
        for fam, names in CHIP_FAMILIES.items():
            if tok.startswith(fam):
                family |= {n.lower() for n in names}
    try:
        release = int(str(pr.get("ro.build.version.release", "")).split(".")[0])
    except ValueError:
        release = None
    reported = pr.get("ro.soc.model") or pr.get("ro.board.platform") or "?"
    out = []
    for r in records:
        f = {"cve": r["cve"], "desc": r["desc"], "severity": r["severity"], "published": r["published"],
             "refs": r["refs"], "kev_listed": r["kev_listed"], "fix": "unknown"}
        b = (bulletin or {}).get(r["cve"])
        if b is not None or r["cve"] in (known or ()):
            f.update(source="bulletin", chip="", android="", bulletin_state=b["state"] if b else None,
                     summary="covered by the Android bulletin data - its verdict is shown there" if b else
                     "in the Android bulletin data, outside the serious issues listed there - no separate "
                     "verdict is made here")
            out.append(f)
            continue
        if vendor and not circl_attributed(r, vendor):
            f.update(source="mention", chip="", android="", summary="mentions %s, but wasn't published by %s "
                     "(published by %s) - not matched against your phone" % (
                         vendor, vendor, r.get("assigner") or r.get("provider") or "someone else"))
            out.append(f)
            continue
        prods = {p.lower() for p in r["products"]}
        if r["damaged"] or not prods:
            chip = "unknown"
            chip_text = "the notice doesn't say which chips are affected"
        elif chip_tokens & prods:
            chip, chip_text = "listed", "lists your chip (%s)" % reported
        elif family & prods:
            chip = "family"
            chip_text = "lists your chip family (%s); your exact variant can't be confirmed" % (
                "/".join(sorted(n.upper() for n in family & prods)))
        else:
            chip = "unmatched"
            chip_text = "your chip (%s) couldn't be matched to its list" % reported
        majors = None if r.get("ranges") else _android_majors(r["versions"])
        if r.get("ranges"):
            android, a_text = "unknown", "it gives Android version ranges that this check doesn't interpret"
        elif majors is None or release is None:
            android, a_text = "unknown", "Android versions not stated" if majors is None else "your Android version is unknown"
        elif release in majors:
            android, a_text = "listed", "lists Android %d" % release
        else:
            android, a_text = "not_listed", "not listed for Android %d (lists %s)" % (
                release, ", ".join(str(m) for m in sorted(majors)))
        f.update(source="maker", chip=chip, android=android, summary="%s; %s; whether your update includes the "
                 "fix can't be told" % (chip_text, a_text))
        out.append(f)
    rank = {("listed", "listed"): 0, ("family", "listed"): 1}
    out.sort(key=lambda f: f["published"], reverse=True)                    # newest first ...
    order = {"maker": 0, "bulletin": 1, "mention": 2}
    out.sort(key=lambda f: (order[f["source"]], rank.get((f.get("chip"), f.get("android")), 2)))
    return out


def virustotal(key, sha256):
    """{'known': bool, 'malicious': n, 'suspicious': n, 'engines': n, 'label': str} or {'error': ..}."""
    try:
        d = _http("https://www.virustotal.com/api/v3/files/" + sha256, {"x-apikey": key})
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"known": False}
        if e.code in (401, 403):
            return {"error": "VirusTotal rejected the API key"}
        if e.code == 429:
            return {"error": "VirusTotal quota reached (free keys: 4 per minute, 500 per day)", "quota": True}
        return {"error": "VirusTotal error %d" % e.code}
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"error": "can't reach VirusTotal: %s" % e}
    attrs = (d.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    label = ((attrs.get("popular_threat_classification") or {}).get("suggested_threat_label") or "")
    return {"known": True, "malicious": int(stats.get("malicious", 0)), "suspicious": int(stats.get("suspicious", 0)),
            "engines": sum(int(v) for v in stats.values() if isinstance(v, int)), "label": label,
            "link": "https://www.virustotal.com/gui/file/" + sha256}


def malwarebazaar(key, sha256):
    try:
        d = _http("https://mb-api.abuse.ch/api/v1/", {"Auth-Key": key},
                  urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode())
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return {"error": "MalwareBazaar rejected the Auth-Key"}
        return {"error": "MalwareBazaar error %d" % e.code}
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"error": "can't reach MalwareBazaar: %s" % e}
    status = d.get("query_status")
    if status == "ok" and d.get("data"):
        item = d["data"][0]
        return {"known": True, "family": item.get("signature") or "", "tags": item.get("tags") or [],
                "first_seen": item.get("first_seen") or "",
                "link": "https://bazaar.abuse.ch/sample/%s/" % sha256}
    if status in ("hash_not_found", "no_results"):
        return {"known": False}
    return {"error": "MalwareBazaar: %s" % status}


_tracker_db = {"time": 0, "db": {}}
_tracker_lock = threading.Lock()


def exodus_tracker_names(cfg):
    with _tracker_lock:
        cached = load_json(TRACKERS_FILE, {})
        db = cached.get("_db") or {}
        if db and time.time() - cached.get("_db_time", 0) < 7 * 86400:
            return db
        try:
            d = _http(cfg["exodus_url"].rstrip("/") + "/api/trackers",
                      {"Authorization": "Token " + cfg["exodus_token"]})
            # code/network signatures are kept too: the code inspector uses them
            # (offline) to tell which SDK a piece of code or an address belongs to
            db = {str(k): {"name": v.get("name", ""), "website": v.get("website", ""),
                           "code_signature": v.get("code_signature", "") or "",
                           "network_signature": v.get("network_signature", "") or ""}
                  for k, v in (d.get("trackers") or {}).items()}
            cached["_db"], cached["_db_time"] = db, time.time()
            save_json(TRACKERS_FILE, cached)
        except Exception:
            pass
        return db


def cached_exodus_trackers():
    """Exodus tracker list as cached by an earlier deep scan - NEVER fetches.
    Entries saved by older versions lack signatures and are simply skipped by
    inspector_signatures()."""
    db = load_json(TRACKERS_FILE, {}).get("_db") or {}
    return [v for v in db.values() if isinstance(v, dict)]


def exodus_report(cfg, pkg, version_code):
    """{'found': bool, 'trackers': [names], 'version': str, 'exact': bool} or {'error': ..}."""
    url = cfg["exodus_url"].rstrip("/") + "/api/search/%s/details" % urllib.parse.quote(pkg)
    try:
        reports = _http(url, {"Authorization": "Token " + cfg["exodus_token"]})
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return {"error": "Exodus rejected the token"}
        if e.code == 404:
            return {"found": False}
        return {"error": "Exodus error %d" % e.code}
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"error": "can't reach Exodus: %s" % e}
    if not isinstance(reports, list) or not reports:
        return {"found": False}
    exact = [r for r in reports if str(r.get("version_code")) == str(version_code)]
    rep = exact[0] if exact else max(reports, key=lambda r: int(r.get("version_code") or 0))
    names = exodus_tracker_names(cfg)
    trackers = sorted({names.get(str(t), {}).get("name") or "tracker #%s" % t for t in rep.get("trackers") or []})
    return {"found": True, "trackers": trackers, "version": rep.get("version_name", ""),
            "exact": bool(exact), "link": "https://reports.exodus-privacy.eu.org/en/reports/%s/latest/" % pkg}


def part_verdict(r):
    """One part's lookup result -> 'bad', 'sus', 'clean', 'unknown' or 'error'.
    'clean' means VirusTotal knows this exact file and no scanner flags it;
    MalwareBazaar not knowing a file is NOT proof it's clean."""
    vt, mb = (r or {}).get("vt"), (r or {}).get("mb")
    if (vt and vt.get("malicious", 0) >= 3) or (mb and mb.get("known")):
        return "bad"
    if vt and (vt.get("malicious", 0) > 0 or vt.get("suspicious", 0) > 0):
        return "sus"
    if vt and vt.get("known"):
        return "clean"
    if (vt and vt.get("error")) or (mb and mb.get("error")):
        return "error"
    return "unknown"


def _lookup_lines(vt, mb):
    lines = []
    if vt:
        if vt.get("error"):
            lines.append("VirusTotal: " + vt["error"])
        elif not vt.get("known"):
            lines.append("VirusTotal: this exact file was never uploaded there (unknown - not proof of "
                         "anything either way)")
        else:
            lines.append("VirusTotal: %d of %d virus scanners flag it%s" % (
                vt["malicious"], vt["engines"], (" as '%s'" % vt["label"]) if vt.get("label") else ""))
    if mb:
        if mb.get("error"):
            lines.append("MalwareBazaar: " + mb["error"])
        elif mb.get("known"):
            lines.append("MalwareBazaar: KNOWN MALWARE%s" % (" (%s)" % mb["family"] if mb.get("family") else ""))
        else:
            lines.append("MalwareBazaar: not in the malware database")
    return lines


def reputation_findings(apps, labeler, idents, rep):
    """One malware finding per app, judged over ALL its parts:
      - any part flagged            -> BAD
      - any part suspicious         -> WARN
      - some part couldn't be read  -> INFO 'only partly checked' (never OK)
      - every part known & clean    -> OK
      - otherwise                   -> INFO 'not known to the databases'
    Plus a separate WARN when parts are signed by different keys."""
    out = []
    for p, ident in idents.items():
        lbl = label_of(apps, labeler, p)
        parts = identity_parts(ident)
        legacy = not isinstance(ident.get("parts"), list)
        read = [x for x in parts if x.get("sha256")]
        unread = [x for x in parts if not x.get("sha256")]
        verdicts = [(x, part_verdict(rep.get(x["sha256"])), rep.get(x["sha256"]) or {}) for x in read]
        kinds = {v for _, v, _ in verdicts}
        multi = len(parts) > 1

        lines = []
        for x, v, r in verdicts:
            ll = _lookup_lines(r.get("vt"), r.get("mb")) or ["not looked up yet"]
            if multi:
                lines.append("%s: %s" % (apk_part_label(x).capitalize(), "; ".join(ll)))
            else:
                lines.extend(ll)
        for x in unread:
            lines.append("%s: couldn't be read from the phone (%s) - NOT checked" % (
                apk_part_label(x).capitalize(), x.get("error") or "unknown reason"))
        if legacy:
            lines.append("Only the main app file was checked (result from an older version of this "
                         "program). Run a deep scan to check every part of the app.")
        if not any(r.get("vt") or r.get("mb") for _, _, r in verdicts) and not unread:
            lines.append("No lookup service is set up - add a key in Security settings.")

        partial = bool(unread) or legacy or ident.get("coverage") == "partial"
        if "bad" in kinds:
            level, title = BAD, "Flagged as malware: %s" % lbl
        elif "sus" in kinds:
            level, title = WARN, "Some scanners are suspicious of: %s" % lbl
        elif partial:
            level, title = INFO, "Only partly checked: %s" % lbl
        elif read and kinds == {"clean"}:
            level, title = OK, "Clean on VirusTotal: %s%s" % (lbl, " (all %d parts)" % len(parts) if multi else "")
        else:
            level, title = INFO, "Not known to the databases: %s" % lbl
        if partial and level in (BAD, WARN):
            lines.append("Note: %s part(s) couldn't be checked at all." % (len(unread) or "some"))
        advice = ("Uninstall it, change passwords you used on this device, and check the 'Powerful access' "
                  "section." if level == BAD else (
                      "A few detections can be false alarms (often adware or aggressive trackers). "
                      "Look at the link and decide." if level == WARN else (
                          "Run the deep scan again; if a part still can't be read, the phone may be "
                          "blocking access to it." if partial else "")))
        tech = []
        for x in parts:
            tech.append("%s  %s  sha256 %s  cert %s" % (
                x.get("name", "?"), x.get("kind", "?"), x.get("sha256") or "-",
                (x.get("cert") or "-") if x.get("sha256") else "-"))
            r = rep.get(x.get("sha256") or "", {})
            for y in (r.get("vt"), r.get("mb")):
                if y and y.get("link"):
                    tech.append("    " + y["link"])
        tech.append("coverage %s, signers %s" % ("legacy-base-only" if legacy else ident.get("coverage", "?"),
                                                 ident.get("signers", "unknown")))
        out.append(finding("malware", level, title, "\n".join(lines), advice, "\n".join(tech),
                           pkg=p, key="malware:%s" % p))

        if ident.get("signers") == "different":
            base_set = set(ident.get("certs") or [])
            odd = [apk_part_label(x) for x in read if x.get("certs") and set(x["certs"]) != base_set]
            unk = [apk_part_label(x) for x in read if not x.get("certs")]
            text = ("Every part of an app should be signed by the same developer key - Android normally "
                    "refuses to install it otherwise. Here these parts don't match the main app file: %s. "
                    "This can mean the app was tampered with, or that this program misread a signature."
                    % ", ".join(odd))
            if unk:
                text += (" The signature of %s couldn't be read at all, so it's unknown whether "
                         "it matches." % ", ".join(unk))
            out.append(finding(
                "malware", WARN, "Parts of %s are signed by different keys" % lbl, text,
                "Compare with a fresh copy from a trusted store before trusting this app.",
                "\n".join("%s certs %s" % (x.get("name"), ",".join(x.get("certs") or []) or "-")
                          for x in read), pkg=p, key="malware-signers:%s" % p))
    out.sort(key=lambda f: (LEVEL_RANK[f["level"]], f["title"].lower()))
    return out


def tracker_findings(apps, labeler, reports):
    out = []
    for p, r in reports.items():
        lbl = label_of(apps, labeler, p)
        if r.get("error"):
            out.append(finding("trackers", INFO, "Couldn't get the tracker report: %s" % lbl, r["error"],
                               pkg=p, key="trackers:%s" % p))
        elif not r.get("found"):
            out.append(finding("trackers", INFO, "No Exodus report for %s" % lbl,
                               "Exodus Privacy hasn't analysed this app.", pkg=p, key="trackers:%s" % p))
        else:
            n = len(r["trackers"])
            level = OK if n == 0 else (WARN if n >= 5 else INFO)
            out.append(finding("trackers", level, "%s: %d tracker%s" % (lbl, n, "" if n == 1 else "s"),
                               ("It contains: " + ", ".join(r["trackers"])) if n else "No known trackers inside.",
                               "" if r.get("exact") else "Report is for version %s - yours may differ slightly."
                               % (r.get("version") or "?"), r.get("link", ""), pkg=p, key="trackers:%s" % p))
    out.sort(key=lambda f: (LEVEL_RANK[f["level"]], f["title"].lower()))
    return out


# --------------------------------------------------------------------------
# rooting database: one AI rooting answer per codename, shared across devices
# --------------------------------------------------------------------------

ROOTING_DB_SCHEMA = 2   # 1 = legacy codename-keyed flat dict; 2 = {schema, entries{}}


class RootingDBError(Exception):
    """Raised when the rooting DB can't be stored safely (e.g. private perms failed)."""


_rooting_db_future = [False]   # set when a newer-than-supported schema is seen


def rooting_db_is_future():
    """True if the on-disk DB was written by a newer app version (schema > ours).
    In that case we never rewrite it and operate read-only to avoid data loss."""
    return _rooting_db_future[0]


def _ensure_private_dir():
    """Create CONFIG_DIR as 0700. Raises RootingDBError if perms can't be set."""
    try:
        os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
    except OSError as e:
        raise RootingDBError("can't create %s: %s" % (CONFIG_DIR, e))
    try:
        os.chmod(CONFIG_DIR, 0o700)
    except OSError as e:
        raise RootingDBError("can't set private (0700) permissions on %s: %s" % (CONFIG_DIR, e))


def _write_rooting_db(entries, force=False):
    """Persist the entries map privately (0600 file, 0700 dir) with schema version.
    Returns True on success, False on failure (never raises to GUI callers). Refuses
    to overwrite a future-schema file unless force=True (used to deliberately reset)."""
    if _rooting_db_future[0] and not force:
        return False
    try:
        _ensure_private_dir()
    except RootingDBError:
        return False
    ok = save_json(ROOTING_DB_FILE, {"schema": ROOTING_DB_SCHEMA, "entries": entries}, private=True)
    if ok and force:
        _rooting_db_future[0] = False   # we just wrote a current-schema file
    return ok


def _backup_once():
    """Copy the current DB file to .bak once, with private perms (0600)."""
    try:
        if os.path.exists(ROOTING_DB_FILE) and not os.path.exists(ROOTING_DB_FILE + ".bak"):
            import shutil as _sh
            _sh.copy2(ROOTING_DB_FILE, ROOTING_DB_FILE + ".bak")
            try:
                os.chmod(ROOTING_DB_FILE + ".bak", 0o600)
            except OSError:
                pass
    except OSError:
        pass


def _keep_damaged(path):
    """A saved file exists but can't be read as JSON: copy it aside once (0600) so the
    next save can't silently destroy it. Best effort."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return                                       # can't even read it: nothing to copy
    try:
        if not data.strip() or isinstance(json.loads(data.decode("utf-8")), dict):
            return                                   # empty, or a readable object: nothing to keep
    except (ValueError, UnicodeDecodeError):
        pass                                         # not JSON / not a JSON object: keep a copy
    folder, base = os.path.split(path)
    try:
        names = os.listdir(folder or ".")
    except OSError:
        names = []
    for n in names:                                  # the same damaged content is kept only once
        if n.startswith(base + ".damaged-"):
            try:
                with open(os.path.join(folder, n), "rb") as f:
                    if f.read() == data:
                        return
            except OSError:
                continue                             # unreadable entry: check the others
    try:
        dest = "%s.damaged-%s" % (path, time.strftime("%Y%m%d-%H%M%S"))
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except OSError:
        pass


def load_rooting_db():
    """Return the entries map {key: entry}, migrating older formats once.

    Migration decides from the TOP-LEVEL structure, not per-entry:
      - current schema (2): return entries as-is.
      - future schema (>2): don't touch it; operate read-only (rooting_db_is_future).
      - any older/flat structure: migrate every entry to composite keys and rewrite
        as schema 2. Collisions are kept (disambiguated), nothing is dropped, and a
        one-time 0600 .bak of the pre-migration file is left beside it."""
    _rooting_db_future[0] = False
    raw = load_json(ROOTING_DB_FILE, {})
    if not raw and os.path.exists(ROOTING_DB_FILE):
        _keep_damaged(ROOTING_DB_FILE)               # unreadable: keep a copy before anything overwrites it
    if not isinstance(raw, dict) or not raw:
        return {}
    schema = raw.get("schema")
    if isinstance(schema, int) and schema > ROOTING_DB_SCHEMA:
        _rooting_db_future[0] = True   # newer app wrote this - preserve it untouched
        return raw.get("entries", {}) if isinstance(raw.get("entries"), dict) else {}
    if schema == ROOTING_DB_SCHEMA and isinstance(raw.get("entries"), dict):
        return raw["entries"]

    # Anything else is an older/intermediate structure needing migration: a bare
    # {codename/key: entry} map, or a wrapper with entries{} but an older schema,
    # or entries that already have identity dicts but no current schema wrapper.
    source = raw.get("entries") if isinstance(raw.get("entries"), dict) else raw
    entries = {}
    for key, entry in source.items():
        if key in ("schema", "entries") or not isinstance(entry, dict):
            continue
        if "identity" not in entry:
            entry["identity"] = {"maker": entry.get("maker", ""),
                                 "codename": entry.get("codename", key),
                                 "model": entry.get("model_number", ""),
                                 "platform": entry.get("chip", ""),
                                 "region": entry.get("region", "")}
        new_key = identity_key_str(entry["identity"])
        if new_key in entries:        # collision: keep both, don't overwrite
            n = 2
            while "%s#%d" % (new_key, n) in entries:
                n += 1
            new_key = "%s#%d" % (new_key, n)
        entries[new_key] = entry
    _backup_once()
    _write_rooting_db(entries)   # always rewrite older structures in current schema
    return entries


def device_identity(info):
    """The composite identity for a device. Any part may be '' if the device
    didn't report it. The key is built from maker|codename|model|platform|region
    so regional variants (different unlock policy / firmware) don't overwrite each
    other. SoC fields are recorded for display/variant reasoning but NOT invented."""
    props = (info or {}).get("props", {})
    return {
        "maker": (props.get("ro.product.manufacturer") or props.get("ro.product.brand") or "").strip(),
        "codename": (info or {}).get("codename", "").strip(),
        "model": props.get("ro.product.model", "").strip(),
        "platform": (props.get("ro.board.platform") or props.get("ro.product.board") or "").strip(),
        "region": (props.get("ro.miui.region") or props.get("ro.boot.hwcountry")
                   or props.get("ro.boot.hwc") or (info or {}).get("region", "")).strip(),
        # SoC identifiers kept distinct; these are NOT the same as board/platform
        "soc_model": props.get("ro.soc.model", "").strip(),
        "soc_manufacturer": props.get("ro.soc.manufacturer", "").strip(),
        "board": props.get("ro.product.board", "").strip(),
    }


# Fields that form the DB key (identity that distinguishes a flashable variant).
KEY_FIELDS = ("maker", "codename", "model", "platform", "region")
# Fields compared for conflict/agreement (SoC adds corroboration when present).
MATCH_FIELDS = ("maker", "codename", "model", "platform", "region", "soc_model", "board")


def identity_key_str(identity):
    """The DB key for an identity: maker|codename|model|platform|region, lowercased."""
    return "|".join((identity.get(f, "") or "") for f in KEY_FIELDS).lower()


def _entry_identity(e):
    i = e.get("identity", {})
    return {"maker": i.get("maker", "") or e.get("maker", ""),
            "codename": i.get("codename", "") or e.get("codename", ""),
            "model": i.get("model", "") or e.get("model_number", ""),
            "platform": i.get("platform", "") or e.get("chip", ""),
            "region": i.get("region", "") or e.get("region", ""),
            "soc_model": i.get("soc_model", ""),
            "soc_manufacturer": i.get("soc_manufacturer", ""),
            "board": i.get("board", "")}


def identity_conflict(a, b):
    """True if two identities POSITIVELY disagree on any field both actually have.
    Missing fields don't conflict - only values present on both sides and differing."""
    for k in MATCH_FIELDS:
        va, vb = (a.get(k) or "").strip().lower(), (b.get(k) or "").strip().lower()
        if va and vb and va != vb:
            return True
    return False


# The identity fields that, together with codename, make a variant "sufficiently
# complete" to call a match exact. (region distinguishes regional variants.)
_VARIANT_FIELDS = ("maker", "model", "platform", "region")


def identity_match_quality(want, have):
    """Grade how well two identities match, from fields present on BOTH sides.

      "conflict" - any shared field positively disagrees.
      "exact"    - codename agrees AND every variant field present on both agrees
                   AND enough of them are present to distinguish a variant
                   (codename + >=2 of maker/model/platform/region).
      "partial"  - codename agrees and some variant evidence agrees, but not enough
                   to fully establish the variant.
      "codename" - ONLY the codename is shared evidence.
      "none"     - no shared codename -> never auto-reuse device-specific steps.

    A matching codename is REQUIRED for any reuse grade: without it, we return
    "none" even if maker/model/platform happen to line up, because rooting steps
    are keyed to the codename."""
    if identity_conflict(want, have):
        return "conflict"
    wc = (want.get("codename") or "").strip().lower()
    hc = (have.get("codename") or "").strip().lower()
    if not wc or not hc or wc != hc:
        return "none"   # codename not confirmed on both sides -> no reuse
    # codename agrees. Count variant fields present AND agreeing on both sides.
    agree = [k for k in _VARIANT_FIELDS
             if (want.get(k) or "").strip() and (have.get(k) or "").strip()
             and (want.get(k) or "").strip().lower() == (have.get(k) or "").strip().lower()]
    if len(agree) >= 2:
        return "exact"
    if len(agree) >= 1:
        return "partial"
    return "codename"


def rooting_db_get(info):
    """Look up a saved entry for a device.

    Returns a copy of the entry with a "match" field:
        "exact"     - composite identity corroborated (codename + >=1 of
                      maker/model/platform agree, nothing conflicts)
        "codename"  - only the codename could be confirmed; full hardware identity
                      unconfirmed (missing fields, not a positive conflict)
        "ambiguous" - several saved variants are compatible; caller should let the
                      user choose. The copy also carries "candidates": [keys].
    Entries whose identity POSITIVELY conflicts with the device are never returned.
    `info` may also be a bare codename string (compatibility) - that can only ever
    yield a "codename" (or "ambiguous") match, never "exact"."""
    db = load_rooting_db()
    if not db:
        return None
    if isinstance(info, str):
        want = {"codename": info.strip(), "maker": "", "model": "", "platform": ""}
    else:
        want = device_identity(info)

    graded = []   # (quality, key, entry)
    for key, e in db.items():
        q = identity_match_quality(want, _entry_identity(e))
        if q in ("exact", "partial", "codename"):
            graded.append((q, key, e))
    if not graded:
        return None
    # pick the strongest grade present, but if more than one entry shares the best
    # grade the result is ambiguous and the caller must let the user choose.
    for grade in ("exact", "partial", "codename"):
        hits = [g for g in graded if g[0] == grade]
        if not hits:
            continue
        if len(hits) == 1:
            return dict(hits[0][2], match=grade, key=hits[0][1])
        return dict(hits[0][2], match="ambiguous",
                    candidates=[g[1] for g in graded], ambiguous_grade=grade)
    return None


def rooting_db_get_key(key):
    """Fetch one entry by its exact DB key, as a MANUAL selection.

    match="selected" signals the user picked this variant by hand - it does NOT
    assert the saved variant matches the connected device, so the caller computes
    compatibility separately."""
    db = load_rooting_db()
    e = db.get(key)
    return dict(e, match="selected", key=key) if e else None


def rooting_db_put(info, res):
    """Store one AI rooting result under the device's composite identity.
    `info` is the device_info() dict (or, for refresh-all, a reconstructed one).
    Returns True only if the entry was actually persisted to disk."""
    if not isinstance(res, dict) or not res.get("answer"):
        return False
    if _rooting_db_future[0]:
        return False   # never overwrite a newer-schema DB
    db = load_rooting_db()
    if _rooting_db_future[0]:        # load may have detected a future schema
        return False
    identity = device_identity(info)
    if not any(identity.values()):
        return False
    props = (info or {}).get("props", {})
    db[identity_key_str(identity)] = {
        "identity": identity,
        "codename": identity.get("codename", ""),
        "maker": identity.get("maker", ""),
        "model_number": identity.get("model", ""),
        "marketname": (info or {}).get("marketname", ""),
        "answer": res["answer"],
        "provider": res.get("provider", ""),
        "model": res.get("model", ""),
        "when": res.get("when", time.strftime("%Y-%m-%d %H:%M")),
        "researched_release": props.get("ro.build.version.release", ""),
        "researched_sdk": props.get("ro.build.version.sdk", ""),
        "researched_patch": props.get("ro.build.version.security_patch", ""),
        "researched_build": (props.get("ro.mi.os.version.incremental")
                             or props.get("ro.build.version.incremental", "")),
        "researched_fingerprint": props.get("ro.build.fingerprint", ""),
        # kept for display/back-compat; distinct SoC fields live in identity
        "chip": identity.get("platform", "") or props.get("ro.product.board", ""),
        "soc_model": identity.get("soc_model", ""),
        "soc_manufacturer": identity.get("soc_manufacturer", ""),
        "board": identity.get("board", ""),
        "region": identity.get("region", ""),
    }
    return _write_rooting_db(db)


def rooting_db_delete(key):
    """Delete by the exact DB key (as shown in the database window).

    A bare codename is accepted ONLY when it matches exactly one entry; if several
    variants share it, deletion is refused (returns False) so the caller must pass
    the exact key. This prevents deleting an arbitrary variant."""
    db = load_rooting_db()
    if key in db:
        del db[key]
        return _write_rooting_db(db)
    matches = [k for k in db
               if (_entry_identity(db[k]).get("codename", "")).lower() == str(key).strip().lower()]
    if len(matches) == 1:
        del db[matches[0]]
        return _write_rooting_db(db)
    return False   # 0 matches, or ambiguous (several variants) -> refuse


def rooting_compatibility(entry, info):
    """Compare the connected device's firmware with what the cached entry was
    researched at. Does NOT do lexicographical version comparison. Returns
    (status, message, fields) where status is:
        "match"    - same build fingerprint (or same build/API where fingerprint
                     is absent): firmware-specific steps should still apply
        "hardware" - same model, firmware differs: hardware/unlock research still
                     applies, but firmware-specific flashing steps need checking
        "verify"   - compatibility can't be established -> REQUIRES VERIFICATION
    fields maps each compared field -> (same|differs|unknown, old, now)."""
    if not entry or not info:
        return "verify", "no data to compare", {}
    props = info.get("props", {})
    now = {"fingerprint": props.get("ro.build.fingerprint", ""),
           "sdk": props.get("ro.build.version.sdk", ""),
           "release": props.get("ro.build.version.release", ""),
           "patch": props.get("ro.build.version.security_patch", ""),
           "build": (props.get("ro.mi.os.version.incremental")
                     or props.get("ro.build.version.incremental", ""))}
    was = {"fingerprint": entry.get("researched_fingerprint", ""),
           "sdk": entry.get("researched_sdk", ""),
           "release": entry.get("researched_release", ""),
           "patch": entry.get("researched_patch", ""),
           "build": entry.get("researched_build", "")}
    fields = {}
    for k in now:
        if now[k] and was[k]:
            fields[k] = ("same" if now[k] == was[k] else "differs", was[k], now[k])
        else:
            fields[k] = ("unknown", was[k], now[k])

    # Any field present on both sides that disagrees means firmware is not identical.
    differs = [k for k in ("fingerprint", "build", "patch", "sdk", "release")
               if now[k] and was[k] and now[k] != was[k]]

    if now["fingerprint"] and was["fingerprint"]:
        if now["fingerprint"] == was["fingerprint"]:
            # fingerprint matches; make sure nothing else present contradicts it
            contradict = [k for k in ("build", "patch", "sdk", "release")
                          if now[k] and was[k] and now[k] != was[k]]
            if contradict:
                return "verify", ("build fingerprint matches but %s disagrees - treat as needing "
                                  "verification" % ", ".join(contradict)), fields
            return "match", "same build fingerprint - firmware is identical", fields
        same_api = now["sdk"] and was["sdk"] and now["sdk"] == was["sdk"]
        msg = "same API level, different build" if same_api else "different API level and build"
        return "hardware", "firmware differs (%s)" % msg, fields

    # No usable fingerprint on at least one side.
    if differs:
        # a build or security-patch difference is a real firmware change; an API/
        # release-only difference means hardware research may still apply.
        if any(k in ("build", "patch", "fingerprint") for k in differs):
            return "hardware", "firmware differs (%s changed)" % ", ".join(differs), fields
        return "hardware", "API/Android level differs (%s) - firmware-specific steps need " \
                           "checking" % ", ".join(differs), fields

    # Nothing contradicts. Is there enough POSITIVE evidence to call it identical?
    # A matching fingerprint is conclusive; otherwise require the incremental build
    # to agree AND be corroborated by another independent property (API or patch),
    # because a build string alone can collide or be reused and doesn't pin the
    # boot image. One identifier matching with other key fields missing -> verify.
    if now["fingerprint"] and was["fingerprint"] and now["fingerprint"] == was["fingerprint"]:
        return "match", "same build fingerprint", fields   # (handled above, kept for safety)
    build_same = now["build"] and was["build"] and now["build"] == was["build"]
    if build_same:
        corroboration = []
        if now["sdk"] and was["sdk"] and now["sdk"] == was["sdk"]:
            corroboration.append("API")
        if now["patch"] and was["patch"] and now["patch"] == was["patch"]:
            corroboration.append("patch")
        if corroboration:
            return "match", "same build, corroborated by %s" % "+".join(corroboration), fields
        return "verify", ("only the build identifier matches - no fingerprint, and API/patch "
                          "aren't both confirmed, so firmware isn't established"), fields
    # No fingerprint, no matching build: insufficient to establish either a match
    # OR a hardware-compatible difference. This is uncertainty, not "hardware".
    return "verify", "can't establish firmware compatibility - build/fingerprint not confirmed", fields


def rooting_entry_stale(entry, info):
    """Back-compat boolean: True when the entry is not an exact firmware match."""
    status, _, _ = rooting_compatibility(entry, info)
    return status != "match"


# ==========================================================================
# APK static inspector - phase 1a: analysis engine
# ==========================================================================
#
# Looks INSIDE an installed app's APK files (base + every split) without ever
# running them: manifest, DEX code references, resources, assets and native
# libraries -> network endpoints (with the code that uses them), suspicious
# code indicators, embedded SDKs, and an honest list of what couldn't be
# analysed.
#
# Process model: the heavy lifting (Androguard) runs in a SEPARATE worker
# process - "<inspector python> security_audit.py --inspect-worker job.json" -
# under memory / CPU / file-size limits, in its own process group, killed on
# timeout or Stop. It's a resource-limited process running with the user's own
# permissions, not a sandbox. The GUI process never imports Androguard, so a crash or a
# hostile APK can't take the app down. Androguard lives in its own virtual
# environment (it pulls in a large dependency tree). Results are local only:
# nothing here talks to the network or to an AI.

INSPECT_SCHEMA = 1
INSPECT_ANDROGUARD = "4.1.4"            # the version this code is tested with
INSPECT_VENV = os.path.join(os.path.expanduser("~"), ".local", "share", "adb_manager", "inspector-venv")
INSPECT_PROGRESS = "ADBM-PROGRESS "     # worker -> parent progress line prefix

# what a stage can end as; anything but "done"/"skipped" makes the result incomplete
STAGE_DONE, STAGE_SKIPPED, STAGE_PARTIAL, STAGE_FAILED, STAGE_TIMEOUT = \
    "done", "skipped", "partial", "failed", "timeout"


def _clamp(v, lo, hi):
    return max(lo, min(hi, v))


def inspector_limits(apk_bytes, dex_bytes, cfg=None):
    """Resource caps for one inspection, derived from THIS computer (RAM, CPUs)
    and the app's size - nothing is tuned to one machine. Overridable through
    the security settings (inspector_mem_mb, inspector_timeout_s, inspector_mode).

    mode "full" traces every address back to its class+method (Androguard's
    whole-program analysis: slower, more memory); "quick" reads the code
    tables only. "auto" picks full when the estimated need fits comfortably."""
    cfg = cfg or {}
    try:
        ram = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        ram = 4 << 30
    cpus = os.cpu_count() or 1
    mem = _clamp(int(ram * 0.5), 1536 << 20, 16 << 30)
    if cfg.get("inspector_mem_mb"):
        mem = int(cfg["inspector_mem_mb"]) << 20
    # rough: full analysis needs ~350 MB + ~60x the DEX size; quick ~250 MB + ~8x
    need_full = (350 << 20) + 60 * dex_bytes
    mode = cfg.get("inspector_mode") or "auto"
    if mode == "auto":
        mode = "full" if need_full <= mem * 0.7 else "quick"
    slow = 2.0 / _clamp(cpus, 1, 2)                    # single-core machines get more time
    timeout = int(_clamp((180 + 40 * (dex_bytes >> 20) + 4 * (apk_bytes >> 20)) * slow, 180, 3600))
    if cfg.get("inspector_timeout_s"):
        timeout = int(cfg["inspector_timeout_s"])
    return {"mem_bytes": mem, "timeout_s": timeout, "mode": mode, "cpu_s": timeout * 2,
            "file_bytes": 2 << 30,               # largest file the worker may write
            "max_entries": 200000,               # zip entries per APK part
            "max_uncompressed": 4 << 30,         # total uncompressed size per part
            "max_ratio": 200,                    # per-entry compression ratio (bombs)
            "max_native_lib": 96 << 20, "max_native_total": 384 << 20,
            "max_asset_file": 2 << 20, "max_asset_total": 48 << 20,
            "ram_bytes": ram, "cpus": cpus, "need_full_bytes": need_full}


INSPECT_INSTALL_HELP = (
    "The code inspector needs Androguard %(v)s in its own Python environment:\n\n"
    "  python3 -m venv %(venv)s\n"
    "  %(venv)s/bin/pip install androguard==%(v)s\n\n"
    "If 'python3 -m venv' fails, install your system's venv package first:\n"
    "  Debian / Ubuntu:  sudo apt install python3-venv\n"
    "  Fedora:           (included with python3)\n"
    "  Arch:             (included with python)\n\n"
    "Optional, for reading imported functions of native libraries: 'readelf'\n"
    "(package 'binutils' on Debian/Ubuntu, Fedora and Arch).")


def _probe_androguard(python, timeout=30):
    """Version of Androguard importable by that interpreter, or None."""
    try:
        p = subprocess.run([python, "-c", "import sys, androguard; "
                            "print(androguard.__version__); print(sys.version.split()[0])"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                           timeout=timeout, env=_worker_env())
    except (OSError, subprocess.TimeoutExpired):
        return None
    if p.returncode != 0:
        return None
    lines = p.stdout.decode("utf-8", "replace").split()
    return {"androguard": lines[0], "python": lines[1]} if len(lines) >= 2 else None


def inspector_env(cfg=None):
    """Which tools the inspector can use on this computer. Never installs anything.
    Returns {"python", "androguard", "python_version", "readelf", "ok", "problems",
    "help"}; ok means the required part (Androguard) is usable."""
    import shutil
    import sys
    cfg = cfg or {}
    candidates = [cfg.get("inspector_python"), os.path.join(INSPECT_VENV, "bin", "python"), sys.executable]
    env = {"python": None, "androguard": None, "python_version": None,
           "readelf": shutil.which("readelf"), "problems": [], "help": INSPECT_INSTALL_HELP % {
               "v": INSPECT_ANDROGUARD, "venv": INSPECT_VENV}}
    for py in [c for c in candidates if c]:
        if not os.path.exists(py):
            continue
        got = _probe_androguard(py)
        if got:
            env.update(python=py, androguard=got["androguard"], python_version=got["python"])
            break
    if not env["python"]:
        env["problems"].append("Androguard isn't installed for the inspector")
    elif env["androguard"] != INSPECT_ANDROGUARD:
        env["problems"].append("Androguard %s found; this program is tested with %s - results may differ"
                               % (env["androguard"], INSPECT_ANDROGUARD))
    if not env["readelf"]:
        env["problems"].append("readelf not found: native libraries are scanned for addresses, but their "
                               "imported network functions can't be listed")
    env["ok"] = bool(env["python"])
    return env


# ---- container safety (pure Python: runs before any parser touches the APK) -

def apk_container_check(path, limits):
    """Inspect an APK's zip structure WITHOUT extracting it. Returns
    {"ok": bool, "problems": [(severity, text)], "dex": [...], "native": [...],
     "assets": [...], "entries": n, "uncompressed": bytes}.
    severity "fatal" stops analysis of that part (malformed, bomb, too big);
    "warn" is reported but analysis goes on - nothing is ever written to disk
    under a name taken from the archive."""
    import stat as _stat
    out = {"ok": True, "problems": [], "dex": [], "native": [], "assets": [], "entries": 0,
           "uncompressed": 0}

    def bad(sev, text):
        out["problems"].append((sev, text))
        if sev == "fatal":
            out["ok"] = False
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError, ValueError) as e:
        bad("fatal", "not a readable APK/zip file (%s)" % (str(e) or type(e).__name__))
        return out
    with zf:
        infos = zf.infolist()
        out["entries"] = len(infos)
        if len(infos) > limits["max_entries"]:
            bad("fatal", "too many files inside (%d)" % len(infos))
            return out
        seen = set()
        for i in infos:
            n = i.filename
            if n in seen:
                bad("warn", "the same name appears twice inside the APK: %r - different tools could read "
                            "different contents (a known tampering trick)" % n[:200])
            seen.add(n)
            parts = n.replace("\\", "/").split("/")
            if n.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", n) or ".." in parts or "\x00" in n \
                    or "\\" in n:
                bad("warn", "unsafe file name inside the APK: %r" % n[:200])
            if _stat.S_ISLNK(i.external_attr >> 16):
                bad("warn", "symbolic link inside the APK: %r" % n[:200])
            if i.flag_bits & 0x1:
                bad("warn", "encrypted entry inside the APK: %r" % n[:200])
            out["uncompressed"] += i.file_size
            if i.compress_size and i.file_size > (1 << 20) and i.file_size / i.compress_size > limits["max_ratio"]:
                bad("fatal", "an entry expands %dx (%r) - looks like a decompression bomb"
                    % (i.file_size // max(1, i.compress_size), n[:200]))
            base = parts[-1]
            if re.match(r"^classes\d*\.dex$", n):
                out["dex"].append(n)
            elif n.startswith("lib/") and base.endswith(".so"):
                out["native"].append(n)
            elif n.startswith(("assets/", "res/raw/")):
                out["assets"].append(n)
        if out["uncompressed"] > limits["max_uncompressed"]:
            bad("fatal", "too large when unpacked (%d MB)" % (out["uncompressed"] >> 20))
    return out


def read_member_capped(zf, name, cap):
    """Read one archive member into memory, refusing to go past `cap` bytes no
    matter what the header claims. Returns bytes or raises ValueError."""
    buf, total = [], 0
    with zf.open(name) as f:
        while True:
            chunk = f.read(1 << 16)
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                raise ValueError("%s is larger than the %d MB limit" % (name, cap >> 20))
            buf.append(chunk)
    return b"".join(buf)


# ---- endpoints: extraction and classification -----------------------------

_URL_RE = re.compile(r"\b(?:https?|wss?|ftp)://[^\s\"'<>\\^`{|}]{1,2048}", re.I)
_IP_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?(?![\d.])")
# bare IPv6, optionally "[addr]:port". ipaddress decides validity: invalid C++
# expressions ("std::string", "Foo::Bar::baz", "ns::a::b") are rejected by it,
# while valid-but-ambiguous ones ("a::b", "dead::beef") are kept and labelled.
_IP6_RE = re.compile(r"(?<![\w:.\[])(\[)?([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?(1)\](?::(\d{1,5}))?)(?![\w:.])")
_HOST_TLDS = ("com", "net", "org", "io", "co", "app", "dev", "info", "biz", "me", "tv", "cn", "ru", "de",
              "uk", "fr", "jp", "br", "in", "eu", "us", "xyz", "cloud", "ai", "top", "site", "online",
              "tech", "pt", "es", "it", "nl", "pl", "kr", "tw", "hk", "sg", "au", "ca", "mx", "tk", "cc",
              "ws", "pw", "su", "ir", "ly", "link", "live", "club", "pro", "shop", "store")
_HOST_RE = re.compile(r"(?<![\w.\-/@])((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:%s))(?::(\d{1,5}))?(?![\w\-.])"
                      % "|".join(_HOST_TLDS))
# first labels that mean "Java/Kotlin package name", not a host
_PKG_ROOTS = {"com", "org", "net", "android", "androidx", "java", "javax", "kotlin", "kotlinx", "dalvik", "io",
              "de", "uk", "fr", "jp", "cn", "ru", "me", "co", "app", "dev", "info", "us", "eu", "sun", "libcore"}
_PLACEHOLDER_RE = re.compile(r"%[0-9.$]*[sdxXf]|\{[^}]{0,40}\}|\$\{|<[a-z_]{1,30}>")
_STD_PORTS = {80, 443, 8080, 8443}


def _parse_endpoint(value):
    """Split a URL into scheme/host/port; None if it isn't one."""
    try:
        u = urllib.parse.urlsplit(value)
        host = (u.hostname or "").lower()
        port = u.port
    except ValueError:
        return None
    if not host:
        return None
    return {"scheme": u.scheme.lower(), "host": host, "port": port}


def extract_endpoints(text, package_like=()):
    """Find network endpoints in one string. Returns a list of
    {"value", "kind" (url|ip|host), "scheme", "host", "port", "constructed"}.
    package_like: Java package / class name prefixes present in the app, so that
    'com.example.foo' style names aren't mistaken for host names."""
    found, spans = [], []
    for m in _URL_RE.finditer(text):
        v = m.group(0).rstrip(").,;:'\"!]")
        p = _parse_endpoint(v)
        if not p:
            continue
        spans.append(m.span())
        found.append(dict(p, value=v, kind="url", constructed=bool(_PLACEHOLDER_RE.search(v))
                          or v.endswith(("/", "=", "?"))))

    def inside(span):
        return any(a <= span[0] and span[1] <= b for a, b in spans)
    for m in _IP_RE.finditer(text):
        if inside(m.span()):
            continue
        ip = m.group(1)
        try:
            import ipaddress
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        port = int(m.group(2)) if m.group(2) and int(m.group(2)) <= 65535 else None
        found.append({"value": m.group(0), "kind": "ip", "scheme": "", "host": ip, "port": port,
                      "constructed": False})
    for m in _IP6_RE.finditer(text):
        if inside(m.span()):
            continue
        cand = m.group(2)
        try:
            import ipaddress
            ip6 = ipaddress.IPv6Address(cand)
        except ValueError:
            continue                      # not a valid address at all
        if ip6.is_unspecified:
            continue                      # "::" alone means "no address" - never a destination
        # Valid IPv6 that has the exact SHAPE of C++ scope text - unbracketed, one
        # "::" and no single ":", every part a C++ identifier (letter/_ first, then
        # letters/digits/_): a::b, dead::beef, face::b00c, a1::b2, ::b. Kept, but
        # marked ambiguous so it isn't treated as a confirmed network destination.
        # 2001::1 / ::1 aren't ambiguous: a part starting with a digit can't be a
        # C++ identifier. Brackets ([dead::beef]:4444) are address notation.
        halves = cand.split("::")
        ambiguous = (not m.group(1) and len(halves) == 2 and ":" not in halves[0] and ":" not in halves[1]
                     and all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", h) for h in halves if h))
        port = int(m.group(3)) if m.group(3) and int(m.group(3)) <= 65535 else None
        spans.append(m.span())
        found.append({"value": m.group(0), "kind": "ip", "scheme": "", "host": str(ip6), "port": port,
                      "constructed": False, "ambiguous": ambiguous})
    for m in _HOST_RE.finditer(text):
        if inside(m.span()):
            continue
        host = m.group(1)
        labels = host.split(".")
        if labels[0] in _PKG_ROOTS or len(labels) < 2 or any(host == p or p.startswith(host + ".")
                                                             for p in package_like):
            continue
        port = int(m.group(2)) if m.group(2) and int(m.group(2)) <= 65535 else None
        found.append({"value": m.group(0), "kind": "host", "scheme": "", "host": host, "port": port,
                      "constructed": False})
    return found


def registrable_domain(host):
    """'api.eu.example.co.uk' -> 'example.co.uk' (simple public-suffix rule)."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and labels[-2] in ("co", "com", "net", "org", "gov", "ac", "edu") and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


# Fallback table of common SDKs, written for this program from public package
# and domain names (not copied from any tracker database). Used when no Exodus
# tracker data is cached. Incomplete by nature - an SDK not listed here is
# "unknown", never "safe".
SDK_FALLBACK = [
    # name, code package prefixes, domains it is known to contact
    ("Firebase", ("com.google.firebase",), ("firebaseio.com", "firebase.google.com", "firebaseinstallations.googleapis.com",
                                           "firebaselogging.googleapis.com", "app-measurement.com")),
    ("Google Mobile Ads", ("com.google.android.gms.ads",), ("doubleclick.net", "googlesyndication.com",
                                                            "googleadservices.com")),
    ("Facebook SDK", ("com.facebook",), ("facebook.com", "fbcdn.net", "facebook.net")),
    ("AppsFlyer", ("com.appsflyer",), ("appsflyer.com", "appsflyersdk.com")),
    ("Adjust", ("com.adjust.sdk",), ("adjust.com", "adjust.io")),
    ("Branch", ("io.branch",), ("branch.io", "app.link")),
    ("OneSignal", ("com.onesignal",), ("onesignal.com",)),
    ("Sentry", ("io.sentry",), ("sentry.io",)),
    ("Crashlytics", ("com.crashlytics", "com.google.firebase.crashlytics"), ("crashlytics.com",)),
    ("Unity Ads", ("com.unity3d.ads", "com.unity3d.services"), ("unityads.unity3d.com", "unity3d.com")),
    ("AppLovin", ("com.applovin",), ("applovin.com", "applvn.com")),
    ("Mixpanel", ("com.mixpanel",), ("mixpanel.com",)),
    ("Amplitude", ("com.amplitude",), ("amplitude.com",)),
    ("Segment", ("com.segment",), ("segment.io", "segment.com")),
    ("Braze", ("com.braze", "com.appboy"), ("braze.com", "appboy.com")),
    ("Microsoft App Center", ("com.microsoft.appcenter",), ("appcenter.ms",)),
    ("Bugsnag", ("com.bugsnag",), ("bugsnag.com",)),
]
_GENERIC_PKG_WORDS = {"com", "org", "net", "android", "app", "apps", "mobile", "client", "free", "pro", "lite",
                      "main", "application", "google", "gms", "io", "co", "de", "the", "www"}


def sdk_owner(dotted_class, signatures):
    """Which SDK a class belongs to: (name, source) or (None, None).
    signatures = [(name, [package prefixes], [domains], source)]."""
    for name, prefixes, _, source in signatures:
        for pref in prefixes:
            base = pref.rstrip(".")
            if dotted_class == base or dotted_class.startswith(base + "."):
                return name, source
    return None, None


def inspector_signatures(cached_exodus=None):
    """SDK signatures: cached Exodus tracker data (if the deep scan fetched it)
    plus the built-in fallback table. Never fetches anything."""
    sigs = []
    for t in (cached_exodus or []):
        prefixes = [p.strip().rstrip("\\.").replace("\\.", ".") for p in (t.get("code_signature") or "").split("|")
                    if p.strip()]
        domains = [d.strip().lstrip("\\.").replace("\\.", ".") for d in (t.get("network_signature") or "").split("|")
                   if d.strip()]
        if prefixes:
            sigs.append((t.get("name") or "?", prefixes, domains, "Exodus"))
    sigs += [(n, list(p), list(d), "built-in list") for n, p, d in SDK_FALLBACK]
    return sigs


def classify_endpoint(ep, ctx):
    """Classify one endpoint from LOCAL evidence only. ep: {"host", "port",
    "scheme", "kind", "constructed", "locations": [{"part", "source", "cls"}]}.
    ctx: {"package", "signatures", "sdks_present": {name}, "bad_hosts": set()}.

    Returns {"classification", "confidence", "evidence": [...], "issues": [...],
    "owner"}. classification is one of:
      expected   - supporting evidence ties it to the app or an SDK it contains
                   ("expected" is not "safe": tracker endpoints are expected too)
      malicious  - only with explicit evidence (a host in ctx["bad_hosts"])
      suspicious - with the specific reasons listed
      unknown    - not enough evidence either way
    A recognised big-company domain is NOT expected by itself, and an
    unfamiliar one is NOT suspicious by itself."""
    import ipaddress
    host, port = ep["host"], ep.get("port")
    evidence, issues, reasons, owner = [], [], [], None
    sources = {loc.get("source") for loc in ep.get("locations", [])}
    owners = {loc.get("owner") for loc in ep.get("locations", []) if loc.get("owner")}
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    local = bool(ip and (ip.is_loopback or ip.is_private or ip.is_link_local)) or host in ("localhost",)
    if ep.get("scheme") in ("http", "ws", "ftp") and not local:
        issues.append("sent without encryption (%s://) - anyone on the network path can read or change it"
                      % ep["scheme"])
    if host in ctx.get("bad_hosts", ()):
        return {"classification": "malicious", "confidence": "high",
                "evidence": ["listed as malicious in a reputation source you looked up"],
                "issues": issues, "owner": None}
    if ip and ip.is_loopback or host == "localhost":
        return {"classification": "expected", "confidence": "high",
                "evidence": ["loopback address - traffic never leaves the device"], "issues": [], "owner": None}
    if ep.get("ambiguous"):
        return {"classification": "unknown", "confidence": "low",
                "evidence": ["this is valid IPv6 address syntax (%s), but it reads just as well as ordinary "
                             "program text, such as a C++ name - not treated as a network destination "
                             "without more evidence" % host], "issues": [], "owner": None}
    if ip and (ip.is_link_local or (ip.version == 4 and ip.is_private)):
        return {"classification": "unknown", "confidence": "low",
                "evidence": ["a local-network address (router, LAN device) - not on the internet"],
                "issues": [], "owner": None}
    if ip and not ip.is_global:
        return {"classification": "unknown", "confidence": "low",
                "evidence": ["a private or reserved address range - not a normal public internet destination"],
                "issues": [], "owner": None}
    reg = registrable_domain(host) if not ip else ""
    # evidence for "expected"
    for name, prefixes, domains, source in ctx.get("signatures", []):
        if reg and any(registrable_domain(d) == reg or host == d or host.endswith("." + d) for d in domains):
            if name in ctx.get("sdks_present", set()):
                owner = name
                evidence.append("matches the known addresses of %s, whose code is inside this app (%s)"
                                % (name, source))
            else:
                evidence.append("matches the known addresses of %s, but that SDK's code wasn't found here"
                                % name)
            break
    if owners and not owner:
        owner = sorted(owners)[0]
        evidence.append("referenced from code that belongs to %s" % owner)
    pkg_words = {w for w in ctx.get("package", "").lower().split(".") if w not in _GENERIC_PKG_WORDS and len(w) > 2}
    if reg and reg.split(".")[0] in pkg_words:
        evidence.append("the domain matches a word in the app's package name (%s) - a hint it belongs to the "
                        "developer, not proof" % ctx.get("package"))
    # reasons for "suspicious"
    if ip and ip.is_global:
        reasons.append("a raw internet IP address instead of a name%s" % (
            " (a bare number like this can also be a version number)"
            if ip.version == 4 and not port and ep.get("kind") != "url" else ""))
    if port and port not in _STD_PORTS and not local:
        reasons.append("an unusual port (%d)" % port)
    if sources and sources <= {"native", "asset"}:
        reasons.append("found only in %s, not in the app's main code" % " and ".join(sorted(
            {"native": "native libraries", "asset": "bundled asset files"}[s] for s in sources)))
    if reasons:
        cls, conf = "suspicious", "medium" if len(reasons) > 1 else "low"
    elif owner and any("whose code is inside" in e for e in evidence):
        cls, conf = "expected", "medium"
    elif evidence and any(("package name" in e) or ("belongs to" in e) for e in evidence):
        cls, conf = "expected", "low"
    else:
        cls, conf = "unknown", "low"
    return {"classification": cls, "confidence": conf, "evidence": evidence + reasons,
            "issues": issues, "owner": owner}


def obfuscation_level(class_names):
    """Share of classes with 1-2 letter simple names (a, b, aB ...): an analysis
    limitation, not proof of malice (most release apps are minified)."""
    names = [c.strip("L;").split("/")[-1].split("$")[0] for c in class_names]
    names = [n for n in names if n]
    if not names:
        return 0.0
    return sum(1 for n in names if len(n) <= 2) / len(names)


def summarize_inspection(res):
    """The one-line verdict. Never says 'clean': an analysis can only say what
    it found in the parts it could read."""
    stages = res.get("stages", [])
    incomplete = [s for s in stages if s["status"] not in (STAGE_DONE, STAGE_SKIPPED)]
    sus_eps = [e for e in res.get("endpoints", []) if e["classification"] in ("suspicious", "malicious")]
    sus_ind = [i for i in res.get("indicators", []) if i["severity"] in ("warn", "bad")]
    unenc = [e for e in res.get("endpoints", []) if e.get("issues")]
    parts = res.get("parts", [])
    covered = sum(1 for p in parts if p.get("analysed"))
    coverage = "%d of %d app part(s) analysed, %s mode" % (covered, len(parts), res.get("mode", "?"))
    if incomplete or covered < len(parts):
        head = "Analysis incomplete"
        level = INFO
    elif sus_eps or sus_ind:
        head = "Worth a look: %d suspicious address(es), %d code warning(s)" % (len(sus_eps), len(sus_ind))
        level = WARN
    else:
        head = "No suspicious indicators found in the parts analysed"
        level = OK
    extra = []
    if unenc:
        extra.append("%d address(es) used without encryption" % len(unenc))
    if incomplete:
        extra.append("not finished: " + ", ".join(s["name"] for s in incomplete))
    return {"level": level, "text": head, "coverage": coverage, "notes": extra}


# ---- running the worker ----------------------------------------------------

def _worker_env():
    keep = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR") if k in os.environ}
    keep["PYTHONNOUSERSITE"] = "1"
    keep["PYTHONDONTWRITEBYTECODE"] = "1"
    return keep


# Applies the limits as the FIRST thing inside the child, then runs the worker
# script. Used instead of preexec_fn, which isn't safe to use from a program that
# has other threads running (the GUI does). These are resource limits on a normal
# process running with the user's own permissions - not a sandbox.
_LIMITED_BOOT = (
    "import json, os, resource, runpy, sys\n"
    "L = json.loads(sys.argv[1])\n"
    "os.umask(0o077)\n"
    "for k, v in ((resource.RLIMIT_AS, L['mem_bytes']), (resource.RLIMIT_CPU, L['cpu_s']),\n"
    "             (resource.RLIMIT_FSIZE, L['file_bytes']), (resource.RLIMIT_CORE, 0)):\n"
    "    try:\n"
    "        resource.setrlimit(k, (v, v))\n"
    "    except (ValueError, OSError):\n"
    "        pass\n"
    "script = sys.argv[2]\n"
    "sys.argv = [script] + sys.argv[3:]\n"
    "runpy.run_path(script, run_name='__main__')\n")


def limited_cmd(python, limits, script, *args):
    """Command line that runs `script args...` under `limits` (see _LIMITED_BOOT)."""
    lim = {k: int(limits[k]) for k in ("mem_bytes", "cpu_s", "file_bytes")}
    return [python, "-c", _LIMITED_BOOT, json.dumps(lim), script] + list(args)


def run_inspection(job, python, limits, on_progress=None, stop=None, script=None):
    """Run the worker on `job` and return its result dict.

    job: {"package", "version_code", "parts": [{"name", "kind", "path"}],
          "signatures", "mode"}. Paths must be private copies.
    Never raises for worker problems: a crash, a timeout, Stop, bad output or a
    missing result all come back as a result whose stages say so (and whose
    summary is therefore "Analysis incomplete" - never a clean result)."""
    import signal
    import shutil
    import tempfile
    work = tempfile.mkdtemp(prefix="adbm_inspect_")
    os.chmod(work, 0o700)
    started = time.time()
    proc = None

    def failed(status, why, stderr=""):
        res = {"schema": INSPECT_SCHEMA, "package": job.get("package"), "version_code": job.get("version_code"),
               "mode": limits.get("mode"), "parts": [{"name": p["name"], "kind": p.get("kind"), "analysed": False}
                                                     for p in job.get("parts", [])],
               "stages": [{"id": "worker", "name": "code analysis", "status": status, "detail": why}],
               "endpoints": [], "indicators": [], "sdks": [], "limitations": [why],
               "worker_stderr": stderr[-4000:]}
        res["summary"] = summarize_inspection(res)
        return res
    try:
        jpath = os.path.join(work, "job.json")
        rpath = os.path.join(work, "result.json")
        atomic_write_json(jpath, dict(job, mode=limits["mode"], limits=limits, result=rpath,
                                      scratch=os.path.join(work, "scratch")), private=True)
        try:
            proc = subprocess.Popen(limited_cmd(python, limits, script or os.path.abspath(__file__),
                                                "--inspect-worker", jpath),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                    cwd=work, env=_worker_env(), start_new_session=True)
        except OSError as e:
            return failed(STAGE_FAILED, "couldn't start the analysis program: %s" % (e.strerror or e))
        err_chunks = []
        t_err = threading.Thread(target=lambda: err_chunks.append(proc.stderr.read(1 << 20)), daemon=True)
        t_err.start()
        lines = []

        def reader():
            for raw in proc.stdout:
                line = raw.decode("utf-8", "replace").rstrip("\n")
                if line.startswith(INSPECT_PROGRESS) and on_progress:
                    try:
                        on_progress(json.loads(line[len(INSPECT_PROGRESS):]))
                    except (ValueError, TypeError):
                        pass
                lines.append(line)
        t_out = threading.Thread(target=reader, daemon=True)
        t_out.start()
        status, why = None, ""
        while proc.poll() is None:
            if stop is not None and stop.is_set():
                status, why = STAGE_FAILED, "stopped by you"
            elif time.time() - started > limits["timeout_s"]:
                status, why = STAGE_TIMEOUT, "took longer than %d s and was stopped" % limits["timeout_s"]
            if status:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
                break
            time.sleep(0.1)
        proc.wait()
        t_out.join(5)
        t_err.join(5)
        stderr = b"".join(c for c in err_chunks if c).decode("utf-8", "replace")
        if status:
            return failed(status, why, stderr)
        if proc.returncode != 0:
            why = "the analysis program ended with an error (exit %s)" % proc.returncode
            if proc.returncode in (-9, -24) or "MemoryError" in stderr:
                why = "the analysis ran out of its memory or CPU allowance (try quick mode)"
            return failed(STAGE_FAILED, why, stderr)
        try:
            with open(rpath, encoding="utf-8") as f:
                res = json.load(f)
        except (OSError, ValueError) as e:
            return failed(STAGE_FAILED, "the analysis produced no readable result (%s)" % e, stderr)
        if not isinstance(res, dict) or res.get("schema") != INSPECT_SCHEMA:
            return failed(STAGE_FAILED, "the analysis result has an unexpected format", stderr)
        res["summary"] = summarize_inspection(res)
        res["seconds"] = round(time.time() - started, 1)
        return res
    finally:
        if proc is not None:
            for pipe in (proc.stdout, proc.stderr):
                try:
                    pipe.close()
                except (OSError, AttributeError):
                    pass
        shutil.rmtree(work, ignore_errors=True)


# ---- per-identity result cache ---------------------------------------------
#
# One saved inspection per EXACT app version: package + versionCode + the
# SHA-256 of every installed part. A new version, a re-signed copy or a changed
# split gets a different key, so an old result is never shown as current.

INSPECT_DIR = os.path.join(CONFIG_DIR, "inspections")


def inspection_key(pkg, version_code, part_hashes):
    """Stable key for one exact app build (part order doesn't matter)."""
    hs = sorted(h for h in part_hashes if h)
    if not pkg or not hs:
        return None
    return "%s|%s|%s" % (pkg, version_code or "", ",".join(hs))


def inspection_key_from_identity(pkg, version_code, ident):
    """Key from a COMPLETE cached deep-scan identity (no device access needed);
    None if the identity doesn't cover every part."""
    if not identity_complete(ident):
        return None
    return inspection_key(pkg, version_code, [x.get("sha256") for x in identity_parts(ident)])


def _inspection_path(key):
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", key.split("|", 1)[0])[:80]
    return os.path.join(INSPECT_DIR, "%s-%s.json" % (safe, hashlib.sha256(key.encode()).hexdigest()[:20]))


def save_inspection(key, res):
    """Private (0600/0700), atomic. Raises OSError on failure - callers report it."""
    atomic_write_json(_inspection_path(key), dict(res, key=key), private=True)


def load_inspection(key):
    """The saved result for exactly this build, or None (missing, damaged, other
    schema, or saved under a different key)."""
    if not key:
        return None
    try:
        with open(_inspection_path(key), encoding="utf-8") as f:
            res = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(res, dict) or res.get("schema") != INSPECT_SCHEMA or res.get("key") != key:
        return None
    return res


def finding_id(kind, item):
    """Stable id of one finding inside a result (used to file AI answers)."""
    if kind == "endpoint":
        return "ep:" + hashlib.sha256(item.get("value", "").encode()).hexdigest()[:16]
    return "ind:" + item.get("id", "?")


_SECRET_KEYS = r"(?:access_?token|refresh_?token|id_?token|token|api_?key|apikey|key|secret|client_?secret|" \
               r"password|passwd|pwd|pass|auth|authorization|session|sessionid|sid|sig|signature|bearer)"
# value = an optional auth scheme (Bearer/Basic/...) + a quoted string (whole,
# spaces included) or a bare token
_AUTH_SCHEMES = r"(?:bearer|basic|digest|token|negotiate|ntlm)"
_SECRET_VALUE = r"(?:%s\s+)?(?:\"[^\"]*\"|'[^']*'|[^\s\"'&;,]+)" % _AUTH_SCHEMES
_SECRET_KV_RE = re.compile(r"(?i)\b(%s)(\s*[=:]\s*)%s" % (_SECRET_KEYS, _SECRET_VALUE))
# a whole Authorization header value goes - its structure (Digest's username=,
# nonce=, response= ...) is never parsed field by field
_AUTH_HEADER_RE = re.compile(r"(?i)\b((?:proxy-)?authorization)(\s*[=:]\s*)[^\r\n]*")
# a standalone scheme + credential, however short ("Bearer abc", "token x1") -
# every scheme in _AUTH_SCHEMES (one list, reused), applied AFTER _DIGEST_RE
_AUTH_SCHEME_RE = re.compile(r"(?i)\b(%s)\s+(?!\[redacted\])\S+" % _AUTH_SCHEMES)
# structured Digest: "Digest name=..." / "Digest username*=..." -> redacted to end of line
_DIGEST_RE = re.compile(r"(?i)\b(digest)\s+(?!\[redacted\])[A-Za-z_][A-Za-z0-9_\-]*\*?\s*=[^\r\n]*")
_URL_START_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9+.\-]*)://(?:[^@/?#]*@)?([A-Za-z0-9.\-]*)")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*")
_LONG_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{32,}(?![A-Za-z0-9_\-])")
_URL_IN_TEXT_RE = re.compile(r"\b(?:https?|wss?|ftp)://[^\s\"'<>]+", re.I)


def _secretish_segment(seg):
    """A path segment that looks like a key/token rather than a word - judged on
    its percent-DECODED form too, so %XX-encoding can't hide a token."""
    decoded = urllib.parse.unquote(seg)
    if decoded != seg and _secretish_plain(decoded):
        return True
    return _secretish_plain(seg)


def _secretish_plain(seg):
    if len(seg) >= 32 and re.fullmatch(r"[A-Za-z0-9_\-=.~+]+", seg):
        return True
    if len(seg) >= 16 and re.fullmatch(r"[0-9a-fA-F]+", seg):
        return True
    return len(seg) >= 20 and re.search(r"\d", seg) and re.search(r"[A-Za-z]", seg) and \
        re.fullmatch(r"[A-Za-z0-9_\-]+", seg) and not re.search(r"[aeiou]{2}|[_\-]", seg.lower())


def redact_url(value):
    """Keep scheme, host, port and readable path; drop user:password, the query
    string, the fragment, and token-looking path segments."""
    try:
        u = urllib.parse.urlsplit(value)
        host = u.hostname or ""
        port = u.port
    except ValueError:
        return _redact_unparseable_url(value)
    if not u.scheme or not host:
        return _redact_unparseable_url(value)
    netloc = ("[%s]" % host if ":" in host else host) + (":%d" % port if port else "")
    path = "/".join("[redacted]" if _secretish_segment(seg) else seg for seg in u.path.split("/"))
    out = "%s://%s%s" % (u.scheme, netloc, path)
    if u.query:
        out += "?[query removed]"
    if u.fragment:
        out += "#[removed]"
    return out


def _redact_unparseable_url(value):
    """Fail closed: a URL that can't be parsed keeps at most its scheme and a
    plain host name - user info, port, path, query and fragment all go."""
    m = _URL_START_RE.match(value or "")
    if m and m.group(2):
        return "%s://%s/[rest of an unreadable address removed]" % (m.group(1).lower(), m.group(2).lower())
    return "[unreadable address removed]"


def redact_text(text, urls=True):
    """Redact URLs (see redact_url), key=value secrets, JWTs and long tokens in free text."""
    if not isinstance(text, str):
        return text
    if urls:
        def one(m):
            v = m.group(0)
            tail = len(v) - len(v.rstrip(").,;:!]"))
            return redact_url(v[:len(v) - tail]) + v[len(v) - tail:]
        text = _URL_IN_TEXT_RE.sub(one, text)
    text = _JWT_RE.sub("[redacted]", text)
    text = _AUTH_HEADER_RE.sub(lambda m: m.group(1) + m.group(2) + "[redacted]", text)
    text = _SECRET_KV_RE.sub(lambda m: m.group(1) + m.group(2) + "[redacted]", text)
    text = _DIGEST_RE.sub(lambda m: m.group(1) + " [redacted]", text)
    text = _AUTH_SCHEME_RE.sub(lambda m: m.group(1) + " [redacted]", text)   # "Bearer abc" anywhere
    return _LONG_TOKEN_RE.sub("[redacted]", text)


def finding_context(res, kind, item, label=""):
    """ONLY what the AI may see about one finding: the finding's own evidence and
    a few code locations - never the app's code, other findings or file paths.
    Addresses and evidence are redacted (credentials, query strings, fragments,
    token-like values) - the window shows this exact text before sending."""
    locs = []
    for loc in (item.get("locations") or [])[:5]:
        # these come from the APK itself (names inside it) - redacted like any other text
        locs.append({k: redact_text(str(loc.get(k))) for k in ("part", "source", "cls", "method", "owner")
                     if loc.get(k)})
    base = {"package": res.get("package"), "version_code": res.get("version_code"), "app_label": label,
            "analysis_mode": res.get("mode"), "kind": kind, "locations": locs}
    if kind == "endpoint":
        base.update({k: item.get(k) for k in ("host", "port", "scheme", "classification", "confidence",
                                               "owner", "constructed")})
        base["value"] = redact_url(item.get("value", "")) if item.get("kind") == "url" else \
            redact_text(item.get("value", ""))
        base["evidence"] = [redact_text(x) for x in item.get("evidence") or []]
        base["issues"] = [redact_text(x) for x in item.get("issues") or []]
    else:
        base.update({k: item.get(k) for k in ("id", "severity", "confidence")})
        base["title"] = redact_text(item.get("title", ""))
        base["detail"] = redact_text(item.get("detail", ""))
    return base


# ---- the worker (runs in the inspector's own Python, never in the GUI) -----

API_INDICATORS = [
    # id, title, severity, [(class, method) any of], plain explanation
    ("dynamic_code", "Can load extra code while running", "warn",
     [("Ldalvik/system/DexClassLoader;", "<init>"), ("Ldalvik/system/InMemoryDexClassLoader;", "<init>"),
      ("Ldalvik/system/PathClassLoader;", "<init>")],
     "The app can load program code that isn't part of what was installed (e.g. downloaded later). "
     "Legitimate uses exist (plugins, updates), but code loaded this way was NOT analysed here."),
    ("exec", "Can run system commands", "warn",
     [("Ljava/lang/Runtime;", "exec"), ("Ljava/lang/ProcessBuilder;", "start")],
     "The app can start command-line programs on the device. Some apps do this for diagnostics; "
     "malware uses it to do things the normal app interface doesn't allow."),
    ("reflection", "Calls code by name (reflection)", "info",
     [("Ljava/lang/Class;", "forName"), ("Ljava/lang/reflect/Method;", "invoke")],
     "Very common in normal apps and libraries. It also means some calls can't be traced statically."),
    ("js_bridge", "Lets web pages call app code", "info",
     [("Landroid/webkit/WebView;", "addJavascriptInterface")],
     "Web content shown inside the app can call into the app. Safe only if the app shows trusted pages."),
    ("native_load_path", "Loads a native library from a file path", "info",
     [("Ljava/lang/System;", "load")],
     "Most apps load bundled libraries by name; loading from a path can mean a library obtained later."),
]
NETWORK_APIS = [
    ("HTTP (java.net)", [("Ljava/net/URL;", "openConnection"), ("Ljava/net/HttpURLConnection;", "*")]),
    ("raw sockets", [("Ljava/net/Socket;", "<init>"), ("Ljava/net/DatagramSocket;", "<init>"),
                     ("Ljava/nio/channels/SocketChannel;", "open")]),
    ("DNS lookups", [("Ljava/net/InetAddress;", "getByName"), ("Ljava/net/InetAddress;", "getAllByName")]),
    ("TLS / SSL", [("Ljavax/net/ssl/SSLContext;", "init"), ("Ljavax/net/ssl/SSLSocketFactory;", "*")]),
    ("OkHttp", [("Lokhttp3/OkHttpClient;", "*")]),
    ("WebSocket", [("Lokhttp3/OkHttpClient;", "newWebSocket"), ("Lokhttp3/WebSocket;", "*")]),
    ("Apache HTTP", [("Lorg/apache/http/impl/client/DefaultHttpClient;", "*"),
                     ("Lorg/apache/http/client/HttpClient;", "*")]),
    ("WebView pages", [("Landroid/webkit/WebView;", "loadUrl")]),
    ("gRPC", [("Lio/grpc/ManagedChannelBuilder;", "*")]),
]
NATIVE_NET_SYMBOLS = {"socket", "connect", "getaddrinfo", "gethostbyname", "gethostbyname2", "sendto", "send",
                      "recv", "recvfrom", "inet_pton", "inet_addr", "SSL_connect", "SSL_write", "SSL_read",
                      "curl_easy_perform", "curl_easy_setopt"}
TEXT_ASSET_EXT = (".json", ".xml", ".txt", ".js", ".html", ".htm", ".properties", ".cfg", ".conf", ".yaml",
                  ".yml", ".ini", ".csv", ".plist")
MAX_ENDPOINTS, MAX_LOCATIONS = 5000, 20


def _dotted(cls):
    return (cls or "").strip()[1:-1].replace("/", ".") if (cls or "").startswith("L") else (cls or "")


def _api_hit(refs, wanted):
    return [(c, m) for c, m in wanted if (m == "*" and any(rc == c for rc, _ in refs)) or (c, m) in refs]


def _inspect_worker(job_path):
    """Entry point of the worker process. Writes job["result"]; exit code 0 even
    when parts failed (that's reported inside the result), non-zero only if the
    worker itself breaks."""
    import gc
    import shutil
    import xml.etree.ElementTree as ET
    with open(job_path, encoding="utf-8") as f:
        job = json.load(f)
    limits, mode = job["limits"], job["mode"]
    scratch = job["scratch"]
    os.makedirs(scratch, mode=0o700, exist_ok=True)
    try:
        from loguru import logger
        logger.remove()
    except ImportError:
        pass
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    from androguard.core.axml import AXMLPrinter

    def progress(stage, msg, **kw):
        print(INSPECT_PROGRESS + json.dumps(dict(kw, stage=stage, msg=msg)), flush=True)

    signatures = [tuple(x) for x in (job.get("signatures") or [])] or inspector_signatures()
    package = job.get("package") or ""
    res = {"schema": INSPECT_SCHEMA, "package": package, "version_code": job.get("version_code"),
           "mode": mode, "parts": [], "manifest": {}, "endpoints": [], "indicators": [], "sdks": [],
           "network_apis": [], "limitations": []}
    stage_state = {k: {"id": k, "name": n, "status": STAGE_SKIPPED, "detail": []} for k, n in (
        ("container", "checking the APK files"), ("manifest", "reading the manifest"),
        ("code", "reading the code"), ("resources", "reading resources and bundled files"),
        ("native", "reading native libraries"), ("classify", "classifying what was found"))}

    def mark(stage, status, detail=None):
        st = stage_state[stage]
        order = [STAGE_SKIPPED, STAGE_DONE, STAGE_PARTIAL, STAGE_FAILED]
        if st["status"] == STAGE_SKIPPED or order.index(status) > order.index(st["status"]):
            st["status"] = status
        if detail:
            st["detail"].append(detail)

    eps = {}                       # key -> endpoint record
    ind = {}                       # indicator id -> record
    sdk_hits = {}                  # name -> {"source", "classes", "parts"}
    net_apis = {}                  # label -> set(parts)
    all_classes = []

    def add_endpoint(value_rec, loc):
        key = (value_rec["kind"], value_rec["scheme"], value_rec["host"], value_rec["port"], value_rec["value"])
        e = eps.get(key)
        if e is None:
            if len(eps) >= MAX_ENDPOINTS:
                return
            e = eps[key] = dict(value_rec, locations=[])
        if len(e["locations"]) < MAX_LOCATIONS and loc not in e["locations"]:
            e["locations"].append(loc)

    def add_indicator(iid, title, sev, text, loc=None, conf="medium"):
        r = ind.setdefault(iid, {"id": iid, "title": title, "severity": sev, "detail": text,
                                 "confidence": conf, "locations": []})
        if loc and len(r["locations"]) < MAX_LOCATIONS and loc not in r["locations"]:
            r["locations"].append(loc)

    def loc_for(part, source, file=None, cls=None, method=None):
        d = _dotted(cls) if cls else None
        owner = sdk_owner(d, signatures)[0] if d else None
        own = bool(d and package and (d == package or d.startswith(package + ".")))
        return {"part": part, "source": source, "file": file, "cls": d, "method": method,
                "owner": owner, "own_code": own}

    def scan_text(part, source, file, text, cls=None, method=None, pkgs=()):
        for e in extract_endpoints(text, pkgs):
            add_endpoint(e, loc_for(part, source, file, cls, method))

    for idx, p in enumerate(job["parts"]):
        name, path = p["name"], p["path"]
        prec = {"name": name, "kind": p.get("kind"), "analysed": False, "dex": [], "native": [],
                "problems": []}
        res["parts"].append(prec)
        progress("container", "checking %s" % name, part=name)
        chk = apk_container_check(path, limits)
        prec["problems"] = ["%s: %s" % s for s in chk["problems"]]
        prec["dex"], prec["native"] = chk["dex"], chk["native"]
        if not chk["ok"]:
            mark("container", STAGE_PARTIAL, "%s: %s" % (name, "; ".join(t for s, t in chk["problems"] if s == "fatal")))
            continue
        mark("container", STAGE_DONE)
        try:
            apk = APK(path)
        except Exception as e:      # androguard raises many kinds on malformed input
            mark("manifest", STAGE_PARTIAL, "%s: Androguard couldn't open it (%s)" % (name, type(e).__name__))
            apk = None

        def g(fn, *a, default=None):
            try:
                return fn(*a)
            except Exception:
                return default
        # -- manifest --
        if apk is not None:
            progress("manifest", "reading the manifest of %s" % name, part=name)
            man = {"package": g(apk.get_package, default=""), "version_code": g(apk.get_androidversion_code),
                   "target_sdk": g(apk.get_target_sdk_version), "min_sdk": g(apk.get_min_sdk_version),
                   "permissions": sorted(g(apk.get_permissions, default=[]) or []),
                   "cleartext": g(apk.get_attribute_value, "application", "usesCleartextTraffic"),
                   "nsc": g(apk.get_attribute_value, "application", "networkSecurityConfig"),
                   "debuggable": g(apk.get_attribute_value, "application", "debuggable")}
            if p.get("kind") == "base" or not res["manifest"]:
                res["manifest"] = man
            mark("manifest", STAGE_DONE)
            if str(man["debuggable"]).lower() == "true":
                add_indicator("debuggable", "Built in debug mode", "warn",
                              "Release apps aren't debuggable. A debuggable app on your phone can be "
                              "inspected and changed by anything with USB debugging access.",
                              loc_for(name, "manifest"), "high")
            if str(man["cleartext"]).lower() == "true":
                add_indicator("cleartext_allowed", "Allows unencrypted connections", "info",
                              "The manifest allows plain http:// connections, which can be read or changed "
                              "by anyone on the network path.", loc_for(name, "manifest"), "high")
            try:
                ts = int(man["target_sdk"] or 0)
            except (TypeError, ValueError):
                ts = 0
            if p.get("kind") == "base" and 0 < ts < 28 and not man["nsc"] and man["cleartext"] is None:
                add_indicator("cleartext_default", "Unencrypted connections allowed by default", "info",
                              "The app targets an Android version older than 9 (API %d), where plain "
                              "http:// is allowed unless the app forbids it." % ts, loc_for(name, "manifest"),
                              "high")
        # -- code --
        try:
            zf = zipfile.ZipFile(path)
        except (zipfile.BadZipFile, OSError) as e:
            mark("code", STAGE_PARTIAL, "%s: %s" % (name, e))
            continue
        with zf:
            dex_ok = 0
            pkgs = set()
            refs = set()
            strings_by_dex = {}
            for dn in chk["dex"]:
                progress("code", "reading %s / %s" % (name, dn), part=name)
                try:
                    d = DEX(read_member_capped(zf, dn, limits["max_uncompressed"]))
                except Exception as e:
                    mark("code", STAGE_PARTIAL, "%s/%s couldn't be parsed (%s)" % (name, dn, type(e).__name__))
                    continue
                dex_ok += 1
                strings_by_dex[dn] = [s for s in g(d.get_strings, default=[]) or []]
                for c in g(d.get_classes, default=[]) or []:
                    cn = g(c.get_name, default="")
                    all_classes.append(cn)
                    dc = _dotted(cn)
                    if "." in dc:
                        pkgs.add(dc.rsplit(".", 1)[0])
                    owner, src = sdk_owner(dc, signatures)
                    if owner:
                        h = sdk_hits.setdefault(owner, {"name": owner, "source": src, "classes": 0, "parts": []})
                        h["classes"] += 1
                        if name not in h["parts"]:
                            h["parts"].append(name)
                    for itf in g(c.get_interfaces, default=[]) or []:
                        if itf in ("Ljavax/net/ssl/X509TrustManager;", "Ljavax/net/ssl/HostnameVerifier;"):
                            add_indicator("custom_tls", "Has its own certificate-checking code", "warn",
                                          "Classes here replace Android's normal check of website certificates. "
                                          "Done wrong, it accepts any certificate and connections can be "
                                          "intercepted. This static check can't tell whether it's done right.",
                                          loc_for(name, "dex", dn, cn), "low")
                mids = g(d.get_methods_id_item, default=None)
                for m in (getattr(mids, "method_id_items", None) or []):
                    try:
                        refs.add((m.get_class_name(), m.get_name()))
                    except Exception:
                        pass
            if chk["dex"] and dex_ok == 0:
                mark("code", STAGE_FAILED if len(job["parts"]) == 1 else STAGE_PARTIAL,
                     "%s: none of its code files could be read" % name)
            elif chk["dex"]:
                mark("code", STAGE_DONE)
            prec["analysed"] = dex_ok == len(chk["dex"])
            # where each string is used (full mode) or just which file (quick mode)
            traced = set()
            if mode == "full" and dex_ok:
                progress("code", "tracing which code uses each address in %s" % name, part=name)
                try:
                    from androguard.misc import AnalyzeAPK
                    _, _, dx = AnalyzeAPK(path)
                    for sa_ in dx.get_strings():
                        v = sa_.get_value()
                        found = extract_endpoints(v, pkgs)
                        if not found:
                            continue
                        traced.add(v)
                        xs = list(sa_.get_xref_from())
                        for e in found:
                            if not xs:
                                add_endpoint(e, dict(loc_for(name, "dex", None), method="(not used by any code)"))
                            for cls_a, meth in xs[:MAX_LOCATIONS]:
                                add_endpoint(e, loc_for(name, "dex", None, cls_a.name, g(lambda: meth.name)))
                    for iid, title, sev, wanted, text in API_INDICATORS:
                        for c, mname in _api_hit(refs, wanted):
                            for ma in g(dx.find_methods, re.escape(c), re.escape(mname), default=[]) or []:
                                for xr in list(ma.get_xref_from())[:MAX_LOCATIONS]:
                                    add_indicator(iid, title, sev, text,
                                                  loc_for(name, "dex", None, xr[0].name, g(lambda: xr[1].name)))
                    del dx
                    gc.collect()
                except MemoryError:
                    mark("code", STAGE_PARTIAL, "%s: ran out of memory while tracing - addresses shown without "
                                                "their code location" % name)
                    gc.collect()
                except Exception as e:
                    mark("code", STAGE_PARTIAL, "%s: tracing failed (%s)" % (name, type(e).__name__))
            for dn, strs in strings_by_dex.items():
                for v in strs:
                    if v in traced:
                        continue
                    scan_text(name, "dex", dn, v, pkgs=pkgs)
                    if v in ("su", "/system/xbin/su", "/system/bin/su", "/sbin/su") or "which su" in v:
                        add_indicator("root_checks", "Looks for root (su)", "info",
                                      "The app mentions the su program. Banking and game apps often check for "
                                      "root to refuse running; other apps ask for root to do more.",
                                      loc_for(name, "dex", dn), "low")
            for iid, title, sev, wanted, text in API_INDICATORS:
                if _api_hit(refs, wanted) and iid not in ind:
                    add_indicator(iid, title, sev, text, loc_for(name, "dex", ", ".join(chk["dex"])),
                                  "low" if mode == "quick" else "medium")
            if ("Ljavax/crypto/Cipher;", "getInstance") in refs and ("Landroid/util/Base64;", "decode") in refs:
                add_indicator("crypto_strings", "Decodes and decrypts data while running", "info",
                              "The app both decodes and decrypts data. Usually for normal security, but it's "
                              "also how some apps hide addresses or settings from analysis like this one - "
                              "anything hidden that way wasn't seen here.", loc_for(name, "dex"), "low")
            for label, wanted in NETWORK_APIS:
                if _api_hit(refs, wanted):
                    net_apis.setdefault(label, set()).add(name)
            # -- resources, assets, network security config --
            progress("resources", "reading resources of %s" % name, part=name)
            try:
                if apk is not None:
                    arsc = g(apk.get_android_resources)
                    sp = getattr(arsc, "stringpool_main", None) if arsc else None
                    for i in range(int(getattr(sp, "stringCount", 0) or 0)):
                        scan_text(name, "resource", "resources.arsc", g(sp.getString, i, default="") or "", pkgs=pkgs)
                    for fn in [f for f in (g(apk.get_files, default=[]) or []) if f.startswith("res/xml/")]:
                        raw = read_member_capped(zf, fn, limits["max_asset_file"])
                        try:
                            xml = AXMLPrinter(raw).get_xml()
                            root = ET.fromstring(xml)
                        except Exception:
                            continue
                        if root.tag != "network-security-config":
                            continue
                        for el in root.iter():
                            if el.tag == "domain" and el.text:
                                add_endpoint({"value": el.text.strip(), "kind": "host", "scheme": "",
                                              "host": el.text.strip().lower(), "port": None, "constructed": False},
                                             loc_for(name, "resource", fn))
                            for k, v in el.attrib.items():
                                if k.endswith("cleartextTrafficPermitted") and v == "true":
                                    add_indicator("cleartext_allowed", "Allows unencrypted connections", "info",
                                                  "The network security settings allow plain http:// "
                                                  "connections.", loc_for(name, "resource", fn), "high")
                        for anchors in root.iter("trust-anchors"):
                            parent_debug = any(anchors in list(d_) for d_ in root.iter("debug-overrides"))
                            for cert in anchors.iter("certificates"):
                                src = next((v for k, v in cert.attrib.items() if k.endswith("src")), "")
                                if src == "user" and not parent_debug:
                                    add_indicator("user_ca", "Trusts certificates added by the user", "warn",
                                                  "The app accepts certificates installed by the user. That "
                                                  "lets anyone who can install one (or trick you into it) "
                                                  "read the app's encrypted traffic.",
                                                  loc_for(name, "resource", fn), "high")
                used = 0
                for an in chk["assets"]:
                    if not an.lower().endswith(TEXT_ASSET_EXT):
                        continue
                    info = zf.getinfo(an)
                    if info.file_size > limits["max_asset_file"]:
                        mark("resources", STAGE_PARTIAL, "%s: %s skipped (too large)" % (name, an))
                        continue
                    if used + info.file_size > limits["max_asset_total"]:
                        mark("resources", STAGE_PARTIAL, "%s: some bundled files skipped (size limit)" % name)
                        break
                    used += info.file_size
                    scan_text(name, "asset", an,
                              read_member_capped(zf, an, limits["max_asset_file"]).decode("utf-8", "replace"),
                              pkgs=pkgs)
                mark("resources", STAGE_DONE)
            except Exception as e:
                mark("resources", STAGE_PARTIAL, "%s: %s" % (name, type(e).__name__))
            # -- native libraries --
            if chk["native"]:
                progress("native", "reading native libraries of %s" % name, part=name)
                total = 0
                readelf = shutil.which("readelf")
                if not readelf:
                    mark("native", STAGE_PARTIAL, "readelf isn't installed: imported functions not listed")
                for ln_ in chk["native"]:
                    info = zf.getinfo(ln_)
                    if info.file_size > limits["max_native_lib"] or total + info.file_size > limits["max_native_total"]:
                        mark("native", STAGE_PARTIAL, "%s: %s skipped (size limit)" % (name, ln_))
                        continue
                    total += info.file_size
                    try:
                        blob = read_member_capped(zf, ln_, limits["max_native_lib"])
                    except ValueError as e:
                        mark("native", STAGE_PARTIAL, str(e))
                        continue
                    for m in re.finditer(rb"[\x20-\x7e]{6,2048}", blob):
                        s_ = m.group(0).decode("ascii")
                        if "." in s_ or "://" in s_ or s_.count(":") >= 2:   # ":" pairs: IPv6
                            scan_text(name, "native", ln_, s_, pkgs=pkgs)
                    if readelf:
                        tmp = os.path.join(scratch, "lib%03d.so" % idx)   # never a name from the archive
                        with open(tmp, "wb") as f:
                            f.write(blob)
                        try:
                            out = subprocess.run([readelf, "--dyn-syms", "-W", tmp], stdout=subprocess.PIPE,
                                                 stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                                                 timeout=60).stdout.decode("utf-8", "replace")
                            # columns: Num Value Size Type Bind Vis Ndx Name [(version)]
                            und = set()
                            for ln in out.splitlines():
                                cols = ln.split()
                                if len(cols) >= 8 and cols[6] == "UND":
                                    und.add(cols[7].split("@")[0])
                            net = sorted(und & NATIVE_NET_SYMBOLS)
                            if net:
                                add_indicator("native_network", "Native code does its own networking", "info",
                                              "A native library calls network functions directly (%s). That's "
                                              "normal for games and media apps, but native code is harder to "
                                              "inspect - addresses built there may not be visible here."
                                              % ", ".join(net[:8]), loc_for(name, "native", ln_), "high")
                                mark("native", STAGE_DONE)
                        except subprocess.TimeoutExpired:
                            mark("native", STAGE_PARTIAL, "%s: readelf timed out" % ln_)
                        finally:
                            try:
                                os.remove(tmp)
                            except OSError:
                                pass
                    mark("native", STAGE_DONE)
        if apk is not None:
            del apk
        gc.collect()

    # -- classify --
    progress("classify", "classifying %d addresses" % len(eps))
    present = set(sdk_hits)
    ctx = {"package": package, "signatures": signatures, "sdks_present": present,
           "bad_hosts": set(job.get("bad_hosts") or [])}
    for e in eps.values():
        e.update(classify_endpoint(e, ctx))
        if e.get("constructed"):
            e["evidence"].append("the address contains blanks that are filled in while the app runs (%s)"
                                 % e["value"][:80])
    res["endpoints"] = sorted(eps.values(), key=lambda e: (
        {"malicious": 0, "suspicious": 1, "unknown": 2, "expected": 3}[e["classification"]], e["host"]))
    obf = obfuscation_level(all_classes)
    if obf > 0.3:
        res["limitations"].append("%d%% of the code has shortened names (obfuscation): who owns a piece of "
                                  "code can be missed or wrong" % int(obf * 100))
        add_indicator("obfuscated", "Code names are scrambled (obfuscation)", "info",
                      "Most release apps shorten names to save space; it also makes analysis harder. "
                      "This is a limitation of the analysis, not proof of anything.", conf="medium")
    if mode == "quick":
        res["limitations"].append("quick mode: addresses are listed with the code FILE they're in, not the exact "
                                  "class and method that uses them")
    res["limitations"].append("only what's written inside the app was analysed: addresses the app downloads, "
                              "builds or decrypts while running can't be seen this way")
    res["indicators"] = sorted(ind.values(), key=lambda i: ({"bad": 0, "warn": 1, "info": 2}[i["severity"]],
                                                           i["title"]))
    res["sdks"] = sorted(sdk_hits.values(), key=lambda s: s["name"].lower())
    res["network_apis"] = [{"api": k, "parts": sorted(v)} for k, v in sorted(net_apis.items())]
    res["obfuscation"] = round(obf, 3)
    mark("classify", STAGE_DONE)
    res["stages"] = [dict(s, detail="; ".join(s["detail"])) for s in stage_state.values()]
    atomic_write_json(job["result"], res, private=True)
    return 0



# ==========================================================================
# App names (labels) from APK metadata
# ==========================================================================
#
# Android exposes no shell command that returns an app's display name, so the
# name is read from the app's own base.apk: its binary manifest (AndroidManifest.xml,
# "AXML") says android:label = a literal string or a resource id, and the resource
# table (resources.arsc, "ARSC") holds the string for each language.
#
#   - Zip directory parsing (fixed-size headers only) runs in the GUI process.
#   - Inflating and parsing AXML/ARSC - complex untrusted binary formats - runs in
#     a separate, resource-limited worker process (time / CPU / memory / file-size
#     limits; "security_audit.py --label-worker job.json"), like the inspector.
#     It runs with the user's own permissions: limited, NOT a sandbox.
#   - Locale choice is BEST EFFORT Android resource resolution (language, region,
#     script), not an exact replacement for PackageManager.getApplicationLabel():
#     the result says which kind of match was used.

LABEL_MAX_CD = 8 << 20           # zip central directory
LABEL_MAX_MANIFEST = 2 << 20     # compressed manifest
LABEL_MAX_MANIFEST_OUT = 4 << 20  # inflated manifest
LABEL_MAX_ARSC = 16 << 20        # resources.arsc (stored or compressed)
LABEL_MAX_ARSC_OUT = 24 << 20    # inflated resources.arsc
LABEL_MAX_LEN = 200              # longest label kept
LABEL_MATCHES = ("literal", "exact", "language", "default", "other")
ANDROID_LABEL_ATTR = 0x01010001  # android:label
ANDROID_NS_URI = "http://schemas.android.com/apk/res/android"


class LabelError(ValueError):
    pass


def _u16(b, o):
    if o < 0 or o + 2 > len(b):
        raise LabelError("read past end")
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    if o < 0 or o + 4 > len(b):
        raise LabelError("read past end")
    return struct.unpack_from("<I", b, o)[0]


# ---- zip directory (GUI side: fixed headers, bounded) ----------------------

def zip_find_cd(tail, file_size):
    """From the last bytes of a zip (the tail MUST end at end of file), return
    (cd_offset, cd_size, entry_count). The end record must be complete, its comment
    must end exactly at end of file, and the central directory must sit directly
    before it. Raises LabelError."""
    tail_start = file_size - len(tail)
    i = len(tail) - 22
    while i >= 0:
        if tail[i:i + 4] == b"PK\x05\x06" and i + 22 + _u16(tail, i + 20) == len(tail):
            break
        i -= 1
    else:
        raise LabelError("no valid zip end record")
    if _u16(tail, i + 4) or _u16(tail, i + 6) or _u16(tail, i + 8) != _u16(tail, i + 10):
        raise LabelError("multi-disk zip not supported")
    count, cd_size, cd_off = _u16(tail, i + 10), _u32(tail, i + 12), _u32(tail, i + 16)
    if 0xFFFF in (count,) or cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
        raise LabelError("zip64 not supported")
    if cd_size > LABEL_MAX_CD or cd_off + cd_size != tail_start + i:
        raise LabelError("central directory out of range")
    return cd_off, cd_size, count


def zip_find_entries(cd, cd_off, count, wanted=("AndroidManifest.xml", "resources.arsc")):
    """Central directory -> {name: (method, comp_size, size, local_header_offset)}.
    Exactly `count` entries must fill the directory completely; a wanted name may
    appear only once; entries must start before the directory."""
    out, o = {}, 0
    for _ in range(count):
        if o + 46 > len(cd) or cd[o:o + 4] != b"PK\x01\x02":
            raise LabelError("bad central directory entry")
        flags, method = _u16(cd, o + 8), _u16(cd, o + 10)
        csize, usize = _u32(cd, o + 20), _u32(cd, o + 24)
        nlen, xlen, clen = _u16(cd, o + 28), _u16(cd, o + 30), _u16(cd, o + 32)
        lho = _u32(cd, o + 42)
        end = o + 46 + nlen + xlen + clen
        if end > len(cd):
            raise LabelError("entry past end of directory")
        name = cd[o + 46:o + 46 + nlen].decode("utf-8", "replace")
        if name in wanted:
            if 0xFFFFFFFF in (csize, usize, lho):
                raise LabelError("zip64 entry %s not supported" % name)
            if name in out:
                raise LabelError("duplicate %s entry" % name)
            if method not in (0, 8) or flags & 0x1 or lho + 30 + csize > cd_off:
                raise LabelError("unusable entry %s" % name)
            out[name] = (method, csize, usize, lho)
        o = end
    if o != len(cd):
        raise LabelError("central directory not fully consumed")
    return out


def zip_data_offset(local_header, lho, name, csize, cd_off):
    """Local file header -> absolute data offset; the header must match the name
    and the whole data range must end before the central directory."""
    if local_header[:4] != b"PK\x03\x04":
        raise LabelError("bad local header")
    nlen, xlen = _u16(local_header, 26), _u16(local_header, 28)
    if len(local_header) < 30 + nlen or local_header[30:30 + nlen].decode("utf-8", "replace") != name:
        raise LabelError("local header doesn't match")
    start = lho + 30 + nlen + xlen
    if start + csize > cd_off:
        raise LabelError("entry data out of range")
    return start


# ---- AXML / ARSC (worker side only) ----------------------------------------

def _string_pool(b, o, limit, max_strings=500000):
    """Parse a ResStringPool chunk at o that must end by `limit`.
    Returns (get(i) -> str, chunk_size)."""
    ctype, hsize, size = _u16(b, o), _u16(b, o + 2), _u32(b, o + 4)
    if ctype != 0x0001 or hsize < 28 or size < hsize or o + size > limit:
        raise LabelError("bad string pool")
    count, flags, sstart = _u32(b, o + 8), _u32(b, o + 16), _u32(b, o + 20)
    if count > max_strings or hsize + 4 * count > size or (count and not hsize + 4 * count <= sstart < size):
        raise LabelError("string pool too large")
    utf8 = bool(flags & 0x100)
    end = o + size

    def get(i):
        if not 0 <= i < count:
            raise LabelError("string index out of range")
        p = o + sstart + _u32(b, o + hsize + 4 * i)
        if not o + sstart <= p < end:
            raise LabelError("string offset out of range")
        if utf8:
            n = b[p]
            p += 2 if n & 0x80 else 1                    # skip UTF-16 length
            if p >= end:
                raise LabelError("string past end")
            n = b[p]
            if n & 0x80:
                if p + 1 >= end:
                    raise LabelError("string past end")
                n = ((n & 0x7F) << 8) | b[p + 1]
                p += 2
            else:
                p += 1
            n = min(n, 4 * LABEL_MAX_LEN)
            if p + n > end:
                raise LabelError("string past end")
            return b[p:p + n].decode("utf-8", "replace")
        n = _u16(b, p)
        p += 2
        if n & 0x8000:
            n = ((n & 0x7FFF) << 16) | _u16(b, p)
            p += 2
        n = min(n, 2 * LABEL_MAX_LEN)
        if p + 2 * n > end:
            raise LabelError("string past end")
        return b[p:p + 2 * n].decode("utf-16-le", "replace")
    return get, size


def axml_app_label(b, max_chunks=200000):
    """Binary manifest -> ("literal", text) or ("ref", resource_id) or (None, None)."""
    if len(b) < 8 or _u16(b, 0) != 0x0003:
        raise LabelError("not a binary manifest")
    total = _u32(b, 4)
    if total > len(b) or total < 8 or _u16(b, 2) != 8:
        raise LabelError("manifest size doesn't match the data")
    o, n, strings, resmap = 8, 0, None, []
    result, seen_app = (None, None), False       # decided only after the WHOLE file checks out
    while o + 8 <= total and n < max_chunks:
        ctype, hsize, size = _u16(b, o), _u16(b, o + 2), _u32(b, o + 4)
        if size < 8 or hsize > size or o + size > total:
            raise LabelError("bad manifest chunk")
        n += 1
        cend = o + size
        if ctype == 0x0001 and strings is None:
            strings, _ = _string_pool(b, o, cend)
        elif ctype == 0x0180:
            if hsize < 8 or (size - hsize) % 4 or (size - hsize) // 4 > 100000:
                raise LabelError("bad resource map")
            resmap = [_u32(b, o + hsize + 4 * k) for k in range((size - hsize) // 4)]
        elif ctype == 0x0102 and strings is not None:
            ext = o + hsize
            if hsize < 16 or ext + 20 > cend:
                raise LabelError("bad element header")
            name = _u32(b, ext + 4)
            if not seen_app and name < 0x7FFFFFFF and strings(name) == "application":
                seen_app = True
                astart, asize, acount = _u16(b, ext + 8), _u16(b, ext + 10), _u16(b, ext + 12)
                if asize < 20 or acount > 4096 or ext + astart + acount * asize > cend or astart < 20:
                    raise LabelError("bad attributes")
                for k in range(acount):
                    a = ext + astart + k * asize
                    ns, an, raw = _u32(b, a), _u32(b, a + 4), _u32(b, a + 8)
                    dtype, data = b[a + 15], _u32(b, a + 16)
                    is_label = (an < len(resmap) and resmap[an] == ANDROID_LABEL_ATTR)
                    if not is_label and an != 0xFFFFFFFF and ns != 0xFFFFFFFF and not (an < len(resmap) and resmap[an]):
                        try:                         # by name only for android:label (not tools:/app:label)
                            is_label = strings(an) == "label" and strings(ns) == ANDROID_NS_URI
                        except LabelError:
                            is_label = False
                    if not is_label:
                        continue
                    if dtype == 0x01 and data:                  # @string/... reference
                        result = ("ref", data)
                    elif dtype == 0x03:
                        result = ("literal", strings(data))
                    elif raw != 0xFFFFFFFF:
                        result = ("literal", strings(raw))
                    break
        o += size
    if o != total:
        raise LabelError("manifest chunks don't add up")
    return result


def _lang(b2):
    if not b2 or b2 == b"\x00\x00":
        return ""
    if b2[0] & 0x80:                                         # packed 3-letter code
        a, c = b2[0], b2[1]
        return "".join(chr(ord("a") + x) for x in (c & 0x1F, ((c & 0xE0) >> 5) | ((a & 0x03) << 3),
                                                       (a & 0x7C) >> 2))
    return b2.decode("ascii", "replace").lower()


def arsc_strings_for(b, resid, max_chunks=200000):
    """resources.arsc + resource id -> [(lang, region, script, qualified, text)]."""
    if len(b) < 12 or _u16(b, 0) != 0x0002:
        raise LabelError("not a resource table")
    total = _u32(b, 4)
    if total > len(b) or _u16(b, 2) != 12 or total < 12:
        raise LabelError("resource table size doesn't match the data")
    pkg_id, type_id, entry_id = resid >> 24, (resid >> 16) & 0xFF, resid & 0xFFFF
    o, n, gstrings, found = 12, 0, None, []
    while o + 8 <= total and n < max_chunks:
        ctype, hsize, size = _u16(b, o), _u16(b, o + 2), _u32(b, o + 4)
        if size < 8 or hsize > size or o + size > total:
            raise LabelError("bad table chunk")
        n += 1
        if ctype == 0x0001 and gstrings is None:
            gstrings, _ = _string_pool(b, o, o + size)
        elif ctype == 0x0200 and gstrings is not None and hsize >= 12 and _u32(b, o + 8) == pkg_id:
            p, pend = o + hsize, o + size
            while p + 8 <= pend and n < max_chunks:
                t, th, ts = _u16(b, p), _u16(b, p + 2), _u32(b, p + 4)
                if ts < 8 or th > ts or p + ts > pend:
                    raise LabelError("bad package chunk")
                n += 1
                if t == 0x0201 and th >= 24 and b[p + 8] == type_id:
                    flags, count, estart = b[p + 9], _u32(b, p + 12), _u32(b, p + 16)
                    cfg = p + 20
                    csz = _u32(b, cfg)
                    if flags & 0x01 and flags & 0x02:
                        raise LabelError("sparse and 16-bit offsets can't be combined")
                    # sparse arrays hold (16-bit index, 16-bit offset/4) pairs = 4 bytes
                    # each; otherwise 2 bytes (16-bit offsets) or 4 bytes per entry
                    owidth = 4 if flags & 0x01 else (2 if flags & 0x02 else 4)
                    if csz < 4 or cfg + csz > p + th or count > 65536 or \
                            not th + owidth * count <= estart <= ts:
                        raise LabelError("bad type chunk")
                    lang = _lang(b[cfg + 8:cfg + 10]) if csz >= 12 else ""
                    region = b[cfg + 10:cfg + 12].replace(b"\x00", b"").decode("ascii", "replace") \
                        if csz >= 12 and not (b[cfg + 10] & 0x80) else ""
                    script = b[cfg + 36:cfg + 40].replace(b"\x00", b"").decode("ascii", "replace") \
                        if csz >= 40 else ""
                    qualified = any(b[cfg + 4:cfg + 8]) or (csz >= 36 and any(b[cfg + 12:cfg + 36]))
                    offs, off = p + th, None
                    if flags & 0x01:                             # sparse: (index, offset/4) pairs
                        for k in range(count):
                            if _u16(b, offs + 4 * k) == entry_id:
                                off = _u16(b, offs + 4 * k + 2) * 4
                                break
                    elif entry_id < count:
                        if flags & 0x02:                         # 16-bit offsets (Android 13+)
                            v = _u16(b, offs + 2 * entry_id)
                            off = None if v == 0xFFFF else v * 4
                        else:
                            v = _u32(b, offs + 4 * entry_id)
                            off = None if v == 0xFFFFFFFF else v
                    if off is not None:
                        e = p + estart + off
                        if e + 8 > p + ts:            # whole minimum header inside the chunk,
                            raise LabelError("entry out of range")   # checked before any read
                        eflags = _u16(b, e + 2)
                        if eflags & 0x0008:                      # compact entry (Android 14+)
                            dtype, data = eflags >> 8, _u32(b, e + 4)
                        elif eflags & 0x0001:                    # complex (bag) - not a string
                            dtype, data = None, None
                        else:
                            esz = _u16(b, e)
                            vo = e + esz
                            if esz < 8 or vo + 8 > p + ts:
                                raise LabelError("value out of range")
                            dtype, data = b[vo + 3], _u32(b, vo + 4)
                        if dtype == 0x03:
                            found.append((lang, region, script, qualified, gstrings(data)))
                        elif dtype == 0x01 and data and data != resid:
                            found.append((lang, region, script, qualified, ("ref", data)))
                p += ts
            if p != pend:
                raise LabelError("package chunks don't add up")
        o += size
    if o != total:
        raise LabelError("resource table chunks don't add up")
    return found


def pick_locale_string(cands, locale):
    """Best-effort Android-like choice. locale = {"lang", "region", "script"}.
    Returns (text, match) with match in LABEL_MATCHES."""
    lang, region, script = (locale.get(k, "").lower() for k in ("lang", "region", "script"))
    # Android's pseudo-locales (en-XA accented, ar-XB right-to-left) exist for testing
    # translations and are never chosen for a real device language
    cands = [c for c in cands if isinstance(c[4], str) and c[1].upper() not in ("XA", "XB")]
    if not cands:
        return None, None

    def best(pred):
        hits = [c for c in cands if pred(c)]
        hits.sort(key=lambda c: c[3])                   # unqualified configs first
        return hits[0][4] if hits else None
    if lang:
        for pred, m in ((lambda c: c[0] == lang and c[1].lower() == region and c[2].lower() == script, "exact"),
                        (lambda c: c[0] == lang and c[1].lower() == region and region, "exact"),
                        (lambda c: c[0] == lang and not c[1], "language"),
                        (lambda c: c[0] == lang, "language")):
            t = best(pred)
            if t:
                return t, m
    t = best(lambda c: not c[0])
    if t:
        return t, "default"
    return cands[0][4], "other"


def label_from_parts(manifest, arsc, locale):
    """Worker-side: decoded manifest (+ optional resources.arsc) -> label dict."""
    kind, val = axml_app_label(manifest)
    if kind is None:
        return {"label": None, "match": None, "error": "the manifest has no app label"}
    if kind == "literal":
        return {"label": val, "match": "literal", "error": ""}
    if arsc is None:
        return {"label": None, "match": None, "error": "the label is a resource but the resource table wasn't read"}
    resid = val
    for _ in range(4):                                  # follow @string -> @string chains
        cands = arsc_strings_for(arsc, resid)
        text, match = pick_locale_string(cands, locale)
        if text:
            return {"label": text, "match": match, "error": ""}
        refs = [c[4][1] for c in cands if isinstance(c[4], tuple)]
        if not refs:
            break
        resid = refs[0]
    return {"label": None, "match": None, "error": "the label resource wasn't found"}


def clean_label(text):
    """Display-safe: no control characters, trimmed, bounded."""
    if not isinstance(text, str):
        return None
    t = "".join(ch for ch in text if ch.isprintable() or ch == " ").strip()
    return t[:LABEL_MAX_LEN] or None


def _label_worker(job_path):
    import zlib
    with open(job_path, encoding="utf-8") as f:
        job = json.load(f)
    out = {}

    def load(spec, cap_in, cap_out):
        """Read one entry and decode it strictly: input and output caps, the
        declared size must match, and a deflate stream must end exactly at EOF -
        incomplete streams, unconsumed input or trailing data are rejected."""
        if not spec:
            return None
        with open(spec["path"], "rb") as f:
            raw = f.read(cap_in + 1)
        if len(raw) > cap_in:
            raise LabelError("entry too large")
        if spec["method"] == 0:
            if len(raw) > cap_out:
                raise LabelError("expands too much")
            data = raw
        else:
            d = zlib.decompressobj(-15)
            data = d.decompress(raw, cap_out + 1)
            if len(data) > cap_out or d.unconsumed_tail:
                raise LabelError("expands too much")
            if not d.eof or d.unused_data:
                raise LabelError("incomplete or padded deflate stream")
        if "size" in spec and len(data) != spec["size"]:
            raise LabelError("size doesn't match the zip directory")
        return data
    for item in job["items"]:
        try:
            man = load(item["manifest"], LABEL_MAX_MANIFEST, LABEL_MAX_MANIFEST_OUT)
            arsc = load(item.get("arsc"), LABEL_MAX_ARSC, LABEL_MAX_ARSC_OUT)
            out[item["id"]] = label_from_parts(man, arsc, job.get("locale") or {})
        except Exception as e:                          # malformed input is expected; report it
            out[item["id"]] = {"label": None, "match": None, "error": "unreadable: %s" % type(e).__name__}
    atomic_write_json(job["result"], {"schema": 1, "results": out}, private=True)
    return 0


def run_label_worker(items, locale, timeout_s=60, mem_bytes=768 << 20, script=None):
    """Parse a batch in the isolated worker. items: [{"id", "manifest": {"path","method"},
    "arsc": {...}|None}]. Returns {id: {"label","match","error"}}; never raises. Only
    validated results come back: ids from the batch, labels cleaned, known match kinds."""
    import signal
    import shutil
    import sys
    import tempfile
    work = tempfile.mkdtemp(prefix="adbm_label_")
    os.chmod(work, 0o700)
    fail = {it["id"]: {"label": None, "match": None, "error": "the name reader didn't finish"} for it in items}
    proc = None
    try:
        jpath, rpath = os.path.join(work, "job.json"), os.path.join(work, "result.json")
        atomic_write_json(jpath, {"items": items, "locale": locale, "result": rpath}, private=True)
        limits = {"mem_bytes": mem_bytes, "cpu_s": timeout_s, "file_bytes": 4 << 20}
        try:
            proc = subprocess.Popen(limited_cmd(sys.executable, limits, script or os.path.abspath(__file__),
                                                "--label-worker", jpath),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                                    cwd=work, env=_worker_env(), start_new_session=True)
        except OSError:
            return fail
        try:
            proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            proc.wait()
            return fail
        if proc.returncode != 0:
            return fail
        try:
            with open(rpath, encoding="utf-8") as f:
                res = json.load(f)
        except (OSError, ValueError):
            return fail
        got = res.get("results") if isinstance(res, dict) and res.get("schema") == 1 else None
        if not isinstance(got, dict):
            return fail
        out = {}
        for it in items:
            r = got.get(it["id"])
            if not isinstance(r, dict):
                out[it["id"]] = fail[it["id"]]
                continue
            label = clean_label(r.get("label"))
            match = r.get("match") if r.get("match") in LABEL_MATCHES else None
            out[it["id"]] = {"label": label if match else None, "match": match if label else None,
                             "error": str(r.get("error") or "")[:200] if not (label and match) else ""}
        return out
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == "--inspect-worker":
        sys.exit(_inspect_worker(sys.argv[2]))
    if len(sys.argv) == 3 and sys.argv[1] == "--label-worker":
        sys.exit(_label_worker(sys.argv[2]))
    sys.stderr.write("security_audit.py is part of ADB Manager - run adb_manager.py\n")
    sys.exit(2)
