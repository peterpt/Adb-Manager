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
KEEP_SNAPSHOTS = 30

DEFAULT_SEC_CONFIG = {"virustotal_key": "", "malwarebazaar_key": "", "exodus_token": "",
                      "exodus_url": "https://reports.exodus-privacy.eu.org",
                      "deep_include_updated_system": False}

OK, INFO, WARN, BAD = "ok", "info", "warn", "bad"
LEVEL_RANK = {BAD: 0, WARN: 1, INFO: 2, OK: 3}

SECTIONS = [("device", "Device protection"),
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


def save_json(path, data, private=False):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1, ensure_ascii=False)
        if private:
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
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

def collect(shell, apps, sockets=None):
    """Everything the quick checkup needs from the device, in one place.
    apps = the Apps tab's records (package -> dict). Returns a dict of raw facts."""
    def get(cmd, timeout=30):
        try:
            return shell(cmd, timeout) or ""
        except Exception:
            return ""
    props = {}
    for key, prop in (("release", "ro.build.version.release"), ("sdk", "ro.build.version.sdk"),
                      ("patch", "ro.build.version.security_patch"), ("crypto", "ro.crypto.state"),
                      ("vbstate", "ro.boot.verifiedbootstate"), ("flash_locked", "ro.boot.flash.locked"),
                      ("vbmeta", "ro.boot.vbmeta.device_state"), ("debuggable", "ro.debuggable"),
                      ("adb_tcp", "service.adb.tcp.port"), ("adb_tcp2", "persist.adb.tcp.port"),
                      ("model", "ro.product.model"), ("maker", "ro.product.manufacturer")):
        props[key] = get("getprop " + prop).strip()
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
        settings[key] = _clean(get("settings get %s %s" % (ns, name)))
    selinux = get("getenforce").strip()
    su = get("for p in /system/xbin/su /system/bin/su /sbin/su /su/bin/su /system/sbin/su "
             "/data/local/xbin/su /data/local/bin/su; do [ -e $p ] && echo $p; done").split()
    nets = get("ls /sys/class/net").split()
    admins_raw = get("dumpsys device_policy", 60)
    admins = []
    for m in re.finditer(r"ComponentInfo\{([\w.]+)/", admins_raw):
        if m.group(1) not in admins:
            admins.append(m.group(1))
    appops_raw = get("dumpsys appops", 120)
    return {"props": props, "settings": settings, "selinux": selinux, "su": su,
            "vpn_ifaces": [n for n in nets if n.startswith(("tun", "ppp", "ipsec", "wg"))],
            "admins": admins, "appops": parse_appops(appops_raw), "apps": apps,
            "sockets": sockets or []}


def launcher_packages(shell, pkgs):
    """Which of `pkgs` have an icon in the app drawer. Returns (set, method)."""
    try:
        out = shell("cmd package query-activities --brief -a android.intent.action.MAIN "
                    "-c android.intent.category.LAUNCHER", 60) or ""
    except Exception:
        out = ""
    found = set(m.group(1) for m in re.finditer(r"(?m)^\s*([A-Za-z][\w.]*)/[\w.$]+\s*$", out))
    if found:
        return found & set(pkgs), "query-activities"
    have = set()
    for p in pkgs:
        try:
            dump = shell("dumpsys package " + p, 30) or ""
        except Exception:
            continue
        if "android.intent.category.LAUNCHER" in dump:
            have.add(p)
    return have, "per-package"


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
        "mi_unlock": "blocked",
        "method": "unisoc_cve",
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

UNISOC_PLATFORMS = ("ums", "sc98", "sc77", "sc96", "t606", "t612", "t616", "t610", "t618",
                    "t620", "t700", "t7250", "sp9", "sharkl")


def rooting_guidance(info):
    """A plain-words rooting summary for THIS device. Returns (lines, links).
    lines = [(level, text)]; link = (text, url). Never does anything - advice only."""
    codename = (info.get("codename") or "").lower()
    plat = (info.get("props", {}).get("ro.board.platform", "") + " " +
            info.get("props", {}).get("ro.product.board", "")).lower()
    chip = info.get("props", {}).get("ro.board.platform", "") or info.get("props", {}).get("ro.product.board", "")
    is_unisoc = any(tok in plat for tok in UNISOC_PLATFORMS)
    boot = info.get("bootloader")
    lines, links = [], []
    note = ROOT_NOTES.get(codename)

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

    if note:
        lines.append((INFO, "Known device: %s - %s." % (note["names"], note["soc"])))
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
            lines.append((WARN, "This is a Unisoc (Spreadtrum) chip (%s). Xiaomi's Mi Unlock often "
                               "doesn't support Unisoc phones; unlocking usually needs a PC exploit tool "
                               "(CVE-2022-38694) on Windows, which is higher-risk than a normal unlock."
                          % (chip or "ums9230")))
            links = [("CVE-2022-38694 Unisoc unlock tools (TomKing062)",
                      "https://github.com/TomKing062/CVE-2022-38694_unlock_bootloader/releases"),
                     ("XDA: Unisoc unlock threads", "https://xdaforums.com/tags/unisoc/"),
                     ("Magisk (official)", "https://github.com/topjohnwu/Magisk/releases")]
        elif info.get("is_xiaomi"):
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
    lines.append((INFO, "This app only shows this guidance and can check the bootloader state. It "
                        "never unlocks, flashes or roots - those are done with the PC tools above, "
                        "which on this phone means a Windows machine."))
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
                 "ro.build.version.release", "ro.build.version.sdk", "ro.build.version.incremental",
                 "ro.build.id", "ro.build.display.id", "ro.build.version.security_patch",
                 "ro.build.date", "ro.build.type", "ro.build.tags",
                 "ro.miui.ui.version.name", "ro.mi.os.version.name", "ro.mi.os.version.incremental",
                 "ro.build.version.opporom", "ro.vivo.os.version", "ro.build.version.emui",
                 "ro.boot.flash.locked", "ro.boot.verifiedbootstate", "ro.boot.vbmeta.device_state",
                 "ro.boot.warranty_bit", "ro.warranty_bit", "ro.secureboot.lockstate",
                 "ro.boot.cross_region", "ro.boot.hwc", "ro.boot.hwcountry",
                 "ro.miui.region", "ro.product.locale", "ro.boot.dynamic_partitions",
                 "ro.boot.slot_suffix", "ro.boot.bootloader", "ro.bootloader",
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

    # bootloader locked state, from several possible props
    locked_raw = (props.get("ro.boot.flash.locked") or
                  ("locked" if props.get("ro.boot.verifiedbootstate") == "green" else
                   "unlocked" if props.get("ro.boot.verifiedbootstate") in ("orange", "yellow") else "") or
                  ("unlocked" if props.get("ro.boot.vbmeta.device_state") == "unlocked" else
                   "locked" if props.get("ro.boot.vbmeta.device_state") == "locked" else "") or
                  props.get("ro.secureboot.lockstate", ""))
    bootloader = _yesno(locked_raw, "LOCKED", "UNLOCKED")
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
    rooting.append(("Bootloader", bootloader,
                    "must be UNLOCKED before any root is possible; unlocking wipes the phone"))
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
    slots = "yes (A/B)" if props.get("ro.boot.slot_suffix") or \
            props.get("ro.boot.dynamic_partitions") == "true" else "no / unknown"
    rooting.append(("A/B partitions", slots,
                    "affects how TWRP/Magisk are installed (patched boot image vs recovery)"))

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
    # SELinux
    se = facts["selinux"]
    if se.lower() == "enforcing":
        out.append(finding("device", OK, "SELinux protection is on (enforcing)", key="selinux"))
    elif se.lower() == "permissive":
        out.append(finding("device", BAD, "SELinux protection is OFF (permissive)",
                           "Android's main wall between apps and the system is not enforced. Usually "
                           "caused by rooting or a modified system.", "", "getenforce=Permissive", key="selinux"))
    # root
    magisk = [x for x in ("com.topjohnwu.magisk", "eu.chainfire.supersu", "com.koushikdutta.superuser",
                          "me.weishu.kernelsu") if x in facts["apps"]]
    if facts["su"] or magisk:
        out.append(finding("device", WARN, "The device is rooted",
                           "Apps that get root access can do anything, invisibly - including hiding from "
                           "this checkup. Fine if you rooted it yourself on purpose.",
                           "Only grant root to apps you trust completely.",
                           "su: %s  root apps: %s" % (" ".join(facts["su"]) or "-", " ".join(magisk) or "-"),
                           key="root"))
    else:
        out.append(finding("device", OK, "No signs of root", key="root"))
    # bootloader / verified boot
    vb = p.get("vbstate", "")
    unlocked = p.get("flash_locked") == "0" or p.get("vbmeta") == "unlocked" or vb in ("orange",)
    if unlocked:
        out.append(finding("device", WARN, "The bootloader is unlocked",
                           "The system can be replaced without wiping data, so someone with the device in "
                           "hand could plant a modified system. Normal on custom-ROM devices.",
                           tech="verifiedbootstate=%s flash.locked=%s vbmeta=%s"
                           % (vb or "-", p.get("flash_locked") or "-", p.get("vbmeta") or "-"), key="boot"))
    elif vb == "green" or p.get("flash_locked") == "1":
        out.append(finding("device", OK, "Bootloader locked / verified boot OK", key="boot",
                           tech="verifiedbootstate=%s" % (vb or "-")))
    elif vb == "yellow":
        out.append(finding("device", WARN, "Verified boot uses a custom key (yellow)",
                           "The system was signed by someone other than the maker (custom ROM).", key="boot"))
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
            system = a.get("system", True if not a else False)
            inst_text, inst_kind = installer_text(a.get("installer", ""))
            hidden = (not system) and launcher is not None and p not in launcher
            flags = []
            if not system and inst_kind != "store":
                flags.append(inst_text)
            if hidden:
                flags.append("it has no icon in the app drawer")
            if system:
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
            if system:
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
    if not out:
        out.append(finding("access", OK, "No app holds any of these powerful switches", key="access:none"))
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
    if not out:
        out.append(finding("usage", OK, "No camera, microphone, location or contacts use recorded "
                           "in the last 7 days", key="usage:none"))
    return out


# --------------------------------------------------------------------------
# snapshots: fingerprint the device, compare with the previous check
# --------------------------------------------------------------------------

def build_snapshot(serial, facts, access, launcher, identities):
    apps = {}
    for p, a in facts["apps"].items():
        if a.get("removed"):
            continue
        ident = identities.get(identity_key(p, a)) or {}
        apps[p] = {"v": a.get("version", ""), "vc": a.get("version_code", ""), "sys": bool(a.get("system")),
                   "inst": a.get("installer", ""), "cert": ident.get("cert", ""),
                   "perms": sorted(x for x in a.get("granted", []) if x in SENSITIVE_PERMS),
                   "icon": None if launcher is None or a.get("system") else (p in launcher)}
    p = facts["props"]
    return {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "serial": serial,
            "device": {"patch": p.get("patch", ""), "release": p.get("release", ""),
                       "selinux": facts["selinux"], "root": bool(facts["su"]),
                       "crypto": p.get("crypto", "")},
            "apps": apps, "access": {k: sorted(v) for k, v in access.items()}}


def snap_dir(serial):
    return os.path.join(SNAP_DIR, re.sub(r"[^A-Za-z0-9._-]+", "_", serial))


def last_snapshot(serial):
    d = snap_dir(serial)
    try:
        files = sorted(f for f in os.listdir(d) if f.endswith(".json"))
    except OSError:
        return None
    return load_json(os.path.join(d, files[-1]), {}) if files else None


def save_snapshot(serial, snap):
    d = snap_dir(serial)
    save_json(os.path.join(d, time.strftime("%Y%m%d-%H%M%S") + ".json"), snap)
    try:
        files = sorted(f for f in os.listdir(d) if f.endswith(".json"))
        for f in files[:-KEEP_SNAPSHOTS]:
            os.remove(os.path.join(d, f))
    except OSError:
        pass


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
        before = set(prev.get("access", {}).get(cat, []))
        for p in sorted(set(cur.get("access", {}).get(cat, [])) - before):
            sysapp = ca.get(p, {}).get("sys", False)
            out.append(finding("changes", INFO if sysapp else WARN, "%s was given: %s" % (lbl(p), name),
                               "Not there at %s." % when, how, pkg=p, key="changes:access:%s:%s" % (cat, p)))
    dp, dc = prev.get("device", {}), cur.get("device", {})
    if dc.get("root") and not dp.get("root"):
        out.append(finding("changes", BAD, "The device became rooted since %s" % when, key="changes:root"))
    if dp.get("selinux", "").lower() == "enforcing" and dc.get("selinux", "").lower() == "permissive":
        out.append(finding("changes", BAD, "SELinux was switched to permissive since %s" % when,
                           key="changes:selinux"))
    if dp.get("patch") and dc.get("patch") and dp["patch"] != dc["patch"]:
        out.append(finding("changes", INFO, "Security patch changed: %s \u2192 %s" % (dp["patch"], dc["patch"]),
                           key="changes:patch"))
    if not out:
        out.append(finding("changes", OK, "Nothing changed since %s" % when, key="changes:none"))
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
        if start < 0:
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
        z = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        return []
    blocks = [n for n in z.namelist()
              if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))]
    if not blocks:
        return []
    data = z.read(blocks[0])
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


# --------------------------------------------------------------------------
# outside services (all optional)
# --------------------------------------------------------------------------

UA = "adb_manager-security-check/1.0"


def _http(url, headers=None, data=None, timeout=30):
    req = urllib.request.Request(url, data=data, headers=dict({"User-Agent": UA}, **(headers or {})))
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


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
            db = {str(k): {"name": v.get("name", ""), "website": v.get("website", "")}
                  for k, v in (d.get("trackers") or {}).items()}
            cached["_db"], cached["_db_time"] = db, time.time()
            save_json(TRACKERS_FILE, cached)
        except Exception:
            pass
        return db


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


def reputation_findings(apps, labeler, idents, rep):
    out = []
    for p, ident in idents.items():
        r = rep.get(ident["sha256"], {})
        lbl = label_of(apps, labeler, p)
        vt, mb = r.get("vt"), r.get("mb")
        bad = (vt and vt.get("malicious", 0) >= 3) or (mb and mb.get("known"))
        sus = vt and (vt.get("malicious", 0) > 0 or vt.get("suspicious", 0) > 0)
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
        if not lines:
            lines.append("No lookup service is set up - add a key in Security settings.")
        if bad:
            level, title = BAD, "Flagged as malware: %s" % lbl
        elif sus:
            level, title = WARN, "Some scanners are suspicious of: %s" % lbl
        elif vt and vt.get("known"):
            level, title = OK, "Clean on VirusTotal: %s" % lbl
        else:
            level, title = INFO, "Not known to the databases: %s" % lbl
        advice = ("Uninstall it, change passwords you used on this device, and check the 'Powerful access' "
                  "section." if bad else ("A few detections can be false alarms (often adware or "
                                         "aggressive trackers). Look at the link and decide." if sus else ""))
        tech = "sha256 %s\ncert %s" % (ident["sha256"], ident.get("cert") or "-")
        for x in (vt, mb):
            if x and x.get("link"):
                tech += "\n" + x["link"]
        out.append(finding("malware", level, title, "\n".join(lines), advice, tech, pkg=p, key="malware:%s" % p))
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
