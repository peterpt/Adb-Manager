"""Read-only permission inventory: which apps hold which permissions, for ONE
Android user, from 'dumpsys package packages'. Pure functions - no adb, no GUI.

Three different things are kept apart (Android doesn't treat them the same):
  * runtime permissions  - asked at run time (camera, location, ...): allowed /
                           not allowed, plus Android's flags (fixed, restricted, ...)
  * install permissions  - granted when the app is installed (internet, ...)
  * special access       - 'draw over apps', 'all files access', ...: decided by
                           special-access settings (AppOps), NOT by the permission
                           lists. Their entries in those lists can be misleading
                           (seen on a real Redmi: MANAGE_EXTERNAL_STORAGE granted=false),
                           so they're never shown as allowed or denied here.
Roles, accessibility and notification access aren't permissions at all; the
Security tab shows them.
"""
import re

PKG_HDR_RE = re.compile(r"^\s*Package \[([^\]]+)\] \(")
USER_RE = re.compile(r"^User (\d+):")
PERM_RE = re.compile(r"^([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+): granted=(true|false)(?:, flags=\[([^\]]*)\])?")
NAME_RE = re.compile(r"^([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+)$")

# special access: decided by special-access settings, not by these lists
SPECIAL_ACCESS = {
    "android.permission.SYSTEM_ALERT_WINDOW": "Draw over other apps",
    "android.permission.WRITE_SETTINGS": "Change system settings",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "All files access",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Install unknown apps",
    "android.permission.PACKAGE_USAGE_STATS": "Usage access",
    "android.permission.SCHEDULE_EXACT_ALARM": "Alarms & reminders",
    "android.permission.ACCESS_NOTIFICATION_POLICY": "Do Not Disturb access",
    "android.permission.MANAGE_MEDIA": "Media management",
    "android.permission.USE_FULL_SCREEN_INTENT": "Full-screen notifications",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Accessibility (see the Security tab)",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": "Notification access (see the Security tab)",
    "android.permission.BIND_DEVICE_ADMIN": "Device admin (see the Security tab)",
    "android.permission.BIND_VPN_SERVICE": "VPN",
}

# runtime permission -> plain group name
GROUPS = [
    ("Location", ("ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
                  "ACCESS_MEDIA_LOCATION")),
    ("Camera", ("CAMERA",)),
    ("Microphone", ("RECORD_AUDIO",)),
    ("Contacts", ("READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS")),
    ("Calendar", ("READ_CALENDAR", "WRITE_CALENDAR")),
    ("Phone", ("READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE", "ANSWER_PHONE_CALLS", "ADD_VOICEMAIL",
               "USE_SIP", "ACCEPT_HANDOVER", "PROCESS_OUTGOING_CALLS")),
    ("Call log", ("READ_CALL_LOG", "WRITE_CALL_LOG")),
    ("SMS", ("SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH", "RECEIVE_MMS")),
    ("Files & media", ("READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO",
                       "READ_MEDIA_AUDIO", "READ_MEDIA_VISUAL_USER_SELECTED")),
    ("Body sensors", ("BODY_SENSORS", "BODY_SENSORS_BACKGROUND")),
    ("Physical activity", ("ACTIVITY_RECOGNITION",)),
    ("Nearby devices", ("BLUETOOTH_CONNECT", "BLUETOOTH_SCAN", "BLUETOOTH_ADVERTISE", "NEARBY_WIFI_DEVICES",
                        "UWB_RANGING")),
    ("Notifications", ("POST_NOTIFICATIONS",)),
]
_GROUP_OF = {"android.permission." + p: g for g, ps in GROUPS for p in ps}
GROUP_ORDER = [g for g, _ in GROUPS] + ["Other"]

# Android's permission flags -> plain words (unknown flags are shown as they are)
FLAG_WORDS = {
    "SYSTEM_FIXED": "fixed by the system - can't be changed",
    "POLICY_FIXED": "fixed by a device policy (e.g. work/school management) - can't be changed",
    "USER_FIXED": "you chose 'don't ask again'",
    "GRANTED_BY_DEFAULT": "granted by Android's default policy",
    "GRANTED_BY_ROLE": "given because the app holds a role (e.g. default SMS / dialer app)",
    "APPLY_RESTRICTION": "held back by a restriction policy (restricted permission)",
    "RESTRICTION_INSTALLER_EXEMPT": "exempt from the restriction (allowed by the installer)",
    "RESTRICTION_SYSTEM_EXEMPT": "exempt from the restriction (system)",
    "RESTRICTION_UPGRADE_EXEMPT": "exempt from the restriction (kept from an older Android)",
    "ONE_TIME": "allowed 'only this time'",
    "AUTO_REVOKED": "removed automatically because the app wasn't used",
    "REVIEW_REQUIRED": "must be reviewed before the app runs (old app)",
    "REVOKED_COMPAT": "turned off for an old app in compatibility mode",
    "REVOKE_WHEN_REQUESTED": "will be removed if the app asks again",
}
_QUIET = {"USER_SET", "USER_SENSITIVE_WHEN_GRANTED", "USER_SENSITIVE_WHEN_DENIED", "SELECTED_LOCATION_ACCURACY"}


def group_of(perm):
    return _GROUP_OF.get(perm, "Other")


def short(perm):
    return perm.rsplit(".", 1)[-1]


def parse(text, user):
    """'dumpsys package packages' -> {pkg: {"requested": [...], "install": {perm: (granted, flags)},
    "runtime": {perm: (granted, flags)} or None (no block for `user`), "legacy": [...] (old
    'grantedPermissions:' list, Android < 6)}}. Only the first block of each package counts."""
    out, cur, section, in_user = {}, None, None, None
    for line in (text or "").splitlines():
        s = line.strip()
        if s.startswith(("Queries:", "Hidden system packages:", "Dexopt state:")):
            break
        m = PKG_HDR_RE.match(line)
        if m:
            name = m.group(1)
            cur = None if name in out else out.setdefault(
                name, {"requested": [], "install": {}, "runtime": None, "legacy": []})
            section, in_user = None, None
            continue
        if cur is None or not s:
            continue
        mu = USER_RE.match(s)
        if mu:
            in_user, section = int(mu.group(1)), None
            continue
        if s in ("requested permissions:", "install permissions:", "runtime permissions:", "grantedPermissions:"):
            section = s[:-1]
            if section == "runtime permissions" and in_user == user and cur["runtime"] is None:
                cur["runtime"] = {}
            continue
        if s.endswith(":") and not PERM_RE.match(s):
            section = None
            continue
        if section == "requested permissions":
            nm = NAME_RE.match(s.split(":")[0])
            if nm:
                cur["requested"].append(nm.group(1))
            continue
        if section == "grantedPermissions":
            nm = NAME_RE.match(s)
            if nm:
                cur["legacy"].append(nm.group(1))
            continue
        pm = PERM_RE.match(s)
        if pm and section in ("install permissions", "runtime permissions"):
            flags = frozenset(f.strip() for f in (pm.group(3) or "").replace("|", " ").split() if f.strip())
            entry = (pm.group(2) == "true", flags)
            if section == "install permissions" and in_user is None:
                cur["install"][pm.group(1)] = entry
            elif section == "runtime permissions" and in_user == user and cur["runtime"] is not None:
                cur["runtime"][pm.group(1)] = entry
    return out


def explain(granted, flags):
    """(status word, [plain notes], can_change: True/False)."""
    notes = [FLAG_WORDS[f] for f in sorted(flags) if f in FLAG_WORDS]
    notes += ["Android flag: %s" % f for f in sorted(flags) if f not in FLAG_WORDS and f not in _QUIET]
    fixed = bool({"SYSTEM_FIXED", "POLICY_FIXED"} & flags)
    status = "allowed" if granted else ("held back by policy" if "APPLY_RESTRICTION" in flags else "not allowed")
    return status, notes, not fixed


def inventory(parsed, sdk, user_verified):
    """Per app, the three kinds kept apart. Runtime permissions need a confirmed user
    (they're per user); without one they're 'unknown', never 'not allowed'."""
    apps = {}
    for pkg, d in parsed.items():
        special = sorted({p for p in d["requested"] + list(d["install"]) if p in SPECIAL_ACCESS})
        if sdk is not None and sdk < 23:
            runtime, mode = {}, "install_time"          # Android < 6: everything granted at install
        elif not user_verified:
            runtime, mode = {}, "user_unknown"
        elif d["runtime"] is None:
            runtime, mode = {}, "no_user_block"
        else:
            runtime, mode = {p: v for p, v in d["runtime"].items() if p not in SPECIAL_ACCESS}, "ok"
        install = {p: v for p, v in d["install"].items() if p not in SPECIAL_ACCESS}
        apps[pkg] = {"runtime": runtime, "runtime_mode": mode, "install": install, "special": special,
                     "legacy": [p for p in d["legacy"] if p not in SPECIAL_ACCESS],
                     "requested": d["requested"]}
    return apps


def by_group(apps, include_denied=False):
    """{group: [(pkg, perm, granted, flags)]} over runtime permissions."""
    out = {}
    for pkg, a in apps.items():
        for perm, (granted, flags) in a["runtime"].items():
            if granted or include_denied:
                out.setdefault(group_of(perm), []).append((pkg, perm, granted, flags))
    return out
