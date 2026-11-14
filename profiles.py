"""Debloat profiles (v1): save which apps are OFF / removed / background-restricted
on one phone, and compare that with another phone - pure logic, no adb, no GUI.

A profile describes the CURRENT state of a phone (however it got that way), not a
list of commands. Applying it is the GUI's job and always goes through the app's
existing, verified operations, one reviewed action at a time.

Design rules (agreed with the reviewer):
  * The profile is untrusted input: strict schema, unknown keys/actions rejected,
    duplicate packages rejected, malformed evidence treated as unknown.
  * Comparison is per ACTION, not per app: one app can be "already OFF" and
    "background: will change" at the same time.
  * Risk is always computed on the target phone. A profile carries no risk labels.
  * "Removed for user" is only offered when the target package is a preinstalled
    app whose factory copy is still on the phone AND the phone has the restore
    command - never because a name shows up in a package list.
  * Signer evidence: known + different = conflict; unknown on either side = unknown,
    never a match.
"""
import json
import re
import time

FORMAT = "adb-manager-profile"
VERSION = 1
ACTIONS = ("off", "removed", "background")
MAX_BYTES = 1_000_000
MAX_APPS = 5000
RESTORE_MIN_SDK = 24            # 'cmd package install-existing' exists from Android 7

TOP_KEYS = {"format", "version", "created", "source", "apps"}
SOURCE_KEYS = {"maker", "model", "release", "sdk", "user"}
APP_KEYS = {"actions", "evidence"}
EVIDENCE_KEYS = {"version_code", "signers"}

_PKG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_VC_RE = re.compile(r"^[0-9]{1,20}$")
_FACTORY_PREFIX = ("/system/", "/product/", "/vendor/", "/system_ext/", "/odm/", "/oem/", "/apex/")

# per-action comparison results
ALREADY = "already"            # the target phone already has this state
WILL_CHANGE = "will_change"    # can be applied (after review)
MISSING = "missing"            # the app isn't on the target phone
NOT_APPLICABLE = "not_applicable"
UNSUPPORTED = "unsupported"    # this phone / this app can't do it safely
UNKNOWN = "unknown"            # the state couldn't be read - never applied blindly
CONFLICT = "conflict"          # a different app under the same name (signer differs)
STATUS_WORDS = {ALREADY: "already done", WILL_CHANGE: "will change", MISSING: "not on this phone",
                NOT_APPLICABLE: "doesn't apply", UNSUPPORTED: "not possible here", UNKNOWN: "couldn't be read",
                CONFLICT: "different app (signer differs)"}
ACTION_WORDS = {"off": "Turn OFF", "removed": "Remove for user", "background": "Restrict background"}


class ProfileError(ValueError):
    """The file isn't a valid version-1 profile; the message says why."""


# ------------------------------------------------------------------ reading
def _no_duplicates(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise ProfileError("the key %r appears twice" % k)
        seen[k] = v
    return seen


def _keys(obj, allowed, where, required=()):
    if not isinstance(obj, dict):
        raise ProfileError("%s must be an object" % where)
    extra = set(obj) - allowed
    if extra:
        raise ProfileError("unknown key(s) in %s: %s" % (where, ", ".join(sorted(map(str, extra)))))
    missing = [k for k in required if k not in obj]
    if missing:
        raise ProfileError("missing key(s) in %s: %s" % (where, ", ".join(missing)))


def load_profile(data):
    """bytes/str -> a validated profile dict, or ProfileError."""
    if isinstance(data, bytes):
        if len(data) > MAX_BYTES:
            raise ProfileError("the file is too large for a profile (%d bytes)" % len(data))
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError:
            raise ProfileError("the file isn't UTF-8 text")
    if not isinstance(data, str) or len(data.encode("utf-8")) > MAX_BYTES:
        raise ProfileError("the file is too large for a profile")
    try:
        doc = json.loads(data, object_pairs_hook=_no_duplicates)
    except ProfileError:
        raise
    except (ValueError, RecursionError) as e:
        raise ProfileError("the file isn't valid JSON (%s)" % e)
    _keys(doc, TOP_KEYS, "the profile", required=("format", "version", "apps"))
    if doc["format"] != FORMAT:
        raise ProfileError("this isn't an ADB Manager profile")
    if type(doc["version"]) is not int:
        raise ProfileError("the profile version must be a number")
    if doc["version"] != VERSION:
        raise ProfileError("profile version %d isn't supported by this ADB Manager (it reads version %d)"
                           % (doc["version"], VERSION))
    if "created" in doc and not isinstance(doc["created"], str):
        raise ProfileError("'created' must be text")
    src = doc.get("source", {})
    _keys(src, SOURCE_KEYS, "'source'")
    for k in ("maker", "model", "release"):
        if k in src and not isinstance(src[k], str):
            raise ProfileError("source %s must be text" % k)
    for k in ("sdk", "user"):
        if k in src and (type(src[k]) is not int or src[k] < 0):
            raise ProfileError("source %s must be a whole number" % k)
    apps = doc["apps"]
    if not isinstance(apps, dict):
        raise ProfileError("'apps' must be an object")
    if len(apps) > MAX_APPS:
        raise ProfileError("too many apps in the profile (%d)" % len(apps))
    for pkg, entry in apps.items():
        if not _PKG_RE.match(pkg) or len(pkg) > 255:
            raise ProfileError("%r isn't a valid package name" % pkg[:80])
        _keys(entry, APP_KEYS, pkg, required=("actions",))
        acts = entry["actions"]
        if not isinstance(acts, list) or not acts:
            raise ProfileError("%s: 'actions' must be a non-empty list" % pkg)
        if any(not isinstance(a, str) or a not in ACTIONS for a in acts):
            raise ProfileError("%s: unknown action (allowed: %s)" % (pkg, ", ".join(ACTIONS)))
        if len(set(acts)) != len(acts):
            raise ProfileError("%s: an action is listed twice" % pkg)
        if "off" in acts and "removed" in acts:
            raise ProfileError("%s: 'off' and 'removed' contradict each other" % pkg)
        ev = entry.get("evidence", {})
        _keys(ev, EVIDENCE_KEYS, "%s evidence" % pkg)
        if "version_code" in ev and (not isinstance(ev["version_code"], str) or not _VC_RE.match(ev["version_code"])):
            raise ProfileError("%s: version_code must be digits" % pkg)
        if "signers" in ev:
            s = ev["signers"]
            if not isinstance(s, list) or not s or len(s) > 10 or \
                    any(not isinstance(x, str) or not _HEX64_RE.match(x) for x in s):
                raise ProfileError("%s: signers must be a list of SHA-256 fingerprints" % pkg)
    return doc


# ---------------------------------------------------------------- the phone
def restorable(app, sdk):
    """Can 'Remove for user' be undone on this phone for this app? (True, why) /
    (False, why) / (None, why when it can't be told). Requires a preinstalled app
    whose factory copy is still on the phone, and the restore command."""
    if not isinstance(app, dict):
        return False, "the app isn't on this phone"
    if not sdk or sdk < RESTORE_MIN_SDK:
        return False, "this Android version has no command to bring a removed app back"
    system = app.get("system")
    if system is None:
        return None, "it couldn't be told whether it came with the phone"
    if not system:
        return False, "it's an app you installed - removing it would delete it for good"
    path = app.get("path") or ""
    if path.startswith(_FACTORY_PREFIX):
        return True, "it came with the phone and its factory copy is still there"
    if app.get("updated_system"):
        return True, "an updated preinstalled app - its factory copy is still on the phone"
    if not path:
        return None, "its file location couldn't be read"
    return False, "its factory copy couldn't be found on the phone (%s)" % path[:80]


def _digits(sdk):
    try:
        return int(str(sdk).strip())
    except (TypeError, ValueError):
        return 0


def signer_evidence(pkg, app, identities, identity_key):
    """Signer fingerprints for the app AS IT IS NOW, from the deep-scan cache - only
    when the cached record is for this exact version and every part agrees."""
    ident = (identities or {}).get(identity_key(pkg, app))
    if not isinstance(ident, dict) or ident.get("signers") != "same":
        return None
    certs = ident.get("certs")
    if not isinstance(certs, list) or not certs or any(not isinstance(c, str) or not _HEX64_RE.match(c)
                                                      for c in certs):
        return None
    return sorted(set(certs))[:10]


def build_profile(apps, props, user, background, identities=None, identity_key=None, now=None):
    """The current state of a phone -> a profile dict.
    apps: the Apps tab records; background: {pkg: True (restricted) / False / None};
    only states that were actually read are written."""
    sdk = _digits(props.get("sdk"))
    out = {}
    for pkg in sorted(apps):
        a = apps[pkg]
        if not _PKG_RE.match(pkg):
            continue
        acts = []
        if a.get("removed"):
            if restorable(a, sdk)[0] is True:
                acts.append("removed")
        else:
            if a.get("disabled") is True:
                acts.append("off")
            if background.get(pkg) is True:
                acts.append("background")
        if not acts:
            continue
        ev = {}
        vc = str(a.get("version_code") or "")
        if _VC_RE.match(vc):
            ev["version_code"] = vc
        if identity_key and not a.get("removed"):
            s = signer_evidence(pkg, a, identities, identity_key)
            if s:
                ev["signers"] = s
        out[pkg] = {"actions": acts}
        if ev:
            out[pkg]["evidence"] = ev
    src = {"user": int(user)}
    for k, pk in (("maker", "maker"), ("model", "model"), ("release", "release")):
        if props.get(pk):
            src[k] = str(props[pk])[:80]
    if sdk:
        src["sdk"] = sdk
    return {"format": FORMAT, "version": VERSION,
            "created": now or time.strftime("%Y-%m-%d %H:%M"), "source": src, "apps": out}


def dump_profile(doc):
    """The exact text written to disk (validated on the way out, too)."""
    text = json.dumps(doc, indent=1, ensure_ascii=False)    # = security_audit.json_payload()
    load_profile(text)
    return text


# ------------------------------------------------------------- comparison
def _signer_check(evidence, target_signers):
    want = evidence.get("signers")
    if not want or not target_signers:
        return UNKNOWN
    a, b = set(want), set(target_signers)
    if a == b:
        return "match"
    if a & b:
        return UNKNOWN                 # overlapping sets (key rotation?) - not proof either way
    return CONFLICT


def compare(doc, target):
    """Profile vs. the target phone, per action.

    target: {"apps": Apps-tab records, "sdk": int, "user": int, "background": {pkg: bool|None},
             "signers": {pkg: [fingerprints]} (current-version only), "risk_of": fn(pkg) -> risk,
             "critical": the risk value that must never be preselected}
    Returns [{"pkg", "risk", "signer", "version", "actions": {action: {"status", "why",
             "preselect"}}}], sorted by package name."""
    apps, sdk, user = target["apps"], _digits(target.get("sdk")), target.get("user", 0)
    bg = target.get("background") or {}
    rows = []
    for pkg in sorted(doc["apps"]):
        entry = doc["apps"][pkg]
        ev = entry.get("evidence") or {}
        a = apps.get(pkg)
        row = {"pkg": pkg, "risk": target["risk_of"](pkg) if a else None, "signer": UNKNOWN,
               "version": UNKNOWN, "actions": {}}
        if a is not None:
            row["signer"] = _signer_check(ev, (target.get("signers") or {}).get(pkg))
            vc = str(a.get("version_code") or "")
            if ev.get("version_code") and _VC_RE.match(vc):
                row["version"] = "same" if vc == ev["version_code"] else "different"
        for act in entry["actions"]:
            if a is None:
                st, why = MISSING, "this app isn't installed on this phone"
            elif row["signer"] == CONFLICT:
                st, why = CONFLICT, "same name, but signed by someone else - a different app"
            elif act == "off":
                if a.get("removed"):
                    st, why = NOT_APPLICABLE, "it's removed on this phone"
                elif a.get("disabled") is True:
                    st, why = ALREADY, "it's already OFF"
                elif a.get("disabled") is False:
                    st, why = WILL_CHANGE, "it's ON now"
                else:
                    st, why = UNKNOWN, "its on/off state couldn't be read"
            elif act == "removed":
                if a.get("removed"):
                    st, why = ALREADY, "it's already removed for this user"
                elif user != 0:
                    st, why = UNSUPPORTED, "removing is only supported for the phone's main user"
                else:
                    ok, why = restorable(a, sdk)
                    st = WILL_CHANGE if ok is True else UNKNOWN if ok is None else UNSUPPORTED
            else:                                                     # background
                if a.get("removed"):
                    st, why = NOT_APPLICABLE, "it's removed on this phone"
                elif sdk and sdk < 24:
                    st, why = UNSUPPORTED, "background restriction needs Android 7 or newer"
                elif bg.get(pkg) is True:
                    st, why = ALREADY, "background is already restricted"
                elif bg.get(pkg) is False:
                    st, why = WILL_CHANGE, "it may run in the background now"
                else:
                    st, why = UNKNOWN, "its background setting couldn't be read"
            pre = st == WILL_CHANGE and row["risk"] != target.get("critical")
            row["actions"][act] = {"status": st, "why": why, "preselect": pre}
        rows.append(row)
    return rows


def counts(rows):
    """{status: n} over every action of every row."""
    out = {}
    for r in rows:
        for v in r["actions"].values():
            out[v["status"]] = out.get(v["status"], 0) + 1
    return out


# ------------------------------------------------- the phone's own AppOps view
_UID_RE = re.compile(r"^Uid (\S+):$")


def uid_user(uid_text):
    """'u10a123' -> 10, '1010123' -> 10, '1000' -> 0, anything else -> None."""
    m = re.match(r"^u(\d+)(?:[a-z]\d+|_[a-z0-9]+)?$", uid_text)
    if m:
        return int(m.group(1))
    if uid_text.isdigit():
        return int(uid_text) // 100000
    return None


def background_from_appops(text, user, ops_for):
    """'dumpsys appops' -> {pkg: True (restricted) / False} for ONE Android user.
    ops_for(pkg) -> the ops a background restriction uses for that app (the app's
    own adb_manager.background_ops rule), [] if none apply, None if unknown.
    Restricted = every one of those ops is 'ignore'. An app with no entry for an op
    has the default (allowed). Apps whose ops can't be decided are left out."""
    res, cur_user, pkg, modes = {}, None, None, {}

    def flush():
        if pkg is not None and cur_user == user:
            res[pkg] = dict(modes)
    for line in (text or "").splitlines():
        s = line.strip()
        m = _UID_RE.match(s)
        if m:
            flush()
            cur_user, pkg, modes = uid_user(m.group(1)), None, {}
            continue
        m = re.match(r"^Package (\S+):$", s)
        if m:
            flush()
            pkg, modes = m.group(1), {}
            continue
        if pkg is None:
            continue
        m = re.match(r"^(RUN_ANY_IN_BACKGROUND|RUN_IN_BACKGROUND)(?:: mode=| \()(\w+)", s)
        if m:
            modes[m.group(1)] = m.group(2)
    flush()
    out = {}
    for p, ops in res.items():
        need = ops_for(p)
        if need:                                       # None (unknown) and [] (none apply) are left out
            out[p] = all(ops.get(op) == "ignore" for op in need)
    return out
