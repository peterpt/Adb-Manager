"""Known Android security issues vs. this device - assessment only.

Compares a device's reported Android version, security patch level (SPL), maker
and chip against Android Security Bulletin data (as published by OSV) and the
CISA Known Exploited Vulnerabilities list. Pure functions: no network, no adb,
no AI. Nothing here runs, downloads or suggests an exploit.

Honesty rules this module is built around:
  * "fixed" only ever means "fixed according to the patch level the phone REPORTS".
  * Missing or ambiguous data gives "unknown", never a clean result.
  * Bulletins stop listing an Android version once it is out of support, so
    "not listed for your version" is only "not affected" when the data shows that
    version was still getting fixes when that bulletin came out.
  * Being on the CISA list means "exploited in real attacks"; it says nothing about
    a public exploit or about root. Those two stay unknown here.
"""
import datetime
import re

# states
POTENTIAL = "potentially_affected"
UNKNOWN = "unknown"
FIXED = "fixed_by_reported_patch"
NOT_AFFECTED = "not_affected"
_RANK = {POTENTIAL: 3, UNKNOWN: 2, FIXED: 1, NOT_AFFECTED: 0}

# Android version labels used by the bulletin data, by API level.
# QPR releases share the API level of their base release.
SDK_LABELS = {
    26: ("8.0", "oc"), 27: ("8.1", "oc-mr1"), 28: ("9", "pi"), 29: ("10", "qt"),
    30: ("11", "rvc", "rvc-qpr"), 31: ("12", "sc"), 32: ("12L", "sc-v2"), 33: ("13", "tm"),
    34: ("14",), 35: ("15",), 36: ("16", "16-qpr2"), 37: ("17", "17-qpr2"),
}
LABEL_SDK = {lab: sdk for sdk, labs in SDK_LABELS.items() for lab in labs}
OLDEST_SDK_IN_DATA = min(SDK_LABELS)
PIXEL_LABELS = ("Pixel-family specific", "Pixel Watch family")
DEVICE_LABELS = ("SoCVersion", "Device specific", "Bootloader", "Platform")

# chip makers whose chips are certainly NOT Qualcomm, by reported SoC maker / platform prefix
_NOT_QCOM_MAKERS = ("mediatek", "unisoc", "spreadtrum", "sprd", "samsung", "google", "hisilicon", "rockchip",
                    "allwinner", "amlogic", "nvidia", "intel")
_NOT_QCOM_PREFIX = ("mt", "ums", "sc98", "sc77", "sc96", "t606", "t612", "t616", "t610", "t618", "t620", "t700",
                    "t7250", "sp98", "sharkl", "exynos", "universal", "gs101", "gs201", "zuma", "kirin", "hi3",
                    "rk3", "tegra")
_QCOM_MAKERS = ("qti", "qualcomm", "qcom")
_QCOM_PREFIX = ("msm", "sdm", "apq", "qcom", "kona", "lahaina", "taro", "kalama", "pineapple", "sun", "lito",
                "bengal", "holi", "trinket", "atoll", "parrot", "crow", "khaje", "monaco", "blair")

_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")
MAX_DETAILS = 600
MAX_ADVISORIES = 3


def parse_spl(text):
    """'YYYY-MM-DD' -> the same string if it is a real date, else None."""
    m = _DATE_RE.match((text or "").strip())
    if not m:
        return None
    try:
        datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None
    return m.group(0)


# ---------------------------------------------------------------- data intake
def _entry_spl(aff):
    es = aff.get("ecosystem_specific") if isinstance(aff.get("ecosystem_specific"), dict) else {}
    spl = parse_spl(es.get("spl") if isinstance(es.get("spl"), str) else "")
    if spl:
        return spl
    ranges = aff.get("ranges")
    for rng in ranges if isinstance(ranges, list) else []:   # fallback: "15:2026-06-01"
        events = rng.get("events") if isinstance(rng, dict) else None
        for ev in events if isinstance(events, list) else []:
            fixed = ev.get("fixed") if isinstance(ev, dict) else None
            if isinstance(fixed, str) and ":" in fixed:
                spl = parse_spl(fixed.rsplit(":", 1)[1])
                if spl:
                    return spl
    return None


def _strs(v, cap=20, size=80):
    return [x[:size] for x in v[:cap] if isinstance(x, str)] if isinstance(v, list) else []


def compact_record(rec):
    """One OSV Android record -> the few fields the check needs (drops the large
    code-signature data). Returns None if the record isn't usable."""
    if not isinstance(rec, dict) or not isinstance(rec.get("id"), str):
        return None
    damaged = []
    aliases = rec.get("aliases")
    if not isinstance(aliases, list) or any(not isinstance(a, str) for a in aliases):
        damaged.append("aliases")
    cves = [a for a in _strs(aliases, 40) if re.match(r"^CVE-\d{4}-\d{4,}$", a)]
    affected = []
    affected_in = rec.get("affected")
    if not isinstance(affected_in, list) or not affected_in:
        damaged.append("affected")
    for aff in affected_in if isinstance(affected_in, list) else []:
        if not isinstance(aff, dict) or not isinstance(aff.get("package"), dict):
            if "affected" not in damaged:
                damaged.append("affected")
            continue
        pkg = aff["package"]
        if pkg.get("ecosystem") != "Android":
            continue
        es = aff.get("ecosystem_specific") if isinstance(aff.get("ecosystem_specific"), dict) else {}
        affected.append({"pkg": str(pkg.get("name", ""))[:120], "labels": _strs(aff.get("versions")),
                         "spl": _entry_spl(aff), "severity": str(es.get("severity", ""))[:20],
                         "types": _strs(es.get("types"), 8, 20)})
    refs = rec.get("references")
    advisories = [r["url"][:300] for r in (refs if isinstance(refs, list) else [])
                  if isinstance(r, dict) and r.get("type") == "ADVISORY" and isinstance(r.get("url"), str)
                  and r["url"].startswith("https://")][:MAX_ADVISORIES]
    return {"id": rec["id"][:80], "cves": cves, "published": str(rec.get("published", ""))[:10],
            "details": str(rec.get("details") or rec.get("summary") or "")[:MAX_DETAILS],
            "affected": affected, "advisories": advisories, "damaged": damaged}


def compact_kev(doc):
    """CISA KEV JSON -> {CVE: {"added": date, "name": short name}}; None if not KEV-shaped."""
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        return None
    out = {}
    for v in doc["vulnerabilities"]:
        if isinstance(v, dict) and isinstance(v.get("cveID"), str) and re.match(r"^CVE-\d{4}-\d{4,}$", v["cveID"]):
            out[v["cveID"]] = {"added": str(v.get("dateAdded", ""))[:10],
                               "name": str(v.get("vulnerabilityName", ""))[:160]}
    return out


# ------------------------------------------------------------- device facts
def chip_family(props):
    """'qualcomm', 'other' (certainly not Qualcomm) or None (can't tell)."""
    maker = str(props.get("ro.soc.manufacturer") or "").strip().lower()
    text = " ".join(str(props.get(k) or "") for k in ("ro.board.platform", "ro.product.board",
                                                         "ro.soc.model")).lower()
    tokens = [t for t in re.split(r"[^a-z0-9]+", text) if t]
    # every recognised signal counts - the maker property doesn't overrule the platform
    qc = bool(maker) and maker.startswith(_QCOM_MAKERS) or any(t.startswith(_QCOM_PREFIX) for t in tokens)
    other = bool(maker) and maker.startswith(_NOT_QCOM_MAKERS) or any(t.startswith(_NOT_QCOM_PREFIX) for t in tokens)
    if qc != other:
        return "qualcomm" if qc else "other"
    return None                                               # nothing recognised, or signals disagree


def pixel_identity(maker, model):
    """True (a Pixel), False (certainly not), None (can't tell): a Google phone whose
    model name is missing can't be ruled out."""
    maker, model = (maker or "").strip().lower(), (model or "").strip().lower()
    if not maker:
        return None
    if maker != "google":
        return False
    if not model:
        return None
    return "pixel" in model


def device_facts(props):
    """The facts the check uses, from the device's getprop map. Anything missing stays None."""
    try:
        sdk = int((props.get("ro.build.version.sdk") or "").strip())
    except ValueError:
        sdk = None
    maker = (props.get("ro.product.manufacturer") or props.get("ro.product.brand") or "").strip()
    model = (props.get("ro.product.model") or "").strip()
    return {"sdk": sdk, "release": (props.get("ro.build.version.release") or "").strip(),
            "spl": parse_spl(props.get("ro.build.version.security_patch")),
            "maker": maker or None,
            "pixel": pixel_identity(maker, model),
            "chip": chip_family(props)}


# ------------------------------------------------------------------ matching
def _kind(entry):
    labels = entry["labels"]
    if any(lab.endswith("-next") for lab in labels) and not any(lab in LABEL_SDK for lab in labels):
        # development branch: only meaningful for the release it became
        return "aosp" if any(lab[:-5] in LABEL_SDK for lab in labels) else "ignore"
    if any(lab in PIXEL_LABELS for lab in labels):
        return "pixel"
    if "Kernel" in labels:
        return "kernel"
    if "SoCVersion" in labels and entry["pkg"].lower().endswith("qualcomm"):
        return "qualcomm"
    if any(lab in LABEL_SDK for lab in labels):
        return "aosp"
    return "vendor"                                           # :unknown:, SoCVersion, device specific, ...


FIXED_WHY = "your patch level %s is at or after the fix (%s)"
COVERED_WHY = ("covered by your patch level %s (fix: %s) if it applies to your phone at all - "
               "whether it does can't be told")


def _by_patch(dev_spl, fix_spl, unfixed_state, why, fixed_why=FIXED_WHY):
    if not dev_spl:
        return UNKNOWN, "your phone's security patch level couldn't be read"
    if not fix_spl:
        return UNKNOWN, "the bulletin data has no fix date for this part"
    if dev_spl >= fix_spl:
        return FIXED, fixed_why % (dev_spl, fix_spl)
    return unfixed_state, why % (dev_spl, fix_spl)


def support_window(records):
    """{API level: date of the newest bulletin that still lists it} - how long the
    data shows each Android version receiving fixes."""
    out = {}
    for r in records:
        for e in r["affected"]:
            for lab in e["labels"]:
                sdk = LABEL_SDK.get(lab)
                if sdk and r.get("published") and r["published"] > out.get(sdk, ""):
                    out[sdk] = r["published"]
    return out


def _aosp_verdict(entries, dev, published, support):
    if dev["sdk"] is None:
        return UNKNOWN, "your Android version couldn't be read", None, None
    if dev["sdk"] < OLDEST_SDK_IN_DATA:
        return UNKNOWN, "the bulletin data doesn't cover Android versions this old", None, None
    mine = set(SDK_LABELS.get(dev["sdk"], ()))
    matched = [e for e in entries if mine & set(e["labels"])]
    if matched:
        spls = [e["spl"] for e in matched]
        fix = None if None in spls else max(spls)
        st, why = _by_patch(dev["spl"], fix, POTENTIAL,
                            "listed for your Android version and your patch level %s is older than the fix (%s)")
        return st, why, fix, True
    nxt = [e for e in entries if {lab[:-5] for lab in e["labels"] if lab.endswith("-next")} & mine]
    if nxt:                       # fixed while your version was still in development
        spls = [e["spl"] for e in nxt]
        fix = None if None in spls else max(spls)
        st, why = _by_patch(dev["spl"], fix, UNKNOWN,
                            "fixed while your Android version was in development; your patch %s is older "
                            "than the fix (%s), so it can't be told if your build has it", COVERED_WHY)
        return st, why, fix, None
    if dev["sdk"] not in SDK_LABELS:
        return UNKNOWN, "your Android version isn't in the bulletin data yet", None, None
    if published and support.get(dev["sdk"], "") >= published:
        return NOT_AFFECTED, ("your Android version was still getting fixes when this bulletin came out, "
                              "and it isn't listed"), None, False
    return UNKNOWN, ("not listed for your Android version, but by then your version may no longer have been "
                     "getting fixes - that isn't the same as not affected"), None, None


def assess_record(rec, dev, kev=None, support=None):
    """One compact record vs. one device -> a finding dict (see module docstring)."""
    damaged = rec.get("damaged") or []
    groups = {}
    for e in rec["affected"]:
        groups.setdefault(_kind(e), []).append(e)
    groups.pop("ignore", None)
    parts = []                                       # (state, reason, fix_spl, confidence, applies)
    if "aosp" in groups:
        st, why, fix, applies = _aosp_verdict(groups["aosp"], dev, rec.get("published"), support or {})
        parts.append((st, why, fix, "medium", applies))
    for kind, label in (("kernel", "Linux kernel"), ("qualcomm", "Qualcomm chip"), ("pixel", "Pixel device")):
        for e in groups.get(kind, ()):
            applies = True if kind == "kernel" else dev["chip"] == "qualcomm" if kind == "qualcomm" else dev["pixel"]
            if kind == "qualcomm" and dev["chip"] is None or kind == "pixel" and dev["pixel"] is None:
                applies = None
                st, why = _by_patch(dev["spl"], e["spl"], UNKNOWN,
                                    "affects some devices; can't tell if yours is one (patch %s, fix %s)",
                                    COVERED_WHY)
            elif not applies:
                st, why = NOT_AFFECTED, "%s issue - doesn't apply to your device" % label
            else:
                st, why = _by_patch(dev["spl"], e["spl"], POTENTIAL,
                                    label + " issue; your patch level %s is older than the fix (%s) - whether "
                                    "your exact build contains the faulty code can't be read")
            parts.append((st, why, e["spl"], "low", applies))
    for e in groups.get("vendor", ()):
        st, why = _by_patch(dev["spl"], e["spl"], UNKNOWN,
                            "chip/vendor part with no maker named in the data; your patch %s is older than "
                            "the fix (%s), but whether it applies to your phone can't be told", COVERED_WHY)
        parts.append((st, why, e["spl"], "low", None))
    if "affected" in damaged:      # part of the record is unreadable: whatever was read can't clear it
        parts.append((UNKNOWN, "part of the bulletin data for this issue was damaged, so it can't be assessed",
                      None, "low", None))
    if not parts:
        parts.append((UNKNOWN, "no usable entries in the bulletin data", None, "low", None))
    state, why, fix, conf, applies = max(parts, key=lambda p: _RANK[p[0]])
    types = sorted({t for e in rec["affected"] for t in e["types"]})
    sev = sorted({e["severity"] for e in rec["affected"] if e["severity"]},
                 key=lambda s: ("Critical", "High", "Moderate", "Low").index(s)
                 if s in ("Critical", "High", "Moderate", "Low") else 9)
    kev_hits = [] if kev is None else [c for c in rec["cves"] if c in kev]
    cves_known = bool(rec["cves"]) and "aliases" not in damaged
    return {"id": rec["id"], "cves": rec["cves"], "state": state, "reason": why, "confidence": conf,
            # True / False / None: whether the issue is known to apply to this device. A FIXED
            # finding with applies=None means "covered by the reported patch IF it applies".
            "applies": applies,
            "fix_spl": fix, "device_spl": dev["spl"], "severity": sev[0] if sev else "",
            "types": types, "details": rec["details"], "advisories": rec["advisories"],
            # three SEPARATE questions - never merged into one verdict
            # a KEV hit is proof; "not on the list" needs a complete, readable CVE list
            "exploited_in_wild": None if kev is None else True if kev_hits else (False if cves_known else None),
            "public_exploit": None,          # no authoritative source; unknown unless researched
            "root_demonstrated": None,       # ditto
            "impact": impact_text(types)}


def impact_text(types):
    if "RCE" in types:
        return "remote code execution (bulletin rating) - not the same as root"
    if "EoP" in types:
        return "privilege escalation (bulletin rating) - not the same as root"
    return ", ".join(types) or "not stated"


def relevant(rec):
    """Issues worth showing: privilege escalation / code execution rated High or Critical."""
    return any(set(e["types"]) & {"EoP", "RCE"} and e["severity"] in ("High", "Critical") for e in rec["affected"])


def assess(records, props, kev=None):
    """All relevant records vs. the device -> {"device", "findings", "counts", "notes"}."""
    dev = device_facts(props)
    support = support_window(records)
    findings = [assess_record(r, dev, kev, support) for r in records if relevant(r) or r.get("damaged")]
    order = {POTENTIAL: 0, UNKNOWN: 1, FIXED: 2, NOT_AFFECTED: 3}
    findings.sort(key=lambda f: (order[f["state"]], not f["exploited_in_wild"], f["fix_spl"] or "9999"))
    counts = {s: 0 for s in order}
    for f in findings:
        counts[f["state"]] += 1
    counts["potential_and_exploited"] = sum(1 for f in findings if f["state"] == POTENTIAL and f["exploited_in_wild"])
    notes = []
    damaged = sum(1 for r in records if r.get("damaged"))
    if damaged:
        notes.append("%d issue(s) in the bulletin data were damaged and are shown as 'unknown'." % damaged)
    if not records:
        notes.append("No bulletin data downloaded yet - nothing can be said about known issues.")
    if dev["spl"] is None:
        notes.append("Your phone's security patch level couldn't be read, so no issue can be called fixed.")
    if dev["sdk"] is not None and dev["sdk"] < OLDEST_SDK_IN_DATA:
        notes.append("The bulletin data starts at Android 8.0; for this phone most answers are 'unknown'.")
    published = sorted(r["published"] for r in records if r.get("published"))
    if published and dev["spl"] and dev["spl"] < published[0]:
        notes.append("Your patch level is older than the oldest bulletin in the data (%s); issues fixed "
                     "before then aren't listed at all." % published[0])
    if kev is None:
        notes.append("The CISA known-exploited list isn't downloaded, so 'exploited in real attacks' is unknown.")
    return {"device": dev, "findings": findings, "counts": counts, "notes": notes}
