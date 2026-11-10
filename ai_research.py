"""
ai_research.py - ask an AI (Anthropic or OpenAI) to research one Android package
with web search: what the vendor says it does vs. what independent sources say.

Used by adb_manager.py. The AI must answer with one JSON object (see
REPLY_FIELDS); this module parses and cleans it so the app can show it.

Config file: ~/.config/adb_manager/ai_config.json (created by the app's
"AI settings" window, permissions 600). Empty api_key = use the
ANTHROPIC_API_KEY / OPENAI_API_KEY environment variable instead.

Needs the official SDKs:  pip install anthropic openai
(only the one for the provider you actually use).
"""

import json
import os
import re
import threading
import time

CONFIG_DIR = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
                          "adb_manager")
CONFIG_FILE = os.path.join(CONFIG_DIR, "ai_config.json")
ROOT_DB_FILE = os.path.join(CONFIG_DIR, "root_research_db.json")

PROVIDERS = {
    "anthropic": {"label": "Anthropic (Claude)", "env": "ANTHROPIC_API_KEY",
                  "models": ["claude-fable-5-1", "claude-opus-5-5", "claude-sonnet-5-5",
                             "claude-haiku-5-5"]},
    "openai": {"label": "OpenAI", "env": "OPENAI_API_KEY",
               "models": ["gpt-5.5", "gpt-5.5-mini"]},
}

DEFAULT_CONFIG = {
    "provider": "anthropic",
    "second_opinion": "openai",
    "anthropic": {"api_key": "", "model": "claude-fable-5-1", "max_searches": 5},
    "openai": {"api_key": "", "model": "gpt-5.5"},
}

VERDICTS = ("safe", "careful", "keep_on", "unknown")

# Ask the servers for gzip/deflate only. If an old 'brotli' package is installed
# (e.g. Debian's python3-brotli), the SDKs' HTTP library advertises brotli but
# then crashes decoding it ("process() takes no keyword arguments"), which the
# SDK reports as a connection error. Without brotli in the request it never
# comes into play. (peterpt + Claude 2026-11-08)
HTTP_HEADERS = {"Accept-Encoding": "gzip, deflate"}
BACKING = ("research", "users", "unconfirmed")


# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------

def load_config():
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            saved = json.load(f)
        if isinstance(saved, dict):
            for k, v in saved.items():
                if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                    cfg[k].update(v)
                else:
                    cfg[k] = v
    except (OSError, ValueError):
        pass
    return cfg


def save_config(cfg):
    """Save the AI settings (they hold API keys): 0700 folder, 0600 file, unique temp
    file, fsync, atomic rename. Raises OSError on failure; the temp file is removed."""
    import tempfile
    os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)
    payload = json.dumps(cfg, indent=2)
    fd, tmp = tempfile.mkstemp(dir=CONFIG_DIR, prefix="." + os.path.basename(CONFIG_FILE) + ".",
                               suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, CONFIG_FILE)
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


def api_key(cfg, provider):
    key = (cfg.get(provider) or {}).get("api_key", "").strip()
    return key or os.environ.get(PROVIDERS[provider]["env"], "").strip()


def model_of(cfg, provider):
    return (cfg.get(provider) or {}).get("model", "").strip() or DEFAULT_CONFIG[provider]["model"]


# --------------------------------------------------------------------------
# what we send
# --------------------------------------------------------------------------

SYSTEM_PROMPT = """You check Android packages for the owner of the device, who wants to know \
what each package really does before deciding to turn it off.

Rules:
- Use web search. First find what the official vendor says the package does. Then look for \
independent information: security research, privacy analyses, tracker reports, CVEs, and \
reports from people who disabled the package.
- Don't accept the vendor's description just because it is official, and don't repeat rumours \
as facts. Mark every finding with how well it is backed.
- If you can't find reliable information, write "unknown". Never guess.
- Write for a non-technical person: short, plain sentences.
- Reply with ONE JSON object and nothing else: no markdown, no text before or after it."""

REPLY_FIELDS = """{
  "vendor": "who makes this package",
  "vendor_says": "what the vendor says it does, 1-3 sentences",
  "independent_findings": [
    {"finding": "one fact from an independent source",
     "backing": "research | users | unconfirmed",
     "source": "URL"}
  ],
  "data_collection": "what data it collects or sends, and to whom - or \\"unknown\\"",
  "disagreements": "where independent sources contradict or add to the vendor - or \\"none found\\"",
  "when_disabled": "what breaks or what people reported after disabling it - or \\"unknown\\"",
  "verdict": "safe | careful | keep_on | unknown",
  "confidence": "high | medium | low",
  "summary": "one or two plain sentences for the device owner",
  "sources": ["URL", "URL"]
}"""


def build_request(app, props):
    """The user message: the facts about this package on this device + the job."""
    pkg = app["package"]
    device = " ".join(x for x in (props.get("maker", ""), props.get("model", "")) if x) or "unknown"
    if app.get("system"):
        installed = "came pre-installed with the device (system app)"
        if app.get("path"):
            installed += ", located at " + app["path"]
    else:
        installed = "installed by the user"
        if app.get("installer"):
            installed += " from " + app["installer"]
    perms = ", ".join(p.replace("android.permission.", "") for p in app.get("perms", [])[:40])
    return (
        "Package: {pkg}\n"
        "Device: {device}, Android {release}\n"
        "Installed: {installed}\n"
        "Version: {version}\n"
        "Permissions it requests: {perms}\n\n"
        "Your job:\n"
        "1. Find what the official vendor says this package does.\n"
        "2. Find what independent sources say about it, especially data collection and network use.\n"
        "3. List where the independent information contradicts or adds to the vendor's description.\n"
        "4. Find what happens when people disable it.\n"
        "5. Decide whether it is safe to disable on this device.\n\n"
        "Reply with this JSON object only:\n{fields}"
    ).format(pkg=pkg, device=device, release=props.get("release", "?"), installed=installed,
             version=app.get("version") or "unknown", perms=perms or "none listed",
             fields=REPLY_FIELDS)


# --------------------------------------------------------------------------
# calling the providers
# --------------------------------------------------------------------------

class AIError(Exception):
    pass


def _ask_anthropic(cfg, system, prompt, timeout):
    try:
        import anthropic
    except ImportError:
        raise AIError("the 'anthropic' Python package isn't installed (pip install anthropic)")
    key = api_key(cfg, "anthropic")
    if not key:
        raise AIError("no Anthropic API key - add it in AI settings")
    client = anthropic.Anthropic(api_key=key, timeout=timeout, default_headers=HTTP_HEADERS)
    max_searches = int((cfg.get("anthropic") or {}).get("max_searches", 5) or 5)
    tools = [{"type": "web_search_20250305", "name": "web_search", "max_uses": max_searches}]
    messages = [{"role": "user", "content": prompt}]
    usage = {"input_tokens": 0, "output_tokens": 0, "searches": 0}
    texts = []
    try:
        for _ in range(4):  # long searches can come back as 'pause_turn' - continue them
            resp = client.messages.create(model=model_of(cfg, "anthropic"), max_tokens=4000,
                                          system=system, messages=messages, tools=tools)
            u = resp.usage
            usage["input_tokens"] += getattr(u, "input_tokens", 0) or 0
            usage["output_tokens"] += getattr(u, "output_tokens", 0) or 0
            stu = getattr(u, "server_tool_use", None)
            usage["searches"] += (getattr(stu, "web_search_requests", 0) or 0) if stu else 0
            texts = [b.text for b in resp.content if getattr(b, "type", "") == "text"]
            if resp.stop_reason == "pause_turn":
                messages.append({"role": "assistant", "content": resp.content})
                continue
            break
    except anthropic.AuthenticationError:
        raise AIError("Anthropic rejected the API key")
    except anthropic.PermissionDeniedError as e:
        raise AIError("Anthropic refused the request (is web search enabled for your "
                      "organisation in the Claude Console?): %s" % _short(e))
    except anthropic.NotFoundError:
        raise AIError("Anthropic doesn't know the model '%s'" % model_of(cfg, "anthropic"))
    except anthropic.RateLimitError:
        raise AIError("Anthropic rate limit reached - wait a minute and try again")
    except anthropic.APIConnectionError as e:
        raise AIError("can't reach Anthropic: %s" % explain_error(e))
    except anthropic.APIError as e:
        raise AIError("Anthropic error: %s" % explain_error(e))
    return "".join(texts), usage


def _ask_openai(cfg, system, prompt, timeout):
    try:
        import openai
    except ImportError:
        raise AIError("the 'openai' Python package isn't installed (pip install openai)")
    key = api_key(cfg, "openai")
    if not key:
        raise AIError("no OpenAI API key - add it in AI settings")
    client = openai.OpenAI(api_key=key, timeout=timeout, default_headers=HTTP_HEADERS)
    try:
        resp = client.responses.create(model=model_of(cfg, "openai"), instructions=system,
                                       input=prompt, tools=[{"type": "web_search"}])
    except openai.AuthenticationError:
        raise AIError("OpenAI rejected the API key")
    except openai.NotFoundError:
        raise AIError("OpenAI doesn't know the model '%s'" % model_of(cfg, "openai"))
    except openai.RateLimitError:
        raise AIError("OpenAI rate limit or quota reached")
    except openai.APIConnectionError as e:
        raise AIError("can't reach OpenAI: %s" % explain_error(e))
    except openai.APIError as e:
        raise AIError("OpenAI error: %s" % explain_error(e))
    u = getattr(resp, "usage", None)
    usage = {"input_tokens": getattr(u, "input_tokens", 0) or 0 if u else 0,
             "output_tokens": getattr(u, "output_tokens", 0) or 0 if u else 0,
             "searches": sum(1 for it in (getattr(resp, "output", None) or [])
                             if getattr(it, "type", "") == "web_search_call")}
    return getattr(resp, "output_text", "") or "", usage


def _short(e, limit=300):
    s = str(getattr(e, "message", "") or e)
    return s if len(s) <= limit else s[:limit] + "..."


def _chain(e):
    """The exception plus everything that caused it, outermost first."""
    out, seen, cur = [], set(), e
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        out.append(cur)
        cur = cur.__cause__ or cur.__context__
    return out


def explain_error(e):
    """'Type: message' of the real (innermost) cause, plus a plain-words hint.
    The SDKs only say 'Connection error.'; the useful part is underneath."""
    chain = _chain(e)
    parts = []
    for x in chain:
        m = _short(x, 200).strip()
        txt = "%s: %s" % (type(x).__name__, m) if m else type(x).__name__
        if txt not in parts:
            parts.append(txt)
    detail = parts[0] if len(parts) == 1 else parts[0] + "  <- caused by: " + parts[-1]
    low = " ".join(parts).lower()
    hint = ""
    if "output_buffer_limit" in low or "process() takes no keyword" in low:
        hint = ("an old 'brotli' Python package on this PC doesn't fit the AI library "
                "(pip3 install --user --break-system-packages -U brotli)")
    elif "certificate" in low or "ssl" in low or "tls" in low:
        hint = ("the secure (SSL) connection check failed on this PC - usually missing or "
                "outdated CA certificates (apt install --reinstall ca-certificates), a wrong "
                "system clock, or a proxy/antivirus that inspects HTTPS")
    elif ("name or service not known" in low or "getaddrinfo" in low or "name resolution" in low
          or "nodename nor servname" in low):
        hint = "this PC can't look up the server's name (DNS problem)"
    elif "proxy" in low:
        hint = ("a proxy is in the way - check the HTTPS_PROXY / HTTP_PROXY / ALL_PROXY "
                "environment variables")
    elif "timed out" in low or "timeout" in low:
        hint = "the connection timed out (slow network or something blocking it)"
    elif "refused" in low:
        hint = "the connection was refused (firewall or proxy?)"
    elif "unreachable" in low:
        hint = "the network is unreachable from this PC"
    return (hint + "  [" + detail + "]") if hint else detail


# --------------------------------------------------------------------------
# reading the reply
# --------------------------------------------------------------------------

def extract_json(text):
    """Find the JSON object in the AI's reply, tolerating ```json fences or chatter."""
    t = re.sub(r"```(?:json)?", "", text or "").strip()
    start, end = t.find("{"), t.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("no JSON object in the reply")
    return json.loads(t[start:end + 1])


def _s(v):
    if v is None:
        return ""
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False)
    return str(v).strip()


def normalize(data):
    """Make the parsed reply safe to display whatever the AI actually sent."""
    if not isinstance(data, dict):
        raise ValueError("the reply is not a JSON object")
    verdict = _s(data.get("verdict")).lower().replace(" ", "_").replace("-", "_")
    if verdict not in VERDICTS:
        verdict = "keep_on" if verdict in ("keep", "critical") else "unknown"
    conf = _s(data.get("confidence")).lower()
    if conf not in ("high", "medium", "low"):
        conf = "low"
    findings = []
    for f in data.get("independent_findings") or []:
        if isinstance(f, dict):
            b = _s(f.get("backing")).lower()
            findings.append({"finding": _s(f.get("finding")),
                             "backing": b if b in BACKING else "unconfirmed",
                             "source": _s(f.get("source"))})
        elif _s(f):
            findings.append({"finding": _s(f), "backing": "unconfirmed", "source": ""})
    sources = [_s(x) for x in (data.get("sources") or []) if _s(x)]
    if isinstance(data.get("sources"), str):
        sources = [data["sources"]]
    return {
        "vendor": _s(data.get("vendor")),
        "vendor_says": _s(data.get("vendor_says")),
        "independent_findings": [f for f in findings if f["finding"]],
        "data_collection": _s(data.get("data_collection")) or "unknown",
        "disagreements": _s(data.get("disagreements")),
        "when_disabled": _s(data.get("when_disabled")) or "unknown",
        "verdict": verdict,
        "confidence": conf,
        "summary": _s(data.get("summary")),
        "sources": sources,
    }


ROOT_SYSTEM_PROMPT = """You help the owner of an Android phone find out how to unlock its \
bootloader and root it, for THIS exact device model. Rooting a phone you own is legitimate.

Rules:
- Use web search. Base the answer on the device's exact codename and chipset, not just the \
marketing name (several phones share a marketing name).
- Be accurate about risk. If the method is an exploit, needs Windows, can brick the device, or if \
anti-rollback makes old firmware dangerous, say so plainly.
- If you can't find reliable model-specific information, say so - don't invent steps.
- Prefer official or well-known sources (the device maker, Magisk's GitHub, established XDA threads, \
the unlock-tool author's repo). Give the links.
- Write for a capable but non-expert person: short, clear sentences.
- Reply with ONE JSON object and nothing else: no markdown, no text before or after it."""

ROOT_REPLY_FIELDS = """{
  "device": "which phone(s) this codename refers to, and the chipset",
  "can_unlock": "yes | no | difficult | unknown",
  "unlock_method": "how the bootloader is unlocked for this model, in plain steps (short)",
  "needs_windows": true,
  "wait_time": "any waiting period the maker imposes, or \\"none\\"",
  "twrp": "is there a TWRP or OrangeFox recovery for this exact codename? name it, or \\"none found\\"",
  "root_method": "how root is installed once unlocked (e.g. Magisk-patched boot image)",
  "brick_risk": "low | medium | high, and why",
  "anti_rollback": "what the anti-rollback situation means for this model, or \\"not applicable\\"",
  "summary": "two or three plain sentences the owner should read first",
  "sources": ["URL", "URL"],
  "confidence": "high | medium | low"
}"""


def build_root_request(info):
    """info = the dict from security_audit.device_info(): build the question."""
    props = info.get("props", {})
    def g(*keys):
        for k in keys:
            if props.get(k):
                return props[k]
        return "unknown"
    return (
        "Device facts read from the phone itself:\n"
        "Marketing name: {market}\n"
        "Internal codename: {codename}\n"
        "Model number: {model}\n"
        "Maker: {maker}\n"
        "Chipset / platform: {chip}\n"
        "Android version: {rel} (API {sdk})\n"
        "System software: {miui}\n"
        "Build: {build}\n"
        "Bootloader state: {boot}\n"
        "Anti-rollback: {arb}\n\n"
        "Find, for THIS exact codename and chipset:\n"
        "1. Can the bootloader be unlocked, and exactly how (and does it need Windows)?\n"
        "2. Any maker-imposed waiting period.\n"
        "3. Is there a TWRP or OrangeFox recovery for this codename?\n"
        "4. How root is installed after unlocking.\n"
        "5. The brick risk, and what anti-rollback means here.\n\n"
        "Reply with this JSON object only:\n{fields}"
    ).format(market=info.get("marketname") or "unknown", codename=info.get("codename") or "unknown",
             model=g("ro.product.model"), maker=g("ro.product.manufacturer", "ro.product.brand"),
             chip=g("ro.board.platform", "ro.product.board"),
             rel=g("ro.build.version.release"), sdk=g("ro.build.version.sdk"),
             miui=info.get("miui") or "stock Android",
             build=g("ro.mi.os.version.incremental", "ro.build.version.incremental", "ro.build.display.id"),
             boot=info.get("bootloader") or "unknown",
             arb="active (index %s)" % props.get("ro.boot.arb_version", "?") if info.get("arb") else "not detected",
             fields=ROOT_REPLY_FIELDS)


def _s_yesno(v):
    v = _s(v).lower()
    return {"true": "yes", "false": "no", "1": "yes", "0": "no"}.get(v, _s(v))


def normalize_root(data):
    if not isinstance(data, dict):
        raise ValueError("the reply is not a JSON object")
    conf = _s(data.get("confidence")).lower()
    sources = [_s(x) for x in (data.get("sources") or []) if _s(x)]
    if isinstance(data.get("sources"), str):
        sources = [data["sources"]]
    return {
        "device": _s(data.get("device")),
        "can_unlock": _s(data.get("can_unlock")).lower() or "unknown",
        "unlock_method": _s(data.get("unlock_method")),
        "needs_windows": _s_yesno(data.get("needs_windows")),
        "wait_time": _s(data.get("wait_time")),
        "twrp": _s(data.get("twrp")),
        "root_method": _s(data.get("root_method")),
        "brick_risk": _s(data.get("brick_risk")),
        "anti_rollback": _s(data.get("anti_rollback")),
        "summary": _s(data.get("summary")),
        "sources": sources,
        "confidence": conf if conf in ("high", "medium", "low") else "low",
    }


def research_rooting(provider, cfg, info, timeout=240):
    """Ask ONE provider how to root this exact device. Never raises."""
    res = {"provider": provider, "model": model_of(cfg, provider),
           "when": time.strftime("%Y-%m-%d %H:%M"), "error": "", "raw": "", "usage": {}}
    prompt = build_root_request(info)
    try:
        ask = _ask_anthropic if provider == "anthropic" else _ask_openai
        text, usage = ask(cfg, ROOT_SYSTEM_PROMPT, prompt, timeout)
        res["usage"] = usage
        try:
            res["answer"] = normalize_root(extract_json(text))
        except ValueError as e:
            res["error"] = "the AI's reply wasn't valid JSON (%s)" % e
            res["raw"] = (text or "")[:4000]
    except AIError as e:
        res["error"] = str(e)
    except Exception as e:
        res["error"] = explain_error(e)
    return res


# --------------------------------------------------------------------------
# rooting research database: one saved AI answer per device model (codename)
# --------------------------------------------------------------------------

_root_db_lock = threading.Lock()
ROOT_INFO_PROPS = ("ro.product.model", "ro.product.manufacturer", "ro.product.brand", "ro.board.platform",
                   "ro.product.board", "ro.build.version.release", "ro.build.version.sdk",
                   "ro.mi.os.version.incremental", "ro.build.version.incremental", "ro.build.display.id",
                   "ro.boot.arb_version")


def root_info_for_db(info):
    """The part of device_info() needed to ask the AI again later, without the phone."""
    return {"codename": info.get("codename", ""), "marketname": info.get("marketname", ""),
            "miui": info.get("miui", ""), "bootloader": info.get("bootloader", ""),
            "arb": bool(info.get("arb")), "is_xiaomi": bool(info.get("is_xiaomi")),
            "props": {k: v for k, v in (info.get("props") or {}).items() if k in ROOT_INFO_PROPS}}


def info_build(info):
    p = info.get("props") or {}
    return (p.get("ro.mi.os.version.incremental") or p.get("ro.build.version.incremental")
            or p.get("ro.build.display.id") or "")


def root_db_load():
    with _root_db_lock:
        try:
            with open(ROOT_DB_FILE, encoding="utf-8") as f:
                db = json.load(f)
            return db if isinstance(db, dict) else {}
        except (OSError, ValueError):
            return {}


def _root_db_save(db):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    tmp = ROOT_DB_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=1, ensure_ascii=False)
    os.replace(tmp, ROOT_DB_FILE)


def root_db_get(codename):
    return root_db_load().get((codename or "").lower())


def root_db_put(info, res):
    """Store a research result for this model. A failed attempt never replaces a good
    saved answer - it is recorded as last_error instead. Returns the stored entry."""
    key = (info.get("codename") or "").lower()
    if not key:
        return None
    with _root_db_lock:
        try:
            with open(ROOT_DB_FILE, encoding="utf-8") as f:
                db = json.load(f)
            if not isinstance(db, dict):
                db = {}
        except (OSError, ValueError):
            db = {}
        old = db.get(key)
        if res.get("answer"):
            entry = {"info": root_info_for_db(info), "result": res,
                     "updated": time.strftime("%Y-%m-%d %H:%M"), "updated_ts": time.time()}
        elif isinstance(old, dict) and (old.get("result") or {}).get("answer"):
            entry = dict(old)
            entry["last_error"] = res.get("error") or "no answer"
            entry["last_error_when"] = time.strftime("%Y-%m-%d %H:%M")
        else:
            entry = {"info": root_info_for_db(info), "result": res,
                     "updated": time.strftime("%Y-%m-%d %H:%M"), "updated_ts": time.time()}
        db[key] = entry
        _root_db_save(db)
        return entry


def root_db_delete(codenames):
    with _root_db_lock:
        try:
            with open(ROOT_DB_FILE, encoding="utf-8") as f:
                db = json.load(f)
        except (OSError, ValueError):
            return
        for c in codenames:
            db.pop((c or "").lower(), None)
        _root_db_save(db)


def research(provider, cfg, app, props, timeout=240):
    """Ask one provider about one package. Never raises; errors go in 'error'."""
    res = {"provider": provider, "model": model_of(cfg, provider),
           "when": time.strftime("%Y-%m-%d %H:%M"), "error": "", "raw": "", "usage": {}}
    prompt = build_request(app, props)
    try:
        ask = _ask_anthropic if provider == "anthropic" else _ask_openai
        text, usage = ask(cfg, SYSTEM_PROMPT, prompt, timeout)
        res["usage"] = usage
        try:
            res["answer"] = normalize(extract_json(text))
        except ValueError as e:
            res["error"] = "the AI's reply wasn't valid JSON (%s)" % e
            res["raw"] = (text or "")[:4000]
    except AIError as e:
        res["error"] = str(e)
    except Exception as e:  # anything unexpected from an SDK
        res["error"] = explain_error(e)
    return res


def test_connection(provider, cfg, timeout=60):
    """Tiny request without web search, to check key + model. Returns (ok, message)."""
    try:
        if provider == "anthropic":
            import anthropic
            key = api_key(cfg, provider)
            if not key:
                return False, "no API key"
            r = anthropic.Anthropic(api_key=key, timeout=timeout, default_headers=HTTP_HEADERS).messages.create(
                model=model_of(cfg, provider), max_tokens=10,
                messages=[{"role": "user", "content": "Reply with the word OK."}])
            text = "".join(b.text for b in r.content if getattr(b, "type", "") == "text")
        else:
            import openai
            key = api_key(cfg, provider)
            if not key:
                return False, "no API key"
            r = openai.OpenAI(api_key=key, timeout=timeout, default_headers=HTTP_HEADERS).responses.create(
                model=model_of(cfg, provider), input="Reply with the word OK.")
            text = getattr(r, "output_text", "")
        return True, "works (%s replied: %s)" % (model_of(cfg, provider), text.strip()[:40])
    except ImportError as e:
        return False, "Python package missing: %s" % e
    except Exception as e:
        return False, explain_error(e)


def list_models(provider, cfg, timeout=60):
    """Text models this key can use, newest-looking first (same filters as the
    trading project's pt_e5_providers.list_models). Returns (ok, models | error)."""
    key = api_key(cfg, provider)
    if not key:
        return False, "no API key"
    try:
        ids = []
        if provider == "anthropic":
            import anthropic
            cl = anthropic.Anthropic(api_key=key, timeout=timeout, default_headers=HTTP_HEADERS)  # kept alive while paging
            for m in cl.models.list(limit=100):
                mid = str(getattr(m, "id", "") or "")
                if mid.startswith("claude-"):
                    ids.append(mid)
        else:
            import openai
            cl = openai.OpenAI(api_key=key, timeout=timeout, default_headers=HTTP_HEADERS)
            for m in cl.models.list():
                mid = str(getattr(m, "id", "") or "")
                ml = mid.lower()
                if ml.startswith(("gpt-", "o1", "o3", "o4", "chatgpt-")) and not any(
                        x in ml for x in ("audio", "realtime", "transcribe", "tts", "image",
                                          "search", "embedding", "moderation", "instruct")):
                    ids.append(mid)
        if not ids:
            return False, "the key works but no text models were listed"
        return True, sorted(set(ids), reverse=True)
    except ImportError as e:
        return False, "Python package missing: %s" % e
    except Exception as e:
        return False, explain_error(e)
