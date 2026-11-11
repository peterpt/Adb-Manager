"""Tests for ADB Manager - NOT part of the app; only for checking it (and for ChatGPT review).

Keep it in the same folder as adb_manager.py and run:

    xvfb-run -a python3 -m unittest -v app_tests

(Without a display, the GUI tests are skipped and the rest still run.
 Note: plain 'unittest discover' looks for test*.py; to discover this file use
 python3 -m unittest discover -p "app_tests.py" -v)

Safety: before any app module is imported, the config folder is pointed at a
throw-away temp dir, so the tests can never touch the real ~/.config/adb_manager.
If some app modules were already imported by something else, they must all use
the same temporary config folder; the remaining ones are then forced into it
too. Otherwise the tests refuse to run."""

# ---- isolation: MUST run before the app modules are imported --------------
import atexit
import os
import shutil
import sys
import tempfile

# captured BEFORE isolation: where the real inspector venv and the sample cache live
_REAL_HOME = os.path.expanduser("~")
_APP_MODULES = ("adb_manager", "security_audit", "ai_research")
_TMP_ROOT = os.path.realpath(tempfile.gettempdir())


def _inside_tmp(path):
    return os.path.realpath(path).startswith(_TMP_ROOT + os.sep)


def _isolate():
    """Return the temp config root every app module must use, and make sure any
    app module imported from now on resolves to it as well.

    - No app module imported yet: create a fresh temp root (cleaned up at exit).
    - Some already imported: each one's CONFIG_DIR must be <root>/adb_manager with
      the SAME root, inside the system temp folder. Anything else -> refuse.
    In both cases XDG_CONFIG_HOME and HOME are then set to that root BEFORE the
    remaining modules are imported, so the current environment (which may have
    been changed or unset since) is never trusted."""
    loaded = [m for m in _APP_MODULES if m in sys.modules]
    if not loaded:
        root = tempfile.mkdtemp(prefix="adbm-test-")
        atexit.register(shutil.rmtree, root, True)
    else:
        roots = set()
        for m in loaded:
            d = getattr(sys.modules[m], "CONFIG_DIR", None)
            if not d or os.path.basename(d) != "adb_manager":
                raise RuntimeError("app module %s has an unexpected CONFIG_DIR %r - refusing "
                                   "to run" % (m, d))
            roots.add(os.path.realpath(os.path.dirname(d)))
        if len(roots) != 1:
            raise RuntimeError("app modules were imported with different config folders %s - "
                               "refusing to run" % sorted(roots))
        root = roots.pop()
        if not _inside_tmp(root):
            raise RuntimeError("app modules were imported with a real config folder (%s); "
                               "import app_tests first or run it on its own" % root)
    os.environ["XDG_CONFIG_HOME"] = root
    os.environ["HOME"] = root
    return root


TMP_HOME = _isolate()
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ---- normal imports -------------------------------------------------------
import json                   # noqa: E402
import multiprocessing        # noqa: E402
import posixpath              # noqa: E402
import re                     # noqa: E402
import stat                   # noqa: E402
import subprocess             # noqa: E402
import threading              # noqa: E402
import time                   # noqa: E402
import unittest               # noqa: E402
from unittest import mock     # noqa: E402

import tkinter as tk          # noqa: E402
import adb_manager as am      # noqa: E402
import ai_research as ai      # noqa: E402
import security_audit as sa   # noqa: E402

for _m in (am, sa, ai):   # final check: every module really landed in the temp root
    if os.path.realpath(_m.CONFIG_DIR) != os.path.join(os.path.realpath(TMP_HOME), "adb_manager"):
        raise RuntimeError("%s resolved CONFIG_DIR=%s outside the test root %s"
                           % (_m.__name__, _m.CONFIG_DIR, TMP_HOME))

MP = multiprocessing.get_context("fork")   # Linux-first project


def destroy_root(root):
    """Cancel pending Tk timers, then destroy - otherwise they fire into a dead
    interpreter and print 'invalid command name ...' noise."""
    try:
        for after_id in root.tk.splitlist(root.tk.call("after", "info")):
            root.tk.call("after", "cancel", after_id)     # not after_cancel(): destroy() deletes the command
    except tk.TclError:
        pass
    root.destroy()


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


# ---- helpers that run in child processes -----------------------------------

def _mp_put_keys(path, prefix, n):
    st = am.JsonStore(path)
    for i in range(n):
        if not st.put("%s%d" % (prefix, i), "%s-value-%d" % (prefix, i)):
            raise SystemExit(1)


def _mp_nested_adder(path, pkgs):
    st = am.JsonStore(path)
    for p in pkgs:
        if not st.update("DEV", lambda v, p=p: dict(v or {}, **{p: "on"}), {}):
            raise SystemExit(1)


def _mp_stale_then_update(path, pkg, loaded, go, done):
    """Load the store, wait, then update the SAME top-level key - by the time we
    update, our in-memory copy is stale (the other process already saved)."""
    st = am.JsonStore(path)
    loaded.set()
    go.wait(10)
    ok = st.update("DEV", lambda v: dict(v or {}, **{pkg: pkg + "-ts"}), {})
    done.set()
    raise SystemExit(0 if ok else 1)


def _mp_startup_on_damaged(path, role, in_recovery, b_at_lock, out):
    """Open a JsonStore on a damaged file, synchronised on PROVEN lock contention:
      - A enters recovery (holding the startup lock) and signals in_recovery;
      - B starts loading only after that. B's first fcntl.flock(LOCK_EX) is
        instrumented: it first tries LOCK_EX|LOCK_NB, which must fail with
        BlockingIOError because A holds the lock - kernel-level evidence of
        contention. Only then does B signal b_at_lock and take the real blocking
        lock. If the non-blocking attempt succeeds, A was NOT holding the lock:
        B unlocks at once, records the failure, and the test fails;
      - A stays inside recovery until b_at_lock arrives, then finishes.
    No sleeps. A reports whether the signal arrived and B reports whether
    contention was proven; the test asserts both."""
    import fcntl
    got_signal = None
    contended = []          # B: result of the first non-blocking probe
    if role == "A":
        orig = am.JsonStore._move_aside
        waited = []

        def held_move(self):
            in_recovery.set()
            waited.append(b_at_lock.wait(10))   # B is now at its flock(LOCK_EX)
            return orig(self)
        am.JsonStore._move_aside = held_move
    else:
        real_flock = fcntl.flock

        def flock(fd, op):
            if op & fcntl.LOCK_EX and not contended:   # only B's first exclusive lock
                try:
                    real_flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    contended.append(True)    # A holds it: contention proven
                else:
                    real_flock(fd, fcntl.LOCK_UN)
                    contended.append(False)   # A was NOT holding the lock -> test fails
                b_at_lock.set()               # (also on failure, so A doesn't hang)
            return real_flock(fd, op)
        fcntl.flock = flock
        in_recovery.wait(10)
    st = am.JsonStore(path)
    if role == "A":
        got_signal = bool(waited and waited[0])
    else:
        got_signal = bool(contended and contended[0])   # B: contention proven
    ok = st.put("from_" + role, role)
    out.put((role, st.read_only, st.load_problem, ok, got_signal))


# ==========================================================================
# Round 1 - storage hardening (E-11, snapshot private save)
# ==========================================================================

_ISO_CHILD = r"""
import json, os, sys
sys.path.insert(0, sys.argv[1])
scenario = sys.argv[2]
tmp, fake_home = os.environ["TMPDIR"], sys.argv[3]
if scenario == "partial":
    os.environ["XDG_CONFIG_HOME"] = os.path.join(tmp, "iso")
    import security_audit                         # ONE module imported early, isolated
    del os.environ["XDG_CONFIG_HOME"]             # then the environment changes:
    os.environ["HOME"] = fake_home                # unset XDG, HOME -> "real" home
elif scenario == "real":
    os.environ["XDG_CONFIG_HOME"] = os.path.join(fake_home, ".config")
    import security_audit                         # imported with a REAL config dir
elif scenario == "mixed":
    os.environ["XDG_CONFIG_HOME"] = os.path.join(tmp, "one")
    import security_audit
    os.environ["XDG_CONFIG_HOME"] = os.path.join(tmp, "two")
    import ai_research                            # two different temp roots
try:
    import app_tests
except RuntimeError as e:
    print(json.dumps({"refused": str(e)}))
    sys.exit(0)
print(json.dumps({"root": app_tests.TMP_HOME,
                  "dirs": [m.CONFIG_DIR for m in (app_tests.am, app_tests.sa, app_tests.ai)]}))
"""


class IsolationTest(unittest.TestCase):
    def test_app_config_dir_is_temp(self):
        for d in (am.CONFIG_DIR, sa.CONFIG_DIR, ai.CONFIG_DIR):
            self.assertTrue(d.startswith(TMP_HOME), d)

    def _child(self, scenario):
        """Run a fresh Python with its OWN temp folder and a fake 'real' home that
        is OUTSIDE that temp folder, so 'real' really means not-temp here."""
        import subprocess
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        tmp, home = os.path.join(base, "tmp"), os.path.join(base, "home")
        os.makedirs(tmp)
        os.makedirs(home)
        script = os.path.join(base, "child.py")
        write(script, _ISO_CHILD)
        env = dict(os.environ, TMPDIR=tmp, HOME=home)
        env.pop("XDG_CONFIG_HOME", None)
        out = subprocess.run([sys.executable, script, os.path.dirname(os.path.abspath(__file__)),
                              scenario, home], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout.strip().splitlines()[-1]), tmp, home

    def test_partial_import_then_env_changed_still_isolated(self):
        res, tmp, home = self._child("partial")
        self.assertNotIn("refused", res)
        root = os.path.realpath(os.path.join(tmp, "iso"))
        self.assertEqual(os.path.realpath(res["root"]), root)
        for d in res["dirs"]:
            self.assertEqual(os.path.realpath(d), os.path.join(root, "adb_manager"))
            self.assertFalse(os.path.realpath(d).startswith(os.path.realpath(home)))
        self.assertFalse(os.path.exists(os.path.join(home, ".config")))

    def test_module_imported_with_real_config_refused(self):
        res, tmp, home = self._child("real")
        self.assertIn("real config folder", res.get("refused", ""))

    def test_modules_with_different_roots_refused(self):
        res, tmp, home = self._child("mixed")
        self.assertIn("different config folders", res.get("refused", ""))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.dir = os.path.join(self.tmp, "cfg")
        self.path = os.path.join(self.dir, "store.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def corrupt_files(self):
        return sorted(n for n in os.listdir(self.dir) if ".corrupt-" in n)


class AtomicWriteTests(Base):
    def test_private_by_default(self):
        sa.atomic_write_json(self.path, {"a": 1})
        self.assertEqual(mode(self.path), 0o600)
        self.assertEqual(mode(self.dir), 0o700)

    def test_unique_temp_name_and_no_leftovers(self):
        seen = []
        real = tempfile.mkstemp

        def spy(*a, **k):
            r = real(*a, **k)
            seen.append(r[1])
            return r
        with mock.patch("tempfile.mkstemp", side_effect=spy):
            sa.atomic_write_json(self.path, {"a": 1})
            sa.atomic_write_json(self.path, {"a": 2})
        self.assertEqual(len(set(seen)), 2)
        for t in seen:
            self.assertNotEqual(t, self.path + ".tmp")
            self.assertFalse(os.path.exists(t))
        self.assertEqual(os.listdir(self.dir), ["store.json"])

    def test_failed_rename_keeps_old_file_and_raises(self):
        sa.atomic_write_json(self.path, {"good": True})
        with mock.patch("os.replace", side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(OSError):
                sa.atomic_write_json(self.path, {"good": False})
        self.assertEqual(json.loads(read(self.path)), {"good": True})
        self.assertEqual(os.listdir(self.dir), ["store.json"])   # temp cleaned up

    def test_no_chmod_after_rename(self):
        """A chmod failure on the final path must not turn a committed write into a
        reported failure: the mode is set on the temp file before the rename."""
        real = os.chmod

        def chmod(p, m, *a, **k):
            if os.path.abspath(p) == os.path.abspath(self.path):
                raise OSError(1, "Operation not permitted")
            return real(p, m, *a, **k)
        with mock.patch("os.chmod", side_effect=chmod):
            sa.atomic_write_json(self.path, {"new": 1})
        self.assertEqual(json.loads(read(self.path)), {"new": 1})
        self.assertEqual(mode(self.path), 0o600)

    def test_unencodable_raises_oserror_and_writes_nothing(self):
        with self.assertRaises(OSError):
            sa.atomic_write_json(self.path, {"x": object()})
        self.assertFalse(os.path.exists(self.path))

    def test_save_json_returns_false_on_failure(self):
        with mock.patch("os.replace", side_effect=OSError(5, "I/O error")):
            self.assertFalse(sa.save_json(self.path, {"a": 1}))
        self.assertTrue(sa.save_json(self.path, {"a": 1}))


class JsonStoreTests(Base):
    def test_put_get_persist_private(self):
        st = am.JsonStore(self.path)
        self.assertTrue(st.put("k", {"v": 1}))
        self.assertEqual(mode(self.path), 0o600)
        self.assertEqual(mode(self.dir), 0o700)
        self.assertEqual(am.JsonStore(self.path).get("k"), {"v": 1})

    def test_loose_old_file_is_tightened(self):
        os.makedirs(self.dir)
        write(self.path, '{"a": 1}')
        os.chmod(self.path, 0o644)
        st = am.JsonStore(self.path)
        self.assertEqual(mode(self.path), 0o600)
        self.assertEqual(st.get("a"), 1)
        self.assertIsNone(st.load_problem)

    def test_failed_tightening_is_reported(self):
        os.makedirs(self.dir)
        write(self.path, '{"a": 1}')
        real = os.chmod

        def chmod(p, m, *a, **k):
            if os.path.abspath(p) == os.path.abspath(self.path):
                raise OSError(1, "Operation not permitted")
            return real(p, m, *a, **k)
        with mock.patch("os.chmod", side_effect=chmod):
            st = am.JsonStore(self.path)
        self.assertIn("private", st.load_problem)
        self.assertFalse(st.read_only)          # still usable, just warned
        self.assertEqual(st.get("a"), 1)

    def test_get_returns_copy_and_put_stores_copy(self):
        st = am.JsonStore(self.path)
        val = {"list": [1]}
        st.put("k", val)
        val["list"].append(2)
        got = st.get("k")
        got["list"].append(3)
        self.assertEqual(st.get("k"), {"list": [1]})

    def test_empty_file_at_start_kept_as_corrupt_backup(self):
        """An EXISTING 0-byte file is probably a truncated store - not an empty one."""
        os.makedirs(self.dir)
        write(self.path, "")
        st = am.JsonStore(self.path)
        self.assertIn("empty (0 bytes)", st.load_problem)
        self.assertFalse(st.read_only)
        aside = self.corrupt_files()
        self.assertEqual(len(aside), 1)
        self.assertEqual(os.path.getsize(os.path.join(self.dir, aside[0])), 0)
        self.assertEqual(mode(os.path.join(self.dir, aside[0])), 0o600)
        self.assertTrue(st.put("a", 1))
        self.assertEqual(json.loads(read(self.path)), {"a": 1})

    def test_truncated_after_load_not_overwritten_then_replayed(self):
        st = am.JsonStore(self.path)
        records = {"com.app%d" % i: {"answer": "research %d" % i} for i in range(200)}
        for k, v in records.items():
            self.assertTrue(st.put(k, v))
        write(self.path, "")                        # something truncates the database
        self.assertFalse(st.put("new", 1))
        self.assertFalse(st.update("cnt", lambda v: v + 1, 0))
        self.assertIn("empty (0 bytes)", st.last_error)
        self.assertEqual(os.path.getsize(self.path), 0)   # left untouched
        self.assertEqual((st.get("new"), st.get("cnt")), (1, 1))   # pending, in memory
        write(self.path, json.dumps(records))       # user restores the backup
        self.assertTrue(st.put("later", 2))
        expected = dict(records, new=1, cnt=1, later=2)
        self.assertEqual(json.loads(read(self.path)), expected)

    def test_save_failure_reported_value_kept_then_retried(self):
        st = am.JsonStore(self.path)
        st.put("old", 1)
        with mock.patch.object(sa, "atomic_write_json", side_effect=OSError(28, "No space left on device")):
            self.assertFalse(st.put("new", 2))
            self.assertFalse(st.update("cnt", lambda v: v + 1, 0))
        self.assertIn("No space left", st.last_error)
        self.assertEqual((st.get("new"), st.get("cnt")), (2, 1))   # kept for the session
        disk = json.loads(read(self.path))
        self.assertEqual(disk, {"old": 1})                          # not on disk yet
        self.assertTrue(st.put("other", 3))                         # next save retries both
        self.assertIsNone(st.last_error)
        self.assertEqual(json.loads(read(self.path)), {"old": 1, "new": 2, "cnt": 1, "other": 3})

    # -- fail closed ---------------------------------------------------------

    def test_corrupt_at_start_moved_aside_not_overwritten(self):
        os.makedirs(self.dir)
        write(self.path, "{not json")
        st = am.JsonStore(self.path)
        self.assertIn("damaged", st.load_problem)
        self.assertFalse(st.read_only)
        aside = self.corrupt_files()
        self.assertEqual(len(aside), 1)
        self.assertEqual(read(os.path.join(self.dir, aside[0])), "{not json")
        self.assertEqual(mode(os.path.join(self.dir, aside[0])), 0o600)
        self.assertTrue(st.put("a", 1))

    def test_non_dict_at_start_moved_aside(self):
        os.makedirs(self.dir)
        write(self.path, "[1, 2]")
        st = am.JsonStore(self.path)
        self.assertTrue(st.load_problem)
        self.assertEqual(len(self.corrupt_files()), 1)

    def test_corrupt_backup_never_replaces_an_earlier_one(self):
        os.makedirs(self.dir)
        stamp = "20260101-000000"
        earlier = "%s.corrupt-%s-%d" % (self.path, stamp, os.getpid())
        write(earlier, "EARLIER BACKUP")
        write(self.path, "{second damaged file")
        with mock.patch("time.strftime", return_value=stamp):
            am.JsonStore(self.path)
        self.assertEqual(read(earlier), "EARLIER BACKUP")
        names = self.corrupt_files()
        self.assertEqual(len(names), 2)
        other = [n for n in names if os.path.join(self.dir, n) != earlier][0]
        self.assertEqual(read(os.path.join(self.dir, other)), "{second damaged file")

    def test_backup_chmod_failure_leaves_original_untouched(self):
        os.makedirs(self.dir)
        write(self.path, "{damaged")
        real = os.chmod

        def chmod(p, m, *a, **k):
            if ".corrupt-" in os.path.basename(p):
                raise OSError(1, "Operation not permitted")
            return real(p, m, *a, **k)
        with mock.patch("os.chmod", side_effect=chmod):
            st = am.JsonStore(self.path)
        self.assertTrue(st.read_only)
        self.assertIn("private", st.load_problem)
        self.assertEqual(read(self.path), "{damaged")      # original still where it was
        self.assertEqual(self.corrupt_files(), [])          # no unprotected backup kept
        self.assertFalse(st.put("a", 1))
        self.assertEqual(read(self.path), "{damaged")

    def test_unreadable_at_start_makes_store_read_only(self):
        os.makedirs(self.path)            # a folder where the file should be: open() fails
        st = am.JsonStore(self.path)
        self.assertTrue(st.read_only)
        self.assertFalse(st.put("a", 1))
        self.assertTrue(st.last_error)
        self.assertTrue(os.path.isdir(self.path))   # never clobbered

    def _fail_closed_after_load(self, damage, check_untouched):
        st = am.JsonStore(self.path)
        self.assertTrue(st.put("good", 1))
        damage()
        self.assertFalse(st.put("pending", 2))
        self.assertFalse(st.update("cnt", lambda v: v + 1, 0))
        self.assertIn("left untouched", st.last_error)
        check_untouched()
        self.assertEqual((st.get("pending"), st.get("cnt")), (2, 1))   # still in memory
        return st

    def test_corrupt_after_load_fails_closed_then_recovers(self):
        st = self._fail_closed_after_load(
            lambda: write(self.path, "{garbage written by something else"),
            lambda: self.assertEqual(read(self.path), "{garbage written by something else"))
        # once the file is valid again, the pending changes are replayed onto IT
        write(self.path, json.dumps({"good": 1, "external": "kept"}))
        self.assertTrue(st.put("later", 3))
        self.assertEqual(json.loads(read(self.path)),
                         {"good": 1, "external": "kept", "pending": 2, "cnt": 1, "later": 3})

    def test_non_dict_after_load_fails_closed(self):
        self._fail_closed_after_load(
            lambda: write(self.path, "[1, 2, 3]"),
            lambda: self.assertEqual(read(self.path), "[1, 2, 3]"))

    def test_unreadable_after_load_fails_closed(self):
        def damage():
            os.remove(self.path)
            os.makedirs(self.path)
        self._fail_closed_after_load(damage, lambda: self.assertTrue(os.path.isdir(self.path)))

    # -- concurrency ---------------------------------------------------------

    def test_thread_safe_update_loses_nothing(self):
        st = am.JsonStore(self.path)

        def work():
            for _ in range(50):
                st.update("n", lambda v: v + 1, 0)
        ts = [threading.Thread(target=work) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(st.get("n"), 400)
        self.assertEqual(json.loads(read(self.path)), {"n": 400})

    def test_two_processes_distinct_top_level_keys(self):
        ps = [MP.Process(target=_mp_put_keys, args=(self.path, p, 40)) for p in ("a", "b")]
        for p in ps:
            p.start()
        for p in ps:
            p.join(30)
            self.assertEqual(p.exitcode, 0)
        expected = {"%s%d" % (p, i): "%s-value-%d" % (p, i) for p in ("a", "b") for i in range(40)}
        self.assertEqual(json.loads(read(self.path)), expected)

    def test_stale_process_nested_update_same_key_deterministic(self):
        """The bug ChatGPT found, reproduced on purpose (no lucky scheduling):
        A and B both load DEV={...}; A updates and saves; THEN B - whose copy is
        now stale - updates DEV. Both packages must survive."""
        os.makedirs(self.dir)
        write(self.path, json.dumps({"DEV": {"com.existing": "x"}, "OTHER": 1}))
        la, lb, go_a, done_a, done_b = (MP.Event() for _ in range(5))
        a = MP.Process(target=_mp_stale_then_update, args=(self.path, "com.one", la, go_a, done_a))
        b = MP.Process(target=_mp_stale_then_update, args=(self.path, "com.two", lb, done_a, done_b))
        a.start()
        b.start()
        self.assertTrue(la.wait(10) and lb.wait(10))    # both loaded the SAME old value
        go_a.set()                                        # A saves first, then B goes
        for p in (a, b):
            p.join(30)
            self.assertEqual(p.exitcode, 0)
        self.assertEqual(json.loads(read(self.path)),
                         {"DEV": {"com.existing": "x", "com.one": "com.one-ts", "com.two": "com.two-ts"},
                          "OTHER": 1})

    def test_four_processes_nested_updates_same_key_stress(self):
        groups = [["p%d.app%d" % (g, i) for i in range(25)] for g in range(4)]
        ps = [MP.Process(target=_mp_nested_adder, args=(self.path, pk)) for pk in groups]
        for p in ps:
            p.start()
        for p in ps:
            p.join(60)
            self.assertEqual(p.exitcode, 0)
        expected = {p: "on" for pk in groups for p in pk}
        self.assertEqual(json.loads(read(self.path)), {"DEV": expected})

    def test_simultaneous_startup_on_damaged_file(self):
        os.makedirs(self.dir)
        write(self.path, "{damaged by a crash")
        in_rec, b_at_lock, out = MP.Event(), MP.Event(), MP.Queue()
        ps = [MP.Process(target=_mp_startup_on_damaged, args=(self.path, r, in_rec, b_at_lock, out))
              for r in ("A", "B")]
        for p in ps:
            p.start()
        for p in ps:
            p.join(30)
            self.assertEqual(p.exitcode, 0)
        res = {r: (ro, prob, ok, sig) for r, ro, prob, ok, sig in (out.get(timeout=5) for _ in ps)}
        self.assertTrue(res["A"][3], "A never got B's contention signal while recovering")
        self.assertTrue(res["B"][3], "B's non-blocking probe did not hit A's lock: "
                                     "no real contention was exercised")
        self.assertEqual(res["A"][0], False, res["A"][1])   # neither became read-only
        self.assertEqual(res["B"][0], False, res["B"][1])
        self.assertTrue(res["A"][2] and res["B"][2])          # both writes succeeded
        self.assertIn("damaged", res["A"][1])                 # A did the recovery
        self.assertIsNone(res["B"][1])                        # B found it already done
        aside = self.corrupt_files()
        self.assertEqual(len(aside), 1)                       # exactly one backup ...
        self.assertEqual(read(os.path.join(self.dir, aside[0])), "{damaged by a crash")  # ... intact
        self.assertEqual(mode(os.path.join(self.dir, aside[0])), 0o600)
        self.assertEqual(json.loads(read(self.path)), {"from_A": "A", "from_B": "B"})

    def test_two_stores_same_process_nested(self):
        s1, s2 = am.JsonStore(self.path), am.JsonStore(self.path)
        s1.update("DEV", lambda v: dict(v, a=1), {})
        s2.update("DEV", lambda v: dict(v, b=2), {})   # s2's copy is stale
        self.assertEqual(json.loads(read(self.path)), {"DEV": {"a": 1, "b": 2}})
        self.assertEqual(s2.get("DEV"), {"a": 1, "b": 2})


class SnapshotTests(Base):
    def setUp(self):
        super().setUp()
        self.p = mock.patch.object(sa, "SNAP_DIR", os.path.join(self.dir, "snapshots"))
        self.p.start()

    def tearDown(self):
        self.p.stop()
        super().tearDown()

    def test_snapshot_private_and_true(self):
        self.assertTrue(sa.save_snapshot("SER 1", {"time": "t"}))
        d = sa.snap_dir("SER 1")
        files = os.listdir(d)
        self.assertEqual(len(files), 1)
        self.assertEqual(mode(os.path.join(d, files[0])), 0o600)
        self.assertEqual(mode(d), 0o700)
        self.assertEqual(mode(sa.SNAP_DIR), 0o700)

    def test_failed_snapshot_returns_false_and_keeps_old_ones(self):
        d = sa.snap_dir("S")
        os.makedirs(d)
        for i in range(sa.KEEP_SNAPSHOTS):
            write(os.path.join(d, "2020010%d-000000.json" % i), "{}")
        with mock.patch.object(sa, "atomic_write_json", side_effect=OSError(28, "full")):
            self.assertFalse(sa.save_snapshot("S", {}))
        self.assertEqual(len(os.listdir(d)), sa.KEEP_SNAPSHOTS)   # nothing pruned


class ConfigSaveTests(Base):
    def test_save_config_private_atomic(self):
        cfgfile = os.path.join(self.dir, "ai_config.json")
        with mock.patch.object(ai, "CONFIG_DIR", self.dir), mock.patch.object(ai, "CONFIG_FILE", cfgfile):
            ai.save_config({"anthropic": {"api_key": "sk-test"}})
            self.assertEqual(mode(cfgfile), 0o600)
            self.assertEqual(mode(self.dir), 0o700)
            with mock.patch("os.replace", side_effect=OSError(28, "full")):
                with self.assertRaises(OSError):
                    ai.save_config({"anthropic": {"api_key": "sk-new"}})
            self.assertEqual(json.loads(read(cfgfile))["anthropic"]["api_key"], "sk-test")
            self.assertEqual(os.listdir(self.dir), ["ai_config.json"])


# ---- GUI: Apps-tab callers of JsonStore ----------------------------------

@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class AppsTabStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()
        args = mock.Mock(serial=None, local=TMP_HOME, remote="/sdcard")
        with mock.patch.object(am.App, "scan_devices", lambda self, *a, **k: None):
            cls.app = am.App(cls.root, args)
        cls.tab = cls.app.apps_tab

    @classmethod
    def tearDownClass(cls):
        destroy_root(cls.root)

    def setUp(self):
        self.tab._store_warned.clear()   # each test starts with no "already warned" state

    def test_ai_result_saved_and_keeps_old_good_answer(self):
        t = self.tab
        t._ai_result("com.x", "anthropic", {"provider": "anthropic", "answer": "good"})
        t._ai_result("com.x", "anthropic", {"provider": "anthropic", "error": "timeout"})
        disk = am.JsonStore(am.AI_CACHE_FILE).get("com.x")
        self.assertEqual(disk["anthropic"]["answer"], "good")
        self.assertEqual(disk["anthropic"]["last_error"], "timeout")

    def test_change_done_updates_store_and_completes(self):
        """No blanket except: only the UI refreshes unrelated to storage are mocked,
        and any unexpected exception fails the test."""
        t = self.tab
        t.serial = "S1"
        t.apps = {"com.a": {"package": "com.a"}, "com.b": {"package": "com.b"}}
        with mock.patch.object(t, "end_job") as end_job, \
                mock.patch.object(t, "populate") as populate, \
                mock.patch.object(t, "render") as render, \
                mock.patch.object(self.app, "info") as info, \
                mock.patch.object(self.app, "error") as error, \
                mock.patch.object(am.messagebox, "showerror") as showerror:
            t._change_done("S1", False, [("com.a", True, ""), ("com.b", False, "Failure [x]")], None)
        mine = am.JsonStore(am.TURNED_OFF_FILE).get("S1")
        self.assertEqual(set(mine), {"com.a"})
        self.assertTrue(t.apps["com.a"]["disabled"])
        self.assertNotIn("disabled", t.apps["com.b"])
        end_job.assert_called_once()
        populate.assert_called_once()
        render.assert_called_once()
        info.assert_not_called()
        error.assert_called_once()
        self.assertIn("1 turned off, 1 failed", error.call_args[0][0])
        showerror.assert_not_called()          # only one failure -> no extra dialog

    def test_pending_callbacks_replay_frozen_values(self):
        """A pending update must write what the user saw, even if it is replayed
        after the app state, the clock and the original result object changed."""
        t = self.tab
        t.serial = "S2"
        t.apps = {"com.a": {"package": "com.a"}}
        res = {"provider": "openai", "answer": "first"}
        with mock.patch.object(sa, "atomic_write_json", side_effect=OSError(28, "full")), \
                mock.patch.object(am.time, "strftime", return_value="2026-01-01 10:00"), \
                mock.patch.object(t, "end_job"), mock.patch.object(t, "populate"), \
                mock.patch.object(t, "render"), mock.patch.object(self.app, "info"), \
                mock.patch.object(self.app, "error"):
            t._change_done("S2", False, [("com.a", True, "")], None)
            t._ai_result("com.frozen", "openai", res)
        self.assertTrue(t.turned_off._pending and t.ai_cache._pending)
        # now everything the callbacks could have peeked at changes ...
        t.apps = {}                          # e.g. a rescan
        res["answer"] = "MUTATED"           # caller reuses its dict
        with mock.patch.object(am.time, "strftime", return_value="2099-12-31 23:59"):
            self.assertTrue(t.turned_off.put("unrelated", 1))   # replays pending ops
            self.assertTrue(t.ai_cache.put("unrelated", 1))
        self.assertEqual(am.JsonStore(am.TURNED_OFF_FILE).get("S2"), {"com.a": "2026-01-01 10:00"})
        self.assertEqual(am.JsonStore(am.AI_CACHE_FILE).get("com.frozen")["openai"]["answer"], "first")

    def test_save_failure_reported_once(self):
        t = self.tab
        with mock.patch.object(sa, "atomic_write_json", side_effect=OSError(28, "No space left")), \
                mock.patch.object(self.app, "error") as err:
            t._ai_result("com.y", "openai", {"provider": "openai", "answer": "a"})
            t._ai_result("com.z", "openai", {"provider": "openai", "answer": "b"})
        self.assertEqual(err.call_count, 1)
        self.assertIn("No space left", err.call_args[0][0])
        self.assertEqual(t.ai_cache.get("com.y")["openai"]["answer"], "a")   # kept in session



# ==========================================================================
# Round 7 - E-13: deep scan covers EVERY installed APK part
# ==========================================================================

import hashlib  # noqa: E402


def _h(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _part(name, content=None, certs=("C1",), error=None):
    d = {"path": "/data/app/x/" + name, "name": name, "kind": sa.apk_part_kind(name)}
    if error:
        d["error"] = error
    else:
        d.update(sha256=_h(content or name), size=10, cert=certs[0] if certs else "", certs=list(certs))
    return d


VT_CLEAN = {"known": True, "malicious": 0, "suspicious": 0, "engines": 70, "label": ""}
VT_BAD = {"known": True, "malicious": 6, "suspicious": 0, "engines": 70, "label": "trojan.x"}
VT_SUS = {"known": True, "malicious": 1, "suspicious": 0, "engines": 70, "label": ""}
VT_UNKNOWN = {"known": False}


class PartIdentityTests(unittest.TestCase):
    def test_part_kinds(self):
        self.assertEqual(sa.apk_part_kind("base.apk"), "base")
        self.assertEqual(sa.apk_part_kind("split_config.arm64_v8a.apk"), "config")
        self.assertEqual(sa.apk_part_kind("split_config.xxhdpi.apk"), "config")
        self.assertEqual(sa.apk_part_kind("split_df_camera.apk"), "feature")

    def test_plain_labels(self):
        self.assertEqual(sa.apk_part_label({"name": "base.apk"}), "main app file")
        self.assertIn("processor", sa.apk_part_label({"name": "split_config.arm64_v8a.apk"}))
        self.assertIn("screen", sa.apk_part_label({"name": "split_config.xxhdpi.apk"}))
        self.assertIn("'df_camera'", sa.apk_part_label({"name": "split_df_camera.apk"}))

    def test_full_coverage_same_signer(self):
        i = sa.make_app_identity("p", [_part("base.apk"), _part("split_config.arm64_v8a.apk")])
        self.assertEqual((i["coverage"], i["signers"], i["unread"]), ("full", "same", []))
        self.assertEqual(i["sha256"], _h("base.apk"))      # old top-level fields = base
        self.assertEqual(i["cert"], "C1")
        self.assertTrue(sa.identity_complete(i))

    def test_unread_split_is_partial(self):
        i = sa.make_app_identity("p", [_part("base.apk"), _part("split_x.apk", error="copy failed")])
        self.assertEqual(i["coverage"], "partial")
        self.assertEqual(i["unread"], ["split_x.apk"])
        self.assertFalse(sa.identity_complete(i))

    def test_missing_base_is_partial(self):
        i = sa.make_app_identity("p", [_part("split_x.apk")])
        self.assertEqual(i["coverage"], "partial")
        self.assertEqual(i["sha256"], "")

    def test_signers_different_and_unknown(self):
        diff = sa.make_app_identity("p", [_part("base.apk"), _part("split_x.apk", certs=("C2",))])
        self.assertEqual(diff["signers"], "different")
        unk = sa.make_app_identity("p", [_part("base.apk"), _part("split_x.apk", certs=())])
        self.assertEqual(unk["signers"], "unknown")

    def test_signers_mixed_different_wins_but_unknown_is_listed(self):
        """Base A, one split B, another readable split with no signer info."""
        i = sa.make_app_identity("p", [_part("base.apk", certs=("A",)),
                                       _part("split_b.apk", certs=("B",)),
                                       _part("split_none.apk", certs=())])
        self.assertEqual(i["signers"], "different")        # confirmed mismatch wins
        self.assertEqual(i["signers_unknown"], ["split_none.apk"])   # ... but not hidden

    def test_signers_unknown_base(self):
        i = sa.make_app_identity("p", [_part("base.apk", certs=()), _part("split_b.apk", certs=("B",))])
        self.assertEqual(i["signers"], "unknown")          # no known base set to compare with

    def test_legacy_record_not_complete(self):
        legacy = {"sha256": _h("base.apk"), "size": 1, "cert": "C1", "certs": ["C1"], "pkg": "p"}
        self.assertFalse(sa.identity_complete(legacy))
        self.assertEqual(len(sa.identity_parts(legacy)), 1)


class PartReputationTests(unittest.TestCase):
    lbl = staticmethod(lambda p: "Label " + p)

    def run_rep(self, parts, vts, legacy=None):
        ident = legacy or sa.make_app_identity("p", parts)
        rep = {h: {"vt": v} for h, v in vts.items()}
        return sa.reputation_findings({"p": {}}, self.lbl, {"p": ident}, rep)

    def test_single_part_clean_unchanged_wording(self):
        f = self.run_rep([_part("base.apk")], {_h("base.apk"): VT_CLEAN})
        self.assertEqual((f[0]["level"], f[0]["title"]), (sa.OK, "Clean on VirusTotal: Label p"))

    def test_all_parts_clean(self):
        parts = [_part("base.apk"), _part("split_config.arm64_v8a.apk"), _part("split_feat.apk")]
        f = self.run_rep(parts, {x["sha256"]: VT_CLEAN for x in parts})
        self.assertEqual(f[0]["level"], sa.OK)
        self.assertIn("all 3 parts", f[0]["title"])

    def test_flagged_split_flags_the_app(self):
        """The whole point of E-13: malware only in a split must not hide behind a clean base."""
        parts = [_part("base.apk"), _part("split_config.arm64_v8a.apk")]
        f = self.run_rep(parts, {parts[0]["sha256"]: VT_CLEAN, parts[1]["sha256"]: VT_BAD})
        self.assertEqual(f[0]["level"], sa.BAD)
        self.assertIn("Processor-specific code", f[0]["detail"])
        self.assertIn("6 of 70", f[0]["detail"])

    def test_suspicious_split_warns(self):
        parts = [_part("base.apk"), _part("split_feat.apk")]
        f = self.run_rep(parts, {parts[0]["sha256"]: VT_CLEAN, parts[1]["sha256"]: VT_SUS})
        self.assertEqual(f[0]["level"], sa.WARN)

    def test_unread_part_never_clean(self):
        parts = [_part("base.apk"), _part("split_feat.apk", error="copy failed: permission denied")]
        f = self.run_rep(parts, {parts[0]["sha256"]: VT_CLEAN})
        self.assertEqual(f[0]["level"], sa.INFO)
        self.assertIn("Only partly checked", f[0]["title"])
        self.assertIn("NOT checked", f[0]["detail"])
        self.assertIn("permission denied", f[0]["detail"])

    def test_unread_part_still_reports_bad(self):
        parts = [_part("base.apk"), _part("split_feat.apk", error="copy failed")]
        f = self.run_rep(parts, {parts[0]["sha256"]: VT_BAD})
        self.assertEqual(f[0]["level"], sa.BAD)
        self.assertIn("couldn't be checked", f[0]["detail"])

    def test_legacy_base_only_is_partly_checked(self):
        legacy = {"sha256": _h("base.apk"), "size": 1, "cert": "C1", "certs": ["C1"], "pkg": "p"}
        f = self.run_rep(None, {_h("base.apk"): VT_CLEAN}, legacy=legacy)
        self.assertEqual(f[0]["level"], sa.INFO)
        self.assertIn("Only partly checked", f[0]["title"])
        self.assertIn("older version", f[0]["detail"])

    def test_unknown_part_not_clean(self):
        parts = [_part("base.apk"), _part("split_feat.apk")]
        f = self.run_rep(parts, {parts[0]["sha256"]: VT_CLEAN, parts[1]["sha256"]: VT_UNKNOWN})
        self.assertEqual(f[0]["level"], sa.INFO)
        self.assertIn("Not known", f[0]["title"])

    def test_mixed_signers_warning_names_mismatch_and_unknown(self):
        parts = [_part("base.apk", certs=("A",)), _part("split_config.arm64_v8a.apk", certs=("B",)),
                 _part("split_feat.apk", certs=())]
        f = self.run_rep(parts, {x["sha256"]: VT_CLEAN for x in parts})
        w = [x for x in f if "signed by different keys" in x["title"]][0]
        self.assertIn("processor-specific code", w["detail"])            # the mismatching part
        self.assertIn("optional feature 'feat'", w["detail"])           # the unknown one ...
        self.assertIn("couldn't be read at all", w["detail"])           # ... flagged as unknown
        self.assertNotIn("optional feature 'feat', ", w["detail"].split("don't match")[1].split(".")[0])

    def test_different_signers_extra_warning(self):
        parts = [_part("base.apk"), _part("split_feat.apk", certs=("OTHER",))]
        f = self.run_rep(parts, {x["sha256"]: VT_CLEAN for x in parts})
        titles = [x["title"] for x in f]
        self.assertTrue(any("signed by different keys" in t for t in titles), titles)


class PmPathsAndReadTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def test_pm_paths_raises_on_failure(self):
        with mock.patch.object(am, "adb_shell", return_value=(1, "", "Error: package not found")):
            with self.assertRaises(am.AdbError):
                am.pm_paths("S", "com.x")

    def test_pm_paths_parses_all_parts(self):
        out = "package:/data/app/x/base.apk\npackage:/data/app/x/split_config.arm64_v8a.apk\n"
        with mock.patch.object(am, "adb_shell", return_value=(0, out, "")):
            self.assertEqual(am.pm_paths("S", "com.x"),
                             ["/data/app/x/base.apk", "/data/app/x/split_config.arm64_v8a.apk"])

    def _fake_pull(self, fail=()):
        def pull(cmd, on_pct, cancel):
            remote, local = cmd[-2], cmd[-1]
            if posixpath.basename(remote) in fail:
                return 1, "adb: error: failed to stat remote object: Permission denied"
            write(local, "APK:" + remote)
            return 0, ""
        return pull

    def test_reads_every_part_and_cleans_up(self):
        paths = ["/data/app/x/base.apk", "/data/app/x/split_config.arm64_v8a.apk", "/data/app/x/split_f.apk"]
        with mock.patch.object(am, "pm_paths", return_value=paths), \
                mock.patch.object(am, "adb_transfer", side_effect=self._fake_pull()):
            i = am.read_app_identity("S", "com.x", self.work, threading.Event())
        self.assertEqual([x["sha256"] for x in i["parts"]], [_h("APK:" + p) for p in paths])
        self.assertEqual(i["coverage"], "full")
        self.assertEqual(os.listdir(self.work), [])          # copies deleted

    def test_unreadable_split_recorded_not_skipped(self):
        paths = ["/data/app/x/base.apk", "/data/app/x/split_f.apk"]
        with mock.patch.object(am, "pm_paths", return_value=paths), \
                mock.patch.object(am, "adb_transfer", side_effect=self._fake_pull(fail={"split_f.apk"})):
            i = am.read_app_identity("S", "com.x", self.work, threading.Event())
        self.assertEqual(i["coverage"], "partial")
        self.assertEqual(i["unread"], ["split_f.apk"])
        self.assertIn("Permission denied", i["parts"][1]["error"])

    def test_stop_returns_none(self):
        """Stop pressed while the LAST part is copying: adb_transfer reports
        'cancelled'. That must not be cached as 'this part is unreadable'."""
        stop = threading.Event()
        paths = ["/data/app/x/base.apk", "/data/app/x/split_f.apk"]

        def pull(cmd, on_pct, cancel):
            if cmd[-2].endswith("split_f.apk"):
                stop.set()              # user presses Stop during the last copy
                return -1, "cancelled"
            write(cmd[-1], "x")
            return 0, ""
        with mock.patch.object(am, "pm_paths", return_value=paths), \
                mock.patch.object(am, "adb_transfer", side_effect=pull):
            self.assertIsNone(am.read_app_identity("S", "com.x", self.work, stop))
        self.assertEqual(os.listdir(self.work), [])

    def test_stop_before_next_part_returns_none(self):
        stop = threading.Event()
        paths = ["/data/app/x/base.apk", "/data/app/x/split_f.apk"]

        def pull(cmd, on_pct, cancel):
            write(cmd[-1], "x")
            stop.set()                  # Stop pressed right after the first copy finished
            return 0, ""
        with mock.patch.object(am, "pm_paths", return_value=paths), \
                mock.patch.object(am, "adb_transfer", side_effect=pull) as tr:
            self.assertIsNone(am.read_app_identity("S", "com.x", self.work, stop))
        self.assertEqual(tr.call_count, 1)   # didn't start copying the next part
        self.assertEqual(os.listdir(self.work), [])


def _app(vc="1"):
    return {"package": "", "system": False, "version_code": vc, "last_update": "t", "granted": [],
            "requested": [], "installer": "", "version": "1.0"}


class _DeepScanHarness:
    """Shared fakes for the deep-scan tests (no test_ methods here)."""
    # Runs the real SecurityTab._do_check with only the device and the internet
    # faked: adb_shell/pm_paths/adb_transfer and the VirusTotal lookup.
    PATHS = {
        "com.a": ["/data/app/a/base.apk", "/data/app/a/split_config.arm64_v8a.apk", "/data/app/a/split_f.apk"],
        "com.b": ["/data/app/b/base.apk", "/data/app/b/split_blocked.apk"],
    }

    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()
        args = mock.Mock(serial=None, local=TMP_HOME, remote="/sdcard")
        with mock.patch.object(am.App, "scan_devices", lambda self, *a, **k: None):
            cls.app = am.App(cls.root, args)
        cls.tab = cls.app.sec_tab

    @classmethod
    def tearDownClass(cls):
        destroy_root(cls.root)

    def setUp(self):
        for f in (sa.IDENTITY_FILE, sa.REPUTATION_FILE, sa.TRACKERS_FILE):
            if os.path.exists(f):
                os.remove(f)
        self.tab.stop.clear()
        self.pulled, self.vt_calls = [], []
        self.cfg = dict(sa.DEFAULT_SEC_CONFIG, virustotal_key="k", malwarebazaar_key="", exodus_token="")
        self.vt_answers = {_h("APK:/data/app/a/split_config.arm64_v8a.apk"): VT_BAD}

    def pull(self, cmd, on_pct, cancel):
        remote, local = cmd[-2], cmd[-1]
        self.pulled.append(remote)
        if remote.endswith("split_blocked.apk"):
            return 1, "adb: error: Permission denied"
        write(local, "APK:" + remote)
        return 0, ""

    def vt(self, key, h):
        self.vt_calls.append(h)
        return self.vt_answers.get(h, VT_CLEAN)

    def scan(self, deep=True, apps=None):
        apps = apps or {"com.a": _app(), "com.b": _app()}
        with mock.patch.object(am, "adb_shell", return_value=(0, "", "")), \
                mock.patch.object(am, "read_sockets", return_value=([], [])), \
                mock.patch.object(am, "pm_paths", side_effect=lambda s, p: self.PATHS[p]), \
                mock.patch.object(am, "adb_transfer", side_effect=self.pull), \
                mock.patch.object(sa, "virustotal", side_effect=self.vt), \
                mock.patch.object(sa, "launcher_packages", return_value=(set(apps), "test")), \
                mock.patch.object(am.time, "sleep"):
            return self.tab._do_check("SER", deep, self.cfg, apps)

    def mal(self, res, pkg):
        return [f for f in res["findings"] if f["section"] == "malware" and f.get("pkg") == pkg
                and f["key"].startswith("malware:")][0]



@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class DeepScanIntegrationTests(_DeepScanHarness, unittest.TestCase):
    def test_every_part_pulled_hashed_and_looked_up(self):
        res = self.scan()
        self.assertEqual(sorted(self.pulled), sorted(self.PATHS["com.a"] + self.PATHS["com.b"]))
        expected = {_h("APK:" + p) for p in self.PATHS["com.a"] + ["/data/app/b/base.apk"]}
        self.assertEqual(set(self.vt_calls), expected)        # every READABLE part, once each
        self.assertEqual(len(self.vt_calls), len(expected))
        self.assertEqual(self.mal(res, "com.a")["level"], sa.BAD)     # malware only in a split
        b = self.mal(res, "com.b")
        self.assertEqual(b["level"], sa.INFO)
        self.assertIn("Only partly checked", b["title"])
        ids = json.loads(read(sa.IDENTITY_FILE))
        cov = {v["pkg"]: v["coverage"] for v in ids.values()}
        self.assertEqual(cov, {"com.a": "full", "com.b": "partial"})
        self.assertEqual(mode(sa.IDENTITY_FILE), 0o600)

    def test_second_scan_skips_complete_retries_partial_and_reuses_lookups(self):
        self.scan()
        self.pulled, self.vt_calls = [], []
        self.scan()
        self.assertEqual(sorted(self.pulled), sorted(self.PATHS["com.b"]))  # only the partial app again
        self.assertEqual(self.vt_calls, [])                                 # results remembered

    def test_legacy_base_only_record_is_reread(self):
        k = sa.identity_key("com.a", _app())
        sa.atomic_write_json(sa.IDENTITY_FILE, {k: {"pkg": "com.a", "sha256": _h("old"), "size": 1,
                                                    "cert": "C", "certs": ["C"]}})
        res = self.scan(apps={"com.a": _app()})
        self.assertEqual(sorted(self.pulled), sorted(self.PATHS["com.a"]))
        self.assertEqual(self.mal(res, "com.a")["level"], sa.BAD)

    def test_plain_checkup_with_legacy_record_says_partly_checked(self):
        k = sa.identity_key("com.a", _app())
        sa.atomic_write_json(sa.IDENTITY_FILE, {k: {"pkg": "com.a", "sha256": _h("old"), "size": 1,
                                                    "cert": "C", "certs": ["C"]}})
        sa.atomic_write_json(sa.REPUTATION_FILE, {_h("old"): {"vt": VT_CLEAN, "time": time.time()}})
        res = self.scan(deep=False, apps={"com.a": _app()})
        self.assertEqual(self.pulled, [])
        f = self.mal(res, "com.a")
        self.assertEqual(f["level"], sa.INFO)
        self.assertIn("Only partly checked", f["title"])

    def test_pm_path_failure_recorded_as_unread(self):
        with mock.patch.dict(self.PATHS, {"com.a": None}):
            def pm(s, p):
                if p == "com.a":
                    raise am.AdbError("pm path com.a failed: Error")
                return self.PATHS[p]
            with mock.patch.object(am, "adb_shell", return_value=(0, "", "")), \
                    mock.patch.object(am, "read_sockets", return_value=([], [])), \
                    mock.patch.object(am, "pm_paths", side_effect=pm), \
                    mock.patch.object(am, "adb_transfer", side_effect=self.pull), \
                    mock.patch.object(sa, "virustotal", side_effect=self.vt), \
                    mock.patch.object(sa, "launcher_packages", return_value=({"com.a"}, "t")), \
                    mock.patch.object(am.time, "sleep"):
                res = self.tab._do_check("SER", True, self.cfg, {"com.a": _app()})
        f = self.mal(res, "com.a")
        self.assertIn("Only partly checked", f["title"])
        self.assertIn("pm path com.a failed", f["detail"])

    def test_cache_save_failure_reported(self):
        real = sa.save_json
        with mock.patch.object(sa, "save_json",
                               side_effect=lambda path, data, private=True:
                               False if path == sa.IDENTITY_FILE else real(path, data, private)):
            res = self.scan()
        w = [f for f in res["findings"] if f["key"] == "changes:cache-save-failed"]
        self.assertEqual(len(w), 1)
        self.assertIn("apk_identity.json", w[0]["detail"])


class SnapshotCertTests(unittest.TestCase):
    """An UNKNOWN signer must never look like a REPLACED one, and must not make
    us forget the last known signer either."""

    def facts(self, vc="1"):
        return {"apps": {"com.a": dict(_app(vc), granted=[])},
                "props": {}, "selinux": "Enforcing", "su": []}

    def snap(self, identities, prev=None, vc="1"):
        return sa.build_snapshot("S", self.facts(vc), {}, set(), identities, prev=prev)

    def cert_findings(self, prev, cur):
        return [f for f in sa.compare_snapshots(prev, cur, None) if f["key"].startswith("changes:cert:")]

    def ident(self, cert, vc="1"):
        k = sa.identity_key("com.a", _app(vc))
        if cert is None:     # base unreadable
            return {k: sa.make_app_identity("com.a", [_part("base.apk", error="copy failed")])}
        return {k: sa.make_app_identity("com.a", [_part("base.apk", certs=(cert,))])}

    def test_unreadable_base_is_not_a_cert_change_and_keeps_known_signer(self):
        prev = self.snap(self.ident("A"))
        cur = self.snap(self.ident(None), prev=prev)
        self.assertEqual(self.cert_findings(prev, cur), [])
        self.assertEqual(cur["apps"]["com.a"]["cert"], "A")             # carried forward ...
        self.assertTrue(cur["apps"]["com.a"]["cert_unverified"])         # ... and marked so

    def test_no_identity_after_update_keeps_known_signer(self):
        prev = self.snap(self.ident("A"))
        cur = self.snap({}, prev=prev, vc="2")                           # updated, not deep-scanned
        self.assertEqual(self.cert_findings(prev, cur), [])
        self.assertEqual(cur["apps"]["com.a"]["cert"], "A")

    def test_replacement_hidden_behind_unknown_scan_is_still_caught(self):
        s1 = self.snap(self.ident("A"))
        s2 = self.snap(self.ident(None), prev=s1)       # base unreadable this time
        s3 = self.snap(self.ident("EVIL"), prev=s2)     # readable again: different signer
        f = self.cert_findings(s2, s3)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["level"], sa.BAD)
        self.assertIn("old cert A", f[0]["tech"])

    def test_verified_cert_not_marked_unverified(self):
        prev = self.snap(self.ident("A"))
        cur = self.snap(self.ident("A"), prev=prev)
        self.assertFalse(cur["apps"]["com.a"]["cert_unverified"])

    def test_first_ever_unknown_stays_blank(self):
        cur = self.snap(self.ident(None))
        self.assertEqual(cur["apps"]["com.a"]["cert"], "")


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class DeepScanSaveAndSnapshotTests(_DeepScanHarness, unittest.TestCase):
    """Uses the same deep-scan harness; adds only its own tests."""

    def rep_save(self, fail_calls):
        calls = []
        real = sa.save_json

        def fake(path, data, private=True):
            if path == sa.REPUTATION_FILE:
                calls.append(1)
                if len(calls) in fail_calls(len(calls)):
                    return False
            return real(path, data, private)
        return fake, calls

    def test_rep_first_write_fails_later_succeeds_no_warning(self):
        fake, calls = self.rep_save(lambda n: {1})
        with mock.patch.object(sa, "save_json", side_effect=fake):
            res = self.scan()
        self.assertGreater(len(calls), 1)
        self.assertEqual([f for f in res["findings"] if f["key"] == "changes:cache-save-failed"], [])
        saved = json.loads(read(sa.REPUTATION_FILE))       # the later write saved the first result too
        self.assertIn(_h("APK:/data/app/a/base.apk"), saved)

    def test_rep_last_write_fails_warning(self):
        state = {}

        def fails(n):
            return {n} if n == state.get("last") else set()
        # first run to count the writes, then fail exactly the last one
        fake, calls = self.rep_save(lambda n: set())
        with mock.patch.object(sa, "save_json", side_effect=fake):
            self.scan()
        state["last"] = len(calls)
        for f in (sa.IDENTITY_FILE, sa.REPUTATION_FILE):
            os.remove(f)
        fake, calls = self.rep_save(fails)
        with mock.patch.object(sa, "save_json", side_effect=fake):
            res = self.scan()
        w = [f for f in res["findings"] if f["key"] == "changes:cache-save-failed"]
        self.assertEqual(len(w), 1)
        self.assertIn("reputation.json", w[0]["detail"])

    def test_unreadable_base_after_known_signer_no_false_cert_change(self):
        """Real scan path: previous snapshot knows signer A; now pm path fails."""
        k = sa.identity_key("com.a", _app())
        prev = sa.build_snapshot("SER", {"apps": {"com.a": _app()}, "props": {}, "selinux": "Enforcing",
                                         "su": []}, {}, set(),
                                 {k: sa.make_app_identity("com.a", [_part("base.apk", certs=("A",))])})
        with mock.patch.object(sa, "SNAP_DIR", os.path.join(TMP_HOME, "snaps-cert-test")):
            self.assertTrue(sa.save_snapshot("SER", prev))

            def pm(s, p):
                raise am.AdbError("pm path com.a failed: Error")
            with mock.patch.object(am, "adb_shell", return_value=(0, "", "")), \
                    mock.patch.object(am, "read_sockets", return_value=([], [])), \
                    mock.patch.object(am, "pm_paths", side_effect=pm), \
                    mock.patch.object(sa, "virustotal", side_effect=self.vt), \
                    mock.patch.object(sa, "launcher_packages", return_value=({"com.a"}, "t")), \
                    mock.patch.object(am.time, "sleep"):
                res = self.tab._do_check("SER", True, self.cfg, {"com.a": _app()})
            self.assertEqual([f for f in res["findings"] if f["key"].startswith("changes:cert:")], [])
            saved = sa.last_snapshot("SER")["apps"]["com.a"]
        self.assertEqual((saved["cert"], saved["cert_unverified"]), ("A", True))


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class NetworkSeenSaveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()
        args = mock.Mock(serial=None, local=TMP_HOME, remote="/sdcard")
        with mock.patch.object(am.App, "scan_devices", lambda self, *a, **k: None):
            cls.app = am.App(cls.root, args)
        cls.net = next(v for v in vars(cls.app).values() if isinstance(v, am.NetworkTab))

    @classmethod
    def tearDownClass(cls):
        destroy_root(cls.root)

    def test_seen_save_failure_warned_once(self):
        n = self.net
        n.serial, n.seen, n.learn_until = "SER", {}, 0.0
        # two DIFFERENT destinations (the app groups an address block like 203.0.113.* as one)
        socks = [{"uid": 10123, "remote_ip": ip, "remote_port": 443, "proto": "tcp"}
                 for ip in ("203.0.113.1", "198.51.100.1")]
        with mock.patch.object(sa, "save_json", return_value=False), \
                mock.patch.object(self.app, "error") as err, \
                mock.patch.object(n, "owner_key", return_value="com.x"):
            for sk in socks:
                n.note_destination(sk)
            self.assertEqual(sa.save_json.call_count, 2)       # really attempted twice
        warnings = [c[0][0] for c in err.call_args_list if "this session only" in c[0][0]]
        self.assertEqual(len(warnings), 1)                     # warned once, not per destination
        alerts = [c[0][0] for c in err.call_args_list if c[0][0].startswith("New destination")]
        self.assertEqual(len(alerts), 2)                       # normal alerts still shown



# ==========================================================================
# Round 9 - E-14 part 1: device verdicts (boot state, A/B, root, failed reads)
# ==========================================================================

def fake_shell(answers=None, fail=()):
    """A device shell for sa.collect(): raises for commands containing any string
    in `fail` (like the real wrapper does on a non-zero exit), returns canned
    output for commands containing a key of `answers`, else "" - except the su
    loop, which gets its completion sentinel unless told otherwise."""
    answers = dict(answers or {})

    def shell(cmd, timeout=30):
        for f in fail:
            if f in cmd:
                raise am.AdbError("exit code 1: %s failed" % f)
        for k, v in answers.items():
            if k in cmd:
                return v
        if sa.SU_SENTINEL in cmd:
            return sa.SU_SENTINEL + "\n"
        if "dumpsys appops" in cmd:
            return "Uid mode: (none)\n"
        return ""
    return shell


def facts_from(answers=None, fail=(), apps=None):
    return sa.collect(fake_shell(answers, fail), apps if apps is not None else {"com.a": _app()}, [])


def by_key(findings, key):
    return [f for f in findings if f["key"] == key]


class BootStateTests(unittest.TestCase):
    def test_matrix(self):
        cases = [
            (("green", "1", "locked"), "locked"),
            (("yellow", "1", "locked"), "custom_key"),     # the old bug: reported as OK/green
            (("yellow", "", ""), "custom_key"),
            (("orange", "0", "unlocked"), "unlocked"),
            (("red", "1", ""), "failed"),
            (("", "0", ""), "unlocked"),
            (("", "", "locked"), "locked"),
            (("", "", ""), "unknown"),
        ]
        for args, want in cases:
            self.assertEqual(sa.boot_state(*args)["state"], want, args)

    def test_conflict_takes_less_safe_reading(self):
        bs = sa.boot_state("green", "0", "")
        self.assertEqual(bs["state"], "unlocked")
        self.assertIn("flash.locked", bs["conflict"])

    def test_yellow_unlocked_conflict(self):
        bs = sa.boot_state("yellow", "0", "")
        self.assertEqual(bs["state"], "unlocked")           # less safe reading wins
        self.assertTrue(bs["conflict"])
        bs = sa.boot_state("yellow", "", "unlocked")
        self.assertEqual(bs["state"], "unlocked")

    def test_contradicting_lock_properties_unlocked_wins(self):
        for vb in ("yellow", "green", ""):
            for fl, vm in (("1", "unlocked"), ("0", "locked")):
                bs = sa.boot_state(vb, fl, vm)
                self.assertEqual(bs["state"], "unlocked", (vb, fl, vm))
                self.assertIn("contradict", bs["conflict"], (vb, fl, vm))
                self.assertIn("flash.locked=%s" % fl, bs["conflict"])
                self.assertIn("vbmeta.device_state=%s" % vm, bs["conflict"])

    def test_red_with_contradicting_flags_is_failed_and_described(self):
        for fl, vm in (("1", "unlocked"), ("0", "locked")):
            bs = sa.boot_state("red", fl, vm)
            self.assertEqual(bs["state"], "failed", (fl, vm))
            self.assertIn("red wins over flash.locked=%s, vbmeta.device_state=%s" % (fl, vm), bs["conflict"])
            self.assertIn("contradict", bs["conflict"])

    def test_agreeing_lock_properties_no_conflict(self):
        self.assertEqual(sa.boot_state("", "1", "locked"), {"state": "locked", "conflict": ""})
        self.assertEqual(sa.boot_state("", "0", "unlocked"), {"state": "unlocked", "conflict": ""})
        self.assertEqual(sa.boot_state("green", "1", "locked"), {"state": "locked", "conflict": ""})

    def test_red_always_wins(self):
        for fl, vm in (("1", "locked"), ("0", "unlocked"), ("1", ""), ("", "")):
            bs = sa.boot_state("red", fl, vm)
            self.assertEqual(bs["state"], "failed", (fl, vm))
            self.assertEqual(bool(bs["conflict"]), bool(fl or vm), (fl, vm))

    def test_orange_locked_conflict_stays_unlocked(self):
        bs = sa.boot_state("orange", "1", "locked")
        self.assertEqual(bs["state"], "unlocked")
        self.assertTrue(bs["conflict"])

    def check(self, vb, fl="", vm=""):
        return by_key(sa.check_device(facts_from({"ro.boot.verifiedbootstate": vb, "ro.boot.flash.locked": fl,
                                                  "ro.boot.vbmeta.device_state": vm})), "boot")

    def test_yellow_locked_is_custom_key_not_ok(self):
        f = self.check("yellow", "1", "locked")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["level"], sa.INFO)
        self.assertIn("custom key", f[0]["title"])

    def test_red_is_bad(self):
        f = self.check("red", "1")
        self.assertEqual(f[0]["level"], sa.BAD)

    def test_green_ok_orange_warn(self):
        self.assertEqual(self.check("green", "1")[0]["level"], sa.OK)
        self.assertEqual(self.check("orange", "0")[0]["level"], sa.WARN)

    def test_boot_unreadable(self):
        f = by_key(sa.check_device(facts_from(fail=("verifiedbootstate", "flash.locked", "vbmeta"))), "boot")
        self.assertEqual(f[0]["title"], "Couldn't check the bootloader")


class DeviceInfoTests(unittest.TestCase):
    def info(self, props):
        def shell(cmd, timeout=15):
            return props.get(cmd.split()[-1], "")
        d = sa.device_info(shell)
        return d, {lbl: (val, note) for _, rows in d["groups"] for lbl, val, note in rows}

    def test_yellow_shown_as_locked_with_custom_key(self):
        d, rows = self.info({"ro.boot.verifiedbootstate": "yellow", "ro.boot.flash.locked": "1"})
        self.assertEqual(d["bootloader"], "LOCKED")
        self.assertIn("custom key", rows["Bootloader"][0])

    def test_device_info_and_checkup_agree(self):
        for vb, fl in (("green", "1"), ("yellow", "1"), ("orange", "0"), ("yellow", "0")):
            d, _ = self.info({"ro.boot.verifiedbootstate": vb, "ro.boot.flash.locked": fl})
            st = sa.boot_state(vb, fl, "")["state"]
            want = {"locked": "LOCKED", "custom_key": "LOCKED", "unlocked": "UNLOCKED",
                    "failed": "VERIFICATION FAILED"}[st]
            self.assertEqual(d["bootloader"], want, (vb, fl))

    def test_dynamic_partitions_are_not_ab(self):
        _, rows = self.info({"ro.boot.dynamic_partitions": "true"})
        self.assertEqual(rows["A/B slots"][0], "not detected")
        self.assertIn("NOT mean", rows["Dynamic partitions"][1])

    def test_ab_update_property(self):
        _, rows = self.info({"ro.build.ab_update": "true"})
        self.assertEqual(rows["A/B slots"][0], "yes (A/B)")
        _, rows = self.info({"ro.build.ab_update": "false"})
        self.assertEqual(rows["A/B slots"][0], "not detected")
        _, rows = self.info({"ro.build.ab_update": "false", "ro.boot.dynamic_partitions": "true"})
        self.assertEqual(rows["A/B slots"][0], "not detected")

    def test_slot_suffix_is_ab(self):
        _, rows = self.info({"ro.boot.slot_suffix": "_b", "ro.virtual_ab.enabled": "true"})
        self.assertIn("yes (A/B)", rows["A/B slots"][0])
        self.assertIn("slot b", rows["A/B slots"][0])
        self.assertIn("virtual A/B", rows["A/B slots"][0])
        self.assertNotIn("Dynamic partitions", rows)


class FailedReadTests(unittest.TestCase):
    def test_collect_records_failures(self):
        f = facts_from(fail=("getenforce", "dumpsys appops", "enabled_accessibility_services"))
        self.assertEqual(sorted(f["failed"]), ["appops", "selinux", "setting:accessibility"])

    def test_su_needs_sentinel(self):
        f = facts_from({"for p in": "/system/xbin/su\n"})        # no sentinel: output cut short
        self.assertIn("su", f["failed"])
        self.assertEqual(f["su"], [])
        ok = facts_from({"for p in": "/system/xbin/su\n" + sa.SU_SENTINEL + "\n"})
        self.assertEqual(ok["su"], ["/system/xbin/su"])
        self.assertNotIn("su", ok["failed"])

    def test_empty_appops_counts_as_failed(self):
        f = facts_from({"dumpsys appops": ""})
        self.assertIn("appops", f["failed"])

    def test_root_unknown_is_not_all_clear(self):
        f = by_key(sa.check_device(facts_from(fail=("for p in",))), "root")
        self.assertEqual((f[0]["level"], f[0]["title"]), (sa.INFO, "Couldn't fully check for root"))

    def test_manager_app_with_successful_su_check_is_not_confirmed_root(self):
        apps = {"com.a": _app(), "me.bmax.apatch": _app()}
        found = sa.check_device(facts_from(apps=apps))
        root = by_key(found, "root")[0]
        self.assertEqual(root["level"], sa.INFO)
        self.assertIn("root not confirmed", root["title"])
        mgr = by_key(found, "root-manager")[0]
        self.assertEqual(mgr["level"], sa.WARN)
        self.assertIn("me.bmax.apatch", mgr["title"])
        self.assertIn("does NOT confirm", mgr["detail"])

    def test_manager_app_with_failed_su_check_stays_unknown(self):
        apps = {"com.a": _app(), "me.bmax.apatch": _app()}
        found = sa.check_device(facts_from(fail=("for p in",), apps=apps))
        self.assertEqual(by_key(found, "root")[0]["title"], "Couldn't fully check for root")
        self.assertEqual(len(by_key(found, "root-manager")), 1)

    def test_su_program_is_positive_evidence(self):
        found = sa.check_device(facts_from({"for p in": "/system/xbin/su\n" + sa.SU_SENTINEL + "\n"}))
        root = by_key(found, "root")[0]
        self.assertEqual(root["level"], sa.WARN)
        self.assertIn("su program", root["title"])
        self.assertIn("does not establish that root access currently works", root["detail"])
        self.assertIn("/system/xbin/su", root["tech"])
        self.assertEqual(by_key(found, "root-manager"), [])

    def test_no_root_wording_is_honest(self):
        f = by_key(sa.check_device(facts_from()), "root")
        self.assertEqual((f[0]["level"], f[0]["title"]), (sa.OK, "No common signs of root"))
        self.assertIn("can still be hidden", f[0]["detail"])

    def test_selinux_patch_proxy_unread(self):
        found = sa.check_device(facts_from(fail=("getenforce", "security_patch", "http_proxy")))
        self.assertEqual(by_key(found, "selinux")[0]["title"], "Couldn't check SELinux protection")
        self.assertEqual(by_key(found, "patch")[0]["title"], "Couldn't read the security patch level")
        self.assertEqual(len(by_key(found, "proxy-unread")), 1)

    def test_access_unread_never_ok(self):
        facts = facts_from(fail=("enabled_accessibility_services",))
        f = sa.check_access(facts, sa.access_lists(facts), set(), None)
        self.assertEqual([x["key"] for x in f], ["access:unread"])
        self.assertIn("Accessibility", f[0]["detail"])

    def test_usage_unread_never_ok(self):
        facts = facts_from(fail=("dumpsys appops",))
        f = sa.check_usage(facts, set(), None)
        self.assertEqual([x["key"] for x in f], ["usage:unread"])

    def test_all_good_still_ok(self):
        facts = facts_from()
        self.assertEqual([x["key"] for x in sa.check_access(facts, sa.access_lists(facts), set(), None)],
                         ["access:none"])
        self.assertEqual([x["key"] for x in sa.check_usage(facts, set(), None)], ["usage:none"])


class SnapshotUnknownTests(unittest.TestCase):
    def snap(self, facts, prev=None):
        return sa.build_snapshot("S", facts, sa.access_lists(facts), set(), {}, prev=prev)

    def changes(self, a, b, prefix):
        return [f for f in sa.compare_snapshots(a, b, None) if f["key"].startswith(prefix)]

    def test_manager_app_appearing_is_not_a_root_transition(self):
        s1 = self.snap(facts_from())
        s2 = self.snap(facts_from(apps={"com.a": _app(), "com.topjohnwu.magisk": _app()}), prev=s1)
        self.assertIs(s2["device"]["root"], False)                   # su checked, none found
        self.assertEqual(s2["device"]["root_apps"], ["com.topjohnwu.magisk"])
        self.assertEqual([f["key"] for f in self.changes(s1, s2, "changes:root")],
                         ["changes:root-app:com.topjohnwu.magisk"])   # manager change, NOT "rooted"

    def test_su_appearing_is_a_root_transition(self):
        s1 = self.snap(facts_from())
        s2 = self.snap(facts_from({"for p in": "/system/bin/su\n" + sa.SU_SENTINEL + "\n"}), prev=s1)
        self.assertIs(s2["device"]["root"], True)
        f = self.changes(s1, s2, "changes:root")
        self.assertEqual([x["key"] for x in f], ["changes:root"])
        self.assertEqual(f[0]["level"], sa.BAD)

    def test_old_snapshot_without_root_apps_no_manager_alarm(self):
        s1 = self.snap(facts_from())
        del s1["device"]["root_apps"]                                 # pre-round-9 snapshot
        s2 = self.snap(facts_from(apps={"com.a": _app(), "com.topjohnwu.magisk": _app()}), prev=s1)
        self.assertEqual(self.changes(s1, s2, "changes:root"), [])

    def test_unknown_root_never_becomes_rooted_alarm(self):
        s1 = self.snap(facts_from(fail=("for p in",)))          # first check: su check failed
        self.assertIsNone(s1["device"]["root"])
        s2 = self.snap(facts_from({"for p in": "/system/bin/su\n" + sa.SU_SENTINEL + "\n"}), prev=s1)
        self.assertIs(s2["device"]["root"], True)
        self.assertEqual(self.changes(s1, s2, "changes:root"), [])   # never known "not rooted"

    def test_manager_app_with_failed_su_keeps_unknown_in_snapshot(self):
        s1 = self.snap(facts_from(fail=("for p in",), apps={"com.a": _app(), "com.topjohnwu.magisk": _app()}))
        self.assertIsNone(s1["device"]["root"])                  # never upgraded by the manager app
        self.assertEqual(s1["device"]["root_apps"], ["com.topjohnwu.magisk"])

    def test_failed_root_check_keeps_known_value(self):
        s1 = self.snap(facts_from())
        s2 = self.snap(facts_from(fail=("for p in",)), prev=s1)
        self.assertIs(s2["device"]["root"], False)
        self.assertIn("root", s2["device"]["unverified"])

    def test_failed_access_read_no_false_alarm_next_time(self):
        acc = {"enabled_accessibility_services": "com.x/.Svc"}
        s1 = self.snap(facts_from(acc))
        s2 = self.snap(facts_from(fail=("enabled_accessibility_services",)), prev=s1)
        self.assertEqual(s2["access"]["accessibility"], ["com.x"])
        self.assertIn("accessibility", s2["access_unverified"])
        s3 = self.snap(facts_from(acc), prev=s2)
        self.assertEqual(self.changes(s2, s3, "changes:access:"), [])

    def test_real_access_change_across_failed_read_still_caught(self):
        s1 = self.snap(facts_from())
        s2 = self.snap(facts_from(fail=("enabled_accessibility_services",)), prev=s1)
        s3 = self.snap(facts_from({"enabled_accessibility_services": "com.spy/.Svc"}), prev=s2)
        self.assertEqual(len(self.changes(s2, s3, "changes:access:accessibility:com.spy")), 1)

    def test_selinux_change_across_failed_read_still_caught(self):
        s1 = self.snap(facts_from({"getenforce": "Enforcing"}))
        s2 = self.snap(facts_from(fail=("getenforce",)), prev=s1)
        self.assertEqual(s2["device"]["selinux"], "Enforcing")
        s3 = self.snap(facts_from({"getenforce": "Permissive"}), prev=s2)
        self.assertEqual(len(self.changes(s2, s3, "changes:selinux")), 1)


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class CheckupShellFailureTests(_DeepScanHarness, unittest.TestCase):
    """Real SecurityTab._do_check: a command with a non-zero exit code must come
    out as 'couldn't check', not as an all-clear."""

    def test_nonzero_exit_becomes_couldnt_check(self):
        def shell(serial, cmd, timeout=60):
            if cmd.startswith("getenforce") or cmd.startswith("dumpsys appops"):
                return 1, "", "/system/bin/sh: getenforce: Permission denied"
            if sa.SU_SENTINEL in cmd:
                return 0, sa.SU_SENTINEL + "\n", ""
            return 0, "", ""
        with mock.patch.object(am, "adb_shell", side_effect=shell), \
                mock.patch.object(am, "read_sockets", return_value=([], [])), \
                mock.patch.object(sa, "launcher_packages", return_value=({"com.a"}, "t")):
            res = self.tab._do_check("SER", False, self.cfg, {"com.a": _app()})
        keys = {f["key"]: f for f in res["findings"]}
        self.assertEqual(keys["selinux"]["title"], "Couldn't check SELinux protection")
        self.assertIn("usage:unread", keys)
        self.assertNotIn("usage:none", keys)
        self.assertEqual(keys["root"]["title"], "No common signs of root")   # su check DID complete



# ==========================================================================
# Round 12 - E-14 part 2: UDP state, prefix boundaries, dead rooting store,
#            evidence-gated rooting advice
# ==========================================================================

import app_knowledge as kb   # noqa: E402


def proc_line(lip, lport, rip, rport, st, uid=10100, inode=123):
    """One /proc/net line. IPs as dotted v4, ports as int."""
    def hx(ip):
        return "".join("%02X" % int(b) for b in reversed(ip.split(".")))
    return ("0: %s:%04X %s:%04X %s 00000000:00000000 00:00000000 00000000 %d 0 %d 1"
            % (hx(lip), lport, hx(rip), rport, st, uid, inode))


def proc_text(tcp=(), udp=(), portrange=None):
    out = ["==tcp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid"]
    out += [proc_line(*x) for x in tcp]
    out += ["==udp", "  sl  local_address rem_address   st"]
    out += [proc_line(*x) for x in udp]
    if portrange is not None:
        out += ["==portrange", portrange]
    return "\n".join(out) + "\n"


class UdpStateTests(unittest.TestCase):
    def kinds(self, text):
        socks, _ = am.parse_proc_net(text)
        return {(x["proto"], x["local_port"]): (x["kind"], x["state"]) for x in socks}

    def test_udp_fixed_port_is_open_temporary_port_is_client(self):
        k = self.kinds(proc_text(udp=[("0.0.0.0", 5353, "0.0.0.0", 0, "07"),
                                       ("0.0.0.0", 45000, "0.0.0.0", 0, "07"),
                                       ("10.0.0.5", 41000, "8.8.8.8", 53, "01")]))
        self.assertEqual(k[("udp", 5353)], ("listen", "OPEN"))
        self.assertEqual(k[("udp", 45000)], ("udp_temp", "TEMPORARY"))   # was "listen" before
        self.assertEqual(k[("udp", 41000)], ("connected", "CONNECTED"))

    def test_device_port_range_is_used(self):
        text = proc_text(udp=[("0.0.0.0", 35000, "0.0.0.0", 0, "07"),
                              ("0.0.0.0", 45000, "0.0.0.0", 0, "07")], portrange="40000\t50000")
        k = self.kinds(text)
        self.assertEqual(k[("udp", 35000)][0], "listen")      # outside the device's temp range
        self.assertEqual(k[("udp", 45000)][0], "udp_temp")
        socks, _ = am.parse_proc_net(text)
        self.assertEqual(socks[0]["eph_range"], "40000-50000")

    def test_bad_port_range_falls_back_to_default(self):
        socks, _ = am.parse_proc_net(proc_text(udp=[("0.0.0.0", 45000, "0.0.0.0", 0, "07")],
                                               portrange="cat: Permission denied"))
        self.assertEqual(socks[0]["kind"], "udp_temp")
        self.assertIn("(default)", socks[0]["eph_range"])

    def test_tcp_unchanged(self):
        k = self.kinds(proc_text(tcp=[("0.0.0.0", 8080, "0.0.0.0", 0, "0A"),
                                       ("10.0.0.5", 50000, "1.2.3.4", 443, "01"),
                                       ("10.0.0.5", 50001, "1.2.3.4", 443, "07")]))
        self.assertEqual(k[("tcp", 8080)][0], "listen")
        self.assertEqual(k[("tcp", 50000)][0], "connected")
        self.assertEqual(k[("tcp", 50001)][0], "other")       # TCP 07 is a closed TCP socket


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class NetworkTabUdpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()
        args = mock.Mock(serial=None, local=TMP_HOME, remote="/sdcard")
        with mock.patch.object(am.App, "scan_devices", lambda self, *a, **k: None):
            cls.app = am.App(cls.root, args)
        cls.net = next(v for v in vars(cls.app).values() if isinstance(v, am.NetworkTab))

    @classmethod
    def tearDownClass(cls):
        destroy_root(cls.root)

    def socks(self):
        s, _ = am.parse_proc_net(proc_text(udp=[("0.0.0.0", 5353, "0.0.0.0", 0, "07"),
                                                 ("0.0.0.0", 45000, "0.0.0.0", 0, "07")]))
        return s

    def test_temp_udp_not_an_open_port(self):
        n = self.net
        temp = [x for x in self.socks() if x["kind"] == "udp_temp"][0]
        self.assertFalse(n.wanted(temp, "Open ports"))
        self.assertFalse(n.wanted(temp, "Open ports reachable from the network"))
        self.assertFalse(n.wanted(temp, "All connections"))
        self.assertTrue(n.wanted(temp, "Everything (incl. closing)"))
        self.assertEqual(n.risk(temp), "")
        self.assertIn("Temporary UDP socket", n.sock_text(temp))
        self.assertIn("likely client side", n.sock_text(temp))      # heuristic, not certainty

    def test_temp_udp_raises_no_new_port_alert(self):
        n = self.net
        n.serial, n.prev_listen, n.busy = "SER", set(), True
        with mock.patch.object(self.app, "error") as err, mock.patch.object(self.app, "info"), \
                mock.patch.object(n, "populate"), mock.patch.object(n, "render"):
            n._done("SER", [x for x in self.socks() if x["kind"] == "udp_temp"], [], None, True)
        err.assert_not_called()
        with mock.patch.object(self.app, "error") as err, mock.patch.object(self.app, "info"), \
                mock.patch.object(n, "populate"), mock.patch.object(n, "render"):
            n._done("SER", self.socks(), [], None, True)            # the fixed port IS new
        self.assertEqual(err.call_count, 1)
        self.assertIn("UDP 5353", err.call_args[0][0])


class PrefixBoundaryTests(unittest.TestCase):
    def test_prefix_matches(self):
        self.assertTrue(kb.prefix_matches("com.android.networkstack", "com.android.networkstack"))
        self.assertTrue(kb.prefix_matches("com.android.networkstack.tethering", "com.android.networkstack"))
        self.assertFalse(kb.prefix_matches("com.android.networkstackhelper", "com.android.networkstack"))
        self.assertTrue(kb.prefix_matches("com.android.theme.font.x", "com.android.theme."))
        self.assertFalse(kb.prefix_matches("com.android.themepicker", "com.android.theme."))

    def test_lookup_respects_boundaries(self):
        self.assertIsNone(kb.lookup("com.android.networkstackhelper"))
        self.assertEqual(kb.lookup("com.android.networkstack.tethering")["risk"], kb.CRITICAL)

    def test_every_rule_respects_boundaries(self):
        for prefix, *_ in kb.PREFIX_RULES:
            base = prefix.rstrip(".")
            self.assertFalse(kb.prefix_matches(base + "zzimpostor", prefix), prefix)
            self.assertTrue(kb.prefix_matches(base + ".child", prefix), prefix)


class DeadRootStoreTests(unittest.TestCase):
    def test_duplicate_rooting_store_removed(self):
        for name in ("root_db_load", "root_db_get", "root_db_put", "root_db_delete", "_root_db_save",
                     "ROOT_DB_FILE", "root_info_for_db", "info_build"):
            self.assertFalse(hasattr(ai, name), name)
        self.assertTrue(callable(ai.research_rooting))      # the part the app uses stays
        for name in ("rooting_db_get", "rooting_db_put", "rooting_db_delete"):   # the real store
            self.assertTrue(callable(getattr(sa, name)), name)


class RootingGuidanceTests(unittest.TestCase):
    def guide(self, codename="", platform="", maker="", soc_maker="", boot="LOCKED"):
        props = {"ro.board.platform": platform}
        if soc_maker:
            props["ro.soc.manufacturer"] = soc_maker
        info = {"codename": codename, "props": props, "bootloader": boot,
                "is_xiaomi": maker == "xiaomi", "arb": False}
        lines, links = sa.rooting_guidance(info)
        return " ".join(t for _, t in lines), links

    def test_known_device_with_matching_chip(self):
        text, links = self.guide("serenity", "ums9230", "xiaomi")
        self.assertIn("codename and chip both match", text)
        self.assertIn("CVE-2022-38694", text)
        self.assertIn("run on Windows", text)

    def test_known_codename_wrong_chip_not_asserted(self):
        text, links = self.guide("serenity", "mt6765", "xiaomi")
        self.assertIn("may NOT apply", text)
        self.assertNotIn("CVE-2022-38694", text)
        self.assertNotIn("Windows", text)
        self.assertFalse(any("CVE" in t for t, _ in links))

    def test_unlisted_unisoc_is_check_not_claim(self):
        text, _ = self.guide("someunisoc", "ums512")
        self.assertIn("whether it applies to THIS chip isn't known", text)
        self.assertNotIn("usually needs", text)
        self.assertNotIn("Windows", text)

    def test_unlisted_unisoc_xiaomi_links_official_route_and_os(self):
        text, links = self.guide("unknownredmi", "ums512", "xiaomi")
        self.assertIn("Mi Unlock tool (Windows)", text)
        self.assertIn("try that official route first", text)
        self.assertIn("run on Windows", text)                      # closing PC requirement
        self.assertEqual(links[0], ("Xiaomi Mi Unlock (official) - try this first",
                                    "https://en.miui.com/unlock/"))  # official route listed first
        self.assertIn("whether it applies to THIS chip isn't known", text)   # CVE stays a "check"

    def test_generic_device_never_mentions_windows(self):
        text, _ = self.guide("generic", "msm8953")
        self.assertNotIn("Windows", text)
        self.assertNotIn("CVE", text)

    def test_xiaomi_official_route_names_windows(self):
        text, _ = self.guide("lavender", "sdm660", "xiaomi")
        self.assertIn("Mi Unlock tool (Windows)", text)
        self.assertIn("run on Windows", text)

    def test_unisoc_detection_is_token_based(self):
        # 'ums' appears INSIDE these words but they don't start with it -> not Unisoc
        self.assertFalse(sa.is_unisoc_chip({"props": {"ro.board.platform": "drums"}}))
        self.assertFalse(sa.is_unisoc_chip({"props": {"ro.board.platform": "mt6100"}}))   # contains 't610'
        self.assertTrue(sa.is_unisoc_chip({"props": {"ro.board.platform": "t610"}}))
        self.assertTrue(sa.is_unisoc_chip({"props": {"ro.board.platform": "ums9230"}}))
        self.assertTrue(sa.is_unisoc_chip({"props": {"ro.soc.manufacturer": "Unisoc"}}))



# ==========================================================================
# Round 14 - APK static inspector, phase 1a (engine)
# ==========================================================================
#
# Real-APK tests need (a) Androguard in the inspector's venv - found via
# $ADBM_INSPECTOR_PYTHON or ~/.local/share/adb_manager/inspector-venv - and
# (b) sample APKs, downloaded once from Androguard's own test suite at a pinned
# commit, checked against pinned SHA-256s and cached in
# ~/.cache/adb_manager-test-samples ($ADBM_TEST_SAMPLES). Without either, those
# tests are SKIPPED (never failed); everything else runs without them.

import io                     # noqa: E402
import zipfile as _zipfile    # noqa: E402

AG_COMMIT = "d594fd39beb934e438a5bf8089b206d5800d81e0"      # androguard v4.1.4
SAMPLES = {
    "com.teleca.jamendo_35.apk": "44e880a1e6c64a5a273fcdb568054bc298669377e60302f0b97ccd13ffb33b6d",
    "multidex.apk": "b91263e9232c35a01a001b4e7dfb7094494b075c243308d768ff2a459754e79b",
}


def inspector_python():
    for py in (os.environ.get("ADBM_INSPECTOR_PYTHON"),
               os.path.join(_REAL_HOME, ".local", "share", "adb_manager", "inspector-venv", "bin", "python")):
        if py and os.path.exists(py) and sa._probe_androguard(py):
            return py
    return None


_SAMPLE_CACHE = {}


def sample(name):
    """Path to a pinned sample APK, downloading it once; None if unavailable."""
    if name in _SAMPLE_CACHE:
        return _SAMPLE_CACHE[name]
    d = os.environ.get("ADBM_TEST_SAMPLES") or os.path.join(_REAL_HOME, ".cache", "adb_manager-test-samples")
    path = os.path.join(d, name)
    def digest(p):
        with open(p, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    if not (os.path.exists(path) and digest(path) == SAMPLES[name]):
        try:
            os.makedirs(d, exist_ok=True)
            url = "https://raw.githubusercontent.com/androguard/androguard/%s/tests/data/APK/%s" % (AG_COMMIT, name)
            import urllib.request
            data = urllib.request.urlopen(url, timeout=60).read()
            if hashlib.sha256(data).hexdigest() != SAMPLES[name]:
                raise ValueError("checksum mismatch")
            with open(path + ".part", "wb") as f:
                f.write(data)
            os.replace(path + ".part", path)
        except Exception:
            path = None
    _SAMPLE_CACHE[name] = path
    return path


def make_zip(path, entries, mode=_zipfile.ZIP_DEFLATED):
    with _zipfile.ZipFile(path, "w", mode) as z:
        for n, data in entries:
            if isinstance(n, _zipfile.ZipInfo):
                z.writestr(n, data)
            else:
                z.writestr(n, data)
    return path


LIM = sa.inspector_limits(1 << 20, 1 << 18, {"inspector_mode": "quick"})


class InspectorLimitsTests(unittest.TestCase):
    def test_scales_with_ram_and_overrides(self):
        with mock.patch("os.sysconf", side_effect=lambda k: {"SC_PAGE_SIZE": 4096,
                                                             "SC_PHYS_PAGES": (2 << 30) // 4096}[k]):
            small = sa.inspector_limits(50 << 20, 40 << 20)
        with mock.patch("os.sysconf", side_effect=lambda k: {"SC_PAGE_SIZE": 4096,
                                                             "SC_PHYS_PAGES": (32 << 30) // 4096}[k]):
            big = sa.inspector_limits(50 << 20, 40 << 20)
        self.assertLess(small["mem_bytes"], big["mem_bytes"])
        self.assertEqual(small["mode"], "quick")          # 40 MB of code won't fit full on 2 GB
        self.assertEqual(big["mode"], "full")
        o = sa.inspector_limits(1, 1, {"inspector_mem_mb": 777, "inspector_timeout_s": 42, "inspector_mode": "quick"})
        self.assertEqual((o["mem_bytes"], o["timeout_s"], o["mode"]), (777 << 20, 42, "quick"))

    def test_slower_machines_get_more_time(self):
        with mock.patch("os.cpu_count", return_value=1):
            one = sa.inspector_limits(10 << 20, 5 << 20)["timeout_s"]
        with mock.patch("os.cpu_count", return_value=8):
            many = sa.inspector_limits(10 << 20, 5 << 20)["timeout_s"]
        self.assertGreater(one, many)


class InspectorEnvTests(unittest.TestCase):
    def test_missing_androguard_gives_install_help(self):
        with mock.patch.object(sa, "_probe_androguard", return_value=None), \
                mock.patch("shutil.which", return_value="/usr/bin/readelf"):
            env = sa.inspector_env({})
        self.assertFalse(env["ok"])
        self.assertIn("python3 -m venv", env["help"])
        self.assertIn("androguard==%s" % sa.INSPECT_ANDROGUARD, env["help"])
        self.assertIn("python3-venv", env["help"])            # distro-neutral, Debian named
        self.assertIn("Fedora", env["help"])

    def test_missing_readelf_and_version_mismatch_reported(self):
        with mock.patch.object(sa, "_probe_androguard", return_value={"androguard": "3.3.5", "python": "3.11.2"}), \
                mock.patch("shutil.which", return_value=None):
            env = sa.inspector_env({"inspector_python": sys.executable})
        self.assertTrue(env["ok"])
        self.assertTrue(any("readelf" in p for p in env["problems"]))
        self.assertTrue(any("3.3.5" in p for p in env["problems"]))


class ContainerCheckTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def p(self, name):
        return os.path.join(self.d, name)

    def test_normal_apk_lists_parts(self):
        make_zip(self.p("a.apk"), [("AndroidManifest.xml", b"x"), ("classes.dex", b"d"), ("classes2.dex", b"d"),
                                   ("lib/arm64-v8a/libx.so", b"e"), ("assets/c.json", b"{}")])
        c = sa.apk_container_check(self.p("a.apk"), LIM)
        self.assertTrue(c["ok"])
        self.assertEqual(c["dex"], ["classes.dex", "classes2.dex"])
        self.assertEqual(c["native"], ["lib/arm64-v8a/libx.so"])
        self.assertEqual(c["problems"], [])

    def test_unsafe_names_symlinks_duplicates_flagged(self):
        link = _zipfile.ZipInfo("assets/link")
        link.external_attr = (0o120777 << 16)
        with warnings_off():
            make_zip(self.p("b.apk"), [("../../etc/evil", b"x"), ("/abs", b"x"), ("a\\b", b"x"), (link, b"/etc"),
                                       ("classes.dex", b"1"), ("classes.dex", b"2")])
        c = sa.apk_container_check(self.p("b.apk"), LIM)
        text = " ".join(t for _, t in c["problems"])
        for word in ("unsafe file name", "symbolic link", "same name appears twice"):
            self.assertIn(word, text)
        self.assertTrue(c["ok"])                          # warnings: analysis still goes on

    def test_bomb_and_too_many_entries_are_fatal(self):
        make_zip(self.p("bomb.apk"), [("classes.dex", b"\0" * (8 << 20))])
        self.assertFalse(sa.apk_container_check(self.p("bomb.apk"), LIM)["ok"])
        make_zip(self.p("many.apk"), [("f%d" % i, b"") for i in range(30)])
        self.assertFalse(sa.apk_container_check(self.p("many.apk"), dict(LIM, max_entries=10))["ok"])

    def test_not_a_zip_is_fatal(self):
        write(self.p("junk.apk"), "this is not an apk")
        c = sa.apk_container_check(self.p("junk.apk"), LIM)
        self.assertFalse(c["ok"])
        self.assertIn("not a readable", c["problems"][0][1])

    def test_read_member_capped(self):
        make_zip(self.p("c.apk"), [("big", b"a" * 5000)])
        with _zipfile.ZipFile(self.p("c.apk")) as z:
            self.assertEqual(len(sa.read_member_capped(z, "big", 6000)), 5000)
            with self.assertRaises(ValueError):
                sa.read_member_capped(z, "big", 1000)


class _NoWarn:
    def __enter__(self):
        import warnings
        self.c = warnings.catch_warnings()
        self.c.__enter__()
        warnings.simplefilter("ignore")

    def __exit__(self, *a):
        self.c.__exit__(*a)


def warnings_off():
    return _NoWarn()


class EndpointExtractionTests(unittest.TestCase):
    def ex(self, text, pkgs=()):
        return [(e["kind"], e["value"]) for e in sa.extract_endpoints(text, pkgs)]

    def test_urls_ips_hosts(self):
        self.assertEqual(self.ex("see https://api.example.com/v1/x)."), [("url", "https://api.example.com/v1/x")])
        self.assertEqual(self.ex("connect 8.8.4.4:853 now"), [("ip", "8.8.4.4:853")])
        self.assertEqual(self.ex("cdn.example-cdn.xyz"), [("host", "cdn.example-cdn.xyz")])
        self.assertEqual(self.ex("wss://push.example.io/ws"), [("url", "wss://push.example.io/ws")])

    def test_package_names_are_not_hosts(self):
        self.assertEqual(self.ex("android.intent.action.VIEW"), [])
        self.assertEqual(self.ex("com.google.android.gms.ads"), [])
        self.assertEqual(self.ex("java.io"), [])
        self.assertEqual(self.ex("okhttp3.internal.io", pkgs={"okhttp3.internal.io"}), [])

    def test_constructed_and_url_host_not_duplicated(self):
        e = sa.extract_endpoints("http://www.example.com/track/%d")
        self.assertEqual(len(e), 1)
        self.assertTrue(e[0]["constructed"])
        self.assertEqual(e[0]["host"], "www.example.com")
        self.assertFalse(sa.extract_endpoints("https://example.com/fixed/page.html")[0]["constructed"])

    def test_invalid_ip_ignored(self):
        self.assertEqual(self.ex("999.1.1.1"), [])

    def test_registrable_domain(self):
        self.assertEqual(sa.registrable_domain("api.eu.example.co.uk"), "example.co.uk")
        self.assertEqual(sa.registrable_domain("a.b.example.com"), "example.com")


class EndpointClassificationTests(unittest.TestCase):
    SIGS = sa.inspector_signatures()

    def cls(self, value, sources=("dex",), owner=None, sdks=(), package="com.example.app", bad=()):
        e = sa.extract_endpoints(value)[0]
        e["locations"] = [{"source": s, "owner": owner} for s in sources]
        return sa.classify_endpoint(e, {"package": package, "signatures": self.SIGS,
                                        "sdks_present": set(sdks), "bad_hosts": set(bad)})

    def test_loopback_and_lan(self):
        self.assertEqual(self.cls("http://127.0.0.1:8080/x")["classification"], "expected")
        r = self.cls("http://192.168.1.10/x")
        self.assertEqual(r["classification"], "unknown")
        self.assertEqual(r["issues"], [])                 # LAN http isn't flagged as interceptable internet

    def test_sdk_endpoint_expected_only_when_sdk_code_present(self):
        with_code = self.cls("https://t.appsflyer.com/api", sdks=("AppsFlyer",))
        self.assertEqual((with_code["classification"], with_code["owner"]), ("expected", "AppsFlyer"))
        without = self.cls("https://t.appsflyer.com/api")
        self.assertNotEqual(without["classification"], "expected")
        self.assertTrue(any("wasn't found" in x for x in without["evidence"]))

    def test_big_company_domain_not_expected_by_itself(self):
        self.assertEqual(self.cls("https://www.google.com/search")["classification"], "unknown")

    def test_unfamiliar_domain_not_suspicious_by_itself(self):
        self.assertEqual(self.cls("https://api.some-unknown-startup.io/v2")["classification"], "unknown")

    def test_suspicious_reasons(self):
        r = self.cls("http://1.2.3.4:4444/gate", sources=("native",))
        self.assertEqual((r["classification"], r["confidence"]), ("suspicious", "medium"))
        joined = " ".join(r["evidence"])
        for word in ("raw internet IP", "unusual port (4444)", "native libraries"):
            self.assertIn(word, joined)
        self.assertTrue(r["issues"])                      # and unencrypted
        bare = self.cls("1.2.3.4")
        self.assertIn("version number", " ".join(bare["evidence"]))

    def test_malicious_only_with_explicit_evidence(self):
        self.assertEqual(self.cls("https://bad.example.net/x", bad={"bad.example.net"})["classification"], "malicious")
        self.assertNotEqual(self.cls("https://bad.example.net/x")["classification"], "malicious")

    def test_developer_domain_hint(self):
        r = self.cls("https://api.jamendo.com/x", package="com.teleca.jamendo")
        self.assertEqual((r["classification"], r["confidence"]), ("expected", "low"))
        self.assertIn("not proof", " ".join(r["evidence"]))

    def test_third_party_owner_from_code_location(self):
        r = self.cls("https://api.some-unknown-startup.io/v2", owner="Facebook SDK")
        self.assertEqual(r["owner"], "Facebook SDK")
        self.assertIn("belongs to Facebook SDK", " ".join(r["evidence"]))

    def test_exodus_signatures_used(self):
        sigs = sa.inspector_signatures([{"name": "TrackCo", "code_signature": "com.trackco.|com.tc.sdk",
                                         "network_signature": "trackco\\.net"}])
        self.assertEqual(sa.sdk_owner("com.trackco.core.X", sigs), ("TrackCo", "Exodus"))
        self.assertEqual(sa.sdk_owner("com.trackcoevil.X", sigs)[0], None)      # namespace boundary
        e = sa.extract_endpoints("https://in.trackco.net/e")[0]
        e["locations"] = [{"source": "dex"}]
        r = sa.classify_endpoint(e, {"package": "p", "signatures": sigs, "sdks_present": {"TrackCo"}})
        self.assertEqual(r["owner"], "TrackCo")


class InspectionSummaryTests(unittest.TestCase):
    def res(self, stages=("done",), eps=(), inds=(), analysed=(True,)):
        return {"stages": [{"id": "s%d" % i, "name": "stage %d" % i, "status": st} for i, st in enumerate(stages)],
                "endpoints": [{"classification": c, "issues": []} for c in eps],
                "indicators": [{"severity": s} for s in inds],
                "parts": [{"analysed": a} for a in analysed], "mode": "full"}

    def test_incomplete_never_ok(self):
        for stages, analysed in ((("done", "partial"), (True,)), (("done", "failed"), (True,)),
                                 (("done", "timeout"), (True,)), (("done",), (True, False))):
            s = sa.summarize_inspection(self.res(stages, analysed=analysed))
            self.assertEqual(s["text"], "Analysis incomplete", (stages, analysed))
            self.assertNotEqual(s["level"], sa.OK)

    def test_never_says_clean(self):
        s = sa.summarize_inspection(self.res())
        self.assertEqual(s["level"], sa.OK)
        self.assertNotIn("clean", s["text"].lower())
        self.assertIn("parts analysed", s["text"])

    def test_suspicious_warns(self):
        self.assertEqual(sa.summarize_inspection(self.res(eps=("suspicious",)))["level"], sa.WARN)
        self.assertEqual(sa.summarize_inspection(self.res(inds=("warn",)))["level"], sa.WARN)

    def test_obfuscation_level(self):
        self.assertGreater(sa.obfuscation_level(["La/a;", "La/b;", "Lb/aB;", "Lcom/x/Main;"]), 0.7)
        self.assertEqual(sa.obfuscation_level(["Lcom/x/MainActivity;", "Lcom/x/Helper;"]), 0.0)


FAKE_WORKERS = {
    "crash": "import sys; sys.exit(3)\n",
    "hang": "import time\nprint('ADBM-PROGRESS {\"stage\": \"code\", \"msg\": \"working\"}', flush=True)\ntime.sleep(60)\n",
    "garbage": ("import json, sys\njob = json.load(open(sys.argv[2]))\n"
                "open(job['result'], 'w').write('not json')\n"),
    "wrongschema": ("import json, sys\njob = json.load(open(sys.argv[2]))\n"
                    "json.dump({'schema': 999}, open(job['result'], 'w'))\n"),
    "memhog": "x = bytearray(3 << 30)\n",
    "ok": ("import json, sys\njob = json.load(open(sys.argv[2]))\n"
           "print('ADBM-PROGRESS {\"stage\": \"code\", \"msg\": \"hello\"}', flush=True)\n"
           "json.dump({'schema': %d, 'package': job['package'], 'mode': job['mode'],"
           " 'parts': [{'name': 'base.apk', 'analysed': True}],"
           " 'stages': [{'id': 'code', 'name': 'reading the code', 'status': 'done'}],"
           " 'endpoints': [], 'indicators': [], 'sdks': [], 'limitations': []}, open(job['result'], 'w'))\n"
           % sa.INSPECT_SCHEMA),
}


class RunInspectionTests(unittest.TestCase):
    """The parent-side runner, against tiny fake workers (no Androguard needed)."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def run_fake(self, kind, limits=None, stop=None, progress=None):
        script = os.path.join(self.d, kind + ".py")
        write(script, FAKE_WORKERS[kind] if kind in FAKE_WORKERS else kind)
        before = set(os.listdir(tempfile.gettempdir()))
        r = sa.run_inspection({"package": "p", "version_code": "1", "parts": [{"name": "base.apk", "path": "x"}]},
                              sys.executable, limits or dict(LIM, timeout_s=20), progress, stop, script=script)
        leftover = [n for n in set(os.listdir(tempfile.gettempdir())) - before if n.startswith("adbm_inspect_")]
        self.assertEqual(leftover, [])                       # private work dir always removed
        return r

    def assert_incomplete(self, r, word):
        self.assertEqual(r["summary"]["text"], "Analysis incomplete")
        self.assertIn(word, r["stages"][0]["detail"])
        self.assertFalse(r["parts"][0]["analysed"])

    def test_ok_worker_and_progress(self):
        got = []
        r = self.run_fake("ok", progress=got.append)
        self.assertEqual(r["summary"]["level"], sa.OK)
        self.assertEqual(got, [{"stage": "code", "msg": "hello"}])

    def test_crash(self):
        self.assert_incomplete(self.run_fake("crash"), "exit 3")

    def test_timeout(self):
        t = time.time()
        r = self.run_fake("hang", limits=dict(LIM, timeout_s=1))
        self.assertLess(time.time() - t, 10)
        self.assertEqual(r["stages"][0]["status"], sa.STAGE_TIMEOUT)
        self.assert_incomplete(r, "longer than")

    def test_stop(self):
        stop = threading.Event()
        threading.Timer(0.5, stop.set).start()
        self.assert_incomplete(self.run_fake("hang", stop=stop), "stopped by you")

    def test_bad_results(self):
        self.assert_incomplete(self.run_fake("garbage"), "no readable result")
        self.assert_incomplete(self.run_fake("wrongschema"), "unexpected format")

    def test_memory_limit_enforced(self):
        r = self.run_fake("memhog", limits=dict(LIM, mem_bytes=512 << 20))
        self.assert_incomplete(r, "memory")

    def test_missing_python(self):
        r = sa.run_inspection({"package": "p", "parts": []}, "/nonexistent/python", LIM)
        self.assertEqual(r["summary"]["text"], "Analysis incomplete")
        self.assertIn("couldn't start", r["stages"][0]["detail"])

    def test_inspection_makes_no_ai_or_network_calls(self):
        """Parent side: nothing AI/network is touched. Worker side: its code
        contains no network or AI calls at all (it runs in another process)."""
        import inspect
        with mock.patch.object(ai, "research") as r1, mock.patch.object(ai, "research_rooting") as r2, \
                mock.patch("urllib.request.urlopen") as net, mock.patch.object(sa, "_http") as http:
            self.run_fake("ok")
        for m in (r1, r2, net, http):
            m.assert_not_called()
        src = "".join(inspect.getsource(f) for f in (
            sa._inspect_worker, sa.apk_container_check, sa.extract_endpoints, sa.classify_endpoint,
            sa.inspector_signatures, sa.summarize_inspection))
        for word in ("urlopen", "_http(", "ai_research", "anthropic", "openai", "virustotal", "malwarebazaar"):
            self.assertNotIn(word, src)


@unittest.skipUnless(inspector_python(), "Androguard not installed for the inspector")
class RealApkInspectionTests(unittest.TestCase):
    """Real Androguard on real sample APKs."""

    @classmethod
    def setUpClass(cls):
        cls.py = inspector_python()
        cls.jam = sample("com.teleca.jamendo_35.apk")
        cls.d = tempfile.mkdtemp()
        cls.full = cls.run_parts([("base.apk", "base", cls.jam)], "com.teleca.jamendo", "full") if cls.jam else None

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, True)

    @classmethod
    def run_parts(cls, parts, pkg, mode="full", env=None):
        lim = sa.inspector_limits(1 << 20, 1 << 18, {"inspector_mode": mode})
        job = {"package": pkg, "version_code": "1", "signatures": sa.inspector_signatures(),
               "parts": [{"name": n, "kind": k, "path": p} for n, k, p in parts]}
        if env:
            with mock.patch.object(sa, "_worker_env", return_value=env):
                return sa.run_inspection(job, cls.py, lim)
        return sa.run_inspection(job, cls.py, lim)

    def need(self, *paths):
        if not all(paths):
            self.skipTest("sample APK not available (offline?)")

    def ep(self, res, value):
        return next(e for e in res["endpoints"] if e["value"] == value)

    def test_hardcoded_endpoints_traced_to_code(self):
        self.need(self.jam)
        r = self.full
        self.assertEqual(r["summary"]["text"], "No suspicious indicators found in the parts analysed")
        e = self.ep(r, "http://api.jamendo.com/get2/")
        self.assertEqual(e["locations"][0]["cls"], "com.teleca.jamendo.api.impl.JamendoGet2ApiImpl")
        self.assertTrue(e["locations"][0]["own_code"])
        self.assertTrue(e["issues"])                                   # plain http
        self.assertEqual(e["classification"], "expected")              # developer-domain hint
        self.assertIn("HTTP (java.net)", [a["api"] for a in r["network_apis"]])

    def test_dynamic_construction_indicator(self):
        self.need(self.jam)
        e = self.ep(self.full, "http://www.jamendo.com/track/%d")
        self.assertTrue(e["constructed"])
        self.assertIn("filled in while the app runs", " ".join(e["evidence"]))

    def test_quick_mode_lists_file_not_class(self):
        self.need(self.jam)
        r = self.run_parts([("base.apk", "base", self.jam)], "com.teleca.jamendo", "quick")
        e = self.ep(r, "http://api.jamendo.com/get2/")
        self.assertIsNone(e["locations"][0]["cls"])
        self.assertEqual(e["locations"][0]["file"], "classes.dex")
        self.assertTrue(any("quick mode" in x for x in r["limitations"]))

    def test_multiple_dex_files(self):
        md = sample("multidex.apk")
        self.need(md)
        r = self.run_parts([("base.apk", "base", md)], "")
        self.assertEqual(r["parts"][0]["dex"], ["classes.dex", "classes2.dex"])
        self.assertTrue(r["parts"][0]["analysed"])

    def test_malformed_apks_are_incomplete_not_clean(self):
        trunc = os.path.join(self.d, "trunc.apk")
        self.need(self.jam)
        with open(self.jam, "rb") as f:
            data = f.read()
        with open(trunc, "wb") as f:
            f.write(data[: len(data) // 3])
        junk = os.path.join(self.d, "junk.apk")
        with open(junk, "wb") as f:
            f.write(os.urandom(4096))
        for path in (trunc, junk):
            r = self.run_parts([("base.apk", "base", path)], "x")
            self.assertEqual(r["summary"]["text"], "Analysis incomplete", path)
            self.assertFalse(r["parts"][0]["analysed"])

    @unittest.skipUnless(shutil.which("gcc"), "gcc not installed (needed to build a test native library)")
    def test_split_with_native_library(self):
        self.need(self.jam)
        c = os.path.join(self.d, "net.c")
        write(c, '#include <sys/socket.h>\n#include <netdb.h>\n#include <string.h>\n'
                 'const char *adbm_c2 = "http://1.2.3.4:4444/gate";\n'
                 'const char *adbm_cdn = "updates.example-cdn.xyz";\n'
                 'const char *adbm_v6 = "2a00:1450:4001:82a::200e";\n'
                 'int f(void){struct addrinfo *r=0; if(getaddrinfo(adbm_cdn,"443",0,&r)) return -1;'
                 'int s=socket(AF_INET,SOCK_STREAM,0); connect(s,r->ai_addr,r->ai_addrlen);'
                 'return (int)strlen(adbm_c2);}\n')
        so = os.path.join(self.d, "libnet.so")
        subprocess.run(["gcc", "-shared", "-fPIC", "-O1", "-o", so, c], check=True)
        with open(so, "rb") as f:
            lib = f.read()
        split = make_zip(os.path.join(self.d, "split_config.x86_64.apk"),
                         [("AndroidManifest.xml", b""), ("lib/x86_64/libnet.so", lib)])
        r = self.run_parts([("base.apk", "base", self.jam), ("split_config.x86_64.apk", "config", split)],
                           "com.teleca.jamendo")
        self.assertEqual([p["analysed"] for p in r["parts"]], [True, True])
        e = self.ep(r, "http://1.2.3.4:4444/gate")
        self.assertEqual(e["classification"], "suspicious")
        self.assertEqual(e["locations"][0]["part"], "split_config.x86_64.apk")
        self.assertEqual(e["locations"][0]["source"], "native")
        v6 = self.ep(r, "2a00:1450:4001:82a::200e")                    # bare IPv6 inside native code
        self.assertEqual((v6["classification"], v6["locations"][0]["source"]), ("suspicious", "native"))
        if shutil.which("readelf"):
            n = next(i for i in r["indicators"] if i["id"] == "native_network")
            self.assertIn("getaddrinfo", n["detail"])
        self.assertEqual(r["summary"]["level"], sa.WARN)

    @unittest.skipUnless(shutil.which("gcc"), "gcc not installed (needed to build a test native library)")
    def test_missing_readelf_makes_native_stage_partial(self):
        self.need(self.jam)
        so = os.path.join(self.d, "libx.so")
        c = os.path.join(self.d, "x.c")
        write(c, 'const char *u = "https://x.example.com/a"; int g(void){return 1;}\n')
        subprocess.run(["gcc", "-shared", "-fPIC", "-o", so, c], check=True)
        with open(so, "rb") as f:
            lib = f.read()
        split = make_zip(os.path.join(self.d, "split_x.apk"), [("lib/x86_64/libx.so", lib)])
        env = dict(sa._worker_env(), PATH="/nonexistent")
        r = self.run_parts([("split_x.apk", "feature", split)], "p", env=env)
        native = next(s for s in r["stages"] if s["id"] == "native")
        self.assertEqual(native["status"], sa.STAGE_PARTIAL)
        self.assertIn("readelf", native["detail"])
        self.assertEqual(r["summary"]["text"], "Analysis incomplete")
        self.assertTrue(any(e["value"] == "https://x.example.com/a" for e in r["endpoints"]))  # strings still scanned



# ==========================================================================
# Round 15 - APK inspector, phase 1b: window, per-identity cache, explicit AI
# ==========================================================================

def _result(level="ok", stages=None, eps=None, inds=None, parts=None, key=None):
    r = {"schema": sa.INSPECT_SCHEMA, "package": "com.x", "version_code": "7", "mode": "full",
         "parts": parts or [{"name": "base.apk", "kind": "base", "analysed": True, "dex": ["classes.dex"]}],
         "stages": stages or [{"id": "code", "name": "reading the code", "status": "done", "detail": ""}],
         "endpoints": eps if eps is not None else [
             {"value": "http://1.2.3.4:4444/gate", "kind": "url", "host": "1.2.3.4", "port": 4444, "scheme": "http",
              "classification": "suspicious", "confidence": "medium", "evidence": ["a raw internet IP address"],
              "issues": ["sent without encryption (http://)"], "owner": None, "constructed": False,
              "locations": [{"part": "base.apk", "source": "dex", "file": "classes.dex", "cls": "com.x.Net",
                             "method": "go", "owner": None, "own_code": True}]},
             {"value": "https://api.x.com/v1", "kind": "url", "host": "api.x.com", "port": None, "scheme": "https",
              "classification": "expected", "confidence": "low", "evidence": ["hint"], "issues": [],
              "owner": None, "constructed": False, "locations": []}],
         "indicators": inds if inds is not None else [
             {"id": "exec", "title": "Can run system commands", "severity": "warn", "detail": "d",
              "confidence": "medium", "locations": []}],
         "sdks": [], "network_apis": [], "limitations": ["static analysis only"],
         "worker_stderr": "SECRET-TRACEBACK /home/user/private/path"}
    if key:
        r["key"] = key
    r["summary"] = sa.summarize_inspection(r)
    return r


class InspectionCacheTests(unittest.TestCase):
    def setUp(self):
        self.p = mock.patch.object(sa, "INSPECT_DIR", tempfile.mkdtemp())
        self.p.start()
        self.addCleanup(lambda: (self.p.stop(), shutil.rmtree(sa.INSPECT_DIR, True)))

    def test_key_is_order_independent_and_needs_hashes(self):
        self.assertEqual(sa.inspection_key("p", "1", ["b", "a"]), sa.inspection_key("p", "1", ["a", "b"]))
        self.assertNotEqual(sa.inspection_key("p", "1", ["a"]), sa.inspection_key("p", "2", ["a"]))
        self.assertIsNone(sa.inspection_key("p", "1", []))
        self.assertIsNone(sa.inspection_key("", "1", ["a"]))

    def test_key_from_identity_only_when_complete(self):
        full = sa.make_app_identity("p", [_part("base.apk"), _part("split_a.apk")])
        part = sa.make_app_identity("p", [_part("base.apk"), _part("split_a.apk", error="x")])
        legacy = {"sha256": "h", "cert": "C", "certs": ["C"]}
        self.assertTrue(sa.inspection_key_from_identity("p", "1", full))
        self.assertIsNone(sa.inspection_key_from_identity("p", "1", part))
        self.assertIsNone(sa.inspection_key_from_identity("p", "1", legacy))

    def test_save_private_and_load_only_exact_key(self):
        k = sa.inspection_key("com.x", "7", ["h1"])
        sa.save_inspection(k, _result())
        path = sa._inspection_path(k)
        self.assertEqual(mode(path), 0o600)
        self.assertEqual(mode(sa.INSPECT_DIR), 0o700)
        self.assertEqual(sa.load_inspection(k)["package"], "com.x")
        self.assertIsNone(sa.load_inspection(sa.inspection_key("com.x", "7", ["h2"])))   # other build
        self.assertIsNone(sa.load_inspection(None))

    def test_damaged_or_foreign_files_ignored(self):
        k = sa.inspection_key("com.x", "7", ["h1"])
        os.makedirs(sa.INSPECT_DIR, exist_ok=True)
        write(sa._inspection_path(k), "{broken")
        self.assertIsNone(sa.load_inspection(k))
        sa.atomic_write_json(sa._inspection_path(k), dict(_result(), key=k, schema=999))
        self.assertIsNone(sa.load_inspection(k))
        sa.atomic_write_json(sa._inspection_path(k), dict(_result(), key="someone|else|h"))
        self.assertIsNone(sa.load_inspection(k))


class FindingAITests(unittest.TestCase):
    def test_context_contains_only_this_finding(self):
        r = _result()
        ep = r["endpoints"][0]
        ctx = sa.finding_context(r, "endpoint", ep, "X App")
        text = json.dumps(ctx)
        self.assertIn("1.2.3.4:4444", text)
        self.assertNotIn("api.x.com", text)                 # other findings stay out
        self.assertNotIn("SECRET-TRACEBACK", text)          # worker output stays out
        self.assertNotIn("classes.dex", text)               # file paths stay out
        self.assertNotIn("Can run system commands", text)
        self.assertEqual(ctx["locations"], [{"part": "base.apk", "source": "dex", "cls": "com.x.Net",
                                             "method": "go"}])
        many = dict(ep, locations=[dict(ep["locations"][0], method="m%d" % i) for i in range(12)])
        self.assertEqual(len(sa.finding_context(r, "endpoint", many)["locations"]), 5)

    def test_finding_ids_stable_and_distinct(self):
        r = _result()
        a, b = (sa.finding_id("endpoint", e) for e in r["endpoints"])
        self.assertNotEqual(a, b)
        self.assertEqual(a, sa.finding_id("endpoint", dict(r["endpoints"][0])))
        self.assertEqual(sa.finding_id("indicator", r["indicators"][0]), "ind:exec")

    def test_request_and_normalize(self):
        r = _result()
        req = ai.build_finding_request(sa.finding_context(r, "endpoint", r["endpoints"][0], "X App"))
        self.assertIn("http://1.2.3.4:4444/gate", req)
        self.assertIn("suspicious", req)
        self.assertIn("com.x.Net", req)
        n = ai.normalize_finding({"summary": " s ", "assessment": "TOTALLY SAFE", "sources": [
            {"title": "ok", "url": "https://a.example"}, {"url": "javascript:alert(1)"}]})
        self.assertEqual(n["assessment"], "unclear")         # unknown labels never become "normal"
        self.assertEqual([x["url"] for x in n["sources"]], ["https://a.example"])
        self.assertEqual(n["who_runs_it"], "unknown")

    def test_explain_finding_never_raises(self):
        with mock.patch.object(ai, "_ask_anthropic", side_effect=RuntimeError("boom")):
            res = ai.explain_finding("anthropic", {}, {"kind": "indicator", "title": "t"})
        self.assertTrue(res["error"])
        with mock.patch.object(ai, "_ask_anthropic", return_value=("not json", {})):
            res = ai.explain_finding("anthropic", {}, {"kind": "indicator", "title": "t"})
        self.assertIn("valid JSON", res["error"])


class ExodusSignatureCacheTests(unittest.TestCase):
    def test_signatures_kept_and_read_offline(self):
        api = {"trackers": {"5": {"name": "TrackCo", "website": "w", "code_signature": "com.trackco.",
                                  "network_signature": "trackco\\.net"}}}
        cfg = {"exodus_url": "https://exodus.example", "exodus_token": "t"}
        with mock.patch.object(sa, "TRACKERS_FILE", os.path.join(tempfile.mkdtemp(), "t.json")):
            self.addCleanup(shutil.rmtree, os.path.dirname(sa.TRACKERS_FILE), True)
            with mock.patch.object(sa, "_http", return_value=api):
                sa.exodus_tracker_names(cfg)
            with mock.patch.object(sa, "_http") as http, mock.patch("urllib.request.urlopen") as net:
                cached = sa.cached_exodus_trackers()
                http.assert_not_called()
                net.assert_not_called()
        self.assertEqual(cached[0]["code_signature"], "com.trackco.")
        sigs = sa.inspector_signatures(cached)
        self.assertEqual(sa.sdk_owner("com.trackco.a.B", sigs), ("TrackCo", "Exodus"))

    def test_old_cache_without_signatures_is_harmless(self):
        sigs = sa.inspector_signatures([{"name": "Old", "website": "w"}])
        self.assertFalse(any(s[0] == "Old" for s in sigs))


class KeepCopiesTests(PmPathsAndReadTests):
    """read_app_identity(keep=True) for the inspector (inherits helpers only)."""

    def test_keep_true_leaves_copies_with_paths(self):
        paths = ["/data/app/x/base.apk", "/data/app/x/split_f.apk"]
        with mock.patch.object(am, "pm_paths", return_value=paths), \
                mock.patch.object(am, "adb_transfer", side_effect=self._fake_pull(fail={"split_f.apk"})):
            i = am.read_app_identity("S", "com.x", self.work, threading.Event(), keep=True)
        self.assertTrue(os.path.exists(i["parts"][0]["local"]))
        self.assertNotIn("local", i["parts"][1])            # unreadable part: no file kept
        self.assertEqual(len(os.listdir(self.work)), 1)


for _n in [n for n in dir(PmPathsAndReadTests) if n.startswith("test_")]:
    setattr(KeepCopiesTests, _n, None)                     # don't re-run the parent's tests here


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class InspectWindowTests(unittest.TestCase):
    ENV_OK = {"ok": True, "python": sys.executable, "problems": [], "help": ""}

    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()
        args = mock.Mock(serial=None, local=TMP_HOME, remote="/sdcard")
        with mock.patch.object(am.App, "scan_devices", lambda self, *a, **k: None):
            cls.app = am.App(cls.root, args)
        cls.tab = cls.app.apps_tab

    @classmethod
    def tearDownClass(cls):
        destroy_root(cls.root)

    def setUp(self):
        shutil.rmtree(sa.INSPECT_DIR, True)
        for f in (sa.IDENTITY_FILE,):
            if os.path.exists(f):
                os.remove(f)
        self.info = {"package": "com.x", "version": "1.0", "version_code": "7", "last_update": "t"}
        self.wins = []
        self.addCleanup(lambda: [w.close() for w in self.wins if w.alive()])

    def pump(self, until=lambda: False, timeout=10.0):
        end = time.time() + timeout
        while time.time() < end:
            try:
                while True:
                    item = self.app.q.get_nowait()
                    if item[0] == "call":
                        item[1](*item[2:])
            except Exception:
                pass
            self.root.update()
            if until():
                return True
            time.sleep(0.02)
        return False

    def open(self, env=None):
        with mock.patch.object(sa, "inspector_env", return_value=env or self.ENV_OK):
            w = am.InspectWindow(self.root, self.app, "SER", "com.x", self.info, "X App")
            self.wins.append(w)
            self.pump(lambda: w.env is not None)
        return w

    def device(self, fail=()):
        def pull(cmd, on_pct, cancel):
            if posixpath.basename(cmd[-2]) in fail:
                return 1, "adb: error: Permission denied"
            write(cmd[-1], "APK:" + cmd[-2])
            return 0, ""
        return [mock.patch.object(am, "pm_paths", return_value=["/data/app/x/base.apk", "/data/app/x/split_a.apk"]),
                mock.patch.object(am, "adb_transfer", side_effect=pull)]

    def run_window(self, w, force=False, result=None, fail=(), extra=()):
        patches = self.device(fail) + [mock.patch.object(sa, "run_inspection", return_value=result or _result())]
        patches += list(extra)
        mocks = [p_.start() for p_ in patches]
        try:
            w.inspect(force)
            self.pump(lambda: not w.busy, 20)
            return mocks[2]                                  # the run_inspection mock
        finally:
            for p_ in patches:
                p_.stop()

    def summary(self, w):
        return w.summary.get("1.0", "end")

    def key_for(self, fail=()):
        hs = [_h("APK:/data/app/x/" + n) for n in ("base.apk", "split_a.apk")]
        return sa.inspection_key("com.x", "7", hs)

    # -- the Apps-tab button ---------------------------------------------------

    def test_button_needs_exactly_one_installed_app(self):
        t = self.tab
        t.serial = "SER"
        t.apps = {"com.x": dict(self.info), "com.y": dict(self.info, removed=True)}
        with mock.patch.object(t, "selected_pkgs", return_value=[]), mock.patch.object(self.app, "info") as inf:
            t.inspect_selected()
        self.assertIn("exactly one", inf.call_args[0][0])
        with mock.patch.object(t, "selected_pkgs", return_value=["com.y"]), mock.patch.object(self.app, "info") as inf:
            t.inspect_selected()
        self.assertIn("removed", inf.call_args[0][0])
        with mock.patch.object(t, "selected_pkgs", return_value=["com.x"]), \
                mock.patch.object(sa, "inspector_env", return_value=self.ENV_OK), \
                mock.patch.object(am, "read_app_identity") as rai, mock.patch.object(sa, "run_inspection") as ri:
            t.inspect_selected()
            w = t._inspect_wins["com.x"]
            self.wins.append(w)
            t.inspect_selected()                               # second click: same window
            self.assertIs(t._inspect_wins["com.x"], w)
            self.pump(lambda: w.env is not None)
        rai.assert_not_called()                                # opening never touches the phone
        ri.assert_not_called()

    # -- opening ---------------------------------------------------------------

    def test_missing_tools_shows_help_and_blocks(self):
        env = {"ok": False, "python": None, "problems": ["no androguard"], "help": "python3 -m venv HELPTEXT"}
        w = self.open(env)
        self.assertIn("isn't set up", self.summary(w))
        self.assertIn("HELPTEXT", self.summary(w))
        self.assertIn("disabled", w.go_btn.state())
        with mock.patch.object(sa, "run_inspection") as ri:
            w.inspect(False)
        ri.assert_not_called()

    def test_saved_result_shown_on_open_without_device(self):
        ident = sa.make_app_identity("com.x", [_part("base.apk", "APK:/data/app/x/base.apk"),
                                               _part("split_a.apk", "APK:/data/app/x/split_a.apk")])
        sa.atomic_write_json(sa.IDENTITY_FILE, {sa.identity_key("com.x", self.info): ident})
        sa.save_inspection(self.key_for(), dict(_result(), inspected="2026-11-01 10:00"))
        with mock.patch.object(am, "read_app_identity") as rai:
            w = self.open()
        rai.assert_not_called()
        self.assertIn("Saved result for this exact version", self.summary(w))
        self.assertEqual(len(w.ep_tree.get_children()), 2)

    # -- inspecting --------------------------------------------------------------

    def test_inspect_saves_private_result_and_cleans_up(self):
        w = self.open()
        before = {n for n in os.listdir(tempfile.gettempdir()) if n.startswith("adbm_apk_")}
        ri = self.run_window(w)
        ri.assert_called_once()
        job = ri.call_args[0][0]
        self.assertEqual([p["name"] for p in job["parts"]], ["base.apk", "split_a.apk"])
        self.assertTrue(all(p["path"].startswith(tempfile.gettempdir()) for p in job["parts"]))
        left = {n for n in os.listdir(tempfile.gettempdir()) if n.startswith("adbm_apk_")} - before
        self.assertEqual(left, set())                           # copies always deleted
        saved = sa.load_inspection(self.key_for())
        self.assertIsNotNone(saved)
        self.assertEqual(mode(sa._inspection_path(self.key_for())), 0o600)
        self.assertEqual(w.ep_tree.item(w.ep_tree.get_children()[0], "values")[0], "Worth a look")

    def test_cached_build_skips_worker_unless_forced(self):
        sa.save_inspection(self.key_for(), _result())
        w = self.open()
        self.run_window(w).assert_not_called()                 # same build: result reused
        self.assertIn("Saved result", self.summary(w))
        self.run_window(w, force=True).assert_called_once()   # 'Inspect again'

    def test_stop_during_copy_saves_nothing(self):
        w = self.open()

        def pull(cmd, on_pct, cancel):
            w.stop.set()
            return -1, "cancelled"
        with mock.patch.object(am, "pm_paths", return_value=["/data/app/x/base.apk"]), \
                mock.patch.object(am, "adb_transfer", side_effect=pull), \
                mock.patch.object(sa, "run_inspection") as ri, mock.patch.object(self.app, "error") as err:
            w.inspect(False)
            self.pump(lambda: not w.busy)
        ri.assert_not_called()
        self.assertIn("Stopped", err.call_args[0][0])
        self.assertFalse(os.path.isdir(sa.INSPECT_DIR) and os.listdir(sa.INSPECT_DIR))

    def test_part_not_copied_is_incomplete_and_not_saved(self):
        w = self.open()
        ri = self.run_window(w, fail={"split_a.apk"})
        self.assertEqual([p["name"] for p in ri.call_args[0][0]["parts"]], ["base.apk"])
        self.assertIn("Analysis incomplete", self.summary(w))
        self.assertIn("isn't saved", w.progress.cget("text"))
        self.assertFalse(os.path.isdir(sa.INSPECT_DIR) and os.listdir(sa.INSPECT_DIR))
        parts = w.parts_txt.get("1.0", "end")
        self.assertIn("split_a.apk", parts)
        self.assertIn("couldn't be copied", parts)

    def test_interrupted_analysis_shown_incomplete_not_saved(self):
        w = self.open()
        broken = _result(stages=[{"id": "worker", "name": "code analysis", "status": "timeout",
                                  "detail": "took longer than 10 s"}],
                         parts=[{"name": "base.apk", "analysed": False}], eps=[], inds=[])
        self.run_window(w, result=broken)
        self.assertIn("Analysis incomplete", self.summary(w))
        self.assertNotIn("nothing worrying", self.summary(w))
        self.assertIn("took longer", w.limits_txt.get("1.0", "end"))
        self.assertFalse(os.path.isdir(sa.INSPECT_DIR) and os.listdir(sa.INSPECT_DIR))
        self.assertIn("\u26d4 code", w.stage_lbl.cget("text"))

    def test_closed_window_never_frees_tk_objects_off_the_gui_thread(self):
        import gc
        problems = []
        old = sys.unraisablehook
        sys.unraisablehook = lambda u: problems.append(repr(u.exc_value))
        try:
            w = self.open()
            self.run_window(w)
            w.close()
            self.wins.remove(w)
            del w
            self.pump(lambda: not am._LIVE_INSPECT_WINDOWS, 5)
            t = threading.Thread(target=gc.collect)       # garbage collection on a background thread
            t.start()
            t.join()
        finally:
            sys.unraisablehook = old
        self.assertEqual([p_ for p_ in problems if "main thread" in p_], [])

    def test_ok_result_wording_is_not_a_safety_promise(self):
        w = self.open()
        self.run_window(w, result=_result(eps=[], inds=[]))
        text = self.summary(w)
        self.assertIn("No suspicious indicators found in the parts analysed", text)
        self.assertIn("isn't a promise", text)
        self.assertNotIn("clean", text.lower())

    # -- AI only on request -----------------------------------------------------

    def ai_cfg(self, key=True):
        return {"provider": "anthropic", "anthropic": {"api_key": "sk-test" if key else ""}}

    def select_first(self, w):
        first = w.ep_tree.get_children()[0]
        w.ep_tree.selection_set(first)
        self.pump(lambda: w.current is not None, 2)

    def test_no_ai_call_without_a_click_and_one_call_with_it(self):
        good = {"provider": "anthropic", "when": "now", "error": "", "answer": {
            "summary": "A test server.", "who_runs_it": "unknown", "assessment": "concerning",
            "why": "raw IP", "what_to_do": "uninstall", "sources": []}}
        with mock.patch.object(ai, "explain_finding", return_value=good) as ex, \
                mock.patch.object(ai, "load_config", return_value=self.ai_cfg()), \
                mock.patch.object(am.InspectWindow, "confirm_send", return_value=True):
            w = self.open()
            self.run_window(w)
            self.select_first(w)
            ex.assert_not_called()                           # opening, inspecting, selecting: no AI
            w.ask_ai(False)
            self.pump(lambda: not w.ai_busy)
            self.assertEqual(ex.call_count, 1)
            ctx = ex.call_args[0][2]
            self.assertEqual(ctx["value"], "http://1.2.3.4:4444/gate")
            self.assertNotIn("SECRET-TRACEBACK", json.dumps(ctx))
            self.assertIn("Concerning", w.ev.get("1.0", "end"))
            saved = sa.load_inspection(self.key_for())
            fid = sa.finding_id("endpoint", saved["endpoints"][0])
            self.assertEqual(saved["ai"][fid]["anthropic"]["answer"]["assessment"], "concerning")
            w.ask_ai(False)                                  # already answered: shown, not re-asked
            self.pump(lambda: not w.ai_busy, 1)
            self.assertEqual(ex.call_count, 1)
            ex.return_value = {"provider": "anthropic", "when": "later", "error": "timeout"}
            w.ask_ai(True)                                   # 'Ask AI again': explicit refresh
            self.pump(lambda: not w.ai_busy)
            self.assertEqual(ex.call_count, 2)
            kept = sa.load_inspection(self.key_for())["ai"][fid]["anthropic"]
            self.assertEqual(kept["answer"]["assessment"], "concerning")   # good answer kept on failure
            self.assertEqual(kept["error"], "timeout")

    def test_no_api_key_no_call(self):
        with mock.patch.object(ai, "explain_finding") as ex, \
                mock.patch.object(ai, "load_config", return_value=self.ai_cfg(key=False)), \
                mock.patch.object(am.messagebox, "showinfo") as box:
            w = self.open()
            self.run_window(w)
            self.select_first(w)
            w.ask_ai(False)
            self.pump(lambda: False, 0.3)
        ex.assert_not_called()
        self.assertIn("API key", box.call_args[0][0])


@unittest.skipUnless(os.environ.get("DISPLAY") and inspector_python(), "needs a display and Androguard")
class InspectWindowRealTests(InspectWindowTests):
    """One real run: window -> fake phone copy of a real APK -> real worker."""

    def test_real_end_to_end(self):
        jam = sample("com.teleca.jamendo_35.apk")
        if not jam:
            self.skipTest("sample APK not available (offline?)")
        self.info = {"package": "com.teleca.jamendo", "version": "1.0", "version_code": "35", "last_update": "t"}
        env = dict(self.ENV_OK, python=inspector_python())

        def pull(cmd, on_pct, cancel):
            shutil.copy(jam, cmd[-1])
            return 0, ""
        with mock.patch.object(sa, "inspector_env", return_value=env):
            w = am.InspectWindow(self.root, self.app, "SER", "com.teleca.jamendo", self.info, "Jamendo")
            self.wins.append(w)
            self.pump(lambda: w.env is not None)
        with mock.patch.object(am, "pm_paths", return_value=["/data/app/j/base.apk"]), \
                mock.patch.object(am, "adb_transfer", side_effect=pull), \
                mock.patch.object(ai, "explain_finding") as ex:
            w.mode_var.set(am.INSPECT_MODES[2][0])
            w.inspect(False)
            self.assertTrue(self.pump(lambda: not w.busy, 120))
        ex.assert_not_called()
        self.assertIn("No suspicious indicators found in the parts analysed", w.summary.get("1.0", "end"))
        rows = [w.ep_tree.item(i, "values") for i in w.ep_tree.get_children()]
        self.assertIn("http://api.jamendo.com/get2/", [r[1] for r in rows])


for _n in [n for n in dir(InspectWindowTests) if n.startswith("test_")]:
    setattr(InspectWindowRealTests, _n, None)               # only its own real test runs



# ==========================================================================
# Round 16 - phase 1b corrections: recovery, redaction + preview, real sources
# ==========================================================================

SECRET_URL = "https://admin:hunter2@api.example.com:8443/v1/users/9f8e7d6c5b4a39281706f5e4d3c2b1a0/x?token=SECRET123&a=1#frag"


class RedactionTests(unittest.TestCase):
    def test_redact_url(self):
        r = sa.redact_url(SECRET_URL)
        self.assertEqual(r, "https://api.example.com:8443/v1/users/[redacted]/x?[query removed]#[removed]")
        self.assertEqual(sa.redact_url("https://cdn.example.com/assets/app-logo.png"),
                         "https://cdn.example.com/assets/app-logo.png")        # readable paths stay
        self.assertEqual(sa.redact_url("http://1.2.3.4:4444/gate"), "http://1.2.3.4:4444/gate")

    def test_redact_text(self):
        t = sa.redact_text("blanks (http://x.com/a?api_key=SECRET) jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig "
                           "password=hunter2 apikey: abcdefghijklmnopqrstuvwxyz0123456789")
        for bad in ("SECRET", "eyJhbGci", "hunter2", "abcdefghijklmnopqrstuvwxyz0123456789"):
            self.assertNotIn(bad, t)
        self.assertIn("(http://x.com/a?[query removed])", t)                     # punctuation kept

    def test_context_carries_no_secrets(self):
        r = _result()
        ep = dict(r["endpoints"][0], value=SECRET_URL, host="api.example.com", port=8443,
                  evidence=["the address contains blanks that are filled in while the app runs (%s)" % SECRET_URL],
                  issues=["sent with key=SECRET123"])
        ctx = sa.finding_context(r, "endpoint", ep)
        blob = json.dumps(ctx) + ai.build_finding_request(ctx)
        for bad in ("hunter2", "admin", "SECRET123", "frag", "9f8e7d6c5b4a39281706f5e4d3c2b1a0", "a=1"):
            self.assertNotIn(bad, blob)
        self.assertEqual((ctx["host"], ctx["port"]), ("api.example.com", 8443))
        ind = sa.finding_context(r, "indicator", dict(r["indicators"][0], detail="uses token=ABCSECRET"))
        self.assertNotIn("ABCSECRET", json.dumps(ind))


class SourceVerificationTests(unittest.TestCase):
    def ask(self, sources, urls, searches):
        reply = json.dumps({"summary": "s", "assessment": "unclear", "sources": sources})
        with mock.patch.object(ai, "_ask_anthropic", return_value=(reply, {"searches": searches, "urls": urls})):
            return ai.explain_finding("anthropic", {}, {"kind": "indicator", "title": "t"})

    def test_only_retrieved_sources_are_verified(self):
        r = self.ask([{"title": "a", "url": "https://real.example/page/"},
                      {"title": "b", "url": "https://made-up.example/x"}], ["https://real.example/page"], 2)
        self.assertEqual([x["matched"] for x in r["answer"]["sources"]], [False, False])   # trailing / differs
        r = self.ask([{"title": "a", "url": "https://Real.Example/page"},
                      {"title": "b", "url": "https://made-up.example/x"}], ["https://real.example/page"], 2)
        self.assertEqual([x["matched"] for x in r["answer"]["sources"]], [True, False])
        self.assertEqual(r["searches"], 2)

    def test_no_search_recorded(self):
        r = self.ask([{"title": "a", "url": "https://real.example"}], [], 0)
        self.assertEqual(r["searches"], 0)
        self.assertFalse(r["answer"]["sources"][0]["matched"])

    def test_url_collection_from_provider_responses(self):
        from types import SimpleNamespace as N
        content = [N(type="text", text="x"),
                   N(type="web_search_tool_result", content=[N(url="https://a.example"), N(url="https://b.example")])]
        self.assertEqual(ai._anthropic_result_urls(content), ["https://a.example", "https://b.example"])
        output = [N(type="web_search_call"),
                  N(type="message", content=[N(annotations=[N(type="url_citation", url="https://c.example"),
                                                            N(type="other", url="https://no.example")])])]
        self.assertEqual(ai._openai_result_urls(output), ["https://c.example"])


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class InspectWindowRecoveryTests(InspectWindowTests):
    """Failures anywhere must hand the window back, delete the copies and save nothing."""

    def tmp_copies(self):
        return {n for n in os.listdir(tempfile.gettempdir()) if n.startswith("adbm_apk_")}

    def nothing_saved(self):
        return not (os.path.isdir(sa.INSPECT_DIR) and os.listdir(sa.INSPECT_DIR))

    def test_prepare_exception_recovers_and_retries(self):
        with mock.patch.object(sa, "inspector_env", side_effect=RuntimeError("config exploded")):
            w = am.InspectWindow(self.root, self.app, "SER", "com.x", self.info, "X App")
            self.wins.append(w)
            self.assertTrue(self.pump(lambda: "Couldn't check" in self.summary(w), 5))
        self.assertIn("config exploded", self.summary(w))
        self.assertEqual(w.check_btn.winfo_manager(), "pack")         # shown in the button row
        with mock.patch.object(sa, "inspector_env", return_value=self.ENV_OK):
            w.check_again()
            self.assertTrue(self.pump(lambda: w.env is not None, 5))
        self.assertNotIn("disabled", w.go_btn.state())

    def unexpected(self, target, exc, extra=()):
        w = self.open()
        before = self.tmp_copies()
        patches = self.device() + list(extra) + [mock.patch.object(*target, side_effect=exc),
                                                 mock.patch.object(self.app, "error")]
        mocks = [p_.start() for p_ in patches]
        try:
            w.inspect(False)
            self.assertTrue(self.pump(lambda: not w.busy, 10))
        finally:
            for p_ in patches:
                p_.stop()
        self.assertFalse(w.busy)
        self.assertIn("failed unexpectedly", mocks[-1].call_args[0][0])
        self.assertEqual(self.tmp_copies() - before, set())           # copies removed
        self.assertTrue(self.nothing_saved())
        self.assertNotIn("No suspicious", self.summary(w))
        self.assertNotIn("disabled", w.go_btn.state())               # can retry
        ri = self.run_window(w)                                        # ... and the retry works
        ri.assert_called_once()
        self.assertIsNotNone(sa.load_inspection(self.key_for()))

    def test_unexpected_copy_exception(self):
        self.unexpected((am, "read_app_identity"), RuntimeError("usb glitch"))

    def test_unexpected_worker_exception(self):
        self.unexpected((sa, "run_inspection"), RuntimeError("worker launcher bug"))

    def test_unexpected_save_path_exception(self):
        self.unexpected((sa, "summarize_inspection"), ValueError("bad result"))

    def test_worker_launch_failure_incomplete_not_saved(self):
        w = self.open()
        failed = _result(stages=[{"id": "worker", "name": "code analysis", "status": "failed",
                                  "detail": "couldn't start the analysis program: No such file"}],
                         parts=[{"name": "base.apk", "analysed": False}], eps=[], inds=[])
        self.run_window(w, result=failed)
        self.assertIn("Analysis incomplete", self.summary(w))
        self.assertTrue(self.nothing_saved())

    def test_preview_shows_redacted_text_and_decline_sends_nothing(self):
        r = _result()
        r["endpoints"][0]["value"] = SECRET_URL
        with mock.patch.object(ai, "explain_finding") as ex, \
                mock.patch.object(ai, "load_config", return_value=self.ai_cfg()), \
                mock.patch.object(am.InspectWindow, "confirm_send", return_value=False) as ask:
            w = self.open()
            self.run_window(w, result=r)
            self.select_first(w)
            w.ask_ai(False)
            self.pump(lambda: False, 0.3)
        ex.assert_not_called()                                         # declined: nothing sent
        shown = ask.call_args[0][1]
        self.assertIn("api.example.com:8443", shown)
        for bad in ("hunter2", "SECRET123", "frag"):
            self.assertNotIn(bad, shown)

    def test_confirmed_request_carries_no_secrets(self):
        r = _result()
        r["endpoints"][0]["value"] = SECRET_URL
        good = {"provider": "anthropic", "when": "now", "error": "", "searches": 0,
                "answer": {"summary": "s", "who_runs_it": "unknown", "assessment": "unclear", "why": "w",
                           "what_to_do": "d", "sources": [{"title": "t", "url": "https://x.example",
                                                           "matched": False}]}}
        with mock.patch.object(ai, "explain_finding", return_value=good) as ex, \
                mock.patch.object(ai, "load_config", return_value=self.ai_cfg()), \
                mock.patch.object(am.InspectWindow, "confirm_send", return_value=True):
            w = self.open()
            self.run_window(w, result=r)
            self.select_first(w)
            w.ask_ai(False)
            self.pump(lambda: not w.ai_busy)
        blob = json.dumps(ex.call_args[0][2])
        for bad in ("hunter2", "admin", "SECRET123", "frag", "9f8e7d6c5b4a39281706f5e4d3c2b1a0"):
            self.assertNotIn(bad, blob)
        ev = w.ev.get("1.0", "end")
        self.assertIn("No web search was done", ev)
        self.assertIn("NOT among the pages the AI's search returned", ev)

    def test_ai_job_exception_restores_button(self):
        with mock.patch.object(ai, "explain_finding", side_effect=RuntimeError("sdk bug")), \
                mock.patch.object(ai, "load_config", return_value=self.ai_cfg()), \
                mock.patch.object(am.InspectWindow, "confirm_send", return_value=True), \
                mock.patch.object(self.app, "error") as err:
            w = self.open()
            self.run_window(w)
            self.select_first(w)
            w.ask_ai(False)
            self.assertTrue(self.pump(lambda: not w.ai_busy, 5))
        self.assertIn("sdk bug", err.call_args[0][0])
        self.assertNotIn("disabled", w.ask_btn.state())                # can ask again


for _n in [n for n in dir(InspectWindowTests) if n.startswith("test_")]:
    setattr(InspectWindowRecoveryTests, _n, None)                    # only its own tests run here



# ==========================================================================
# Round 17 - URL matching, redaction gaps, full preview, save/cleanup failures
# ==========================================================================

class UrlMatchTests(unittest.TestCase):
    def test_path_case_and_trailing_slash_matter(self):
        self.assertNotEqual(ai._url_norm("https://example.com/OfficialPage"),
                            ai._url_norm("https://example.com/officialpage"))
        self.assertNotEqual(ai._url_norm("https://example.com/page/"), ai._url_norm("https://example.com/page"))
        self.assertEqual(ai._url_norm("HTTPS://Example.COM/OfficialPage"),
                         ai._url_norm("https://example.com/OfficialPage"))     # scheme/host only
        self.assertNotEqual(ai._url_norm("https://e.com/a?Q=1"), ai._url_norm("https://e.com/a?q=1"))

    def test_case_different_page_not_matched(self):
        reply = json.dumps({"summary": "s", "assessment": "unclear",
                            "sources": [{"title": "t", "url": "https://example.com/OfficialPage"}]})
        with mock.patch.object(ai, "_ask_anthropic",
                               return_value=(reply, {"searches": 1, "urls": ["https://example.com/officialpage"]})):
            r = ai.explain_finding("anthropic", {}, {"kind": "indicator", "title": "t"})
        self.assertFalse(r["answer"]["sources"][0]["matched"])


class RedactionGapTests(unittest.TestCase):
    def test_quoted_values_redacted_whole(self):
        self.assertEqual(sa.redact_text('password="super secret"'), "password=[redacted]")
        self.assertEqual(sa.redact_text("password='two words here' ok"), "password=[redacted] ok")

    def test_authorization_schemes(self):
        for t in ("Authorization: Bearer abc123", "Authorization=Basic dXNlcjpwYXNz", "header Bearer abc123def"):
            r = sa.redact_text(t)
            for bad in ("abc123", "dXNlcjpwYXNz"):
                self.assertNotIn(bad, r, t)

    def test_percent_encoded_token_segment(self):
        enc = "".join("%%%02X" % ord(c) for c in "9f8e7d6c5b4a3928")
        self.assertEqual(sa.redact_url("https://api.example.com/v1/%s/profile" % enc),
                         "https://api.example.com/v1/[redacted]/profile")
        self.assertEqual(sa.redact_url("https://example.com/files/My%20Document.pdf"),
                         "https://example.com/files/My%20Document.pdf")      # readable path kept as-is

    def test_location_fields_redacted(self):
        r = _result()
        ep = dict(r["endpoints"][0], locations=[{"part": "base.apk", "source": "dex",
                                                 "cls": "com.x.Api$token=SECRETVALUE",
                                                 "method": "call Bearer abc123xyz",
                                                 "owner": "Lib " + "k" * 40}])
        blob = json.dumps(sa.finding_context(r, "endpoint", ep))
        for bad in ("SECRETVALUE", "abc123xyz", "k" * 40):
            self.assertNotIn(bad, blob)


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class SendPreviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()

    @classmethod
    def tearDownClass(cls):
        destroy_root(cls.root)

    def test_preview_holds_the_complete_text(self):
        text = "\n".join("line %04d " % i + "x" * 40 for i in range(200))       # ~10k characters
        d = am.SendPreview(self.root, "Anthropic", text)
        self.assertEqual(d.txt.get("1.0", "end-1c"), text)                  # nothing cut off
        d.send()
        self.assertTrue(d.result)

    def test_cancel_returns_false(self):
        d = am.SendPreview(self.root, "OpenAI", "short")
        d.destroy()
        self.assertFalse(d.result)


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class InspectWindowFailureTests(InspectWindowRecoveryTests):
    def test_full_request_goes_to_the_preview(self):
        r = _result()
        r["endpoints"][0]["evidence"] = ["reason %d: found in an unusual place in the code" % i
                                         for i in range(80)]                  # long request
        with mock.patch.object(ai, "explain_finding") as ex, \
                mock.patch.object(ai, "load_config", return_value=self.ai_cfg()), \
                mock.patch.object(am.InspectWindow, "confirm_send", return_value=False) as conf:
            w = self.open()
            self.run_window(w, result=r)
            self.select_first(w)
            w.ask_ai(False)
            self.pump(lambda: False, 0.3)
        shown = conf.call_args[0][1]
        self.assertGreater(len(shown), 3000)
        self.assertIn("reason 79", shown)                                    # the very end is there
        ex.assert_not_called()

    def test_unexpected_save_exception(self):
        self.unexpected((sa, "save_inspection"), ValueError("disk driver bug"),
                        extra=[mock.patch.object(sa, "run_inspection", return_value=_result())])
        # unexpected() already checked: not busy, error shown, copies removed, NOTHING cached,
        # and that a retry (with saving working again) succeeds and saves.

    def test_cleanup_failure_is_reported(self):
        w = self.open()
        made = []
        real_mk = tempfile.mkdtemp

        def mk(*a, **k):
            d = real_mk(*a, **k)
            made.append(d)
            return d
        self.addCleanup(lambda: [shutil.rmtree(d, True) for d in made])
        with mock.patch.object(am.tempfile, "mkdtemp", side_effect=mk), \
                mock.patch.object(am.shutil, "rmtree", side_effect=OSError(13, "Permission denied")), \
                mock.patch.object(self.app, "error") as err:
            self.run_window(w)
            self.pump(lambda: err.called, 3)
        msgs = [c[0][0] for c in err.call_args_list]
        self.assertTrue(any("Couldn't delete the temporary copies" in m and made[0] in m and "Permission denied" in m
                            for m in msgs), msgs)


for _n in [n for n in dir(InspectWindowRecoveryTests) if n.startswith("test_")]:
    setattr(InspectWindowFailureTests, _n, None)                     # only its own tests run here



# ==========================================================================
# Round 18 - redaction fails closed: malformed URLs, short/structured auth
# ==========================================================================

BAD_URL = "https://admin:secret@example.com:invalid/path?session=private&other=value#private"


class RedactionFailClosedTests(unittest.TestCase):
    def test_malformed_url_fails_closed(self):
        r = sa.redact_url(BAD_URL)
        for bad in ("admin", "secret", "invalid", "session", "private", "other", "value", "path"):
            self.assertNotIn(bad, r, r)
        self.assertEqual(r, "https://example.com/[rest of an unreadable address removed]")
        self.assertEqual(sa.redact_url("https://[broken/x?y=1"), "[unreadable address removed]")

    def test_malformed_url_inside_text_and_context(self):
        t = sa.redact_text("blanks filled at run time (%s)" % BAD_URL)
        for bad in ("admin", "secret", "session", "private", "value"):
            self.assertNotIn(bad, t)
        r = _result()
        ep = dict(r["endpoints"][0], value=BAD_URL, evidence=["seen as %s" % BAD_URL])
        blob = json.dumps(sa.finding_context(r, "endpoint", ep))
        for bad in ("admin", "secret", "session", "private", "other=value"):
            self.assertNotIn(bad, blob)

    def test_short_standalone_bearer(self):
        for t in ("Bearer abc", "header: Bearer x1", "basic Zm9v"):
            r = sa.redact_text(t)
            for bad in ("abc", "x1", "Zm9v"):
                self.assertNotIn(bad, r, t)

    def test_every_auth_scheme_standalone(self):
        """Coverage restored for ALL schemes in _AUTH_SCHEMES (token/digest were lost in round 18)."""
        for t, secret in (("token abc", "abc"), ("Token x1", "x1"), ("Digest abc123", "abc123"),
                          ("Bearer q", "q "), ("NTLM TlRMTVNT", "TlRMTVNT"), ("Negotiate YIIab", "YIIab")):
            r = sa.redact_text(t + " ")
            self.assertNotIn(secret, r, t)
            self.assertIn("[redacted]", r, t)
        for scheme in re.findall(r"[a-z]+", sa._AUTH_SCHEMES):          # one list, all covered
            self.assertEqual(sa.redact_text("%s z9" % scheme), "%s [redacted]" % scheme, scheme)

    def test_digest_star_parameter_redacted_to_end(self):
        t = sa.redact_text("Digest username*=UTF-8''J%C3%A4s, realm=\"x\", nonce=\"secret\", response=\"r1\"")
        self.assertEqual(t, "Digest [redacted]")

    def test_digest_runs_before_generic_scheme_pass(self):
        # if the generic pass ran first it would redact only "username=..." and leave nonce/response
        t = sa.redact_text('Digest username="alice", nonce="secret", response="resp-secret"')
        self.assertEqual(t, "Digest [redacted]")

    def test_digest_authorization_removed_whole(self):
        hdr = 'Authorization: Digest username="alice", realm="example", nonce="secret", response="digest-secret"'
        self.assertEqual(sa.redact_text(hdr), "Authorization: [redacted]")
        bare = sa.redact_text('Digest username="alice", nonce="secret", response="digest-secret"')
        for bad in ("alice", "secret", "digest-secret", "realm"):
            self.assertNotIn(bad, bare)



# ==========================================================================
# Round 19 - hard-coded IP addresses: bare IPv6 too
# ==========================================================================

class HardcodedIpTests(unittest.TestCase):
    CTX = {"package": "com.example.app", "signatures": sa.inspector_signatures(), "sdks_present": set()}

    def found(self, text):
        return [(e["kind"], e["host"], e["port"]) for e in sa.extract_endpoints(text)]

    def classify(self, text, source="dex"):
        e = sa.extract_endpoints(text)[0]
        e["locations"] = [{"source": source}]
        return sa.classify_endpoint(e, self.CTX)

    def test_ipv4_everywhere(self):
        self.assertEqual(self.found("http://45.33.12.9/gate"), [("url", "45.33.12.9", None)])
        self.assertEqual(self.found("connect 45.33.12.9:4444"), [("ip", "45.33.12.9", 4444)])
        self.assertEqual(self.found("45.33.12.9"), [("ip", "45.33.12.9", None)])
        self.assertEqual(self.classify("45.33.12.9:4444")["classification"], "suspicious")

    def test_bare_ipv6(self):
        self.assertEqual(self.found("2a00:1450:4001:82a::200e"), [("ip", "2a00:1450:4001:82a::200e", None)])
        self.assertEqual(self.found("[2a00:1450:4001:82a::200e]:4444"), [("ip", "2a00:1450:4001:82a::200e", 4444)])
        r = self.classify("[2a00:1450:4001:82a::200e]:4444")
        self.assertEqual(r["classification"], "suspicious")
        joined = " ".join(r["evidence"])
        self.assertIn("raw internet IP", joined)
        self.assertIn("unusual port (4444)", joined)

    def test_ipv6_in_url_not_duplicated(self):
        self.assertEqual(self.found("http://[2a00:1450:4001:82a::200e]:8443/x"),
                         [("url", "2a00:1450:4001:82a::200e", 8443)])

    def test_local_ipv6_not_suspicious(self):
        self.assertEqual(self.classify("fe80::1ff:fe23:4567:890a")["classification"], "unknown")

    def test_invalid_lookalikes_rejected(self):
        # not valid IPv6 at all (ipaddress decides), or "::" = no address
        for t in ("std::string", "Foo::Bar::baz", "ns::a::b", "12:30:45", "::"):
            self.assertEqual(self.found(t), [], t)

    def test_short_compressed_ipv6_extracted(self):
        self.assertEqual(self.found("::1"), [("ip", "::1", None)])
        self.assertEqual(self.found("2001::1"), [("ip", "2001::1", None)])
        self.assertEqual(self.classify("::1")["classification"], "expected")          # loopback
        r = self.classify("2001::1")
        self.assertEqual(r["classification"], "unknown")                             # reserved range
        self.assertIn("reserved", r["evidence"][0])

    def test_ambiguous_ipv6_kept_but_not_alarming(self):
        for t in ("a::b", "dead::beef"):
            eps = sa.extract_endpoints(t)
            self.assertEqual([(e["host"], e["ambiguous"]) for e in eps], [(t, True)], t)
            for src in ("dex", "native"):                  # even where native-only would add a reason
                r = self.classify(t, source=src)
                self.assertEqual(r["classification"], "unknown", (t, src))
                self.assertNotIn(r["classification"], ("suspicious", "malicious"))
                self.assertIn("program text", r["evidence"][0])

    def test_cpp_identifier_shaped_ipv6_is_ambiguous(self):
        """Digits don't make it an address: C++ identifiers may contain digits after the
        first character (face::b00c, a1::b2). Any unbracketed 'ident::ident' stays ambiguous."""
        for t in ("face::b00c", "a1::b2", "::b"):
            e = sa.extract_endpoints(t)[0]
            self.assertTrue(e["ambiguous"], t)
            for src in ("dex", "native"):
                r = self.classify(t, source=src)
                self.assertEqual((r["classification"], r["confidence"]), ("unknown", "low"), (t, src))

    def test_non_identifier_parts_are_unambiguous(self):
        e = sa.extract_endpoints("2001::1")[0]               # "2001" can't be a C++ identifier
        self.assertFalse(e["ambiguous"])
        self.assertFalse(sa.extract_endpoints("::1")[0]["ambiguous"])
        e = sa.extract_endpoints("ab:cd::ef")[0]             # single ":" never occurs in C++ scope text
        self.assertFalse(e["ambiguous"])
        self.assertEqual(self.classify("ab:cd::ef")["classification"], "suspicious")

    def test_bracketed_short_form_is_not_ambiguous(self):
        e = sa.extract_endpoints("[dead::beef]:4444")[0]          # brackets + port = address syntax
        self.assertFalse(e["ambiguous"])
        self.assertEqual(e["port"], 4444)
        self.assertFalse(sa.extract_endpoints("[face::b00c]")[0]["ambiguous"])
        self.assertEqual(self.classify("[face::b00c]:443")["classification"], "suspicious")

    def test_version_number_note_only_for_ipv4(self):
        self.assertIn("version number", " ".join(self.classify("45.33.12.9")["evidence"]))
        self.assertNotIn("version number", " ".join(self.classify("2a00:1450:4001:82a::200e")["evidence"]))



# ==========================================================================
# Round 21 - About window credits
# ==========================================================================

@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class AboutWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()
        args = mock.Mock(serial=None, local=TMP_HOME, remote="/sdcard")
        with mock.patch.object(am.App, "scan_devices", lambda self, *a, **k: None):
            cls.app = am.App(cls.root, args)

    @classmethod
    def tearDownClass(cls):
        destroy_root(cls.root)

    def labels(self, w):
        out = []
        for c in w.winfo_children():
            try:
                out.append((c, c.cget("text")))
            except tk.TclError:
                pass
            out += self.labels(c)
        return out

    def test_credits(self):
        self.app.show_about()
        win = self.app._about_win
        self.addCleanup(win.destroy)
        texts = [t for _, t in self.labels(win)]
        for want in ("Project concept & vision", "Code implementation", "Architecture & security review",
                     "Testing", "Pedro", " (https://github.com/peterpt)",
                     " - original idea, product direction and requirements",
                     "Claude Opus 5.5 (Anthropic)", " - primary code builder and implementation",
                     "ChatGPT, GPT-6 (OpenAI)",
                     " - architecture guidance, independent code review and security analysis",
                     "Automated test suite", "Real-device testing", " - Pedro"):
            self.assertIn(want, texts)
        self.assertTrue(any("Gemini" in t for t in texts))              # the exclusion note stays
        self.assertTrue(any(t.startswith("Built through human creativity") for t in texts))
        self.assertFalse(any("Independent testing" in t for t in texts))  # tests aren't independent
        link = next(c for c, t in self.labels(win) if t == "Pedro")
        self.root.deiconify()                                            # Tk only clicks mapped widgets,
        win.deiconify()                                                  # and the About window is a child
        self.addCleanup(self.root.withdraw)                              # of the (hidden) test root
        for _ in range(20):
            win.update()
            if link.winfo_viewable():
                break
            time.sleep(0.05)
        with mock.patch.object(self.app, "_open_url") as op:
            link.event_generate("<Button-1>", x=2, y=2)
            win.update()
        op.assert_called_once_with("https://github.com/peterpt")       # opens the profile, not the label text
        self.app.show_about()                                            # second click: same window
        self.assertIs(self.app._about_win, win)


if __name__ == "__main__":
    unittest.main()
