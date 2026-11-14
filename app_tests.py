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
import glob
import json                   # noqa: E402
import multiprocessing        # noqa: E402
import posixpath              # noqa: E402
import shlex                  # noqa: E402
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

import copy                    # noqa: E402
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



# ==========================================================================
# Round 22 - real app names (labels) from APK metadata
# ==========================================================================

import struct as _st          # noqa: E402


def _pool(strings):
    """ResStringPool (UTF-16)."""
    data, offs = b"", []
    for t in strings:
        offs.append(len(data))
        enc = t.encode("utf-16-le")
        data += _st.pack("<H", len(t)) + enc + b"\x00\x00"
    while len(data) % 4:
        data += b"\x00"
    start = 28 + 4 * len(strings)
    body = b"".join(_st.pack("<I", o) for o in offs) + data
    return _st.pack("<HHIIIIII", 0x0001, 28, 28 + len(body), len(strings), 0, 0, start, 0) + body


def make_axml(label=None, label_ref=None, name_attr_empty=False):
    """Binary manifest with <manifest><application android:label=...>."""
    strings = ["" if name_attr_empty else "label", "application", "manifest"]
    if label is not None:
        strings.append(label)
    sp = _pool(strings)
    resmap = _st.pack("<HHI", 0x0180, 8, 12) + _st.pack("<I", 0x01010001)

    def elem(name_idx, attrs):
        ext = _st.pack("<IIHHHHHH", 0xFFFFFFFF, name_idx, 20, 20, len(attrs), 0, 0, 0)
        body = _st.pack("<II", 1, 0xFFFFFFFF) + ext + b"".join(attrs)
        return _st.pack("<HHI", 0x0102, 16, 8 + len(body)) + body
    attrs = []
    if label is not None:
        attrs.append(_st.pack("<IIIHBBI", 0xFFFFFFFF, 0, 3, 8, 0, 0x03, 3))
    elif label_ref is not None:
        attrs.append(_st.pack("<IIIHBBI", 0xFFFFFFFF, 0, 0xFFFFFFFF, 8, 0, 0x01, label_ref))
    body = sp + resmap + elem(2, []) + elem(1, attrs)
    return _st.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def _cfg(lang="", region="", script=""):
    c = bytearray(64)
    _st.pack_into("<I", c, 0, 64)
    c[8:10] = lang.encode().ljust(2, b"\x00")[:2] if lang else b"\x00\x00"
    c[10:12] = region.encode().ljust(2, b"\x00")[:2] if region else b"\x00\x00"
    if script:
        c[36:40] = script.encode()[:4]
    return bytes(c)


def make_arsc(values, resid=0x7F010000, mode="plain"):
    """values: [((lang, region, script), text)] -> resources.arsc with one string
    resource per config. mode: plain | off16 (Android 13) | compact (Android 14)."""
    gsp = _pool([t for _, t in values])
    tsp, ksp = _pool(["string"]), _pool(["app_name"])
    type_id, entry = (resid >> 16) & 0xFF, resid & 0xFFFF
    types = b""
    for i, ((lang, region, script), _) in enumerate(values):
        count = entry + 1
        cfg = _cfg(lang, region, script)
        hsize = 20 + len(cfg)
        if mode == "compact":
            ent = _st.pack("<HHI", 0, 0x0008 | (0x03 << 8), i)
        else:
            ent = _st.pack("<HHI", 8, 0, 0) + _st.pack("<HBBI", 8, 0, 0x03, i)
        if mode in ("sparse", "sparse16"):
            count = 1                                     # one (index, offset/4) pair
            offs = _st.pack("<HH", entry, 0)
            flags = 0x01 | (0x02 if mode == "sparse16" else 0)
        elif mode == "off16":
            offs = b"".join(_st.pack("<H", 0 if k == entry else 0xFFFF) for k in range(count))
            while len(offs) % 4:
                offs += b"\x00\x00"
            flags = 0x02
        else:
            offs = b"".join(_st.pack("<I", 0 if k == entry else 0xFFFFFFFF) for k in range(count))
            flags = 0
        estart = hsize + len(offs)
        body = cfg + offs + ent
        types += _st.pack("<HHIBBHII", 0x0201, hsize, 20 + len(body), type_id, flags, 0, count, estart) + body
    name = "com.example".encode("utf-16-le").ljust(256, b"\x00")
    phead = 288
    pkg_body = name + _st.pack("<IIIII", phead, 0, phead + len(tsp), 0, 0)
    pkg = _st.pack("<HHII", 0x0200, phead, 0, resid >> 24) + pkg_body
    pkg = pkg + tsp + ksp + types
    pkg = pkg[:4] + _st.pack("<I", len(pkg)) + pkg[8:]
    body = gsp + pkg
    return _st.pack("<HHII", 0x0002, 12, 12 + len(body), 1) + body


class LabelParserTests(unittest.TestCase):
    EN = {"lang": "en", "region": "US", "script": ""}
    PT = {"lang": "pt", "region": "PT", "script": ""}
    VALUES = [(("", "", ""), "Calendar"), (("pt", "", ""), "Calendário"), (("pt", "BR", ""), "Agenda"),
              (("en", "XA", ""), "[Çåļéñðåŕ]")]

    def label(self, man, arsc, loc):
        return sa.label_from_parts(man, arsc, loc)

    def test_literal_label(self):
        r = self.label(make_axml(label="WhatsApp"), None, self.EN)
        self.assertEqual((r["label"], r["match"]), ("WhatsApp", "literal"))

    def test_resource_label_by_locale(self):
        man, arsc = make_axml(label_ref=0x7F010000), make_arsc(self.VALUES)
        self.assertEqual(self.label(man, arsc, self.PT)["label"], "Calendário")      # pt-PT -> plain pt
        self.assertEqual(self.label(man, arsc, self.PT)["match"], "language")
        r = self.label(man, arsc, {"lang": "pt", "region": "BR"})
        self.assertEqual((r["label"], r["match"]), ("Agenda", "exact"))
        r = self.label(man, arsc, self.EN)                                          # pseudo-locale skipped
        self.assertEqual((r["label"], r["match"]), ("Calendar", "default"))
        r = self.label(man, arsc, {})
        self.assertEqual((r["label"], r["match"]), ("Calendar", "default"))

    def test_android13_and_14_layouts(self):
        man = make_axml(label_ref=0x7F010000)
        for mode in ("off16", "compact"):
            r = self.label(man, make_arsc(self.VALUES, mode=mode), self.PT)
            self.assertEqual(r["label"], "Calendário", mode)

    def test_obfuscated_attribute_name_uses_resource_map(self):
        r = self.label(make_axml(label="Secret App", name_attr_empty=True), None, self.EN)
        self.assertEqual(r["label"], "Secret App")

    def test_missing_label_and_missing_resource(self):
        self.assertIsNone(self.label(make_axml(), None, self.EN)["label"])
        r = self.label(make_axml(label_ref=0x7F010005), make_arsc(self.VALUES), self.EN)
        self.assertIsNone(r["label"])
        self.assertIn("wasn't found", r["error"])
        r = self.label(make_axml(label_ref=0x7F010000), None, self.EN)
        self.assertIn("resource table wasn't read", r["error"])

    def test_hostile_inputs_never_escape(self):
        import random
        rnd = random.Random(1234)
        man, arsc = make_axml(label_ref=0x7F010000), make_arsc(self.VALUES)
        bad = [b"", b"\x03\x00\x08\x00", os.urandom(4096), man[:40], arsc[:100],
               man[:8] + b"\x00" * 8 + man[16:],                       # zero-size chunk (loop attempt)
               man[:4] + _st.pack("<I", 0xFFFFFFFF) + man[8:]]           # 4 GB size claim
        for _ in range(300):
            m = bytearray(rnd.choice([man, arsc]))
            for _ in range(rnd.randint(1, 8)):
                m[rnd.randrange(len(m))] = rnd.randrange(256)
            bad.append(bytes(m))
        t = time.time()
        for b in bad:
            for args in ((b, arsc), (man, b)):
                try:
                    r = sa.label_from_parts(args[0], args[1], self.PT)
                    self.assertIsInstance(r, dict)
                except sa.LabelError:
                    pass
        self.assertLess(time.time() - t, 20)

    def test_clean_label(self):
        self.assertEqual(sa.clean_label("Evil\x1b[31mApp\n"), "Evil[31mApp")
        self.assertEqual(len(sa.clean_label("x" * 999)), sa.LABEL_MAX_LEN)
        self.assertIsNone(sa.clean_label("   "))

    @unittest.skipUnless(inspector_python(), "Androguard not installed (used as the reference)")
    def test_matches_androguard_on_real_apk(self):
        jam = sample("com.teleca.jamendo_35.apk")
        if not jam:
            self.skipTest("sample APK not available")
        with _zipfile.ZipFile(jam) as z:
            man, arsc = z.read("AndroidManifest.xml"), z.read("resources.arsc")
        mine = sa.label_from_parts(man, arsc, self.EN)["label"]
        ref = subprocess.run([inspector_python(), "-c", "import sys\nfrom loguru import logger; logger.remove()\n"
                              "from androguard.core.apk import APK\nprint(APK(sys.argv[1]).get_app_name())", jam],
                             capture_output=True, text=True, timeout=120).stdout.strip()
        self.assertEqual(mine, ref)
        self.assertEqual(mine, "Jamendo")


class ZipRangeTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def apk(self, arsc_stored=True, big_arsc=False):
        path = os.path.join(self.d, "base.apk")
        with _zipfile.ZipFile(path, "w") as z:
            z.writestr(_zipfile.ZipInfo("AndroidManifest.xml"), make_axml(label_ref=0x7F010000),
                       compress_type=_zipfile.ZIP_DEFLATED)
            data = make_arsc(LabelParserTests.VALUES) + (b"\0" * (sa.LABEL_MAX_ARSC + 10) if big_arsc else b"")
            z.writestr(_zipfile.ZipInfo("resources.arsc"), data,
                       compress_type=_zipfile.ZIP_STORED if arsc_stored else _zipfile.ZIP_DEFLATED)
            z.writestr("classes.dex", b"dex")
        return path

    def fake_device(self, path):
        def rread(serial, rpath, off, length, timeout=30):
            with open(path, "rb") as f:
                f.seek(off)
                return f.read(length)
        return [mock.patch.object(am, "remote_read", side_effect=rread),
                mock.patch.object(am, "remote_size", return_value=os.path.getsize(path))]

    def read(self, path):
        pt = self.fake_device(path)
        for p_ in pt:
            p_.start()
        try:
            meter = {"used": 0}
            return am.read_label_parts("S", "/data/app/x/base.apk", self.d, "a0", meter), meter["used"]
        finally:
            for p_ in pt:
                p_.stop()

    def test_reads_only_label_parts_and_resolves(self):
        path = self.apk()
        parts, used = self.read(path)
        self.assertEqual(parts["manifest"]["method"], 8)
        self.assertEqual(parts["arsc"]["method"], 0)
        self.assertLess(used, os.path.getsize(path) + 70000)
        self.assertEqual(parts["manifest"]["size"], len(make_axml(label_ref=0x7F010000)))
        r = sa.run_label_worker([{"id": "com.x", "manifest": parts["manifest"], "arsc": parts["arsc"]}],
                                {"lang": "pt", "region": "PT"})
        self.assertEqual(r["com.x"], {"label": "Calendário", "match": "language", "error": ""})

    def test_oversized_resource_table_skipped(self):
        parts, used = self.read(self.apk(big_arsc=True))
        self.assertIsNone(parts["arsc"])                    # falls back instead of reading 16 MB+

    def test_bad_zip_raises_label_error(self):
        bad = os.path.join(self.d, "bad.apk")
        write(bad, "not a zip at all")
        with self.assertRaises(sa.LabelError):
            self.read(bad)

    def test_zip64_and_out_of_range_refused(self):
        tail = b"x" * 10 + b"PK\x05\x06" + b"\x00" * 8 + _st.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF) + b"\x00\x00"
        with self.assertRaises(sa.LabelError):
            sa.zip_find_cd(tail, 10 ** 6)
        tail = b"PK\x05\x06" + b"\x00" * 8 + _st.pack("<II", 100, 999999) + b"\x00\x00"
        with self.assertRaises(sa.LabelError):
            sa.zip_find_cd(tail, 1000)


class RemoteReadSafetyTests(unittest.TestCase):
    def test_unusual_paths_never_reach_the_shell(self):
        with mock.patch("subprocess.run") as run, mock.patch.object(am, "adb_shell") as sh:
            for bad in ("/data/app/x/base.apk; rm -rf /", "/data/app/$(reboot)/base.apk", "relative/base.apk",
                        "/data/app/x/base.apk\nid", "/data/app/x/notes.txt", "/data/app/x y/base.apk"):
                with self.assertRaises(am.AdbError):
                    am.remote_read("S", bad, 0, 10)
                with self.assertRaises(am.AdbError):
                    am.remote_size("S", bad)
        run.assert_not_called()
        sh.assert_not_called()

    def test_block_aligned_dd_and_slicing(self):
        blob = bytes(range(256)) * 64                       # 16 KB "file"
        def run(cmd, **kw):
            m = re.search(r"bs=(\d+) skip=(\d+) count=(\d+)", cmd[-1])
            bs, skip, count = map(int, m.groups())
            self.assertIn("if=%s " % shlex.quote("/data/app/x/base.apk"), cmd[-1])   # passed through shlex.quote
            return mock.Mock(returncode=0, stdout=blob[skip * bs:(skip + count) * bs])
        with mock.patch("subprocess.run", side_effect=run):
            self.assertEqual(am.remote_read("S", "/data/app/x/base.apk", 5000, 300), blob[5000:5300])

    def test_locale_parsing(self):
        for raw, want in (("pt-PT", {"lang": "pt", "region": "PT", "script": ""}),
                          ("zh-Hant-TW", {"lang": "zh", "region": "TW", "script": "Hant"}),
                          ("en_US", {"lang": "en", "region": "US", "script": ""})):
            with mock.patch.object(am, "adb_shell", return_value=(0, raw + "\n", "")):
                self.assertEqual(am.device_locale("S"), want)


class LabelWorkerTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def files(self, man, arsc=None):
        mp = os.path.join(self.d, "m")
        with open(mp, "wb") as f:
            f.write(man)
        item = {"id": "com.x", "manifest": {"path": mp, "method": 0}, "arsc": None}
        if arsc is not None:
            ap = os.path.join(self.d, "r")
            with open(ap, "wb") as f:
                f.write(arsc)
            item["arsc"] = {"path": ap, "method": 0}
        return [item]

    def test_garbage_is_a_failed_name_not_a_crash(self):
        r = sa.run_label_worker(self.files(os.urandom(5000)), {})
        self.assertIsNone(r["com.x"]["label"])

    def test_timeout_and_bad_output_contained(self):
        hang = os.path.join(self.d, "hang.py")
        write(hang, "import time\ntime.sleep(60)\n")
        t = time.time()
        r = sa.run_label_worker(self.files(make_axml(label="A")), {}, timeout_s=1, script=hang)
        self.assertLess(time.time() - t, 10)
        self.assertIn("didn't finish", r["com.x"]["error"])
        liar = os.path.join(self.d, "liar.py")
        write(liar, "import json, sys\nj = json.load(open(sys.argv[2]))\n"
                    "json.dump({'schema': 1, 'results': {'com.x': {'label': 'Evil\\u001bName', 'match': 'bogus'},"
                    " 'com.other': {'label': 'Injected', 'match': 'exact'}}}, open(j['result'], 'w'))\n")
        r = sa.run_label_worker(self.files(make_axml(label="A")), {}, script=liar)
        self.assertEqual(list(r), ["com.x"])                   # no ids outside the batch
        self.assertIsNone(r["com.x"]["label"])                 # unknown match kind -> rejected

    def test_memory_limit_contained(self):
        hog = os.path.join(self.d, "hog.py")
        write(hog, "x = bytearray(3 << 30)\n")
        r = sa.run_label_worker(self.files(make_axml(label="A")), {}, mem_bytes=256 << 20, script=hog)
        self.assertIsNone(r["com.x"]["label"])


def real_app(pkg, system=False):
    """An app record shaped exactly like scan_packages() makes them."""
    return {"package": pkg, "path": "/data/app/%s/base.apk" % pkg, "system": system, "updated_system": False,
            "disabled": False, "uid": "10100", "version": "1.0", "version_code": "1", "target_sdk": "34",
            "installer": "", "first_install": "t", "last_update": "t", "perms": [], "granted": [],
            "in_use": None, "removed": False, "icon": None, "group": "android" if system else "user"}


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class AppNameGuiTests(unittest.TestCase):
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
        t = self.tab
        t.stop_label_reader()
        for k in t.labels.keys():
            t.labels.put(k, None)
        t.serial = t.scanned_serial = "SER"
        t.label_locale = {"lang": "pt", "region": "PT", "script": ""}
        t.apps = {p: real_app(p, sys_) for p, sys_ in (("com.whatsapp", False), ("com.android.calendar.go", True),
                                                       ("com.facebook.system", True))}
        t.build_family()
        t.populate()

    def entry(self, p, label, **kw):
        a = self.tab.apps[p]
        e = {"label": label, "match": "exact", "error": "", "version_code": str(a["version_code"]),
             "last_update": str(a["last_update"]), "apk_path": a["path"], "locale": self.tab.label_locale,
             "source": "apk"}
        e.update(kw)
        return e

    def test_priority_apk_then_play_then_builtin_then_package(self):
        t = self.tab
        self.assertEqual(t.label("com.facebook.system"), "Facebook App Installer")          # built-in
        t.cache.put("com.facebook.system", {"play": {"found": True, "name": "FB Installer (Play)"}})
        self.assertEqual(t.label("com.facebook.system"), "FB Installer (Play)")              # Play beats built-in
        t.labels.put("com.facebook.system", self.entry("com.facebook.system", "Instalador do Facebook"))
        self.assertEqual(t.label("com.facebook.system"), "Instalador do Facebook")           # APK beats both
        self.assertEqual(t.label("com.android.calendar.go"), "com.android.calendar.go")      # nothing -> package
        t.cache.put("com.facebook.system", None)

    def test_label_shown_but_actions_use_package(self):
        t = self.tab
        t.labels.put("com.whatsapp", self.entry("com.whatsapp", "WhatsApp Messenger"))
        t.refresh_row("com.whatsapp")
        self.assertEqual(t.tree.item("p:com.whatsapp", "text"), "WhatsApp Messenger")
        self.assertIn("com.whatsapp", t.tree.item("p:com.whatsapp", "values"))            # Package column unchanged
        t.tree.selection_set("p:com.whatsapp")
        self.assertEqual(t.selected_pkgs(), ["com.whatsapp"])                              # actions get the id
        with mock.patch.object(am, "InspectWindow") as iw, mock.patch.object(t, "selected_pkgs",
                                                                             return_value=["com.whatsapp"]):
            t._inspect_wins.clear()
            t.inspect_selected()
        self.assertEqual(iw.call_args[0][3], "com.whatsapp")
        self.assertTrue(t.matches(t.apps["com.whatsapp"], "messenger", "All apps"))       # search by name
        self.assertTrue(t.matches(t.apps["com.whatsapp"], "com.whatsapp", "All apps"))    # ... or by id

    def test_cache_invalidated_by_version_time_path_locale(self):
        t = self.tab
        for change in ({"version_code": "999"}, {"last_update": "other"}, {"apk_path": "/data/app/y/base.apk"},
                       {"locale": {"lang": "en", "region": "US", "script": ""}}):
            t.labels.put("com.whatsapp", self.entry("com.whatsapp", "WhatsApp", **change))
            self.assertEqual(t.label("com.whatsapp"), "com.whatsapp", change)

    def test_duplicate_names_keep_distinct_rows(self):
        t = self.tab
        for p in ("com.whatsapp", "com.android.calendar.go"):
            t.labels.put(p, self.entry(p, "Settings"))
        t.populate()
        rows = [(t.tree.item("p:" + p, "text"), t.tree.item("p:" + p, "values")[-1])
                for p in ("com.whatsapp", "com.android.calendar.go")]
        self.assertEqual({r[0] for r in rows}, {"Settings"})
        self.assertEqual({r[1] for r in rows}, {"com.whatsapp", "com.android.calendar.go"})

    def test_late_result_from_previous_connection_is_ignored(self):
        t = self.tab
        old_gen = t.label_gen
        t.set_device("OTHER")                                   # new connection
        t.serial = t.scanned_serial = "SER"                     # same serial again, newer generation
        t.apps = {"com.whatsapp": real_app("com.whatsapp")}
        a = t.apps["com.whatsapp"]
        stale = {"com.whatsapp": {"label": "OLD DEVICE NAME", "match": "exact", "error": "", "path": a["path"],
                                  "version_code": str(a["version_code"]), "last_update": str(a["last_update"]),
                                  "system": False}}
        t._labels_ready(old_gen, "SER", t.label_locale, stale)
        self.assertIsNone(t.labels.get("com.whatsapp"))
        self.assertEqual(t.label("com.whatsapp"), "com.whatsapp")
        t._labels_ready(t.label_gen, "SER", t.label_locale, stale)   # the current one is applied
        self.assertEqual(t.label("com.whatsapp"), "OLD DEVICE NAME")

    def test_result_for_changed_app_is_ignored(self):
        t = self.tab
        a = t.apps["com.whatsapp"]
        res = {"com.whatsapp": {"label": "WA", "match": "exact", "error": "", "path": a["path"],
                                "version_code": "1", "last_update": "BEFORE-UPDATE", "system": False}}
        t._labels_ready(t.label_gen, "SER", t.label_locale, res)
        self.assertIsNone(t.labels.get("com.whatsapp"))

    def run_reader(self, budget_mb=200, fail=()):
        t = self.tab
        calls = []

        def parts(serial, path, work, tag, meter):
            pkg = path.split("/")[3]
            calls.append(pkg)
            meter["used"] += 150 << 20                         # counted even when the read then fails
            if pkg in fail:
                raise sa.LabelError("broken")
            mp = os.path.join(work, tag)
            with open(mp, "wb") as f:
                f.write(make_axml(label="Name of " + pkg))
            return {"manifest": {"path": mp, "method": 0}, "arsc": None}
        cfg = dict(sa.load_sec_config(), app_labels_max_mb=budget_mb)
        t.shown_pkg = "com.android.calendar.go"
        # the GUI process must never parse AXML/ARSC itself - only the isolated worker may
        with mock.patch.object(sa, "label_from_parts", side_effect=AssertionError("parsed in the GUI")), \
                mock.patch.object(sa, "axml_app_label", side_effect=AssertionError("parsed in the GUI")), \
                mock.patch.object(sa, "arsc_strings_for", side_effect=AssertionError("parsed in the GUI")), \
                mock.patch.object(am, "read_label_parts", side_effect=parts), \
                mock.patch.object(am, "device_locale", return_value=t.label_locale), \
                mock.patch.object(sa, "load_sec_config", return_value=cfg), \
                mock.patch.object(self.app, "info") as info:
            t.start_label_reader()
            end = time.time() + 20
            while time.time() < end:
                alive = t._label_thread.is_alive()
                try:
                    while True:
                        item = self.app.q.get_nowait()
                        if item[0] == "call":
                            item[1](*item[2:])
                except Exception:
                    pass
                self.root.update()
                if not alive:                           # thread done AND its posts processed
                    break
                time.sleep(0.02)
        return calls, info

    def test_reader_order_budget_and_resume(self):
        calls, info = self.run_reader(budget_mb=200)
        self.assertEqual(calls[0], "com.android.calendar.go")          # selected app first
        self.assertEqual(calls[1], "com.whatsapp")                     # then user apps, then system
        self.assertEqual(len(calls), 2)                                # 150 MB each, 200 MB budget
        self.assertIn("limit", info.call_args[0][0])
        self.assertEqual(self.tab.label("com.whatsapp"), "Name of com.whatsapp")
        calls2, _ = self.run_reader(budget_mb=200)                     # next connection resumes
        self.assertEqual(calls2, ["com.facebook.system"])

    def test_failures_cached_until_update(self):
        calls, _ = self.run_reader(fail={"com.whatsapp"}, budget_mb=1000)
        self.assertIn("com.whatsapp", calls)
        self.assertEqual(self.tab.label("com.whatsapp"), "com.whatsapp")       # failure -> package id
        calls2, _ = self.run_reader(budget_mb=1000)
        self.assertNotIn("com.whatsapp", calls2)                               # not retried ...
        self.tab.apps["com.whatsapp"]["version_code"] = "2"
        calls3, _ = self.run_reader(budget_mb=1000)
        self.assertIn("com.whatsapp", calls3)                                  # ... until it's updated

    def test_turning_off_stops_reading(self):
        t = self.tab
        with mock.patch.object(sa, "save_sec_config"):
            t.read_names.set(False)
            gen = t.label_gen
            t._read_names_toggled()
        self.assertTrue(t.label_stop.is_set())
        self.assertGreater(t.label_gen, gen)
        t.read_names.set(True)



# ==========================================================================
# Round 23 - name reader hardening
# ==========================================================================

class ZipStrictTests(ZipRangeTests):
    """1. ZIP validation and exact reads."""

    def raw_zip(self, entries, comment=b""):
        path = os.path.join(self.d, "z.apk")
        with _zipfile.ZipFile(path, "w") as z:
            for name, data in entries:
                z.writestr(_zipfile.ZipInfo(name), data)
            z.comment = comment
        with open(path, "rb") as f:
            return f.read()

    def parse(self, blob):
        tail = blob[-min(len(blob), 65557):]
        cd_off, cd_size, count = sa.zip_find_cd(tail, len(blob))
        return sa.zip_find_entries(blob[cd_off:cd_off + cd_size], cd_off, count)

    def test_good_zip_and_comment(self):
        blob = self.raw_zip([("AndroidManifest.xml", b"m")], comment=b"hello")
        self.assertIn("AndroidManifest.xml", self.parse(blob))

    def test_eocd_comment_length_must_reach_end(self):
        blob = self.raw_zip([("AndroidManifest.xml", b"m")], comment=b"hello")
        with self.assertRaises(sa.LabelError):
            self.parse(blob + b"junk")                               # bytes after the declared comment
        with self.assertRaises(sa.LabelError):
            self.parse(blob[:-2])                                    # comment cut short

    def test_entry_count_and_full_consumption(self):
        blob = bytearray(self.raw_zip([("AndroidManifest.xml", b"m"), ("b", b"x")]))
        i = blob.rfind(b"PK\x05\x06")
        _st.pack_into("<HH", blob, i + 8, 1, 1)                       # claims 1 entry, directory holds 2
        with self.assertRaises(sa.LabelError):
            self.parse(bytes(blob))

    def test_duplicate_target_entry_rejected(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            blob = self.raw_zip([("AndroidManifest.xml", b"a"), ("AndroidManifest.xml", b"b")])
        with self.assertRaises(sa.LabelError) as cm:
            self.parse(blob)
        self.assertIn("duplicate", str(cm.exception))

    def test_local_header_must_match_and_fit(self):
        blob = self.raw_zip([("AndroidManifest.xml", b"m" * 50)])
        e = self.parse(blob)["AndroidManifest.xml"]
        cd_off = sa.zip_find_cd(blob[-65557:], len(blob))[0]
        lh = blob[e[3]:e[3] + 100]
        self.assertGreater(sa.zip_data_offset(lh, e[3], "AndroidManifest.xml", e[1], cd_off), e[3])
        with self.assertRaises(sa.LabelError):
            sa.zip_data_offset(lh, e[3], "resources.arsc", e[1], cd_off)       # name mismatch
        with self.assertRaises(sa.LabelError):
            sa.zip_data_offset(lh, e[3], "AndroidManifest.xml", cd_off, cd_off)  # data runs into directory

    def test_short_reads_are_errors(self):
        path = self.apk()
        def short(serial, rpath, off, length, timeout=30):
            with open(path, "rb") as f:
                f.seek(off)
                return f.read(max(0, length - 1))                    # always one byte short
        with mock.patch("subprocess.run", side_effect=lambda cmd, **kw: mock.Mock(
                returncode=0, stdout=b"x" * 10)):
            with self.assertRaises(am.AdbError):
                am.remote_read("S", "/data/app/x/base.apk", 0, 100)
        with mock.patch.object(am, "remote_read", side_effect=short), \
                mock.patch.object(am, "remote_size", return_value=os.path.getsize(path)):
            with self.assertRaises((sa.LabelError, am.AdbError)):
                am.read_label_parts("S", "/data/app/x/base.apk", self.d, "a0")


class ParserStrictTests(unittest.TestCase):
    """2. Every nested read stays inside its chunk; declared sizes must match."""
    MAN, ARSC = make_axml(label_ref=0x7F010000), make_arsc(LabelParserTests.VALUES)

    def bad(self, man=None, arsc=None):
        with self.assertRaises(sa.LabelError):
            sa.label_from_parts(man or self.MAN, arsc if arsc is not None else self.ARSC, {"lang": "pt"})

    def test_declared_size_larger_than_buffer(self):
        self.bad(man=self.MAN[:-4])                                  # truncated: size field now too big
        self.bad(arsc=self.ARSC[:-4])

    def test_size_claim_beyond_intact_data(self):
        # every chunk intact, only the header claims 16 more bytes than exist:
        # silently clamping to the buffer would accept this as a full parse
        m = bytearray(self.MAN)
        _st.pack_into("<I", m, 4, len(m) + 16)
        self.bad(man=bytes(m))
        a = bytearray(self.ARSC)
        _st.pack_into("<I", a, 4, len(a) + 16)
        self.bad(arsc=bytes(a))

    def test_trailing_garbage_and_misaligned_chunks(self):
        m = bytearray(self.MAN + b"\x00" * 8)
        _st.pack_into("<I", m, 4, len(m))                            # declared size covers 8 junk bytes
        self.bad(man=bytes(m))

    def test_attribute_array_outside_element(self):
        m = bytearray(self.MAN)
        i = m.rfind(_st.pack("<HH", 0x0102, 16))                     # last element = <application>
        _st.pack_into("<H", m, i + 16 + 8 + 4, 1000)                 # attributeStart far outside
        self.bad(man=bytes(m))

    def test_type_chunk_config_and_entry_offsets(self):
        a = bytearray(self.ARSC)
        i = a.find(_st.pack("<HH", 0x0201, 84))                      # first type chunk (hsize 20+64)
        _st.pack_into("<I", a, i + 20, 4000)                         # config size bigger than the header
        self.bad(arsc=bytes(a))
        a = bytearray(self.ARSC)
        _st.pack_into("<I", a, i + 16, 999999)                       # entriesStart past the chunk
        self.bad(arsc=bytes(a))
        a = bytearray(self.ARSC)
        _st.pack_into("<I", a, i + 84, 5000)                         # entry offset past the chunk
        self.bad(arsc=bytes(a))

    def test_value_size_too_small(self):
        a = bytearray(self.ARSC)
        i = a.find(_st.pack("<HH", 0x0201, 84))
        estart = _st.unpack_from("<I", a, i + 16)[0]
        _st.pack_into("<H", a, i + estart, 2)                        # entry header claims 2 bytes
        self.bad(arsc=bytes(a))


class LimitsAndInflateTests(LabelWorkerTests):
    """3. limits applied inside the child (no preexec_fn); 4. strict inflate."""

    def test_no_preexec_fn_and_limits_in_child(self):
        real = subprocess.Popen
        seen = []

        def spy(*a, **k):
            seen.append(k)
            return real(*a, **k)
        with mock.patch("subprocess.Popen", side_effect=spy):
            sa.run_label_worker(self.files(make_axml(label="A")), {})
        self.assertTrue(seen)
        self.assertNotIn("preexec_fn", seen[0])
        self.assertTrue(seen[0].get("start_new_session"))
        probe = os.path.join(self.d, "probe.py")
        write(probe, "import resource, sys, json\n"
                     "open(sys.argv[1], 'w').write(json.dumps(resource.getrlimit(resource.RLIMIT_AS)))\n")
        out = os.path.join(self.d, "limits.json")
        subprocess.run(sa.limited_cmd(sys.executable, {"mem_bytes": 300 << 20, "cpu_s": 5, "file_bytes": 1 << 20},
                                      probe, out), timeout=30, check=True)
        self.assertEqual(json.loads(read(out))[0], 300 << 20)       # set inside the child, before the script

    def test_inspector_launch_has_no_preexec_fn_either(self):
        import inspect
        self.assertNotIn("preexec_fn=", inspect.getsource(sa.run_inspection))
        self.assertNotIn("preexec_fn=", inspect.getsource(sa.run_label_worker))

    def deflated(self, data, method=8):
        import zlib
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        return c.compress(data) + c.flush()

    def run_spec(self, raw, method=8, size=None):
        mp = os.path.join(self.d, "m")
        with open(mp, "wb") as f:
            f.write(raw)
        spec = {"path": mp, "method": method}
        if size is not None:
            spec["size"] = size
        return sa.run_label_worker([{"id": "com.x", "manifest": spec, "arsc": None}], {})["com.x"]

    def test_valid_deflate_ok(self):
        man = make_axml(label="Good")
        self.assertEqual(self.run_spec(self.deflated(man), size=len(man))["label"], "Good")

    def test_truncated_deflate_rejected(self):
        man = make_axml(label="Good")
        r = self.run_spec(self.deflated(man)[:-6], size=len(man))
        self.assertIsNone(r["label"])

    def test_trailing_data_after_deflate_rejected(self):
        man = make_axml(label="Good")
        self.assertIsNone(self.run_spec(self.deflated(man) + b"EXTRA", size=len(man))["label"])

    def test_size_mismatch_rejected(self):
        man = make_axml(label="Good")
        self.assertIsNone(self.run_spec(self.deflated(man), size=len(man) + 1)["label"])
        self.assertIsNone(self.run_spec(man, method=0, size=len(man) - 1)["label"])

    def test_documentation_says_not_a_sandbox(self):
        src = read(sa.__file__)
        self.assertIn("NOT a sandbox", src)
        self.assertIn("not a sandbox", src)


class ReaderLifecycleTests(AppNameGuiTests):
    """5. the thread always reports back; 6. budget parsing + failed reads counted."""

    def test_top_level_failure_still_reports(self):
        t = self.tab
        with mock.patch.object(am, "device_locale", side_effect=RuntimeError("usb unplugged")), \
                mock.patch.object(self.app, "info") as info:
            t.start_label_reader()
            t._label_thread.join(10)
            self.assertFalse(t._label_thread.is_alive())
            end = time.time() + 5
            while time.time() < end and not info.called:
                try:
                    while True:
                        item = self.app.q.get_nowait()
                        if item[0] == "call":
                            item[1](*item[2:])
                except Exception:
                    pass
                self.root.update()
        self.assertTrue(info.called)
        self.assertIn("unexpected problem", info.call_args[0][0])
        self.assertIn("usb unplugged", info.call_args[0][0])

    def test_budget_parsing_and_clamping(self):
        for raw, want in (("abc", 200), (None, 200), (-5, 1), (0, 1), ("1e9", 2048), (50.7, 50), ("75", 75)):
            self.assertEqual(am.label_budget_mb({"app_labels_max_mb": raw}), want, raw)
        self.assertEqual(am.label_budget_mb({}), 200)

    def test_failed_reads_count_toward_budget(self):
        calls, info = self.run_reader(budget_mb=200, fail={"com.android.calendar.go"})
        self.assertEqual(len(calls), 2)                    # the failure's 150 MB counted: stops after 2
        self.assertIn("limit", info.call_args[0][0])


for _n in [n for n in dir(ZipRangeTests) if n.startswith("test_")]:
    setattr(ZipStrictTests, _n, None)
for _n in [n for n in dir(LabelWorkerTests) if n.startswith("test_")]:
    setattr(LimitsAndInflateTests, _n, None)
for _n in [n for n in dir(AppNameGuiTests) if n.startswith("test_")]:
    setattr(ReaderLifecycleTests, _n, None)



# ==========================================================================
# Round 24 - round-23 review corrections
# ==========================================================================

class Round23CorrectionTests(ZipRangeTests):
    MAN = make_axml(label_ref=0x7F010000)

    def test_short_read_bytes_counted(self):
        """A1: a genuine short read inside read_label_parts still feeds the meter."""
        path = self.apk()
        with open(path, "rb") as f:
            blob = f.read()
        cd_off, cd_size, _ = sa.zip_find_cd(blob[-65557:], len(blob))
        tail_len = min(len(blob), 65535 + 22)
        K = cd_size // 2                                  # bytes of the directory that will arrive
        calls = []

        def run(cmd, **kw):
            m = re.search(r"bs=(\d+) skip=(\d+) count=(\d+)", cmd[-1])
            bs, skip, count = map(int, m.groups())
            calls.append(1)
            data = blob[skip * bs:(skip + count) * bs]
            if len(calls) == 2:                           # the central-directory read comes back short:
                pre = cd_off - skip * bs                  # aligned bytes BEFORE the requested offset ...
                self.assertGreater(pre, 0)
                data = data[:pre + K]                     # ... plus only K bytes of the directory
            return mock.Mock(returncode=0, stdout=data)
        meter = {"used": 0}
        with mock.patch("subprocess.run", side_effect=run), \
                mock.patch.object(am, "remote_size", return_value=len(blob)):
            with self.assertRaises(am.ShortReadError) as cm:
                am.read_label_parts("S", "/data/app/x/base.apk", self.d, "a0", meter)
        self.assertEqual(cm.exception.received, K)                  # exactly the requested bytes that came
        self.assertEqual(meter["used"], tail_len + K)               # aligned prefix NOT counted

    def test_sparse_entries(self):
        """A2: sparse pairs are 4 bytes; sparse + 16-bit offsets is rejected."""
        r = sa.label_from_parts(self.MAN, make_arsc(LabelParserTests.VALUES, mode="sparse"), {"lang": "pt"})
        self.assertEqual(r["label"], "Calendário")
        with self.assertRaises(sa.LabelError):
            sa.label_from_parts(self.MAN, make_arsc(LabelParserTests.VALUES, mode="sparse16"), {"lang": "pt"})
        a = bytearray(make_arsc(LabelParserTests.VALUES, mode="sparse"))
        i = a.find(_st.pack("<HH", 0x0201, 84))
        _st.pack_into("<I", a, i + 12, 50)                 # 50 pairs claimed: 200 bytes, overlap entries
        with self.assertRaises(sa.LabelError):
            sa.label_from_parts(self.MAN, bytes(a), {"lang": "pt"})

    def test_entry_header_must_fit_before_reading(self):
        """A3: an entry offset leaving < 8 bytes in the chunk is rejected."""
        a = bytearray(make_arsc(LabelParserTests.VALUES))
        i = a.find(_st.pack("<HH", 0x0201, 84))
        ts, estart = _st.unpack_from("<I", a, i + 4)[0], _st.unpack_from("<I", a, i + 16)[0]
        _st.pack_into("<I", a, i + 84, ts - estart - 4)    # entry starts 4 bytes before chunk end
        with self.assertRaises(sa.LabelError):
            sa.label_from_parts(self.MAN, bytes(a), {"lang": "pt"})

    def test_stored_entry_output_cap(self):
        """A4: stored data above the output cap is rejected like deflated data."""
        mp = os.path.join(self.d, "m")
        with open(mp, "wb") as f:
            f.write(self.MAN)
        rp, jp = os.path.join(self.d, "res.json"), os.path.join(self.d, "job.json")
        with open(jp, "w") as f:
            json.dump({"items": [{"id": "x", "manifest": {"path": mp, "method": 0, "size": len(self.MAN)},
                                  "arsc": None}], "locale": {}, "result": rp}, f)
        with mock.patch.object(sa, "LABEL_MAX_MANIFEST_OUT", 16):
            sa._label_worker(jp)
        r = json.loads(read(rp))["results"]["x"]
        self.assertIsNone(r["label"])
        self.assertIn("LabelError", r["error"])

    def test_zip64_entry_sentinels(self):
        """A5: ZIP64 sentinels in a target entry are rejected."""
        path = os.path.join(self.d, "z.apk")
        with _zipfile.ZipFile(path, "w") as z:
            z.writestr("AndroidManifest.xml", b"m")
        with open(path, "rb") as f:
            blob = f.read()
        cd_off, cd_size, count = sa.zip_find_cd(blob[-65557:], len(blob))
        for field in (20, 24, 42):                          # comp size, size, local header offset
            cd = bytearray(blob[cd_off:cd_off + cd_size])
            _st.pack_into("<I", cd, field, 0xFFFFFFFF)
            with self.assertRaises(sa.LabelError):
                sa.zip_find_entries(bytes(cd), cd_off, count)


for _n in [n for n in dir(ZipRangeTests) if n.startswith("test_")]:
    setattr(Round23CorrectionTests, _n, None)



# ==========================================================================
# Round 26 - Autorun milestone 1: read-only detection
# ==========================================================================

REDMI_QUERY = """132 receivers found:
  Receiver #0:
    priority=2147483647 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
    com.android.traceur/.Receiver
  Receiver #2:
    priority=1000 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
    android/com.android.server.BootReceiver
  Receiver #6:
    priority=999 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
    com.android.deskclock.go/com.android.deskclock.AlarmInitReceiver
  Receiver #9:
    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true
    org.videolan.vlc/.TvReceiver
"""

OLD_RESOLVER = """Activity Resolver Table:
  Non-Data Actions:
      android.intent.action.MAIN:
        41c2 com.foo/.Main filter 9a1b

Receiver Resolver Table:
  Non-Data Actions:
      android.intent.action.BOOT_COMPLETED:
        4f1a2b3 com.old.app/.BootReceiver filter 1c2d3e
        5a6b7c8 com.other/com.other.Starter filter 2d3e4f
      android.intent.action.SCREEN_ON:
        6b7c8d9 com.noise/.ScreenRx filter 3e4f5a
      "android.intent.action.LOCKED_BOOT_COMPLETED":
        7c8d9e0 com.old.app/.BootReceiver filter 4f5a6b

Service Resolver Table:
      android.intent.action.BOOT_COMPLETED:
        8d9e0f1 com.notareceiver/.Svc filter 5a6b7c
"""

VLC_DUMPSYS = """Packages:
  Package [org.videolan.vlc] (3f1a2b):
    userId=10123
    User 0: ceDataInode=12345 installed=true hidden=false suspended=false distractionFlags=0 stopped=false notLaunched=false enabled=0 instant=false virtual=false
      gids=[3003]
      runtime permissions:
        android.permission.POST_NOTIFICATIONS: granted=true
      disabledComponents:
        org.videolan.vlc.widget.VLCAppWidgetProviderBlack
        org.videolan.vlc.widget.VLCAppWidgetProviderWhite
      enabledComponents:
        org.videolan.vlc.ExtraRx
    User 10: ceDataInode=99 installed=true hidden=false enabled=3 instant=false
      disabledComponents:
        org.videolan.vlc.TvReceiver
"""


class AutorunParserTests(unittest.TestCase):
    def test_full_component(self):
        self.assertEqual(am.full_component("org.videolan.vlc/.TvReceiver"), ("org.videolan.vlc", "org.videolan.vlc.TvReceiver"))
        self.assertEqual(am.full_component("android/com.android.server.BootReceiver"),
                         ("android", "com.android.server.BootReceiver"))
        self.assertIsNone(am.full_component("priority=0 preferredOrder=0"))
        self.assertIsNone(am.full_component("Receiver #9:"))

    def test_query_output_from_a_real_phone(self):
        self.assertEqual(am.parse_query_receivers(REDMI_QUERY), [
            ("com.android.traceur", "com.android.traceur.Receiver"),
            ("android", "com.android.server.BootReceiver"),
            ("com.android.deskclock.go", "com.android.deskclock.AlarmInitReceiver"),
            ("org.videolan.vlc", "org.videolan.vlc.TvReceiver")])

    def test_old_resolver_table(self):
        got = am.parse_receiver_resolver(OLD_RESOLVER)
        self.assertEqual(got[("com.old.app", "com.old.app.BootReceiver")],
                         {"android.intent.action.BOOT_COMPLETED", "android.intent.action.LOCKED_BOOT_COMPLETED"})
        self.assertIn(("com.other", "com.other.Starter"), got)
        self.assertNotIn(("com.noise", "com.noise.ScreenRx"), got)           # not a boot action
        self.assertNotIn(("com.notareceiver", "com.notareceiver.Svc"), got)  # service table, not receivers

    def test_user_state_per_user(self):
        u0 = am.parse_package_user_state(VLC_DUMPSYS, 0)
        self.assertEqual(u0["pkg_state"], 0)
        self.assertEqual(u0["disabled"], {"org.videolan.vlc.widget.VLCAppWidgetProviderBlack",
                                          "org.videolan.vlc.widget.VLCAppWidgetProviderWhite"})
        self.assertEqual(u0["enabled"], {"org.videolan.vlc.ExtraRx"})
        u10 = am.parse_package_user_state(VLC_DUMPSYS, 10)               # never assume user 0
        self.assertEqual((u10["pkg_state"], u10["disabled"]), (3, {"org.videolan.vlc.TvReceiver"}))
        self.assertFalse(am.parse_package_user_state(VLC_DUMPSYS, 5)["found"])

    def test_state_words(self):
        st = am.parse_package_user_state(VLC_DUMPSYS, 0)
        self.assertEqual(am.receiver_state_word("org.videolan.vlc.TvReceiver", st), "DEFAULT")
        self.assertEqual(am.receiver_state_word("org.videolan.vlc.ExtraRx", st), "ENABLED")
        self.assertEqual(am.receiver_state_word("org.videolan.vlc.widget.VLCAppWidgetProviderBlack", st), "DISABLED")
        self.assertEqual(am.receiver_state_word("x", None), "UNKNOWN")
        self.assertEqual(am.receiver_state_word("x", {"found": False}), "UNKNOWN")

    def test_current_user(self):
        def sh(answers):
            return lambda serial, cmd, timeout=15: answers.get(cmd.split()[0] + " " + cmd.split()[1],
                                                                (255, "", "Unknown command"))
        with mock.patch.object(am, "adb_shell", side_effect=sh({"am get-current-user": (0, "10\n", "")})):
            self.assertEqual(am.current_user("S"), (10, "detected"))
        with mock.patch.object(am, "adb_shell", side_effect=sh({"am get-current-user": (0, "0\n", "")})):
            self.assertEqual(am.current_user("S"), (0, "detected"))
        one = "Users:\n\tUserInfo{0:Owner:c13} running\n"
        many = one + "\tUserInfo{10:Work:30} running\n"
        with mock.patch.object(am, "adb_shell", side_effect=sh({"pm list": (0, one, "")})):
            self.assertEqual(am.current_user("S"), (0, "single-user"))       # failed, but user 0 is the only one
        with mock.patch.object(am, "adb_shell", side_effect=sh({"pm list": (0, many, "")})):
            self.assertEqual(am.current_user("S"), (0, "unverified"))        # several users: not verified
        with mock.patch.object(am, "adb_shell", side_effect=am.AdbError("offline")):
            self.assertEqual(am.current_user("S"), (0, "unverified"))        # no way to establish it


class AutorunDetectionTests(unittest.TestCase):
    def shell(self, flag_ok=True, query_ok=True, resolver=OLD_RESOLVER):
        calls = []

        def sh(serial, cmd, timeout=30):
            calls.append(cmd)
            if cmd.startswith("cmd package query-receivers"):
                if not query_ok:
                    return 127, "", "/system/bin/sh: cmd: not found"
                if am.QUERY_FLAGS in cmd and not flag_ok:
                    return 255, "", "Error: Unknown option: --query-flags"
                if "BOOT_COMPLETED" in cmd and "LOCKED" not in cmd:
                    return 0, REDMI_QUERY, ""
                return 0, "No receivers found\n", ""
            if cmd.startswith("dumpsys package r"):
                return 0, resolver, ""
            return 0, "", ""
        return sh, calls

    def test_query_with_disabled_components_is_complete(self):
        sh, calls = self.shell()
        with mock.patch.object(am, "adb_shell", side_effect=sh):
            r = am.detect_boot_receivers("S", 10)
        self.assertTrue(r["complete"])
        self.assertTrue(r["disabled_included"])
        self.assertIn(("org.videolan.vlc", "org.videolan.vlc.TvReceiver"), r["receivers"])
        self.assertTrue(all("--user 10" in c for c in calls if c.startswith("cmd package")))   # scoped to user
        self.assertTrue(any("--query-flags %s" % am.QUERY_FLAGS in c for c in calls))

    def test_flag_rejected_retries_and_says_partial(self):
        sh, calls = self.shell(flag_ok=False)
        with mock.patch.object(am, "adb_shell", side_effect=sh):
            r = am.detect_boot_receivers("S", 0)
        self.assertFalse(r["complete"])
        self.assertIn(("org.videolan.vlc", "org.videolan.vlc.TvReceiver"), r["receivers"])
        self.assertIn("switched off", " ".join(r["notes"]))

    def test_old_android_falls_back_to_resolver_table(self):
        sh, calls = self.shell(query_ok=False)
        with mock.patch.object(am, "adb_shell", side_effect=sh):
            r = am.detect_boot_receivers("S", 0)
        self.assertEqual(r["method"], "dumpsys receiver table")
        self.assertFalse(r["complete"])
        self.assertIn(("com.old.app", "com.old.app.BootReceiver"), r["receivers"])

    def test_receiver_states_unknown_on_failure(self):
        with mock.patch.object(am, "adb_shell", side_effect=am.AdbError("gone")):
            self.assertEqual(am.receiver_states("S", 0, {"a.b"}), {"a.b": None})


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class AutorunTabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()
        args = mock.Mock(serial=None, local=TMP_HOME, remote="/sdcard")
        with mock.patch.object(am.App, "scan_devices", lambda self, *a, **k: None):
            cls.app = am.App(cls.root, args)
        cls.tab = cls.app.autorun_tab

    @classmethod
    def tearDownClass(cls):
        destroy_root(cls.root)

    def data(self):
        st = am.parse_package_user_state(VLC_DUMPSYS, 0)
        return {"receivers": {("org.videolan.vlc", "org.videolan.vlc.TvReceiver"): {"actions": {am.BOOT_ACTIONS[0]}},
                              ("com.android.traceur", "com.android.traceur.Receiver"): {"actions": {am.BOOT_ACTIONS[0]}}},
                "method": "Package Manager query", "disabled_included": True, "complete": True, "notes": [],
                "user": 0, "user_source": "detected",
                "states": {"org.videolan.vlc": st, "com.android.traceur": None}}

    def setUp(self):
        self.app.apps_tab.apps = {"com.android.traceur": real_app("com.android.traceur", True),
                                  "org.videolan.vlc": real_app("org.videolan.vlc")}
        self.tab.serial, self.tab.data = "SER", None

    def test_tab_registered(self):
        self.assertIn("Autorun", [self.app.nb.tab(t, "text").strip() for t in self.app.nb.tabs()])

    def test_list_hides_system_by_default_and_shows_state(self):
        t = self.tab
        t._done(t.gen, "SER", self.data(), None)
        self.assertEqual(t.tree.get_children(), ("p:org.videolan.vlc",))
        kid = t.tree.get_children("p:org.videolan.vlc")[0]
        self.assertEqual(t.tree.item(kid, "values")[1], "DEFAULT - manifest decides")
        self.assertIn("1 system app(s) hidden", t.status.cget("text"))
        self.assertIn("Receiver inventory: complete Package Manager query for this user, including switched-off "
                      "and off-until-used receivers", t.status.cget("text"))
        self.assertIn("not yet cross-checked", t.status.cget("text"))
        t.show_sys.set(True)
        t.populate()
        self.assertEqual(len(t.tree.get_children()), 2)
        t.show_sys.set(False)

    def test_partial_detection_is_said(self):
        t = self.tab
        d = dict(self.data(), complete=False, notes=["may miss switched-off receivers"])
        t._done(t.gen, "SER", d, None)
        self.assertIn("PARTIAL", t.status.cget("text"))

    def test_late_result_for_previous_device_ignored(self):
        t = self.tab
        gen = t.gen
        t.set_device("OTHER")
        t._done(gen, "SER", self.data(), None)
        self.assertIsNone(t.data)

    def test_error_reported(self):
        t = self.tab
        t.busy = True
        t._done(t.gen, "SER", None, "AdbError: device offline")
        self.assertIn("device offline", t.status.cget("text"))
        self.assertFalse(t.busy)

    def test_detail_says_capability_not_proof(self):
        t = self.tab
        t._done(t.gen, "SER", self.data(), None)
        t.tree.selection_set("p:org.videolan.vlc")
        t.on_select()
        self.assertIn("doesn't prove", t.detail.get("1.0", "end"))

    def test_worker_always_reports(self):
        t = self.tab
        with mock.patch.object(am, "current_user", side_effect=RuntimeError("boom")):
            t._work(t.gen, "SER")
        item = self.app.q.get_nowait()
        while item[1] != t._done:
            item = self.app.q.get_nowait()
        self.assertIn("boom", item[5])



# ---- Open shell button -----------------------------------------------------

class OpenShellTests(unittest.TestCase):
    def which(self, present):
        return lambda name: ("/usr/bin/" + name) if name in present else None

    def test_terminal_choice_order(self):
        with mock.patch.dict(os.environ, {"TERMINAL": ""}), mock.patch("shutil.which",
                                                                       side_effect=self.which({"xterm", "konsole"})):
            self.assertEqual(am.find_terminal(), ("/usr/bin/konsole", "-e", "argv", []))  # list order
        with mock.patch.dict(os.environ, {"TERMINAL": "kitty"}), mock.patch("shutil.which",
                                                                            side_effect=self.which({"kitty", "xterm"})):
            self.assertEqual(am.find_terminal(), ("/usr/bin/kitty", "", "argv", []))      # $TERMINAL wins
        with mock.patch.dict(os.environ, {"TERMINAL": "myterm"}), mock.patch("shutil.which",
                                                                             side_effect=self.which({"myterm"})):
            self.assertEqual(am.find_terminal(), ("/usr/bin/myterm", "-e", "argv", []))  # unknown: -e
        with mock.patch.dict(os.environ, {"TERMINAL": ""}), mock.patch("shutil.which", return_value=None):
            self.assertIsNone(am.find_terminal())

    def test_command_styles(self):
        self.assertEqual(am.shell_command(("/usr/bin/gnome-terminal", "--", "argv"), "ABC123"),
                         ["/usr/bin/gnome-terminal", "--", am.ADB, "-s", "ABC123", "shell"])
        self.assertEqual(am.shell_command(("/usr/bin/kitty", "", "argv"), "ABC123"),
                         ["/usr/bin/kitty", am.ADB, "-s", "ABC123", "shell"])
        cmd = am.shell_command(("/usr/bin/tilix", "-e", "string"), "ABC123")
        self.assertEqual(cmd[:2], ["/usr/bin/tilix", "-e"])
        self.assertEqual(shlex.split(cmd[2]), [am.ADB, "-s", "ABC123", "shell"])

    def test_hostile_serial_stays_one_argument(self):
        evil = "x; rm -rf ~ #"
        argv = am.shell_command(("/usr/bin/xterm", "-e", "argv"), evil)
        self.assertEqual(argv[argv.index("-s") + 1], evil)                 # a single argv word, no shell
        s_mode = am.shell_command(("/usr/bin/lxterminal", "-e", "string"), evil)
        self.assertEqual(shlex.split(s_mode[2])[2], evil)                  # quoted in string mode

    def test_open_device_shell(self):
        self.assertIn("No device", am.open_device_shell(None))
        with mock.patch.object(am, "find_terminal", return_value=None):
            self.assertIn("No terminal program", am.open_device_shell("SER"))
        with mock.patch.object(am, "find_terminal", return_value=("/usr/bin/xterm", "-e", "argv")), \
                mock.patch("subprocess.Popen") as po:
            self.assertIsNone(am.open_device_shell("SER"))
        args, kw = po.call_args
        self.assertEqual(args[0], ["/usr/bin/xterm", "-e", am.ADB, "-s", "SER", "shell"])
        self.assertTrue(kw["start_new_session"])
        self.assertNotIn("shell", kw)                                       # never shell=True
        with mock.patch.object(am, "find_terminal", return_value=("/usr/bin/xterm", "-e", "argv")), \
                mock.patch("subprocess.Popen", side_effect=OSError(2, "No such file")):
            self.assertIn("Couldn't start xterm", am.open_device_shell("SER"))


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class OpenShellButtonTests(AutorunTabTests):
    def test_button_reports(self):
        t = self.tab
        self.assertEqual(t.shell_btn.cget("text"), "Open shell")
        with mock.patch.object(am, "open_device_shell", return_value=None), \
                mock.patch.object(self.app, "info") as info:
            t.open_shell()
        self.assertIn("Started a terminal for an ADB shell", info.call_args[0][0])
        with mock.patch.object(am, "open_device_shell", return_value="No terminal program was found."), \
                mock.patch.object(self.app, "error") as err:
            t.open_shell()
        self.assertIn("No terminal", err.call_args[0][0])


for _n in [n for n in dir(AutorunTabTests) if n.startswith("test_")]:
    setattr(OpenShellButtonTests, _n, None)



# ==========================================================================
# Round 27 - Autorun milestone 1 corrections
# ==========================================================================

class AutorunFallbackTests(AutorunDetectionTests):
    """3. the full dumpsys fallback runs whenever the short one fails or is empty."""

    def run_fallback(self, r_answer, full_answer):
        def sh(serial, cmd, timeout=30):
            if cmd.startswith("cmd package query-receivers"):
                return 127, "", "/system/bin/sh: cmd: not found"
            if cmd == "dumpsys package r":
                return r_answer
            if cmd == "dumpsys package":
                return full_answer
            return 0, "", ""
        with mock.patch.object(am, "adb_shell", side_effect=sh):
            return am.detect_boot_receivers("S", 0)

    def test_short_table_ok(self):
        r = self.run_fallback((0, OLD_RESOLVER, ""), (1, "", "should not be needed"))
        self.assertEqual(r["method"], "dumpsys receiver table")
        self.assertIn(("com.old.app", "com.old.app.BootReceiver"), r["receivers"])

    def test_short_ok_but_no_table(self):
        r = self.run_fallback((0, "Packages:\n  nothing here\n", ""), (0, OLD_RESOLVER, ""))
        self.assertIn(("com.old.app", "com.old.app.BootReceiver"), r["receivers"])

    def test_short_fails_full_ok(self):
        r = self.run_fallback((1, "", "Unknown option r"), (0, OLD_RESOLVER, ""))
        self.assertIn(("com.old.app", "com.old.app.BootReceiver"), r["receivers"])
        self.assertEqual(r["method"], "dumpsys receiver table")

    def test_both_fail(self):
        r = self.run_fallback((1, "", "x"), (1, "", "y"))
        self.assertEqual((r["method"], r["receivers"], r["complete"]), ("nothing worked", {}, False))
        self.assertIn("couldn't be read", " ".join(r["notes"]))

    def test_both_ok_no_boot_receivers(self):
        empty = "Receiver Resolver Table:\n  Non-Data Actions:\n      android.intent.action.SCREEN_ON:\n" \
                "        1 com.x/.Rx filter 2\n"
        r = self.run_fallback((0, empty, ""), (0, empty, ""))
        self.assertEqual((r["method"], r["receivers"]), ("dumpsys receiver table", {}))
        self.assertFalse(r["complete"])
        self.assertIn("lists no start-up receivers", " ".join(r["notes"]))     # found, but empty

    def test_component_named_exception_is_not_an_error(self):
        """6. 'Exception' inside a class name must not look like a failed command."""
        out = "1 receivers found:\n  Receiver #0:\n    priority=0\n    com.example/.ExceptionReceiver\n"
        self.assertFalse(am.query_error(out))
        self.assertTrue(am.query_error("Exception occurred while executing 'query-receivers':\n"))
        self.assertTrue(am.query_error("Error: Unknown option: --query-flags\n"))
        self.assertTrue(am.query_error("/system/bin/sh: cmd: not found"))

        def sh(serial, cmd, timeout=30):
            if cmd.startswith("cmd package query-receivers") and "BOOT_COMPLETED" in cmd and "LOCKED" not in cmd:
                return 0, out, ""
            return 0, "No receivers found\n", ""
        with mock.patch.object(am, "adb_shell", side_effect=sh):
            r = am.detect_boot_receivers("S", 0)
        self.assertIn(("com.example", "com.example.ExceptionReceiver"), r["receivers"])
        self.assertTrue(r["complete"])


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class AutorunCorrectionGuiTests(AutorunTabTests):
    def pump(self, until, timeout=10):
        end = time.time() + timeout
        while time.time() < end and not until():
            try:
                while True:
                    item = self.app.q.get_nowait()
                    if item[0] == "call":
                        item[1](*item[2:])
            except Exception:
                pass
            self.root.update()
            time.sleep(0.02)
        return until()

    def fake_device(self, serial_receivers):
        def det(serial, user):
            return {"receivers": serial_receivers[serial], "method": "Package Manager query",
                    "disabled_included": True, "complete": True, "notes": []}
        return [mock.patch.object(am, "current_user", return_value=(0, "detected")),
                mock.patch.object(am, "detect_boot_receivers", side_effect=det),
                mock.patch.object(am, "receiver_states", return_value={})]

    def test_device_change_mid_refresh_frees_the_tab(self):
        """1. A running, switch to B, A's late result ignored, B refreshes and shows."""
        t = self.tab
        t.serial, t.busy = "A", True                       # a refresh for A is in flight
        old_gen = t.gen
        t.refresh_btn.state(["disabled"])
        t.set_device("B")
        self.assertFalse(t.busy)
        self.assertNotIn("disabled", t.refresh_btn.state())
        t._done(old_gen, "A", self.data(), None)           # A's result arrives late
        self.assertIsNone(t.data)
        rec_b = {("org.videolan.vlc", "org.videolan.vlc.TvReceiver"): {"actions": {am.BOOT_ACTIONS[0]}}}
        p = self.fake_device({"B": rec_b})
        for x in p:
            x.start()
        try:
            t.refresh()
            self.assertTrue(self.pump(lambda: t.data is not None))
        finally:
            for x in p:
                x.stop()
        self.assertEqual(list(t.data["receivers"]), list(rec_b))
        self.assertEqual(t.tree.get_children(), ("p:org.videolan.vlc",))

    def test_disconnect_then_reconnect(self):
        t = self.tab
        t.serial, t.busy = "A", True
        t.set_device(None)                                 # unplugged mid-refresh
        self.assertFalse(t.busy)
        t.set_device("A")
        p = self.fake_device({"A": {}})
        for x in p:
            x.start()
        try:
            t.refresh()
            self.assertTrue(self.pump(lambda: t.data is not None))
        finally:
            for x in p:
                x.stop()

    def test_unverified_user_is_disclosed(self):
        """2. a fallback user 0 is never presented as the verified current user."""
        t = self.tab
        d = dict(self.data(), user_source="unverified", complete=False,
                 notes=["the current Android user couldn't be established"])
        t._done(t.gen, "SER", d, None)
        self.assertIn("Current user: NOT VERIFIED", t.status.cget("text"))
        self.assertIn("NOT verified", t.status.cget("text"))
        kid = t.tree.get_children("p:org.videolan.vlc")[0]
        self.assertIn("not verified", t.tree.item(kid, "values")[1])
        d = dict(self.data(), user_source="single-user")
        t._done(t.gen, "SER", d, None)
        self.assertNotIn("NOT VERIFIED", t.status.cget("text"))
        self.assertIn("the only user", t.status.cget("text"))

    def test_default_never_shown_as_on(self):
        """4. DEFAULT / package state 0 are never worded as 'on'."""
        self.assertNotIn("on", am.AutorunTab.STATE_WORDS["DEFAULT"].lower().replace("decides", ""))
        self.assertEqual(am.PKG_STATE_WORDS[0], "DEFAULT (manifest decides)")
        t = self.tab
        t._done(t.gen, "SER", self.data(), None)
        t.tree.selection_set("p:org.videolan.vlc")
        t.on_select()
        self.assertIn("DEFAULT (manifest decides)", t.detail.get("1.0", "end"))

    def test_results_before_apps_scan_are_unclassified(self):
        """7. unknown system/user is shown honestly, then fixed once the Apps scan finishes."""
        t = self.tab
        self.app.apps_tab.apps = {}                        # Apps scan not finished
        t._done(t.gen, "SER", self.data(), None)
        self.assertEqual(len(t.tree.get_children()), 2)    # nothing hidden as "system" on a guess
        self.assertIn("not yet known as system or user", t.status.cget("text"))
        self.assertIn("not known yet", t.tree.item("p:com.android.traceur", "values")[1])
        self.app.apps_tab.apps = {"com.android.traceur": real_app("com.android.traceur", True),
                                  "org.videolan.vlc": real_app("org.videolan.vlc")}
        t.populate()
        self.assertEqual(t.tree.get_children(), ("p:org.videolan.vlc",))


for _n in [n for n in dir(AutorunDetectionTests) if n.startswith("test_")]:
    setattr(AutorunFallbackTests, _n, None)
for _n in [n for n in dir(AutorunTabTests) if n.startswith("test_")]:
    setattr(AutorunCorrectionGuiTests, _n, None)



# ==========================================================================
# Round 28 - round-27 review corrections
# ==========================================================================

class Round27DetectionTests(AutorunFallbackTests):
    def test_unscoped_query_is_disclosed(self):
        """1. if only the query WITHOUT --user worked, that's said and the result is partial."""
        def sh(serial, cmd, timeout=30):
            if cmd.startswith("cmd package query-receivers"):
                if "--user" in cmd:
                    return 255, "", "Error: Unknown option: --user"
                return 0, REDMI_QUERY if ("BOOT_COMPLETED" in cmd and "LOCKED" not in cmd) else "", ""
            return 0, "", ""
        with mock.patch.object(am, "adb_shell", side_effect=sh):
            r = am.detect_boot_receivers("S", 10)
        self.assertIn(("org.videolan.vlc", "org.videolan.vlc.TvReceiver"), r["receivers"])
        self.assertTrue(r["disabled_included"])            # the flag alone still worked ...
        self.assertFalse(r["user_scoped"])                 # ... but --user didn't
        self.assertFalse(r["complete"])                    # so NOT complete, for the scoping reason alone
        self.assertIn("couldn't be scoped to the selected Android user", " ".join(r["notes"]))

    def test_dumpsys_without_table_marker(self):
        """2. success without a receiver table is NOT presented as reading the table."""
        r = self.run_fallback((0, "Packages:\n  x\n", ""), (0, "Packages:\n  y\n", ""))
        self.assertEqual(r["method"], "nothing usable")
        self.assertIn("contained no receiver table", " ".join(r["notes"]))
        self.assertNotIn("older receiver table that may miss", " ".join(r["notes"]))

    def test_partial_query_kept_when_fallback_fails(self):
        def sh(serial, cmd, timeout=30):
            if cmd.startswith("cmd package query-receivers"):
                if "BOOT_COMPLETED" in cmd and "LOCKED" not in cmd:
                    return 0, REDMI_QUERY, ""
                return 1, "", "Error: something"                 # other actions fail
            if cmd.startswith("dumpsys package"):
                return 1, "", "dumpsys failed"
            return 0, "", ""
        with mock.patch.object(am, "adb_shell", side_effect=sh):
            r = am.detect_boot_receivers("S", 0)
        self.assertIn(("org.videolan.vlc", "org.videolan.vlc.TvReceiver"), r["receivers"])   # kept
        self.assertEqual(r["method"], "Package Manager query (some start-up events only)")
        self.assertIn("fallback was unavailable", " ".join(r["notes"]))
        self.assertNotIn("older receiver table", " ".join(r["notes"]))
        self.assertFalse(r["complete"])


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class Round27GuiTests(AutorunCorrectionGuiTests):
    def test_inventory_and_user_reported_separately(self):
        """3. a complete inventory stays complete; the unverified user is a separate line."""
        t = self.tab
        d = dict(self.data(), user_source="unverified", user_verified=False)       # complete stays True
        t._done(t.gen, "SER", d, None)
        text = t.status.cget("text")
        self.assertIn("Receiver inventory: complete Package Manager query", text)
        self.assertIn("Current user: NOT VERIFIED", text)
        self.assertTrue(t.data["complete"])

    def test_worker_does_not_downgrade_inventory_for_unverified_user(self):
        t = self.tab
        rec = {("org.videolan.vlc", "org.videolan.vlc.TvReceiver"): {"actions": {am.BOOT_ACTIONS[0]}}}
        with mock.patch.object(am, "current_user", return_value=(0, "unverified")), \
                mock.patch.object(am, "detect_boot_receivers", return_value={
                    "receivers": rec, "method": "Package Manager query", "disabled_included": True,
                    "user_scoped": True, "complete": True, "notes": []}), \
                mock.patch.object(am, "receiver_states", return_value={}):
            t.busy = True
            t._work(t.gen, "SER")
            self.assertTrue(self.pump(lambda: t.data is not None))
        self.assertTrue(t.data["complete"])
        self.assertFalse(t.data["user_verified"])

    def test_record_without_system_field_is_unknown(self):
        """4. an Apps record whose system flag isn't known is not treated as a user app."""
        t = self.tab
        rec = real_app("com.android.traceur", True)
        rec["system"] = None
        self.app.apps_tab.apps = {"com.android.traceur": rec, "org.videolan.vlc": real_app("org.videolan.vlc")}
        self.assertIsNone(t.is_system("com.android.traceur"))
        t._done(t.gen, "SER", self.data(), None)
        self.assertIn("not known yet", t.tree.item("p:com.android.traceur", "values")[1])


class TerminalEnvTests(unittest.TestCase):
    """5. $TERMINAL with arguments; 6. the app's own adb everywhere."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_terminal_with_arguments(self):
        with mock.patch.dict(os.environ, {"TERMINAL": "kitty --single-instance"}), \
                mock.patch("shutil.which", side_effect=lambda n: "/usr/bin/" + n if n == "kitty" else None):
            term = am.find_terminal()
        self.assertEqual(term, ("/usr/bin/kitty", "", "argv", ["--single-instance"]))
        self.assertEqual(am.shell_command(term, "SER"),
                         ["/usr/bin/kitty", "--single-instance", am.ADB, "-s", "SER", "shell"])

    def test_quoted_path_with_spaces(self):
        exe = os.path.join(self.d, "my term", "term")
        os.makedirs(os.path.dirname(exe))
        write(exe, "#!/bin/sh\n")
        os.chmod(exe, 0o755)
        with mock.patch.dict(os.environ, {"TERMINAL": '"%s" -x' % exe}):
            term = am.find_terminal()
        self.assertEqual(term[0], exe)
        self.assertEqual(term[3], ["-x"])

    def test_missing_configured_terminal_falls_back(self):
        with mock.patch.dict(os.environ, {"TERMINAL": "no-such-terminal --flag"}), \
                mock.patch("shutil.which", side_effect=lambda n: "/usr/bin/xterm" if n == "xterm" else None):
            self.assertEqual(am.find_terminal(), ("/usr/bin/xterm", "-e", "argv", []))
        with mock.patch.dict(os.environ, {"TERMINAL": '"unbalanced'}), \
                mock.patch("shutil.which", side_effect=lambda n: "/usr/bin/xterm" if n == "xterm" else None):
            self.assertEqual(am.find_terminal()[0], "/usr/bin/xterm")

    def test_empty_terminal(self):
        with mock.patch.dict(os.environ, {"TERMINAL": "   "}), \
                mock.patch("shutil.which", side_effect=lambda n: "/usr/bin/xterm" if n == "xterm" else None):
            self.assertEqual(am.find_terminal(), ("/usr/bin/xterm", "-e", "argv", []))

    def test_terminal_args_with_hostile_serial(self):
        evil = "x; rm -rf ~ #"
        argv = am.shell_command(("/usr/bin/xterm", "-e", "argv", ["-fa", "Mono"]), evil)
        self.assertEqual(argv[:4], ["/usr/bin/xterm", "-fa", "Mono", "-e"])
        self.assertEqual(argv[argv.index("-s") + 1], evil)
        s_mode = am.shell_command(("/usr/bin/tilix", "-e", "string", ["--new-process"]), evil)
        self.assertEqual(s_mode[:3], ["/usr/bin/tilix", "--new-process", "-e"])
        self.assertEqual(shlex.split(s_mode[3])[2], evil)

    def test_configured_adb_used_everywhere(self):
        odd = "/opt/android platform tools/adb"
        with mock.patch.object(am, "ADB", odd):
            argv = am.shell_command(("/usr/bin/xterm", "-e", "argv", []), "SER")
            self.assertEqual(argv[2], odd)                              # not a PATH 'adb'
            s_mode = am.shell_command(("/usr/bin/lxterminal", "-e", "string", []), "SER")
            self.assertEqual(shlex.split(s_mode[2])[0], odd)
            hint = am.manual_shell_hint("SER 1")
            self.assertEqual(shlex.split(hint), [odd, "-s", "SER 1", "shell"])   # pasteable as-is
            with mock.patch.object(am, "find_terminal", return_value=None):
                self.assertIn(shlex.quote(odd), am.open_device_shell("SER"))


for _n in [n for n in dir(AutorunFallbackTests) if n.startswith("test_")]:
    setattr(Round27DetectionTests, _n, None)
for _n in [n for n in dir(AutorunCorrectionGuiTests) if n.startswith("test_")]:
    setattr(Round27GuiTests, _n, None)



# ==========================================================================
# Round 29 - round-28 review corrections
# ==========================================================================

UNTIL_USED_DUMPSYS = """Packages:
  Package [com.carrier.setup] (1a2b):
    User 0: ceDataInode=1 installed=true hidden=false enabled=4 instant=false
"""


class Round28DetectionTests(AutorunFallbackTests):
    def test_heading_must_be_a_real_section(self):
        """1. the words inside ordinary output are not a found table."""
        prose = ("Packages:\n  Package [com.x] (1):\n    description=Explains the Receiver Resolver Table: see docs\n"
                 "    note: Receiver Resolver Table missing on this build\n")
        self.assertFalse(am.has_receiver_resolver(prose))
        self.assertTrue(am.has_receiver_resolver(OLD_RESOLVER))
        self.assertEqual(am.parse_receiver_resolver(prose), {})
        r = self.run_fallback((0, prose, ""), (0, prose, ""))
        self.assertEqual(r["method"], "nothing usable")
        self.assertIn("contained no receiver table", " ".join(r["notes"]))

    def test_resolver_inventory_scope_not_established(self):
        """2. an older-device fallback never claims a user-scoped inventory."""
        r = self.run_fallback((0, OLD_RESOLVER, ""), (1, "", ""))
        self.assertEqual(r["inventory_scope"], "resolver")
        self.assertIn("per-user inventory scope not established", " ".join(r["notes"]))
        self.assertFalse(r["complete"])

    def test_until_used_package_included(self):
        """3. 0x8200 asks for disabled AND off-until-used components; such a package's
        receivers are listed and the package is shown as OFF until used."""
        def sh(serial, cmd, timeout=30):
            if cmd.startswith("cmd package query-receivers"):
                body = "    com.example/.BootRx\n"
                if am.QUERY_FLAGS in cmd:                          # only the combined flags reveal it
                    body += "    com.carrier.setup/.SetupBootRx\n"
                return 0, ("2 receivers found:\n" + body) if "LOCKED" not in cmd and "QUICK" not in cmd \
                    else "No receivers found\n", ""
            return 0, "", ""
        with mock.patch.object(am, "adb_shell", side_effect=sh):
            r = am.detect_boot_receivers("S", 0)
        self.assertIn(("com.carrier.setup", "com.carrier.setup.SetupBootRx"), r["receivers"])
        self.assertTrue(r["complete"])
        self.assertEqual(am.QUERY_FLAGS, "0x8200")
        st = am.parse_package_user_state(UNTIL_USED_DUMPSYS, 0)
        self.assertEqual(st["pkg_state"], 4)
        self.assertEqual(am.PKG_STATE_WORDS[4], "OFF until used")


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class Round28GuiTests(AutorunCorrectionGuiTests):
    def test_resolver_scope_shown_with_detected_user(self):
        t = self.tab
        d = dict(self.data(), complete=False, method="dumpsys receiver table", inventory_scope="resolver",
                 notes=["read from the resolver table; per-user inventory scope not established (the states "
                        "shown are still read for the selected user)"], user_source="detected", user_verified=True)
        t._done(t.gen, "SER", d, None)
        text = t.status.cget("text")
        self.assertIn("PARTIAL", text)
        self.assertIn("per-user inventory scope not established", text)
        self.assertNotIn("NOT VERIFIED", text)                  # the user itself was verified

    def test_until_used_package_shown_off(self):
        t = self.tab
        st = am.parse_package_user_state(UNTIL_USED_DUMPSYS, 0)
        self.app.apps_tab.apps = {"com.carrier.setup": real_app("com.carrier.setup")}
        d = dict(self.data(), receivers={("com.carrier.setup", "com.carrier.setup.SetupBootRx"):
                                         {"actions": {am.BOOT_ACTIONS[0]}}},
                 states={"com.carrier.setup": st})
        t._done(t.gen, "SER", d, None)
        self.assertEqual(t.tree.item("p:com.carrier.setup", "values")[1], "app OFF")
        t.tree.selection_set("p:com.carrier.setup")
        t.on_select()
        self.assertIn("OFF until used", t.detail.get("1.0", "end"))


class Round28TerminalTests(TerminalEnvTests):
    def test_executable_directory_rejected(self):
        """4. an absolute $TERMINAL that is a directory (even 'executable') isn't a terminal."""
        d = os.path.join(self.d, "termdir")
        os.makedirs(d)
        os.chmod(d, 0o755)
        with mock.patch.dict(os.environ, {"TERMINAL": d}), \
                mock.patch("shutil.which", side_effect=lambda n: "/usr/bin/xterm" if n == "xterm" else None):
            self.assertEqual(am.find_terminal()[0], "/usr/bin/xterm")


for _n in [n for n in dir(AutorunFallbackTests) if n.startswith("test_")]:
    setattr(Round28DetectionTests, _n, None)
for _n in [n for n in dir(AutorunCorrectionGuiTests) if n.startswith("test_")]:
    setattr(Round28GuiTests, _n, None)
for _n in [n for n in dir(TerminalEnvTests) if n.startswith("test_")]:
    setattr(Round28TerminalTests, _n, None)



# ==========================================================================
# Round 30 - Autorun milestone 2: controls (confirm, apply, verify)
# ==========================================================================

class FakePhone:
    """A tiny phone: component overrides, package state and appops per (pkg, op),
    answering the same shell commands the app sends."""

    def __init__(self, refuse_components=False, root=False, appops_cmd="cmd appops", sdk=34):
        self.disabled, self.enabled, self.pkg_state, self.ops = set(), set(), {}, {}
        self.refuse, self.root, self.appops_cmd, self.sdk, self.log = refuse_components, root, appops_cmd, sdk, []

    def dumpsys(self, pkg):
        lines = ["Packages:", "  Package [%s] (1):" % pkg, "    targetSdk=%d" % getattr(self, "target", 34),
                 "    User 0: ceDataInode=1 installed=true enabled=%d" % self.pkg_state.get(pkg, 0)]
        mine = [c for p, c in self.disabled if p == pkg]
        if mine:
            lines += ["      disabledComponents:"] + ["        " + c for c in mine]
        mine = [c for p, c in self.enabled if p == pkg]
        if mine:
            lines += ["      enabledComponents:"] + ["        " + c for c in mine]
        return "\n".join(lines) + "\n"

    def __call__(self, serial, cmd, timeout=30):
        self.log.append(cmd)
        as_root = cmd.startswith("su -c ")
        if as_root:
            if not self.root:
                return 127, "", "/system/bin/sh: su: not found"
            cmd = shlex.split(cmd)[2]
            if cmd == "id":
                return 0, "uid=0(root) gid=0(root)\n", ""
        if cmd == "getprop ro.build.fingerprint":
            return 0, "Xiaomi/serenity/serenity:15/AP3A/1:user/release-keys\n", ""
        if cmd == "getprop ro.build.version.sdk":
            return 0, "%d\n" % self.sdk, ""
        if cmd.startswith("dumpsys package "):
            return 0, self.dumpsys(shlex.split(cmd)[2]), ""
        m = re.match(r"pm (disable-user|enable|default-state) --user 0 (\S+)$", cmd)
        if m:
            verb, target = m.group(1), shlex.split(m.group(2))[0]
            if "/" in target:
                if self.refuse and not as_root:
                    return 255, "", ("Exception occurred while executing 'disable-user':\n"
                                     "java.lang.SecurityException: Shell cannot change component state for %s to 3"
                                     % target)
                p, c = target.split("/", 1)
                self.disabled.discard((p, c))
                self.enabled.discard((p, c))
                if verb == "disable-user":
                    self.disabled.add((p, c))
                elif verb == "enable":
                    self.enabled.add((p, c))
                return 0, "Component {%s} new state: %s\n" % (target, verb), ""
            self.pkg_state[target] = 3 if verb == "disable-user" else 1
            return 0, "Package %s new state: %s\n" % (target, verb), ""
        for pref in ("cmd appops", "appops"):
            if cmd.startswith(pref + " "):
                if pref != self.appops_cmd:
                    return 127, "", "/system/bin/sh: %s: not found" % pref.split()[-1]
                rest = cmd[len(pref) + 1:].replace("--user 0 ", "")
                if rest == "help":
                    return 0, "AppOps service commands:\n", ""
                parts = rest.split()
                if parts[0] == "get":
                    v = self.ops.get((parts[1], parts[2]))
                    return 0, ("%s: %s\n" % (parts[2], v)) if v else "No operations.\nDefault mode: allow\n", ""
                if parts[0] == "set":
                    self.ops[(parts[1], parts[2])] = parts[3]
                    return 0, "", ""
        return 0, "", ""


class AutorunControlFunctionTests(unittest.TestCase):
    PKG, CLS = "org.videolan.vlc", "org.videolan.vlc.TvReceiver"

    def run_with(self, phone, fn, *a):
        with mock.patch.object(am, "adb_shell", side_effect=phone):
            return fn(*a)

    def test_component_refused_changes_nothing(self):
        ph = FakePhone(refuse_components=True)
        r = self.run_with(ph, am.set_component_state, "S", 0, self.PKG, self.CLS, "disabled")
        self.assertEqual((r["outcome"], r["state"]), ("refused", "DEFAULT"))
        self.assertFalse(any(c.startswith("pm disable-user --user 0 org.videolan.vlc") and "/" not in c
                             for c in ph.log))                 # never fell back to the whole package

    def test_component_verified_and_restored_exactly(self):
        ph = FakePhone()
        r = self.run_with(ph, am.set_component_state, "S", 0, self.PKG, self.CLS, "disabled")
        self.assertEqual((r["outcome"], r["state"]), ("verified", "DISABLED"))
        r = self.run_with(ph, am.set_component_state, "S", 0, self.PKG, self.CLS, "default")
        self.assertEqual((r["outcome"], r["state"]), ("verified", "DEFAULT"))

    def test_component_command_ok_but_state_not_changed_is_unverified(self):
        ph = FakePhone()
        with mock.patch.object(am, "adb_shell", side_effect=lambda s, c, timeout=30: (
                (0, "Component new state: disabled-user\n", "") if c.startswith("pm ") else ph(s, c, timeout))):
            r = am.set_component_state("S", 0, self.PKG, self.CLS, "disabled")
        self.assertEqual(r["outcome"], "unverified")           # never trusted from the output alone

    def test_root_needs_real_uid0(self):
        self.assertFalse(self.run_with(FakePhone(root=False), am.root_available, "S"))
        self.assertTrue(self.run_with(FakePhone(root=True), am.root_available, "S"))
        with mock.patch.object(am, "adb_shell", return_value=(0, "uid=2000(shell)\n", "")):
            self.assertFalse(am.root_available("S"))             # su present, but not root

    def test_root_path_goes_through_su(self):
        ph = FakePhone(refuse_components=True, root=True)
        r = self.run_with(ph, am.set_component_state, "S", 0, self.PKG, self.CLS, "disabled", True)
        self.assertEqual(r["outcome"], "verified")
        self.assertTrue(any(c.startswith("su -c ") for c in ph.log))

    def test_background_ops_by_version_and_target(self):
        self.assertEqual(am.background_ops(34, 34), ["RUN_ANY_IN_BACKGROUND"])
        self.assertEqual(am.background_ops(30, 25), ["RUN_ANY_IN_BACKGROUND", "RUN_IN_BACKGROUND"])
        self.assertEqual(am.background_ops(26, 34), ["RUN_IN_BACKGROUND"])
        self.assertEqual(am.background_ops(23, 34), [])

    def test_restrict_and_allow_restore_originals(self):
        ph = FakePhone()
        ph.ops[(self.PKG, "RUN_IN_BACKGROUND")] = "allow"        # explicit original
        r = self.run_with(ph, am.restrict_background, "S", "cmd appops", self.PKG, 0,
                          ["RUN_ANY_IN_BACKGROUND", "RUN_IN_BACKGROUND"])
        self.assertEqual(r["outcome"], "verified")
        self.assertEqual(r["originals"], {"RUN_ANY_IN_BACKGROUND": "implicit", "RUN_IN_BACKGROUND": "allow"})
        r2 = self.run_with(ph, am.allow_background, "S", "cmd appops", self.PKG, 0, r["originals"])
        self.assertEqual(r2["outcome"], "verified")
        self.assertEqual(ph.ops[(self.PKG, "RUN_IN_BACKGROUND")], "allow")        # exact
        self.assertEqual(ph.ops[(self.PKG, "RUN_ANY_IN_BACKGROUND")], "default")  # functionally equal
        self.assertEqual(r2["approximate"], ["RUN_ANY_IN_BACKGROUND"])           # ... and said so

    def test_older_appops_tool_and_none(self):
        self.assertEqual(self.run_with(FakePhone(appops_cmd="appops"), am.appops_prefix, "S"), "appops")
        self.assertIsNone(self.run_with(FakePhone(appops_cmd="nothing"), am.appops_prefix, "S"))

    def test_restrict_unreadable_mode_changes_nothing(self):
        ph = FakePhone()
        with mock.patch.object(am, "appops_get", return_value=None), \
                mock.patch.object(am, "appops_set") as st:
            r = am.restrict_background("S", "cmd appops", self.PKG, 0, ["RUN_ANY_IN_BACKGROUND"])
        self.assertEqual(r["outcome"], "unsupported")
        st.assert_not_called()

    def test_whole_package_off_on_verified(self):
        ph = FakePhone()
        r = self.run_with(ph, am.set_package_state, "S", 0, self.PKG, False)
        self.assertEqual((r["outcome"], r["pkg_state"]), ("verified", 3))
        r = self.run_with(ph, am.set_package_state, "S", 0, self.PKG, True)
        self.assertEqual((r["outcome"], r["pkg_state"]), ("verified", 1))


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class AutorunControlGuiTests(AutorunCorrectionGuiTests):
    PKG, CLS = "org.videolan.vlc", "org.videolan.vlc.TvReceiver"

    def setUp(self):
        super().setUp()
        for k in self.tab.saved.keys():
            self.tab.saved.put(k, None)
        self.tab.denied.clear()
        self.app.apps_tab.use_root.set(False)
        d = self.data()
        d["states"]["org.videolan.vlc"]["target_sdk"] = 34
        self.tab._done(self.tab.gen, "SER", d, None)

    def select(self, iid):
        self.tab.tree.selection_set(iid)
        self.tab.on_select()

    def run_act(self, phone, kind, answer=True):
        t = self.tab
        with mock.patch.object(am, "adb_shell", side_effect=phone), \
                mock.patch.object(am.messagebox, "askyesno", return_value=answer) as ask, \
                mock.patch.object(am.messagebox, "showinfo") as ok, \
                mock.patch.object(am.messagebox, "showwarning") as warn:
            t.act(kind)
            self.pump(lambda: not t.busy, 10)
        return ask, ok, warn

    def test_buttons_follow_selection(self):
        t = self.tab
        self.select("p:" + self.PKG)
        self.assertIn("disabled", t.btns["rx_off"].state())           # needs a receiver
        self.assertNotIn("disabled", t.btns["bg_restrict"].state())
        self.assertNotIn("disabled", t.btns["app_off"].state())
        self.assertIn("disabled", t.btns["app_on"].state())
        self.select("r:%s/%s" % (self.PKG, self.CLS))
        self.assertNotIn("disabled", t.btns["rx_off"].state())
        self.assertIn("disabled", t.btns["rx_back"].state())          # nothing saved to restore yet

    def test_declined_confirmation_sends_nothing(self):
        ph = FakePhone()
        self.select("r:%s/%s" % (self.PKG, self.CLS))
        ask, ok, warn = self.run_act(ph, "rx_off", answer=False)
        ask.assert_called_once()
        self.assertEqual(ph.log, [])

    def test_receiver_off_verified_then_put_back(self):
        ph = FakePhone()
        self.select("r:%s/%s" % (self.PKG, self.CLS))
        ask, ok, warn = self.run_act(ph, "rx_off")
        self.assertIn("Switch off only this start-up receiver", ask.call_args[0][1])
        self.assertIn("Done - checked on the phone", ok.call_args[0][1])
        self.assertIn("DISABLED", ok.call_args[0][1])
        self.select("r:%s/%s" % (self.PKG, self.CLS))
        self.assertNotIn("disabled", self.tab.btns["rx_back"].state())
        ask, ok, warn = self.run_act(ph, "rx_back")
        self.assertIn("DEFAULT", ok.call_args[0][1])
        self.assertEqual(ph.disabled, set())

    def test_refusal_reported_and_remembered_no_fallback(self):
        ph = FakePhone(refuse_components=True)
        self.select("r:%s/%s" % (self.PKG, self.CLS))
        ask, ok, warn = self.run_act(ph, "rx_off")
        msg = warn.call_args[0][1]
        self.assertIn("Not changed - Android refused it", msg)
        self.assertIn("Nothing else was changed", msg)
        self.assertEqual(ph.pkg_state, {})                              # whole app untouched
        self.assertEqual(len(self.tab.denied), 1)
        self.select("r:%s/%s" % (self.PKG, self.CLS))
        ask, ok, warn = self.run_act(ph, "rx_off", answer=False)
        self.assertIn("refused this on this phone before", ask.call_args[0][1])   # manual retry offered

    def test_root_requested_but_unavailable(self):
        ph = FakePhone(refuse_components=True, root=False)
        self.app.apps_tab.use_root.set(True)
        self.select("r:%s/%s" % (self.PKG, self.CLS))
        ask, ok, warn = self.run_act(ph, "rx_off")
        self.assertIn("su didn't return uid 0", warn.call_args[0][1])
        self.assertFalse(any(c.startswith("pm ") for c in ph.log))     # nothing tried

    def test_background_restrict_and_allow(self):
        ph = FakePhone()
        self.select("p:" + self.PKG)
        ask, ok, warn = self.run_act(ph, "bg_restrict")
        self.assertIn("does NOT remove its start-up receivers", ask.call_args[0][1])
        self.assertIn("RUN_ANY_IN_BACKGROUND = ignore", ok.call_args[0][1])
        self.select("p:" + self.PKG)
        ask, ok, warn = self.run_act(ph, "bg_allow")
        self.assertIn("behaves the same", ok.call_args[0][1])
        self.assertEqual(ph.ops[(self.PKG, "RUN_ANY_IN_BACKGROUND")], "default")

    def test_whole_app_off_is_explicit_and_verified(self):
        ph = FakePhone()
        self.select("p:" + self.PKG)
        ask, ok, warn = self.run_act(ph, "app_off")
        self.assertIn("NOT the same as switching off one receiver", ask.call_args[0][1])
        self.assertIn("OFF (by user)", ok.call_args[0][1])
        self.assertEqual(self.tab.tree.item("p:" + self.PKG, "values")[1], "app OFF")
        self.select("p:" + self.PKG)
        self.assertNotIn("disabled", self.tab.btns["app_on"].state())

    def test_system_app_warning(self):
        t = self.tab
        t.show_sys.set(True)
        t.populate()
        self.assertIn("SYSTEM app", t.confirm_text("app_off", "com.android.traceur", None))
        t.show_sys.set(False)

    def test_action_exception_reported(self):
        self.select("p:" + self.PKG)
        with mock.patch.object(am, "set_package_state", side_effect=RuntimeError("boom")):
            ask, ok, warn = self.run_act(FakePhone(), "app_off")
        self.assertIn("boom", warn.call_args[0][1])
        self.assertFalse(self.tab.busy)

    def test_join_words_with_dot(self):
        t = self.tab
        d = self.data()
        d["receivers"][(self.PKG, self.CLS)]["actions"] = {am.BOOT_ACTIONS[0], am.BOOT_ACTIONS[1]}
        t._done(t.gen, "SER", d, None)
        self.assertIn(" · ", t.tree.item("p:" + self.PKG, "values")[0])


for _n in [n for n in dir(AutorunCorrectionGuiTests) if n.startswith("test_")]:
    setattr(AutorunControlGuiTests, _n, None)



# ==========================================================================
# Round 31 - round-30 review corrections
# ==========================================================================

class Round30FunctionTests(unittest.TestCase):
    def test_unknown_target_sdk_is_unknown(self):
        self.assertIsNone(am.background_ops(30, None))
        self.assertIsNone(am.background_ops(28, 0))
        self.assertEqual(am.background_ops(26, None), ["RUN_IN_BACKGROUND"])    # 7-8: target irrelevant

    def test_nonzero_user_appops_never_unscoped(self):
        calls = []

        def sh(serial, cmd, timeout=20):
            calls.append(cmd)
            if "--user" in cmd:
                return 255, "", "Error: Unknown option: --user"
            return 0, "No operations.\n", ""
        with mock.patch.object(am, "adb_shell", side_effect=sh):
            self.assertIsNone(am.appops_get("S", "cmd appops", "p", "RUN_ANY_IN_BACKGROUND", 10))
            self.assertFalse(am.appops_set("S", "cmd appops", "p", "RUN_ANY_IN_BACKGROUND", "ignore", 10))
        self.assertTrue(all("--user 10" in c for c in calls))             # no unscoped attempt for user 10
        with mock.patch.object(am, "adb_shell", side_effect=sh):
            self.assertEqual(am.appops_get("S", "cmd appops", "p", "RUN_ANY_IN_BACKGROUND", 0), "implicit")


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class Round30GuiTests(AutorunControlGuiTests):
    def test_component_record_written_before_change(self):
        t = self.tab
        seen = {}

        class Watch(FakePhone):
            def __call__(ph, serial, cmd, timeout=30):
                if cmd.startswith("pm disable-user") and "/" in cmd:
                    seen["record"] = t.saved.get(t.saved_key(self.PKG))       # what's on disk RIGHT NOW
                return FakePhone.__call__(ph, serial, cmd, timeout)
        self.select("r:%s/%s" % (self.PKG, self.CLS))
        self.run_act(Watch(), "rx_off")
        self.assertEqual(seen["record"]["components"][self.CLS], "DEFAULT")

    def test_save_failure_changes_nothing(self):
        ph = FakePhone()
        self.select("r:%s/%s" % (self.PKG, self.CLS))
        with mock.patch.object(self.tab, "_save_record", return_value=False):
            ask, ok, warn = self.run_act(ph, "rx_off")
        self.assertIn("couldn't be saved to disk", warn.call_args[0][1])
        self.assertFalse(any(c.startswith("pm ") for c in ph.log))
        self.select("p:" + self.PKG)
        with mock.patch.object(self.tab, "_save_record", return_value=False):
            ask, ok, warn = self.run_act(ph, "bg_restrict")
        self.assertIn("couldn't be saved to disk", warn.call_args[0][1])
        self.assertFalse(any(" set " in c for c in ph.log))

    def test_refusal_removes_unneeded_record(self):
        self.select("r:%s/%s" % (self.PKG, self.CLS))
        self.run_act(FakePhone(refuse_components=True), "rx_off")
        rec = self.tab.saved.get(self.tab.saved_key(self.PKG)) or {}
        self.assertNotIn(self.CLS, rec.get("components", {}))             # nothing to put back

    def test_appops_record_written_before_first_set(self):
        t = self.tab
        seen = {}

        class Watch(FakePhone):
            def __call__(ph, serial, cmd, timeout=30):
                if " set " in cmd and "record" not in seen:
                    seen["record"] = t.saved.get(t.saved_key(self.PKG))
                return FakePhone.__call__(ph, serial, cmd, timeout)
        self.select("p:" + self.PKG)
        self.run_act(Watch(), "bg_restrict")
        self.assertEqual(seen["record"]["appops"], {"RUN_ANY_IN_BACKGROUND": "implicit"})

    def test_unverified_user_blocks_changes(self):
        t = self.tab
        d = dict(self.data(), user_source="unverified", user_verified=False)
        t._done(t.gen, "SER", d, None)
        self.select("p:" + self.PKG)
        self.assertTrue(all("disabled" in b.state() for b in t.btns.values()))
        ph = FakePhone()
        with mock.patch.object(am, "adb_shell", side_effect=ph), \
                mock.patch.object(am.messagebox, "askyesno") as ask, \
                mock.patch.object(am.messagebox, "showwarning") as warn:
            t.act("app_off")                                          # bypassing the disabled button
        ask.assert_not_called()
        self.assertIn("couldn't be established", warn.call_args[0][1])
        self.assertEqual(ph.log, [])

    def test_context_snapshot_not_live_state(self):
        t = self.tab
        ctx = {"serial": "A", "user": 0, "user_verified": True, "pkg": self.PKG, "cls": self.CLS,
               "before": "DEFAULT", "target_sdk": 34, "key": "A|0|" + self.PKG, "want_root": False}
        t.serial = "B"                                                # the GUI moved on to another phone
        with mock.patch.object(am, "adb_shell", side_effect=FakePhone()):
            res = t._act_run("rx_off", ctx)
        self.assertEqual(res["outcome"], "verified")
        self.assertEqual(t.saved.get("A|0|" + self.PKG)["components"][self.CLS], "DEFAULT")
        self.assertIsNone(t.saved.get("B|0|" + self.PKG))

    def test_unknown_target_refused(self):
        t = self.tab
        t.data["states"][self.PKG]["target_sdk"] = None
        ph = FakePhone()
        self.select("p:" + self.PKG)
        ask, ok, warn = self.run_act(ph, "bg_restrict")
        self.assertIn("target Android version couldn't be read", warn.call_args[0][1])
        self.assertFalse(any(" set " in c for c in ph.log))

    def test_root_checkbox_wording(self):
        texts = []

        def walk(w):
            for c in w.winfo_children():
                try:
                    texts.append(c.cget("text"))
                except tk.TclError:
                    pass
                walk(c)
        walk(self.tab)
        self.assertIn("Use root (su) for this operation", texts)


for _n in [n for n in dir(AutorunControlGuiTests) if n.startswith("test_")]:
    setattr(Round30GuiTests, _n, None)



# ==========================================================================
# Round 32 - round-31 review corrections
# ==========================================================================

@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class Round31GuiTests(Round30GuiTests):
    def watching_phone(self, seen, trigger):
        t = self.tab

        class Watch(FakePhone):
            def __call__(ph, serial, cmd, timeout=30):
                if trigger(cmd) and "record" not in seen:
                    # read the FILE, not the store's memory: is it really on disk?
                    try:
                        with open(t.saved.path, encoding="utf-8") as f:
                            seen["record"] = json.load(f).get(t.saved_key(self.PKG))
                    except (OSError, ValueError):
                        seen["record"] = None
                return FakePhone.__call__(ph, serial, cmd, timeout)
        return Watch()

    def test_retry_after_failed_save_never_bypasses_write_ahead(self):
        """1. a failed write leaves the record in memory; a retry must still not change the phone."""
        for kind, row, trigger in (("rx_off", "r:%s/%s" % (self.PKG, self.CLS),
                                    lambda c: c.startswith("pm disable-user") and "/" in c),
                                   ("bg_restrict", "p:" + self.PKG, lambda c: " set " in c)):
            ph = FakePhone()
            with mock.patch.object(sa, "atomic_write_json", side_effect=OSError(28, "No space left")):
                for _ in range(2):                                   # first attempt, then a retry
                    self.select(row)
                    ask, ok, warn = self.run_act(ph, kind)
                    self.assertIn("couldn't be saved to disk", warn.call_args[0][1], kind)
            self.assertFalse(any(c.startswith("pm ") or " set " in c for c in ph.log), kind)
            seen = {}
            ph2 = self.watching_phone(seen, trigger)
            self.select(row)
            self.run_act(ph2, kind)                                  # disk works again
            self.assertIsNotNone(seen.get("record"), kind)           # on disk before the change
            for k in self.tab.saved.keys():
                self.tab.saved.put(k, None)

    def test_memory_only_record_still_requires_disk_write(self):
        """1 (on its own, independent of the rollback): a record that exists ONLY in
        memory - left by an earlier failed write - must not let a change skip the
        disk check."""
        t = self.tab
        key = t.saved_key(self.PKG)
        with mock.patch.object(sa, "atomic_write_json", side_effect=OSError(28, "No space left")):
            t.saved.put(key, {"components": {self.CLS: "DEFAULT"},
                              "appops": {"RUN_ANY_IN_BACKGROUND": "implicit"}})   # memory only
            self.assertIsNotNone(t.saved.get(key))
            for kind, row in (("rx_off", "r:%s/%s" % (self.PKG, self.CLS)), ("bg_restrict", "p:" + self.PKG)):
                ph = FakePhone()
                self.select(row)
                ask, ok, warn = self.run_act(ph, kind)
                self.assertIn("couldn't be saved to disk", warn.call_args[0][1], kind)
                self.assertFalse(any(c.startswith("pm ") or " set " in c for c in ph.log), kind)

    def test_failed_save_does_not_offer_put_back(self):
        self.select("r:%s/%s" % (self.PKG, self.CLS))
        with mock.patch.object(sa, "atomic_write_json", side_effect=OSError(28, "No space left")):
            self.run_act(FakePhone(), "rx_off")
        self.select("r:%s/%s" % (self.PKG, self.CLS))
        self.assertIn("disabled", self.tab.btns["rx_back"].state())   # nothing to put back

    def test_generic_failure_with_confirmed_unchanged_state_removes_record(self):
        ph = FakePhone()
        with mock.patch.object(am, "adb_shell", side_effect=lambda s_, c, timeout=30: (
                (1, "", "Error: something odd") if c.startswith("pm ") else ph(s_, c, timeout))):
            self.select("r:%s/%s" % (self.PKG, self.CLS))
            with mock.patch.object(am.messagebox, "askyesno", return_value=True), \
                    mock.patch.object(am.messagebox, "showwarning"), mock.patch.object(am.messagebox, "showinfo"):
                self.tab.act("rx_off")
                self.pump(lambda: not self.tab.busy)
        rec = self.tab.saved.get(self.tab.saved_key(self.PKG)) or {}
        self.assertNotIn(self.CLS, rec.get("components", {}))       # read-back proved: still DEFAULT

    def test_failure_with_unknown_readback_keeps_record(self):
        """2. FAILED alone doesn't prove nothing changed: an unknown read-back keeps the record."""
        def sh(s_, c, timeout=30):
            if c.startswith("pm ") or c.startswith("dumpsys package"):
                return 1, "", "error: device busy"
            return FakePhone()(s_, c, timeout)
        self.select("r:%s/%s" % (self.PKG, self.CLS))
        with mock.patch.object(am, "adb_shell", side_effect=sh), \
                mock.patch.object(am.messagebox, "askyesno", return_value=True), \
                mock.patch.object(am.messagebox, "showwarning") as warn, mock.patch.object(am.messagebox, "showinfo"):
            self.tab.act("rx_off")
            self.pump(lambda: not self.tab.busy)
        rec = self.tab.saved.get(self.tab.saved_key(self.PKG)) or {}
        self.assertEqual(rec.get("components", {}).get(self.CLS), "DEFAULT")
        self.assertIn("original state was kept", warn.call_args[0][1])

    def test_refusal_with_confirmed_unchanged_state_removes_record(self):
        self.select("r:%s/%s" % (self.PKG, self.CLS))
        self.run_act(FakePhone(refuse_components=True), "rx_off")
        rec = self.tab.saved.get(self.tab.saved_key(self.PKG)) or {}
        self.assertNotIn(self.CLS, rec.get("components", {}))


for _n in [n for n in dir(Round30GuiTests) if n.startswith("test_")]:
    setattr(Round31GuiTests, _n, None)



# ==========================================================================
# Round 33 - cleanup decided by read-back only
# ==========================================================================

@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class Round32GuiTests(Round31GuiTests):
    def record(self):
        return (self.tab.saved.get(self.tab.saved_key(self.PKG)) or {}).get("components", {})

    def test_verified_but_unchanged_removes_record(self):
        """already DISABLED, 'off' pressed: since Milestone 3 nothing is sent at all (no-op), shown as
        information, and no restore record is written."""
        ph = FakePhone()
        ph.disabled.add((self.PKG, self.CLS))
        t = self.tab
        t.data["states"][self.PKG]["disabled"].add(self.CLS)          # the list showed it as DISABLED
        self.select("r:%s/%s" % (self.PKG, self.CLS))
        ask, ok, warn = self.run_act(ph, "rx_off")
        self.assertIn("already in that state, so nothing was sent", ok.call_args[0][1])
        self.assertFalse(warn.called)
        self.assertFalse([c for c in ph.log if "disable-user" in c])
        self.assertNotIn(self.CLS, self.record())

    def test_verified_and_changed_keeps_record(self):
        """DEFAULT -> DISABLED: verified, read-back differs -> record kept for 'Put it back'."""
        self.select("r:%s/%s" % (self.PKG, self.CLS))
        self.run_act(FakePhone(), "rx_off")
        self.assertEqual(self.record().get(self.CLS), "DEFAULT")


for _n in [n for n in dir(Round31GuiTests) if n.startswith("test_")]:
    setattr(Round32GuiTests, _n, None)



# ==========================================================================
# Round 34 - interface pass: window fits the screen, wrapping, icons
# ==========================================================================

from tkinter import ttk       # noqa: E402


class WindowSizeTests(unittest.TestCase):
    def test_never_larger_than_the_screen(self):
        for sw, sh in ((800, 480), (1024, 600), (1366, 768), (1920, 1080), (3840, 2160)):
            for scale in (1.0, 1.5, 2.0):
                w, h, x, y, mw, mh = am.initial_window_size(sw, sh, scale)
                self.assertLessEqual(w, sw, (sw, sh, scale))
                self.assertLessEqual(h, sh, (sw, sh, scale))
                self.assertLessEqual(x + w, sw)
                self.assertLessEqual(y + h, sh)
                self.assertLessEqual(mw, w)             # a minimum never bigger than the window
                self.assertLessEqual(mh, h)

    def test_big_screen_gets_the_usual_size(self):
        self.assertEqual(am.initial_window_size(1920, 1080)[:2], (1250, 780))

    def test_scaling_grows_the_window(self):
        self.assertGreater(am.initial_window_size(3840, 2160, 2.0)[0], 1250)


class IconDrawingTests(unittest.TestCase):
    def test_every_icon_draws_and_is_not_blank_or_full(self):
        for name in am.ICON_SHAPES:
            mask = am.raster_icon(name, 16)
            on = sum(map(sum, mask))
            self.assertEqual((len(mask), len(mask[0])), (16, 16), name)
            self.assertGreater(on, 12, name)            # something visible
            self.assertLess(on, 16 * 16 * 0.75, name)   # not a solid block

    def test_mapping_points_to_real_icons(self):
        for text, name in am.ICON_FOR_TEXT.items():
            self.assertIn(name, am.ICON_SHAPES, text)
        for name in am.TAB_ICONS:
            self.assertIn(name, am.ICON_SHAPES)

    def test_labels_that_already_have_a_symbol_get_no_icon(self):
        for text in ("⟳", "Upload →", "← Download", "↑ Up"):
            self.assertNotIn(text, am.ICON_FOR_TEXT)


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class InterfaceGuiTests(unittest.TestCase):
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

    def buttons(self, w=None):
        out = []
        for c in (w or self.root).winfo_children():
            if isinstance(c, ttk.Button):
                out.append(c)
            out += self.buttons(c)
        return out

    def test_tabs_have_icons_and_keep_text(self):
        nb = self.app.nb
        for i, tab in enumerate(nb.tabs()):
            self.assertTrue(str(nb.tab(tab, "image")), i)
            self.assertTrue(nb.tab(tab, "text").strip(), i)

    def test_known_buttons_get_icons_with_text(self):
        seen = 0
        for b in self.buttons():
            text = str(b.cget("text"))
            if text in am.ICON_FOR_TEXT:
                self.assertTrue(str(b.cget("image")), text)
                self.assertEqual(str(b.cget("compound")), "left", text)
                seen += 1
        self.assertGreater(seen, 15)

    def test_icons_have_a_dimmed_look_when_disabled(self):
        b = self.app.autorun_tab.btns["app_off"]
        spec = [str(x) for x in b.cget("image")]
        self.assertIn("disabled", spec)
        self.assertEqual(len(spec), 3)

    def test_icon_size_follows_scaling(self):
        with mock.patch.object(am, "ui_scale", return_value=2.0):
            self.assertEqual(am.Icons(self.root).size, 32)
        with mock.patch.object(am, "ui_scale", return_value=1.0):
            self.assertEqual(am.Icons(self.root).size, 16)

    def test_windows_opened_later_get_icons(self):
        top = tk.Toplevel(self.root)
        self.addCleanup(top.destroy)
        b = ttk.Button(top, text="Refresh")
        b.pack()
        am.apply_icons(top, self.app.icons)
        self.assertTrue(str(b.cget("image")))

    def test_toolbar_wraps_and_unwraps_without_losing_buttons(self):
        f = ttk.Frame(self.root)
        f.pack(fill="x")
        self.addCleanup(f.destroy)
        btns = [ttk.Button(f, text="Button number %d" % i) for i in range(6)]
        for b in btns:
            b.pack(side="left", padx=4)
        wr = am.WrapRow(f)
        wr.layout(250)
        self.assertGreater(wr.line_count(), 2)          # narrow: several lines
        wr.layout(5000)
        self.assertEqual(wr.line_count(), 1)            # wide: back to one line
        self.assertTrue(all(b.winfo_manager() == "pack" for b in btns))     # none lost
        wr.layout(250)
        order = [str(w) for r in wr.rows if r.winfo_manager() for w in r.pack_slaves()]
        self.assertEqual(order, [str(b) for b in btns])                     # order kept

    def test_bottom_controls_survive_a_short_window(self):
        """the regression this pass fixes: rows below a stretching list were squeezed
        out of short windows. Now they're served before the list."""
        f = ttk.Frame(self.root, height=200)
        f.pack_propagate(False)
        f.pack()
        self.addCleanup(f.destroy)
        big = tk.Text(f, height=40)
        big.pack(fill="both", expand=True)
        bar = ttk.Button(f, text="Under the list")
        bar.pack(fill="x")
        am.protect_bottom_bars(f)
        self.assertEqual(bar.pack_info()["side"], "bottom")
        self.assertEqual(f.pack_slaves().index(bar), 0)  # served before the list
        self.root.deiconify()
        self.addCleanup(self.root.withdraw)
        for _ in range(5):
            self.root.update()
        self.assertTrue(bar.winfo_ismapped())
        self.assertGreater(bar.winfo_height(), 5)

    def test_real_apps_tab_bottom_rows_are_protected(self):
        """the Apps-tab rows under the list (Turn OFF..., AI research, options) are
        served before the list in the running app, not just in a toy frame."""
        tab = self.app.apps_tab
        for btn in (tab.undo_btn, tab.ask_btn):
            w = btn
            while w.master is not tab:
                w = w.master
            self.assertEqual(w.pack_info()["side"], "bottom", btn.cget("text"))

    def test_status_lines_wrap(self):
        lab = self.app.autorun_tab.status
        lab.event_generate("<Configure>", width=300, height=20)
        self.root.update()
        self.assertEqual(int(str(lab.cget("wraplength"))), 300 - 12)

    def test_status_bar_packed_at_the_bottom(self):
        self.assertEqual(self.app.status.master.pack_info()["side"], "bottom")



# ==========================================================================
# Round 35 - Milestone 1: device capture, sanitising, real-output fixtures,
#            Copy diagnostics
# ==========================================================================

FAKE_ADB = r'''#!/usr/bin/env python3
# Fake adb for capture tests: answers like a phone, with privacy traps built in.
import sys

SERIAL = "ABC123SERIAL"
args = sys.argv[1:]
if args[:1] == ["devices"]:
    print("List of devices attached\n%s\tdevice\n" % SERIAL)
    sys.exit(0)
if args[:1] == ["version"]:
    print("Android Debug Bridge version 1.0.41")
    sys.exit(0)
assert args[0] == "-s" and args[2] == "shell", args
cmd = args[3]
out, err, rc = "", "", 0
PKGS = {"com.android.settings": "/system/priv-app/Settings/Settings.apk",
        "com.google.android.youtube": "/data/app/~~yt9==/com.google.android.youtube-zz1==/base.apk",
        "com.foo.pro": "/system/app/FooPro/FooPro.apk",
        "android": "/system/framework/framework-res.apk",
        "com.whatsapp": "/data/app/~~ab12==/com.whatsapp-cd34==/base.apk",
        "com.mybank.app": "/mnt/expand/1234-abcd/app/com.mybank.app-1/base.apk",
        "com.foo": "/data/app/com.foo-2/base.apk"}
SYSTEM = ["com.android.settings", "com.google.android.youtube", "com.foo.pro", "android"]
THIRD = ["com.whatsapp", "com.mybank.app", "com.foo"]
if cmd == "getprop":
    out = ("[ro.build.version.release]: [15]\n[ro.build.version.sdk]: [35]\n[ro.product.manufacturer]: [Xiaomi]\n"
           "[ro.product.model]: [Redmi A7]\n[ro.serialno]: [%s]\n[persist.sys.timezone]: [Europe/Lisbon]\n"
           "[ro.config.low_ram]: [true]\n[ro.boot.verifiedbootstate]: [green]\n" % SERIAL)
elif cmd == "am get-current-user":
    out = "0\n"
elif cmd == "pm list users":
    out = "Users:\n\tUserInfo{0:Pedro Silva:c13} running\n"
elif cmd.startswith("pm list packages"):
    f = cmd[len("pm list packages"):].split()
    names = SYSTEM if "-s" in f else THIRD if "-3" in f else ["com.foo"] if "-d" in f else list(PKGS)
    out = "".join(("package:%s=%s\n" % (PKGS[n], n)) if "-f" in f else ("package:%s\n" % n) for n in names)
elif cmd.startswith("cmd package query-receivers"):
    if "LOCKED" in cmd or "QUICKBOOT" in cmd:
        out = "No receivers found\n"
    else:
        rx = ["com.android.settings/.BootRx", "com.google.android.youtube/.Rx", "com.whatsapp/.BootRx",
              "com.foo/.Boot", "com.foo.pro/.ProRx"]
        if "--query-flags" in cmd:
            rx.append("com.android.settings/.OffRx")          # only visible with disabled matching
        out = "%d receivers found:\n" % len(rx) + "".join("  Receiver #%d:\n    priority=0\n    %s\n" % (i, r)
                                                          for i, r in enumerate(rx))
elif cmd == "dumpsys package r":
    out = ("Activity Resolver Table:\n  Non-Data Actions:\n      android.intent.action.MAIN:\n"
           "        1 com.whatsapp/.Main filter 2\n\nReceiver Resolver Table:\n  Non-Data Actions:\n"
           "      android.intent.action.BOOT_COMPLETED:\n        3 com.whatsapp/.BootRx filter 4\n"
           "        5 com.foo.pro/.ProRx filter 6\n\nService Resolver Table:\n      x:\n        7 a/.b filter 8\n")
elif cmd.startswith("dumpsys package "):
    p = cmd.split()[-1].strip("'")
    out = ("Packages:\n  Package [%s] (abc):\n    userId=10123\n    versionCode=42 minSdk=21 targetSdk=34\n"
           "    flags=[ HAS_CODE ]\n    codePath=%s\n    installerPackageName=com.android.vending\n"
           "    owner=pedro.silva@example.com\n    requested permissions:\n      android.permission.CAMERA\n"
           "    User 0: ceDataInode=1 installed=true hidden=false enabled=%d instant=false\n"
           "      gids=[3003]\n      runtime permissions:\n        android.permission.CAMERA: granted=true\n"
           "      disabledComponents:\n        %s.OffRx\n" % (p, PKGS.get(p, "?"), 3 if p == "com.foo" else 0, p))
elif cmd == "cmd appops help":
    out = "AppOps service (appops) commands:\n  help\n"
elif cmd == "appops help":
    rc, err = 127, "/system/bin/sh: appops: not found (device %s)\n" % SERIAL
elif cmd.startswith("cmd appops get"):
    out = "No operations.\nDefault mode: allow\n"
sys.stdout.write(out)
sys.stderr.write(err)
sys.exit(rc)
'''


def captures_dir():
    """Real captures for parser tests: $ADBM_FIXTURES, or fixtures/ next to this file."""
    return os.environ.get("ADBM_FIXTURES") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


class CaptureBase(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.adb = os.path.join(self.d, "adb")
        write(self.adb, FAKE_ADB)
        os.chmod(self.adb, 0o755)
        patcher = mock.patch.object(am, "ADB", self.adb)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.out = os.path.join(self.d, "captures")

    def capture(self, **kw):
        path, summary = am.run_capture("ABC123SERIAL", out_dir=self.out, **kw)
        with open(path, encoding="utf-8") as f:
            return path, summary, json.load(f)


class CaptureSanitizerTests(unittest.TestCase):
    def clean(self):
        system = {"com.android.settings", "com.google.android.youtube", "com.foo.pro"}
        third = {"com.whatsapp", "com.foo"}
        everything = system | third | {"com.mystery"}          # in neither list: unknown
        return am.CaptureSanitizer("ABC123SERIAL", system, third, everything)

    def test_user_and_unknown_anonymised_system_kept(self):
        c = self.clean()
        t = c("com.whatsapp/.Rx com.mystery.Boot com.android.settings/.X com.google.android.youtube")
        self.assertNotIn("whatsapp", t)
        self.assertNotIn("mystery", t)                           # unknown -> anonymised
        self.assertIn("com.android.settings/.X", t)
        self.assertIn("com.google.android.youtube", t)            # updated system app, kept

    def test_prefix_of_a_system_package_is_not_touched(self):
        c = self.clean()
        t = c("com.foo/.Boot com.foo.pro/.ProRx com.foo.pro.Inner com.foo.Boot")
        self.assertIn("com.foo.pro/.ProRx", t)
        self.assertIn("com.foo.pro.Inner", t)
        self.assertNotIn("com.foo/", t)
        self.assertNotIn("com.foo.Boot", t)

    def test_placeholders_are_stable(self):
        c = self.clean()
        a, b = c("com.whatsapp"), c("x com.whatsapp/.Y")
        self.assertEqual(b, "x %s/.Y" % a)

    def test_paths_serial_names_and_personal_strings(self):
        c = self.clean()
        t = c("/data/app/~~ab12==/com.whatsapp-cd34==/base.apk /mnt/expand/1234-abcd/app/com.foo-1/base.apk "
              "error: device ABC123SERIAL not found UserInfo{0:Pedro Silva:c13} a@b.com +351 912 345 678 "
              "aa:bb:cc:dd:ee:ff versionCode=1234567890")
        for bad in ("ab12", "cd34", "1234-abcd", "ABC123SERIAL", "Pedro", "a@b.com", "912", "aa:bb"):
            self.assertNotIn(bad, t, bad)
        self.assertIn("versionCode=1234567890", t)                # long digit runs aren't phone numbers
        self.assertIn("UserInfo{0:user0:c13}", t)


class CaptureRunnerBoundsTests(CaptureBase):
    def script(self, body):
        write(self.adb, "#!/usr/bin/env python3\nimport sys, time\n" + body)
        os.chmod(self.adb, 0o755)

    def test_output_cap_kills_and_marks_truncated(self):
        self.script("sys.stdout.write('x' * (5 << 20)); sys.stdout.flush()\n")
        r = am.capture_run("S", "anything", cap=100000)
        self.assertTrue(r["truncated"])
        self.assertIsNone(r["rc"])                               # incomplete is never "succeeded"
        self.assertEqual(len(r["out"]), 100000)

    def test_timeout(self):
        self.script("time.sleep(30)\n")
        t = time.time()
        r = am.capture_run("S", "anything", timeout=1)
        self.assertLess(time.time() - t, 10)
        self.assertTrue(r["timed_out"])
        self.assertIsNone(r["rc"])

    def test_error_text_bounded(self):
        self.script("sys.stderr.write('e' * 100000); sys.exit(3)\n")
        r = am.capture_run("S", "anything")
        self.assertEqual((r["rc"], len(r["err"])), (3, am.CAPTURE_ERR_CAP))


class CaptureEndToEndTests(CaptureBase):
    def test_no_leaks_and_system_names_kept(self):
        path, summary, doc = self.capture()
        raw = json.dumps(doc)
        for bad in ("ABC123SERIAL", "whatsapp", "mybank", "Pedro", "pedro", "ro.serialno", "timezone",
                    "1234-abcd", "android.permission.CAMERA", "installerPackageName"):
            self.assertNotIn(bad, raw, bad)
        for good in ("com.android.settings", "com.foo.pro", "com.google.android.youtube"):
            self.assertIn(good, raw, good)
        self.assertNotIn('"com.foo/', raw)
        self.assertEqual(doc["schema"], "adbm-capture")
        self.assertNotIn("serial", json.dumps(doc["device"]).lower())

    def test_private_file_folder_and_no_overwrite(self):
        p1 = self.capture()[0]
        p2 = self.capture()[0]
        self.assertNotEqual(p1, p2)                              # second run the same day: new file
        self.assertEqual(oct(os.stat(p1).st_mode & 0o777), "0o600")
        self.assertEqual(oct(os.stat(self.out).st_mode & 0o777), "0o700")
        self.assertTrue(os.path.basename(p1).startswith("Xiaomi-Redmi_A7-sdk35-"))

    def test_only_read_only_commands_are_sent(self):
        sent = []
        real = am.capture_run

        def spy(serial, cmd, cap=am.CAPTURE_PROBE_CAP, timeout=am.CAPTURE_TIMEOUT):
            sent.append(cmd)
            return real(serial, cmd, cap, timeout)
        self.capture(runner=spy)
        allowed = ("getprop", "am get-current-user", "pm list users", "pm list packages ",
                   "cmd package query-receivers ", "dumpsys package", "cmd appops get ", "appops get ")
        for c in sent:
            self.assertTrue(c.startswith(allowed), c)
            self.assertNotRegex(c, r"\b(set|disable|enable|uninstall|install|grant|revoke|rm|reboot)\b")

    def test_summary_accepted_vs_observed(self):
        path, summary, doc = self.capture()
        self.assertEqual(summary["disabled_matching"], "observed")   # the flag added .OffRx
        self.assertEqual(summary["user_scoping"], "accepted")        # never "observed" from one capture
        self.assertEqual(summary["current_user"], "detected")
        self.assertEqual(summary["appops_tool"], "cmd appops")
        self.assertEqual(summary["resolver_table"], "present")
        # flags accepted but adding nothing -> only "accepted"
        txt = read(self.adb).replace('rx.append("com.android.settings/.OffRx")', 'pass')
        write(self.adb, txt)
        self.assertEqual(self.capture()[1]["disabled_matching"], "accepted")
        # flags rejected -> "unknown"
        txt = read(self.adb).replace('elif cmd.startswith("cmd package query-receivers"):',
                                     'elif "--query-flags" in cmd:\n    rc, err = 255, "Error: Unknown option"\n'
                                     'elif cmd.startswith("cmd package query-receivers"):')
        write(self.adb, txt)
        s = self.capture()[1]
        self.assertEqual(s["disabled_matching"], "unknown")
        self.assertEqual(s["query_forms_accepted"], ["user", "plain"])

    def test_total_cap_marks_later_probes_incomplete(self):
        full = self.capture()[2]
        bare = copy.deepcopy(full)
        for p_ in bare["probes"]:
            p_["out"] = ""
        cap = am.capture_bytes(bare) + 2000           # room for the metadata, not for all the output
        self.assertLess(cap, am.capture_bytes(full))
        with mock.patch.object(am, "CAPTURE_TOTAL_CAP", cap):
            path, summary, doc = self.capture()
        self.assertTrue(summary["truncated"])
        self.assertLessEqual(os.path.getsize(path), cap)                   # the real file on disk
        self.assertIn("INCOMPLETE", am.capture_summary_text(summary))

    def test_metadata_that_cannot_fit_saves_nothing(self):
        with mock.patch.object(am, "CAPTURE_TOTAL_CAP", 1500):
            with self.assertRaises(OSError):
                self.capture()
        self.assertEqual([f for f in os.listdir(self.out) if f.endswith(".json")]
                         if os.path.isdir(self.out) else [], [])

    def test_cli_reports_a_failed_save(self):
        with mock.patch.object(am, "pick_capture_serial", return_value=("ABC123SERIAL", None)), \
                mock.patch.object(am, "run_capture", side_effect=OSError(28, "No space left")), \
                mock.patch("sys.stderr", new_callable=io.StringIO) as err, \
                mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(am.capture_main(None), 1)
        self.assertIn("Capture not saved", err.getvalue())

    def test_atomic_write_failure_inside_run_capture(self):
        with mock.patch.object(sa, "atomic_write_json", side_effect=OSError(28, "No space left")):
            with self.assertRaises(OSError):
                am.run_capture("ABC123SERIAL", out_dir=self.out)
        self.assertEqual([f for f in os.listdir(self.out) if f.endswith(".json")], [])

    def test_trimmed_dump_parses_like_the_full_one(self):
        r = am.capture_run("ABC123SERIAL", "dumpsys package com.foo")
        trimmed = am.trim_package_dump(r["out"])
        self.assertEqual(am.parse_package_user_state(r["out"], 0), am.parse_package_user_state(trimmed, 0))
        self.assertNotIn("permission", trimmed)


class RealCaptureFixtureTests(CaptureBase):
    """Runs the app's real parsers on captured phone output. Uses every capture in
    fixtures/ (or $ADBM_FIXTURES); always also checks one made from the fake phone,
    so the checks themselves are exercised."""

    def check(self, doc, name):
        by = {p["id"]: p for p in doc["probes"]}
        s = doc["summary"]
        for pid in ("pkgs_all", "pkgs_system"):
            if by[pid]["rc"] == 0 and not by[pid]["truncated"]:
                self.assertTrue(am.parse_pm_list(by[pid]["out"]), (name, pid))
        best = next((f for f, *_ in am.QUERY_FORMS if f in s["query_forms_accepted"]), None)
        if best:
            out = by["query:%s:%s" % (best, am.BOOT_ACTIONS[0])]["out"]
            rx = am.parse_query_receivers(out)                          # must parse; may be empty
            if name == "fake":
                self.assertTrue(rx, (name, "the fake phone has boot receivers"))
            else:
                pr = by["query:%s:%s" % (best, am.BOOT_ACTIONS[0])]
                complete = pr["rc"] == 0 and not (pr["truncated"] or pr.get("err_truncated") or pr["timed_out"])
                understood = rx or not out.strip() or "No receivers found" in out or "0 receivers" in out
                self.assertTrue(complete and understood, (name, "unparsed or incomplete receiver output"))
        user = int(by["current_user"]["out"].strip()) if s["current_user"] == "detected" else 0
        for pid, p in by.items():
            if pid.startswith("pkg:") and p["rc"] == 0 and not p["truncated"]:
                st = am.parse_package_user_state(p["out"], user)
                self.assertTrue(st["found"], (name, pid))
                self.assertIsNotNone(st["pkg_state"], (name, pid))
            if pid.startswith("appops:") and p["rc"] == 0:
                self.assertIsNotNone(am.parse_appops_mode(p["out"], pid.rsplit(":", 1)[1]), (name, pid))
        if s["resolver_table"] == "present":
            am.parse_receiver_resolver(by["resolver"]["out"])          # must not raise

    def test_fake_phone_capture(self):
        self.check(self.capture()[2], "fake")

    def test_real_captures(self):
        files = sorted(glob.glob(os.path.join(captures_dir(), "*.json")))
        if not files:
            self.skipTest("no real captures in %s" % captures_dir())
        for f in files:
            with open(f, encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(doc.get("schema"), "adbm-capture", f)
            with self.subTest(capture=os.path.basename(f)):
                self.check(doc, os.path.basename(f))


class DiagnosticsTests(CaptureBase):
    def test_no_device(self):
        t = am.diagnostics_text(None)
        self.assertIn("No phone connected", t)
        self.assertIn("Python", t)

    def test_with_device_nothing_personal(self):
        t = am.diagnostics_text("ABC123SERIAL")
        self.assertIn("Xiaomi Redmi A7, Android 15 (SDK 35), Go/low-RAM", t)
        self.assertIn("Checked for Android user 0 (detected)", t)
        for bad in ("ABC123SERIAL", "whatsapp", "com.android.settings", "Pedro", "Europe/Lisbon"):
            self.assertNotIn(bad, t, bad)


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class DiagnosticsWindowTests(AboutWindowTests):
    def test_copy_diagnostics(self):
        with mock.patch.object(am, "diagnostics_text", return_value="DIAG TEXT"):
            self.app.show_diagnostics()
            win = self.app._diag_win
            self.addCleanup(win.destroy)
            end = time.time() + 5
            while time.time() < end:
                try:
                    while True:
                        item = self.app.q.get_nowait()
                        if item[0] == "call":
                            item[1](*item[2:])
                except Exception:
                    pass
                self.root.update()
                texts = [w for w in self.labels(win)]
                if any(isinstance(w, tk.Text) and "DIAG TEXT" in w.get("1.0", "end") for w in self.all(win)):
                    break
                time.sleep(0.02)
        copy = next(w for w, t in self.labels(win) if t == "Copy all")
        self.assertNotIn("disabled", copy.state())
        copy.invoke()
        self.assertEqual(self.root.clipboard_get(), "DIAG TEXT")

    def all(self, w):
        out = []
        for c in w.winfo_children():
            out.append(c)
            out += self.all(c)
        return out

    def test_about_has_the_button(self):
        self.app.show_about()
        win = self.app._about_win
        self.addCleanup(win.destroy)
        self.assertIn("Copy diagnostics", [t for _, t in self.labels(win)])


for _n in [n for n in dir(AboutWindowTests) if n.startswith("test_")]:
    setattr(DiagnosticsWindowTests, _n, None)



# ==========================================================================
# Round 36 - fixes for bugs found in Gemini's review
# ==========================================================================

@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class WorkProfileNetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()
        args = mock.Mock(serial=None, local=TMP_HOME, remote="/sdcard")
        with mock.patch.object(am.App, "scan_devices", lambda self, *a, **k: None):
            cls.app = am.App(cls.root, args)
        cls.tab = cls.app.net_tab

    @classmethod
    def tearDownClass(cls):
        destroy_root(cls.root)

    def sock(self, uid, port):
        return {"uid": uid, "kind": "conn", "proto": "tcp", "local_ip": "10.0.0.2", "local_port": port,
                "remote_ip": "142.250.0.1", "remote_port": 443, "state": "ESTABLISHED", "inode": port,
                "family": 4}

    def text(self):
        return self.tab.detail.get("1.0", "end") if hasattr(self.tab, "detail") else ""

    def test_owner_rows_use_the_full_uid(self):
        t = self.tab
        work = 10 * 100000 + 10123                       # same app, work profile (user 10)
        t.socks = [self.sock(10123, 40001), self.sock(work, 40002)]
        captured = {}
        with mock.patch.object(t, "render_owner", side_effect=lambda w, uid, items: captured.update(
                uid=uid, items=items)), mock.patch.object(t.tree, "selection", return_value=("x",)):
            t.rows["x"] = ("owner", work)
            t.render()
        self.assertEqual(captured["uid"], work)
        self.assertEqual([s["local_port"] for s in captured["items"]], [40002])   # was [] before the fix

    def test_system_uid_in_a_profile_is_system(self):
        t = self.tab
        lines = []
        t.render_owner(lambda text, *tags: lines.append(text), 10 * 100000 + 1000, [])
        self.assertTrue(any("A part of Android itself" in l for l in lines))


class Round36SmallFixTests(unittest.TestCase):
    def test_certs_from_v1_closes_the_zip(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        apk = os.path.join(d, "x.apk")
        with _zipfile.ZipFile(apk, "w") as z:
            z.writestr("classes.dex", b"x")
        opened = []
        real = _zipfile.ZipFile

        def tracking(*a, **k):
            zf = real(*a, **k)
            opened.append(zf)
            return zf
        with mock.patch.object(sa.zipfile, "ZipFile", side_effect=tracking):
            self.assertEqual(sa.certs_from_v1(apk), [])
        self.assertTrue(opened)
        self.assertTrue(all(zf.fp is None for zf in opened))       # closed before returning

    def test_damaged_restore_record_sends_nothing(self):
        tab = am.AutorunTab.__new__(am.AutorunTab)
        tab.saved = mock.Mock()
        ctx = {"serial": "S", "user": 0, "user_verified": True, "pkg": "a.b", "cls": "a.b.Rx", "before": "DEFAULT",
               "target_sdk": 34, "key": "S|0|a.b", "want_root": False}
        for bad in (None, 7, ["DEFAULT"], {"x": 1}, "", "ON", "disabled-user"):
            tab.saved.get.return_value = {"components": {"a.b.Rx": bad}}
            with mock.patch.object(am, "adb_shell") as sh, mock.patch.object(am, "set_component_state") as st:
                res = tab._act_run("rx_back", ctx)
            self.assertEqual(res["outcome"], "failed", bad)
            self.assertIn("missing or damaged", res["message"], bad)
            st.assert_not_called()
            sh.assert_not_called()


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class StoreProblemReportTests(WorkProfileNetworkTests):
    def test_newer_stores_are_reported(self):
        apps = self.app.apps_tab
        with mock.patch.object(apps.labels, "load_problem", "app_labels.json was damaged"), \
                mock.patch.object(self.app.autorun_tab.saved, "load_problem", "autorun_saved.json unreadable"), \
                mock.patch.object(self.app, "error") as err:
            apps._report_store_problems()
        msgs = " ".join(c[0][0] for c in err.call_args_list)
        self.assertIn("app_labels.json", msgs)
        self.assertIn("autorun_saved.json", msgs)


for _n in [n for n in dir(WorkProfileNetworkTests) if n.startswith("test_")]:
    setattr(StoreProblemReportTests, _n, None)



# ==========================================================================
# Round 37 - capture review corrections
# ==========================================================================

class Round37CaptureTests(CaptureBase):
    def edit(self, old, new):
        t = read(self.adb)
        self.assertIn(old, t)
        write(self.adb, t.replace(old, new))

    def test_disabled_observed_only_with_package_evidence(self):
        s = self.capture()[1]
        self.assertEqual(s["disabled_matching"], "observed")          # settings.OffRx disabled in its dump
        self.edit('"      disabledComponents:\\n        %s.OffRx\\n" % (p, PKGS.get(p, "?"), 3 if p == "com.foo" else 0, p))',
                  '"      disabledComponents:\\n        %s.Other\\n" % (p, PKGS.get(p, "?"), 3 if p == "com.foo" else 0, p))')
        self.assertEqual(self.capture()[1]["disabled_matching"], "accepted")   # extra receiver, not disabled

    def test_truncated_or_missing_dump_is_not_evidence(self):
        doc = self.capture()[2]
        for p in doc["probes"]:
            if p["id"] == "pkg:com.android.settings":
                p["truncated"], p["rc"] = True, None
        self.assertEqual(am.capture_summary(doc["probes"])["disabled_matching"], "accepted")
        probes = [p for p in doc["probes"] if p["id"] != "pkg:com.android.settings"]
        self.assertEqual(am.capture_summary(probes)["disabled_matching"], "accepted")

    def test_second_user_comparison(self):
        self.edit('out = "Users:\\n\\tUserInfo{0:Pedro Silva:c13} running\\n"',
                  'out = "Users:\\n\\tUserInfo{0:Pedro Silva:c13} running\\n\\tUserInfo{10:Work:30}\\n"')
        self.assertEqual(self.capture()[1]["user_scoping"], "accepted")         # same answer for both users
        self.edit('    if "LOCKED" in cmd or "QUICKBOOT" in cmd:',
                  '    if "--user 10" in cmd:\n        out = "1 receivers found:\\n    com.android.settings/.BootRx\\n"\n'
                  '    elif "LOCKED" in cmd or "QUICKBOOT" in cmd:')
        path, s, doc = self.capture()
        self.assertEqual(s["user_scoping"], "observed")
        self.assertNotIn("Work", json.dumps(doc))                                # user name masked
        self.edit('out = "1 receivers found:\\n    com.android.settings/.BootRx\\n"',
                  'rc, err = 255, "Error: no such user"')
        self.assertEqual(self.capture()[1]["user_scoping"], "accepted")         # a failed probe proves nothing

    def test_single_user_stays_accepted(self):
        s = self.capture()[1]
        self.assertEqual(s["user_scoping"], "accepted")

    def test_old_appops_tool_is_used_for_reads(self):
        self.edit('elif cmd == "cmd appops help":', 'elif cmd.startswith("cmd appops"):\n    rc, err = 127, "cmd: not found"\n'
                  'elif cmd == "cmd appops help":')
        self.edit('elif cmd == "appops help":\n    rc, err = 127, "/system/bin/sh: appops: not found (device %s)\\n" % SERIAL',
                  'elif cmd == "appops help":\n    out = "usage: appops ...\\n"\nelif cmd.startswith("appops get"):\n'
                  '    out = "RUN_IN_BACKGROUND: allow\\n"')
        path, s, doc = self.capture()
        self.assertEqual(s["appops_tool"], "appops")
        reads = [p for p in doc["probes"] if p["id"].startswith("appops:")]
        self.assertTrue(reads)
        self.assertTrue(all(p["cmd"].startswith("appops get ") for p in reads))
        got = [am.parse_appops_mode(p["out"], p["id"].rsplit(":", 1)[1]) for p in reads]
        self.assertIn("allow", got)

    def test_no_appops_tool_no_reads(self):
        self.edit('elif cmd == "cmd appops help":', 'elif cmd.startswith("cmd appops"):\n    rc, err = 127, "cmd: not found"\n'
                  'elif cmd == "cmd appops help":')
        path, s, doc = self.capture()
        self.assertEqual(s["appops_tool"], "none")
        self.assertFalse([p for p in doc["probes"] if p["id"].startswith("appops:")])

    def test_names_only_in_resolver_output_are_anonymised(self):
        self.edit('"        5 com.foo.pro/.ProRx filter 6\\n',
                  '"        5 com.foo.pro/.ProRx filter 6\\n        9 com.secret.messenger/.Boot filter 7\\n')
        raw = json.dumps(self.capture()[2])
        self.assertNotIn("secret", raw)

    def test_unreadable_system_list_anonymises_everything(self):
        # the system list prints names but then FAILS: a partial list must not be trusted
        self.edit('names = SYSTEM if "-s" in f else', 'names = None if "-s" in f else')
        self.edit('    out = "".join(("package:%s=%s\\n"',
                  '    if names is None:\n        sys.stdout.write("".join("package:%s\\n" % n for n in SYSTEM))\n'
                  '        sys.exit(1)\n    out = "".join(("package:%s=%s\\n"')
        raw = json.dumps(self.capture()[2]["probes"][3:])               # beyond props/user probes
        self.assertNotIn("com.android.settings", raw)
        self.assertNotIn("com.foo.pro", raw)

    def test_phone_formats_and_numbers_that_must_survive(self):
        c = am.CaptureSanitizer("S", set(), set(), set())
        t = c("call 912 345 678 or 21-123-4567 or (21) 123 4567; versionCode=123456789 "
              "[ro.build.version.security_patch]: [2025-03-01] AP3A.240905.015 priority=1000 build 9876543210")
        for bad in ("912 345 678", "21-123-4567", "(21) 123 4567"):
            self.assertNotIn(bad, t, bad)
        for good in ("versionCode=123456789", "2025-03-01", "AP3A.240905.015", "priority=1000", "9876543210"):
            self.assertIn(good, t, good)

    def test_final_file_size_limit_with_multibyte_and_escaping(self):
        # payload INSIDE the resolver section, so it's kept by resolver_section()
        self.edit('elif cmd == "pm list users":', 'elif cmd == "dumpsys package r":\n'
                  '    out = "Receiver Resolver Table:\\n" + ("  \\u00e9\\u4e2d\\"\\\\x\\n" * 60000)\n'
                  'elif cmd == "pm list users":')
        with mock.patch.object(am, "CAPTURE_TOTAL_CAP", 120000):
            path, s, doc = self.capture()
        res = next(p for p in doc["probes"] if p["id"] == "resolver")
        self.assertTrue(res["truncated"])                                        # it was the one cut
        self.assertLessEqual(os.path.getsize(path), 120000)                     # the real saved bytes
        self.assertIn("resolver", s["truncated"])
        self.assertEqual(s["resolver_table"], "unknown")                         # cut -> unknown, not "absent"

    def test_fit_capture_counts_serialised_bytes(self):
        doc = {"schema": "adbm-capture", "version": 1, "device": {},
               "probes": [{"id": "props", "cmd": "getprop", "rc": 0, "out": "中" * 10000, "err": "",
                           "truncated": False, "timed_out": False}]}
        fitted = am.fit_capture(doc, cap=9000)
        self.assertLessEqual(am.capture_bytes(fitted), 9000)
        self.assertTrue(fitted["probes"][0]["truncated"])
        self.assertIsNone(fitted["probes"][0]["rc"])

    def test_stderr_truncation_recorded(self):
        write(self.adb, "#!/usr/bin/env python3\nimport sys\nsys.stderr.write('e' * 100000)\n")
        os.chmod(self.adb, 0o755)
        r = am.capture_run("S", "x")
        self.assertTrue(r["err_truncated"])
        self.assertFalse(r["truncated"])


class Round37DiagnosticsTests(CaptureBase):
    def test_detected_user_and_failures_listed(self):
        t = read(self.adb).replace('out = "0\\n"', 'out = "10\\n"')
        write(self.adb, t)
        d = am.diagnostics_text("ABC123SERIAL")
        self.assertIn("Checked for Android user 10 (detected)", d)
        self.assertIn("Old receiver table: present", d)
        self.assertIn("Switched-off receivers included:", d)
        self.assertIn("AppOps tool: cmd appops", d)
        self.assertIn("Checks that didn't work: none", d)       # a missing OLD tool isn't a failure
        self.assertNotIn("ABC123SERIAL", d)
        self.assertNotIn("/system/bin/sh", d)                     # no raw error text

    def test_queries_use_the_detected_user(self):
        t = read(self.adb).replace('out = "0\\n"', 'out = "10\\n"')
        write(self.adb, t)
        sent = []
        real = am.capture_run

        def spy(serial, cmd, cap=am.CAPTURE_PROBE_CAP, timeout=am.CAPTURE_TIMEOUT):
            sent.append(cmd)
            return real(serial, cmd, cap, timeout)
        am.diagnostics_text("ABC123SERIAL", runner=spy)
        users = [c for c in sent if "--user" in c]
        self.assertTrue(users)
        self.assertTrue(all("--user 10" in c for c in users))


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class StartupStoreReportTests(unittest.TestCase):
    def test_autorun_store_problem_reported_at_startup(self):
        root = tk.Tk()
        root.withdraw()
        self.addCleanup(destroy_root, root)
        args = mock.Mock(serial=None, local=TMP_HOME, remote="/sdcard")
        with mock.patch.object(am.App, "scan_devices", lambda self, *a, **k: None):
            app = am.App(root, args)
        app.autorun_tab.saved.load_problem = "autorun_saved.json was damaged"
        with mock.patch.object(app, "error") as err:
            end = time.time() + 3
            while time.time() < end and not err.called:
                root.update()
                time.sleep(0.05)
        self.assertIn("autorun_saved.json", " ".join(c[0][0] for c in err.call_args_list))



# ==========================================================================
# Round 38 - final capture corrections
# ==========================================================================

def probe(pid, out="", rc=0, **kw):
    d = {"id": pid, "cmd": pid, "rc": rc, "out": out, "err": "", "truncated": False, "err_truncated": False,
         "timed_out": False}
    d.update(kw)
    return d


def rx_out(*comps):
    return "%d receivers found:\n" % len(comps) + "".join("    %s\n" % c for c in comps)


class Round38SummaryTests(unittest.TestCase):
    A0 = am.BOOT_ACTIONS[0]

    def base(self, scoped=("a.b/.Rx",), plain=("a.b/.Rx",), flags_only=("a.b/.Rx",), other=None, user_out="0\n",
             users="Users:\n\tUserInfo{0:x:c13}\n\tUserInfo{10:y:30}\n", scoped_rc=0):
        ps = [probe("current_user", user_out), probe("users", users)]
        for name, _, _ in am.QUERY_FORMS:
            for a in am.BOOT_ACTIONS:
                comps = {"user+flags": scoped, "user": plain, "flags": flags_only, "plain": plain}[name] \
                    if a == self.A0 else ()
                rc = scoped_rc if name == "user+flags" else 0
                ps.append(probe("query:%s:%s" % (name, a), rx_out(*comps) if rc == 0 else "", rc=rc,
                                err="" if rc == 0 else "Error: Unknown option"))
        if other is not None:
            ps.append(probe("query:other_user:10", rx_out(*other)))
        return ps

    def test_user_scoping_compares_equivalent_queries(self):
        s = am.capture_summary(self.base(scoped=(), other=("a.b/.Rx",)))
        self.assertEqual(s["user_scoping"], "observed")                # empty vs non-empty is a real difference
        s = am.capture_summary(self.base(scoped=("a.b/.Rx",), other=("a.b/.Rx",)))
        self.assertEqual(s["user_scoping"], "accepted")                # identical sets

    def test_failed_scoped_query_is_never_replaced(self):
        s = am.capture_summary(self.base(scoped_rc=255, flags_only=("c.d/.Other",), other=("a.b/.Rx",)))
        self.assertNotEqual(s["user_scoping"], "observed")             # unscoped result isn't substituted

    def test_empty_scoped_result_is_used_not_the_unscoped_one(self):
        # scoped succeeds EMPTY, unscoped flags query returns receivers equal to the other user's
        s = am.capture_summary(self.base(scoped=(), flags_only=("a.b/.Rx",), other=("a.b/.Rx",)))
        self.assertEqual(s["user_scoping"], "observed")                # compared () with other, correctly

    def test_disabled_matching_uses_the_successful_form(self):
        dump = ("  Package [a.b] (1):\n    User 0: installed=true enabled=0\n      disabledComponents:\n"
                "        a.b.Off\n")
        ps = self.base(scoped=(), plain=(), flags_only=("a.b/.Off",)) + [probe("pkg:a.b", dump)]
        # scoped (user+flags) succeeded with an EMPTY set: that's the chosen answer, so no extra receiver
        self.assertEqual(am.capture_summary(ps)["disabled_matching"], "accepted")
        ps = self.base(scoped_rc=255, plain=(), flags_only=("a.b/.Off",)) + [probe("pkg:a.b", dump)]
        self.assertEqual(am.capture_summary(ps)["disabled_matching"], "observed")   # flags form chosen

    def test_no_observation_for_an_unidentified_user(self):
        dump = ("  Package [a.b] (1):\n    User 0: installed=true enabled=0\n      disabledComponents:\n"
                "        a.b.Off\n")
        ps = self.base(scoped=("a.b/.Off",), plain=(), user_out="", ) + [probe("pkg:a.b", dump)]
        ps[0]["rc"] = 255
        self.assertEqual(am.capture_summary(ps)["disabled_matching"], "accepted")   # two users, none detected
        ps[1]["out"] = "Users:\n\tUserInfo{0:x:c13}\n"                              # demonstrably single-user
        self.assertEqual(am.capture_summary(ps)["disabled_matching"], "observed")

    def test_stderr_truncation_counts_as_incomplete(self):
        ps = self.base()
        ps[2]["err_truncated"] = True
        s = am.capture_summary(ps)
        self.assertIn(ps[2]["id"], s["truncated"])
        self.assertNotIn("user+flags", s["query_forms_accepted"])

    def test_resolver_tri_state(self):
        ok = am.capture_summary([probe("resolver", "Receiver Resolver Table:\n  x\n")])
        absent = am.capture_summary([probe("resolver", "")])
        failed = am.capture_summary([probe("resolver", "", rc=1)])
        timed = am.capture_summary([probe("resolver", "", rc=None, timed_out=True)])
        self.assertEqual([ok["resolver_table"], absent["resolver_table"], failed["resolver_table"],
                          timed["resolver_table"]], ["present", "absent", "unknown", "unknown"])
        self.assertIn("couldn't be checked", am.capture_summary_text(dict(failed, device="x", android="1",
                                                                          sdk="1", boot_receivers=0)))


class Round38SampleTests(unittest.TestCase):
    def test_never_more_than_twelve_dumps(self):
        sysp = {"s%02d.x" % i for i in range(30)}
        third = {"u%02d.x" % i for i in range(30)}
        pick = am.pick_sample(sysp | third, sysp, third, {"d.x"}, evidence={"e%d.x" % i for i in range(9)})
        self.assertEqual(len(pick), 12)
        self.assertEqual(pick[:4], sorted("e%d.x" % i for i in range(9))[:4])       # evidence first
        self.assertEqual(len([p for p in pick if p.startswith("u")]), 3)          # user samples kept
        self.assertIn("d.x", pick)

    def test_capture_has_at_most_twelve_pkg_probes(self):
        t = CaptureBase("setUp")
        t.setUp()
        self.addCleanup(t.doCleanups)
        many_sys = "".join('"com.sys%d.app": "/system/app/S%d.apk", ' % (i, i) for i in range(20))
        many_usr = "".join('"com.usr%d.app": "/data/app/u%d/base.apk", ' % (i, i) for i in range(20))
        txt = read(t.adb).replace('PKGS = {', 'PKGS = {' + many_sys + many_usr)
        txt = txt.replace('SYSTEM = [', 'SYSTEM = [%s' % "".join('"com.sys%d.app", ' % i for i in range(20)))
        txt = txt.replace('THIRD = [', 'THIRD = [%s' % "".join('"com.usr%d.app", ' % i for i in range(20)))
        txt = txt.replace('rx = ["com.android.settings/.BootRx",',
                          'rx = [%s"com.android.settings/.BootRx",' % "".join(
                              '"com.sys%d.app/.R", "com.usr%d.app/.R", ' % (i, i) for i in range(20)))
        write(t.adb, txt)
        doc = t.capture()[2]
        self.assertLessEqual(len([p for p in doc["probes"] if p["id"].startswith("pkg:")]), 12)


class Round38DiagnosticsTests(CaptureBase):
    def test_stderr_cut_reported(self):
        txt = read(self.adb).replace('elif cmd == "am get-current-user":\n    out = "0\\n"',
                                     'elif cmd == "am get-current-user":\n    out, err = "0\\n", "x" * 5000')
        self.assertNotEqual(txt, read(self.adb))
        write(self.adb, txt)
        d = am.diagnostics_text("ABC123SERIAL")
        self.assertIn("current_user: error output cut at the size limit", d)

    def test_unknown_resolver_not_reported_as_absent(self):
        txt = read(self.adb).replace('elif cmd == "dumpsys package r":', 'elif cmd == "dumpsys package r":\n'
                                     '    sys.exit(1)\nelif cmd == "never":')
        write(self.adb, txt)
        d = am.diagnostics_text("ABC123SERIAL")
        self.assertIn("Old receiver table: couldn't be checked", d)

    def test_writer_and_size_check_share_one_serialisation(self):
        doc = {"a": "é中\"\\", "b": [1, 2]}
        p = os.path.join(self.d, "x.json")
        sa.atomic_write_json(p, doc)
        self.assertEqual(os.path.getsize(p), am.capture_bytes(doc))



# ==========================================================================
# Round 39 - confirmed users, error lines never count as evidence
# ==========================================================================

class Round39SummaryTests(Round38SummaryTests):
    def test_users_probe_failed_or_cut_means_no_observation(self):
        for change in ({"rc": 1}, {"truncated": True, "rc": None}, {"err_truncated": True}):
            ps = self.base(scoped=("a.b/.Rx",), other=())
            ps[1].update(change)                              # the users probe
            self.assertNotEqual(am.capture_summary(ps)["user_scoping"], "observed", change)

    def test_other_user_must_be_in_the_user_list(self):
        ps = self.base(scoped=("a.b/.Rx",), other=(), users="Users:\n\tUserInfo{0:x:c13}\n\tUserInfo{11:y:30}\n")
        self.assertNotEqual(am.capture_summary(ps)["user_scoping"], "observed")      # probe is for user 10
        ps = self.base(scoped=("a.b/.Rx",), other=())                                # 0 and 10 confirmed
        self.assertEqual(am.capture_summary(ps)["user_scoping"], "observed")

    def test_scoped_user_must_be_in_the_user_list(self):
        ps = self.base(scoped=("a.b/.Rx",), other=(), user_out="5\n")                # current user 5 not listed
        self.assertNotEqual(am.capture_summary(ps)["user_scoping"], "observed")

    def test_resolver_error_line_with_exit_zero_is_unknown(self):
        s = am.capture_summary([probe("resolver", "Error: Can't find service: package\n")])
        self.assertEqual(s["resolver_table"], "unknown")
        s = am.capture_summary([probe("resolver", "", err="Exception occurred while dumping\n")])
        self.assertEqual(s["resolver_table"], "unknown")

    def test_package_dump_error_line_is_not_evidence(self):
        dump = ("  Package [a.b] (1):\n    User 0: installed=true enabled=0\n      disabledComponents:\n"
                "        a.b.Off\nError: dump interrupted\n")
        ps = self.base(scoped=("a.b/.Off",), plain=()) + [probe("pkg:a.b", dump)]
        ps[1]["out"] = "Users:\n\tUserInfo{0:x:c13}\n"
        self.assertEqual(am.capture_summary(ps)["disabled_matching"], "accepted")


class Round39CaptureTests(CaptureBase):
    def edit(self, old, new):
        t = read(self.adb)
        self.assertIn(old, t)
        write(self.adb, t.replace(old, new))

    def test_failed_user_list_schedules_no_second_user_probe(self):
        self.edit('out = "Users:\\n\\tUserInfo{0:Pedro Silva:c13} running\\n"',
                  'out = "Users:\\n\\tUserInfo{0:Pedro Silva:c13} running\\n\\tUserInfo{10:Work:30}\\n"; rc = 1')
        path, s, doc = self.capture()
        self.assertFalse([p for p in doc["probes"] if p["id"].startswith("query:other_user")])
        self.assertNotEqual(s["user_scoping"], "observed")

    def test_system_list_with_error_line_is_not_trusted(self):
        # exit 0, partial system list, then an error line: names must not count as system
        self.edit('names = SYSTEM if "-s" in f else', 'names = None if "-s" in f else')
        self.edit('    out = "".join(("package:%s=%s\\n"',
                  '    if names is None:\n        sys.stdout.write("".join("package:%s\\n" % n for n in SYSTEM) + '
                  '"Error: Could not access the Package Manager\\n")\n        sys.exit(0)\n'
                  '    out = "".join(("package:%s=%s\\n"')
        raw = json.dumps(self.capture()[2]["probes"][3:])
        self.assertNotIn("com.android.settings", raw)
        self.assertNotIn("com.foo.pro", raw)

    def test_diagnostics_classifies_resolver_errors_without_showing_them(self):
        self.edit('elif cmd == "dumpsys package r":', 'elif cmd == "dumpsys package r":\n'
                  '    rc, err = 127, "/system/bin/sh: dumpsys: not found SECRET-DETAIL\\n"\nelif cmd == "never":')
        d = am.diagnostics_text("ABC123SERIAL")
        self.assertIn("resolver: not supported", d)                 # classified from the stderr kept inside
        self.assertIn("Old receiver table: couldn't be checked", d)
        self.assertNotIn("SECRET-DETAIL", d)


class Round39FixtureTests(RealCaptureFixtureTests):
    def test_empty_successful_real_inventory_is_accepted(self):
        doc = self.capture()[2]
        for p in doc["probes"]:
            if p["id"].startswith("query:"):
                p["out"] = ""                                          # complete, successful, empty
        self.check(doc, "real-phone-without-receivers")

    def test_unparsable_real_output_is_rejected(self):
        doc = self.capture()[2]
        for p in doc["probes"]:
            if p["id"].startswith("query:"):
                p["out"] = "garbled ### output\n"
        with self.assertRaises(AssertionError):
            self.check(doc, "real-phone-garbled")


for _n in [n for n in dir(Round38SummaryTests) if n.startswith("test_")]:
    setattr(Round39SummaryTests, _n, None)
for _n in [n for n in dir(RealCaptureFixtureTests) if n.startswith("test_")]:
    setattr(Round39FixtureTests, _n, None)



# ==========================================================================
# Round 40 - filters must never erase a command's error report
# ==========================================================================

class Round40EndToEndTests(CaptureBase):
    def edit(self, old, new):
        t = read(self.adb)
        self.assertIn(old, t)
        write(self.adb, t.replace(old, new))

    def test_resolver_stdout_error_survives_filtering(self):
        self.edit('elif cmd == "dumpsys package r":', 'elif cmd == "dumpsys package r":\n'
                  '    out = "Error: Can\'t find service: package\\n"\nelif cmd == "never-r":')
        path, s, doc = self.capture()
        res = next(p for p in doc["probes"] if p["id"] == "resolver")
        self.assertEqual(res["out"], "")                      # the filter kept nothing ...
        self.assertTrue(res["command_error"])                 # ... but the error was recorded first
        self.assertEqual(s["resolver_table"], "unknown")      # not "absent"

    def test_package_dump_error_after_a_good_block_is_not_evidence(self):
        # every package dump ends with an error line that trim_package_dump drops
        self.edit('"      disabledComponents:\\n        %s.OffRx\\n" % (p, PKGS.get(p, "?"), 3 if p == "com.foo" else 0, p))',
                  '"      disabledComponents:\\n        %s.OffRx\\nError: dump interrupted\\n" % '
                  '(p, PKGS.get(p, "?"), 3 if p == "com.foo" else 0, p))')
        path, s, doc = self.capture()
        dumps = [p for p in doc["probes"] if p["id"].startswith("pkg:")]
        self.assertTrue(dumps)
        self.assertTrue(all(p["command_error"] for p in dumps))
        self.assertTrue(all("Error" not in p["out"] for p in dumps))        # filtered out ...
        self.assertNotEqual(s["disabled_matching"], "observed")           # ... yet still not evidence

    def test_successful_dumps_unchanged(self):
        path, s, doc = self.capture()
        res = next(p for p in doc["probes"] if p["id"] == "resolver")
        self.assertFalse(res["command_error"])
        self.assertEqual(s["resolver_table"], "present")
        self.assertEqual(s["disabled_matching"], "observed")
        self.assertTrue(all(not p["command_error"] for p in doc["probes"] if p["id"].startswith("pkg:")))

    def test_diagnostics_classify_a_resolver_stdout_error_without_showing_it(self):
        self.edit('elif cmd == "dumpsys package r":', 'elif cmd == "dumpsys package r":\n'
                  '    out = "Error: Can\'t find service: package SECRET-DETAIL\\n"\nelif cmd == "never-r":')
        d = am.diagnostics_text("ABC123SERIAL")
        self.assertIn("resolver: reported an error", d)
        self.assertIn("Old receiver table: couldn't be checked", d)
        self.assertNotIn("SECRET-DETAIL", d)
        self.assertNotIn("find service", d)



# ==========================================================================
# Round 41 - AppOps found by a real read, judged by content (real Redmi:
#            every appops command returns exit code 255, even when it works)
# ==========================================================================

class RedmiExitCodePhone(FakePhone):
    """Like the real Redmi A7 (Android 15): appops commands work but exit with 255."""

    def __init__(self, ignore_set=False, **kw):
        super().__init__(**kw)
        self.ignore_set = ignore_set

    def __call__(self, serial, cmd, timeout=30):
        if (cmd.startswith("cmd appops ") or cmd.startswith("appops ")) and self.ignore_set and " set " in " " + cmd:
            self.log.append(cmd)
            return 255, "", ""                                  # "accepted", but nothing happens
        rc, out, err = FakePhone.__call__(self, serial, cmd, timeout)
        if cmd.startswith("cmd appops ") and rc == 0:
            rc = 255
        return rc, out, err


class AppOpsDetectionTests(unittest.TestCase):
    PKG = "org.videolan.vlc"

    def run_with(self, phone, fn, *a):
        with mock.patch.object(am, "adb_shell", side_effect=phone):
            return fn(*a)

    def test_tool_found_although_every_command_exits_255(self):
        ph = RedmiExitCodePhone()
        self.assertEqual(self.run_with(ph, am.appops_prefix, "S"), "cmd appops")
        self.assertFalse(any(c.endswith(" help") for c in ph.log))            # no help-text guessing
        self.assertTrue(any(c == "cmd appops " + am.APPOPS_PROBE for c in ph.log))

    def test_restrict_and_allow_verified_on_that_phone(self):
        ph = RedmiExitCodePhone()
        r = self.run_with(ph, am.restrict_background, "S", "cmd appops", self.PKG, 0, ["RUN_ANY_IN_BACKGROUND"])
        self.assertEqual(r["outcome"], "verified")
        r2 = self.run_with(ph, am.allow_background, "S", "cmd appops", self.PKG, 0, r["originals"])
        self.assertEqual(r2["outcome"], "verified")

    def test_a_write_that_does_nothing_is_never_called_verified(self):
        ph = RedmiExitCodePhone(ignore_set=True)
        r = self.run_with(ph, am.restrict_background, "S", "cmd appops", self.PKG, 0, ["RUN_ANY_IN_BACKGROUND"])
        self.assertEqual(r["outcome"], "unverified")                             # the read-back decides

    def test_non_answers_are_rejected(self):
        for out, err in (("", ""), ("usage: appops ...\n", ""), ("Error: Unknown operation string\n", ""),
                         ("", "/system/bin/sh: cmd: not found"), ("garbage\n", "")):
            self.assertFalse(am.appops_answer_ok(out, err), (out, err))
        self.assertTrue(am.appops_answer_ok("No operations.\nDefault mode: allow\n", ""))
        self.assertTrue(am.appops_answer_ok("RUN_IN_BACKGROUND: ignore\n", ""))

    def test_no_tool_at_all(self):
        self.assertIsNone(self.run_with(FakePhone(appops_cmd="nothing"), am.appops_prefix, "S"))

    def test_tool_without_user_option_falls_back_for_user_0(self):
        def sh(serial, cmd, timeout=20):
            if "--user" in cmd:
                return 255, "Error: Unknown option: --user\n", ""
            return 255, "RUN_ANY_IN_BACKGROUND: ignore\n", ""
        with mock.patch.object(am, "adb_shell", side_effect=sh):
            self.assertEqual(am.appops_get("S", "cmd appops", self.PKG, "RUN_ANY_IN_BACKGROUND", 0), "ignore")
            self.assertIsNone(am.appops_get("S", "cmd appops", self.PKG, "RUN_ANY_IN_BACKGROUND", 10))


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class RedmiRestrictGuiTests(AutorunControlGuiTests):
    def test_restrict_background_works_on_the_redmi_behaviour(self):
        """the exact flow that said 'this phone has no AppOps command' on the real Redmi"""
        ph = RedmiExitCodePhone()
        self.select("p:" + self.PKG)
        ask, ok, warn = self.run_act(ph, "bg_restrict")
        self.assertFalse(warn.called, warn.call_args)
        self.assertIn("Done - checked on the phone", ok.call_args[0][1])
        self.assertIn("RUN_ANY_IN_BACKGROUND = ignore", ok.call_args[0][1])


class AppOpsCaptureTests(CaptureBase):
    def test_capture_detects_the_tool_despite_exit_255(self):
        t = read(self.adb).replace('elif cmd.startswith("cmd appops get"):\n    out = "No operations.\\nDefault mode: allow\\n"',
                                   'elif cmd.startswith("cmd appops get"):\n    out, rc = "No operations.\\nDefault mode: allow\\n", 255')
        self.assertNotEqual(t, read(self.adb))
        write(self.adb, t)
        path, s, doc = self.capture()
        self.assertEqual(s["appops_tool"], "cmd appops")
        self.assertTrue([p for p in doc["probes"] if p["id"].startswith("appops:")])   # sample reads happen
        d = am.diagnostics_text("ABC123SERIAL")
        self.assertIn("AppOps tool: cmd appops", d)
        self.assertNotIn("appops_tool", d)                                       # not listed as a failure


for _n in [n for n in dir(AutorunControlGuiTests) if n.startswith("test_")]:
    setattr(RedmiRestrictGuiTests, _n, None)



# ==========================================================================
# Round 42 - an incomplete AppOps probe never establishes the tool
# ==========================================================================

class Round42AppOpsCompletenessTests(CaptureBase):
    GOOD = "No operations.\nDefault mode: allow\n"

    def test_summary_rejects_incomplete_answers(self):
        for flag in ("err_truncated", "command_error", "truncated", "timed_out"):
            ps = [probe("appops_tool:cmd", self.GOOD, rc=255, **{flag: True})]
            self.assertEqual(am.capture_summary(ps)["appops_tool"], "none", flag)
        self.assertEqual(am.capture_summary([probe("appops_tool:cmd", self.GOOD, rc=255)])["appops_tool"],
                         "cmd appops")                                  # control: complete answer counts

    def test_capture_rejects_a_stderr_cut_answer(self):
        t = read(self.adb).replace('elif cmd.startswith("cmd appops get"):\n    out = "No operations.\\nDefault mode: allow\\n"',
                                   'elif cmd.startswith("cmd appops get"):\n    out, err = "No operations.\\nDefault mode: allow\\n", "w" * 5000')
        self.assertNotEqual(t, read(self.adb))
        write(self.adb, t)
        path, s, doc = self.capture()
        self.assertEqual(s["appops_tool"], "none")
        self.assertFalse([p for p in doc["probes"] if p["id"].startswith("appops:")])   # no sample reads

    def test_capture_rejects_an_answer_flagged_as_error(self):
        real = am.capture_run

        def runner(serial, cmd, cap=am.CAPTURE_PROBE_CAP, timeout=am.CAPTURE_TIMEOUT):
            r = real(serial, cmd, cap, timeout)
            return r
        with mock.patch.object(am, "query_error",
                               side_effect=lambda t: "Default mode" in (t or "") and "No operations" in (t or "")
                               and "MARK" in (t or "")):
            t = read(self.adb).replace('elif cmd.startswith("cmd appops get"):\n    out = "No operations.\\nDefault mode: allow\\n"',
                                       'elif cmd.startswith("cmd appops get"):\n    out = "No operations.\\nDefault mode: allow\\n"; err = "MARK"')
            write(self.adb, t)
            path, s, doc = self.capture(runner=runner)
        tool = next(p for p in doc["probes"] if p["id"] == "appops_tool:cmd")
        self.assertTrue(tool["command_error"])
        self.assertEqual(s["appops_tool"], "none")



# ==========================================================================
# Round 43 - known Android security issues vs. this device (assessment only)
# Fixture: REAL records from OSV's Android data and the CISA KEV list
# (CVE-2025-48595, a kernel issue, a Qualcomm issue), code signatures trimmed.
# ==========================================================================

import cve_check as cv

OSV_FIXTURE = json.loads(r"""{"framework":{"schema_version":"1.9.2","id":"ASB-A-430889718","published":"2026-06-01T00:00:00Z","modified":"2026-11-13T17:13:06.336358243Z","aliases":["A-430889718","CVE-2025-48595"],"details":"In multiple locations, there is a possible way to achieve code execution due to an integer overflow. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.","affected":[{"package":{"name":"platform/external/sqlite","ecosystem":"Android"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"17-next:0"},{"fixed":"17-next:2026-06-01"}]}],"versions":["17-next"],"ecosystem_specific":{"fixes":["https://android.googlesource.com/platform/external/sqlite/+/64da918dc231e1daffdd0cb4c8fd349f661dc7a0"],"severity":"High","spl":"2026-06-01","types":["EoP"]},"database_specific":{"source":"https://storage.googleapis.com/android-osv/ASB-A-430889718.json"}},{"package":{"name":"platform/build/release","ecosystem":"Android"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"15:0"},{"fixed":"15:2026-06-01"}]}],"versions":["15"],"ecosystem_specific":{"fixes":["https://android.googlesource.com/platform/build/release/+/21e0356e18f7488c1803e2340000b02494d366c8"],"severity":"High","spl":"2026-06-01","types":["EoP"]},"database_specific":{"source":"https://storage.googleapis.com/android-osv/ASB-A-430889718.json"}},{"package":{"name":"platform/external/sqlite","ecosystem":"Android"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"15:0"},{"fixed":"15:2026-06-01"}]}],"versions":["15"],"ecosystem_specific":{"fixes":["https://android.googlesource.com/platform/external/sqlite/+/53259b30e767bf8e7e9f61740d33c1c33462a7ff"],"severity":"High","spl":"2026-06-01","types":["EoP"],"vanir_signatures":[{"deprecated":false,"digest":{"function_hash":"256791654922173550216519694401914244847","length":271},"id":"ASB-A-430889718-0262b94f","match_only_versions":["15"],"signature_type":"Function","signature_version":"v1","source":"https://android.googlesource.com/platform/external/sqlite/+/8dc8ff81130423f35f69813ffc5ce5ed6bee5b58","target":{"file":"dist/sqlite-autoconf-3440300/orig/sqlite3.c","function":"fts5SourceIdFunc"}}]},"database_specific":{"source":"https://storage.googleapis.com/android-osv/ASB-A-430889718.json"}},{"package":{"name":"platform/vendor/google_shared/build/release","ecosystem":"Android"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"15:0"},{"fixed":"15:2026-06-01"}]}],"versions":["15"],"ecosystem_specific":{"fixes":["https://android.googlesource.com/platform/vendor/google_shared/build/release/+/eb3ac62199c20ba2d184d0d178af6d54a5b3566f"],"severity":"High","spl":"2026-06-01","types":["EoP"]},"database_specific":{"source":"https://storage.googleapis.com/android-osv/ASB-A-430889718.json"}},{"package":{"name":"platform/build/release","ecosystem":"Android"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"16:0"},{"fixed":"16:2026-06-01"}]}],"versions":["16"],"ecosystem_specific":{"fixes":["https://android.googlesource.com/platform/build/release/+/4fa942eccc87d94d99b9144a026a19e555d852f9"],"severity":"High","spl":"2026-06-01","types":["EoP"]},"database_specific":{"source":"https://storage.googleapis.com/android-osv/ASB-A-430889718.json"}},{"package":{"name":"platform/external/sqlite","ecosystem":"Android"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"16:0"},{"fixed":"16:2026-06-01"}]}],"versions":["16"],"ecosystem_specific":{"fixes":["https://android.googlesource.com/platform/external/sqlite/+/d23b65365a93529a1f72e5792ffe6fc91f90521d"],"severity":"High","spl":"2026-06-01","types":["EoP"],"vanir_signatures":[{"deprecated":false,"digest":{"threshold":0.9},"id":"ASB-A-430889718-1ac1cbbc","match_only_versions":["16"],"signature_type":"Line","signature_version":"v1","source":"https://android.googlesource.com/platform/external/sqlite/+/b944515af154aaf989505335f10b6f59f26dc783","target":{"file":"dist/sqlite-autoconf-3440300/orig/sqlite3.c"}}]},"database_specific":{"source":"https://storage.googleapis.com/android-osv/ASB-A-430889718.json"}},{"package":{"name":"platform/build/release","ecosystem":"Android"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"16-qpr2:0"},{"fixed":"16-qpr2:2026-06-01"}]}],"versions":["16-qpr2"],"ecosystem_specific":{"fixes":["https://android.googlesource.com/platform/build/release/+/22c6c36c002073a91655e6c4c40450a186ec9691"],"severity":"High","spl":"2026-06-01","types":["EoP"]},"database_specific":{"source":"https://storage.googleapis.com/android-osv/ASB-A-430889718.json"}},{"package":{"name":"platform/external/sqlite","ecosystem":"Android"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"16-qpr2:0"},{"fixed":"16-qpr2:2026-06-01"}]}],"versions":["16-qpr2"],"ecosystem_specific":{"fixes":["https://android.googlesource.com/platform/external/sqlite/+/2b779db12008e8bd5ffed2a7febcc3bf44257ac1"],"severity":"High","spl":"2026-06-01","types":["EoP"]},"database_specific":{"source":"https://storage.googleapis.com/android-osv/ASB-A-430889718.json"}},{"package":{"name":"platform/external/sqlite","ecosystem":"Android"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"14:0"},{"fixed":"14:2026-06-01"}]}],"versions":["14"],"ecosystem_specific":{"fixes":["https://android.googlesource.com/platform/external/sqlite/+/7bb2643b287be3aaa293a29404b2190cd1c9afa4"],"severity":"High","spl":"2026-06-01","types":["EoP"],"vanir_signatures":[{"deprecated":false,"digest":{"function_hash":"197048159313896363010827363374536833304","length":5323},"id":"ASB-A-430889718-003f9a81","signature_type":"Function","signature_version":"v1","source":"https://android.googlesource.com/platform/external/sqlite/+/7f3961c3642d7dca948d433d768bbdb95be71c65","target":{"file":"dist/orig/sqlite3.c","function":"generateSortTail"}}]},"database_specific":{"source":"https://storage.googleapis.com/android-osv/ASB-A-430889718.json"}}],"references":[{"type":"ADVISORY","url":"https://source.android.com/security/bulletin/2026-06-01"},{"type":"FIX","url":"https://android.googlesource.com/platform/build/release/+/b11607ea3ec7ab3183b558392850c842c582d2cc"},{"type":"FIX","url":"https://android.googlesource.com/platform/external/sqlite/+/cbebed38b5798baa61d3924de8e09db9f458292c"}]},"kernel":{"schema_version":"1.9.2","id":"ASB-A-111893654","published":"2020-09-01T00:00:00Z","modified":"2026-11-13T17:13:06.336358243Z","aliases":["A-111893654","CVE-2020-0404"],"details":"In uvc_scan_chain_forward of uvc_driver.c, there is a possible linked list corruption due to an unusual root cause. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not needed for exploitation.","affected":[{"package":{"name":":linux_kernel:","ecosystem":"Android"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":":0"},{"fixed":":2020-09-05"}]}],"versions":["Kernel"],"ecosystem_specific":{"fixes":["https://android.googlesource.com/kernel/common/+/68035c80e129"],"severity":"High","spl":"2020-09-05","types":["EoP"]},"database_specific":{"source":"https://storage.googleapis.com/android-osv/ASB-A-111893654.json"}}],"references":[{"type":"ADVISORY","url":"https://source.android.com/security/bulletin/2020-09-01"},{"type":"FIX","url":"https://android.googlesource.com/kernel/common/+/68035c80e129"}]},"qualcomm":{"schema_version":"1.9.2","id":"ASB-A-147102899","published":"2020-09-01T00:00:00Z","modified":"2026-11-13T17:13:06.336358243Z","aliases":["2419153","2421602","2421611","A-147102899","CVE-2019-10527"],"affected":[{"package":{"name":":linux_kernel:Qualcomm","ecosystem":"Android"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"SoCVersion:0"},{"fixed":"SoCVersion:2020-09-05"}]}],"versions":["SoCVersion"],"ecosystem_specific":{"fixes":["https://source.codeaurora.org/quic/la/kernel/msm-4.9/commit/?id=24159c63bd7893a6061a29e06e01b96f02543eb3"],"severity":"High","spl":"2020-09-05","types":["Unknown"]},"database_specific":{"source":"https://storage.googleapis.com/android-osv/ASB-A-147102899.json"}}],"references":[{"type":"ADVISORY","url":"https://source.android.com/security/bulletin/2020-09-01"},{"type":"FIX","url":"https://source.codeaurora.org/quic/la/kernel/msm-4.9/commit/?id=24159c63bd7893a6061a29e06e01b96f02543eb3"}]},"kev":{"vulnerabilities":[{"cveID":"CVE-2025-48595","vendorProject":"Android","product":"Framework","vulnerabilityName":"Android Framework Integer Overflow Vulnerability","dateAdded":"2026-06-02","shortDescription":"Android Framework contains an integer overflow vulnerability that allows for code execution that could allow for local privilege escalation.","requiredAction":"Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.","dueDate":"2026-06-05","knownRansomwareCampaignUse":"Unknown","forensicTriage":"No","notes":"https://source.android.com/docs/security/bulletin/2026/2026-06-01 ; https://nvd.nist.gov/vuln/detail/CVE-2025-48595","cwes":["CWE-190"]}]}}""")

REDMI = {"ro.build.version.release": "15", "ro.build.version.sdk": "35",
         "ro.build.version.security_patch": "2026-02-01", "ro.product.manufacturer": "Xiaomi",
         "ro.product.model": "Redmi A7", "ro.soc.manufacturer": "Unisoc", "ro.board.platform": "ums9230"}


def dev_props(**kw):
    p = dict(REDMI)
    for k, v in kw.items():
        key = {"sdk": "ro.build.version.sdk", "spl": "ro.build.version.security_patch",
               "maker": "ro.product.manufacturer", "model": "ro.product.model",
               "soc": "ro.soc.manufacturer", "platform": "ro.board.platform"}[k]
        if v is None:
            p.pop(key, None)
        else:
            p[key] = v
    return p


def rec(labels_spl, types=("EoP",), sev="High", pkg="platform/frameworks/base", published="2026-06-01", cve="CVE-2099-0001"):
    """A synthetic compact record: labels_spl = [(labels, spl), ...]."""
    return {"id": "T-" + cve, "cves": [cve], "published": published, "details": "test", "advisories": [],
            "affected": [{"pkg": pkg, "labels": list(l), "spl": spl, "severity": sev, "types": list(types)}
                         for l, spl in labels_spl]}


# support window used by the synthetic tests: 13 stopped getting fixes in early 2026
SUPPORT = {33: "2026-03-01", 34: "2026-11-01", 35: "2026-11-01", 36: "2026-11-01", 37: "2026-11-01"}


class CveCompactTests(unittest.TestCase):
    def test_real_record_is_compacted(self):
        r = cv.compact_record(OSV_FIXTURE["framework"])
        self.assertEqual(r["cves"], ["CVE-2025-48595"])
        self.assertEqual(r["published"], "2026-06-01")
        self.assertNotIn("vanir", json.dumps(r))                       # big code signatures dropped
        self.assertIn("vanir", json.dumps(OSV_FIXTURE["framework"]))   # (they were in the input)
        self.assertEqual({e["spl"] for e in r["affected"]}, {"2026-06-01"})
        self.assertIn("15", {l for e in r["affected"] for l in e["labels"]})
        self.assertEqual(r["advisories"], ["https://source.android.com/security/bulletin/2026-06-01"])

    def test_fix_date_falls_back_to_the_range(self):
        raw = json.loads(json.dumps(OSV_FIXTURE["kernel"]))
        del raw["affected"][0]["ecosystem_specific"]["spl"]
        self.assertEqual(cv.compact_record(raw)["affected"][0]["spl"], "2020-09-05")   # from ":2020-09-05"
        raw["affected"][0]["ranges"] = []
        self.assertIsNone(cv.compact_record(raw)["affected"][0]["spl"])

    def test_malformed_ranges_and_events_never_crash(self):
        base = json.loads(json.dumps(OSV_FIXTURE["kernel"]))
        del base["affected"][0]["ecosystem_specific"]["spl"]         # force the range fallback
        for ranges in ("x", 5, {"events": []}, [None], ["x"], [5], [{"events": "x"}], [{"events": 7}],
                       [{"events": [None, "x", 3, ["fixed"]]}], [{"events": [{"fixed": 5}]}],
                       [{"events": [{"fixed": "no-colon"}]}], [{"events": [{"fixed": ":2020-99-01"}]}]):
            raw = json.loads(json.dumps(base))
            raw["affected"][0]["ranges"] = ranges
            r = cv.compact_record(raw)
            self.assertIsNone(r["affected"][0]["spl"], ranges)
            f = cv.assess_record(r, cv.device_facts(dev_props(spl="2020-01-01")), None, SUPPORT)
            self.assertEqual(f["state"], cv.UNKNOWN, ranges)            # no fix date -> unknown
        # a good range after bad ones is still found
        raw = json.loads(json.dumps(base))
        raw["affected"][0]["ranges"] = ["x", {"events": None}, {"events": [5, {"fixed": ":2020-09-05"}]}]
        self.assertEqual(cv.compact_record(raw)["affected"][0]["spl"], "2020-09-05")

    def test_malformed_top_level_fields(self):
        for field, bad in (("affected", 5), ("affected", "abc"), ("affected", {"a": 1}),
                           ("references", 5), ("references", "x"), ("aliases", 5),
                           ("affected", [{"package": "x", "versions": 5, "ecosystem_specific": 5}])):
            raw = json.loads(json.dumps(OSV_FIXTURE["framework"]))
            raw[field] = bad
            r = cv.compact_record(raw)
            self.assertIsNotNone(r, (field, bad))
            cv.assess([r], REDMI, {})                                    # never raises

    def test_bad_input(self):
        for bad in (None, [], {"id": 5}, "x"):
            self.assertIsNone(cv.compact_record(bad))
        r = cv.compact_record({"id": "X", "aliases": ["CVE-1", "not", 3], "affected": [5, {"package": {"ecosystem": "npm"}}]})
        self.assertEqual((r["cves"], r["affected"]), ([], []))

    def test_kev(self):
        k = cv.compact_kev(OSV_FIXTURE["kev"])
        self.assertIn("CVE-2025-48595", k)
        self.assertIsNone(cv.compact_kev({"nope": 1}))

    def test_spl_parsing(self):
        self.assertEqual(cv.parse_spl(" 2026-02-01 "), "2026-02-01")
        for bad in ("2026-13-01", "2026-02-30", "2026-2-1", "", None, "unknown"):
            self.assertIsNone(cv.parse_spl(bad), bad)


class CveRealRecordTests(unittest.TestCase):
    def setUp(self):
        self.fw = cv.compact_record(OSV_FIXTURE["framework"])
        self.kern = cv.compact_record(OSV_FIXTURE["kernel"])
        self.qc = cv.compact_record(OSV_FIXTURE["qualcomm"])
        self.kev = cv.compact_kev(OSV_FIXTURE["kev"])

    def one(self, r, props, kev=None, support=SUPPORT):
        return cv.assess_record(r, cv.device_facts(props), kev, support)

    def test_redmi_and_cve_2025_48595(self):
        f = self.one(self.fw, REDMI, self.kev)
        self.assertEqual(f["state"], cv.POTENTIAL)
        self.assertEqual((f["fix_spl"], f["device_spl"]), ("2026-06-01", "2026-02-01"))
        self.assertTrue(f["exploited_in_wild"])
        # the four questions stay separate
        self.assertIsNone(f["public_exploit"])
        self.assertIsNone(f["root_demonstrated"])
        self.assertIn("not the same as root", f["impact"])

    def test_patched_at_or_after_the_fix(self):
        for spl in ("2026-06-01", "2026-06-05", "2027-01-01"):
            self.assertEqual(self.one(self.fw, dev_props(spl=spl))["state"], cv.FIXED, spl)
        self.assertEqual(self.one(self.fw, dev_props(spl="2026-05-05"))["state"], cv.POTENTIAL)

    def test_unreadable_patch_level_is_unknown_never_clean(self):
        for spl in (None, "garbage", "2026-02-31"):
            self.assertEqual(self.one(self.fw, dev_props(spl=spl))["state"], cv.UNKNOWN, spl)

    def test_android_versions(self):
        self.assertEqual(self.one(self.fw, dev_props(sdk="34"))["state"], cv.POTENTIAL)     # 14 listed
        self.assertEqual(self.one(self.fw, dev_props(sdk="36"))["state"], cv.POTENTIAL)     # 16 / 16-qpr2
        # 13 is not listed, but it had stopped getting fixes before June 2026 -> unknown, not clean
        self.assertEqual(self.one(self.fw, dev_props(sdk="33"))["state"], cv.UNKNOWN)
        # 17 only as "17-next" (fixed during development) -> unknown when the patch is older
        self.assertEqual(self.one(self.fw, dev_props(sdk="37"))["state"], cv.UNKNOWN)
        self.assertEqual(self.one(self.fw, dev_props(sdk="37", spl="2026-07-01"))["state"], cv.FIXED)
        # too old for the data, unreadable, or newer than the data
        for sdk in ("23", None, "x", "40"):
            self.assertEqual(self.one(self.fw, dev_props(sdk=sdk))["state"], cv.UNKNOWN, sdk)

    def test_kernel_issue(self):
        self.assertEqual(self.one(self.kern, REDMI)["state"], cv.FIXED)                     # 2026 >= 2020-09-05
        f = self.one(self.kern, dev_props(spl="2020-09-01"))                                 # -01 < -05
        self.assertEqual((f["state"], f["confidence"]), (cv.POTENTIAL, "low"))

    def test_qualcomm_issue_by_chip(self):
        old, new, qcom = "2020-01-01", "2026-02-01", dict(soc="QTI", platform="kona")
        f = self.one(self.qc, dev_props(spl=old))                                            # Unisoc
        self.assertEqual((f["state"], f["applies"]), (cv.NOT_AFFECTED, False))
        f = self.one(self.qc, dev_props(spl=old, **qcom))
        self.assertEqual((f["state"], f["applies"]), (cv.POTENTIAL, True))
        f = self.one(self.qc, dev_props(spl=new, **qcom))
        self.assertEqual((f["state"], f["applies"]), (cv.FIXED, True))
        self.assertIn("at or after the fix", f["reason"])
        f = self.one(self.qc, dev_props(spl=old, soc=None, platform=None))                   # chip unknown
        self.assertEqual((f["state"], f["applies"]), (cv.UNKNOWN, None))
        # chip unknown + newer patch: covered IF it applies - and it says so; never "applies"
        f = self.one(self.qc, dev_props(spl=new, soc=None, platform=None))
        self.assertEqual((f["state"], f["applies"]), (cv.FIXED, None))
        self.assertIn("if it applies to your phone at all", f["reason"])
        f = self.one(self.qc, dev_props(spl=old, soc="Unisoc", platform="kona"))             # conflicting
        self.assertEqual((f["state"], f["applies"]), (cv.UNKNOWN, None))

    def test_kev_separate_from_exploit_and_root(self):
        self.assertIsNone(self.one(self.fw, REDMI, None)["exploited_in_wild"])               # list not downloaded
        self.assertFalse(self.one(self.kern, REDMI, self.kev)["exploited_in_wild"])          # not on the list
        f = self.one(self.fw, REDMI, self.kev)
        self.assertTrue(f["exploited_in_wild"] and f["public_exploit"] is None and f["root_demonstrated"] is None)


class CveSyntheticTests(unittest.TestCase):
    def one(self, r, props=REDMI, support=SUPPORT):
        return cv.assess_record(r, cv.device_facts(props), None, support)

    def test_not_listed_while_supported_is_not_affected(self):
        r = rec([(("16",), "2026-06-01")])                     # introduced in 16; 15 still supported then
        self.assertEqual(self.one(r)["state"], cv.NOT_AFFECTED)

    def test_not_listed_after_support_ended_is_unknown(self):
        r = rec([(("15",), "2026-06-01")])
        self.assertEqual(self.one(r, dev_props(sdk="33"))["state"], cv.UNKNOWN)
        self.assertEqual(self.one(r, dev_props(sdk="33"), support={})["state"], cv.UNKNOWN)

    def test_unnamed_vendor_part_never_matches_or_clears(self):
        r = rec([(("SoCVersion",), "2026-06-05")], pkg=":unknown:")
        self.assertEqual((self.one(r)["state"], self.one(r)["applies"]), (cv.UNKNOWN, None))
        f = self.one(r, dev_props(spl="2026-07-01"))
        self.assertEqual((f["state"], f["applies"]), (cv.FIXED, None))
        self.assertIn("if it applies to your phone at all", f["reason"])

    def test_pixel_parts(self):
        r = rec([(("Pixel-family specific",), "2026-06-05")], pkg=":unknown:")
        self.assertEqual(self.one(r)["state"], cv.NOT_AFFECTED)                              # Xiaomi
        self.assertEqual(self.one(r, dev_props(maker="Google", model="Pixel 8"))["state"], cv.POTENTIAL)
        f = self.one(r, dev_props(maker="Google", model="Pixel 8", spl="2026-07-01"))
        self.assertEqual((f["state"], f["applies"]), (cv.FIXED, True))
        self.assertEqual(self.one(r, dev_props(maker=None))["state"], cv.UNKNOWN)
        f = self.one(r, dev_props(maker=None, spl="2026-07-01"))
        self.assertEqual((f["state"], f["applies"]), (cv.FIXED, None))
        self.assertIn("if it applies to your phone at all", f["reason"])

    def test_worst_part_wins(self):
        r = rec([(("16",), "2026-06-01"), (("SoCVersion",), "2026-06-05")])
        r["affected"][1]["pkg"] = ":unknown:"
        self.assertEqual(self.one(r)["state"], cv.UNKNOWN)       # not affected + unknown = unknown

    def test_missing_fix_date_is_unknown(self):
        self.assertEqual(self.one(rec([(("15",), None)]))["state"], cv.UNKNOWN)
        self.assertEqual(self.one(rec([(("Kernel",), None)], pkg=":linux_kernel:"))["state"], cv.UNKNOWN)

    def test_latest_fix_for_your_version_decides(self):
        # two parts of the same issue for Android 15, fixed at different patch levels
        r = rec([(("15",), "2026-06-01"), (("15",), "2026-07-05")])
        self.assertEqual(self.one(r, dev_props(spl="2026-06-15"))["state"], cv.POTENTIAL)
        self.assertEqual(self.one(r, dev_props(spl="2026-07-05"))["state"], cv.FIXED)

    def test_dev_branch_only_or_empty(self):
        self.assertEqual(self.one(rec([(("99-next",), "2026-06-01")]))["state"], cv.UNKNOWN)
        self.assertEqual(self.one(rec([]))["state"], cv.UNKNOWN)

    def test_relevance_filter(self):
        self.assertTrue(cv.relevant(rec([(("15",), "2026-06-01")])))
        self.assertTrue(cv.relevant(rec([(("15",), "2026-06-01")], types=("RCE",), sev="Critical")))
        self.assertFalse(cv.relevant(rec([(("15",), "2026-06-01")], types=("ID", "DoS"))))
        self.assertFalse(cv.relevant(rec([(("15",), "2026-06-01")], sev="Moderate")))


class CveChipTests(unittest.TestCase):
    def test_chip_family(self):
        f = cv.chip_family
        self.assertEqual(f({"ro.soc.manufacturer": "QTI"}), "qualcomm")
        self.assertEqual(f({"ro.soc.manufacturer": "Mediatek"}), "other")
        self.assertEqual(f({"ro.board.platform": "ums9230"}), "other")
        self.assertEqual(f({"ro.board.platform": "mt6765"}), "other")
        self.assertEqual(f({"ro.board.platform": "lahaina"}), "qualcomm")
        self.assertIsNone(f({}))
        self.assertIsNone(f({"ro.board.platform": "kona", "ro.product.board": "mt6765"}))   # disagree
        self.assertIsNone(f({"ro.board.platform": "sm6225x"}))                                # too generic

    def test_maker_property_does_not_overrule_the_platform(self):
        f = cv.chip_family
        self.assertIsNone(f({"ro.soc.manufacturer": "Unisoc", "ro.board.platform": "kona"}))
        self.assertIsNone(f({"ro.soc.manufacturer": "QTI", "ro.board.platform": "mt6765"}))
        self.assertIsNone(f({"ro.soc.manufacturer": "Qualcomm", "ro.soc.model": "ums9230"}))
        self.assertEqual(f({"ro.soc.manufacturer": "QTI", "ro.board.platform": "kona"}), "qualcomm")   # agree
        self.assertEqual(f({"ro.soc.manufacturer": "Unisoc", "ro.board.platform": "ums9230"}), "other")
        self.assertEqual(f({"ro.soc.manufacturer": "Unisoc", "ro.board.platform": "sm6225x"}), "other")  # unrecognised token


class CveAssessTests(unittest.TestCase):
    def test_full_assessment_on_real_data(self):
        recs = [cv.compact_record(OSV_FIXTURE[k]) for k in ("framework", "kernel", "qualcomm")]
        kev = cv.compact_kev(OSV_FIXTURE["kev"])
        a = cv.assess(recs, REDMI, kev)
        first = a["findings"][0]
        self.assertEqual((first["cves"], first["state"]), (["CVE-2025-48595"], cv.POTENTIAL))
        self.assertEqual(a["counts"]["potential_and_exploited"], 1)
        self.assertEqual(a["counts"][cv.POTENTIAL], 1)
        self.assertNotIn("CVE-2019-10527", [c for f in a["findings"] for c in f["cves"]])   # type Unknown: not shown
        self.assertFalse(a["notes"])

    def test_notes_explain_missing_data(self):
        self.assertTrue(any("No bulletin data" in n for n in cv.assess([], REDMI, {})["notes"]))
        recs = [cv.compact_record(OSV_FIXTURE["framework"])]
        notes = cv.assess(recs, dev_props(spl=None), None)["notes"]
        self.assertTrue(any("patch level couldn't be read" in n for n in notes))
        self.assertTrue(any("known-exploited list" in n for n in notes))
        notes = cv.assess(recs, dev_props(sdk="23", spl="2016-05-01"), {})["notes"]
        self.assertTrue(any("starts at Android 8.0" in n for n in notes))
        self.assertTrue(any("older than the oldest bulletin" in n for n in notes))

    def test_support_window_from_data(self):
        recs = [rec([(("13",), "2025-01-01")], published="2025-01-01"),
                rec([(("13", "14"), "2026-02-01")], published="2026-02-01")]
        self.assertEqual(cv.support_window(recs), {33: "2026-02-01", 34: "2026-02-01"})

    def test_module_is_pure(self):
        with open(cv.__file__, encoding="utf-8") as fh:
            src = fh.read()
        for word in ("import subprocess", "import urllib", "import socket", "adb_shell", "import requests"):
            self.assertNotIn(word, src)



# ==========================================================================
# Round 44 - where an AI's sources came from (app research + rooting research)
# ==========================================================================

APP_REPLY = json.dumps({
    "vendor": "Example", "vendor_says": "does things",
    "independent_findings": [{"finding": "it phones home", "backing": "research",
                              "source": "https://Research.example.org/Report"}],
    "data_collection": "unknown", "disagreements": "none found", "when_disabled": "unknown",
    "verdict": "careful", "confidence": "medium", "summary": "be careful",
    "sources": ["https://vendor.example.com/page", "https://made-up.example.net/x"]})
ROOT_REPLY = json.dumps({"summary": "unlock via the official tool", "can_unlock": "yes",
                         "sources": ["https://xdaforums.com/t/real", "https://imagined.example/x"],
                         "confidence": "medium"})
SEARCH_USAGE = {"searches": 3, "urls": ["https://research.example.org/Report",
                                        "https://VENDOR.example.com/page", "https://xdaforums.com/t/real"]}


class SourceCheckTests(unittest.TestCase):
    def test_matching_rules(self):
        sc = ai.source_check(["https://A.example/Path", "https://a.example/path", "https://b.example/x",
                              "https://c.example/y", 5, "", "https://c.example/y"],
                             {"searches": 2, "urls": ["https://a.example/Path", "https://C.EXAMPLE/y", 7]})
        self.assertEqual(sc["searches"], 2)
        self.assertEqual(sc["urls"], {"https://A.example/Path": True,      # host case doesn't matter
                                      "https://a.example/path": False,     # path case does
                                      "https://b.example/x": False,
                                      "https://c.example/y": True})        # listed twice, kept once

    def test_bad_usage_and_cap(self):
        self.assertEqual(ai.source_check(["https://x.example/"], None), {"searches": 0,
                                                                           "urls": {"https://x.example/": False}})
        self.assertEqual(ai.source_check([], {"searches": "lots"})["searches"], 0)
        self.assertEqual(ai.source_check([], {"searches": -4})["searches"], 0)
        many = ["https://x.example/%d" % i for i in range(100)]
        self.assertEqual(len(ai.source_check(many, {})["urls"]), ai.MAX_CHECKED_SOURCES)


class ResearchProvenanceTests(unittest.TestCase):
    def ask(self, text, usage=SEARCH_USAGE):
        return mock.patch.object(ai, "_ask_anthropic", return_value=(text, dict(usage)))

    def test_app_research_records_the_check(self):
        with self.ask(APP_REPLY):
            res = ai.research("anthropic", {}, {"package": "com.example"}, {})
        sc = res["answer"]["source_check"]
        self.assertEqual(sc["searches"], 3)
        self.assertEqual(sc["urls"], {"https://Research.example.org/Report": True,   # a finding's source
                                      "https://vendor.example.com/page": True,
                                      "https://made-up.example.net/x": False})

    def test_rooting_research_records_the_check(self):
        with self.ask(ROOT_REPLY):
            res = ai.research_rooting("anthropic", {}, {"props": {}, "groups": []})
        self.assertEqual(res["answer"]["source_check"]["urls"],
                         {"https://xdaforums.com/t/real": True, "https://imagined.example/x": False})

    def test_no_search_means_nothing_matches(self):
        with self.ask(ROOT_REPLY, {"searches": 0, "urls": []}):
            sc = ai.research_rooting("anthropic", {}, {"props": {}, "groups": []})["answer"]["source_check"]
        self.assertEqual(sc["searches"], 0)
        self.assertFalse(any(sc["urls"].values()))

    def test_failed_reply_has_no_answer_and_no_check(self):
        with self.ask("not json at all"):
            res = ai.research("anthropic", {}, {"package": "com.example"}, {})
        self.assertNotIn("answer", res)
        self.assertTrue(res["error"])

    def test_the_check_is_saved_with_the_rooting_answer(self):
        with self.ask(ROOT_REPLY):
            res = ai.research_rooting("anthropic", {}, {"props": {}, "groups": []})
        with tempfile.TemporaryDirectory() as d:
            info = {"props": {"ro.product.manufacturer": "Xiaomi", "ro.product.model": "X1"}, "codename": "x1"}
            with mock.patch.object(sa, "ROOTING_DB_FILE", os.path.join(d, "rooting_db.json")):
                self.assertTrue(sa.rooting_db_put(info, res))
                entry = sa.rooting_db_get(info)
        self.assertEqual(entry["answer"]["source_check"], res["answer"]["source_check"])


class SourceDisplayTests(unittest.TestCase):
    def collect(self):
        out = []
        return out, (lambda text, tag=(): out.append((text, tag)))

    def apps_render(self, answer):
        res = {"provider": "anthropic", "model": "m", "when": "now", "answer": answer}
        fake = mock.Mock()
        fake.ai_cache = {"com.example": {"anthropic": res}}
        fake.ai_answers = lambda pkg: {"anthropic": res}
        out, w = self.collect()
        with mock.patch.object(ai, "load_config", return_value={}):
            am.AppsTab.render_ai(fake, "com.example", None, w)
        return "".join(t for t, _ in out), out

    def app_answer(self, usage=SEARCH_USAGE):
        with mock.patch.object(ai, "_ask_anthropic", return_value=(APP_REPLY, dict(usage))):
            return ai.research("anthropic", {}, {"package": "com.example"}, {})["answer"]

    def test_apps_tab_marks_each_source(self):
        text, _ = self.apps_render(self.app_answer())
        self.assertIn("https://Research.example.org/Report  (found by the AI's web search", text)
        self.assertIn("https://made-up.example.net/x  (NOT among the pages", text)
        self.assertIn("not that it backs the answer", text)          # a match isn't proof
        self.assertNotIn("No web search was done", text)

    def test_apps_tab_warns_when_no_search_was_done(self):
        text, out = self.apps_render(self.app_answer({"searches": 0, "urls": []}))
        self.assertIn(("No web search was done for this answer: it's based on the AI's own knowledge, which "
                       "may be out of date, and its sources may be written from memory.\n", "warn"), out)
        self.assertNotIn("NOT among the pages", text)          # no search -> nothing to attribute

    def test_apps_tab_older_answer_says_so_without_inventing_marks(self):
        a = self.app_answer()
        del a["source_check"]
        text, _ = self.apps_render(a)
        self.assertIn("Older answer: it wasn't recorded", text)
        self.assertNotIn("found by the AI's web search", text)
        self.assertNotIn("NOT among the pages", text)

    def info_render(self, answer):
        fake = mock.Mock()
        links = []
        fake.add_link = lambda txt, url: links.append(url)
        out, w = self.collect()
        am.DeviceInfoWindow._render_answer_fields(fake, w, answer)
        return "".join(t for t, _ in out), out, links

    def root_answer(self, usage=SEARCH_USAGE):
        with mock.patch.object(ai, "_ask_anthropic", return_value=(ROOT_REPLY, dict(usage))):
            return ai.research_rooting("anthropic", {}, {"props": {}, "groups": []})["answer"]

    def test_info_window_marks_each_source(self):
        text, out, links = self.info_render(self.root_answer())
        self.assertEqual(links, ["https://xdaforums.com/t/real", "https://imagined.example/x"])
        self.assertEqual(text.count("found by the AI's web search"), 1)
        self.assertEqual(text.count("NOT among the pages"), 1)

    def test_info_window_warns_without_search_even_with_no_sources(self):
        a = self.root_answer({"searches": 0, "urls": []})
        a["sources"] = []
        text, out, links = self.info_render(a)
        self.assertIn("No web search was done", text)
        self.assertEqual(links, [])

    def test_info_window_older_saved_answer(self):
        a = self.root_answer()
        del a["source_check"]
        text, out, links = self.info_render(a)
        self.assertIn("Older answer: it wasn't recorded", text)
        self.assertNotIn("found by the AI's web search", text)
        self.assertEqual(len(links), 2)

    def test_marks_ignore_damaged_checks(self):
        for sc in (None, 5, {"urls": 5}, {"urls": {"https://a.example/": "yes"}}):
            mark = am.source_mark({"source_check": sc}, "https://a.example/")
            self.assertEqual(mark, "", sc)                         # only a real True/False is shown



# ==========================================================================
# Round 45 - "connect the dots": several spyware signs on the same app
# ==========================================================================

def pfacts(apps, appops=None, failed=None):
    return {"apps": apps, "appops": appops or {}, "failed": failed or {}, "settings": {}, "admins": []}


def papp(installer="com.android.packageinstaller", system=False, **kw):
    a = {"system": system, "installer": installer, "removed": False, "disabled": False}
    a.update(kw)
    return a


NO_ACCESS = {c: [] for c in ("accessibility", "admin", "notifications", "overlay", "usage", "install", "sms")}
BOOT_ALL = lambda pkgs, complete=True: {"complete": complete, "pkgs": {p: True for p in pkgs}}  # noqa: E731
LBL = lambda p: p  # noqa: E731


def acc(**cats):
    a = dict(NO_ACCESS)
    for c, pkgs in cats.items():
        a[c] = list(pkgs)
    return a


class PatternCheckTests(unittest.TestCase):
    def run_(self, apps, access=NO_ACCESS, launcher=frozenset(), boot=None, appops=None, failed=None):
        boot = BOOT_ALL(()) if boot is None else boot
        return sa.check_patterns(pfacts(apps, appops, failed), access, launcher, LBL, boot)

    def one(self, found, pkg):
        hits = [f for f in found if f.get("pkg") == pkg]
        return hits[0] if hits else None

    def test_classic_stalkerware(self):
        f = self.one(self.run_({"spy.x": papp()}, acc(accessibility=["spy.x"]), set(), BOOT_ALL(["spy.x"])), "spy.x")
        self.assertEqual(f["level"], sa.BAD)
        self.assertEqual(f["section"], "pattern")
        self.assertIn("Looks like stalkerware", f["title"])
        for line in ("Installed outside an app store: ✔ yes", "No icon in the app drawer: ✔ yes",
                     "Starts by itself when the phone boots: ✔ yes", "Powerful access: Accessibility service"):
            self.assertIn(line, f["detail"])
        self.assertIn("removing it may alert them", f["advice"])

    def test_access_plus_two_signs_is_enough(self):
        # access + outside + boot, but it HAS an icon
        f = self.one(self.run_({"a.b": papp()}, acc(notifications=["a.b"]), {"a.b"}, BOOT_ALL(["a.b"])), "a.b")
        self.assertEqual(f["level"], sa.BAD)
        # access + hidden + boot, from a store
        f = self.one(self.run_({"a.b": papp("com.android.vending")}, acc(admin=["a.b"]), set(),
                               BOOT_ALL(["a.b"])), "a.b")
        self.assertEqual(f["level"], sa.BAD)

    def test_common_combinations_are_not_flagged(self):
        # store app with an icon that reads notifications and starts at boot (smartwatch companion)
        found = self.run_({"watch.app": papp("com.android.vending")}, acc(notifications=["watch.app"]),
                          {"watch.app"}, BOOT_ALL(["watch.app"]))
        self.assertIsNone(self.one(found, "watch.app"))
        self.assertEqual([f["key"] for f in found], ["pattern:none"])
        # access + ONE sign: left to the 'Powerful access' section
        self.assertIsNone(self.one(self.run_({"a.b": papp()}, acc(overlay=["a.b"]), {"a.b"}), "a.b"))
        # sideloaded, hidden keyboard - no access, no boot
        self.assertIsNone(self.one(self.run_({"kb.x": papp()}, NO_ACCESS, set()), "kb.x"))

    def test_hiding_and_self_starting_without_access_is_a_warning(self):
        f = self.one(self.run_({"a.b": papp()}, NO_ACCESS, set(), BOOT_ALL(["a.b"])), "a.b")
        self.assertEqual(f["level"], sa.WARN)
        self.assertIn("Several warning signs", f["title"])

    def test_system_and_removed_apps_ignored(self):
        apps = {"sys.a": papp(system=True), "gone.b": papp(removed=True)}
        found = self.run_(apps, acc(accessibility=["sys.a", "gone.b"]), set(), BOOT_ALL(["sys.a", "gone.b"]))
        self.assertEqual([f["key"] for f in found], ["pattern:none"])

    def test_unreadable_icon_never_means_no_icon(self):
        found = self.run_({"a.b": papp()}, acc(accessibility=["a.b"]), None, BOOT_ALL(()))
        f = self.one(found, "a.b")
        self.assertEqual(f["level"], sa.INFO)
        self.assertIn("Couldn't fully check", f["title"])
        self.assertIn("No icon in the app drawer: ? couldn't be checked", f["detail"])
        self.assertIn("pattern:incomplete", [x["key"] for x in found])
        self.assertNotIn("pattern:none", [x["key"] for x in found])

    def test_incomplete_boot_list_never_means_no_boot(self):
        found = self.run_({"a.b": papp()}, acc(sms=["a.b"]), {"a.b"}, BOOT_ALL((), complete=False))
        f = self.one(found, "a.b")
        self.assertEqual(f["level"], sa.INFO)
        self.assertIn("Starts by itself when the phone boots: ? couldn't be checked", f["detail"])
        self.assertIn("full list of apps that start at boot",
                      [x for x in found if x["key"] == "pattern:incomplete"][0]["detail"])
        # boot not readable at all: same, and said so
        found = sa.check_patterns(pfacts({"a.b": papp()}), acc(sms=["a.b"]), {"a.b"}, LBL, None)
        self.assertEqual(self.one(found, "a.b")["level"], sa.INFO)
        self.assertIn("which apps start at boot", [x for x in found if x["key"] == "pattern:incomplete"][0]["detail"])

    def test_switched_off_start_up_receivers(self):
        boot = {"complete": True, "pkgs": {"a.b": False}}
        found = self.run_({"a.b": papp()}, acc(accessibility=["a.b"]), {"a.b"}, boot)
        self.assertIsNone(self.one(found, "a.b"))                     # access + outside only
        f = self.one(self.run_({"a.b": papp()}, acc(accessibility=["a.b"]), set(), boot), "a.b")
        self.assertIn("no (its start-up receivers are switched off)", f["detail"])

    def test_unreadable_access_is_not_absence(self):
        failed = {"appops": "x", "setting:accessibility": "y"}
        found = self.run_({"a.b": papp()}, NO_ACCESS, set(), BOOT_ALL(["a.b"]), failed=failed)
        f = self.one(found, "a.b")
        self.assertEqual(f["level"], sa.WARN)                        # what was readable
        self.assertIn("could be more serious", f["detail"])          # and what might be missing
        self.assertIn("Powerful access: ? couldn't be checked", f["detail"])
        self.assertIn("Accessibility service", [x for x in found if x["key"] == "pattern:incomplete"][0]["detail"])

    def test_supporting_details(self):
        appops = {"spy.x": {"RECORD_AUDIO": {"ago": 120, "mode": "allow"},
                            "CAMERA": {"ago": 30 * 86400, "mode": "allow"},
                            "FINE_LOCATION": {"ago": 60, "mode": "ignore"}}}
        f = self.one(self.run_({"spy.x": papp(disabled=True)}, acc(accessibility=["spy.x"]), set(),
                               BOOT_ALL(["spy.x"]), appops=appops), "spy.x")
        self.assertIn("Used recently: microphone", f["detail"])
        self.assertNotIn("camera", f["detail"])                       # older than 7 days
        self.assertNotIn("exact location", f["detail"])               # denied
        self.assertIn("currently turned OFF", f["detail"])

    def test_unrecorded_installer_is_unknown_not_sideloaded(self):
        # access + hidden + boot is already the pattern: unknown origin doesn't weaken it
        f = self.one(self.run_({"a.b": papp("")}, acc(accessibility=["a.b"]), set(), BOOT_ALL(["a.b"])), "a.b")
        self.assertEqual(f["level"], sa.BAD)
        self.assertIn("? unknown - no installer was recorded", f["detail"])
        # access + hidden, boot no: with a KNOWN sideload it'd be BAD; unknown origin -> couldn't fully check
        found = self.run_({"a.b": papp("")}, acc(accessibility=["a.b"]), set(), BOOT_ALL(()))
        g = self.one(found, "a.b")
        self.assertEqual(g["level"], sa.INFO)
        self.assertIn("where it came from", g["detail"])
        inc = [x for x in found if x["key"] == "pattern:incomplete"]
        self.assertIn("no installer recorded", inc[0]["detail"])
        self.assertNotIn("pattern:none", [x["key"] for x in found])
        # an unknown origin that can't change anything doesn't make the check "incomplete"
        quiet = self.run_({"kb.x": papp("")}, NO_ACCESS, {"kb.x"}, BOOT_ALL(()))
        self.assertEqual([x["key"] for x in quiet], ["pattern:none"])

    def test_bad_findings_sorted_first(self):
        apps = {"a.warn": papp(), "z.bad": papp()}
        found = self.run_(apps, acc(accessibility=["z.bad"]), set(), BOOT_ALL(["a.warn", "z.bad"]))
        self.assertEqual([f["pkg"] for f in found], ["z.bad", "a.warn"])


class BootSignalTests(unittest.TestCase):
    def det(self, method="Package Manager query", user_scoped=True, receivers=(("a.b", ".Boot"),)):
        return {"receivers": {r: {"actions": set()} for r in receivers}, "method": method,
                "user_scoped": user_scoped}

    def test_complete_only_for_a_scoped_query_and_verified_user(self):
        self.assertTrue(am.boot_signals(self.det(), {}, True)["complete"])
        self.assertFalse(am.boot_signals(self.det(), {}, False)["complete"])
        self.assertFalse(am.boot_signals(self.det(user_scoped=False), {}, True)["complete"])
        self.assertFalse(am.boot_signals(self.det("dumpsys receiver table"), {}, True)["complete"])

    def test_nothing_read_is_none(self):
        for m in ("nothing usable", "nothing worked", ""):
            self.assertIsNone(am.boot_signals(self.det(m, receivers=()), {}, True), m)
        self.assertIsNone(am.boot_signals(None, {}, True))

    def test_receiver_states(self):
        det = self.det(receivers=(("a.b", "a.b.Boot1"), ("a.b", "a.b.Boot2"), ("c.d", "c.d.Boot")))
        st = {"a.b": {"found": True, "disabled": {"a.b.Boot1", "a.b.Boot2"}, "enabled": set()},
              "c.d": {"found": True, "disabled": {"c.d.Boot"}, "enabled": set()}}
        self.assertEqual(am.boot_signals(det, st, True)["pkgs"], {"a.b": False, "c.d": False})
        st["a.b"]["disabled"] = {"a.b.Boot1"}                            # one still on
        self.assertTrue(am.boot_signals(det, st, True)["pkgs"]["a.b"])
        self.assertTrue(am.boot_signals(det, {}, True)["pkgs"]["c.d"])   # state unread -> may run


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class PatternCheckupIntegrationTests(_DeepScanHarness, unittest.TestCase):
    def shell(self, serial, cmd, timeout=60):
        if "enabled_accessibility_services" in cmd:
            return 0, "com.a/com.a.Svc\n", ""
        if cmd == "am get-current-user":
            return 0, "0\n", ""
        if cmd.startswith("dumpsys appops"):
            return 0, "Current AppOps Service state:\n", ""        # readable, nothing granted
        if cmd.startswith("cmd package query-receivers"):
            return 0, "com.a/.BootRx\n" if "BOOT_COMPLETED" in cmd else "", ""
        if sa.SU_SENTINEL in cmd:
            return 0, sa.SU_SENTINEL + "\n", ""
        return 0, "", ""

    def check(self, shell):
        with mock.patch.object(am, "adb_shell", side_effect=shell), \
                mock.patch.object(am, "read_sockets", return_value=([], [])), \
                mock.patch.object(sa, "launcher_packages", return_value=({"com.b"}, "t")):
            apps = {"com.a": dict(_app(), installer="com.android.packageinstaller"),
                    "com.b": dict(_app(), installer="com.android.packageinstaller")}
            return self.tab._do_check("SER", False, self.cfg, apps)

    def test_checkup_reports_the_pattern(self):
        res = self.check(self.shell)
        pat = [f for f in res["findings"] if f["section"] == "pattern"]
        self.assertEqual(res["findings"][0]["section"], "pattern")      # listed first
        a = [f for f in pat if f.get("pkg") == "com.a"][0]
        self.assertEqual(a["level"], sa.BAD)
        self.assertIn("Starts by itself when the phone boots: ✔ yes", a["detail"])
        self.assertFalse([f for f in pat if f.get("pkg") == "com.b"])
        self.assertNotIn("pattern:incomplete", [f["key"] for f in pat])  # everything was readable

    def test_boot_detection_failure_is_reported_not_hidden(self):
        def shell(serial, cmd, timeout=60):
            if cmd.startswith("cmd package query-receivers") or cmd.startswith("dumpsys package"):
                return 1, "", "denied"
            return self.shell(serial, cmd, timeout)
        res = self.check(shell)
        keys = [f["key"] for f in res["findings"] if f["section"] == "pattern"]
        self.assertIn("pattern:incomplete", keys)
        self.assertNotIn("pattern:none", keys)
        a = [f for f in res["findings"] if f.get("pkg") == "com.a" and f["section"] == "pattern"][0]
        self.assertEqual(a["level"], sa.BAD)                  # access + outside + hidden, boot unknown

    def test_crash_in_boot_detection_is_contained(self):
        with mock.patch.object(am, "detect_boot_receivers", side_effect=RuntimeError("boom")):
            res = self.check(self.shell)
        inc = [f for f in res["findings"] if f["key"] == "pattern:incomplete"]
        self.assertEqual(len(inc), 1)
        self.assertIn("which apps start at boot", inc[0]["detail"])



# ==========================================================================
# Round 46 - debloat profiles v1: format, strict reading, export, per-action compare
# ==========================================================================

import profiles as pf

SIG_A, SIG_B = "a" * 64, "b" * 64


def prof(apps, **top):
    d = {"format": pf.FORMAT, "version": pf.VERSION, "apps": apps}
    d.update(top)
    return json.dumps(d)


def tapp(system=False, disabled=False, removed=False, path="/data/app/x/base.apk", vc="5", **kw):
    a = {"system": system, "disabled": disabled, "removed": removed, "path": path, "version_code": vc,
         "updated_system": False, "last_update": "t"}
    a.update(kw)
    return a


class ProfileReadingTests(unittest.TestCase):
    def bad(self, text, word):
        with self.assertRaises(pf.ProfileError) as cm:
            pf.load_profile(text)
        self.assertIn(word, str(cm.exception))

    def test_valid_profile(self):
        d = pf.load_profile(prof({"com.a.b": {"actions": ["off", "background"],
                                              "evidence": {"version_code": "12", "signers": [SIG_A]}}},
                                 source={"maker": "Xiaomi", "sdk": 35, "user": 0}, created="x"))
        self.assertEqual(d["apps"]["com.a.b"]["actions"], ["off", "background"])

    def test_duplicate_packages_rejected(self):
        self.bad('{"format": "%s", "version": 1, "apps": {"com.a.b": {"actions": ["off"]}, '
                 '"com.a.b": {"actions": ["background"]}}}' % pf.FORMAT, "appears twice")

    def test_unknown_or_bad_actions_rejected(self):
        self.bad(prof({"com.a.b": {"actions": ["delete"]}}), "unknown action")
        self.bad(prof({"com.a.b": {"actions": []}}), "non-empty")
        self.bad(prof({"com.a.b": {"actions": "off"}}), "non-empty")
        self.bad(prof({"com.a.b": {"actions": ["off", "off"]}}), "listed twice")
        self.bad(prof({"com.a.b": {"actions": ["off", "removed"]}}), "contradict")

    def test_unknown_keys_rejected_everywhere(self):
        self.bad(prof({}, extra=1), "unknown key")
        self.bad(prof({}, source={"serial": "X"}), "unknown key")
        self.bad(prof({"com.a.b": {"actions": ["off"], "risk": "safe"}}), "unknown key")     # no imported risk
        self.bad(prof({"com.a.b": {"actions": ["off"], "evidence": {"signer": SIG_A}}}), "unknown key")

    def test_evidence_formats(self):
        self.bad(prof({"com.a.b": {"actions": ["off"], "evidence": {"version_code": 12}}}), "digits")
        self.bad(prof({"com.a.b": {"actions": ["off"], "evidence": {"version_code": "1.2"}}}), "digits")
        self.bad(prof({"com.a.b": {"actions": ["off"], "evidence": {"signers": ["ABC"]}}}), "SHA-256")
        self.bad(prof({"com.a.b": {"actions": ["off"], "evidence": {"signers": []}}}), "SHA-256")
        self.bad(prof({"com.a.b": {"actions": ["off"], "evidence": {"signers": [SIG_A.upper()]}}}), "SHA-256")

    def test_header_and_limits(self):
        self.bad('{"format": "other", "version": 1, "apps": {}}', "isn't an ADB Manager profile")
        self.bad(prof({}).replace('"version": 1', '"version": 2'), "isn't supported")
        self.bad(prof({}).replace('"version": 1', '"version": true'), "must be a number")
        self.bad(prof({"not a package": {"actions": ["off"]}}), "valid package name")
        self.bad("[]", "must be an object")
        self.bad("{nope", "valid JSON")
        self.bad(b"\xff\xfe", "UTF-8")
        self.bad(b" " * (pf.MAX_BYTES + 1), "too large")
        self.bad(prof({}, source={"sdk": -1}), "whole number")
        self.bad(prof({}, source={"user": True}), "whole number")


class ProfileRestoreTests(unittest.TestCase):
    def test_only_preinstalled_with_factory_copy(self):
        self.assertTrue(pf.restorable(tapp(system=True, path="/system/app/X/X.apk"), 35)[0])
        self.assertTrue(pf.restorable(tapp(system=True, path="/product/priv-app/Y/Y.apk"), 30)[0])
        self.assertTrue(pf.restorable(tapp(system=True, path="/data/app/z/base.apk", updated_system=True), 30)[0])
        self.assertFalse(pf.restorable(tapp(system=False), 35)[0])             # would delete for good
        # contradictory data (user app reported at a factory path) still never counts as restorable
        self.assertFalse(pf.restorable(tapp(system=False, path="/system/app/X/X.apk"), 35)[0])
        self.assertFalse(pf.restorable(tapp(system=True, path="/data/app/odd/base.apk"), 35)[0])
        self.assertFalse(pf.restorable(tapp(system=True, path="/system/app/X/X.apk"), 23)[0])  # no restore cmd
        self.assertIsNone(pf.restorable(tapp(system=None, path="/system/app/X/X.apk"), 35)[0])
        self.assertIsNone(pf.restorable(tapp(system=True, path=""), 35)[0])
        self.assertFalse(pf.restorable(None, 35)[0])

    def test_package_list_alone_is_not_enough(self):
        # what "pm list packages -u" alone gives: a name, nothing about the payload
        self.assertIsNone(pf.restorable({"system": None, "removed": True}, 35)[0])


class ProfileExportTests(unittest.TestCase):
    def ikey(self, pkg, app):
        return sa.identity_key(pkg, app)

    def test_export_reads_the_current_state(self):
        apps = {"com.off.app": tapp(disabled=True),
                "com.bg.app": tapp(),
                "com.sys.gone": tapp(system=True, removed=True, path="/system/app/G/G.apk"),
                "com.user.gone": tapp(system=False, removed=True),
                "com.normal": tapp()}
        idc = {sa.identity_key("com.off.app", apps["com.off.app"]): {"signers": "same", "certs": [SIG_A]}}
        d = pf.build_profile(apps, {"sdk": "35", "maker": "Xiaomi"}, 0,
                             {"com.bg.app": True, "com.normal": False}, idc, self.ikey, now="t")
        self.assertEqual(d["apps"], {
            "com.off.app": {"actions": ["off"], "evidence": {"version_code": "5", "signers": [SIG_A]}},
            "com.bg.app": {"actions": ["background"], "evidence": {"version_code": "5"}},
            "com.sys.gone": {"actions": ["removed"], "evidence": {"version_code": "5"}}})
        self.assertEqual(d["source"], {"user": 0, "maker": "Xiaomi", "sdk": 35})
        pf.load_profile(pf.dump_profile(d))                        # what's written reads back

    def test_signer_evidence_never_from_a_stale_cache(self):
        app = tapp(disabled=True)
        old = dict(app, version_code="4")                          # the cache is for an older version
        idc = {sa.identity_key("com.x.y", old): {"signers": "same", "certs": [SIG_A]}}
        d = pf.build_profile({"com.x.y": app}, {"sdk": "35"}, 0, {}, idc, self.ikey)
        self.assertNotIn("signers", d["apps"]["com.x.y"]["evidence"])
        for bad in ({"signers": "unknown", "certs": [SIG_A]}, {"signers": "different", "certs": [SIG_A]},
                    {"signers": "same", "certs": []}, {"signers": "same", "certs": ["zz"]}):
            idc = {sa.identity_key("com.x.y", app): bad}
            d = pf.build_profile({"com.x.y": app}, {"sdk": "35"}, 0, {}, idc, self.ikey)
            self.assertNotIn("signers", d["apps"]["com.x.y"]["evidence"], bad)

    def test_unread_background_is_not_exported(self):
        d = pf.build_profile({"com.a.b": tapp()}, {"sdk": "35"}, 0, {"com.a.b": None})
        self.assertEqual(d["apps"], {})


class ProfileCompareTests(unittest.TestCase):
    def target(self, apps, sdk=35, user=0, bg=None, signers=None, risk=None):
        risk = risk or {}
        return {"apps": apps, "sdk": sdk, "user": user, "background": bg or {}, "signers": signers or {},
                "risk_of": lambda p: risk.get(p, "safe"), "critical": "critical"}

    def doc(self, apps):
        return pf.load_profile(prof(apps))

    def test_one_app_different_outcome_per_action(self):
        rows = pf.compare(self.doc({"com.a.b": {"actions": ["off", "background"]}}),
                          self.target({"com.a.b": tapp(disabled=True)}, bg={"com.a.b": False}))
        acts = rows[0]["actions"]
        self.assertEqual(acts["off"]["status"], pf.ALREADY)
        self.assertEqual(acts["background"]["status"], pf.WILL_CHANGE)
        self.assertTrue(acts["background"]["preselect"])
        self.assertFalse(acts["off"]["preselect"])

    def test_missing_and_not_applicable(self):
        rows = pf.compare(self.doc({"com.gone": {"actions": ["off"]}, "com.rm": {"actions": ["off", "background"]}}),
                          self.target({"com.rm": tapp(system=True, removed=True, path="/system/app/R.apk")}))
        by = {r["pkg"]: r for r in rows}
        self.assertEqual(by["com.gone"]["actions"]["off"]["status"], pf.MISSING)
        self.assertEqual(by["com.rm"]["actions"]["off"]["status"], pf.NOT_APPLICABLE)
        self.assertEqual(by["com.rm"]["actions"]["background"]["status"], pf.NOT_APPLICABLE)

    def test_removal_only_when_restorable_on_the_target(self):
        doc = self.doc({"com.sys": {"actions": ["removed"]}})
        ok = pf.compare(doc, self.target({"com.sys": tapp(system=True, path="/system/app/S.apk")}))
        self.assertEqual(ok[0]["actions"]["removed"]["status"], pf.WILL_CHANGE)
        user = pf.compare(doc, self.target({"com.sys": tapp(system=False)}))      # same name, user app here
        self.assertEqual(user[0]["actions"]["removed"]["status"], pf.UNSUPPORTED)
        unk = pf.compare(doc, self.target({"com.sys": tapp(system=None, path="/system/app/S.apk")}))
        self.assertEqual(unk[0]["actions"]["removed"]["status"], pf.UNKNOWN)
        old = pf.compare(doc, self.target({"com.sys": tapp(system=True, path="/system/app/S.apk")}, sdk=22))
        self.assertEqual(old[0]["actions"]["removed"]["status"], pf.UNSUPPORTED)
        other_user = pf.compare(doc, self.target({"com.sys": tapp(system=True, path="/system/app/S.apk")}, user=10))
        self.assertEqual(other_user[0]["actions"]["removed"]["status"], pf.UNSUPPORTED)
        done = pf.compare(doc, self.target({"com.sys": tapp(system=True, removed=True, path="/system/app/S.apk")}))
        self.assertEqual(done[0]["actions"]["removed"]["status"], pf.ALREADY)

    def test_unknown_states_are_never_applied(self):
        rows = pf.compare(self.doc({"com.a.b": {"actions": ["off", "background"]}}),
                          self.target({"com.a.b": tapp(disabled=None)}, bg={}))
        for act in ("off", "background"):
            self.assertEqual(rows[0]["actions"][act]["status"], pf.UNKNOWN)
            self.assertFalse(rows[0]["actions"][act]["preselect"])
        old = pf.compare(self.doc({"com.a.b": {"actions": ["background"]}}),
                         self.target({"com.a.b": tapp()}, sdk=23, bg={"com.a.b": False}))
        self.assertEqual(old[0]["actions"]["background"]["status"], pf.UNSUPPORTED)

    def test_signers(self):
        doc = self.doc({"com.a.b": {"actions": ["off"], "evidence": {"signers": [SIG_A]}}})
        conflict = pf.compare(doc, self.target({"com.a.b": tapp()}, signers={"com.a.b": [SIG_B]}))
        self.assertEqual(conflict[0]["signer"], pf.CONFLICT)
        self.assertEqual(conflict[0]["actions"]["off"]["status"], pf.CONFLICT)
        self.assertFalse(conflict[0]["actions"]["off"]["preselect"])
        self.assertEqual(pf.compare(doc, self.target({"com.a.b": tapp()}, signers={"com.a.b": [SIG_A]}))[0]["signer"],
                         "match")
        self.assertEqual(pf.compare(doc, self.target({"com.a.b": tapp()}))[0]["signer"], pf.UNKNOWN)
        overlap = pf.compare(doc, self.target({"com.a.b": tapp()}, signers={"com.a.b": [SIG_A, SIG_B]}))
        self.assertEqual(overlap[0]["signer"], pf.UNKNOWN)               # rotation? not proof either way
        nodoc = self.doc({"com.a.b": {"actions": ["off"]}})
        self.assertEqual(pf.compare(nodoc, self.target({"com.a.b": tapp()}, signers={"com.a.b": [SIG_B]}))[0]["signer"],
                         pf.UNKNOWN)

    def test_risk_is_local_and_critical_never_preselected(self):
        doc = self.doc({"com.crit": {"actions": ["off"]}})
        rows = pf.compare(doc, self.target({"com.crit": tapp()}, risk={"com.crit": "critical"}))
        self.assertEqual(rows[0]["risk"], "critical")
        self.assertEqual(rows[0]["actions"]["off"]["status"], pf.WILL_CHANGE)
        self.assertFalse(rows[0]["actions"]["off"]["preselect"])

    def test_version_evidence_and_counts(self):
        doc = self.doc({"com.a.b": {"actions": ["off"], "evidence": {"version_code": "5"}},
                        "com.c.d": {"actions": ["off"], "evidence": {"version_code": "7"}}})
        rows = pf.compare(doc, self.target({"com.a.b": tapp(), "com.c.d": tapp(disabled=True)}))
        self.assertEqual([r["version"] for r in rows], ["same", "different"])
        self.assertEqual(pf.counts(rows), {pf.WILL_CHANGE: 1, pf.ALREADY: 1})


class ProfileAppOpsTests(unittest.TestCase):
    DUMP = ("Current AppOps Service state:\n"
            "  Uid u0a10:\n    Package com.r.one:\n      RUN_ANY_IN_BACKGROUND (ignore):\n"
            "    Package com.ok.two:\n      RUN_ANY_IN_BACKGROUND (allow):\n"
            "  Uid u10a10:\n    Package com.r.one:\n      RUN_ANY_IN_BACKGROUND (allow):\n"
            "    Package com.only.ten:\n      RUN_ANY_IN_BACKGROUND (ignore):\n"
            "  Uid 10055:\n    Package com.legacy:\n      RUN_ANY_IN_BACKGROUND: mode=ignore\n"
            "      RUN_IN_BACKGROUND: mode=allow\n"
            "    Package com.noops:\n      CAMERA (allow):\n")

    def ops(self, target):
        return lambda p: ["RUN_ANY_IN_BACKGROUND"] + (["RUN_IN_BACKGROUND"] if target.get(p, 30) < 26 else [])

    def test_one_user_only(self):
        r0 = pf.background_from_appops(self.DUMP, 0, self.ops({"com.legacy": 23}))
        self.assertEqual(r0, {"com.r.one": True, "com.ok.two": False, "com.legacy": False, "com.noops": False})
        r10 = pf.background_from_appops(self.DUMP, 10, self.ops({}))
        self.assertEqual(r10, {"com.r.one": False, "com.only.ten": True})

    def test_unknown_ops_left_out(self):
        r = pf.background_from_appops(self.DUMP, 0, lambda p: None if p == "com.r.one" else [])
        self.assertEqual(r, {})

    def test_uid_user(self):
        for text, user in (("u0a123", 0), ("u10a5", 10), ("u0s1000", 0), ("u11i3", 11), ("1000", 0),
                           ("1010123", 10), ("x", None), ("u", None)):
            self.assertEqual(pf.uid_user(text), user, text)

    def test_module_is_pure(self):
        with open(pf.__file__, encoding="utf-8") as fh:
            src = fh.read()
        for word in ("import subprocess", "adb_shell", "import tkinter", "import urllib"):
            self.assertNotIn(word, src)



# ==========================================================================
# Round 47 - debloat profiles: the window, rechecks, existing operations, stop
# ==========================================================================

class ProfilePhone(FakePhone):
    """FakePhone + package lists, remove-for-user, current user and dumpsys appops."""

    def __init__(self, installed=(), removed=(), user="0", system=None, **kw):
        super().__init__(**kw)
        self.installed, self.removed, self.user = set(installed), set(removed), user
        self.system = dict(system or {})                 # pkg -> APK path of system packages

    def __call__(self, serial, cmd, timeout=30):
        m = re.match(r"pm list packages -f -s --user 0 (\S+)$", cmd)
        if m:
            self.log.append(cmd)
            want = shlex.split(m.group(1))[0]
            return 0, "".join("package:%s=%s\n" % (path, p) for p, path in sorted(self.system.items())
                              if want in p and p in self.installed), ""
        if cmd == "am get-current-user":
            self.log.append(cmd)
            return 0, self.user + "\n", ""
        m = re.match(r"pm list packages (--user 0|-u) (\S+)$", cmd)
        if m:
            self.log.append(cmd)
            pool = self.installed if m.group(1) == "--user 0" else self.installed | self.removed
            want = shlex.split(m.group(2))[0]
            return 0, "".join("package:%s\n" % p for p in sorted(pool) if want in p), ""
        m = re.match(r"pm uninstall --user 0 (\S+)$", cmd)
        if m:
            self.log.append(cmd)
            p = shlex.split(m.group(1))[0]
            self.installed.discard(p)
            self.removed.add(p)
            return 0, "Success\n", ""
        if cmd == "dumpsys appops":
            self.log.append(cmd)
            out = ["Current AppOps Service state:", "  Uid u0a1:"]
            for (pkg, op), mode in sorted(self.ops.items()):
                out += ["    Package %s:" % pkg, "      %s (%s):" % (op, mode)]
            return 0, "\n".join(out) + "\n", ""
        return FakePhone.__call__(self, serial, cmd, timeout)


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class ProfileWindowTests(unittest.TestCase):
    VLC, SYS, CRIT = "org.videolan.vlc", "com.miui.weather2", "com.android.phone"

    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()
        args = mock.Mock(serial=None, local=TMP_HOME, remote="/sdcard")
        with mock.patch.object(am.App, "scan_devices", lambda self, *a, **k: None):
            cls.app = am.App(cls.root, args)
        cls.at = cls.app.apps_tab

    @classmethod
    def tearDownClass(cls):
        destroy_root(cls.root)

    def setUp(self):
        at = self.at
        at.serial = at.scanned_serial = "SER"
        at.job = None
        at.stop.clear()
        at.props = {"sdk": "34", "release": "14", "maker": "Xiaomi", "model": "Redmi"}
        at.apps = {self.VLC: dict(real_app(self.VLC), target_sdk="34", version_code="5"),
                   self.SYS: dict(real_app(self.SYS, True), path="/system/app/W/W.apk", target_sdk="34"),
                   self.CRIT: dict(real_app(self.CRIT, True), path="/system/priv-app/P/P.apk", target_sdk="34")}
        for k in self.app.autorun_tab.saved.keys():
            self.app.autorun_tab.saved.put(k, None)
        self.win = am.ProfileWindow(self.root, self.app)
        self.f = {"serial": "SER", "user": 0, "sdk": 34, "want_root": False,
                  "target_sdk": {self.VLC: 34, self.SYS: 34, self.CRIT: 34}}

    def tearDown(self):
        self.win.destroy()
        self.at.job = None

    def pump(self, until, timeout=10):
        end = time.time() + timeout
        while time.time() < end and not until():
            try:
                while True:
                    item = self.app.q.get_nowait()
                    if item[0] == "call":
                        item[1](*item[2:])
            except Exception:
                pass
            self.root.update()
            time.sleep(0.02)
        return until()

    def phone(self, **kw):
        kw.setdefault("installed", {self.VLC, self.SYS, self.CRIT})
        kw.setdefault("system", {self.SYS: "/system/app/W/W.apk", self.CRIT: "/system/priv-app/P/P.apk"})
        return ProfilePhone(**kw)

    # ---- the two state reads -------------------------------------------------

    def test_removed_state_needs_both_lists(self):
        ph = self.phone(installed={self.VLC}, removed={self.SYS})
        with mock.patch.object(am, "adb_shell", side_effect=ph):
            self.assertFalse(am.profile_removed_state("SER", self.VLC))
            self.assertTrue(am.profile_removed_state("SER", self.SYS))
            self.assertIsNone(am.profile_removed_state("SER", "com.not.there"))
        with mock.patch.object(am, "adb_shell", return_value=(1, "", "Error: unknown option --user")):
            self.assertIsNone(am.profile_removed_state("SER", self.VLC))

    def test_background_state(self):
        ph = self.phone()
        with mock.patch.object(am, "adb_shell", side_effect=ph):
            self.assertFalse(am.profile_background_state("SER", "cmd appops", self.VLC, 0, 34, 34))
            ph.ops[(self.VLC, "RUN_ANY_IN_BACKGROUND")] = "ignore"
            self.assertTrue(am.profile_background_state("SER", "cmd appops", self.VLC, 0, 34, 34))
            self.assertIsNone(am.profile_background_state("SER", None, self.VLC, 0, 34, 34))       # no tool
            self.assertIsNone(am.profile_background_state("SER", "cmd appops", self.VLC, 0, 34, None))  # target?
            self.assertIsNone(am.profile_background_state("SER", "cmd appops", self.VLC, 0, 23, 34))   # too old

    # ---- one action: recheck first, then the existing operation ----------------

    def test_off_uses_the_verified_operation_and_rechecks(self):
        ph = self.phone()
        with mock.patch.object(am, "adb_shell", side_effect=ph):
            self.assertEqual(self.win.apply_one(self.VLC, "off", self.f)[0], "verified")
            self.assertEqual(ph.pkg_state[self.VLC], 3)
            n = len(ph.log)
            self.assertEqual(self.win.apply_one(self.VLC, "off", self.f)[0], "changed")   # already OFF now
            self.assertFalse([c for c in ph.log[n:] if "disable-user" in c])
        with mock.patch.object(am, "adb_shell", side_effect=ph), \
                mock.patch.object(am, "receiver_states", return_value={}):
            self.assertEqual(self.win.apply_one(self.VLC, "off", self.f)[0], "skipped")

    def test_remove_for_user_verified_by_both_lists(self):
        ph = self.phone()
        with mock.patch.object(am, "adb_shell", side_effect=ph):
            out, msg = self.win.apply_one(self.SYS, "removed", self.f)
            self.assertEqual(out, "verified")
            self.assertIn("pm uninstall --user 0 " + self.SYS, ph.log)
            n = len(ph.log)
            self.assertEqual(self.win.apply_one(self.SYS, "removed", self.f)[0], "changed")
            self.assertFalse([c for c in ph.log[n:] if c.startswith("pm uninstall")])
        with mock.patch.object(am, "adb_shell", return_value=(1, "", "boom")):
            self.assertEqual(self.win.apply_one(self.SYS, "removed", self.f)[0], "skipped")

    def test_removal_rechecks_eligibility_at_the_last_moment(self):
        # eligible at review time; by now it's a user app (e.g. replaced by an install) -> never removed
        for system, why in (({}, "no longer"), ({self.SYS: "/data/app/~~x/base.apk"}, None)):
            ph = self.phone(system=system)
            with mock.patch.object(am, "adb_shell", side_effect=ph):
                out, msg = self.win.apply_one(self.SYS, "removed", self.f)
            if why:
                self.assertEqual(out, "changed")
                self.assertIn(why, msg)
                self.assertFalse([c for c in ph.log if c.startswith("pm uninstall")])
            else:                                          # updated system app: factory copy exists
                self.assertEqual(out, "verified")
        # factory copy somewhere unexpected, or the phone too old for the restore command
        ph = self.phone(system={self.SYS: "/mnt/odd/W.apk"})
        with mock.patch.object(am, "adb_shell", side_effect=ph):
            self.assertEqual(self.win.apply_one(self.SYS, "removed", self.f)[0], "changed")
        self.assertFalse([c for c in ph.log if c.startswith("pm uninstall")])
        ph = self.phone(sdk=23)
        with mock.patch.object(am, "adb_shell", side_effect=ph):
            self.assertEqual(self.win.apply_one(self.SYS, "removed", self.f)[0], "changed")
        self.assertFalse([c for c in ph.log if c.startswith("pm uninstall")])

    def test_removal_skipped_when_eligibility_cant_be_read(self):
        ph = self.phone()
        real = ph.__call__

        def broken(serial, cmd, timeout=30):
            if cmd.startswith("pm list packages -f -s"):
                return 1, "", "Error: unknown option"
            return real(serial, cmd, timeout)
        with mock.patch.object(am, "adb_shell", side_effect=broken):
            out, msg = self.win.apply_one(self.SYS, "removed", self.f)
        self.assertEqual(out, "skipped")
        self.assertIn("couldn't confirm", msg)
        self.assertFalse([c for c in ph.log if c.startswith("pm uninstall")])

        def no_sdk(serial, cmd, timeout=30):
            if cmd == "getprop ro.build.version.sdk":
                return 0, "\n", ""
            return real(serial, cmd, timeout)
        with mock.patch.object(am, "adb_shell", side_effect=no_sdk):
            out, msg = self.win.apply_one(self.SYS, "removed", self.f)
        self.assertEqual(out, "skipped")
        self.assertIn("Android version couldn't be read", msg)
        self.assertFalse([c for c in ph.log if c.startswith("pm uninstall")])

    def test_remove_that_doesnt_take_effect_is_not_verified(self):
        ph = self.phone()
        real = ph.__call__

        def ignore_uninstall(serial, cmd, timeout=30):
            if cmd.startswith("pm uninstall"):
                return 0, "Success\n", ""                      # says yes, does nothing
            return real(serial, cmd, timeout)
        with mock.patch.object(am, "adb_shell", side_effect=ignore_uninstall):
            self.assertEqual(self.win.apply_one(self.SYS, "removed", self.f)[0], "unverified")

    def test_background_goes_through_autorun_with_its_restore_record(self):
        ph = self.phone()
        with mock.patch.object(am, "adb_shell", side_effect=ph):
            self.assertEqual(self.win.apply_one(self.VLC, "background", self.f)[0], "verified")
        self.assertEqual(ph.ops[(self.VLC, "RUN_ANY_IN_BACKGROUND")], "ignore")
        rec = self.app.autorun_tab.saved.get(am.AutorunTab.record_key("SER", 0, self.VLC))
        self.assertEqual(rec["appops"], {"RUN_ANY_IN_BACKGROUND": "implicit"})       # original kept for undo
        with mock.patch.object(am, "adb_shell", side_effect=ph):
            self.assertEqual(self.win.apply_one(self.VLC, "background", self.f)[0], "changed")

    def test_no_record_on_disk_means_no_change(self):
        ph = self.phone()
        with mock.patch.object(am, "adb_shell", side_effect=ph), \
                mock.patch.object(self.app.autorun_tab, "_save_record", return_value=False):
            out, msg = self.win.apply_one(self.VLC, "background", self.f)
        self.assertEqual(out, "failed")
        self.assertIn("couldn't be saved", msg)
        self.assertFalse([c for c in ph.log if " set " in c])

    def test_stop_only_between_operations(self):
        plan = [(self.VLC, "off"), (self.SYS, "removed"), (self.CRIT, "off")]
        calls = []

        def one(pkg, act, f):
            calls.append((pkg, act))
            self.at.stop.set()                             # Stop pressed while this one runs
            return "verified", ""
        with mock.patch.object(self.win, "apply_one", side_effect=one), \
                mock.patch.object(self.at, "post") as post:
            self.win._apply_work(plan, self.f)
        self.assertEqual(calls, [(self.VLC, "off")])       # the running one finished
        results = post.call_args[0][2]
        self.assertEqual([r[2] for r in results], ["verified", "stopped", "stopped"])

    # ---- export ------------------------------------------------------------------

    def test_export_writes_a_private_file_and_leaves_the_folder_alone(self):
        self.at.apps[self.VLC]["disabled"] = True
        ph = self.phone()
        ph.ops[(self.SYS, "RUN_ANY_IN_BACKGROUND")] = "ignore"
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o755)
            path = os.path.join(d, "p.json")
            with mock.patch.object(am, "adb_shell", side_effect=ph), \
                    mock.patch.object(am.messagebox, "showinfo"), mock.patch.object(am.messagebox, "showwarning"):
                self.win._export_work("SER", path, copy.deepcopy(self.at.apps), dict(self.at.props))
                self.pump(lambda: False, 0.3)
            self.assertEqual(mode(path), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o755)          # the user's folder untouched
            with open(path, "rb") as fh:
                doc = pf.load_profile(fh.read())
        self.assertEqual(doc["apps"][self.VLC]["actions"], ["off"])
        self.assertEqual(doc["apps"][self.SYS]["actions"], ["background"])
        self.assertEqual(doc["source"]["user"], 0)

    def test_export_refused_for_an_unverified_user(self):
        ph = self.phone(user="garbage")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.json")
            with mock.patch.object(am, "adb_shell", side_effect=ph), \
                    mock.patch.object(am, "current_user", return_value=(0, "unverified")), \
                    mock.patch.object(am.messagebox, "showinfo"), \
                    mock.patch.object(am.messagebox, "showwarning") as warn:
                self.win._export_work("SER", path, copy.deepcopy(self.at.apps), dict(self.at.props))
                self.pump(lambda: warn.called, 2)
            self.assertFalse(os.path.exists(path))
        self.assertIn("Android user couldn't be established", warn.call_args[0][1])

    def test_only_the_main_user_in_this_version(self):
        self.assertIsNone(am.ProfileWindow.user_problem(0, "detected"))
        self.assertIsNone(am.ProfileWindow.user_problem(0, "single-user"))
        self.assertIn("main user", am.ProfileWindow.user_problem(10, "detected"))      # work profile etc.
        self.assertIn("couldn't be established", am.ProfileWindow.user_problem(0, "unverified"))
        ph = self.phone(user="10")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.json")
            with mock.patch.object(am, "adb_shell", side_effect=ph), \
                    mock.patch.object(am.messagebox, "showwarning") as warn:
                self.win._export_work("SER", path, copy.deepcopy(self.at.apps), dict(self.at.props))
                self.pump(lambda: warn.called, 2)
            self.assertFalse(os.path.exists(path))

    # ---- review and apply --------------------------------------------------------

    def review(self, apps, problem=None, bg=None):
        doc = pf.load_profile(json.dumps({"format": pf.FORMAT, "version": 1, "apps": apps}))
        ctx = {"serial": "SER", "user": 0, "problem": problem, "sdk": 34, "path": "x"}
        self.at.job = "x"                                   # _review_done ends the job
        self.win._review_done(doc, ctx, bg or {}, {}, None)

    def test_review_never_preselects_what_should_stay_on(self):
        self.review({self.VLC: {"actions": ["off"]}, self.CRIT: {"actions": ["off"]}})
        self.assertEqual(self.win.ticked, {(self.VLC, "off")})
        self.assertIn("☐", self.win.tree.set(self.CRIT, "off"))      # offered, not ticked
        self.assertTrue(self.win.toggle(self.CRIT, "off"))
        self.assertIn((self.CRIT, "off"), self.win.ticked)
        self.assertIn("should stay on", self.win.summary.cget("text"))

    def test_only_will_change_items_can_be_ticked(self):
        self.at.apps[self.VLC]["disabled"] = True
        self.review({self.VLC: {"actions": ["off"]}, "com.not.here": {"actions": ["off"]}})
        self.assertFalse(self.win.toggle(self.VLC, "off"))                # already done
        self.assertFalse(self.win.toggle("com.not.here", "off"))          # missing
        self.assertEqual(self.win.ticked, set())
        self.assertIn("disabled", self.win.apply_btn.state())

    def test_user_problem_blocks_everything(self):
        self.review({self.VLC: {"actions": ["off"]}}, problem="the user couldn't be established")
        self.assertEqual(self.win.ticked, set())
        self.assertFalse(self.win.toggle(self.VLC, "off"))
        self.assertIn("CAN'T APPLY", self.win.head.cget("text"))
        self.assertIn("disabled", self.win.apply_btn.state())

    def test_apply_end_to_end(self):
        self.review({self.VLC: {"actions": ["off"]}, self.SYS: {"actions": ["removed"]}})
        ph = self.phone()
        with mock.patch.object(am, "adb_shell", side_effect=ph), \
                mock.patch.object(am.messagebox, "askyesno", return_value=True) as ask, \
                mock.patch.object(am.messagebox, "showinfo") as done, \
                mock.patch.object(am.messagebox, "showwarning"), \
                mock.patch.object(self.at, "scan") as rescan:
            self.win.apply()
            self.pump(lambda: done.called, 10)
        self.assertIn("Make 2 change(s)", ask.call_args[0][1])
        self.assertEqual(ph.pkg_state[self.VLC], 3)
        self.assertIn(self.SYS, ph.removed)
        self.assertIn(self.VLC, self.at.turned_off.get("SER", {}))       # offered by "turn back ON" too
        rescan.assert_called_once()
        self.assertEqual(self.win.ticked, set())
        self.assertFalse(self.win.toggle(self.VLC, "off"))                # done items can't be re-ticked

    def test_declined_confirmation_changes_nothing(self):
        self.review({self.VLC: {"actions": ["off"]}})
        ph = self.phone()
        with mock.patch.object(am, "adb_shell", side_effect=ph), \
                mock.patch.object(am.messagebox, "askyesno", return_value=False):
            self.win.apply()
        self.assertIsNone(self.at.job)
        self.assertFalse([c for c in ph.log if "disable-user" in c])

    def test_critical_needs_typed_yes(self):
        self.review({self.CRIT: {"actions": ["off"]}})
        self.win.toggle(self.CRIT, "off")
        ph = self.phone()
        with mock.patch.object(am, "adb_shell", side_effect=ph), \
                mock.patch.object(am.simpledialog, "askstring", return_value="yes") as typed:
            self.win.apply()
        typed.assert_called_once()
        self.assertIsNone(self.at.job)                                     # "yes" isn't "YES"
        self.assertFalse([c for c in ph.log if "disable-user" in c])



# ==========================================================================
# Round 43c - Pixel identity stays three-state; damaged records never look clean
# ==========================================================================

class Cve43cTests(unittest.TestCase):
    def one(self, r, props, kev=None):
        return cv.assess_record(r, cv.device_facts(props), kev, SUPPORT)

    def test_pixel_identity(self):
        self.assertIsNone(cv.pixel_identity("", "Pixel 8"))
        for model in (None, "", "   "):
            self.assertIsNone(cv.pixel_identity("Google", model), repr(model))
        self.assertTrue(cv.pixel_identity("Google", "Pixel 8 Pro"))
        self.assertFalse(cv.pixel_identity("Google", "Nexus Player"))
        self.assertFalse(cv.pixel_identity("Xiaomi", "Pixelated 5"))

    def test_google_without_model_is_never_not_affected(self):
        r = rec([(("Pixel-family specific",), "2026-06-05")], pkg=":unknown:")
        for model in ("", "   "):
            old = self.one(r, dev_props(maker="Google", model=model, spl="2026-01-01"))
            self.assertEqual((old["state"], old["applies"]), (cv.UNKNOWN, None))
            new = self.one(r, dev_props(maker="Google", model=model, spl="2026-07-01"))
            self.assertEqual((new["state"], new["applies"]), (cv.FIXED, None))
            self.assertIn("if it applies to your phone at all", new["reason"])
        gone = dev_props(maker="Google", model=None, spl="2026-07-01")
        self.assertEqual(self.one(r, gone)["applies"], None)

    def damaged(self, field, value):
        raw = json.loads(json.dumps(OSV_FIXTURE["framework"]))
        raw[field] = value
        return cv.compact_record(raw)

    def test_damaged_affected_is_shown_as_unknown_not_dropped(self):
        for bad in (5, "x", {"a": 1}, [], [5, "y"]):
            r = self.damaged("affected", bad)
            self.assertIn("affected", r["damaged"], bad)
            a = cv.assess([r], REDMI, {})
            self.assertEqual(len(a["findings"]), 1, bad)                    # not silently gone
            self.assertEqual(a["findings"][0]["state"], cv.UNKNOWN)
            self.assertTrue(any("damaged" in n for n in a["notes"]))
        # one good entry plus a broken one: the good one can't clear the issue
        raw = json.loads(json.dumps(OSV_FIXTURE["framework"]))
        raw["affected"].append("broken")
        r = cv.compact_record(raw)
        self.assertEqual(self.one(r, dev_props(spl="2027-01-01"))["state"], cv.UNKNOWN)

    def test_damaged_aliases_never_give_a_false_kev_negative(self):
        kev = cv.compact_kev(OSV_FIXTURE["kev"])
        for bad in (5, "CVE-2025-48595", [5], {"x": 1}):
            r = self.damaged("aliases", bad)
            self.assertIn("aliases", r["damaged"], bad)
            self.assertIsNone(self.one(r, REDMI, kev)["exploited_in_wild"], bad)
        # a readable list that simply has no CVE id: still can't say "not exploited"
        r = self.damaged("aliases", ["A-1234"])
        self.assertEqual(r["damaged"], [])
        self.assertIsNone(self.one(r, REDMI, kev)["exploited_in_wild"])
        # the normal cases are unchanged
        good = cv.compact_record(OSV_FIXTURE["framework"])
        self.assertEqual(good["damaged"], [])
        self.assertTrue(self.one(good, REDMI, kev)["exploited_in_wild"])
        self.assertFalse(self.one(cv.compact_record(OSV_FIXTURE["kernel"]), REDMI, kev)["exploited_in_wild"])



# ==========================================================================
# Round 44c - downloading the bulletin data (only on request) and its cache
# ==========================================================================

import io as _io            # noqa: E402
import zipfile as _zf       # noqa: E402


def osv_zip(members):
    buf = _io.BytesIO()
    with _zf.ZipFile(buf, "w") as z:
        for name, data in members.items():
            z.writestr(name, data if isinstance(data, (bytes, str)) else json.dumps(data))
    return buf.getvalue()


class CveDataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.p = mock.patch.object(sa, "CVE_DATA_FILE", os.path.join(self.tmp, "cve_data.json"))
        self.p.start()

    def tearDown(self):
        self.p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fetcher(self, osv=None, kev=None, osv_error=None, kev_error=None):
        def fetch(url, cap, timeout=60):
            if url == sa.OSV_ANDROID_URL:
                if osv_error:
                    raise osv_error
                return osv
            if kev_error:
                raise kev_error
            return kev
        return fetch

    def good_zip(self):
        return osv_zip({"A.json": OSV_FIXTURE["framework"], "B.json": OSV_FIXTURE["kernel"],
                        "bad.json": "{not json", "list.json": [1, 2], "readme.txt": "x"})

    def test_success_writes_a_private_compact_cache(self):
        res = sa.refresh_cve_data(fetch=self.fetcher(self.good_zip(), json.dumps(OSV_FIXTURE["kev"]).encode()))
        self.assertTrue(res["ok"], res)
        self.assertIn("2 issues", res["message"])
        self.assertIn("2 unreadable, skipped", res["message"])
        self.assertEqual(mode(sa.CVE_DATA_FILE), 0o600)
        d = sa.load_cve_data()
        self.assertEqual(len(d["osv_records"]), 2)
        self.assertIn("CVE-2025-48595", d["kev"])
        self.assertNotIn("vanir", read(sa.CVE_DATA_FILE))                 # compacted, not the raw data
        a = cv.assess(d["osv_records"], REDMI, d["kev"])
        self.assertEqual(a["findings"][0]["cves"], ["CVE-2025-48595"])

    def test_bulletin_failure_keeps_the_old_cache(self):
        sa.refresh_cve_data(fetch=self.fetcher(self.good_zip(), json.dumps(OSV_FIXTURE["kev"]).encode()))
        before = read(sa.CVE_DATA_FILE)
        for kw in ({"osv_error": sa.urllib.error.URLError("offline")}, {"osv": b"not a zip"},
                   {"osv": osv_zip({"x.txt": "no records"})}, {"osv": osv_zip({"bad.json": "{"})},
                   {"osv_error": ValueError("the download is larger than the 60 MB limit")}):
            res = sa.refresh_cve_data(fetch=self.fetcher(**kw))
            self.assertFalse(res["ok"], kw)
            self.assertIn("kept", res["message"])
            self.assertEqual(read(sa.CVE_DATA_FILE), before, kw)
        res = sa.refresh_cve_data(fetch=self.fetcher(osv=osv_zip({"x.txt": "no records"})))
        self.assertIn("contains no records", res["message"])

    def test_exploited_list_failure_is_recorded_not_hidden(self):
        for kw in ({"kev_error": sa.urllib.error.URLError("x")}, {"kev": b"{}"}, {"kev": b"garbage"}):
            res = sa.refresh_cve_data(fetch=self.fetcher(self.good_zip(), **kw))
            self.assertTrue(res["ok"], kw)
            d = sa.load_cve_data()
            self.assertIsNone(d["kev"], kw)
            self.assertTrue(d["kev_error"], kw)
            notes = cv.assess(d["osv_records"], REDMI, d["kev"])["notes"]
            self.assertTrue(any("known-exploited list" in n for n in notes), kw)

    def test_stop_keeps_the_old_cache(self):
        ev = threading.Event()
        ev.set()
        res = sa.refresh_cve_data(cancel=ev, fetch=self.fetcher(self.good_zip(), b"{}"))
        self.assertFalse(res["ok"])
        self.assertFalse(os.path.exists(sa.CVE_DATA_FILE))

    def test_oversized_member_is_skipped_not_loaded(self):
        big = dict(OSV_FIXTURE["framework"], details="x" * (sa.OSV_MEMBER_CAP + 10))
        with mock.patch.object(sa, "OSV_MEMBER_CAP", 1 << 16):
            recs, skipped = sa.parse_osv_zip(osv_zip({"big.json": big, "ok.json": OSV_FIXTURE["kernel"]}))
        self.assertEqual((len(recs), skipped), (1, 1))

    def test_load_rejects_damaged_or_foreign_caches(self):
        self.assertIsNone(sa.load_cve_data())                                        # nothing yet
        for bad in ("[]", '{"schema": 2, "osv_records": [{"id": "x", "cves": [], "affected": []}]}',
                    '{"schema": 1, "osv_records": "x"}', '{"schema": 1, "osv_records": [5]}', "{broken"):
            write(sa.CVE_DATA_FILE, bad)
            self.assertIsNone(sa.load_cve_data(), bad)
        write(sa.CVE_DATA_FILE, json.dumps({"schema": 1, "osv_records": [
            {"id": "x", "cves": [], "affected": []}, 7, {"id": "y", "cves": [], "affected": 5},
            {"id": "z", "cves": "x", "affected": []}], "kev": "nope"}))
        d = sa.load_cve_data()
        self.assertEqual((len(d["osv_records"]), d["osv_skipped"], d["kev"]), (1, 3, None))

    def test_download_is_capped_whatever_the_server_says(self):
        class Resp:
            def __init__(self, body, length=None):
                self.body, self.headers = _io.BytesIO(body), {"Content-Length": length} if length else {}

            def read(self, n):
                return self.body.read(n)

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        with mock.patch.object(sa.urllib.request, "urlopen", return_value=Resp(b"x" * 5000)):
            with self.assertRaises(ValueError):
                sa.download_capped("https://x", 1000)                                # no length header
        with mock.patch.object(sa.urllib.request, "urlopen", return_value=Resp(b"x", "99999999")):
            with self.assertRaises(ValueError):
                sa.download_capped("https://x", 1000)                                # declared too big
        with mock.patch.object(sa.urllib.request, "urlopen", return_value=Resp(b"x" * 10)) as uo:
            self.assertEqual(sa.download_capped("https://x", 1000), b"x" * 10)
        self.assertIn("ADB-Manager", uo.call_args[0][0].get_header("User-agent"))



# ==========================================================================
# Round 45c - CIRCL: the chip maker's own notices (fixture = REAL responses)
# ==========================================================================

CIRCL_FIXTURE = json.loads(r"""{"unisoc_page":{"metadata":{"count":753,"page":1,"per_page":3},"data":[{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"state":"PUBLISHED","cveId":"CVE-2022-2984","assignerOrgId":"63f92e9c-2193-4c24-98a9-93640392c3d3","assignerShortName":"Unisoc","dateUpdated":"2025-05-15T15:03:51.597Z","dateReserved":"2022-08-25T00:00:00.000Z","datePublished":"2022-10-14T00:00:00.000Z"},"containers":{"cna":{"providerMetadata":{"orgId":"63f92e9c-2193-4c24-98a9-93640392c3d3","shortName":"Unisoc","dateUpdated":"2022-10-14T00:00:00.000Z"},"descriptions":[{"lang":"en","value":"In jpg driver, there is a possible out of bounds write due to a missing bounds check. This could lead to local denial of service in kernel."}],"affected":[{"vendor":"Unisoc (Shanghai) Technologies Co., Ltd.","product":"SC9863A/SC9832E/SC7731E/T610/T310/T606/T760/T610/T618/T606/T612/T616/T760/T770/T820/S8000","versions":[{"version":"Android10/Android11/Android12","status":"affected"}]}],"references":[{"url":"https://www.unisoc.com/en_us/secy/announcementDetail/1575654905820020738"}],"problemTypes":[{"descriptions":[{"type":"CWE","lang":"en","description":"CWE-787 Out-of-bounds Write","cweId":"CWE-787"}]}],"x_gcve":[{"vulnId":"cve-2022-2984","recordType":"advisory"}]},"adp":[{"providerMetadata":{"orgId":"af854a3a-2127-422b-91ae-364da2661108","shortName":"CVE","dateUpdated":"2024-08-03T00:53:00.678Z"},"title":"CVE Program Container","references":[{"url":"https://www.unisoc.com/en_us/secy/announcementDetail/1575654905820020738","tags":["x_transferred"]}]},{"metrics":[{"cvssV3_1":{"scope":"UNCHANGED","version":"3.1","baseScore":5.5,"attackVector":"LOCAL","baseSeverity":"MEDIUM","vectorString":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H","integrityImpact":"NONE","userInteraction":"NONE","attackComplexity":"LOW","availabilityImpact":"HIGH","privilegesRequired":"LOW","confidentialityImpact":"NONE"}},{"other":{"type":"ssvc","content":{"timestamp":"2025-05-15T15:03:33.213346Z","id":"CVE-2022-2984","options":[{"Exploitation":"none"},{"Automatable":"no"},{"Technical Impact":"partial"}],"role":"CISA Coordinator","version":"2.0.3"}}}],"title":"CISA ADP Vulnrichment","providerMetadata":{"orgId":"134c704f-9b21-4f2e-91b3-4a467353bcc0","shortName":"CISA-ADP","dateUpdated":"2025-05-15T15:03:51.597Z"}}]}},{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"state":"PUBLISHED","cveId":"CVE-2022-2985","assignerOrgId":"63f92e9c-2193-4c24-98a9-93640392c3d3","assignerShortName":"Unisoc","dateUpdated":"2025-05-15T15:03:09.737Z","dateReserved":"2022-08-25T00:00:00.000Z","datePublished":"2022-10-14T00:00:00.000Z"},"containers":{"cna":{"providerMetadata":{"orgId":"63f92e9c-2193-4c24-98a9-93640392c3d3","shortName":"Unisoc","dateUpdated":"2022-10-14T00:00:00.000Z"},"descriptions":[{"lang":"en","value":"In music service, there is a missing permission check. This could lead to elevation of privilege in contacts service with no additional execution privileges needed."}],"affected":[{"vendor":"Unisoc (Shanghai) Technologies Co., Ltd.","product":"SC9863A/SC9832E/SC7731E/T610/T310/T606/T760/T610/T618/T606/T612/T616/T760/T770/T820/S8000","versions":[{"version":"Android10/Android11","status":"affected"}]}],"references":[{"url":"https://www.unisoc.com/en_us/secy/announcementDetail/1575654905820020738"}],"problemTypes":[{"descriptions":[{"type":"CWE","lang":"en","description":"CWE-862 Missing Authorization","cweId":"CWE-862"}]}],"x_gcve":[{"vulnId":"cve-2022-2985","recordType":"advisory"}]},"adp":[{"providerMetadata":{"orgId":"af854a3a-2127-422b-91ae-364da2661108","shortName":"CVE","dateUpdated":"2024-08-03T00:53:00.685Z"},"title":"CVE Program Container","references":[{"url":"https://www.unisoc.com/en_us/secy/announcementDetail/1575654905820020738","tags":["x_transferred"]}]},{"metrics":[{"cvssV3_1":{"scope":"UNCHANGED","version":"3.1","baseScore":7.8,"attackVector":"LOCAL","baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H","integrityImpact":"HIGH","userInteraction":"NONE","attackComplexity":"LOW","availabilityImpact":"HIGH","privilegesRequired":"LOW","confidentialityImpact":"HIGH"}},{"other":{"type":"ssvc","content":{"timestamp":"2025-05-15T15:02:47.655782Z","id":"CVE-2022-2985","options":[{"Exploitation":"none"},{"Automatable":"no"},{"Technical Impact":"total"}],"role":"CISA Coordinator","version":"2.0.3"}}}],"title":"CISA ADP Vulnrichment","providerMetadata":{"orgId":"134c704f-9b21-4f2e-91b3-4a467353bcc0","shortName":"CISA-ADP","dateUpdated":"2025-05-15T15:03:09.737Z"}}]}},{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"state":"PUBLISHED","cveId":"CVE-2022-38669","assignerOrgId":"63f92e9c-2193-4c24-98a9-93640392c3d3","assignerShortName":"Unisoc","dateUpdated":"2025-05-15T14:47:24.374Z","dateReserved":"2022-08-22T00:00:00.000Z","datePublished":"2022-10-14T00:00:00.000Z"},"containers":{"cna":{"providerMetadata":{"orgId":"63f92e9c-2193-4c24-98a9-93640392c3d3","shortName":"Unisoc","dateUpdated":"2022-10-14T00:00:00.000Z"},"descriptions":[{"lang":"en","value":"In soundrecorder service, there is a missing permission check. This could lead to elevation of privilege in contacts service with no additional execution privileges needed."}],"affected":[{"vendor":"Unisoc (Shanghai) Technologies Co., Ltd.","product":"SC9863A/SC9832E/SC7731E/T610/T310/T606/T760/T610/T618/T606/T612/T616/T760/T770/T820/S8000","versions":[{"version":"Android10/Android11/Android12","status":"affected"}]}],"references":[{"url":"https://www.unisoc.com/en_us/secy/announcementDetail/1575654905820020738"}],"problemTypes":[{"descriptions":[{"type":"CWE","lang":"en","description":"CWE-862 Missing Authorization","cweId":"CWE-862"}]}],"x_gcve":[{"vulnId":"cve-2022-38669","recordType":"advisory"}]},"adp":[{"providerMetadata":{"orgId":"af854a3a-2127-422b-91ae-364da2661108","shortName":"CVE","dateUpdated":"2024-08-03T11:02:14.248Z"},"title":"CVE Program Container","references":[{"url":"https://www.unisoc.com/en_us/secy/announcementDetail/1575654905820020738","tags":["x_transferred"]}]},{"metrics":[{"cvssV3_1":{"scope":"UNCHANGED","version":"3.1","baseScore":7.8,"attackVector":"LOCAL","baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H","integrityImpact":"HIGH","userInteraction":"NONE","attackComplexity":"LOW","availabilityImpact":"HIGH","privilegesRequired":"LOW","confidentialityImpact":"HIGH"}},{"other":{"type":"ssvc","content":{"timestamp":"2025-05-15T14:47:03.535982Z","id":"CVE-2022-38669","options":[{"Exploitation":"none"},{"Automatable":"no"},{"Technical Impact":"total"}],"role":"CISA Coordinator","version":"2.0.3"}}}],"title":"CISA ADP Vulnrichment","providerMetadata":{"orgId":"134c704f-9b21-4f2e-91b3-4a467353bcc0","shortName":"CISA-ADP","dateUpdated":"2025-05-15T14:47:24.374Z"}}]}}]},"android_old":{"containers":{"cna":{"affected":[{"product":"Android","vendor":"Google","versions":[{"status":"affected","version":"2.3"}]}],"descriptions":[{"lang":"en","value":"The Bluetooth stack in Android before 2.3.6 allows a physically proximate attacker to obtain contact information via an AT phonebook transfer."}],"problemTypes":[{"descriptions":[{"description":"access to sensitive information","lang":"en","type":"text"}]}],"providerMetadata":{"dateUpdated":"2020-02-12T19:01:48.000Z","orgId":"ebfee0ef-53dd-4cf3-9e2a-08a5bd7a7e28","shortName":"Chrome"},"references":[{"tags":["x_refsource_CONFIRM"],"url":"https://code.google.com/p/android/issues/detail?id=21347"},{"tags":["x_refsource_MISC"],"url":"https://deepsec.net/docs/Slides/2013/DeepSec_2013_Jaime_Sanchez_-_Building_The_First_Android_IDS_On_Network_Level.pdf"}],"x_legacyV4Record":{"CVE_data_meta":{"ASSIGNER":"chrome-cve-admin@google.com","ID":"CVE-2011-2343","STATE":"PUBLIC"},"affects":{"vendor":{"vendor_data":[{"product":{"product_data":[{"product_name":"Android","version":{"version_data":[{"version_value":"2.3"}]}}]},"vendor_name":"Google"}]}},"data_format":"MITRE","data_type":"CVE","data_version":"4.0","description":{"description_data":[{"lang":"eng","value":"The Bluetooth stack in Android before 2.3.6 allows a physically proximate attacker to obtain contact information via an AT phonebook transfer."}]},"problemtype":{"problemtype_data":[{"description":[{"lang":"eng","value":"access to sensitive information"}]}]},"references":{"reference_data":[{"name":"https://code.google.com/p/android/issues/detail?id=21347","refsource":"CONFIRM","url":"https://code.google.com/p/android/issues/detail?id=21347"},{"name":"https://deepsec.net/docs/Slides/2013/DeepSec_2013_Jaime_Sanchez_-_Building_The_First_Android_IDS_On_Network_Level.pdf","refsource":"MISC","url":"https://deepsec.net/docs/Slides/2013/DeepSec_2013_Jaime_Sanchez_-_Building_The_First_Android_IDS_On_Network_Level.pdf"}]}},"x_gcve":[{"vulnId":"cve-2011-2343","recordType":"advisory"}]},"adp":[{"providerMetadata":{"orgId":"af854a3a-2127-422b-91ae-364da2661108","shortName":"CVE","dateUpdated":"2024-08-06T23:00:33.139Z"},"title":"CVE Program Container","references":[{"tags":["x_refsource_CONFIRM","x_transferred"],"url":"https://code.google.com/p/android/issues/detail?id=21347"},{"tags":["x_refsource_MISC","x_transferred"],"url":"https://deepsec.net/docs/Slides/2013/DeepSec_2013_Jaime_Sanchez_-_Building_The_First_Android_IDS_On_Network_Level.pdf"}]}]},"cveMetadata":{"assignerOrgId":"ebfee0ef-53dd-4cf3-9e2a-08a5bd7a7e28","assignerShortName":"Chrome","cveId":"CVE-2011-2343","datePublished":"2020-02-12T19:01:48.000Z","dateReserved":"2011-06-02T00:00:00.000Z","dateUpdated":"2024-08-06T23:00:33.139Z","state":"PUBLISHED"},"dataType":"CVE_RECORD","dataVersion":"5.1"},"record_48595":{"dataType":"CVE_RECORD","dataVersion":"5.2","cveMetadata":{"cveId":"CVE-2025-48595","assignerOrgId":"baff130e-b8d5-4e15-b3d3-c3cf5d5545c6","state":"PUBLISHED","assignerShortName":"google_android","dateReserved":"2025-05-22T18:12:07.428Z","datePublished":"2026-06-01T21:14:49.921Z","dateUpdated":"2026-06-03T03:55:19.122Z"},"containers":{"cna":{"providerMetadata":{"orgId":"baff130e-b8d5-4e15-b3d3-c3cf5d5545c6","shortName":"google_android","dateUpdated":"2026-06-01T21:14:49.921Z"},"problemTypes":[{"descriptions":[{"lang":"en","description":"Elevation of privilege"}]}],"affected":[{"vendor":"Google","product":"Android","versions":[{"version":"16-qpr2","status":"affected"},{"version":"16","status":"affected"},{"version":"15","status":"affected"},{"version":"14","status":"affected"}],"defaultStatus":"unaffected"}],"descriptions":[{"lang":"en","value":"In multiple locations, there is a possible way to achieve code execution due to an integer overflow. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation."}],"references":[{"url":"https://source.android.com/docs/security/bulletin/2026/2026-06-01"}],"x_generator":{"engine":"cvelib 1.7.1"},"x_gcve":[{"vulnId":"CVE-2025-48595","recordType":"advisory"}]},"adp":[{"problemTypes":[{"descriptions":[{"type":"CWE","cweId":"CWE-190","lang":"en","description":"CWE-190 Integer Overflow or Wraparound"}]}],"references":[{"url":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-48595","tags":["government-resource"]}],"metrics":[{"cvssV3_1":{"scope":"UNCHANGED","version":"3.1","baseScore":8.4,"attackVector":"LOCAL","baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","integrityImpact":"HIGH","userInteraction":"NONE","attackComplexity":"LOW","availabilityImpact":"HIGH","privilegesRequired":"NONE","confidentialityImpact":"HIGH"}},{"other":{"type":"ssvc","content":{"timestamp":"2026-06-01T00:00:00+00:00","options":[{"Exploitation":"active"},{"Automatable":"no"},{"Technical Impact":"total"}],"role":"CISA Coordinator","version":"2.0.3","id":"CVE-2025-48595"}}},{"other":{"type":"kev","content":{"dateAdded":"2026-06-02","reference":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-48595"}}}],"title":"CISA ADP Vulnrichment","providerMetadata":{"orgId":"134c704f-9b21-4f2e-91b3-4a467353bcc0","shortName":"CISA-ADP","dateUpdated":"2026-06-03T03:55:19.122Z"},"timeline":[{"time":"2026-06-02T00:00:00.000Z","lang":"en","value":"CVE-2025-48595 added to CISA KEV"}]}]}},"missing":{}}""")
REDMI_CHIP = dict(REDMI, **{"ro.soc.manufacturer": "Spreadtrum", "ro.soc.model": "UMS9230E",
                            "ro.board.platform": "ums9230", "ro.product.board": "serenity"})


def http_error(code, retry=None):
    hdrs = {"Retry-After": str(retry)} if retry is not None else {}
    return sa.urllib.error.HTTPError("https://x", code, "err", hdrs, None)


class CirclParseTests(unittest.TestCase):
    def test_real_unisoc_record(self):
        r = sa.compact_circl(CIRCL_FIXTURE["unisoc_page"]["data"][1])
        self.assertEqual(r["cve"], "CVE-2022-2985")
        self.assertIn("T606", r["products"])
        self.assertIn("SC9863A", r["products"])
        self.assertEqual(r["versions"], ["Android10/Android11"])
        self.assertEqual(r["severity"], "High")
        self.assertFalse(r["kev_listed"])
        self.assertEqual(r["refs"][0][:24], "https://www.unisoc.com/e")

    def test_real_android_record_with_kev(self):
        r = sa.compact_circl(CIRCL_FIXTURE["record_48595"])
        self.assertEqual((r["cve"], r["severity"], r["kev_listed"]), ("CVE-2025-48595", "High", True))
        self.assertEqual(r["versions"], ["16-qpr2", "16", "15", "14"])

    def test_missing_and_malformed(self):
        self.assertIsNone(sa.compact_circl(CIRCL_FIXTURE["missing"]))          # HTTP 200 with {}
        for bad in (None, [], {"cveMetadata": {"cveId": "nope"}}, {"cveMetadata": 5}):
            self.assertIsNone(sa.compact_circl(bad))
        r = sa.compact_circl({"cveMetadata": {"cveId": "CVE-2024-1234"}, "containers": {"cna": {"affected": 5}}})
        self.assertTrue(r["damaged"])

    def test_android_versions(self):
        f = sa._android_majors
        self.assertEqual(f(["Android10/Android11/Android12"]), {10, 11, 12})
        self.assertEqual(f(["16-qpr2", "15"]), {16, 15})
        self.assertEqual(f(["Android 12.0"]), {12})
        self.assertIsNone(f(["n/a"]))
        self.assertIsNone(f(["before 5.1"]))                    # not a list of versions - unknown
        self.assertIsNone(f([]))

    def test_vendor_from_the_phone(self):
        self.assertEqual(sa.circl_vendor({"ro.soc.manufacturer": "Spreadtrum"}), "Unisoc")
        self.assertEqual(sa.circl_vendor({"ro.soc.manufacturer": "QTI"}), "Qualcomm")
        self.assertEqual(sa.circl_vendor({"ro.soc.manufacturer": "Mediatek"}), "MediaTek")
        self.assertIsNone(sa.circl_vendor({}))


class CirclSearchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.p = mock.patch.object(sa, "CIRCL_CACHE_FILE", os.path.join(self.tmp, "circl.json"))
        self.p.start()
        self.urls = []

    def tearDown(self):
        self.p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def pages(self, n_pages, per=sa.CIRCL_PER_PAGE, count=None, dup=False, fail_at=None):
        base = CIRCL_FIXTURE["unisoc_page"]["data"]

        def fetch(url, cap, timeout=30, headers=None):
            self.urls.append((url, headers))
            page = int(re.search(r"page=(\d+)", url).group(1))
            if fail_at == page:
                raise fail_at_error
            recs = []
            if page <= n_pages:
                for i in range(per if page < n_pages else 3):
                    r = json.loads(json.dumps(base[i % 3]))
                    r["cveMetadata"]["cveId"] = "CVE-2022-%d" % (2984 if dup and i < 3 else 10000 + page * 1000 + i)
                    recs.append(r)
            return json.dumps({"metadata": {"count": count or ((n_pages - 1) * per + 3), "page": page,
                                            "per_page": per}, "data": recs}).encode()
        fail_at_error = http_error(429, 60)
        return fetch

    def test_query_parameters_and_headers(self):
        res = sa.circl_search("Unisoc", fetch=self.pages(1))
        url, hdrs = self.urls[0]
        self.assertTrue(url.startswith("https://vulnerability.circl.lu/api/vulnerability/fulltext?"))
        for part in ("q=Unisoc", "page=1", "per_page=100", "sources=cvelistv5"):
            self.assertIn(part, url)
        self.assertEqual(hdrs, {"Accept": "application/json"})
        self.assertTrue(res["complete"])
        self.assertEqual(len(res["records"]), 3)

    def test_pagination_stops_and_dedupes(self):
        res = sa.circl_search("Unisoc", fetch=self.pages(3, dup=True))
        self.assertEqual(len(self.urls), 3)
        self.assertEqual(len({r["cve"] for r in res["records"]}), len(res["records"]))   # no duplicates
        self.assertTrue(res["complete"])

    def test_page_limit_is_reported_as_partial(self):
        res = sa.circl_search("Unisoc", fetch=self.pages(50))
        self.assertEqual(len(self.urls), sa.CIRCL_MAX_PAGES)
        self.assertFalse(res["complete"])
        self.assertIn("page limit", res["partial_reason"])

    def test_rate_limit_midway_keeps_what_was_read_and_says_partial(self):
        res = sa.circl_search("Unisoc", fetch=self.pages(5, fail_at=3))
        self.assertEqual(len(self.urls), 3)                     # no retries
        self.assertFalse(res["complete"])
        self.assertIn("slow down", res["partial_reason"])

    def test_failures_are_errors_never_empty_results(self):
        for exc, kind in ((http_error(503), "unavailable"), (http_error(429, 30), "rate_limited"),
                          (http_error(400), "bad_request"), (sa.urllib.error.URLError("timed out"), "network"),
                          (TimeoutError("timed out"), "network")):
            def fetch(url, cap, timeout=30, headers=None, exc=exc):
                raise exc
            with self.assertRaises(sa.CirclError) as cm:
                sa.circl_search("Unisoc", fetch=fetch)
            self.assertEqual(cm.exception.kind, kind)
            if kind == "rate_limited":
                self.assertEqual(cm.exception.retry_after, 30)
        self.assertFalse(os.path.exists(sa.CIRCL_CACHE_FILE))  # a failure is never cached as "no results"
        for body in (b"not json", b"[]", b'{"data": 5}'):
            with self.assertRaises(sa.CirclError) as cm:
                sa.circl_search("Unisoc", fetch=lambda *a, body=body, **k: body)
            self.assertEqual(cm.exception.kind, "format")

    def test_empty_result_is_a_real_empty_result(self):
        res = sa.circl_search("Unisoc", fetch=lambda *a, **k: b'{"metadata": {"count": 0}, "data": []}')
        self.assertEqual((res["records"], res["complete"]), ([], True))

    def test_cache_hit_refresh_and_bound(self):
        sa.circl_search("Unisoc", fetch=self.pages(1), now=1000.0)
        n = len(self.urls)
        hit = sa.circl_search("Unisoc", fetch=self.pages(1), now=1000.0 + 3600)
        self.assertTrue(hit["from_cache"])
        self.assertEqual(len(self.urls), n)                    # no request
        sa.circl_search("Unisoc", fetch=self.pages(1), now=1000.0 + 3600, refresh=True)
        self.assertGreater(len(self.urls), n)
        n = len(self.urls)
        old = sa.circl_search("Unisoc", fetch=self.pages(1), now=1000.0 + 30 * 86400, max_age=float("inf"))
        self.assertTrue(old["from_cache"])                     # "use the saved copy": no network
        self.assertEqual(len(self.urls), n)
        for i in range(10):
            sa.circl_search("V%d" % i, fetch=self.pages(1), now=5000.0 + i)
        self.assertLessEqual(len(json.loads(read(sa.CIRCL_CACHE_FILE))), sa.CIRCL_MAX_QUERIES)
        self.assertEqual(mode(sa.CIRCL_CACHE_FILE), 0o600)


class CirclMatchTests(unittest.TestCase):
    def recs(self):
        return [sa.compact_circl(r) for r in CIRCL_FIXTURE["unisoc_page"]["data"]]

    def test_redmi_chip_family_and_android_version(self):
        out = {f["cve"]: f for f in sa.circl_assess(self.recs(), REDMI_CHIP)}
        f = out["CVE-2022-2985"]
        self.assertEqual((f["chip"], f["android"], f["fix"]), ("family", "not_listed", "unknown"))
        self.assertIn("exact variant can't be confirmed", f["summary"])
        self.assertIn("not listed for Android 15", f["summary"])

    def test_exact_chip_and_version(self):
        props = dict(REDMI_CHIP, **{"ro.soc.model": "T606", "ro.build.version.release": "11"})
        f = {x["cve"]: x for x in sa.circl_assess(self.recs(), props)}["CVE-2022-2985"]
        self.assertEqual((f["chip"], f["android"]), ("listed", "listed"))
        self.assertIn("whether your update includes the fix can't be told", f["summary"])

    def test_unmatched_chip_is_never_not_affected(self):
        props = dict(REDMI_CHIP, **{"ro.soc.model": "X1", "ro.board.platform": "abc", "ro.product.board": "q"})
        for f in sa.circl_assess(self.recs(), props):
            self.assertEqual(f["chip"], "unmatched")
            self.assertEqual(f["fix"], "unknown")
            self.assertNotIn("not affected", f["summary"])

    def test_generic_android_record_stays_unknown(self):
        f = sa.circl_assess([sa.compact_circl(CIRCL_FIXTURE["android_old"])], REDMI_CHIP)[0]
        self.assertEqual(f["fix"], "unknown")
        self.assertEqual(f["chip"], "unmatched")             # 'Android' isn't a chip
        self.assertEqual(f["android"], "not_listed")          # it lists 2.3 ... and says so
        bad = sa.compact_circl({"cveMetadata": {"cveId": "CVE-2024-1234"}, "containers": {"cna": {"affected": 5}}})
        g = sa.circl_assess([bad], REDMI_CHIP)[0]
        self.assertEqual((g["chip"], g["android"], g["fix"]), ("unknown", "unknown", "unknown"))
        # partly damaged: one readable entry naming the Redmi's chip family + one broken entry
        part = json.loads(json.dumps(CIRCL_FIXTURE["unisoc_page"]["data"][0]))
        part["containers"]["cna"]["affected"].append("broken")
        h = sa.circl_assess([sa.compact_circl(part)], REDMI_CHIP)[0]
        self.assertEqual(h["chip"], "unknown")                 # a damaged list can't place the chip

    def test_bulletin_verdict_is_reused_not_recomputed(self):
        osv = cv.assess([cv.compact_record(OSV_FIXTURE["framework"])], REDMI, cv.compact_kev(OSV_FIXTURE["kev"]))
        bulletin = {c: f for f in osv["findings"] for c in f["cves"]}
        f = sa.circl_assess([sa.compact_circl(CIRCL_FIXTURE["record_48595"])], REDMI_CHIP, bulletin)[0]
        self.assertEqual((f["source"], f["bulletin_state"]), ("bulletin", cv.POTENTIAL))
        self.assertEqual(f["chip"], "")                        # no second, independent verdict

    def test_matched_notices_listed_first(self):
        props = dict(REDMI_CHIP, **{"ro.build.version.release": "12"})
        out = sa.circl_assess(self.recs(), props)
        self.assertEqual([f["android"] for f in out][:2], ["listed", "listed"])
        self.assertEqual(out[-1]["cve"], "CVE-2022-2985")     # Android 10/11 only -> after the matches

    def test_privacy_only_the_vendor_word_is_sent(self):
        sent = []

        def fetch(url, cap, timeout=30, headers=None):
            sent.append(url)
            return b'{"metadata": {"count": 0}, "data": []}'
        with tempfile.TemporaryDirectory() as d, mock.patch.object(sa, "CIRCL_CACHE_FILE", os.path.join(d, "c.json")):
            sa.circl_search(sa.circl_vendor(REDMI_CHIP), fetch=fetch)
        q = sa.urllib.parse.parse_qs(sa.urllib.parse.urlsplit(sent[0]).query)
        self.assertEqual(q["q"], ["Unisoc"])
        for secret in ("UMS9230E", "serenity", "Redmi", "2026-02-01"):
            self.assertNotIn(secret, sent[0])


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class KnownIssuesWindowTests(unittest.TestCase):
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

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.patches = [mock.patch.object(sa, "CVE_DATA_FILE", os.path.join(self.tmp, "cve.json")),
                        mock.patch.object(sa, "CIRCL_CACHE_FILE", os.path.join(self.tmp, "circl.json"))]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def win(self):
        return am.KnownIssuesWindow(self.root, {"props": dict(REDMI_CHIP)}, self.app)

    def test_opening_never_uses_the_network(self):
        with mock.patch.object(sa.urllib.request, "urlopen") as net:
            w = self.win()
            self.root.update()
        net.assert_not_called()
        self.assertIn("No bulletin data yet", w.head.cget("text"))
        w.destroy()

    def test_saved_data_is_assessed_locally(self):
        sa.atomic_write_json(sa.CVE_DATA_FILE, {"schema": 1, "checked": "2026-11-14 10:00",
                                                "osv_records": [cv.compact_record(OSV_FIXTURE["framework"])],
                                                "kev": cv.compact_kev(OSV_FIXTURE["kev"]), "kev_error": ""})
        w = self.win()
        self.assertIn("1 serious issue(s) may affect it", w.head.cget("text"))
        self.assertIn("1 known to be used in real attacks", w.head.cget("text"))
        iid = w.tree.get_children()[0]
        self.assertEqual(w.tree.item(iid, "text"), "CVE-2025-48595")
        w.tree.selection_set(iid)
        w.on_select()
        txt = w.details.get("1.0", "end")
        self.assertIn("Public exploit available?  not tracked here (unknown)", txt)
        self.assertIn("Root shown on similar phones?  not tracked here (unknown)", txt)
        w.destroy()

    def test_failed_search_says_unavailable_not_clean(self):
        w = self.win()
        w._searched("Unisoc", None, sa.CirclError("unavailable", "the search service is unavailable right now"))
        self.assertIn("not the same as 'no issues'", w.status.cget("text"))
        self.assertEqual(w.tree.get_children(), ())
        w.destroy()

    def test_search_results_shown_with_honest_labels(self):
        w = self.win()
        res = {"records": [sa.compact_circl(r) for r in CIRCL_FIXTURE["unisoc_page"]["data"]], "count": 753,
               "complete": False, "fetched": "x", "from_cache": False, "partial_reason": "page limit reached"}
        w._searched("Unisoc", res, None)
        self.assertIn("PARTIAL", w.status.cget("text"))
        vals = [w.tree.set(i, "state") for i in w.tree.get_children()]
        self.assertTrue(all(v.startswith("chip family listed") for v in vals), vals)
        self.assertTrue(all(w.tree.set(i, "fix") == "unknown" for i in w.tree.get_children()))
        w.destroy()



# ==========================================================================
# Round 48 - review corrections: CIRCL partials, ranges, full index, attribution
# ==========================================================================

class CirclCorrectionTests(CirclSearchTests):
    def test_partial_after_429_is_shown_but_never_cached(self):
        res = sa.circl_search("Unisoc", fetch=self.pages(5, fail_at=3), now=1000.0)
        self.assertFalse(res["complete"])
        self.assertTrue(res["records"])                          # shown this session ...
        self.assertFalse(os.path.exists(sa.CIRCL_CACHE_FILE))     # ... but not saved
        n = len(self.urls)
        again = sa.circl_search("Unisoc", fetch=self.pages(2), now=1060.0)
        self.assertFalse(again["from_cache"])                    # no silent reuse of the partial result
        self.assertGreater(len(self.urls), n)
        self.assertTrue(again["complete"])
        self.assertTrue(sa.circl_search("Unisoc", fetch=self.pages(2), now=1070.0)["from_cache"])

    def test_page_limit_partial_not_cached(self):
        sa.circl_search("Unisoc", fetch=self.pages(50))
        self.assertFalse(os.path.exists(sa.CIRCL_CACHE_FILE))

    def test_cancel_before_first_page_is_stopped_not_empty(self):
        ev = threading.Event()
        ev.set()
        res = sa.circl_search("Unisoc", fetch=self.pages(1), cancel=ev)
        self.assertEqual((res["records"], res["stopped"], res["complete"]), ([], True, False))
        self.assertEqual(self.urls, [])
        self.assertFalse(os.path.exists(sa.CIRCL_CACHE_FILE))

    def test_rows_that_arent_cve_records_are_a_data_problem(self):
        body = json.dumps({"metadata": {"count": 2}, "data": [{"x": 1}, {"cveMetadata": {"cveId": "bad"}}]}).encode()
        with self.assertRaises(sa.CirclError) as cm:
            sa.circl_search("Unisoc", fetch=lambda *a, **k: body)
        self.assertEqual(cm.exception.kind, "format")
        self.assertIn("data problem", str(cm.exception))

    def test_mixed_valid_and_unreadable_rows_are_not_a_clean_result(self):
        good = CIRCL_FIXTURE["unisoc_page"]["data"]
        body = json.dumps({"metadata": {"count": 4}, "data": good + [{"junk": True}]}).encode()
        res = sa.circl_search("Unisoc", fetch=lambda *a, **k: body)
        self.assertEqual(len(res["records"]), 3)                  # the readable ones are shown ...
        self.assertFalse(res["complete"])                         # ... but it isn't a clean, complete answer
        self.assertEqual(res["bad_rows"], 1)
        self.assertIn("couldn't be read", res["partial_reason"])
        self.assertFalse(os.path.exists(sa.CIRCL_CACHE_FILE))      # never cached

    def test_empty_page_with_a_nonzero_count_is_not_no_notices(self):
        body = b'{"metadata": {"count": 7, "page": 1, "per_page": 100}, "data": []}'
        res = sa.circl_search("Unisoc", fetch=lambda *a, **k: body)
        self.assertEqual((res["records"], res["complete"]), ([], False))
        self.assertIn("reported 7 result(s) but sent 0", res["partial_reason"])
        self.assertFalse(os.path.exists(sa.CIRCL_CACHE_FILE))

    def test_old_partial_cache_entries_are_ignored(self):
        write(sa.CIRCL_CACHE_FILE, json.dumps({"Unisoc": {"records": [], "complete": False, "time": 1e12}}))
        res = sa.circl_search("Unisoc", fetch=self.pages(1), now=1e12 + 10)
        self.assertFalse(res["from_cache"])


class CirclRangeAttributionTests(unittest.TestCase):
    def rec(self, versions, default=None, assigner="Unisoc", vendor="Unisoc (Shanghai) Technologies Co., Ltd.",
            desc="In x, a bug."):
        aff = {"vendor": vendor, "product": "T606/T616", "versions": versions}
        if default:
            aff["defaultStatus"] = default
        return sa.compact_circl({"cveMetadata": {"cveId": "CVE-2025-11111", "assignerShortName": assigner},
                                 "containers": {"cna": {"providerMetadata": {"shortName": assigner},
                                                        "descriptions": [{"lang": "en", "value": desc}],
                                                        "affected": [aff]}}})

    def test_less_than_range_is_never_not_listed(self):
        r = self.rec([{"version": "Android10", "lessThan": "Android16", "status": "affected"}])
        self.assertTrue(r["ranges"])
        f = sa.circl_assess([r], REDMI_CHIP, vendor="Unisoc")[0]
        self.assertEqual(f["android"], "unknown")                 # Android 15 is inside the range
        self.assertNotIn("not listed", f["summary"])
        for v, d in (([{"version": "10", "lessThanOrEqual": "14", "status": "affected"}], None),
                     ([{"version": "10", "status": "affected", "changes": [{"at": "12", "status": "unaffected"}]}],
                      None),
                     ([{"version": "Android12", "status": "affected"}], "affected")):     # rest affected too
            g = sa.circl_assess([self.rec(v, d)], REDMI_CHIP, vendor="Unisoc")[0]
            self.assertEqual(g["android"], "unknown", (v, d))

    def test_explicit_lists_still_matched(self):
        r = self.rec([{"version": "Android10/Android11", "status": "affected"}])
        self.assertFalse(r["ranges"])
        self.assertEqual(sa.circl_assess([r], REDMI_CHIP, vendor="Unisoc")[0]["android"], "not_listed")

    def test_record_only_mentioning_the_maker(self):
        r = self.rec([{"version": "Android12", "status": "affected"}], assigner="mitre", vendor="SomeOEM",
                     desc="A bug in a phone that uses a Unisoc chip.")
        f = sa.circl_assess([r], REDMI_CHIP, vendor="Unisoc")[0]
        self.assertEqual(f["source"], "mention")
        self.assertIn("wasn't published by Unisoc", f["summary"])
        self.assertEqual(f["chip"], "")                           # never matched as the maker's notice
        own = sa.circl_assess([sa.compact_circl(CIRCL_FIXTURE["unisoc_page"]["data"][0])], REDMI_CHIP,
                              vendor="Unisoc")[0]
        self.assertEqual(own["source"], "maker")                  # assigner "Unisoc" -> its own notice
        self.assertTrue(sa.circl_attributed(self.rec([], assigner="Spreadtrum", vendor="x"),
                                            "Unisoc"))           # the old company name counts too

    def test_affected_vendor_alone_is_not_the_publisher(self):
        r = self.rec([{"version": "Android12", "status": "affected"}], assigner="mitre",
                     vendor="Unisoc (Shanghai) Technologies Co., Ltd.")
        self.assertFalse(sa.circl_attributed(r, "Unisoc"))
        f = sa.circl_assess([r], REDMI_CHIP, vendor="Unisoc")[0]
        self.assertEqual(f["source"], "mention")
        self.assertIn("published by mitre", f["summary"])

    def test_cve_in_bulletin_data_but_not_shown_gets_no_second_verdict(self):
        osv = cv.compact_record(OSV_FIXTURE["qualcomm"])          # type 'Unknown' -> not 'relevant'
        a = cv.assess([osv], REDMI, {})
        self.assertFalse(a["findings"])                           # not among the displayed findings
        circl = self.rec([{"version": "Android15", "status": "affected"}])
        circl["cve"] = osv["cves"][0]
        f = sa.circl_assess([circl], REDMI_CHIP, bulletin={}, known=set(osv["cves"]), vendor="Unisoc")[0]
        self.assertEqual((f["source"], f["bulletin_state"], f["chip"]), ("bulletin", None, ""))
        self.assertIn("no separate verdict", f["summary"])


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class KnownIssuesCorrectionTests(KnownIssuesWindowTests):
    def res(self, records, **kw):
        r = {"records": records, "count": len(records), "complete": True, "stopped": False, "fetched": "x",
             "from_cache": False, "partial_reason": ""}
        r.update(kw)
        return r

    def test_empty_states_are_honest(self):
        w = self.win()
        w._searched("Unisoc", self.res([], stopped=True, complete=False, partial_reason="stopped"), None)
        self.assertIn("stopped before any notices arrived", w.status.cget("text"))
        w._searched("Unisoc", self.res([], complete=False, partial_reason="the service asks to slow down"), None)
        self.assertIn("didn't complete", w.status.cget("text"))
        self.assertNotIn("no notices found", w.status.cget("text"))
        w._searched("Unisoc", self.res([]), None)
        self.assertIn("no notices found (the search completed)", w.status.cget("text"))
        w.destroy()

    def test_index_uses_the_whole_bulletin_download(self):
        q = cv.compact_record(OSV_FIXTURE["qualcomm"])
        sa.atomic_write_json(sa.CVE_DATA_FILE, {"schema": 1, "checked": "x", "osv_records": [q], "kev": {},
                                                "kev_error": ""})
        w = self.win()
        circl = sa.compact_circl(CIRCL_FIXTURE["unisoc_page"]["data"][0])
        circl["cve"] = q["cves"][0]
        w._searched("Unisoc", self.res([circl]), None)
        iid = w.tree.get_children()[0]
        self.assertEqual(w.tree.set(iid, "state"), "in the bulletin data")
        w.destroy()

    for _n in ("test_opening_never_uses_the_network", "test_saved_data_is_assessed_locally",
               "test_failed_search_says_unavailable_not_clean", "test_search_results_shown_with_honest_labels"):
        locals()[_n] = None
    del _n


for _n in [n for n in dir(CirclSearchTests) if n.startswith("test_")]:
    setattr(CirclCorrectionTests, _n, None)



# ==========================================================================
# Round 49 - Milestone 3, part 1: the append-only history of changes
# ==========================================================================

import history   # noqa: E402


class HistoryFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "sub", "history.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def ev(self, i, **kw):
        return history.make_event("SER", "app-off", "com.a%d" % i, "verified", now="2026-11-14 10:00:%02d" % i, **kw)

    def test_append_and_read_newest_first(self):
        for i in range(3):
            self.assertTrue(history.append(self.path, self.ev(i)))
        events, bad = history.read(self.path)
        self.assertEqual([e["pkg"] for e in events], ["com.a2", "com.a1", "com.a0"])
        self.assertEqual(bad, 0)
        self.assertEqual(mode(self.path), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(self.path)).st_mode), 0o700)

    def test_a_line_cut_by_a_crash_is_skipped_and_counted(self):
        history.append(self.path, self.ev(0))
        with open(self.path, "ab") as f:
            f.write(b'{"v":1,"t":"2026-11-14 10:00:09","what":"app-of')        # torn last line
        history.append(self.path, self.ev(1))                                   # later appends still work
        events, bad = history.read(self.path)
        self.assertEqual(([e["pkg"] for e in events], bad), (["com.a1", "com.a0"], 1))
        with open(self.path, "ab") as f:
            f.write(b'[1, 2]\n{"no": "what"}\n\xff\xfe\n')
        self.assertEqual(history.read(self.path)[1], 4)

    def test_every_event_is_flushed_to_disk(self):
        with mock.patch.object(history.os, "fsync", wraps=os.fsync) as fs:
            history.append(self.path, self.ev(0))
        fs.assert_called_once()

    def test_only_ever_appended(self):
        history.append(self.path, self.ev(0))
        first = read(self.path)
        history.append(self.path, self.ev(1))
        self.assertTrue(read(self.path).startswith(first))

    def test_rotation_keeps_one_older_file(self):
        with mock.patch.object(history, "MAX_BYTES", 600):
            for i in range(12):
                history.append(self.path, self.ev(i))
        self.assertTrue(os.path.exists(self.path + ".1"))
        events, bad = history.read(self.path)
        self.assertEqual(events[0]["pkg"], "com.a11")
        self.assertEqual(bad, 0)
        self.assertLess(os.path.getsize(self.path), 600)

    def test_event_fields_are_bounded(self):
        e = history.make_event("SER", "x" * 99, "p" * 999, "weird", "line1\nline2" + "m" * 999, user="0")
        self.assertEqual(e["outcome"], "done")
        self.assertIsNone(e["user"])                                  # only a real number is kept
        self.assertEqual((len(e["what"]), len(e["pkg"]), len(e["msg"])), (60, 255, history.MAX_MSG))
        self.assertNotIn("\n", e["msg"])
        self.assertEqual(history.make_event("S", "x", "p", None)["outcome"], "failed")

    def test_concurrent_writers_never_interleave(self):
        def writer(k):
            for i in range(50):
                history.append(self.path, history.make_event("S%d" % k, "app-off", "p%d" % i, "verified",
                                                             "m" * 300))
        ts = [threading.Thread(target=writer, args=(k,)) for k in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        events, bad = history.read(self.path)
        self.assertEqual((len(events), bad), (200, 0))

    def test_write_failure_is_reported(self):
        os.makedirs(self.path)                                         # a folder where the file should be
        self.assertFalse(history.append(self.path, self.ev(0)))
        self.assertEqual(history.read(self.path), ([], 0))


class HistoryLoggingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.p = [mock.patch.object(am, "HISTORY_FILE", os.path.join(self.tmp, "h.jsonl")),
                  mock.patch.object(am, "ACTIONS_LOG", os.path.join(self.tmp, "actions.log"))]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_log_action_writes_history_and_the_old_log(self):
        am.log_action("SER", "disable", "com.a", True, "new state: disabled-user")
        am.log_action("SER", "restore", "com.b", False, "boom")
        events, _ = history.read(am.HISTORY_FILE)
        self.assertEqual([(e["what"], e["outcome"], e["source"]) for e in events],
                         [("restore", "failed", "apps"), ("disable", "done", "apps")])
        self.assertIn("com.a", read(am.ACTIONS_LOG))


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class HistoryWiringTests(ProfileWindowTests):
    def setUp(self):
        super().setUp()
        self.htmp = tempfile.mkdtemp()
        self.hp = mock.patch.object(am, "HISTORY_FILE", os.path.join(self.htmp, "h.jsonl"))
        self.hp.start()

    def tearDown(self):
        self.hp.stop()
        shutil.rmtree(self.htmp, ignore_errors=True)
        super().tearDown()

    def test_autorun_changes_are_now_logged(self):
        t = self.app.autorun_tab
        ph = self.phone()
        ctx = {"serial": "SER", "user": 0, "user_verified": True, "pkg": self.VLC, "cls": None, "before": None,
               "target_sdk": 34, "key": am.AutorunTab.record_key("SER", 0, self.VLC), "want_root": False}
        with mock.patch.object(am, "adb_shell", side_effect=ph), mock.patch.object(t, "post"):
            t._act_work(t.gen, "bg_restrict", ctx)
        e = history.read(am.HISTORY_FILE)[0][0]
        self.assertEqual((e["what"], e["outcome"], e["source"], e["user"], e["pkg"]),
                         ("bg-restrict", "verified", "autorun", 0, self.VLC))

    def test_profile_changes_are_logged_with_their_real_outcome(self):
        ph = self.phone()
        with mock.patch.object(am, "adb_shell", side_effect=ph):
            self.win.apply_one(self.VLC, "off", self.f)
            self.win.apply_one(self.SYS, "removed", self.f)
        events = history.read(am.HISTORY_FILE)[0]
        self.assertEqual([(e["what"], e["outcome"], e["source"]) for e in events],
                         [("remove-for-user", "verified", "profile"), ("app-off", "verified", "profile")])

    def test_history_window(self):
        history.append(am.HISTORY_FILE, history.make_event("SER", "app-off", self.VLC, "verified", source="autorun"))
        history.append(am.HISTORY_FILE, history.make_event("OTHER", "restore", "com.x", "failed"))
        with open(am.HISTORY_FILE, "ab") as f:
            f.write(b"garbage\n")
        w = am.HistoryWindow(self.root, self.app)
        rows = [w.tree.item(i) for i in w.tree.get_children()]
        self.assertEqual(len(rows), 1)                                   # only the connected phone
        self.assertEqual(rows[0]["values"][0], "Turned OFF")
        self.assertIn("checked on the phone", rows[0]["values"][2])
        self.assertIn("1 unreadable line(s) skipped", w.summary.cget("text"))
        w.only_this.set(False)
        w.refresh()
        self.assertEqual(len(w.tree.get_children()), 2)
        w.destroy()

    for _n in [n for n in dir(ProfileWindowTests) if n.startswith("test_")]:
        locals()[_n] = None
    del _n



# ==========================================================================
# Round 50 - Milestone 3, part 2: pending journal + read-back-only recovery
# ==========================================================================

class JournalBase:
    def setUp(self):
        super().setUp()
        self.jtmp = tempfile.mkdtemp()
        self.jp = [mock.patch.object(am, "PENDING_FILE", os.path.join(self.jtmp, "pending_ops.json")),
                   mock.patch.object(am, "HISTORY_FILE", os.path.join(self.jtmp, "h.jsonl"))]
        for x in self.jp:
            x.start()

    def tearDown(self):
        for x in self.jp:
            x.stop()
        shutil.rmtree(self.jtmp, ignore_errors=True)
        super().tearDown()

    def on_disk(self):
        try:
            return json.loads(read(am.PENDING_FILE))
        except OSError:
            return {}


class JournalTests(JournalBase, unittest.TestCase):
    def test_begin_end_and_noop(self):
        op = am.journal_begin("S", 0, "com.a", "app-off", "on", "off", source="apps")
        self.assertIn(op, self.on_disk())                         # on disk BEFORE anything is sent
        self.assertEqual(mode(am.PENDING_FILE), 0o600)
        am.journal_end(op)
        self.assertEqual(self.on_disk(), {})                      # deleted, not left as null
        self.assertEqual(am.journal_begin("S", 0, "com.a", "app-off", "off", "off"), am.NOOP)
        self.assertEqual(self.on_disk(), {})

    def test_unsaved_record_means_no_change_and_never_reappears(self):
        st = am.pending_store()
        with mock.patch.object(st, "_save", return_value=False):
            self.assertIs(am.journal_begin("S", 0, "com.a", "app-off", "on", "off"), False)
        op2 = am.journal_begin("S", 0, "com.b", "app-off", "on", "off")      # a later save succeeds
        self.assertEqual(list(self.on_disk()), [op2])                         # the refused one isn't there

    def test_settle_rules(self):
        rec = {"original": "on", "desired": "off"}
        self.assertEqual(am.settle(rec, "off"), "verified")
        self.assertEqual(am.settle(rec, "on"), "not_applied")
        self.assertEqual(am.settle(rec, None), "uncertain")
        self.assertEqual(am.settle({"original": None, "desired": "off"}, "on"), "uncertain")
        bg = {"original": {"RUN_ANY_IN_BACKGROUND": "implicit"}, "desired": {"RUN_ANY_IN_BACKGROUND": "ignore"}}
        self.assertEqual(am.settle(bg, {"RUN_ANY_IN_BACKGROUND": "ignore"}), "verified")
        self.assertEqual(am.settle(bg, {"RUN_ANY_IN_BACKGROUND": "implicit"}), "not_applied")

    def test_store_delete_persists(self):
        st = am.JsonStore(os.path.join(self.jtmp, "x.json"))
        st.put("a", 1)
        st.put("b", 2)
        self.assertTrue(st.delete("a"))
        self.assertEqual(am.JsonStore(st.path).keys(), ["b"])


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class JournalWiringTests(JournalBase, ProfileWindowTests):
    def watching(self, ph, needle):
        """Wrap the phone: when the modifying command arrives, remember what was on disk."""
        seen = {}
        real = ph.__call__

        def spy(serial, cmd, timeout=30):
            if needle in cmd and "at_command" not in seen:
                seen["at_command"] = self.on_disk()
            return real(serial, cmd, timeout)
        return spy, seen

    def test_apps_tab_off_is_recorded_before_it_is_sent(self):
        ph = self.phone()
        spy, seen = self.watching(ph, "disable-user")
        with mock.patch.object(am, "adb_shell", side_effect=spy), mock.patch.object(self.at, "post"):
            self.at._change_worker("SER", [self.VLC], False, False)
        rec = list(seen["at_command"].values())
        self.assertEqual([(r["what"], r["original"], r["desired"], r["pkg"]) for r in rec],
                         [("app-off", "on", "off", self.VLC)])
        self.assertEqual(self.on_disk(), {})                      # cleared once it returned

    def test_autorun_and_profile_paths_are_journaled(self):
        ph = self.phone()
        spy, seen = self.watching(ph, " set ")
        with mock.patch.object(am, "adb_shell", side_effect=spy):
            self.assertEqual(self.win.apply_one(self.VLC, "background", self.f)[0], "verified")
        r = list(seen["at_command"].values())[0]
        self.assertEqual((r["what"], r["desired"], r["source"]), ("bg-restrict", {"RUN_ANY_IN_BACKGROUND": "ignore"},
                                                                  "autorun"))
        spy, seen = self.watching(ph, "pm uninstall")
        with mock.patch.object(am, "adb_shell", side_effect=spy):
            self.win.apply_one(self.SYS, "removed", self.f)
        self.assertEqual(list(seen["at_command"].values())[0]["what"], "remove-for-user")
        self.assertEqual(self.on_disk(), {})

    def test_no_record_no_change(self):
        ph = self.phone()
        with mock.patch.object(am.pending_store(), "_save", return_value=False), \
                mock.patch.object(am, "adb_shell", side_effect=ph), mock.patch.object(self.at, "post") as post:
            self.at._change_worker("SER", [self.VLC], False, False)
            out = self.win.apply_one(self.SYS, "removed", self.f)
        self.assertFalse([c for c in ph.log if "disable-user" in c or c.startswith("pm uninstall")])
        self.assertIn("couldn't be saved to disk first", post.call_args[0][3][0][2])
        self.assertEqual(out[0], "failed")

    def run_off(self, phone):
        with mock.patch.object(am, "adb_shell", side_effect=phone):
            return am.AutorunTab._act_run(self.app.autorun_tab, "app_off", {
                "serial": "SER", "user": 0, "pkg": self.VLC, "cls": None, "before": None, "target_sdk": 34,
                "key": am.AutorunTab.record_key("SER", 0, self.VLC), "want_root": False})

    def test_a_dropped_connection_leaves_its_record(self):
        gone = {"yes": False}
        ph = self.phone()

        def dies(serial, cmd, timeout=30):            # the phone disappears as the command is sent
            if "disable-user" in cmd:
                gone["yes"] = True
            if gone["yes"]:
                raise am.AdbError("device offline")
            return ph(serial, cmd, timeout)
        res = self.run_off(dies)
        self.assertEqual(res["outcome"], "failed")
        self.assertEqual([r["what"] for r in self.on_disk().values()], ["app-off"])   # unknown -> stays

    def test_known_outcomes_close_the_record(self):
        self.assertEqual(self.run_off(self.phone())["outcome"], "verified")
        self.assertEqual(self.on_disk(), {})
        ph = self.phone()
        real = ph.__call__

        def refuses(serial, cmd, timeout=30):
            if "disable-user" in cmd:
                return 255, "", "java.lang.SecurityException: Shell cannot change component state"
            return real(serial, cmd, timeout)
        self.assertEqual(self.run_off(refuses)["outcome"], "refused")
        self.assertEqual(self.on_disk(), {})
        gone = {"yes": False}

        def refuses_then_gone(serial, cmd, timeout=30):     # the phone said no, then couldn't be read
            if gone["yes"]:
                raise am.AdbError("device offline")
            if "disable-user" in cmd:
                gone["yes"] = True
                return 255, "", "java.lang.SecurityException: Shell cannot change component state"
            return real(serial, cmd, timeout)
        self.assertEqual(self.run_off(refuses_then_gone)["outcome"], "refused")
        self.assertEqual(self.on_disk(), {})                # a refusal is a known outcome

    # ---- recovery -------------------------------------------------------------------------

    def seed(self, what, pkg, original, desired, user=0, target="", source="apps"):
        return am.journal_begin("SER", user, pkg, what, original, desired, target, source)

    def test_recovery_reads_only_and_settles(self):
        ph = self.phone()
        ph.pkg_state[self.VLC] = 3                      # the OFF did happen
        a = self.seed("app-off", self.VLC, "on", "off")
        b = self.seed("app-off", self.CRIT, "on", "off")  # it didn't
        c = self.seed("uninstall-updates", self.SYS, None, None)   # can't be read back
        d = self.seed("app-off", "com.other.user", "on", "off", user=10)
        with mock.patch.object(am, "adb_shell", side_effect=ph):
            res = {r["id"]: o for r, o in am.reconcile_pending("SER", 0, True)}
        self.assertEqual(res, {a: "verified", b: "not_applied", c: "uncertain", d: "other_user"})
        self.assertEqual(set(self.on_disk()), {c, d})                       # settled ones cleared
        for cmd in ph.log:                                                  # nothing sent again
            self.assertFalse(any(w in cmd for w in ("disable-user", "pm enable", "uninstall", " set ")), cmd)
        events = history.read(am.HISTORY_FILE)[0]
        self.assertEqual(sorted((e["pkg"], e["outcome"], e["source"]) for e in events),
                         [(self.CRIT, "not_applied", "recovery"), (self.VLC, "verified", "recovery")])

    def test_unverified_user_settles_nothing(self):
        self.seed("app-off", self.VLC, "on", "off")
        ph = self.phone()
        with mock.patch.object(am, "adb_shell", side_effect=ph):
            res = am.reconcile_pending("SER", 0, False)
        self.assertEqual([o for r, o in res], ["user_unverified"])
        self.assertEqual(len(self.on_disk()), 1)

    def test_other_phone_untouched(self):
        am.journal_begin("OTHER", 0, self.VLC, "app-off", "on", "off")
        with mock.patch.object(am, "adb_shell", side_effect=self.phone()):
            self.assertEqual(am.reconcile_pending("SER", 0, True), [])
        self.assertEqual(len(self.on_disk()), 1)

    def test_forget_logs_uncertain(self):
        op = self.seed("uninstall-updates", self.SYS, None, None)
        am.forget_pending([op])
        self.assertEqual(self.on_disk(), {})
        e = history.read(am.HISTORY_FILE)[0][0]
        self.assertEqual((e["outcome"], e["source"]), ("uncertain", "recovery"))

    def test_after_a_scan_the_user_is_told_and_undo_list_completed(self):
        ph = self.phone()
        ph.pkg_state[self.VLC] = 3
        self.seed("app-off", self.VLC, "on", "off")
        self.seed("uninstall-updates", self.SYS, None, None)
        with mock.patch.object(am, "adb_shell", side_effect=ph):
            self.at._reconcile_work("SER")
        with mock.patch.object(am.messagebox, "askyesno", return_value=False) as ask, \
                mock.patch.object(am.messagebox, "showinfo"):
            self.pump(lambda: ask.called, 5)
        text = ask.call_args[0][1]
        self.assertIn("only READ", text)
        self.assertIn("it did happen", text)
        self.assertIn("couldn't be confirmed", text)
        self.assertIn(self.VLC, self.at.turned_off.get("SER", {}))         # now offered by "turn back ON"
        self.assertEqual(len(self.on_disk()), 1)                            # "No" keeps the uncertain one

    for _n in [n for n in dir(ProfileWindowTests) if n.startswith("test_")]:
        locals()[_n] = None
    del _n



# ==========================================================================
# Round 50b - Milestone 3 review corrections
# ==========================================================================

class HistoryRotationRaceTests(unittest.TestCase):
    def test_lock_is_a_stable_sidecar_taken_before_the_file_is_touched(self):
        """Deterministic version of the race: the lock must live on '<file>.lock' (never rotated)
        and be held BEFORE the history file is opened, inspected or rotated."""
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "h.jsonl")
            calls, real_open, real_lock, real_size = [], os.open, history._lock, os.path.getsize

            def rec_open(p, *a, **k):
                fd = real_open(p, *a, **k)
                calls.append(("open", os.path.basename(p), fd))
                return fd

            def rec_lock(fd):
                calls.append(("lock", fd))
                return real_lock(fd)

            def rec_size(p):
                calls.append(("size", os.path.basename(p)))
                return real_size(p)
            inodes = set()
            with mock.patch.object(history, "MAX_BYTES", 450):
                for i in range(12):
                    calls.clear()
                    with mock.patch.object(history.os, "open", side_effect=rec_open), \
                            mock.patch.object(history, "_lock", side_effect=rec_lock), \
                            mock.patch.object(history.os.path, "getsize", side_effect=rec_size):
                        self.assertTrue(history.append(path, history.make_event("S", "x", "p%d" % i, "verified")))
                    lock_fd = [c[2] for c in calls if c[0] == "open" and c[1] == "h.jsonl.lock"]
                    self.assertEqual(len(lock_fd), 1)
                    locks = [c for c in calls if c[0] == "lock"]
                    self.assertEqual(locks, [("lock", lock_fd[0])])                # only the sidecar is locked
                    first_touch = next(j for j, c in enumerate(calls) if c[0] in ("open", "size")
                                       and c[1] == "h.jsonl")
                    self.assertLess(calls.index(locks[0]), first_touch)            # locked before touching it
                    inodes.add(os.stat(path + ".lock").st_ino)
            self.assertTrue(os.path.exists(path + ".1"))                           # rotations happened
            self.assertEqual(len(inodes), 1)                                       # the lock file never moved
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_concurrent_writers_across_rotations_lose_nothing(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "h.jsonl")
            N = 60
            with mock.patch.object(history, "MAX_BYTES", 450):     # a rotation every ~2 events
                def writer(k):
                    for i in range(N):
                        history.append(path, history.make_event("S", "app-off", "w%d-%d" % (k, i), "verified"))
                ts = [threading.Thread(target=writer, args=(k,)) for k in range(8)]
                for t in ts:
                    t.start()
                for t in ts:
                    t.join()
            # each rotation keeps only ONE older file, so count what survives in the newest two files
            # and prove it's a gap-free tail: no event written after a kept one may be missing
            names = []
            for p in (path + ".1", path):
                with open(p, encoding="utf-8") as f:
                    names += [json.loads(l)["pkg"] for l in f if l.strip()]
            self.assertEqual(len(names), len(set(names)))                 # nothing duplicated
            last = {}
            for n in names:
                k, i = n[1:].split("-")
                last.setdefault(k, []).append(int(i))
            for k, seq in last.items():
                self.assertEqual(seq, list(range(seq[0], N)), k)          # each writer: a complete tail
            self.assertEqual(mode(path + ".lock"), 0o600)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class Journal50bTests(JournalBase, ProfileWindowTests):
    def seed(self, what, pkg, original, desired, user=0, target="", source="apps"):
        return am.journal_begin("SER", user, pkg, what, original, desired, target, source)

    def test_record_without_a_user_is_never_read_or_settled(self):
        op = self.seed("app-off", self.VLC, "on", "off", user=None)
        ph = self.phone()
        ph.pkg_state[self.VLC] = 3
        with mock.patch.object(am, "adb_shell", side_effect=ph):
            res = am.reconcile_pending("SER", 0, True)
            self.assertIsNone(am.read_op_state("SER", dict(user=None, what="app-off", pkg=self.VLC)))
        self.assertEqual([o for r, o in res], ["unknown_user"])
        self.assertFalse([c for c in ph.log if self.VLC in c])          # the phone was never even read
        self.assertIn(op, self.on_disk())

    def test_users_never_cross(self):
        a = self.seed("app-off", self.VLC, "on", "off", user=10)
        ph = self.phone()
        with mock.patch.object(am, "adb_shell", side_effect=ph):
            self.assertEqual([o for r, o in am.reconcile_pending("SER", 0, True)], ["other_user"])
        am.journal_end(a)
        self.seed("app-off", self.VLC, "on", "off", user=0)
        with mock.patch.object(am, "adb_shell", side_effect=ph):
            self.assertEqual([o for r, o in am.reconcile_pending("SER", 10, True)], ["other_user"])
        self.assertFalse([c for c in ph.log if self.VLC in c])
        self.assertEqual(len(self.on_disk()), 1)

    def test_dialog_tells_the_cases_apart(self):
        self.seed("app-off", self.VLC, "on", "off", user=None)
        with mock.patch.object(am, "adb_shell", side_effect=self.phone()), \
                mock.patch.object(am, "current_user", return_value=(0, "detected")):
            self.at._reconcile_work("SER")
        with mock.patch.object(am.messagebox, "askyesno", return_value=False) as ask, \
                mock.patch.object(am.messagebox, "showinfo"):
            self.pump(lambda: ask.called, 5)
        self.assertIn("isn't known which Android user", ask.call_args[0][1])
        self.seed("app-off", self.CRIT, "on", "off")
        with mock.patch.object(am, "adb_shell", side_effect=self.phone()), \
                mock.patch.object(am, "current_user", return_value=(0, "unverified")):
            self.at._reconcile_work("SER")
        with mock.patch.object(am.messagebox, "askyesno", return_value=False) as ask, \
                mock.patch.object(am.messagebox, "showinfo") as info:
            self.pump(lambda: ask.called or info.called, 5)
        text = (ask.call_args or info.call_args)[0][1]
        self.assertIn("current Android user couldn't be established", text)

    def test_full_uninstall_judged_by_the_installed_list(self):
        ph = self.phone(installed={self.SYS, self.CRIT}, removed={self.VLC})   # gone, but still known (-u)
        self.seed("uninstall-full", self.VLC, "installed", "absent")
        with mock.patch.object(am, "adb_shell", side_effect=ph):
            self.assertEqual([o for r, o in am.reconcile_pending("SER", 0, True)], ["verified"])
        with mock.patch.object(am, "adb_shell", return_value=(1, "", "Error: boom")):
            self.assertIsNone(am.read_op_state("SER", {"what": "uninstall-full", "pkg": self.VLC, "user": 0}))

    def run_act(self, kind, cls=None, before=None):
        return am.AutorunTab._act_run(self.app.autorun_tab, kind, {
            "serial": "SER", "user": 0, "pkg": self.VLC, "cls": cls, "before": before, "target_sdk": 34,
            "key": am.AutorunTab.record_key("SER", 0, self.VLC), "want_root": False})

    def test_noop_receiver_sends_nothing_and_saves_no_record(self):
        ph = self.phone()
        with mock.patch.object(am, "adb_shell", side_effect=ph):
            res = self.run_act("rx_off", "org.videolan.vlc.TvReceiver", "DISABLED")
        self.assertEqual(res["outcome"], "already")
        self.assertFalse([c for c in ph.log if "disable-user" in c])
        self.assertIsNone(self.app.autorun_tab.saved.get(am.AutorunTab.record_key("SER", 0, self.VLC)))
        self.assertEqual(self.on_disk(), {})

    def test_noop_background_sends_nothing_and_saves_no_record(self):
        ph = self.phone()
        ph.ops[(self.VLC, "RUN_ANY_IN_BACKGROUND")] = "ignore"
        with mock.patch.object(am, "adb_shell", side_effect=ph):
            res = self.run_act("bg_restrict")
        self.assertEqual(res["outcome"], "already")
        self.assertFalse([c for c in ph.log if " set " in c])
        self.assertIsNone(self.app.autorun_tab.saved.get(am.AutorunTab.record_key("SER", 0, self.VLC)))

    def test_noop_from_the_journal_is_honoured(self):
        ph = self.phone()
        with mock.patch.object(am, "journal_begin", return_value=am.NOOP), \
                mock.patch.object(am, "adb_shell", side_effect=ph), mock.patch.object(self.at, "post"):
            self.assertEqual(self.run_act("app_off")["outcome"], "already")
            self.assertEqual(self.run_act("rx_back", "org.videolan.vlc.TvReceiver")["outcome"], "failed")  # no record
            self.at._change_worker("SER", [self.VLC], False, False)
        self.assertFalse([c for c in ph.log if "disable-user" in c or "pm enable" in c])

    def test_apps_tab_reads_the_real_state_first(self):
        self.at.turned_off.put("SER", {})                  # other tests share this store
        ph = self.phone()
        ph.pkg_state[self.VLC] = 3                          # the list said ON, the phone says OFF
        with mock.patch.object(am, "adb_shell", side_effect=ph), mock.patch.object(self.at, "post") as post:
            self.at._change_worker("SER", [self.VLC], False, False)
        self.assertFalse([c for c in ph.log if "disable-user" in c])
        results = post.call_args[0][3]
        self.assertEqual(results[0][2], am.ALREADY_MSG)
        self.at.job = "x"
        self.at._change_done("SER", False, results, None)
        self.assertNotIn(self.VLC, self.at.turned_off.get("SER", {}))     # we didn't turn it off
        with mock.patch.object(am, "adb_shell", side_effect=ph), \
                mock.patch.object(am, "receiver_states", return_value={}), \
                mock.patch.object(self.at, "post") as post:
            self.at._change_worker("SER", [self.VLC], True, False)
        self.assertIn("couldn't be read", post.call_args[0][3][0][2])
        self.assertFalse([c for c in ph.log if "pm enable" in c])

    for _n in [n for n in dir(ProfileWindowTests) if n.startswith("test_")]:
        locals()[_n] = None
    del _n



# ==========================================================================
# Milestone 4 - read-only permission inventory (fixture: REAL Redmi output for VLC)
# ==========================================================================

import perm_inventory as pi   # noqa: E402

VLC_DUMP = r"""Packages:
  Package [org.videolan.vlc] (290de6):
    appId=10239
    pkg=Package{cf9cae5 org.videolan.vlc}
    codePath=/data/app/~~VSHed0Khk0LPrsn_CE4OFQ==/org.videolan.vlc-xAqdZh_NdvKeLrRU0o-SfA==
    resourcePath=/data/app/~~VSHed0Khk0LPrsn_CE4OFQ==/org.videolan.vlc-xAqdZh_NdvKeLrRU0o-SfA==
    legacyNativeLibraryDir=/data/app/~~VSHed0Khk0LPrsn_CE4OFQ==/org.videolan.vlc-xAqdZh_NdvKeLrRU0o-SfA==/lib
    extractNativeLibs=false
    primaryCpuAbi=arm64-v8a
    secondaryCpuAbi=null
    cpuAbiOverride=null
    versionCode=13070209 minSdk=32 targetSdk=36
    minExtensionVersions=[]
    versionName=3.7.2
    hiddenApiEnforcementPolicy=2
    usesNonSdkApi=false
    splits=[base, config.arm64_v8a, config.xhdpi]
    apkSigningVersion=3
    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP LARGE_HEAP ]
    privateFlags=[ PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE_VIA_SDK_VERSION ALLOW_AUDIO_PLAYBACK_CAPTURE PRIVATE_FLAG_REQUEST_LEGACY_EXTERNAL_STORAGE HAS_DOMAIN_URLS PARTIALLY_DIRECT_BOOT_AWARE PRIVATE_FLAG_ALLOW_NATIVE_HEAP_POINTER_TAGGING ]
    forceQueryable=false
    queriesIntents=[Intent { act=android.intent.action.SENDTO dat=mailto:xx }]
    scannedAsStoppedSystemApp=false
    supportsScreens=[small, medium, large, xlarge, resizeable, anyDensity]
    usesOptionalLibraries:
      androidx.window.extensions
      androidx.window.sidecar
    timeStamp=2026-11-07 08:26:27
    lastUpdateTime=2026-11-07 08:26:28
    installerPackageName=com.android.vending
    installerPackageUid=10154
    initiatingPackageName=com.android.vending
    originatingPackageName=null
    updateOwnerPackageName=com.android.vending
    packageSource=0
    appMetadataFilePath=/data/app/~~VSHed0Khk0LPrsn_CE4OFQ==/org.videolan.vlc-xAqdZh_NdvKeLrRU0o-SfA==/app.metadata
    appMetadataSource=2
    signatures=PackageSignatures{9df432a version:3, signatures:[2de34caa], past signatures:[609480e7 flags: 1f, 2de34caa flags: 1f]}
    installPermissionsFixed=false
    pkgFlags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP LARGE_HEAP ]
    privatePkgFlags=[ PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE_VIA_SDK_VERSION ALLOW_AUDIO_PLAYBACK_CAPTURE PRIVATE_FLAG_REQUEST_LEGACY_EXTERNAL_STORAGE HAS_DOMAIN_URLS PARTIALLY_DIRECT_BOOT_AWARE PRIVATE_FLAG_ALLOW_NATIVE_HEAP_POINTER_TAGGING ]
    apexModuleName=null
    declared permissions:
      org.videolan.vlc.permission.REMOTE_ACCESS_CONTROL: prot=signature
      org.videolan.vlc.MEDIA: prot=signature
      org.videolan.vlc.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION: prot=signature
    requested permissions:
      android.permission.WRITE_SETTINGS
      android.permission.POST_NOTIFICATIONS
      android.permission.MODIFY_AUDIO_SETTINGS
      android.permission.MANAGE_EXTERNAL_STORAGE
      org.videolan.vlc.permission.REMOTE_ACCESS_CONTROL
      android.permission.SYSTEM_ALERT_WINDOW
      org.videolan.vlc.MEDIA
      org.videolan.vlc.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION
      android.permission.CHANGE_NETWORK_STATE
      android.permission.FOREGROUND_SERVICE
      android.permission.READ_MEDIA_VISUAL_USER_SELECTED
      android.permission.RECEIVE_BOOT_COMPLETED
      android.permission.FOREGROUND_SERVICE_SPECIAL_USE
      android.permission.BLUETOOTH_CONNECT
      com.android.providers.tv.permission.READ_EPG_DATA
      android.permission.BLUETOOTH
      android.permission.INTERNET
      android.permission.READ_EXTERNAL_STORAGE
      com.android.providers.tv.permission.WRITE_EPG_DATA
      android.permission.READ_MEDIA_IMAGES
      org.videolan.vlc.permission.READ_EXTENSION_DATA
      android.permission.FOREGROUND_SERVICE_DATA_SYNC
      android.permission.ACCESS_NETWORK_STATE
      android.permission.READ_MEDIA_AUDIO
      android.permission.READ_MEDIA_VIDEO
      android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK
      android.permission.WRITE_EXTERNAL_STORAGE
      android.permission.VIBRATE
      android.permission.RECORD_AUDIO
      android.permission.WAKE_LOCK
    install permissions:
      android.permission.MODIFY_AUDIO_SETTINGS: granted=true
      android.permission.MANAGE_EXTERNAL_STORAGE: granted=false, flags=[ USER_SET]
      org.videolan.vlc.permission.REMOTE_ACCESS_CONTROL: granted=true
      org.videolan.vlc.MEDIA: granted=true
      org.videolan.vlc.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION: granted=true
      android.permission.CHANGE_NETWORK_STATE: granted=true
      android.permission.FOREGROUND_SERVICE: granted=true
      android.permission.RECEIVE_BOOT_COMPLETED: granted=true
      android.permission.FOREGROUND_SERVICE_SPECIAL_USE: granted=true
      android.permission.BLUETOOTH: granted=true
      android.permission.INTERNET: granted=true
      android.permission.FOREGROUND_SERVICE_DATA_SYNC: granted=true
      android.permission.ACCESS_NETWORK_STATE: granted=true
      android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK: granted=true
      android.permission.VIBRATE: granted=true
      android.permission.WAKE_LOCK: granted=true
    User 0: ceDataInode=16259 deDataInode=16248 installed=true hidden=false suspended=false distractionFlags=0 stopped=false notLaunched=false enabled=1 instant=false virtual=false quarantined=false
      installReason=4
      dataDir=/data/user/0/org.videolan.vlc
      firstInstallTime=2026-11-02 20:18:44
      uninstallReason=0
      overlay paths:
        /data/resource-cache/com.android.systemui-neutral-5PtE.frro
        /data/resource-cache/com.android.systemui-accent-C9Ax.frro
        /data/resource-cache/com.android.systemui-dynamic-1EGF.frro
      lastDisabledCaller: shell:1000
      gids=[3002, 3003]
      runtime permissions:
        android.permission.POST_NOTIFICATIONS: granted=false, flags=[ USER_SET|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
        android.permission.READ_MEDIA_VISUAL_USER_SELECTED: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
        android.permission.BLUETOOTH_CONNECT: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
        android.permission.READ_EXTERNAL_STORAGE: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]
        android.permission.READ_MEDIA_IMAGES: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
        android.permission.READ_MEDIA_AUDIO: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
        android.permission.READ_MEDIA_VIDEO: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
        android.permission.WRITE_EXTERNAL_STORAGE: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|RESTRICTION_INSTALLER_EXEMPT]
        android.permission.RECORD_AUDIO: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
      disabledComponents:
        org.videolan.vlc.widget.VLCAppWidgetProviderBlack
        org.videolan.vlc.widget.VLCAppWidgetProviderWhite

"""

SYSTEM_DUMP = """Packages:
  Package [com.android.phone] (1a2b):
    appId=1001
    requested permissions:
      android.permission.READ_SMS
      android.permission.CALL_PHONE
      android.permission.ACCESS_FINE_LOCATION
      android.permission.SEND_SMS
    install permissions:
      android.permission.INTERNET: granted=true
    User 0: ceDataInode=1 installed=true
      gids=[1001]
      runtime permissions:
        android.permission.READ_SMS: granted=true, flags=[ SYSTEM_FIXED|GRANTED_BY_DEFAULT]
        android.permission.CALL_PHONE: granted=true, flags=[ GRANTED_BY_ROLE|POLICY_FIXED]
        android.permission.ACCESS_FINE_LOCATION: granted=false, flags=[ USER_FIXED|USER_SET]
        android.permission.SEND_SMS: granted=false, flags=[ APPLY_RESTRICTION|SOME_NEW_FLAG]
    User 10: ceDataInode=2 installed=true
      runtime permissions:
        android.permission.READ_SMS: granted=false, flags=[ USER_SET]
  Package [com.old.app] (3c4d):
    requested permissions:
      android.permission.CAMERA
    install permissions:
      android.permission.INTERNET: granted=true

Hidden system packages:
  Package [com.android.phone] (5e6f):
    install permissions:
      android.permission.EVIL: granted=true

Queries:
    User 0:
      runtime permissions:
        android.permission.CAMERA: granted=true
"""


# both apps inside the 'Packages:' section (before 'Hidden system packages' / 'Queries', where parsing stops)
COMBINED_DUMP = SYSTEM_DUMP.replace("\nHidden system packages:", "\n" + VLC_DUMP.replace("Packages:\n", "")
                                    + "\nHidden system packages:")


class PermissionParseTests(unittest.TestCase):
    def test_real_vlc_output(self):
        d = pi.parse(VLC_DUMP, 0)["org.videolan.vlc"]
        self.assertEqual((len(d["requested"]), len(d["install"]), len(d["runtime"])), (30, 16, 9))
        self.assertEqual(d["runtime"]["android.permission.RECORD_AUDIO"],
                         (False, frozenset({"USER_SENSITIVE_WHEN_GRANTED", "USER_SENSITIVE_WHEN_DENIED"})))
        inv = pi.inventory({"org.videolan.vlc": d}, 35, True)["org.videolan.vlc"]
        # the misleading 'MANAGE_EXTERNAL_STORAGE: granted=false' is special access, not a denial
        self.assertEqual(inv["special"], ["android.permission.MANAGE_EXTERNAL_STORAGE",
                                          "android.permission.SYSTEM_ALERT_WINDOW",
                                          "android.permission.WRITE_SETTINGS"])
        self.assertNotIn("android.permission.MANAGE_EXTERNAL_STORAGE", inv["install"])
        self.assertEqual(inv["runtime_mode"], "ok")
        self.assertIn("exempt from the restriction (allowed by the installer)",
                      pi.explain(*d["runtime"]["android.permission.READ_EXTERNAL_STORAGE"])[1])

    def test_per_user_blocks_and_section_boundaries(self):
        p0 = pi.parse(SYSTEM_DUMP, 0)
        self.assertTrue(p0["com.android.phone"]["runtime"]["android.permission.READ_SMS"][0])
        p10 = pi.parse(SYSTEM_DUMP, 10)
        self.assertFalse(p10["com.android.phone"]["runtime"]["android.permission.READ_SMS"][0])
        self.assertEqual(list(p10["com.android.phone"]["runtime"]), ["android.permission.READ_SMS"])
        self.assertIsNone(pi.parse(SYSTEM_DUMP, 11)["com.android.phone"]["runtime"])
        self.assertNotIn("android.permission.EVIL", p0["com.android.phone"]["install"])      # hidden copy ignored
        self.assertIsNone(p0["com.old.app"]["runtime"])                                       # 'Queries:' stops it

    def test_queries_section_never_counts_as_a_package(self):
        d = ("Packages:\n  Package [com.old.app] (1):\n    requested permissions:\n      android.permission.CAMERA\n"
             "Queries:\n    User 0:\n      runtime permissions:\n        android.permission.CAMERA: granted=true\n")
        self.assertIsNone(pi.parse(d, 0)["com.old.app"]["runtime"])

    def test_only_the_first_block_of_a_package_counts(self):
        d = ("Packages:\n  Package [com.a.b] (1):\n    install permissions:\n      android.permission.INTERNET: granted=true\n"
             "  Package [com.a.b] (2):\n    install permissions:\n      android.permission.EVIL: granted=true\n")
        self.assertEqual(list(pi.parse(d, 0)["com.a.b"]["install"]), ["android.permission.INTERNET"])

    def test_special_access_never_listed_as_runtime(self):
        d = ("Packages:\n  Package [com.a.b] (1):\n    User 0: installed=true\n      runtime permissions:\n"
             "        android.permission.SYSTEM_ALERT_WINDOW: granted=true\n"
             "        android.permission.CAMERA: granted=true\n")
        inv = pi.inventory(pi.parse(d, 0), 34, True)["com.a.b"]
        self.assertEqual(list(inv["runtime"]), ["android.permission.CAMERA"])
        self.assertEqual(inv["special"], [])         # not requested -> not shown as asking either

    def test_flags_in_plain_words(self):
        rt = pi.parse(SYSTEM_DUMP, 0)["com.android.phone"]["runtime"]
        st, notes, change = pi.explain(*rt["android.permission.READ_SMS"])
        self.assertEqual((st, change), ("allowed", False))
        self.assertIn("fixed by the system - can't be changed", notes)
        self.assertIn("granted by Android's default policy", notes)
        st, notes, change = pi.explain(*rt["android.permission.CALL_PHONE"])
        self.assertFalse(change)
        self.assertTrue(any("role" in n for n in notes) and any("device policy" in n for n in notes))
        st, notes, change = pi.explain(*rt["android.permission.ACCESS_FINE_LOCATION"])
        self.assertEqual((st, change), ("not allowed", True))
        self.assertIn("you chose 'don't ask again'", notes)
        st, notes, change = pi.explain(*rt["android.permission.SEND_SMS"])
        self.assertEqual(st, "held back by policy")
        self.assertIn("Android flag: SOME_NEW_FLAG", notes)                  # unknown flags shown as they are
        self.assertFalse(any("USER_SET" in n for n in notes))               # routine flags kept quiet

    def test_modes(self):
        parsed = pi.parse(SYSTEM_DUMP, 0)
        self.assertEqual(pi.inventory(parsed, 34, True)["com.old.app"]["runtime_mode"], "no_user_block")
        unk = pi.inventory(parsed, 34, False)["com.android.phone"]
        self.assertEqual((unk["runtime_mode"], unk["runtime"]), ("user_unknown", {}))   # unknown, never 'denied'
        old = pi.inventory(parsed, 22, True)["com.android.phone"]
        self.assertEqual((old["runtime_mode"], old["runtime"]), ("install_time", {}))

    def test_legacy_granted_list(self):
        legacy = ("Packages:\n  Package [com.k.app] (1):\n    requested permissions:\n      android.permission.CAMERA\n"
                  "    grantedPermissions:\n      android.permission.CAMERA\n      android.permission.INTERNET\n")
        inv = pi.inventory(pi.parse(legacy, 0), 19, True)["com.k.app"]
        self.assertEqual((inv["runtime_mode"], inv["legacy"]),
                         ("install_time", ["android.permission.CAMERA", "android.permission.INTERNET"]))

    def test_groups(self):
        inv = pi.inventory(pi.parse(COMBINED_DUMP, 0), 34, True)
        self.assertIn("org.videolan.vlc", inv)
        g = pi.by_group(inv)
        self.assertEqual(sorted(g), ["Phone", "SMS"])                                    # allowed only
        g2 = pi.by_group(inv, include_denied=True)
        self.assertIn("Microphone", g2)
        self.assertEqual(pi.group_of("android.permission.UNHEARD_OF"), "Other")


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class PermissionsWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()
        args = mock.Mock(serial=None, local=TMP_HOME, remote="/sdcard")
        with mock.patch.object(am.App, "scan_devices", lambda self, *a, **k: None):
            cls.app = am.App(cls.root, args)
        cls.at = cls.app.apps_tab

    @classmethod
    def tearDownClass(cls):
        destroy_root(cls.root)

    def setUp(self):
        self.at.serial = "SER"
        self.at.props = {"sdk": "35"}
        self.at.apps = {"org.videolan.vlc": dict(real_app("org.videolan.vlc")),
                        "com.android.phone": dict(real_app("com.android.phone", True))}
        self.log = []

    def shell(self, user="0", dump=None, fail=False):
        def run(serial, cmd, timeout=30):
            self.log.append(cmd)
            if cmd == "am get-current-user":
                return 0, user + "\n", ""
            if cmd == "dumpsys package packages":
                return (1, "", "boom") if fail else (0, dump or COMBINED_DUMP, "")
            return 0, "", ""
        return run

    def open(self, shell):
        with mock.patch.object(am, "adb_shell", side_effect=shell):
            w = am.PermissionsWindow(self.root, self.app)
            end = time.time() + 20                         # finished = the Refresh button is enabled again
            while time.time() < end and "disabled" in w.refresh_btn.state():
                try:
                    while True:
                        item = self.app.q.get_nowait()
                        if item[0] == "call":
                            item[1](*item[2:])
                except Exception:
                    pass
                self.root.update()
                time.sleep(0.02)
        return w

    def texts(self, w):
        out = []
        for g in w.tree.get_children():
            out.append(w.tree.item(g, "text") + " | " + " | ".join(map(str, w.tree.item(g, "values"))))
            out += ["  " + w.tree.item(c, "text") + " | " + " | ".join(map(str, w.tree.item(c, "values")))
                    for c in w.tree.get_children(g)]
        return "\n".join(out)

    def test_group_view_read_only(self):
        w = self.open(self.shell())
        t = self.texts(w)
        self.assertIn("SMS  (1 app allowed)", t)
        self.assertIn("can't be changed", t)
        self.assertNotIn("Microphone", t)                                   # VLC's microphone is not allowed
        self.assertIn("Special access", t)
        self.assertIn("All files access | asks for it", t)
        w.denied.set(True)
        w.populate()
        self.assertIn("Microphone", self.texts(w))
        self.assertEqual(set(self.log), {"am get-current-user", "dumpsys package packages"})   # reads only
        w.destroy()

    def test_app_view_and_filter(self):
        w = self.open(self.shell())
        w.view.set("app")
        w.populate()
        t = self.texts(w)
        self.assertIn("2 allowed", t)
        w.mine.set(True)
        w.populate()
        self.assertNotIn("com.android.phone", self.texts(w).lower())          # preinstalled hidden
        w.destroy()

    def test_unconfirmed_user_is_unknown_not_denied(self):
        with mock.patch.object(am, "current_user", return_value=(0, "unverified")):
            w = self.open(self.shell())
        self.assertIn("couldn't be confirmed", w.status.cget("text"))
        w.view.set("app")
        w.populate()
        self.assertIn("unknown (user not confirmed)", self.texts(w))
        w.destroy()

    def test_failure_is_reported(self):
        w = self.open(self.shell(fail=True))
        self.assertIn("Couldn't read the permissions", w.status.cget("text"))
        self.assertEqual(w.tree.get_children(), ())
        w.destroy()

    def test_old_android(self):
        self.at.props = {"sdk": "22"}
        w = self.open(self.shell())
        self.assertIn("older than 6", w.status.cget("text"))
        w.destroy()



# ==========================================================================
# Milestone 4 review corrections
# ==========================================================================

@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class PermissionsCorrectionTests(PermissionsWindowTests):
    def test_output_without_package_records_is_an_error_not_empty(self):
        w = self.open(self.shell(dump="Some unexpected text\nwithout any Package [x] blocks\n"))
        self.assertIn("Couldn't read the permissions", w.status.cget("text"))
        self.assertIn("no package records", w.status.cget("text"))
        self.assertIsNone(w.apps)
        w.destroy()

    def vlc_rows(self, w):
        vlc = next(i for i in w.tree.get_children() if "videolan" in w.tree.item(i, "text"))
        sub = next(c for c in w.tree.get_children(vlc) if w.tree.item(c, "text") == "Install-time permissions")
        return vlc, {w.tree.item(c, "text"): w.tree.item(c, "values") for c in w.tree.get_children(sub)}

    def test_denied_install_permissions_are_visible(self):
        dump = COMBINED_DUMP.replace("      android.permission.WAKE_LOCK: granted=true\n",
                                     "      android.permission.WAKE_LOCK: granted=true\n"
                                     "      android.permission.NFC: granted=false, flags=[ SOME_FLAG]\n")
        w = self.open(self.shell(dump=dump))
        w.view.set("app")
        w.populate()
        self.assertIn("install-time: 15 granted, 1 not granted", self.texts(w))
        vlc, rows = self.vlc_rows(w)
        self.assertNotIn("NFC (install-time)", rows)                     # hidden until asked ...
        self.assertEqual(rows["INTERNET (install-time)"][0], "granted")
        w.denied.set(True)
        w.populate()
        vlc, rows = self.vlc_rows(w)
        self.assertEqual(rows["NFC (install-time)"][0], "not granted")   # ... then shown, with its state
        self.assertIn("Android flag: SOME_FLAG", rows["NFC (install-time)"][1])
        w.tree.selection_set(vlc)
        w.on_select()
        self.assertIn("NOT granted: NFC", w.detail.cget("text"))
        top = [w.tree.item(c, "text") for c in w.tree.get_children(vlc)]
        self.assertFalse([r for r in top if "(install-time)" in r])      # never mixed with runtime entries
        w.destroy()

    def test_modern_install_records_win_over_the_legacy_list(self):
        dump = ("Packages:\n  Package [org.videolan.vlc] (1):\n    install permissions:\n"
                "      android.permission.NFC: granted=false\n    grantedPermissions:\n"
                "      android.permission.CAMERA\n")
        w = self.open(self.shell(dump=dump))
        w.view.set("app")
        w.populate()
        vlc = next(i for i in w.tree.get_children() if "videolan" in w.tree.item(i, "text"))
        w.tree.selection_set(vlc)
        w.on_select()
        d = w.detail.cget("text")
        self.assertIn("install-time granted: none", d)                    # all modern entries are denied ...
        self.assertNotIn("CAMERA", d)                                      # ... so legacy isn't reported as granted
        self.assertIn("NOT granted: NFC", d)
        w.destroy()

    for _n in [n for n in dir(PermissionsWindowTests) if n.startswith("test_")]:
        locals()[_n] = None
    del _n



# ==========================================================================
# Milestone 5 - snapshots: start at boot, background, timeline
# ==========================================================================

def snapfacts(apps=None, failed=None):
    return {"apps": apps or {"com.user.a": {"version": "1", "version_code": "1", "system": False, "installer": ""},
                             "com.sys.b": {"version": "1", "version_code": "1", "system": True, "installer": ""}},
            "props": {"patch": "2026-02-01", "release": "15", "crypto": ""}, "selinux": "Enforcing",
            "failed": failed or {}, "su": "", "settings": {}, "admins": [], "appops": {}}


def snap(boot=None, bg=None, user=0, prev=None, failed=None):
    return sa.build_snapshot("SER", snapfacts(failed=failed), {}, None, {}, prev=prev, boot=boot, bg=bg, user=user)


class SnapshotExpansionTests(unittest.TestCase):
    def keys(self, found):
        return [f["key"] for f in found]

    def test_boot_and_background_are_recorded(self):
        s1 = snap(boot={"complete": True, "pkgs": {"com.user.a": True, "com.sys.b": False}},
                  bg={"com.user.a": False, "com.sys.b": True})
        self.assertEqual(s1["boot"], {"pkgs": ["com.user.a"], "complete": True, "user": 0, "unverified": False})
        self.assertEqual(s1["bg"], {"pkgs": {"com.user.a": False, "com.sys.b": True}, "user": 0, "unverified": False})

    def test_unreadable_values_are_carried_forward_marked_unverified(self):
        s1 = snap(boot={"complete": True, "pkgs": {"com.user.a": True}}, bg={"com.user.a": True})
        s2 = snap(prev=s1)                                                   # nothing readable this time
        self.assertEqual((s2["boot"]["pkgs"], s2["boot"]["unverified"]), (["com.user.a"], True))
        self.assertEqual((s2["bg"]["pkgs"], s2["bg"]["unverified"]), ({"com.user.a": True}, True))
        self.assertEqual((snap()["boot"], snap()["bg"]), (None, None))     # no previous value: unknown
        self.assertEqual(self.keys(sa.compare_snapshots(s1, s2, None)), ["changes:none-partial"])

    def test_new_boot_starter_needs_a_complete_previous_list(self):
        b0 = snap(boot={"complete": True, "pkgs": {}})
        b1 = snap(boot={"complete": True, "pkgs": {"com.user.a": True, "com.sys.b": True}})
        found = {f["key"]: f for f in sa.compare_snapshots(b0, b1, None)}
        self.assertEqual(found["changes:boot:com.user.a"]["level"], sa.WARN)
        self.assertEqual(found["changes:boot:com.sys.b"]["level"], sa.INFO)
        partial = snap(boot={"complete": False, "pkgs": {}})
        self.assertFalse([k for k in self.keys(sa.compare_snapshots(partial, b1, None)) if k.startswith("changes:boot")])

    def test_no_longer_starting_needs_a_complete_current_list(self):
        b1 = snap(boot={"complete": True, "pkgs": {"com.user.a": True}})
        self.assertIn("changes:boot-off", self.keys(sa.compare_snapshots(b1, snap(boot={"complete": True, "pkgs": {}}),
                                                                         None)))
        self.assertNotIn("changes:boot-off", self.keys(sa.compare_snapshots(
            b1, snap(boot={"complete": False, "pkgs": {}}), None)))

    def test_different_users_or_unverified_never_compare(self):
        b0 = snap(boot={"complete": True, "pkgs": {}}, bg={"com.user.a": True})
        other = snap(boot={"complete": True, "pkgs": {"com.user.a": True}}, bg={"com.user.a": False}, user=10)
        self.assertFalse([k for k in self.keys(sa.compare_snapshots(b0, other, None)) if "boot" in k or "bg" in k])
        unv = dict(snap(boot={"complete": True, "pkgs": {"com.user.a": True}}, bg={"com.user.a": False}))
        unv["boot"]["unverified"] = unv["bg"]["unverified"] = True
        self.assertFalse([k for k in self.keys(sa.compare_snapshots(b0, unv, None)) if "boot" in k or "bg" in k])

    def test_background_changes(self):
        a = snap(bg={"com.user.a": True, "com.sys.b": False})
        b = snap(bg={"com.user.a": False, "com.sys.b": True})
        found = {f["key"]: f for f in sa.compare_snapshots(a, b, None)}
        self.assertEqual(found["changes:bg-lifted:com.user.a"]["level"], sa.WARN)
        self.assertIn("com.sys.b", found["changes:bg-added"]["detail"])
        # an app missing from one side is never a change
        c = snap(bg={"com.user.a": False})
        self.assertFalse([k for k in self.keys(sa.compare_snapshots(snap(bg={}), c, None)) if "bg" in k])
        gone = snap(bg={})                                     # restricted before, absent from today's dump
        self.assertFalse([k for k in self.keys(sa.compare_snapshots(snap(bg={"com.user.a": True}), gone, None))
                          if "bg" in k])                      # unknown, never "restriction lifted"

    def test_partial_check_is_not_an_all_clear(self):
        full = snap(boot={"complete": True, "pkgs": {}}, bg={})
        self.assertEqual(self.keys(sa.compare_snapshots(full, snap(boot={"complete": True, "pkgs": {}}, bg={}), None)),
                         ["changes:none"])
        f = sa.compare_snapshots(full, snap(boot={"complete": False, "pkgs": {}}, bg={}), None)
        self.assertEqual((f[0]["key"], f[0]["level"]), ("changes:none-partial", sa.INFO))
        self.assertIn("the full start-at-boot list", f[0]["detail"])

    def test_old_snapshots_without_the_new_fields(self):
        old = snap(boot={"complete": True, "pkgs": {}}, bg={})
        old.pop("boot")
        old.pop("bg")
        self.assertEqual(sa.snapshot_gaps(old), [])                      # not tracked then: not a gap
        self.assertEqual(self.keys(sa.compare_snapshots(old, snap(boot={"complete": True, "pkgs": {"com.user.a": True}},
                                                                    bg={"com.user.a": True}), None)), ["changes:none"])

    def test_gaps_list(self):
        g = sa.snapshot_gaps(snap(prev=snap(boot={"complete": True, "pkgs": {}}, bg={}),
                                  failed={"selinux": "x"}))
        self.assertIn("which apps start at boot", g)
        self.assertIn("background restrictions", g)

    def test_list_snapshots_skips_damaged_files(self):
        tmp = tempfile.mkdtemp()
        try:
            with mock.patch.object(sa, "SNAP_DIR", tmp):
                for t in ("20261101-100000", "20261102-100000"):
                    sa.atomic_write_json(os.path.join(sa.snap_dir("SER"), t + ".json"), dict(snap(), time=t))
                with open(os.path.join(sa.snap_dir("SER"), "20261103-100000.json"), "w") as f:
                    f.write("{broken")
                self.assertEqual([x[1]["time"] for x in sa.list_snapshots("SER")],
                                 ["20261101-100000", "20261102-100000"])
                self.assertEqual(sa.list_snapshots("NOPE"), [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class SnapshotCheckupTests(PatternCheckupIntegrationTests):
    def shell(self, serial, cmd, timeout=60):
        if cmd.startswith("dumpsys appops"):
            return 0, ("Current AppOps Service state:\n  Uid u0a5:\n    Package com.a:\n"
                       "      RUN_ANY_IN_BACKGROUND (ignore):\n"), ""
        return PatternCheckupIntegrationTests.shell(self, serial, cmd, timeout)

    def run_check(self, shell):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        with mock.patch.object(sa, "SNAP_DIR", tmp):
            with mock.patch.object(am, "adb_shell", side_effect=shell), \
                    mock.patch.object(am, "read_sockets", return_value=([], [])), \
                    mock.patch.object(sa, "launcher_packages", return_value=({"com.b"}, "t")):
                apps = {"com.a": dict(_app(), installer="com.android.packageinstaller", target_sdk="34"),
                        "com.b": dict(_app(), installer="com.android.packageinstaller", target_sdk="34")}
                self.tab._do_check("SER", False, self.cfg, apps)
            return sa.last_snapshot("SER")

    def test_checkup_saves_boot_and_background(self):
        self.app.apps_tab.props = {"sdk": "34"}
        s = self.run_check(self.shell)
        self.assertEqual((s["boot"]["pkgs"], s["boot"]["user"]), (["com.a"], 0))
        self.assertEqual(s["bg"]["pkgs"], {"com.a": True})        # com.b isn't in the dump: unknown, not False

    def test_unknown_android_version_means_background_unread(self):
        self.app.apps_tab.props = {}
        s = self.run_check(self.shell)
        self.assertIsNone(s["bg"])                                     # unread - not a verified empty read
        self.assertIn("background restrictions", sa.snapshot_gaps(s))

    def test_unverified_user_saves_no_per_user_data(self):
        with mock.patch.object(am, "current_user", return_value=(0, "unverified")):
            s = self.run_check(self.shell)
        self.assertEqual((s["boot"], s["bg"]), (None, None))
        self.assertIn("which apps start at boot", sa.snapshot_gaps(s))

    for _n in [n for n in dir(PatternCheckupIntegrationTests) if n.startswith("test_")]:
        locals()[_n] = None
    del _n


@unittest.skipUnless(os.environ.get("DISPLAY"), "needs a display (run under xvfb-run)")
class TimelineWindowTests(unittest.TestCase):
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

    def test_timeline(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        with mock.patch.object(sa, "SNAP_DIR", tmp):
            s1 = dict(snap(boot={"complete": True, "pkgs": {}}, bg={}), time="2026-11-01 10:00:00")
            s2 = dict(snap(boot={"complete": True, "pkgs": {"com.user.a": True}}, bg={}), time="2026-11-02 10:00:00")
            s3 = dict(snap(prev=s2), time="2026-11-03 10:00:00")                     # couldn't read boot / bg
            for i, x in enumerate((s1, s2, s3)):
                sa.atomic_write_json(os.path.join(sa.snap_dir("SER"), "2026110%d-100000.json" % (i + 1)), x)
            w = am.TimelineWindow(self.root, self.app, "SER")
            rows = [(w.list.item(i, "text"), w.list.item(i, "values")[0]) for i in w.list.get_children()]
            self.assertEqual([r[0] for r in rows], ["2026-11-03 10:00:00", "2026-11-02 10:00:00", "2026-11-01 10:00:00"])
            self.assertEqual(rows[2][1], "first check")
            self.assertIn("1 change(s)", rows[1][1])
            self.assertIn("partial", rows[0][1])
            self.assertIn("couldn't read: which apps start at boot", w.text.get("1.0", "end"))   # newest selected
            w.list.selection_set("1")
            w.on_select()
            self.assertIn("now starts by itself at boot", w.text.get("1.0", "end"))
            w.destroy()
            w = am.TimelineWindow(self.root, self.app, "EMPTY")
            self.assertIn("No saved checks", w.head.cget("text"))
            w.destroy()


if __name__ == "__main__":
    unittest.main()
