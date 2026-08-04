"""Unit tests for the weekly version check — run standalone: python tests/test_versioncheck.py

Everything is injected — cache path, clock, fetcher — so no test touches the
network or the real ~/.cache. The contract: opt-out (--no-version-check,
AICHECK_NO_VERSION_CHECK=1), at most one stderr line, and every failure mode
(offline, timeout, 404, bad JSON, unwritable cache) is silence.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from aicheck import scan as scan_mod
from aicheck import versioncheck

NOW = datetime(2026, 7, 31, 12, 0, 0, tzinfo=timezone.utc)
NOTICE = ("v1.2.0 is out — pip install -U aicheck-scan "
          "(release notes: https://github.com/unauthdev/aicheck-scan/releases)")


def _cache(d: str) -> Path:
    return Path(d) / "version-check"


def test_newer_version_notifies_and_writes_cache() -> None:
    with tempfile.TemporaryDirectory() as d:
        cache = _cache(d)
        msg = versioncheck.maybe_notify("1.1.0", cache_path=cache, now=NOW,
                                        fetcher=lambda: "1.2.0")
        assert msg == NOTICE, msg
        data = json.loads(cache.read_text(encoding="utf-8"))
        assert datetime.fromisoformat(data["checked"]) == NOW
    print("ok — newer version → one notice line, cache timestamp written")


def test_fresh_cache_is_silent() -> None:
    with tempfile.TemporaryDirectory() as d:
        cache = _cache(d)
        cache.write_text(json.dumps({"checked": NOW.isoformat()}),
                         encoding="utf-8")
        called = []

        def boom():
            called.append(1)
            raise AssertionError("fetcher must not run within 7 days")

        msg = versioncheck.maybe_notify(
            "1.1.0", cache_path=cache, now=NOW + timedelta(days=6, hours=23),
            fetcher=boom)
        assert msg is None and not called
        # 7 days later the cache no longer protects → fetcher runs
        msg = versioncheck.maybe_notify(
            "1.1.0", cache_path=cache, now=NOW + timedelta(days=7),
            fetcher=lambda: "1.2.0")
        assert msg == NOTICE
    print("ok — cache < 7 days old → silent, fetcher never called")


def test_fetch_failure_silent_and_no_cache_write() -> None:
    with tempfile.TemporaryDirectory() as d:
        cache = _cache(d)

        def boom():
            raise httpx.ConnectError("offline")

        msg = versioncheck.maybe_notify("1.1.0", cache_path=cache, now=NOW,
                                        fetcher=boom)
        assert msg is None
        assert not cache.exists()  # failures don't back off a week
        # garbage fetcher results are silence too
        for junk in (None, "", 42, {}):
            assert versioncheck.maybe_notify(
                "1.1.0", cache_path=cache, now=NOW,
                fetcher=lambda j=junk: j) is None
        assert not cache.exists()
    print("ok — fetcher raising / junk → silent, no cache write")


def test_older_and_equal_versions_silent() -> None:
    with tempfile.TemporaryDirectory() as d:
        for pypi in ("1.0.9", "1.1.0", "1.1", "1.1.0rc1"):
            cache = _cache(d)
            msg = versioncheck.maybe_notify("1.1.0", cache_path=cache, now=NOW,
                                            fetcher=lambda p=pypi: p)
            assert msg is None, pypi
            assert cache.exists()  # a successful check still backs off a week
            cache.unlink()
    print("ok — older/equal/pre-release versions → silent (cache still written)")


def test_unwritable_cache_dir_silent() -> None:
    with tempfile.TemporaryDirectory() as d:
        blocker = Path(d) / "blocker"
        blocker.write_text("not a dir", encoding="utf-8")
        cache = blocker / "version-check"  # mkdir(parents) must fail
        msg = versioncheck.maybe_notify("1.1.0", cache_path=cache, now=NOW,
                                        fetcher=lambda: "1.2.0")
        assert msg is None
    print("ok — unwritable cache dir → silent no-op")


def test_fetch_latest_bad_responses() -> None:
    # PyPI 404s aicheck-scan until it is published — and anything else
    # unexpected — must parse to None (silence), never raise.
    class Resp:
        def __init__(self, status, payload=None, raises=False):
            self.status_code = status
            self._payload, self._raises = payload, raises

        def json(self):
            if self._raises:
                raise ValueError("not json")
            return self._payload

    orig = versioncheck.httpx.get
    try:
        for resp in (Resp(404), Resp(500), Resp(200, raises=True),
                     Resp(200, {}), Resp(200, {"info": {}}),
                     Resp(200, {"info": {"version": 12}})):
            versioncheck.httpx.get = lambda *a, **k: resp
            assert versioncheck._fetch_latest() is None, resp.status_code
        versioncheck.httpx.get = lambda *a, **k: Resp(200, {"info": {"version": "1.2.0"}})
        assert versioncheck._fetch_latest() == "1.2.0"
    finally:
        versioncheck.httpx.get = orig
    print("ok — 404 / bad JSON / missing key → None; good payload → version")


def _run_scan(argv: list[str]):
    """scan.main against a mock transport, capturing exit code/stdout/stderr."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="nope")

    orig = scan_mod.scan

    async def scan_with_transport(target, allow_private=False, services=None, log=None):
        return await orig(target, allow_private=allow_private, services=services,
                          transport=httpx.MockTransport(handler), log=log)

    scan_mod.scan = scan_with_transport
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = scan_mod.main(argv)
    finally:
        scan_mod.scan = orig
    return code, out.getvalue(), err.getvalue()


@contextlib.contextmanager
def _patched(cache: Path, fetcher):
    orig_path, orig_fetch = versioncheck.CACHE_PATH, versioncheck._fetch_latest
    versioncheck.CACHE_PATH, versioncheck._fetch_latest = cache, fetcher
    try:
        yield
    finally:
        versioncheck.CACHE_PATH = orig_path
        versioncheck._fetch_latest = orig_fetch


def test_failure_run_identical_to_disabled_run() -> None:
    with tempfile.TemporaryDirectory() as d:
        env = os.environ.copy()
        os.environ["AICHECK_NO_VERSION_CHECK"] = "1"
        try:
            code_off, out_off, _ = _run_scan(["127.0.0.2", "--allow-private"])
        finally:
            os.environ.clear()
            os.environ.update(env)

        def boom():
            raise httpx.TimeoutException("slow network")

        with _patched(_cache(d), boom):
            code_fail, out_fail, err_fail = _run_scan(["127.0.0.2", "--allow-private"])
        assert code_fail == code_off, (code_fail, code_off)
        assert out_fail == out_off
        assert "is out" not in err_fail
    print("ok — fetcher raising → same exit code and stdout as a no-check run")


def test_env_var_disables() -> None:
    with tempfile.TemporaryDirectory() as d:
        called = []
        env = os.environ.copy()
        os.environ["AICHECK_NO_VERSION_CHECK"] = "1"
        try:
            with _patched(_cache(d), lambda: called.append(1) or "9.9.9"):
                code, _out, _err = _run_scan(["127.0.0.2", "--allow-private"])
        finally:
            os.environ.clear()
            os.environ.update(env)
        assert code == 0
        assert not called
    print("ok — AICHECK_NO_VERSION_CHECK=1 → fetcher never called")


def test_flag_disables() -> None:
    with tempfile.TemporaryDirectory() as d:
        called = []
        with _patched(_cache(d), lambda: called.append(1) or "9.9.9"):
            code, _out, _err = _run_scan(
                ["127.0.0.2", "--allow-private", "--no-version-check"])
        assert code == 0
        assert not called
    print("ok — --no-version-check → fetcher never called")


def test_wrapper_prints_notice_once_to_stderr() -> None:
    with tempfile.TemporaryDirectory() as d:
        cache = _cache(d)
        # Installed package version may already be ≥ 1.2.0; mock a strictly
        # newer PyPI release so the wrapper still has something to announce.
        newer = "9.9.9"
        notice = (f"v{newer} is out — pip install -U aicheck-scan "
                  f"(release notes: https://github.com/unauthdev/aicheck-scan/releases)")
        with _patched(cache, lambda: newer):
            buf = io.StringIO()
            real_now = versioncheck.datetime

            class FakeDatetime(real_now):
                @classmethod
                def now(cls, tz=None):
                    return NOW

            versioncheck.datetime = FakeDatetime
            try:
                with contextlib.redirect_stderr(buf):
                    versioncheck.check_for_update()
            finally:
                versioncheck.datetime = real_now
        assert buf.getvalue() == notice + "\n", buf.getvalue()
        assert json.loads(cache.read_text(encoding="utf-8"))["checked"]
    print("ok — wrapper prints the single stderr line and writes the cache")


def main() -> int:
    test_newer_version_notifies_and_writes_cache()
    test_fresh_cache_is_silent()
    test_fetch_failure_silent_and_no_cache_write()
    test_older_and_equal_versions_silent()
    test_unwritable_cache_dir_silent()
    test_fetch_latest_bad_responses()
    test_failure_run_identical_to_disabled_run()
    test_env_var_disables()
    test_flag_disables()
    test_wrapper_prints_notice_once_to_stderr()
    print("all version-check tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
