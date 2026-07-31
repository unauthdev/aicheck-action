"""Unit tests for --dry-run and --verbose — run standalone: python tests/test_dryrun_verbose.py

Trust-surface guards:
- --dry-run prints the full request plan (header + sorted lines) and exits 0
  without touching recon.gather_facts or DNS — for any target string, even
  ones a real scan would reject.
- --verbose logs every outbound connection to stderr (logical URL + the
  pinned IP actually dialed) 1:1 against what the transport sends, then one
  summary line. Without --verbose there are no → GET lines.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import re
import socket
import sys
from urllib.parse import urlparse

import httpx

from aicheck import recon
from aicheck import scan as scan_mod

GET_LINE = re.compile(r"^→ GET (\S+) \(pinned (\S+)\)$")
SUMMARY = re.compile(r"^# (\d+) connections, all to (\S+) \(IPs: (.*)\)$")


def _norm(url: str) -> tuple:
    """(scheme, host, port, path) with the default port filled in — httpx may
    normalize an explicit default port out of the URL string."""
    u = urlparse(url)
    return (u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80), u.path)


def _mock_transport(recorded: list) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        recorded.append((request.method, _norm(str(request.url))))
        return httpx.Response(404, text="nope")
    return httpx.MockTransport(handler)


def _run_main_with_transport(argv: list[str], transport: httpx.MockTransport):
    """main() takes no transport kwarg, so wrap the module-level scan it
    calls — same pattern as the transport kwarg in scan() itself."""
    orig = scan_mod.scan

    async def scan_with_transport(target, allow_private=False, services=None, log=None):
        return await orig(target, allow_private=allow_private, services=services,
                          transport=transport, log=log)

    scan_mod.scan = scan_with_transport
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = scan_mod.main(argv)
    finally:
        scan_mod.scan = orig
    return code, out.getvalue(), err.getvalue()


def test_dry_run_output() -> None:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = scan_mod.main(["anything.invalid", "--dry-run"])
    assert code == 0
    lines = buf.getvalue().splitlines()
    header, urls = lines[0], lines[1:]
    n = len(recon.probe_plan())
    assert header == (
        f"# aicheck would send these {n} read-only GET requests to anything.invalid:"
    ), header
    assert len(urls) == n >= 40, len(urls)
    assert urls == sorted(urls)
    for u in urls:
        assert "anything.invalid" in u, u
        assert re.match(r"^https?://anything\.invalid:\d+/", u), u
    # the :443 aliases are https — the only TLS in the plan
    assert any(u.startswith("https://") for u in urls)
    print(f"ok — dry-run prints header + {n} sorted request lines, exit 0")


def test_dry_run_touches_nothing() -> None:
    orig_gather, orig_dns = recon.gather_facts, socket.getaddrinfo

    def boom(*a, **k):
        raise AssertionError("dry-run must not probe or resolve")

    recon.gather_facts = boom
    socket.getaddrinfo = boom
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = scan_mod.main(["anything.invalid", "--dry-run"])
    finally:
        recon.gather_facts, socket.getaddrinfo = orig_gather, orig_dns
    assert code == 0
    assert buf.getvalue().count("\n") > 40
    print("ok — dry-run never calls gather_facts or getaddrinfo")


def test_dry_run_unguarded_target() -> None:
    # 10.0.0.1 would be rejected by a real scan without --allow-private;
    # dry-run sends nothing, so there is nothing to guard.
    with contextlib.redirect_stdout(io.StringIO()):
        code = scan_mod.main(["10.0.0.1", "--dry-run"])
    assert code == 0
    print("ok — dry-run exits 0 even for targets a real scan would reject")


def test_verbose_logs_every_connection() -> None:
    recorded: list = []
    code, _out, err = _run_main_with_transport(
        ["127.0.0.2", "--allow-private", "--verbose"], _mock_transport(recorded))
    assert code in (0, 1), code
    lines = err.splitlines()
    get_lines = [l for l in lines if l.startswith("→ GET ")]
    summaries = [l for l in lines if l.startswith("# ")]

    # (a) the → GET lines are exactly what the transport sent: 1:1, same set
    from_log, pinned = [], set()
    for l in get_lines:
        m = GET_LINE.match(l)
        assert m, l
        from_log.append(("GET", _norm(m.group(1))))
        pinned.add(m.group(2))
    assert sorted(from_log) == sorted(recorded)
    assert len(get_lines) == len(recorded) == len(recon.probe_plan())

    # (b) every dialed address is in the target's pinned IP set
    assert pinned and pinned <= {"127.0.0.2"}, pinned

    # (c) one summary line with the correct N
    assert len(summaries) == 1, summaries
    m = SUMMARY.match(summaries[0])
    assert m, summaries[0]
    assert int(m.group(1)) == len(recorded)
    assert m.group(2) == "127.0.0.2"
    assert set(m.group(3).split(", ")) <= {"127.0.0.2"}
    print(f"ok — verbose logs {len(get_lines)} connections 1:1 with the transport + summary")


def test_verbose_log_shows_host_url_and_pinned_ip() -> None:
    # A hostname pinned to an IP: the log line carries the logical host URL
    # plus the IP actually dialed; the transport only ever sees the pinned IP.
    recorded, logged = [], []
    orig_dns = socket.getaddrinfo
    socket.getaddrinfo = lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    try:
        asyncio.run(scan_mod.scan(
            "example.test", allow_private=True, transport=_mock_transport(recorded),
            log=lambda method, url, ip: logged.append((method, url, ip))))
    finally:
        socket.getaddrinfo = orig_dns
    assert len(logged) == len(recorded) == len(recon.probe_plan())
    for method, url, ip in logged:
        assert method == "GET"
        assert urlparse(url).hostname == "example.test", url
        assert ip == "93.184.216.34", ip
    # the dialed URLs are the logical URLs with the pinned IP swapped in
    expect = sorted(
        (m, _norm(u.replace("://example.test", "://93.184.216.34")))
        for m, u, _ip in logged
    )
    assert sorted(recorded) == expect
    print("ok — host URL + pinned IP in the log match the dialed requests 1:1")


def test_silent_by_default() -> None:
    recorded: list = []
    code, _out, err = _run_main_with_transport(
        ["127.0.0.2", "--allow-private"], _mock_transport(recorded))
    assert code in (0, 1), code
    assert len(recorded) == len(recon.probe_plan())  # the scan did probe
    assert "→ GET" not in err
    print("ok — no → GET lines without --verbose")


def main() -> int:
    test_dry_run_output()
    test_dry_run_touches_nothing()
    test_dry_run_unguarded_target()
    test_verbose_logs_every_connection()
    test_verbose_log_shows_host_url_and_pinned_ip()
    test_silent_by_default()
    print("all dry-run/verbose tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
