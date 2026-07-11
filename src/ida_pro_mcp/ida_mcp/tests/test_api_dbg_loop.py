"""Tests for agent-oriented debugger event loop helpers."""

import queue
import subprocess
import time

from ..framework import test
from .. import api_dbg_loop


class _SavedAttr:
    def __init__(self, obj, name, value):
        self.obj = obj
        self.name = name
        self.value = value
        self.old = getattr(obj, name)

    def __enter__(self):
        setattr(self.obj, self.name, self.value)
        return self

    def __exit__(self, *_args):
        setattr(self.obj, self.name, self.old)


@test()
def test_dbg_loop_event_buffer_returns_events_after_cursor():
    old_seq = api_dbg_loop._EVENT_SEQ
    old_events = list(api_dbg_loop._EVENT_BUF)
    try:
        api_dbg_loop._EVENT_BUF.clear()
        api_dbg_loop._EVENT_SEQ = 0

        api_dbg_loop._emit_event("breakpoint", tid=7, ea="0x401000")
        api_dbg_loop._emit_event("exception", tid=7, ea="0x401004")

        assert api_dbg_loop._current_cursor() == 2
        assert api_dbg_loop._copy_events_after(0, 1) == [
            {
                "seq": 1,
                "time": api_dbg_loop._EVENT_BUF[0]["time"],
                "kind": "breakpoint",
                "tid": 7,
                "ea": "0x401000",
            }
        ]
        assert [event["kind"] for event in api_dbg_loop._copy_events_after(1, 10)] == [
            "exception"
        ]
    finally:
        api_dbg_loop._EVENT_BUF.clear()
        api_dbg_loop._EVENT_BUF.extend(old_events)
        api_dbg_loop._EVENT_SEQ = old_seq


@test()
def test_dbg_loop_wait_uses_nonblocking_polling():
    """_wait_for_events_after must respect timeout even when no event arrives."""
    old_seq = api_dbg_loop._EVENT_SEQ
    old_events = list(api_dbg_loop._EVENT_BUF)
    calls = []

    def wait_for_next_event(flags, timeout):
        calls.append((flags, timeout))
        return 0

    try:
        api_dbg_loop._EVENT_BUF.clear()
        api_dbg_loop._EVENT_SEQ = 0
        start = time.monotonic()
        with (
            _SavedAttr(api_dbg_loop.ida_dbg, "wait_for_next_event", wait_for_next_event),
            _SavedAttr(
                api_dbg_loop.ida_dbg,
                "get_process_state",
                lambda: api_dbg_loop.ida_dbg.DSTATE_RUN,
            ),
            _SavedAttr(api_dbg_loop, "_WAIT_POLL_INTERVAL_MS", 1),
        ):
            events = api_dbg_loop._wait_for_events_after(0, 10)
        elapsed_ms = (time.monotonic() - start) * 1000

        assert events == []
        assert calls
        assert elapsed_ms < 250
        assert all(timeout == 0 for _flags, timeout in calls)
        nowait = getattr(api_dbg_loop.ida_dbg, "WFNE_NOWAIT", 0)
        assert nowait == 0 or all(flags & nowait for flags, _timeout in calls)
    finally:
        api_dbg_loop._EVENT_BUF.clear()
        api_dbg_loop._EVENT_BUF.extend(old_events)
        api_dbg_loop._EVENT_SEQ = old_seq


@test()
def test_dbg_loop_init_is_polling_only():
    """dbg_loop_init returns the current cursor without installing debug hooks."""
    result = api_dbg_loop.dbg_loop_init()
    assert result["ok"] is True
    assert result["cursor"] == api_dbg_loop._current_cursor()
    assert not hasattr(api_dbg_loop, "_DBG_HOOKS")
    assert not hasattr(api_dbg_loop, "MCPDbgHooks")


@test()
def test_dbg_loop_cleanup_temp_breakpoints_does_not_crash():
    """_cleanup_temp_breakpoints tolerates missing debugger state."""
    old_bps = set(api_dbg_loop._TEMP_BREAKPOINTS)
    try:
        api_dbg_loop._TEMP_BREAKPOINTS.add(0xDEADBEEF)
        api_dbg_loop._cleanup_temp_breakpoints()
        assert api_dbg_loop._TEMP_BREAKPOINTS == set()
    finally:
        api_dbg_loop._TEMP_BREAKPOINTS.clear()
        api_dbg_loop._TEMP_BREAKPOINTS.update(old_bps)


@test()
def test_dbg_set_process_options_preserves_integer_port():
    current = {
        "path": "/old/program",
        "args": "--old",
        "start_dir": "/old",
        "hostname": "host",
        "password": "password",
        "port": 23946,
    }
    calls = []

    def set_process_options(*args):
        calls.append(args)

    with (
        _SavedAttr(api_dbg_loop, "_process_options", lambda: dict(current)),
        _SavedAttr(api_dbg_loop.ida_dbg, "set_process_options", set_process_options),
    ):
        api_dbg_loop.dbg_set_process_options(path="/new/program")

    assert len(calls) == 1
    assert calls[0] == (
        "/new/program",
        "--old",
        "/old",
        "host",
        "password",
        23946,
    )


@test()
def test_dbg_pty_session_read_drain_works():
    """_PtySession.read drains queued output and respects timeout."""
    proc = None
    try:
        proc = subprocess.Popen(
            ["python", "-c", "print('line1'); print('line2')"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        stdout_q = queue.Queue()
        stderr_q = queue.Queue()
        session = api_dbg_loop._PtySession(
            process=proc,
            stdout_queue=stdout_q,
            stderr_queue=stderr_q,
            path="python",
            args="",
            start_dir="",
        )
        stdout_q.put(("stdout", b"prequeued"))
        out, err, eof, code = session.read(4096, 100)
        assert out == b"prequeued"
        assert err == b""
        assert not eof
    finally:
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass
