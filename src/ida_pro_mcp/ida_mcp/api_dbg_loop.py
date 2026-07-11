"""MCP-driven debugger step/wait tools.

These tools sit above the low-level dbg_* controls. Each tool call actively
drives IDA's debugger through MCP, waits for the debugger state to change, and
returns a compact snapshot that is useful for deciding the next action.

Events are produced by MCP wait/continue calls. The implementation does not
install debugger hooks; every state transition is driven by a tool call that
waits with ``ida_dbg.wait_for_next_event`` and records the observed state.
"""

import os
import queue
import shlex
import socket
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from typing import Annotated, Literal, TypedDict

import ida_bytes
import ida_dbg
import ida_funcs
import ida_idaapi
import ida_idd
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import idaapi
import idc

from .rpc import ext, tool, unsafe
from .sync import IDAError, idasync, keep_batch, get_pre_call_batch
from .utils import Breakpoint, RegisterValue, parse_address


class DebugLoopEvent(TypedDict, total=False):
    seq: int
    time: float
    kind: str
    pid: int
    tid: int
    ea: str
    ip: str
    name: str
    base: str
    size: int
    code: int
    exc_code: str
    exc_ea: str
    exc_info: str
    can_continue: bool


class DebugLoopDisasmLine(TypedDict):
    addr: str
    text: str
    current: bool


class DebugLoopSnapshot(TypedDict, total=False):
    state: str
    ip: str
    current_thread: int
    function: str | None
    function_start: str | None
    gpregs: list[RegisterValue]
    stacktrace: list[dict[str, str]]
    breakpoints: list[Breakpoint]
    disasm: list[DebugLoopDisasmLine]
    errors: list[str]


class DebugLoopResult(TypedDict, total=False):
    status: Literal["event", "timeout"]
    cursor: int
    events: list[DebugLoopEvent]
    snapshot: DebugLoopSnapshot
    continued: bool
    started: bool


class DebugProcessOptions(TypedDict):
    path: str
    args: str
    start_dir: str
    hostname: str
    password: str
    port: int


class DebugProcessInfo(TypedDict, total=False):
    pid: int
    name: str
    addr: str
    error: str


class DebuggerInfo(TypedDict, total=False):
    name: str
    processor: str
    id: int
    flags: int
    supports_process_list: bool
    supports_attach: bool
    supports_detach: bool


class DebugDiagnosis(TypedDict, total=False):
    state: str
    debugger: DebuggerInfo | None
    process_options: DebugProcessOptions
    input_file_path: str
    resolved_input_file_path: str
    idb_path: str
    remote_tcp: dict[str, object]
    process_list: dict[str, int | str | list[DebugProcessInfo]]
    issues: list[str]
    next_steps: list[str]


class DebugModuleInfo(TypedDict, total=False):
    name: str
    base: str
    size: int
    path: str


class DebugPtySessionInfo(TypedDict, total=False):
    session_id: str
    pid: int
    path: str
    args: str
    start_dir: str
    state: str
    exit_code: int | None
    stdout_bytes: int
    stderr_bytes: int


class DebugPtyReadResult(TypedDict, total=False):
    session_id: str
    stdout: str | None
    stderr: str | None
    stdout_hex: str | None
    stderr_hex: str | None
    eof: bool
    exit_code: int | None


_EVENT_BUF: deque[DebugLoopEvent] = deque(maxlen=1000)
_EVENT_SEQ = 0
_EVENT_LOCK = threading.Lock()
_TEMP_BREAKPOINTS: set[int] = set()
_WAIT_POLL_INTERVAL_MS = 50

GENERAL_PURPOSE_REGISTERS = {
    "EAX",
    "EBX",
    "ECX",
    "EDX",
    "ESI",
    "EDI",
    "EBP",
    "ESP",
    "EIP",
    "RAX",
    "RBX",
    "RCX",
    "RDX",
    "RSI",
    "RDI",
    "RBP",
    "RSP",
    "RIP",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
}


def _hex_or_none(value: int | None) -> str | None:
    if value is None or value == ida_idaapi.BADADDR:
        return None
    return hex(value)


def _emit_event(kind: str, **kwargs) -> DebugLoopEvent:
    global _EVENT_SEQ
    with _EVENT_LOCK:
        _EVENT_SEQ += 1
        event: DebugLoopEvent = {
            "seq": _EVENT_SEQ,
            "time": time.time(),
            "kind": kind,
        }
        event.update(kwargs)
        _EVENT_BUF.append(event)
        return dict(event)


def _copy_events_after(cursor: int, limit: int) -> list[DebugLoopEvent]:
    if limit <= 0:
        return []
    with _EVENT_LOCK:
        return [dict(event) for event in _EVENT_BUF if event["seq"] > cursor][:limit]


def _current_cursor() -> int:
    with _EVENT_LOCK:
        return _EVENT_SEQ


# ============================================================================
# Batch-mode lifecycle helpers for start/attach
# ============================================================================

_DBG_START_BATCH_FALLBACK_MS = 30_000


_dbg_start_batch_restore_token = 0
_dbg_start_batch_restore_value: int | None = None


def _debugger_start_has_settled() -> bool:
    if not ida_dbg.is_debugger_on():
        return False
    state = ida_dbg.get_process_state()
    return state in (ida_dbg.DSTATE_SUSP, ida_dbg.DSTATE_RUN, ida_dbg.DSTATE_NOTASK)


def _schedule_dbg_start_batch_restore(restore_batch: int) -> None:
    """Restore batch mode after start/attach settles, using polling only."""
    global _dbg_start_batch_restore_token, _dbg_start_batch_restore_value
    if _dbg_start_batch_restore_value is not None:
        idc.batch(_dbg_start_batch_restore_value)

    _dbg_start_batch_restore_token += 1
    token = _dbg_start_batch_restore_token
    _dbg_start_batch_restore_value = restore_batch
    deadline = time.monotonic() + _DBG_START_BATCH_FALLBACK_MS / 1000.0

    def _poll():
        global _dbg_start_batch_restore_value
        if token != _dbg_start_batch_restore_token:
            return -1
        try:
            settled = _debugger_start_has_settled()
        except Exception:
            settled = False
        if settled or time.monotonic() >= deadline:
            idc.batch(restore_batch)
            if token == _dbg_start_batch_restore_token:
                _dbg_start_batch_restore_value = None
            return -1
        return 100

    ida_kernwin.register_timer(100, _poll)


# ============================================================================
# State and wait helpers
# ============================================================================


def _wait_flags() -> int:
    return ida_dbg.WFNE_ANY | ida_dbg.WFNE_SUSP | ida_dbg.WFNE_SILENT


def _poll_next_debug_event(remaining_ms: int) -> int:
    """Poll one debugger event without letting debugger plugins overrun our deadline."""
    nowait = getattr(ida_dbg, "WFNE_NOWAIT", 0)
    wait_result = ida_dbg.wait_for_next_event(
        _wait_flags() | nowait,
        0,
    )
    if wait_result and wait_result > 0:
        return wait_result

    sleep_ms = min(_WAIT_POLL_INTERVAL_MS, max(remaining_ms, 0))
    if sleep_ms > 0:
        time.sleep(sleep_ms / 1000.0)
    return wait_result


def _debug_event_kind() -> str:
    state = _process_state_name()
    if state == "suspended":
        return "suspend"
    if state == "running":
        return "running"
    if state == "not_running":
        return "not_running"
    return "debug_event"


def _process_state_name() -> str:
    if not ida_dbg.is_debugger_on():
        return "not_running"
    state = ida_dbg.get_process_state()
    if state == ida_dbg.DSTATE_SUSP:
        return "suspended"
    if state == ida_dbg.DSTATE_RUN:
        return "running"
    if state == ida_dbg.DSTATE_NOTASK:
        return "not_running"
    return f"unknown({state})"


def _debug_state_result() -> dict[str, str | bool]:
    state = _process_state_name()
    result: dict[str, str | bool] = {"state": state}
    if state == "running":
        result["running"] = True
    elif state == "suspended":
        result["suspended"] = True
        ip = _hex_or_none(ida_dbg.get_ip_val())
        if ip is not None:
            result["ip"] = ip
    return result


def _ensure_debugger_active() -> "ida_idd.debugger_t":
    dbg = ida_idd.get_dbg()
    if not dbg or not ida_dbg.is_debugger_on():
        raise IDAError("Debugger is not running")
    return dbg


def _ensure_debugger_suspended() -> "ida_idd.debugger_t":
    dbg = _ensure_debugger_active()
    if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
        raise IDAError("Debugger is running; wait until it suspends before inspecting state")
    return dbg


def _get_gp_registers_for_thread(dbg: "ida_idd.debugger_t", tid: int) -> list[RegisterValue]:
    regs = []
    regvals: ida_idd.regvals_t = ida_dbg.get_reg_vals(tid)
    for reg_index, rv in enumerate(regvals):
        reg_info = dbg.regs(reg_index)
        if reg_info.name not in GENERAL_PURPOSE_REGISTERS:
            continue
        try:
            value = rv.pyval(reg_info.dtype)
        except ValueError:
            value = ida_idaapi.BADADDR
        if isinstance(value, int):
            text = hex(value)
        elif isinstance(value, bytes):
            text = value.hex(" ")
        else:
            text = str(value)
        regs.append(RegisterValue(name=reg_info.name, value=text))
    return regs


def _breakpoint_language(bpt: ida_dbg.bpt_t) -> str | None:
    language = getattr(bpt, "elang", None)
    if language is None:
        return None
    text = str(language).strip()
    return text or None


def _list_breakpoints() -> list[Breakpoint]:
    breakpoints: list[Breakpoint] = []
    for index in range(ida_dbg.get_bpt_qty()):
        bpt = ida_dbg.bpt_t()
        if ida_dbg.getn_bpt(index, bpt):
            breakpoints.append(
                Breakpoint(
                    addr=hex(bpt.ea),
                    enabled=bool(bpt.flags & ida_dbg.BPT_ENABLED),
                    condition=str(bpt.condition) if bpt.condition else None,
                    language=_breakpoint_language(bpt),
                )
            )
    return breakpoints


def _has_breakpoint(ea: int) -> bool:
    for index in range(ida_dbg.get_bpt_qty()):
        bpt = ida_dbg.bpt_t()
        if ida_dbg.getn_bpt(index, bpt) and bpt.ea == ea:
            return True
    return False


def _stacktrace() -> list[dict[str, str]]:
    callstack = []
    try:
        tid = ida_dbg.get_current_thread()
        trace = ida_idd.call_stack_t()
        if not ida_dbg.collect_stack_trace(tid, trace):
            return []
        for frame in trace:
            frame_info = {"addr": hex(frame.callea)}
            try:
                module_info = ida_idd.modinfo_t()
                if ida_dbg.get_module_info(frame.callea, module_info):
                    frame_info["module"] = os.path.basename(module_info.name)
                else:
                    frame_info["module"] = "<unknown>"
                frame_info["symbol"] = (
                    ida_name.get_nice_colored_name(
                        frame.callea,
                        ida_name.GNCN_NOCOLOR
                        | ida_name.GNCN_NOLABEL
                        | ida_name.GNCN_NOSEG
                        | ida_name.GNCN_PREFDBG,
                    )
                    or "<unnamed>"
                )
            except Exception as exc:
                frame_info["module"] = "<error>"
                frame_info["symbol"] = str(exc)
            callstack.append(frame_info)
    except Exception:
        pass
    return callstack


def _record_wait_event(wait_result: int) -> DebugLoopEvent:
    kwargs: dict[str, object] = {"code": int(wait_result)}
    ip = _hex_or_none(ida_dbg.get_ip_val())
    if ip is not None:
        kwargs["ip"] = ip
    try:
        tid = ida_dbg.get_current_thread()
        if tid is not None:
            kwargs["tid"] = tid
    except Exception:
        pass
    return _emit_event(_debug_event_kind(), **kwargs)


def _wait_for_events_after(cursor: int, timeout_ms: int) -> list[DebugLoopEvent]:
    deadline = time.monotonic() + max(timeout_ms, 0) / 1000.0
    while True:
        events = _copy_events_after(cursor, 100)
        if events and ida_dbg.get_process_state() != ida_dbg.DSTATE_RUN:
            return events

        if timeout_ms <= 0 or time.monotonic() >= deadline:
            return events

        remaining_ms = int((deadline - time.monotonic()) * 1000)
        if remaining_ms <= 0:
            return events
        wait_result = _poll_next_debug_event(remaining_ms)
        events = _copy_events_after(cursor, 100)
        if events and ida_dbg.get_process_state() != ida_dbg.DSTATE_RUN:
            return events
        if wait_result and wait_result > 0:
            _record_wait_event(wait_result)
            if ida_dbg.get_process_state() != ida_dbg.DSTATE_RUN:
                return _copy_events_after(cursor, 100)


def _wait_for_debugger_state_change(timeout_ms: int) -> list[DebugLoopEvent]:
    cursor = _current_cursor()
    deadline = time.monotonic() + max(timeout_ms, 0) / 1000.0
    while True:
        if ida_dbg.is_debugger_on():
            state = ida_dbg.get_process_state()
            if state in (ida_dbg.DSTATE_SUSP, ida_dbg.DSTATE_RUN):
                _record_wait_event(1)
                return _copy_events_after(cursor, 100)

        if timeout_ms <= 0 or time.monotonic() >= deadline:
            return []

        remaining_ms = int((deadline - time.monotonic()) * 1000)
        if remaining_ms <= 0:
            return []
        wait_result = _poll_next_debug_event(remaining_ms)
        if wait_result and wait_result > 0:
            _record_wait_event(wait_result)
            return _copy_events_after(cursor, 100)


# ============================================================================
# Process options, diagnosis, and process listing
# ============================================================================


def _process_options() -> DebugProcessOptions:
    path, args, start_dir, hostname, password, port = ida_dbg.get_process_options()
    return {
        "path": path or "",
        "args": args or "",
        "start_dir": start_dir or "",
        "hostname": hostname or "",
        "password": password or "",
        "port": int(port or 0),
    }


def _debugger_info() -> DebuggerInfo | None:
    dbg = ida_idd.get_dbg()
    if not dbg:
        return None
    info: DebuggerInfo = {}
    for attr in ("name", "processor", "id", "flags"):
        try:
            value = getattr(dbg, attr)
            info[attr] = value() if callable(value) else value
        except Exception:
            pass
    flags = int(info.get("flags", 0) or 0)
    info["supports_process_list"] = bool(flags & ida_idd.DBG_HAS_GET_PROCESSES)
    info["supports_attach"] = bool(flags & ida_idd.DBG_HAS_ATTACH_PROCESS)
    info["supports_detach"] = bool(flags & ida_idd.DBG_HAS_DETACH_PROCESS)
    return info


def _check_remote_tcp(hostname: str, port: int, timeout_ms: int) -> dict[str, object]:
    result: dict[str, object] = {
        "hostname": hostname,
        "port": port,
        "checked": False,
        "ok": False,
    }
    if not hostname or not port or timeout_ms <= 0:
        return result

    result["checked"] = True
    sock = socket.socket()
    sock.settimeout(timeout_ms / 1000.0)
    try:
        sock.connect((hostname, port))
        result["ok"] = True
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()
    return result


def _option_value(value: str | int | None, current: str | int) -> str | int | None:
    if value is None:
        return None
    if isinstance(value, str) and value == "":
        return current
    return value


def _current_file_candidate() -> str:
    input_path = ida_nalt.get_input_file_path() or ida_nalt.get_root_filename() or ""
    if os.path.isabs(input_path) and os.path.exists(input_path):
        return input_path

    idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
    if idb_path:
        candidate = os.path.join(os.path.dirname(idb_path), input_path)
        if os.path.exists(candidate):
            return candidate

    return input_path


def _list_processes_result() -> dict[str, int | str | list[DebugProcessInfo]]:
    processes = ida_idd.procinfo_vec_t()
    count = ida_dbg.get_processes(processes)
    if count < 0:
        return {"count": -1, "processes": [], "error": "Failed to list debugger processes"}
    return {
        "count": int(count),
        "processes": [_process_info_to_dict(proc) for proc in processes],
    }


def _process_info_to_dict(info) -> DebugProcessInfo:
    item: DebugProcessInfo = {}
    for attr in ("pid", "name"):
        try:
            value = getattr(info, attr)
            item[attr] = value() if callable(value) else value
        except Exception:
            pass
    for attr in ("addr", "start_ea", "ea"):
        try:
            value = getattr(info, attr)
            value = value() if callable(value) else value
            if isinstance(value, int):
                item["addr"] = hex(value)
                break
        except Exception:
            pass
    return item


def _list_modules_result() -> list[DebugModuleInfo]:
    modules: list[DebugModuleInfo] = []
    module_info = ida_idd.modinfo_t()
    if not ida_dbg.get_first_module(module_info):
        return modules
    while True:
        item: DebugModuleInfo = {}
        for attr in ("name", "path"):
            try:
                value = getattr(module_info, attr)
                item[attr] = str(value() if callable(value) else value)
            except Exception:
                pass
        for attr in ("base", "start_ea"):
            try:
                value = getattr(module_info, attr)
                value = value() if callable(value) else value
                if isinstance(value, int):
                    item["base"] = hex(value)
                    break
            except Exception:
                pass
        for attr in ("size",):
            try:
                value = getattr(module_info, attr)
                item[attr] = int(value() if callable(value) else value)
            except Exception:
                pass
        modules.append(item)
        if not ida_dbg.get_next_module(module_info):
            break
    return modules


def _start_process_until_event(
    path: str = "",
    args: str = "",
    start_dir: str = "",
    timeout_ms: int = 10000,
) -> DebugLoopResult:
    cursor = _current_cursor()
    pre_call_batch = get_pre_call_batch()
    if pre_call_batch is None:
        pre_call_batch = 0
    _schedule_dbg_start_batch_restore(restore_batch=pre_call_batch)

    result = ida_dbg.start_process(path or None, args or None, start_dir or None)
    if result == 0:
        raise IDAError("Debugger start was cancelled")
    if result < 0:
        raise IDAError("Failed to start debugger process")

    events = _wait_for_debugger_state_change(timeout_ms)
    status: Literal["event", "timeout"] = "event" if events else "timeout"
    return {
        "status": status,
        "started": True,
        "cursor": _current_cursor(),
        "events": events or _copy_events_after(cursor, 100),
        "snapshot": _debug_snapshot(),
    }


def _attach_process_until_event(
    pid: int,
    event_id: int = ida_idd.PROCESS_ATTACHED,
    timeout_ms: int = 10000,
) -> DebugLoopResult:
    cursor = _current_cursor()
    pre_call_batch = get_pre_call_batch()
    if pre_call_batch is None:
        pre_call_batch = 0
    _schedule_dbg_start_batch_restore(restore_batch=pre_call_batch)

    result = ida_dbg.attach_process(pid, event_id)
    if result == 0:
        raise IDAError("Debugger attach was cancelled")
    if result < 0:
        raise IDAError(f"Failed to attach debugger process: {result}")

    events = _wait_for_debugger_state_change(timeout_ms)
    status: Literal["event", "timeout"] = "event" if events else "timeout"
    return {
        "status": status,
        "started": True,
        "cursor": _current_cursor(),
        "events": events or _copy_events_after(cursor, 100),
        "snapshot": _debug_snapshot(),
    }


def _disasm_context(ip: int, radius: int) -> list[DebugLoopDisasmLine]:
    if ip == ida_idaapi.BADADDR:
        return []

    addrs = []
    ea = ip
    for _ in range(max(radius, 0)):
        prev = ida_bytes.prev_head(ea, 0)
        if prev == ida_idaapi.BADADDR or prev == ea:
            break
        addrs.insert(0, prev)
        ea = prev

    addrs.append(ip)
    ea = ip
    for _ in range(max(radius, 0)):
        nxt = ida_bytes.next_head(ea, ida_idaapi.BADADDR)
        if nxt == ida_idaapi.BADADDR or nxt == ea:
            break
        addrs.append(nxt)
        ea = nxt

    result: list[DebugLoopDisasmLine] = []
    for item_ea in addrs:
        line = ida_lines.generate_disasm_line(item_ea, 0)
        text = ida_lines.tag_remove(line) if line else ""
        result.append({"addr": hex(item_ea), "text": text, "current": item_ea == ip})
    return result


# ============================================================================
# MCP tools
# ============================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_loop_init() -> dict[str, int | bool]:
    """Initialize MCP-driven debugger polling and return the event cursor."""
    return {"ok": True, "cursor": _current_cursor()}


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_get_events(
    cursor: Annotated[int, "Return events with seq greater than this cursor"] = 0,
    limit: Annotated[int, "Maximum events to return"] = 50,
) -> dict[str, int | list[DebugLoopEvent]]:
    """Return debugger events produced by prior MCP wait/continue calls."""
    events = _copy_events_after(cursor, min(max(limit, 0), 200))
    return {"cursor": _current_cursor(), "events": events}


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_get_process_options() -> DebugProcessOptions:
    """Return IDA debugger process options used by MCP-driven starts."""
    return _process_options()


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_set_process_options(
    path: Annotated[str, "Executable path. Empty preserves current value."] = "",
    args: Annotated[str, "Process arguments. Empty preserves current value."] = "",
    start_dir: Annotated[str, "Working directory. Empty preserves current value."] = "",
    hostname: Annotated[str, "Remote debugger hostname. Empty preserves current value."] = "",
    password: Annotated[str, "Remote debugger password. Empty preserves current value."] = "",
    port: Annotated[int, "Remote debugger port. 0 preserves current value."] = 0,
) -> DebugProcessOptions:
    """Set IDA debugger process options through MCP and return the result."""
    current = _process_options()
    ida_dbg.set_process_options(
        _option_value(path, current["path"]),
        _option_value(args, current["args"]),
        _option_value(start_dir, current["start_dir"]),
        _option_value(hostname, current["hostname"]),
        _option_value(password, current["password"]),
        port if port != 0 else current["port"],
    )
    return _process_options()


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_list_processes() -> dict[str, int | str | list[DebugProcessInfo]]:
    """List processes visible to the selected debugger through MCP."""
    return _list_processes_result()


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_resolve(
    name: Annotated[str, "Symbol or hex address to resolve (e.g., 'edit_buffer', '0x401000')"],
) -> dict[str, str]:
    """Resolve a symbol or address in the debugger address space.

    Useful for confirming that a function from a loaded shared library (e.g.
    ``edit_buffer`` in ``libggml.so``) is visible to IDA before setting a
    breakpoint on it.
    """
    ea = parse_address(name)
    return {"input": name, "addr": hex(ea)}


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_modules() -> list[DebugModuleInfo]:
    """List modules loaded in the debuggee process with base addresses."""
    _ensure_debugger_active()
    return _list_modules_result()


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_diagnose(
    include_process_list: Annotated[
        bool, "Also ask the debugger for visible processes. Can block if remote server is unreachable."
    ] = False,
    tcp_timeout_ms: Annotated[
        int, "Remote TCP check timeout in milliseconds. Use 0 to skip."
    ] = 1000,
) -> DebugDiagnosis:
    """Diagnose MCP-driven debugger readiness without starting or attaching."""
    options = _process_options()
    input_path = ida_nalt.get_input_file_path() or ""
    resolved = _current_file_candidate()
    idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB) or ""
    debugger = _debugger_info()
    state = _process_state_name()
    issues: list[str] = []
    next_steps: list[str] = []

    if debugger is None:
        issues.append("No debugger is selected")
        next_steps.append("Select a debugger in IDA, then call dbg_diagnose again")

    if state == "not_running":
        next_steps.append("Call dbg_start_process_until_event or dbg_attach_process_until_event after process options are valid")

    remote_tcp = _check_remote_tcp(options["hostname"], options["port"], tcp_timeout_ms)

    if options["hostname"] and options["port"]:
        if remote_tcp.get("checked") and not remote_tcp.get("ok"):
            issues.append(str(remote_tcp.get("error", "Remote debugger TCP check failed")))
            next_steps.append(
                f"Ensure the remote debugger server is reachable at {options['hostname']}:{options['port']}"
            )
        elif not remote_tcp.get("checked"):
            next_steps.append(
                f"Remote debugger TCP check was skipped for {options['hostname']}:{options['port']}"
            )

    if options["path"] and os.path.isabs(options["path"]) and options["hostname"]:
        issues.append("Process path is local absolute while a remote debugger host is configured")
        next_steps.append("For remote Linux debugging, set path to the remote executable path or attach to an existing PID")

    if resolved and os.path.isabs(resolved) and not os.path.exists(resolved):
        issues.append(f"Resolved input file does not exist locally: {resolved}")

    diagnosis: DebugDiagnosis = {
        "state": state,
        "debugger": debugger,
        "process_options": options,
        "input_file_path": input_path,
        "resolved_input_file_path": resolved,
        "idb_path": idb_path,
        "remote_tcp": remote_tcp,
        "issues": issues,
        "next_steps": next_steps,
    }

    if include_process_list:
        process_list = _list_processes_result()
        diagnosis["process_list"] = process_list
        if int(process_list.get("count", 0)) < 0:
            issues.append(str(process_list.get("error", "Failed to list debugger processes")))

    return diagnosis


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_wait_event(
    cursor: Annotated[int, "Wait for events with seq greater than this cursor"] = 0,
    timeout_ms: Annotated[int, "Maximum wait in milliseconds"] = 5000,
) -> DebugLoopResult:
    """Wait for the next debugger event without resuming execution."""
    _ensure_debugger_active()
    events = _wait_for_events_after(cursor, timeout_ms)
    status: Literal["event", "timeout"] = "event" if events else "timeout"
    return {
        "status": status,
        "cursor": _current_cursor(),
        "events": events,
        "snapshot": _debug_snapshot(),
    }


@ext("dbg")
@unsafe
@tool
@idasync
@keep_batch
def dbg_start_process_until_event(
    path: Annotated[str, "Executable path. Empty uses current process options."] = "",
    args: Annotated[str, "Process arguments. Empty uses current process options."] = "",
    start_dir: Annotated[str, "Working directory. Empty uses current process options."] = "",
    timeout_ms: Annotated[int, "Maximum wait in milliseconds"] = 10000,
) -> DebugLoopResult:
    """Start the configured debugger process via MCP and wait for state/event."""
    return _start_process_until_event(path, args, start_dir, timeout_ms)


@ext("dbg")
@unsafe
@tool
@idasync
@keep_batch
def dbg_start_current_file_until_event(
    timeout_ms: Annotated[int, "Maximum wait in milliseconds"] = 10000,
) -> DebugLoopResult:
    """Start the currently loaded input file via MCP and wait for state/event."""
    path = _current_file_candidate()
    if not path:
        raise IDAError("Could not resolve current input file path")
    start_dir = os.path.dirname(path) if os.path.isabs(path) else ""
    return _start_process_until_event(path, "", start_dir, timeout_ms)


@ext("dbg")
@unsafe
@tool
@idasync
@keep_batch
def dbg_attach_process_until_event(
    pid: Annotated[int, "Process ID to attach to"],
    timeout_ms: Annotated[int, "Maximum wait in milliseconds"] = 10000,
) -> DebugLoopResult:
    """Attach to a running process through MCP and wait for debugger state/event."""
    return _attach_process_until_event(pid=pid, timeout_ms=timeout_ms)


def _debug_snapshot(
    disasm_radius: int = 4,
    include_registers: bool = True,
    include_stack: bool = True,
) -> DebugLoopSnapshot:
    state = _debug_state_result()
    snapshot: DebugLoopSnapshot = {
        "state": state.get("state", "unknown"),
        "breakpoints": _list_breakpoints(),
        "errors": [],
    }
    if "ip" in state:
        snapshot["ip"] = state["ip"]

    if not ida_dbg.is_debugger_on():
        return snapshot

    if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
        return snapshot

    try:
        current_thread = ida_dbg.get_current_thread()
        snapshot["current_thread"] = current_thread
    except Exception as exc:
        snapshot["errors"].append(f"current_thread: {exc}")
        current_thread = None

    ip = ida_dbg.get_ip_val()
    if ip is not None and ip != ida_idaapi.BADADDR:
        snapshot["ip"] = hex(ip)
        func = ida_funcs.get_func(ip)
        if func is not None:
            snapshot["function_start"] = hex(func.start_ea)
            snapshot["function"] = ida_funcs.get_func_name(func.start_ea)
        else:
            snapshot["function_start"] = None
            snapshot["function"] = None
        snapshot["disasm"] = _disasm_context(ip, disasm_radius)

    if include_registers and current_thread is not None:
        try:
            dbg = _ensure_debugger_suspended()
            snapshot["gpregs"] = _get_gp_registers_for_thread(dbg, current_thread)
        except Exception as exc:
            snapshot["errors"].append(f"gpregs: {exc}")

    if include_stack:
        try:
            snapshot["stacktrace"] = _stacktrace()
        except Exception as exc:
            snapshot["errors"].append(f"stacktrace: {exc}")

    return snapshot


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_get_snapshot(
    disasm_radius: Annotated[int, "Instruction radius around current IP"] = 4,
    include_registers: Annotated[bool, "Include current thread GP registers"] = True,
    include_stack: Annotated[bool, "Include current call stack"] = True,
) -> DebugLoopSnapshot:
    """Return an agent-friendly snapshot of the current debugger state."""
    _ensure_debugger_active()
    return _debug_snapshot(
        disasm_radius=max(0, min(disasm_radius, 20)),
        include_registers=include_registers,
        include_stack=include_stack,
    )


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_continue_until_event(
    timeout_ms: Annotated[int, "Maximum wait in milliseconds"] = 5000,
) -> DebugLoopResult:
    """Resume execution and wait for the next debugger event or timeout."""
    _ensure_debugger_suspended()
    return _continue_until_event(timeout_ms)


def _continue_until_event(timeout_ms: int) -> DebugLoopResult:
    cursor = _current_cursor()
    if not idaapi.continue_process():
        raise IDAError("Failed to continue debugger")

    events = _wait_for_events_after(cursor, timeout_ms)
    status: Literal["event", "timeout"] = "event" if events else "timeout"
    return {
        "status": status,
        "continued": True,
        "cursor": _current_cursor(),
        "events": events,
        "snapshot": _debug_snapshot(),
    }


def _cleanup_temp_breakpoints() -> None:
    """Remove all breakpoints tracked as temporary by the debug loop."""
    global _TEMP_BREAKPOINTS
    for ea in list(_TEMP_BREAKPOINTS):
        try:
            ida_dbg.del_bpt(ea)
        except Exception:
            pass
    _TEMP_BREAKPOINTS.clear()


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_add_temp_bp_and_continue(
    addr: Annotated[str, "Temporary breakpoint address (hex, decimal, or symbol)"],
    timeout_ms: Annotated[int, "Maximum wait in milliseconds"] = 5000,
) -> DebugLoopResult:
    """Set a one-shot breakpoint, resume execution, and wait for an event."""
    _ensure_debugger_suspended()
    ea = parse_address(addr)
    created = False
    if not _has_breakpoint(ea):
        if not idaapi.add_bpt(ea, 0, idaapi.BPT_SOFT):
            raise IDAError(f"Failed to add temporary breakpoint at {hex(ea)}")
        created = True
        _TEMP_BREAKPOINTS.add(ea)

    try:
        result = _continue_until_event(timeout_ms)
    finally:
        if created:
            _TEMP_BREAKPOINTS.discard(ea)
            try:
                ida_dbg.del_bpt(ea)
            except Exception:
                pass
    return result


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_read_around(
    addr: Annotated[str, "Center address (hex, decimal, or symbol)"],
    radius: Annotated[int, "Bytes to read before and after addr"] = 64,
) -> list[dict[str, object]]:
    """Read debuggee memory around an address as hex/ASCII chunks.

    Useful for quickly inspecting a buffer pointed to by a register or a
    structure field without first computing exact start/end offsets.
    """
    _ensure_debugger_active()
    ea = parse_address(addr)
    radius = max(0, min(radius, 4096))

    results = []
    for region in [(ea - radius, radius), (ea, radius)]:
        start, size = region
        if start < 0:
            start = 0
            size = ea
        if size <= 0:
            continue
        data = idaapi.dbg_read_memory(start, size)
        if not data:
            continue
        results.append({
            "addr": hex(start),
            "size": len(data),
            "data": data.hex(),
            "ascii": repr(data),
        })
    return results


# ============================================================================
# Interactive CLI I/O controller
# ============================================================================


class _PtySession:
    def __init__(
        self,
        process: subprocess.Popen,
        stdout_queue: "queue.Queue[tuple[str, bytes]]",
        stderr_queue: "queue.Queue[tuple[str, bytes]]",
        path: str,
        args: str,
        start_dir: str,
    ):
        self.process = process
        self.stdout_queue = stdout_queue
        self.stderr_queue = stderr_queue
        self.path = path
        self.args = args
        self.start_dir = start_dir
        self.stdout_bytes = 0
        self.stderr_bytes = 0
        self.closed = False
        self._threads: list[threading.Thread] = []

    def _drain(self, q: "queue.Queue[tuple[str, bytes]]", max_bytes: int) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while total < max_bytes:
            try:
                _stream, data = q.get_nowait()
            except queue.Empty:
                break
            if total + len(data) > max_bytes:
                data = data[: max_bytes - total]
            chunks.append(data)
            total += len(data)
        return b"".join(chunks)

    def read(
        self, max_bytes: int, timeout_ms: int
    ) -> tuple[bytes, bytes, bool, int | None]:
        deadline = time.monotonic() + max(timeout_ms, 0) / 1000.0
        while True:
            stdout = self._drain(self.stdout_queue, max_bytes)
            stderr = self._drain(self.stderr_queue, max_bytes)
            if stdout or stderr:
                self.stdout_bytes += len(stdout)
                self.stderr_bytes += len(stderr)
                return (
                    stdout,
                    stderr,
                    self.process.poll() is not None,
                    self.process.returncode,
                )

            if self.process.poll() is not None:
                # Process exited; drain remaining bytes without timeout
                stdout = self._drain(self.stdout_queue, max_bytes)
                stderr = self._drain(self.stderr_queue, max_bytes)
                self.stdout_bytes += len(stdout)
                self.stderr_bytes += len(stderr)
                return stdout, stderr, True, self.process.returncode

            if time.monotonic() >= deadline:
                return b"", b"", False, None

            time.sleep(min(0.05, max(0, deadline - time.monotonic())))

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.process.stdin.close()
        except Exception:
            pass
        try:
            self.process.terminate()
        except Exception:
            pass


_PTY_SESSIONS: dict[str, _PtySession] = {}
_PTY_LOCK = threading.Lock()


def _read_stream_to_queue(
    stream, q: "queue.Queue[tuple[str, bytes]]", stream_name: str
) -> None:
    try:
        while True:
            data = stream.read(4096)
            if not data:
                break
            q.put((stream_name, data))
    except Exception:
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass


def _cleanup_pty_session(session_id: str) -> None:
    with _PTY_LOCK:
        session = _PTY_SESSIONS.pop(session_id, None)
    if session is not None:
        session.close()


def _pty_session_info(session: _PtySession, session_id: str) -> DebugPtySessionInfo:
    poll = session.process.poll()
    state = "exited" if poll is not None else "running"
    return {
        "session_id": session_id,
        "pid": session.process.pid,
        "path": session.path,
        "args": session.args,
        "start_dir": session.start_dir,
        "state": state,
        "exit_code": session.process.returncode,
        "stdout_bytes": session.stdout_bytes,
        "stderr_bytes": session.stderr_bytes,
    }


@ext("dbg")
@unsafe
@tool
def dbg_pty_start(
    path: Annotated[str, "Executable path"],
    args: Annotated[str, "Process arguments"] = "",
    start_dir: Annotated[str, "Working directory. Empty uses executable directory."] = "",
) -> DebugPtySessionInfo:
    """Start an interactive CLI process and capture its stdin/stdout/stderr.

    Returns a session ID and PID. You can then attach IDA's debugger to the
    returned PID while using dbg_pty_send / dbg_pty_read to drive the CLI.
    """
    if not os.path.exists(path):
        raise IDAError(f"Executable not found: {path}")

    cmd = [path]
    if args:
        if sys.platform == "win32":
            # Windows: shlex posix mode eats backslashes; use non-posix and
            # strip surrounding quotes so quoted arguments still work.
            parts = shlex.split(args, posix=False)
            parts = [p[1:-1] if len(p) >= 2 and p[0] == p[-1] == '"' else p for p in parts]
            cmd.extend(parts)
        else:
            cmd.extend(shlex.split(args))

    cwd = start_dir or os.path.dirname(path) or None

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            bufsize=0,
        )
    except Exception as exc:
        raise IDAError(f"Failed to start process: {exc}") from exc

    stdout_q: "queue.Queue[tuple[str, bytes]]" = queue.Queue()
    stderr_q: "queue.Queue[tuple[str, bytes]]" = queue.Queue()
    session = _PtySession(
        process=proc,
        stdout_queue=stdout_q,
        stderr_queue=stderr_q,
        path=path,
        args=args,
        start_dir=start_dir,
    )

    stdout_thread = threading.Thread(
        target=_read_stream_to_queue,
        args=(proc.stdout, stdout_q, "stdout"),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_read_stream_to_queue,
        args=(proc.stderr, stderr_q, "stderr"),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    session._threads = [stdout_thread, stderr_thread]

    session_id = uuid.uuid4().hex
    with _PTY_LOCK:
        _PTY_SESSIONS[session_id] = session

    return _pty_session_info(session, session_id)


@ext("dbg")
@unsafe
@tool
def dbg_pty_send(
    session_id: Annotated[str, "PTY session ID returned by dbg_pty_start"],
    data: Annotated[str, "Data to send to stdin"],
    is_hex: Annotated[bool, "If true, decode data from hex first"] = False,
) -> dict[str, int | bool]:
    """Send data to the stdin of a process started by dbg_pty_start."""
    with _PTY_LOCK:
        session = _PTY_SESSIONS.get(session_id)
    if session is None:
        raise IDAError(f"PTY session not found: {session_id}")

    if session.process.poll() is not None:
        raise IDAError("Process has already exited")

    try:
        payload = bytes.fromhex(data) if is_hex else data.encode("utf-8", errors="replace")
        session.process.stdin.write(payload)
        session.process.stdin.flush()
    except Exception as exc:
        raise IDAError(f"Failed to send input: {exc}") from exc

    return {"ok": True, "bytes_sent": len(payload)}


@ext("dbg")
@unsafe
@tool
def dbg_pty_read(
    session_id: Annotated[str, "PTY session ID returned by dbg_pty_start"],
    max_bytes: Annotated[int, "Maximum bytes to read per stream"] = 4096,
    timeout_ms: Annotated[int, "Maximum wait in milliseconds"] = 1000,
    separate_streams: Annotated[bool, "Return stdout and stderr separately"] = True,
    encode: Annotated[bool, "Also include UTF-8 text decode of output"] = True,
) -> DebugPtyReadResult:
    """Read stdout/stderr from a process started by dbg_pty_start."""
    with _PTY_LOCK:
        session = _PTY_SESSIONS.get(session_id)
    if session is None:
        raise IDAError(f"PTY session not found: {session_id}")

    stdout, stderr, eof, exit_code = session.read(
        max_bytes=max(0, min(max_bytes, 65536)),
        timeout_ms=timeout_ms,
    )

    result: DebugPtyReadResult = {
        "session_id": session_id,
        "eof": eof,
    }
    if separate_streams:
        result["stdout_hex"] = stdout.hex() if stdout else None
        result["stderr_hex"] = stderr.hex() if stderr else None
        if encode:
            result["stdout"] = stdout.decode("utf-8", errors="replace") if stdout else None
            result["stderr"] = stderr.decode("utf-8", errors="replace") if stderr else None
    else:
        combined = stdout + stderr
        result["stdout_hex"] = combined.hex() if combined else None
        if encode:
            result["stdout"] = combined.decode("utf-8", errors="replace") if combined else None
    if exit_code is not None:
        result["exit_code"] = exit_code

    return result


@ext("dbg")
@unsafe
@tool
def dbg_pty_list() -> list[DebugPtySessionInfo]:
    """List active CLI sessions started by dbg_pty_start."""
    with _PTY_LOCK:
        return [_pty_session_info(s, sid) for sid, s in _PTY_SESSIONS.items()]


@ext("dbg")
@unsafe
@tool
def dbg_pty_close(
    session_id: Annotated[str, "PTY session ID returned by dbg_pty_start"],
) -> DebugPtySessionInfo:
    """Close a CLI session and terminate its process."""
    with _PTY_LOCK:
        session = _PTY_SESSIONS.get(session_id)
    if session is None:
        raise IDAError(f"PTY session not found: {session_id}")

    info = _pty_session_info(session, session_id)
    session.close()
    with _PTY_LOCK:
        _PTY_SESSIONS.pop(session_id, None)
    return info
