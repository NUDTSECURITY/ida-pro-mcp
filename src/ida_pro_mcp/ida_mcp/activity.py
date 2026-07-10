"""Live, redacted MCP tool-call activity viewer for IDA."""

from __future__ import annotations

import json
import threading
from collections import deque
from typing import Any

import ida_kernwin

from . import trace


TITLE = "MCP Activity"
_MAX_RECORDS = 500
_MAX_ARGUMENT_CHARS = 240
_MAX_VALUE_CHARS = 96
_MAX_COLLECTION_ITEMS = 12
_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "token",
    "secret",
    "authorization",
    "cookie",
    "api_key",
    "apikey",
)

_records: deque[dict[str, Any]] = deque(maxlen=_MAX_RECORDS)
_records_lock = threading.Lock()
_viewer: "MCPActivityViewer | None" = None
_installed = False


def _is_sensitive_key(key: object) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _truncate_text(value: str, limit: int = _MAX_VALUE_CHARS) -> str:
    value = value.replace("\r", "\\r").replace("\n", "\\n")
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 3)] + "..."


def _safe_value(value: Any, *, key: object = "", depth: int = 0) -> Any:
    if key and _is_sensitive_key(key):
        return "<redacted>"
    if depth >= 4:
        return "<max-depth>"
    if isinstance(value, dict):
        result = {}
        items = list(value.items())
        for child_key, child_value in items[:_MAX_COLLECTION_ITEMS]:
            result[str(child_key)] = _safe_value(
                child_value, key=child_key, depth=depth + 1
            )
        if len(items) > _MAX_COLLECTION_ITEMS:
            result["..."] = f"{len(items) - _MAX_COLLECTION_ITEMS} more"
        return result
    if isinstance(value, (list, tuple)):
        result = [
            _safe_value(item, depth=depth + 1) for item in value[:_MAX_COLLECTION_ITEMS]
        ]
        if len(value) > _MAX_COLLECTION_ITEMS:
            result.append(f"<{len(value) - _MAX_COLLECTION_ITEMS} more>")
        return result
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    if isinstance(value, str):
        return _truncate_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _truncate_text(str(value))


def format_arguments(arguments: Any) -> str:
    """Return a compact summary suitable for an on-screen audit row."""
    try:
        text = json.dumps(
            _safe_value(arguments),
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
    except Exception:
        text = _truncate_text(str(arguments), _MAX_ARGUMENT_CHARS)
    if len(text) <= _MAX_ARGUMENT_CHARS:
        return text
    return text[: _MAX_ARGUMENT_CHARS - 3] + "..."


def format_record(record: dict[str, Any]) -> str:
    timestamp = str(record.get("ts", ""))
    if "T" in timestamp:
        timestamp = timestamp.split("T", 1)[1].removesuffix("Z")
    timestamp = timestamp[:12] or "--:--:--.---"

    failed = bool(record.get("isError") or record.get("error"))
    status = "ERROR" if failed else "OK"
    try:
        duration = float(record.get("duration_ms", 0.0))
    except (TypeError, ValueError):
        duration = 0.0
    tool_name = _truncate_text(str(record.get("tool", "<unknown>")), 40)
    arguments = format_arguments(record.get("arguments") or {})
    return f"{timestamp:<12} | {status:<5} | {duration:>9.2f} ms | {tool_name:<40} | {arguments}"


def _project_record(record: dict[str, Any]) -> dict[str, Any]:
    """Keep only bounded fields needed by the live viewer."""
    return {
        "ts": record.get("ts", ""),
        "tool": record.get("tool", "<unknown>"),
        "arguments": _safe_value(record.get("arguments") or {}),
        "duration_ms": record.get("duration_ms", 0.0),
        "isError": bool(record.get("isError")),
        "error": bool(record.get("error")),
    }


class MCPActivityViewer(ida_kernwin.simplecustviewer_t):
    """Bounded custom viewer updated from trace events on IDA's UI thread."""

    def __init__(self):
        super().__init__()
        self.closed = False

    def Create(self):
        if not super().Create(TITLE):
            return False
        self.closed = False
        self._render_snapshot()
        return True

    def _render_snapshot(self) -> None:
        self.ClearLines()
        self.AddLine(
            "UTC time     | status |  duration    | tool                                     | arguments"
        )
        self.AddLine("-" * 132)
        with _records_lock:
            records = list(_records)
        for record in records:
            self.AddLine(format_record(record))
        self.Refresh()

    def append_record(self, record: dict[str, Any]) -> None:
        if self.closed:
            return
        while self.Count() >= _MAX_RECORDS + 2:
            self.DelLine(2)
        self.AddLine(format_record(record))
        self.Refresh()
        self.Jump(max(0, self.Count() - 1))

    def OnClose(self):
        global _viewer
        self.closed = True
        if _viewer is self:
            _viewer = None


def _on_trace_record(record: dict[str, Any]) -> None:
    record_copy = _project_record(record)
    with _records_lock:
        _records.append(record_copy)

    if _viewer is None:
        return

    def append_on_ui_thread():
        viewer = _viewer
        if viewer is not None:
            viewer.append_record(record_copy)
        return False

    try:
        ida_kernwin.execute_ui_requests((append_on_ui_thread,))
    except Exception:
        pass


def install() -> None:
    """Subscribe once; records are buffered even while the viewer is closed."""
    global _installed
    if _installed or not ida_kernwin.is_idaq():
        return
    trace.subscribe(_on_trace_record)
    _installed = True


def show() -> bool:
    """Show or focus the activity viewer."""
    global _viewer
    if not ida_kernwin.is_idaq():
        return False
    install()
    if _viewer is not None and _viewer.GetWidget() is not None:
        ida_kernwin.activate_widget(_viewer.GetWidget(), True)
        return True

    viewer = MCPActivityViewer()
    if not viewer.Create():
        existing = ida_kernwin.find_widget(TITLE)
        if existing is not None:
            ida_kernwin.activate_widget(existing, True)
        return False
    _viewer = viewer
    if viewer.Show():
        return True
    _viewer = None
    try:
        viewer.Close()
    except Exception:
        pass
    return False


def shutdown() -> None:
    """Detach the observer and close the viewer before package reload."""
    global _installed, _viewer
    if _installed:
        trace.unsubscribe(_on_trace_record)
        _installed = False
    viewer = _viewer
    _viewer = None
    if viewer is not None and viewer.GetWidget() is not None:
        try:
            viewer.Close()
        except Exception:
            pass


__all__ = [
    "TITLE",
    "format_arguments",
    "format_record",
    "install",
    "show",
    "shutdown",
]
