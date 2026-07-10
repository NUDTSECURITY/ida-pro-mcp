"""Tests for the IDA MCP live activity formatter."""

from .. import activity
from ..framework import test


@test()
def test_activity_redacts_sensitive_arguments():
    summary = activity.format_arguments(
        {
            "path": "/tmp/rpc-server",
            "password": "open-sesame",
            "nested": {"access_token": "token-value"},
        }
    )

    assert "/tmp/rpc-server" in summary
    assert "open-sesame" not in summary
    assert "token-value" not in summary
    assert summary.count("<redacted>") == 2


@test()
def test_activity_argument_summary_is_bounded_and_single_line():
    summary = activity.format_arguments({"code": "line1\n" + "A" * 400})

    assert len(summary) <= activity._MAX_ARGUMENT_CHARS
    assert "\n" not in summary
    assert "\\n" in summary
    assert "..." in summary


@test()
def test_activity_record_contains_operational_fields():
    line = activity.format_record(
        {
            "ts": "2026-07-10T12:34:56.789Z",
            "tool": "dbg_continue_until_event",
            "arguments": {"timeout_ms": 5000},
            "duration_ms": 125.25,
            "isError": False,
        }
    )

    assert "12:34:56.789" in line
    assert "OK" in line
    assert "125.25 ms" in line
    assert "dbg_continue_until_event" in line
    assert '"timeout_ms":5000' in line


@test()
def test_activity_record_marks_errors():
    line = activity.format_record(
        {
            "ts": "2026-07-10T12:34:56.789Z",
            "tool": "dbg_start_process_until_event",
            "arguments": {},
            "duration_ms": 10,
            "error": "IDAError: failed",
        }
    )

    assert "ERROR" in line


@test()
def test_activity_projection_discards_results_and_redacts_arguments():
    projected = activity._project_record(
        {
            "ts": "2026-07-10T12:34:56.789Z",
            "tool": "dbg_get_process_options",
            "arguments": {"password": "secret-value"},
            "structuredContent": {"password": "result-secret"},
            "duration_ms": 1,
            "isError": False,
        }
    )

    assert "structuredContent" not in projected
    assert projected["arguments"]["password"] == "<redacted>"
    assert "secret-value" not in str(projected)
    assert "result-secret" not in str(projected)
