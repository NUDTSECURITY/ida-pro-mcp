# IDA Pro MCP Dynamic Debugging Extension

[中文](README.md) | [English](README.en.md)

This repository is a downstream extension of
[mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp). It focuses on
closing the dynamic-debugging loop for MCP agents such as Codex and Claude
Code.

For installation fundamentals, static analysis, decompilation, xrefs, types,
memory, modification, signatures, and headless idalib features inherited from
upstream, see the
[upstream documentation](https://github.com/mrexodia/ida-pro-mcp#readme).
This document only covers functionality added by this fork.

## Development Goal

Traditional IDA MCP tools perform one operation at a time. After execution is
resumed, an agent must separately wait for suspension, identify the event,
inspect state, and decide what to do next.

This fork adds an agent-oriented orchestration layer:

```text
MCP agent
  -> start or attach
  -> wait for an IDA debugger event
  -> collect registers, stack, and disassembly
  -> set a temporary breakpoint or inspect memory
  -> decide and continue
```

The flow is driven entirely by MCP calls and does not depend on Debugger Hooks
for debugger-state capture.

## New Functionality

### 1. MCP Debugger Event Loop

`api_dbg_loop.py` performs bounded polling with
`ida_dbg.wait_for_next_event` and returns structured events and snapshots.

It supports:

- Start, attach, wait, and continue-until-event operations.
- Incremental event reads through an event cursor.
- One-shot breakpoints followed by continue.
- Snapshots containing IP, function, GP registers, stack trace, breakpoints,
  and nearby disassembly.
- Structured timeout results instead of unbounded waits.

### 2. Debugger Readiness Diagnostics

The fork can read and update process options, probe remote debugger TCP
connectivity, enumerate visible processes and modules, resolve symbols, and
identify common local/remote path configuration errors. Process-option updates
are compatible with IDA 9.2 and preserve an unchanged debugger port correctly.

### 3. Interactive CLI I/O

The `dbg_pty_*` tools start a local CLI process and continuously exchange
stdin/stdout/stderr through MCP. An agent can drive a menu application,
protocol client, or command-line challenge while IDA attaches to the returned
PID.

### 4. MCP Activity Viewer

IDA includes an `MCP Activity` subview showing each tool's UTC timestamp,
duration, status, and bounded redacted argument summary in real time.

The viewer keeps the latest 500 records. Passwords, tokens, cookies, and
similar fields are redacted before entering its in-memory buffer. Complete
audit records remain in the IDB's `$ ida_mcp.trace` netnode and can be exported
with `ida-mcp-trace-dump`.

## Added MCP Tools

| Category | Tools |
|---|---|
| Events and lifecycle | `dbg_loop_init`, `dbg_get_events`, `dbg_wait_event`, `dbg_start_process_until_event`, `dbg_start_current_file_until_event`, `dbg_attach_process_until_event`, `dbg_continue_until_event`, `dbg_add_temp_bp_and_continue` |
| Configuration and diagnostics | `dbg_get_process_options`, `dbg_set_process_options`, `dbg_list_processes`, `dbg_diagnose`, `dbg_resolve`, `dbg_modules` |
| State and memory | `dbg_get_snapshot`, `dbg_read_around` |
| CLI I/O | `dbg_pty_start`, `dbg_pty_send`, `dbg_pty_read`, `dbg_pty_list`, `dbg_pty_close` |

## Quick Start

Requirements match upstream: Python 3.11+, IDA Pro 8.3+ with IDA Pro 9.x
recommended. IDA Free is not supported.

```powershell
git clone https://github.com/NUDTSECURITY/ida-pro-mcp.git
cd ida-pro-mcp
uv sync
uv run ida-pro-mcp --install codex,claude-code --transport streamable-http --scope global
```

Fully restart IDA and the MCP client after installation. Open a target in IDA;
the MCP plugin starts automatically by default and can also be started through
`Edit -> Plugins -> MCP` or `Ctrl-Alt-M`.

Debugger tools belong to the `dbg` extension group. Enable them with:

```text
http://127.0.0.1:13337/mcp?ext=dbg
```

The installer writes the base URL without extension parameters. For dynamic
debugging, change the URL in the Codex, Claude Code, or other client
configuration to the value above, then restart the client.

For the stdio proxy, specify the IDA RPC endpoint explicitly:

```powershell
uv run ida-pro-mcp --ida-rpc "http://127.0.0.1:13337?ext=dbg"
```

## Dynamic Debugging Workflow

Recommended call order:

```text
1. dbg_diagnose
2. dbg_set_process_options
3. dbg_start_process_until_event
4. dbg_get_snapshot
5. dbg_add_temp_bp_and_continue
6. dbg_read_around
7. dbg_continue_until_event, then repeat
```

When Windows IDA debugs a Linux ELF, a remote Linux debugger is required and
`path`/`start_dir` must be absolute paths on the remote Linux host.

## Current Boundaries

- IDA still provides the debugger backend; this fork does not bypass OS or
  target-format constraints.
- Events are polled while an MCP call is waiting, not captured by a permanent
  background stream.
- Without Debugger Hooks, intermediate events outside MCP polling windows are
  not fully recorded.
- `dbg_pty_*` uses local process pipes and does not directly control a remote
  Linux target terminal.
- Remote target files, dependencies, and the IDA remote debug server must be
  prepared separately.

## Validation and Reports

- [Full MCP tool test report](reports/ida_mcp_live_tool_report.md)
- [Debugger and upstream delta report](reports/ida_mcp_debugger_and_fork_delta.md)

```powershell
$env:IDADIR = "C:\Program Files\IDA Professional 9.2"
ida-mcp-test tests/crackme03.elf --category api_dbg_loop --quiet
ida-mcp-test tests/typed_fixture.elf --category trace --quiet
python -m pytest tests/test_mcp_spec_tools_list.py tests/test_mcp_spec_schema_generation.py
```

## Upstream and License

- Upstream: [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
- This fork: [NUDTSECURITY/ida-pro-mcp](https://github.com/NUDTSECURITY/ida-pro-mcp)
- License: [MIT](LICENSE)

Upstream authorship and contributor attribution are retained.
