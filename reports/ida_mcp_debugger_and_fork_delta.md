# IDA MCP Debugger and Fork Delta Notes

- Date: 2026-07-10
- IDA session: `C:\Users\ZhenyeFan\Desktop\ctfTools\test\attachment\rpc-server.i64`
- MCP endpoint: `http://127.0.0.1:13337/mcp?ext=dbg`
- Current upstream baseline used for comparison: `mrexodia/main` at `abb2732`
- Current project commit tested: `6698efc`

## Debugger Findings

The loaded target is an ELF64 x86-64 shared object:

```text
file_type = ELF64 for x86-64 (Shared object)
processor = metapc
debugger = linux
state = not_running
```

This means Windows-local debugging is not a viable execution mode for this IDB.
IDA can expose local debugger APIs through MCP, but a Windows-local debugger cannot
execute a Linux ELF target.

The MCP/IDAPython local debugger probe returned:

```text
load_debugger("win32", False) = False
load_debugger("linux", False) = False
load_debugger("linux", True)  = True
```

Interpretation:

- `win32` local debugger cannot be selected for this ELF target.
- `linux` debugger must be used in remote mode for this target on Windows.
- MCP is not the limiting factor; target format and debugger backend are.

## Remote Debugger Findings

Initial diagnosis showed remote TCP timeout:

```text
hostname = 192.168.230.128
port     = 23946
remote_tcp.ok = false
error = TimeoutError: timed out
```

Windows network probe at that time:

```text
PingSucceeded    = True
TcpTestSucceeded = False
InterfaceAlias   = VMware Network Adapter VMnet8
SourceAddress    = 192.168.230.1
```

After the remote service was started, MCP diagnosis changed to:

```text
remote_tcp.ok = true
issues = []
```

However, starting the target still returned:

```text
dbg_start_current_file_until_event({"timeout_ms": 5000})
=> "Debugger start was cancelled"
dbg_status()
=> {"state": "not_running"}
```

Likely cause: the remote debugger server is reachable, but IDA's remote process
options still need Linux-valid target path, working directory, loader path, and
arguments. IDA explicitly requires these paths to be valid on the remote machine.

Current process options observed through MCP:

```text
path      = rpc-server
args      = --library-path . ./rpc-server -H 127.0.0.1 -p 50052 -m 1
start_dir = C:\Users\ZhenyeFan\Desktop\ctfTools\test\attachment
hostname  = 192.168.230.128
port      = 23946
```

The `start_dir` is a Windows path and is not valid on the Linux remote host. It
should be replaced with the Linux directory that contains `rpc-server` and its
runtime dependencies before trying `dbg_start_process_until_event`.

## IDA Output Explanation

The IDA terminal messages are consistent with the probes:

```text
.text:000055555555748D: Too many lines
connect: ... when connecting to 192.168.230.128:23946
```

- `Too many lines` came from heavy decompile/disassembly rendering during tool
  coverage tests. It is noisy but not a debugger failure.
- The `connect` errors came from the first remote debugger attempts while TCP
  port `23946` was unreachable.
- These actions went through MCP calls, not through manual IDA terminal commands,
  so they do not appear as a typed command transcript in IDA's terminal.

## What Is Shared With Upstream

Compared to `mrexodia/main`, this project still shares the core architecture:

- Stdio/HTTP MCP proxy server.
- IDA GUI plugin and local RPC bridge.
- Existing static analysis, decompile, disasm, xref, memory, type, comment,
  patch, stack, Python execution, survey, composite analysis, and signature tools.
- Existing installer, client configuration, and most test framework structure.
- Upstream fixes through `abb2732`, including the GUI-safe `idb_save` change.

## What Is Unique In This Fork

Current delta from `mrexodia/main`:

```text
12 files changed, 2577 insertions(+), 311 deletions(-)
```

Unique commits on top of upstream:

```text
db0db0c feat(debug): add MCP-driven debugger event loop and interactive CLI I/O
4e06eb6 docs(debug): harden MCP debugger release notes
15674e3 fix(debug): keep MCP debugger loop polling-only
533c06f docs: sync README with current implementation and add Chinese translation
5aaee13 Merge branch 'mrexodia:main' into main
5b932a3 sync project repository metadata to NUDTSECURITY
6698efc add IDA MCP live tool report
```

Main unique files/features:

- `src/ida_pro_mcp/ida_mcp/api_dbg_loop.py`
  - Adds MCP-driven debugger event cursoring.
  - Adds debugger process option read/write helpers.
  - Adds debugger readiness diagnosis.
  - Adds start/attach/wait/continue helpers that return structured event data.
  - Adds snapshot helpers for registers, stack, modules, and nearby memory.
  - Adds `dbg_pty_*` interactive CLI process control.
- `src/ida_pro_mcp/ida_mcp/tests/test_api_dbg_loop.py`
  - Adds focused tests for the new debugger-loop API.
- `README.zh.md`
  - Adds a Chinese README.
- `README.md` and `skills/idapython/SKILL.md`
  - Document the new debugger workflow and MCP usage.
- `reports/ida_mcp_live_tool_report.md`
  - Adds live coverage evidence for all 109 exposed MCP tools.
- `pyproject.toml`
  - Points repository metadata to `NUDTSECURITY/ida-pro-mcp`.

The key differentiator is therefore not general IDA automation, which upstream
already has. The differentiator is MCP-oriented dynamic debugging control:
event-loop polling, debugger state snapshots, controlled continue/wait flows,
and CLI-style stdin/stdout sessions through `dbg_pty_*`.
