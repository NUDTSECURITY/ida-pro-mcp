# IDA Pro MCP

[English](README.md) | [中文](README.zh.md)

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes IDA Pro / idalib to MCP clients. Use it for AI-assisted reverse engineering: inspect decompilation, add comments, rename symbols, search patterns, control the debugger, and more.

This repository provides two complementary servers:

- **`ida-pro-mcp`** — stdio/HTTP proxy that connects to a running IDA Pro GUI instance via the bundled IDA plugin.
- **`idalib-mcp`** — headless supervisor that spawns per-database `idalib` worker processes, so you can analyze binaries without opening the IDA GUI.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Transports](#transports)
- [Tool Reference](#tool-reference)
- [Debugger Extension](#debugger-extension)
- [MCP Resources](#mcp-resources)
- [Prompt Engineering](#prompt-engineering)
- [Development](#development)

## Overview

### `ida-pro-mcp` (GUI mode)

Installs an IDA Pro plugin (`Edit → Plugins → MCP` or `Ctrl-Alt-M`). When the plugin starts an HTTP server, `ida-pro-mcp` auto-discovers it and proxies MCP requests from your client into IDA.

Typical flow:

1. Open a binary in IDA Pro.
2. Start the MCP plugin (it can autostart).
3. Configure your MCP client to run `ida-pro-mcp`.
4. Ask the LLM to analyze the database.

### `idalib-mcp` (headless mode)

Runs a supervisor that keeps each open database in its own `idalib` worker process. Workers register themselves locally and outlive the supervisor; a new supervisor adopting the same path reuses the running worker. Workers self-exit after an idle TTL (default 1 hour).

Typical flow:

```python
idb_open("/path/to/binary.exe", preferred_session_id="binary_a")
decompile("main", database="binary_a")
xrefs_to("ImportantExport", database="binary_a")
```

Every headless tool call must include a `database` argument naming the session returned by `idb_open` (or listed by `idb_list`).

## Prerequisites

- [Python](https://www.python.org/downloads/) **3.11 or higher**
  - Use `idapyswitch` to point IDA at the newest Python version if needed.
- [IDA Pro](https://hex-rays.com/ida-pro) **8.3 or higher**, **9.0+ recommended**
  - **IDA Free is not supported.**
- [uv](https://astral.sh/uv) (recommended for running from source)
- A supported MCP client (see `--list-clients`)

## Installation

### From source

```bash
uv sync
uv run ida-pro-mcp --install
```

`--install` copies the IDA plugin to `%APPDATA%\Hex-Rays\IDA Pro\plugins\` (Windows) or `~/.idapro/plugins/` (macOS/Linux) and optionally writes MCP client configuration.

> **Important**: After installing, completely restart IDA Pro so the new plugin loads. Some MCP clients also run in the background and need to be fully quit and restarted.

### Install for a specific MCP client

```bash
uv run ida-pro-mcp --install claude
uv run ida-pro-mcp --install cursor,vscode
```

Use `--scope project` for project-level config or `--scope global` for user-level config.

### Print configuration without installing

```bash
uv run ida-pro-mcp --config
```

### Uninstall

```bash
uv run ida-pro-mcp --uninstall
```

### Headless `idalib-mcp`

`idalib-mcp` requires the `idapro` package and an activated `idalib` installation. Activate it once with the script shipped by your IDA version, for example:

```bash
# Windows
uv run "C:\Program Files\IDA Professional 9.2\idalib\python\py-activate-idalib.py"

# macOS
uv run "/Applications/IDA Professional 9.2.app/Contents/MacOS/idalib/python/py-activate-idalib.py"
```

Then run the headless supervisor:

```bash
# stdio mode (most clients)
uv run idalib-mcp --stdio

# HTTP mode with an initial binary
uv run idalib-mcp --host 127.0.0.1 --port 8745 path/to/executable

# HTTP mode without an initial binary
uv run idalib-mcp --host 127.0.0.1 --port 8745
```

## Usage

### Start the IDA Pro plugin

In IDA Pro, open a binary and either:

- Wait for autostart (if enabled), or
- Use `Edit → Plugins → MCP` (hotkey `Ctrl-Alt-M`).

The plugin registers the running instance locally; `ida-pro-mcp` auto-discovers it.

### Connect with an MCP client

After installing, your client will run `ida-pro-mcp` over stdio. The proxy discovers the IDA instance and forwards every tool call. If you prefer HTTP/SSE, run:

```bash
uv run ida-pro-mcp --transport http://127.0.0.1:8744/sse
```

### Headless session model

`idalib-mcp` is a supervisor, not a worker. It spawns detached worker processes and can adopt already-running GUI or worker instances. There is no `idb_close` tool; sessions stay alive until idle TTL expires or the user closes the GUI window.

`idb_open` backend selection (`mode` parameter):

- `prefer_headless` (default): spawn/adopt an idalib worker.
- `force_headless`: spawn/adopt a worker, never adopt a GUI.
- `prefer_gui`: adopt a GUI if one has the file open; otherwise spawn a worker.
- `force_gui`: adopt a GUI if one has the file open; otherwise launch a new IDA GUI process.

Management tools:

- `idb_open(input_path, mode="prefer_headless", run_auto_analysis=True, build_caches=True, init_hexrays=True, preferred_session_id="", idle_ttl_sec=600)` — open/adopt a session.
- `idb_list()` — list open sessions and running GUI instances.
- `idb_save(session_id, path="")` — save an IDB.
- `server_health(database=<id>)` — per-session health.

Worker controls:

- `--max-workers N` (default `4`, `0` = unlimited)
- `IDA_MCP_MAX_WORKERS` environment variable

## Transports

### `ida-pro-mcp`

- **stdio** (default) — what most MCP clients expect.
- **HTTP / SSE** — pass a URL to `--transport`, e.g. `http://127.0.0.1:8744/sse`.

### `idalib-mcp`

- **HTTP** (default) — `--host`/`--port`.
- **stdio** — `--stdio`.

### Unsafe tools and extensions

Some tools are marked unsafe and are only available when explicitly enabled:

- `idalib-mcp`: pass `--unsafe`.
- `ida-pro-mcp`: the proxy forwards whatever the running IDA instance exposes.

Debugger tools belong to the `dbg` extension and are hidden by default. Enable them with the `?ext=dbg` query parameter:

```bash
# Direct HTTP
http://127.0.0.1:13337/mcp?ext=dbg

# Through the stdio proxy
uv run ida-pro-mcp --ida-rpc http://127.0.0.1:13337?ext=dbg
```

## Tool Reference

The server exposes the tools below. Schemas (parameter names, types, descriptions) are available from any MCP client via `tools/list`.

### Core IDB metadata (`api_core`)

- `server_health()` — server status, uptime, current IDB path.
- `lookup_funcs(queries)` — get function(s) by address or name.
- `int_convert(inputs)` — convert numbers between decimal, hex, binary, ASCII, etc.
- `list_funcs(queries)` — list functions with filtering and pagination.
- `func_query(queries)` — richer function query (size, type, name filters).
- `list_globals(queries)` — list global variables.
- `entity_query(queries)` — generic query over functions, globals, imports, strings, names.
- `imports(offset, count)` — list imported symbols.
- `imports_query(queries)` — richer import query.
- `idb_save()` — save the current IDB.

### Analysis (`api_analysis`)

- `decompile(addr)` — decompile a function.
- `disasm(addr)` — disassemble a function.
- `analyze_function(addr)` — compact single-function analysis.
- `analyze_batch(queries)` — comprehensive per-function analysis.
- `analyze_component(addrs)` — analyze a group of related functions.
- `func_profile(queries)` — function metrics and sampled details.
- `survey_binary()` — compact overview of the binary.
- `basic_blocks(addrs)` — basic blocks of function(s).
- `callees(addrs)` — functions called by function(s).
- `xrefs_to(addrs)` — cross-references to address(es).
- `xref_query(queries)` — generic xref query.
- `xrefs_to_field(queries)` — xrefs to struct field(s).
- `callgraph(roots)` — bounded call graph from root function(s).
- `trace_data_flow(addr)` — follow cross-references forward or backward.
- `search_text(pattern)` — search rendered disassembly/comments.
- `export_funcs(addrs, format)` — export function data (json, c_header, prototypes).

### Search & patterns

- `find_regex(pattern)` — case-insensitive regex search in strings.
- `find_bytes(patterns)` — byte pattern search (e.g. `48 8B ?? ??`).
- `find(type, targets)` — search strings, immediates, data/code references.
- `find_xref_signatures(addrs)` — create signatures for code that references an address.
- `insn_query(queries)` — query instructions by mnemonic/operand filters.

### Memory (`api_memory`)

- `get_bytes(regions)` — read raw bytes.
- `get_int(queries)` — read integers (`u8`, `i32le`, `u64be`, etc.).
- `get_string(addrs)` — read null-terminated strings.
- `get_global_value(queries)` — read global values by address or name.
- `patch(patches)` — patch bytes.
- `put_int(items)` — write integers.

### Modification (`api_modify`)

- `set_comments(items)` — set comments.
- `append_comments(items)` — append comments.
- `add_bookmark(addr, name, prefix)` — add IDA bookmarks.
- `rename(batch)` — batch rename functions, globals, locals, stack vars.
- `patch_asm(items)` — patch assembly instructions.
- `declare_type(decls)` — declare C types.
- `set_type(edits)` — apply types to functions/globals/locals/stack.
- `type_apply_batch(batch)` — batch type edits.
- `infer_types(addrs)` — infer types at address(es).
- `define_func(items)` — define functions.
- `define_code(items)` — convert bytes to code.
- `undefine(items)` — undefine items.
- `force_recompile(addrs)` — invalidate decompiler cache.
- `set_op_type(items)` — set operand type.
- `make_data(items)` — create typed data symbols.

### Stack (`api_stack`)

- `stack_frame(addrs)` — get stack variables.
- `declare_stack(items)` — create stack variables.
- `delete_stack(items)` — delete stack variables.

### Types (`api_types`)

- `read_struct(queries)` — read struct fields at address(es).
- `search_structs(filter)` — search structures by name.
- `type_query(queries)` — query local types.
- `type_inspect(queries)` — inspect named types.
- `enum_upsert(queries)` — create or update enums.

### Signatures (`api_sigmaker`)

- `make_signature(addrs)` — create byte signatures for addresses.
- `make_signature_for_function(addrs)` — create signatures for function entries.
- `make_signature_for_range(start, end)` — create signatures for a range.

### Python execution (`api_python`)

- `py_eval(code)` — execute Python in IDA context.
- `py_exec_file(file_path)` — execute a Python script file in IDA context.

### Composite / diff (`api_composite`)

- `diff_before_after(addr, action, action_args)` — rename/type/comment with before/after decompilation.

## Debugger Extension

Debugger tools are in the `dbg` extension group and require `?ext=dbg` (see [Transports](#transports)).

The extension provides three complementary APIs:

1. **One-shot control** — single actions that return immediately.
2. **Event-loop control** — polling primitives that block until debugger state changes and return a structured snapshot.
3. **Interactive CLI I/O** — start a target outside IDA, capture stdin/stdout/stderr, then attach IDA to the PID.

### One-shot control

- `dbg_start()` / `dbg_exit()` — start or exit debugger session.
- `dbg_continue()` / `dbg_run_to(addr)` / `dbg_step_into()` / `dbg_step_over()` — execution control.
- `dbg_status()` — current debugger lifecycle state.
- `dbg_bps()` / `dbg_add_bp(addrs)` / `dbg_delete_bp(addrs)` / `dbg_toggle_bp(items)` / `dbg_set_bp_condition(items)` — breakpoints.
- `dbg_regs()` / `dbg_regs_all()` / `dbg_regs_remote(tids)` / `dbg_gpregs()` / `dbg_stacktrace()` — registers and stack.
- `dbg_read(regions)` / `dbg_write(regions)` / `dbg_read_around(addr)` — memory.
- `dbg_list_processes()` / `dbg_modules()` / `dbg_resolve(name)` — processes and modules.
- `dbg_get_process_options()` / `dbg_set_process_options(...)` — launch options.

### Event-loop control

- `dbg_loop_init()` — get the debugger event cursor.
- `dbg_wait_event(cursor, timeout_ms)` — wait for an event without resuming.
- `dbg_continue_until_event(timeout_ms)` — resume and wait for the next event.
- `dbg_start_process_until_event(path, args, start_dir, timeout_ms)` — start and wait.
- `dbg_start_current_file_until_event(timeout_ms)` — start current file and wait.
- `dbg_attach_process_until_event(pid, timeout_ms)` — attach and wait.
- `dbg_add_temp_bp_and_continue(addr, timeout_ms)` — temporary breakpoint + continue.
- `dbg_get_snapshot(...)` — current IP, disassembly, registers, stack trace.
- `dbg_get_events(cursor, limit)` — read captured events.
- `dbg_diagnose(include_process_list)` — readiness check without starting anything.

### Interactive CLI I/O

- `dbg_pty_start(path, args, start_dir)` — start a CLI process.
- `dbg_pty_send(session_id, data)` — send to stdin.
- `dbg_pty_read(session_id, max_bytes, timeout_ms)` — read stdout/stderr.
- `dbg_pty_list()` — list sessions.
- `dbg_pty_close(session_id)` — terminate session.

Typical workflow:

```text
1. dbg_pty_start("/path/to/crackme", args="flag.txt") → {session_id, pid}
2. attach IDA debugger to pid
3. dbg_pty_read(session_id, timeout_ms=500) → "Enter password:"
4. dbg_pty_send(session_id, data="guess\n")
5. dbg_pty_read(session_id, timeout_ms=500) → response
6. dbg_pty_close(session_id)
```

### Live Activity Viewer

Starting the MCP server in IDA automatically opens the `MCP Activity` subview.
Reopen it from `View -> Open subviews -> MCP Activity`. The viewer shows each
tool's UTC timestamp, duration, status, and redacted argument summary in real
time, retaining the latest 500 records.

The viewer hides passwords, tokens, cookies, and similar fields. The complete
persistent trace remains in the IDB's `$ ida_mcp.trace` netnode and can be
exported with `ida-mcp-trace-dump`. Treat exported traces as sensitive because
they can contain original arguments and results.

## MCP Resources

Read-only browsable state:

- `ida://idb/metadata` — IDB file info (path, arch, base, size, hashes).
- `ida://idb/segments` — memory segments with permissions.
- `ida://idb/entrypoints` — entry points.
- `ida://cursor` — current cursor position and function.
- `ida://selection` — current selection range.
- `ida://types` — all local types.
- `ida://structs` — all structures/unions.
- `ida://struct/{name}` — structure definition.
- `ida://import/{name}` — import details.
- `ida://export/{name}` — export details.
- `ida://xrefs/from/{addr}` — cross-references from an address.

## Prompt Engineering

LLMs can hallucinate, especially with integer/byte conversions. A minimal prompt:

```md
Your task is to analyze a crackme in IDA Pro. Use the MCP tools to retrieve information.

- Inspect the decompilation and add comments with your findings.
- Rename variables and functions to sensible names.
- Correct variable and argument types where necessary (especially pointers and arrays).
- If more detail is needed, inspect the disassembly and add comments.
- NEVER convert number bases yourself. Use the `int_convert` MCP tool.
- Do not brute force; derive solutions from analysis and simple Python scripts.
- Create a report.md with your findings and steps taken.
- When you find a solution, ask the user for feedback with the password you found.
```

Another systematic prompt:

```md
Your task is to create a complete reverse engineering analysis.

1. **Decompilation Analysis**: inspect decompiler output, add detailed comments, focus on actual functionality.
2. **Improve Readability**: rename variables/functions, correct types.
3. **Deep Dive**: examine disassembly when needed, document low-level behaviors.
4. **Constraints**: never convert number bases yourself — use `int_convert`; derive conclusions from actual analysis.
5. **Documentation**: produce RE/*.md files with findings and methodology.
```

### Tips for better accuracy

- Tell the LLM to use `int_convert` instead of converting numbers itself.
- For heavy math, consider pairing with a dedicated math MCP.
- Deobfuscate first where possible: string encryption, import hashing, control-flow flattening, code encryption, anti-decompilation tricks.
- Use Lumina/FLIRT to resolve open-source library code and C++ STL before analysis.

## Development

Adding a tool is simple: add a new `@tool` function to one of the `src/ida_pro_mcp/ida_mcp/api_*.py` modules and it is automatically registered.

Run the MCP inspector for interactive testing:

```bash
npx -y @modelcontextprotocol/inspector
```

Run the headless test harness:

```bash
uv run ida-mcp-test tests/crackme03.elf -q
uv run ida-mcp-test tests/typed_fixture.elf -q
```

Measure coverage across both fixtures:

```bash
uv run coverage erase
uv run coverage run -m ida_pro_mcp.test tests/crackme03.elf -q
uv run coverage run --append -m ida_pro_mcp.test tests/typed_fixture.elf -q
uv run coverage report --show-missing
```

Generate a changelog of direct commits:

```bash
git log --first-parent --no-merges 1.2.0..main "--pretty=- %s"
```

## Acknowledgments

Original concept and implementation by [mrexodia](https://github.com/mrexodia), [can1357](https://github.com/can1357), and contributors. The headless `idalib` feature was contributed by [Willi Ballenthin](https://github.com/williballenthin).
