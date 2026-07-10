# IDA Pro MCP Live Tool Report

- Date: 2026-07-10
- Endpoint: `http://127.0.0.1:13337/mcp?ext=dbg`
- IDB: `C:\Users\ZhenyeFan\Desktop\ctfTools\test\attachment\rpc-server.i64`
- Module: `rpc-server`, imagebase `0x555555554000`
- Sample entry: `main` = `0x555555556ce1`; sample `.rodata` = `0x555555558000`
- Tool count: `109`; status counts: `DEBUGGER_CONFIG_BLOCKED` 4, `NEED_DEBUGGER` 20, `OK` 85

## Summary

- MCP initialize, `tools/list`, static analysis, decompile/disasm, memory reads, type operations, comments, signatures, and IDAPython execution were live-tested successfully.
- Dynamic CLI-style interaction is available through `dbg_pty_*`: MCP started a subprocess, sent stdin, and read stdout.
- IDA debugger-control tools are callable, but full stepping/register/memory-snapshot testing needs a live debugger session. The current remote Linux debugger endpoint `192.168.230.128:23946` did not respond.
- During testing, IDA opened `Debug application setup: linux`; the dialog was cancelled, and MCP responsiveness recovered.

## Dynamic CLI Evidence

Example call sequence:

```json
{
  "dbg_pty_start": {
    "path": "C:\\ProgramData\\miniconda3\\python.exe",
    "args": "-c \"import sys; print('ready', flush=True); print('echo:'+sys.stdin.readline().strip(), flush=True)\""
  },
  "dbg_pty_send": {
    "session_id": "<session_id>",
    "data": "hello-from-mcp\\n"
  },
  "dbg_pty_read": {
    "session_id": "<session_id>",
    "timeout_ms": 1000,
    "max_bytes": 4096
  }
}
```

Observed stdout:

```text
ready
echo:hello-from-mcp
```

## Per-Tool Results

| # | Tool | Status | Purpose | Example arguments | Observed result |
|---:|---|---|---|---|---|
| 1 | `server_health` | OK | Health/ready probe for MCP server and current IDB state. | `{}` | keys=status,uptime_sec,idb_path,module,input_path,imagebase,auto_analysis_ready,hexrays_ready |
| 2 | `lookup_funcs` | OK | Get functions by address or name (auto-detects) | `{"queries":["main","0x555555556ce1"]}` | keys=result |
| 3 | `int_convert` | OK | Convert numbers to different formats | `{"inputs":[{"text":"0x10"},{"text":"1234","size":4}]}` | keys=result |
| 4 | `list_funcs` | OK | List functions with optional filtering and offset/count pagination. | `{"queries":[{"offset":0,"count":3}]}` | keys=result |
| 5 | `func_query` | OK | Query functions with richer filtering than list_funcs. | `{"queries":[{"filter":"main","count":3}]}` | keys=result |
| 6 | `list_globals` | OK | List globals with optional filtering and offset/count pagination. | `{"queries":[{"offset":0,"count":3}]}` | keys=result |
| 7 | `entity_query` | OK | Query IDB entities with typed filters, projection, and pagination. | `{"queries":[{"kind":"functions","filter":"main","count":3}]}` | keys=result |
| 8 | `imports` | OK | List imports with module names using offset/count pagination. | `{"offset":0,"count":3}` | keys=data,next_offset |
| 9 | `imports_query` | OK | Query imports with richer filtering than imports(offset,count). | `{"queries":[{"filter":"printf","count":3}]}` | keys=result |
| 10 | `idb_save` | OK | Save active IDB to disk, optionally to a provided path.      Always packs into a single compressed .i64/.idb, removing the loose     .id0/.id1/.id2/.nam/.til working files. | `{}` | keys=ok,path |
| 11 | `find_regex` | OK | Search strings by case-insensitive regex with offset/limit pagination. | `{"pattern":"rpc","limit":5}` | keys=n,matches,cursor |
| 12 | `search_text` | OK | Search the rendered listing for `pattern` over [start, end).      Iterates `idautils.Heads()` in pure Python and renders each via     `ida_lines.generate_disassembly()`. Per-head i | `{"pattern":"main"}` | keys=n,hits,cursor |
| 13 | `decompile` | OK | Decompile function(s) at address(es); returns pseudocode and per-item errors. | `{"addr":"0x555555556ce1"}` | keys=addr,code,error |
| 14 | `disasm` | OK | Disassemble function with offset/max_instructions pagination and optional total count. | `{"addr":"0x555555556ce1","max_instructions":12}` | keys=addr,asm,instruction_count,total_instructions,cursor |
| 15 | `func_profile` | OK | Profile functions with summary metrics and optional sampled details. | `{"queries":[{"filter":"main","count":1}]}` | keys=result |
| 16 | `analyze_batch` | OK | Run comprehensive analysis over one or more target functions. | `{"queries":[{"addr":"0x555555556ce1"}]}` | keys=result |
| 17 | `xrefs_to` | OK | Return xrefs to address(es) or named symbols, capped per target with truncation flag. | `{"addrs":"0x555555556ce1"}` | keys=result |
| 18 | `xref_query` | OK | Query xrefs with direction/type filters and pagination. | `{"queries":[{"addr":"0x555555556ce1","direction":"to","count":5}]}` | keys=result |
| 19 | `xrefs_to_field` | OK | Get cross-references to structure fields | `{"queries":[{"struct":"codex_missing_struct","field":"missing"}]}` | keys=result |
| 20 | `callees` | OK | Return unique callees per function, capped by limit. | `{"addrs":"0x555555556ce1"}` | keys=result |
| 21 | `find_bytes` | OK | Search byte patterns (supports ??) with offset/limit pagination. | `{"patterns":"55 48 89 E5","limit":5}` | keys=result |
| 22 | `basic_blocks` | OK | Return function CFG blocks with offset/max_blocks pagination. | `{"addrs":"0x555555556ce1"}` | keys=result |
| 23 | `find` | OK | Search strings/immediates/refs for targets with offset/limit pagination. | `{"type":"string","targets":"rpc","limit":5}` | keys=result |
| 24 | `insn_query` | OK | Query instructions with mnemonic/operand filters and scoped scans. | `{"queries":[{"func":"0x555555556ce1","count":5,"include_disasm":true}]}` | keys=result |
| 25 | `export_funcs` | OK | Export function data for addresses in json/c_header/prototypes formats. | `{"addrs":"0x555555556ce1","format":"json"}` | keys=format,functions |
| 26 | `callgraph` | OK | Build bounded callgraph from roots with depth/node/edge limits. | `{"roots":"0x555555556ce1","max_depth":1,"max_nodes":20}` | keys=result |
| 27 | `get_bytes` | OK | Read bytes from memory addresses | `{"regions":[{"addr":"0x555555556ce1","size":8}]}` | keys=result |
| 28 | `get_int` | OK | Read integer values from memory addresses | `{"queries":[{"addr":"0x555555556ce1","type":"u8"}]}` | keys=result |
| 29 | `get_string` | OK | Read strings from memory addresses | `{"addrs":"0x555555558000"}` | keys=result |
| 30 | `get_global_value` | OK | Read global variable values by address or symbol name. | `{"queries":[{"addr":"0x555555558000"}]}` | keys=result |
| 31 | `patch` | OK | Patch bytes at memory addresses with hex data | `{"patches":[{"addr":"0x555555556ce1","data":"55"}]}` | keys=result |
| 32 | `put_int` | OK | Write integer values to memory addresses | `{"items":[{"addr":"0x555555556ce1","value":85,"type":"u8"}]}` | keys=result |
| 33 | `declare_type` | OK | Declare C type definitions in local type library. | `{"decls":["struct codex_mcp_test_type { int value; };"]}` | keys=result |
| 34 | `enum_upsert` | OK | Create or extend local enums in an idempotent way. | `{"queries":[{"name":"codex_mcp_test_enum","members":{"CODEX_MCP_TEST_A":1}}]}` | keys=result |
| 35 | `read_struct` | OK | Read struct fields from memory at address; auto-detect type when possible. | `{"queries":[{"addr":"0x555555558000","type":"codex_mcp_test_type"}]}` | keys=result |
| 36 | `search_structs` | OK | Search local structs/unions by name pattern. | `{"filter":"codex_mcp_test*"}` | keys=result |
| 37 | `type_query` | OK | Query local types with structured filters/projection-friendly output. | `{"queries":[{"filter":"codex_mcp_test*","count":5}]}` | keys=result |
| 38 | `type_inspect` | OK | Inspect named types (size/kind/declaration/members). | `{"queries":["codex_mcp_test_type"]}` | keys=result |
| 39 | `set_type` | OK | Apply types (function/global/local/stack) | `{"edits":[{"kind":"function","addr":"0x555555556ce1","type":"int main(int argc, char **argv);","dry_run":true}]}` | keys=result |
| 40 | `type_apply_batch` | OK | Apply multiple type edits and return aggregate status. | `{"batch":{"edits":[{"kind":"function","addr":"0x555555556ce1","type":"int main(int argc, char **argv);"}],"dry_run":true}}` | keys=ok,applied,failed,stopped,results |
| 41 | `infer_types` | OK | Infer and apply likely types at target addresses. | `{"addrs":"0x555555556ce1"}` | keys=result |
| 42 | `add_bookmark` | OK | Add or replace the IDA bookmark at an address. Set prefix="" for no prefix. | `{"addr":"0x555555556ce1","name":"codex_mcp_smoke","prefix":"codex"}` | keys=addr,ea,slot,title,prefix,ok |
| 43 | `set_comments` | OK | Set comments at addresses (both disassembly and decompiler views) | `{"items":[{"addr":"0x555555556ce1","comment":"codex mcp smoke test","repeatable":false}]}` | keys=result |
| 44 | `append_comments` | OK | Append comments at addresses, deduping exact text by default. | `{"items":[{"addr":"0x555555556ce1","comment":"codex mcp smoke append","repeatable":false}]}` | keys=result |
| 45 | `patch_asm` | OK | Patch assembly instructions at addresses | `{"items":[{"addr":"0x555555556ce1","asm":"nop","dry_run":true}]}` | keys=result |
| 46 | `rename` | OK | Batch-rename funcs/globals/locals/stack vars with dry-run options. | `{"batch":{"func":[{"addr":"0x555555556ce1","name":"main"}],"dry_run":true}}` | keys=func,summary |
| 47 | `define_func` | OK | Define functions; IDA infers bounds unless end is provided. | `{"items":[{"addr":"0x555555556ce1"}]}` | keys=result |
| 48 | `define_code` | OK | Convert bytes to code instruction(s) at address(es). | `{"items":[{"addr":"0x555555556ce1"}]}` | keys=result |
| 49 | `undefine` | OK | Undefine item(s) at address(es), converting back to raw bytes. | `{"items":[{"addr":"0x0","size":0}]}` | keys=result |
| 50 | `force_recompile` | OK | Invalidate the Hex-Rays decompile cache for one or more functions.      Use after `set_type`, `rename` (especially of locals), `set_op_type`, or     `make_data` so the next `decomp | `{"items":[{"addr":"0x555555556ce1"}]}` | Retested with correct items parameter; main decompiler cache refreshed. |
| 51 | `set_op_type` | OK | Set the type of an instruction operand. GUI 'Y' / 'O' / '#' equivalent.      Tags an operand at a specific instruction with a desired interpretation.     Useful when the decompiler | `{"items":[{"addr":"0x555555556ce1","op_n":0,"kind":"offset","target_addr":"0x555555556ce1"}]}` | keys=result |
| 52 | `make_data` | OK | Create a typed data symbol at an address, replacing any prior items.      Use this to harden a symbol boundary that the decompiler is currently     expressing through a neighboring | `{"items":[{"addr":"0x555555558000","type":"byte","name":"codex_mcp_test_byte","delete_existing":false}]}` | keys=result |
| 53 | `stack_frame` | OK | Return stack variables for function address(es). | `{"addrs":"0x555555556ce1"}` | keys=result |
| 54 | `declare_stack` | OK | Create stack variables from typed stack declarations. | `{"items":[{"addr":"0x555555556ce1","offset":"-4","name":"codex_stack_test","ty":"int"}]}` | keys=result |
| 55 | `delete_stack` | OK | Delete stack variables by name or offset. | `{"items":[{"addr":"0x555555556ce1","name":"codex_stack_test"}]}` | keys=result |
| 56 | `dbg_start` | DEBUGGER_CONFIG_BLOCKED | Start debugger session for current target.      Requires the user to have selected a debugger (Debugger -> Select debugger)     and configured the target (executable path, argument | `{}` | Starts/connects the remote debugger. This run opened IDA Debug application setup and timed out against 192.168.230.128:23946; the modal was cancelled. |
| 57 | `dbg_status` | OK | Return debugger lifecycle state and current IP if suspended. | `{}` | keys=state |
| 58 | `dbg_exit` | NEED_DEBUGGER | Terminate active debugger session. | `{}` | Tool entrypoint is callable, but it requires a live IDA debugger session. |
| 59 | `dbg_continue` | NEED_DEBUGGER | Resume execution in active debugger session. | `{}` | Tool entrypoint is callable, but it requires a live IDA debugger session. |
| 60 | `dbg_run_to` | NEED_DEBUGGER | Run debuggee until target address is reached. | `{"addr":"0x555555556ce1"}` | Tool entrypoint is callable, but it requires a live IDA debugger session. |
| 61 | `dbg_step_into` | NEED_DEBUGGER | Execute one instruction, stepping into calls. | `{}` | Tool entrypoint is callable, but it requires a live IDA debugger session. |
| 62 | `dbg_step_over` | NEED_DEBUGGER | Execute one instruction, stepping over calls. | `{}` | Tool entrypoint is callable, but it requires a live IDA debugger session. |
| 63 | `dbg_bps` | OK | List breakpoints with address, enabled status, condition, and language. | `{}` | keys=result |
| 64 | `dbg_add_bp` | OK | Add breakpoints at one or more addresses. | `{"addrs":"0x555555556ce1"}` | keys=result |
| 65 | `dbg_delete_bp` | OK | Delete breakpoints at one or more addresses. | `{"addrs":"0x555555556ce1"}` | keys=result |
| 66 | `dbg_toggle_bp` | OK | Enable or disable existing breakpoints in batch. | `{"items":[{"addr":"0x555555556ce1","enabled":true}]}` | keys=result |
| 67 | `dbg_set_bp_condition` | OK | Set or clear breakpoint conditions in batch. | `{"items":[{"addr":"0x555555556ce1","condition":"","language":""}]}` | keys=result |
| 68 | `dbg_regs_all` | NEED_DEBUGGER | Return full register sets for all debugger threads. | `{}` | Tool entrypoint is callable, but it requires a live IDA debugger session. |
| 69 | `dbg_regs_remote` | NEED_DEBUGGER | Return full register sets for specified thread IDs. | `{"tids":[1]}` | Tool entrypoint is callable, but it requires a live IDA debugger session. |
| 70 | `dbg_regs` | NEED_DEBUGGER | Return full registers for current debugger thread. | `{}` | Tool entrypoint is callable, but it requires a live IDA debugger session. |
| 71 | `dbg_gpregs_remote` | NEED_DEBUGGER | Get GP registers for threads | `{"tids":[1]}` | Tool entrypoint is callable, but it requires a live IDA debugger session. |
| 72 | `dbg_gpregs` | NEED_DEBUGGER | Get current thread GP registers | `{}` | Tool entrypoint is callable, but it requires a live IDA debugger session. |
| 73 | `dbg_regs_named_remote` | NEED_DEBUGGER | Return selected registers for a specific thread ID. | `{"thread_id":1,"register_names":"RIP,RSP"}` | Callable with corrected comma-separated register_names; current debugger session is not running. |
| 74 | `dbg_regs_named` | NEED_DEBUGGER | Get specific current thread registers | `{"register_names":"RIP,RSP"}` | Callable with corrected comma-separated register_names; current debugger session is not running. |
| 75 | `dbg_stacktrace` | OK | Return current call stack with module and symbol context. | `{}` | keys=result |
| 76 | `dbg_read` | NEED_DEBUGGER | Read debuggee memory from one or more regions. | `{"regions":[{"addr":"0x555555556ce1","size":8}]}` | Tool entrypoint is callable, but it requires a live IDA debugger session. |
| 77 | `dbg_write` | NEED_DEBUGGER | Write bytes to debuggee memory regions. | `{"regions":[{"addr":"0x555555556ce1","data":"55"}]}` | Tool entrypoint is callable, but it requires a live IDA debugger session. |
| 78 | `dbg_loop_init` | OK | Initialize MCP-driven debugger polling and return the event cursor. | `{}` | keys=ok,cursor |
| 79 | `dbg_get_events` | OK | Return debugger events produced by prior MCP wait/continue calls. | `{}` | keys=cursor,events |
| 80 | `dbg_get_process_options` | OK | Return IDA debugger process options used by MCP-driven starts. | `{}` | keys=path,args,start_dir,hostname,password,port |
| 81 | `dbg_set_process_options` | OK | Set IDA debugger process options through MCP and return the result. | `{"path":"rpc-server","port":23946}` | Set/read process options succeeded for rpc-server and port 23946. |
| 82 | `dbg_list_processes` | OK | List processes visible to the selected debugger through MCP. | `{}` | keys=count,processes,error |
| 83 | `dbg_resolve` | OK | Resolve a symbol or address in the debugger address space.      Useful for confirming that a function from a loaded shared library (e.g.     ``edit_buffer`` in ``libggml.so``) is v | `{"name":"main"}` | keys=input,addr |
| 84 | `dbg_modules` | NEED_DEBUGGER | List modules loaded in the debuggee process with base addresses. | `{}` | Callable, but current debugger session is not running. |
| 85 | `dbg_diagnose` | OK | Diagnose MCP-driven debugger readiness without starting or attaching. | `{}` | keys=state,debugger,process_options,input_file_path,resolved_input_file_path,idb_path,remote_tcp,issues |
| 86 | `dbg_wait_event` | NEED_DEBUGGER | Wait for the next debugger event without resuming execution. | `{"timeout_ms":1}` | Callable, but current debugger session is not running. |
| 87 | `dbg_start_process_until_event` | DEBUGGER_CONFIG_BLOCKED | Start the configured debugger process via MCP and wait for state/event. | `{"path":"Z:/definitely/not/found.exe","timeout_ms":1}` | Starts/connects the remote debugger. This run opened IDA Debug application setup and timed out against 192.168.230.128:23946; the modal was cancelled. |
| 88 | `dbg_start_current_file_until_event` | DEBUGGER_CONFIG_BLOCKED | Start the currently loaded input file via MCP and wait for state/event. | `{"timeout_ms":1}` | Starts/connects the remote debugger. This run opened IDA Debug application setup and timed out against 192.168.230.128:23946; the modal was cancelled. |
| 89 | `dbg_attach_process_until_event` | DEBUGGER_CONFIG_BLOCKED | Attach to a running process through MCP and wait for debugger state/event. | `{"pid":0,"timeout_ms":1}` | Starts/connects the remote debugger. This run opened IDA Debug application setup and timed out against 192.168.230.128:23946; the modal was cancelled. |
| 90 | `dbg_get_snapshot` | NEED_DEBUGGER | Return an agent-friendly snapshot of the current debugger state. | `{"include_registers":false,"include_stack":false,"disasm_radius":1}` | Callable, but current debugger session is not running. |
| 91 | `dbg_continue_until_event` | NEED_DEBUGGER | Resume execution and wait for the next debugger event or timeout. | `{"timeout_ms":1}` | Callable, but current debugger session is not running. |
| 92 | `dbg_add_temp_bp_and_continue` | NEED_DEBUGGER | Set a one-shot breakpoint, resume execution, and wait for an event. | `{"addr":"0x555555556ce1","timeout_ms":1}` | Callable, but current debugger session is not running. |
| 93 | `dbg_read_around` | NEED_DEBUGGER | Read debuggee memory around an address as hex/ASCII chunks.      Useful for quickly inspecting a buffer pointed to by a register or a     structure field without first computing ex | `{"addr":"0x555555556ce1","radius":8}` | Callable, but current debugger session is not running. |
| 94 | `dbg_pty_start` | OK | Start an interactive CLI process and capture its stdin/stdout/stderr.      Returns a session ID and PID. You can then attach IDA's debugger to the     returned PID while using dbg_ | `{"path":"C:\\ProgramData\\miniconda3\\python.exe","args":"-c \"import sys; print('ready', flush=True); print('echo:'+sys.stdin.readline().strip(), flush=True)\""}` | keys=session_id,pid,path,args,start_dir,state,exit_code,stdout_bytes |
| 95 | `dbg_pty_send` | OK | Send data to the stdin of a process started by dbg_pty_start. | `{"session_id":"74a0809244b64606a107eda1392bbccc","data":"hello\\n"}` | keys=ok,bytes_sent |
| 96 | `dbg_pty_read` | OK | Read stdout/stderr from a process started by dbg_pty_start. | `{"session_id":"74a0809244b64606a107eda1392bbccc","timeout_ms":1000,"max_bytes":4096}` | keys=session_id,eof,stdout_hex,stderr_hex,stdout,stderr |
| 97 | `dbg_pty_list` | OK | List active CLI sessions started by dbg_pty_start. | `{}` | keys=result |
| 98 | `dbg_pty_close` | OK | Close a CLI session and terminate its process. | `{"session_id":"74a0809244b64606a107eda1392bbccc"}` | keys=session_id,pid,path,args,start_dir,state,exit_code,stdout_bytes |
| 99 | `py_eval` | OK | Execute Python in IDA context and return result/stdout/stderr. | `{"code":"result = 1 + 2"}` | Retested after closing the IDA modal dialog; returned result=3. |
| 100 | `py_exec_file` | OK | Execute a Python script file in IDA context and return stdout/stderr.      Unlike py_eval, this runs the entire file with exec() using a single shared     globals dict (no locals s | `{"file_path":"<temp>/ida_mcp_py_exec_*.py"}` | Retested after closing the IDA modal dialog; temp script returned an object result. |
| 101 | `survey_binary` | OK | Get a compact overview of the binary in one call. Returns file metadata,     segment layout, entry points, statistics, top 15 strings and functions ranked     by xref count (functi | `{}` | keys=metadata,statistics,segments,entrypoints,interesting_strings,interesting_functions,imports_by_category,call_graph_summary |
| 102 | `analyze_function` | OK | Compact single-function analysis: pseudocode, strings, constants, callers, callees, xrefs, blocks. | `{"addr":"0x555555556ce1"}` | keys=addr,error,name,prototype,size,decompiled,decompile_error,strings |
| 103 | `analyze_component` | OK | Analyze related functions as a group: per-function summaries, internal call graph, shared data. | `{"addrs":["0x555555556ce1"]}` | keys=functions,internal_call_graph,shared_globals,interface_functions,internal_only,string_usage |
| 104 | `diff_before_after` | OK | Rename a function, set its type, or add a comment, and immediately see the     before/after decompilation side by side. Use this instead of calling rename     then decompile separa | `{"addr":"0x555555556ce1","action":"set_comment","action_args":{"comment":"codex diff smoke"}}` | keys=before,after,action_applied,changes_detected |
| 105 | `trace_data_flow` | OK | Follow cross-references from or to an address, automatically traversing     multiple hops. Use 'forward' to see where data flows TO (xrefs-from), or     'backward' to see where dat | `{"addr":"0x555555556ce1"}` | keys=start,direction,depth_reached,nodes,edges |
| 106 | `make_signature` | OK | Create unique byte signatures for addresses. Generates the shortest     unique signature starting at each address by walking instructions and     wildcarding operands. Useful for f | `{"addrs":"0x555555556ce1","max_length":32}` | keys=result |
| 107 | `make_signature_for_function` | OK | Create unique byte signatures for function entry points. Resolves each     name/address to a function, then generates the shortest unique signature     starting at the function sta | `{"addrs":"0x555555556ce1","max_length":64}` | keys=result |
| 108 | `make_signature_for_range` | OK | Create a byte signature for a specific address range (e.g. a selected     region). Unlike make_signature, this does NOT guarantee uniqueness — it     simply encodes the bytes in th | `{"start":"0x555555556ce1","end":"0x555555556ce9"}` | keys=query,addr,signature,format,unique |
| 109 | `find_xref_signatures` | OK | Find signatures for code locations that reference an address. For each     input address, finds all code cross-references TO it, generates a unique     signature at each xref site, | `{"addrs":"0x555555556ce1"}` | keys=result |

## Status Semantics

- `OK`: Direct live call returned a valid result in this IDA session.
- `NEED_DEBUGGER`: Tool is reachable, but requires an active/suspended IDA debugger session.
- `DEBUGGER_CONFIG_BLOCKED`: Tool starts/connects the debugger and was blocked by the current remote debugger configuration.
- Write-capable tools used no-op, dry-run, or low-risk examples where possible. Some smoke tests intentionally wrote a test comment/bookmark/type/enum to verify the write path.
