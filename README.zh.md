# IDA Pro MCP

[English](README.md) | [中文](README.zh.md)

一个面向 MCP 客户端的 [Model Context Protocol](https://modelcontextprotocol.io) 服务器，用于暴露 IDA Pro / idalib 的能力。可用于 AI 辅助逆向工程：查看反编译、添加注释、重命名符号、搜索模式、控制调试器等。

本仓库提供两个互补的服务器：

- **`ida-pro-mcp`** —— stdio/HTTP 代理，通过捆绑的 IDA 插件连接到正在运行的 IDA Pro GUI 实例。
- **`idalib-mcp`** —— headless 监管器，为每个数据库生成独立的 `idalib` worker 进程，从而无需打开 IDA GUI 即可分析二进制文件。

## 目录

- [概述](#概述)
- [前置要求](#前置要求)
- [安装](#安装)
- [使用](#使用)
- [传输方式](#传输方式)
- [工具参考](#工具参考)
- [调试器扩展](#调试器扩展)
- [MCP 资源](#mcp-资源)
- [Prompt 工程](#prompt-工程)
- [开发](#开发)

## 概述

### `ida-pro-mcp`（GUI 模式）

安装 IDA Pro 插件（`Edit → Plugins → MCP` 或 `Ctrl-Alt-M`）。插件启动 HTTP 服务器后，`ida-pro-mcp` 会自动发现它，并将 MCP 请求代理到 IDA 中。

典型流程：

1. 在 IDA Pro 中打开一个二进制文件。
2. 启动 MCP 插件（可设置为自动启动）。
3. 配置你的 MCP 客户端运行 `ida-pro-mcp`。
4. 让 LLM 分析数据库。

### `idalib-mcp`（headless 模式）

运行一个监管器，每个打开的数据库都在独立的 `idalib` worker 进程中。worker 会在本地注册自己，并且比启动它的监管器更长寿；后续监管器访问相同路径时会复用正在运行的 worker。worker 在空闲 TTL（默认 1 小时）后自动退出。

典型流程：

```python
idb_open("/path/to/binary.exe", preferred_session_id="binary_a")
decompile("main", database="binary_a")
xrefs_to("ImportantExport", database="binary_a")
```

每个 headless 工具调用都必须包含 `database` 参数，其值为 `idb_open` 返回的会话 ID（或 `idb_list` 中显示的 ID）。

## 前置要求

- [Python](https://www.python.org/downloads/) **3.11 或更高版本**
  - 如需，使用 `idapyswitch` 让 IDA 指向最新的 Python 版本。
- [IDA Pro](https://hex-rays.com/ida-pro) **8.3 或更高版本**，**建议 9.0+**
  - **不支持 IDA Free。**
- [uv](https://astral.sh/uv)（推荐用于从源码运行）
- 支持的 MCP 客户端（运行 `--list-clients` 查看列表）

## 安装

### 从源码安装

```bash
uv sync
uv run ida-pro-mcp --install
```

`--install` 会将 IDA 插件复制到 `%APPDATA%\Hex-Rays\IDA Pro\plugins\`（Windows）或 `~/.idapro/plugins/`（macOS/Linux），并可选择写入 MCP 客户端配置。

> **重要**：安装后请完全重启 IDA Pro，让新插件加载。某些 MCP 客户端也会在后台运行，需要完全退出并重新启动。

### 为指定 MCP 客户端安装

```bash
uv run ida-pro-mcp --install claude
uv run ida-pro-mcp --install cursor,vscode
```

使用 `--scope project` 表示项目级配置，`--scope global` 表示用户级配置。

### 仅打印配置而不安装

```bash
uv run ida-pro-mcp --config
```

### 卸载

```bash
uv run ida-pro-mcp --uninstall
```

### Headless `idalib-mcp`

`idalib-mcp` 需要 `idapro` 包以及已激活的 `idalib` 安装。使用 IDA 附带的脚本激活一次即可，例如：

```bash
# Windows
uv run "C:\Program Files\IDA Professional 9.2\idalib\python\py-activate-idalib.py"

# macOS
uv run "/Applications/IDA Professional 9.2.app/Contents/MacOS/idalib/python/py-activate-idalib.py"
```

然后启动 headless 监管器：

```bash
# stdio 模式（大多数客户端）
uv run idalib-mcp --stdio

# HTTP 模式并指定初始二进制文件
uv run idalib-mcp --host 127.0.0.1 --port 8745 path/to/executable

# HTTP 模式，不指定初始二进制文件
uv run idalib-mcp --host 127.0.0.1 --port 8745
```

## 使用

### 启动 IDA Pro 插件

在 IDA Pro 中打开二进制文件后，选择以下方式之一：

- 等待自动启动（如果已启用），或
- 使用 `Edit → Plugins → MCP`（快捷键 `Ctrl-Alt-M`）。

插件会在本地注册运行中的实例，`ida-pro-mcp` 会自动发现它。

### 使用 MCP 客户端连接

安装后，客户端会以 stdio 方式运行 `ida-pro-mcp`。代理会发现 IDA 实例并转发所有工具调用。如果你更喜欢 HTTP/SSE，可以运行：

```bash
uv run ida-pro-mcp --transport http://127.0.0.1:8744/sse
```

### Headless 会话模型

`idalib-mcp` 是监管器，不是 worker。它会生成独立的 worker 进程，并能接管已运行的 GUI 或 worker 实例。没有 `idb_close` 工具；会话会一直保持活动，直到空闲 TTL 到期或用户关闭 GUI 窗口。

`idb_open` 的后端选择（`mode` 参数）：

- `prefer_headless`（默认）：生成或复用 idalib worker。
- `force_headless`：生成或复用 worker，绝不接管 GUI。
- `prefer_gui`：如果有 GUI 已打开该文件则接管；否则生成 worker。
- `force_gui`：如果有 GUI 已打开该文件则接管；否则启动新的 IDA GUI 进程。

管理工具：

- `idb_open(input_path, mode="prefer_headless", run_auto_analysis=True, build_caches=True, init_hexrays=True, preferred_session_id="", idle_ttl_sec=600)` —— 打开/接管会话。
- `idb_list()` —— 列出打开的会话和运行中的 GUI 实例。
- `idb_save(session_id, path="")` —— 保存 IDB。
- `server_health(database=<id>)` —— 每个会话的健康状态。

Worker 控制：

- `--max-workers N`（默认 `4`，`0` 表示无限制）
- 环境变量 `IDA_MCP_MAX_WORKERS`

## 传输方式

### `ida-pro-mcp`

- **stdio**（默认）—— 大多数 MCP 客户端期望的方式。
- **HTTP / SSE** —— 向 `--transport` 传入 URL，例如 `http://127.0.0.1:8744/sse`。

### `idalib-mcp`

- **HTTP**（默认）—— `--host`/`--port`。
- **stdio** —— `--stdio`。

### 不安全工具和扩展

部分工具被标记为 unsafe，仅在显式启用时可用：

- `idalib-mcp`：传入 `--unsafe`。
- `ida-pro-mcp`：代理会转发当前运行的 IDA 实例暴露的任何内容。

调试器工具属于 `dbg` 扩展组，默认隐藏。使用 `?ext=dbg` 查询参数启用：

```bash
# 直接 HTTP
http://127.0.0.1:13337/mcp?ext=dbg

# 通过 stdio 代理
uv run ida-pro-mcp --ida-rpc http://127.0.0.1:13337?ext=dbg
```

## 工具参考

服务器暴露以下工具。参数名称、类型和描述等 schema 可通过任何 MCP 客户端的 `tools/list` 获取。

### 核心 IDB 元数据（`api_core`）

- `server_health()` —— 服务器状态、运行时间、当前 IDB 路径。
- `lookup_funcs(queries)` —— 按地址或名称获取函数。
- `int_convert(inputs)` —— 在十进制、十六进制、二进制、ASCII 等之间转换数字。
- `list_funcs(queries)` —— 列出函数，支持过滤和分页。
- `func_query(queries)` —— 更丰富的函数查询（按大小、类型、名称过滤）。
- `list_globals(queries)` —— 列出全局变量。
- `entity_query(queries)` —— 对函数、全局变量、导入、字符串、名称的通用查询。
- `imports(offset, count)` —— 列出导入符号。
- `imports_query(queries)` —— 更丰富的导入查询。
- `idb_save()` —— 保存当前 IDB。

### 分析（`api_analysis`）

- `decompile(addr)` —— 反编译函数。
- `disasm(addr)` —— 反汇编函数。
- `analyze_function(addr)` —— 紧凑的单函数分析。
- `analyze_batch(queries)` —— 全面的逐函数分析。
- `analyze_component(addrs)` —— 分析一组相关函数。
- `func_profile(queries)` —— 函数指标和采样详情。
- `survey_binary()` —— 二进制概览。
- `basic_blocks(addrs)` —— 获取函数的基本块。
- `callees(addrs)` —— 获取函数调用的子函数。
- `xrefs_to(addrs)` —— 获取地址的交叉引用。
- `xref_query(queries)` —— 通用交叉引用查询。
- `xrefs_to_field(queries)` —— 获取结构体字段的交叉引用。
- `callgraph(roots)` —— 从根函数构建有界调用图。
- `trace_data_flow(addr)` —— 向前或向后跟踪交叉引用。
- `search_text(pattern)` —— 搜索渲染后的反汇编/注释。
- `export_funcs(addrs, format)` —— 导出函数数据（json、c_header、prototypes）。

### 搜索与模式匹配

- `find_regex(pattern)` —— 在字符串中执行不区分大小写的正则搜索。
- `find_bytes(patterns)` —— 字节模式搜索（例如 `48 8B ?? ??`）。
- `find(type, targets)` —— 搜索字符串、立即数、数据/代码引用。
- `find_xref_signatures(addrs)` —— 为引用某地址的代码位置创建签名。
- `insn_query(queries)` —— 按助记符/操作数过滤查询指令。

### 内存（`api_memory`）

- `get_bytes(regions)` —— 读取原始字节。
- `get_int(queries)` —— 读取整数（`u8`、`i32le`、`u64be` 等）。
- `get_string(addrs)` —— 读取以 null 结尾的字符串。
- `get_global_value(queries)` —— 按地址或名称读取全局值。
- `patch(patches)` —— 修补字节。
- `put_int(items)` —— 写入整数。

### 修改（`api_modify`）

- `set_comments(items)` —— 设置注释。
- `append_comments(items)` —— 追加注释。
- `add_bookmark(addr, name, prefix)` —— 添加 IDA 书签。
- `rename(batch)` —— 批量重命名函数、全局变量、局部变量、栈变量。
- `patch_asm(items)` —— 修补汇编指令。
- `declare_type(decls)` —— 声明 C 类型。
- `set_type(edits)` —— 将类型应用到函数/全局变量/局部变量/栈变量。
- `type_apply_batch(batch)` —— 批量类型编辑。
- `infer_types(addrs)` —— 在地址处推断类型。
- `define_func(items)` —— 定义函数。
- `define_code(items)` —— 将字节转换为代码指令。
- `undefine(items)` —— 取消定义项目。
- `force_recompile(addrs)` —— 使反编译器缓存失效。
- `set_op_type(items)` —— 设置操作数类型。
- `make_data(items)` —— 创建带类型的数据符号。

### 栈（`api_stack`）

- `stack_frame(addrs)` —— 获取栈变量。
- `declare_stack(items)` —— 创建栈变量。
- `delete_stack(items)` —— 删除栈变量。

### 类型（`api_types`）

- `read_struct(queries)` —— 在地址处读取结构体字段。
- `search_structs(filter)` —— 按名称搜索结构体。
- `type_query(queries)` —— 查询本地类型。
- `type_inspect(queries)` —— 检查具名类型。
- `enum_upsert(queries)` —— 创建或更新枚举。

### 签名（`api_sigmaker`）

- `make_signature(addrs)` —— 为地址创建字节签名。
- `make_signature_for_function(addrs)` —— 为函数入口创建签名。
- `make_signature_for_range(start, end)` —— 为指定范围创建签名。

### Python 执行（`api_python`）

- `py_eval(code)` —— 在 IDA 上下文中执行 Python。
- `py_exec_file(file_path)` —— 在 IDA 上下文中执行 Python 脚本文件。

### 复合 / 对比（`api_composite`）

- `diff_before_after(addr, action, action_args)` —— 重命名/类型/注释并返回修改前后的反编译对比。

## 调试器扩展

调试器工具属于 `dbg` 扩展组，需要 `?ext=dbg` 才能启用（参见[传输方式](#传输方式)）。

该扩展提供三种互补的 API：

1. **单次控制** —— 单个操作，立即返回。
2. **事件循环控制** —— 轮询原语，阻塞直到调试器状态变化并返回结构化快照。
3. **交互式 CLI I/O** —— 在 IDA 外部启动目标，捕获 stdin/stdout/stderr，然后将 IDA 附加到该 PID。

### 单次控制

- `dbg_start()` / `dbg_exit()` —— 启动或退出调试会话。
- `dbg_continue()` / `dbg_run_to(addr)` / `dbg_step_into()` / `dbg_step_over()` —— 执行控制。
- `dbg_status()` —— 当前调试器生命周期状态。
- `dbg_bps()` / `dbg_add_bp(addrs)` / `dbg_delete_bp(addrs)` / `dbg_toggle_bp(items)` / `dbg_set_bp_condition(items)` —— 断点。
- `dbg_regs()` / `dbg_regs_all()` / `dbg_regs_remote(tids)` / `dbg_gpregs()` / `dbg_stacktrace()` —— 寄存器和栈。
- `dbg_read(regions)` / `dbg_write(regions)` / `dbg_read_around(addr)` —— 内存。
- `dbg_list_processes()` / `dbg_modules()` / `dbg_resolve(name)` —— 进程和模块。
- `dbg_get_process_options()` / `dbg_set_process_options(...)` —— 启动选项。

### 事件循环控制

- `dbg_loop_init()` —— 获取调试器事件游标。
- `dbg_wait_event(cursor, timeout_ms)` —— 不恢复执行，等待事件。
- `dbg_continue_until_event(timeout_ms)` —— 恢复执行并等待下一个事件。
- `dbg_start_process_until_event(path, args, start_dir, timeout_ms)` —— 启动并等待。
- `dbg_start_current_file_until_event(timeout_ms)` —— 启动当前文件并等待。
- `dbg_attach_process_until_event(pid, timeout_ms)` —— 附加并等待。
- `dbg_add_temp_bp_and_continue(addr, timeout_ms)` —— 临时断点 + 继续。
- `dbg_get_snapshot(...)` —— 当前 IP、反汇编、寄存器、栈跟踪。
- `dbg_get_events(cursor, limit)` —— 读取已捕获事件。
- `dbg_diagnose(include_process_list)` —— 在不启动的情况下检查就绪状态。

### 交互式 CLI I/O

- `dbg_pty_start(path, args, start_dir)` —— 启动 CLI 进程。
- `dbg_pty_send(session_id, data)` —— 发送到 stdin。
- `dbg_pty_read(session_id, max_bytes, timeout_ms)` —— 读取 stdout/stderr。
- `dbg_pty_list()` —— 列出会话。
- `dbg_pty_close(session_id)` —— 终止会话。

典型工作流：

```text
1. dbg_pty_start("/path/to/crackme", args="flag.txt") → {session_id, pid}
2. 将 IDA 调试器附加到 pid
3. dbg_pty_read(session_id, timeout_ms=500) → "Enter password:"
4. dbg_pty_send(session_id, data="guess\n")
5. dbg_pty_read(session_id, timeout_ms=500) → 响应
6. dbg_pty_close(session_id)
```

### 实时调用面板

IDA 图形界面启动 MCP 服务时会自动打开 `MCP Activity` 子视图，也可从
`View -> Open subviews -> MCP Activity` 重新打开。面板实时显示工具名称、UTC
时间、执行耗时、状态和脱敏后的参数摘要，最多保留最近 500 条记录。

实时面板不会显示密码、令牌、Cookie 等敏感字段。完整的持久化调用记录仍存储
在 IDB 的 `$ ida_mcp.trace` netnode 中，可使用 `ida-mcp-trace-dump` 导出；导出
文件可能包含原始参数和返回值，应按敏感数据处理。

## MCP 资源

只读的可浏览状态：

- `ida://idb/metadata` —— IDB 文件信息（路径、架构、基址、大小、哈希）。
- `ida://idb/segments` —— 带权限的内存段。
- `ida://idb/entrypoints` —— 入口点。
- `ida://cursor` —— 当前光标位置和函数。
- `ida://selection` —— 当前选择范围。
- `ida://types` —— 所有本地类型。
- `ida://structs` —— 所有结构体/联合体。
- `ida://struct/{name}` —— 结构体定义。
- `ida://import/{name}` —— 导入详情。
- `ida://export/{name}` —— 导出详情。
- `ida://xrefs/from/{addr}` —— 来自某地址的交叉引用。

## Prompt 工程

LLM 可能会产生幻觉，尤其是在整数/字节转换方面。一个最简 prompt：

```md
你的任务是分析 IDA Pro 中的一个 crackme。使用 MCP 工具获取信息。

- 检查反编译结果并添加注释记录发现。
- 将变量和函数重命名为有意义的名称。
- 必要时修改变量和参数类型（尤其是指针和数组）。
- 如需更多细节，检查反汇编并添加注释。
- 永远不要自己转换进制。使用 `int_convert` MCP 工具。
- 不要暴力破解；仅从分析和简单 Python 脚本推导解决方案。
- 最后创建 report.md 记录发现和步骤。
- 找到解决方案后，向用户反馈并说明你找到的密码。
```

另一个系统化的 prompt：

```md
你的任务是完成一份全面、深入的逆向工程分析。

1. **反编译分析**：检查反编译输出，添加详细注释，关注实际功能。
2. **提升可读性**：重命名变量/函数，修正类型。
3. **深入挖掘**：需要时检查反汇编，记录底层行为。
4. **约束**：永远不要自己转换进制 —— 使用 `int_convert`；从实际分析中得出结论。
5. **文档**：生成 RE/*.md 文件记录发现和方法论。
```

### 提升 LLM 准确性的技巧

- 明确告诉 LLM 使用 `int_convert`，而不是自己转换数字。
- 涉及复杂数学时，可搭配专用的 math MCP。
- 尽可能先去混淆：字符串加密、导入哈希、控制流平坦化、代码加密、反反编译技巧。
- 使用 Lumina/FLIRT 解析开源库代码和 C++ STL，进一步提升准确性。

## 开发

添加工具很简单：在 `src/ida_pro_mcp/ida_mcp/api_*.py` 中新增一个 `@tool` 函数，它会被自动注册。

使用 MCP inspector 进行交互式测试：

```bash
npx -y @modelcontextprotocol/inspector
```

运行 headless 测试：

```bash
uv run ida-mcp-test tests/crackme03.elf -q
uv run ida-mcp-test tests/typed_fixture.elf -q
```

在两个 fixture 上测量覆盖率：

```bash
uv run coverage erase
uv run coverage run -m ida_pro_mcp.test tests/crackme03.elf -q
uv run coverage run --append -m ida_pro_mcp.test tests/typed_fixture.elf -q
uv run coverage report --show-missing
```

生成直接提交到 main 的变更日志：

```bash
git log --first-parent --no-merges 1.2.0..main "--pretty=- %s"
```

## 致谢

原始创意和实现来自 [mrexodia](https://github.com/mrexodia)、[can1357](https://github.com/can1357) 和贡献者。Headless `idalib` 功能由 [Willi Ballenthin](https://github.com/williballenthin) 贡献。
