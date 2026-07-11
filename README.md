# IDA Pro MCP 动态调试增强版

[中文](README.md) | [English](README.en.md)

本项目基于 [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
进行二次开发，重点补充面向 Codex、Claude Code 等 MCP Agent 的动态调试闭环。

原项目已经提供的安装机制、静态分析、反编译、交叉引用、类型、内存、修改、
签名及 headless idalib 等能力，请直接参阅
[上游项目文档](https://github.com/mrexodia/ida-pro-mcp#readme)。本文只说明本分叉
新增的功能和使用方式。

## 二次开发目标

传统 IDA MCP 工具主要完成一次性调用，例如反编译函数、读取寄存器或执行继续。
对于 AI Agent，单次命令不能形成稳定的动态分析闭环：执行恢复后，Agent 还需要
等待暂停、识别事件、读取现场，再根据结果决定下一步。

本分叉增加了面向 Agent 的调试编排层：

```text
MCP Agent
  -> 启动或附加目标
  -> 等待 IDA 调试事件
  -> 获取寄存器、调用栈和反汇编快照
  -> 设置临时断点或读取内存
  -> 根据结果继续执行
```

整个流程由 MCP 工具调用驱动，不依赖 Debugger Hook 捕获调试状态。

## 新增功能

### 1. MCP 调试事件循环

新增 `api_dbg_loop.py`，通过 `ida_dbg.wait_for_next_event` 进行有界轮询，并返回
结构化事件和状态快照。

主要能力：

- 启动、附加、等待和继续执行直到下一事件。
- 使用事件游标增量读取 MCP 调试事件。
- 设置一次性断点并继续执行。
- 在一次调用中返回当前 IP、函数、通用寄存器、调用栈、断点和附近反汇编。
- 超时后返回结构化状态，不让 Agent 无限等待。

### 2. 调试环境诊断

新增面向远程调试的配置和诊断能力：

- 读取和设置 IDA 调试进程路径、参数、工作目录、远程主机和端口。
- 检查远程调试端口连通性。
- 枚举调试器可见进程和已加载模块。
- 解析调试地址空间中的符号。
- 检查本地路径与远程目标配置不一致等常见问题。
- 兼容 IDA 9.2 的进程选项调用，并正确保留未修改的调试端口。

### 3. 交互式 CLI I/O

`dbg_pty_*` 工具可以启动本机 CLI 进程，并通过 MCP 持续读写
stdin/stdout/stderr。Agent 可以驱动菜单程序、协议客户端或命令行题目，同时将
IDA 调试器附加到返回的 PID。

### 4. MCP Activity 实时面板

IDA 中新增 `MCP Activity` 子视图，实时显示：

- UTC 调用时间。
- MCP 工具名称。
- 执行耗时和成功/错误状态。
- 有界、脱敏后的参数摘要。

面板最多保留最近 500 条记录，密码、令牌、Cookie 等字段在进入面板缓存前即被
脱敏。完整审计记录仍写入 IDB 的 `$ ida_mcp.trace` netnode，可使用
`ida-mcp-trace-dump` 导出。

## 新增 MCP 工具

| 类别 | 工具 |
|---|---|
| 事件与生命周期 | `dbg_loop_init`、`dbg_get_events`、`dbg_wait_event`、`dbg_start_process_until_event`、`dbg_start_current_file_until_event`、`dbg_attach_process_until_event`、`dbg_continue_until_event`、`dbg_add_temp_bp_and_continue` |
| 配置与诊断 | `dbg_get_process_options`、`dbg_set_process_options`、`dbg_list_processes`、`dbg_diagnose`、`dbg_resolve`、`dbg_modules` |
| 状态与内存 | `dbg_get_snapshot`、`dbg_read_around` |
| CLI I/O | `dbg_pty_start`、`dbg_pty_send`、`dbg_pty_read`、`dbg_pty_list`、`dbg_pty_close` |

## 快速开始

要求与上游一致：Python 3.11+、IDA Pro 8.3+，建议使用 IDA Pro 9.x；不支持
IDA Free。

```powershell
git clone https://github.com/NUDTSECURITY/ida-pro-mcp.git
cd ida-pro-mcp
uv sync
uv run ida-pro-mcp --install codex,claude-code --transport streamable-http --scope global
```

安装后完全重启 IDA 和 MCP 客户端。在 IDA 中打开目标文件，MCP 插件默认自动
启动，也可使用 `Edit -> Plugins -> MCP` 或 `Ctrl-Alt-M`。

动态调试工具属于 `dbg` 扩展组，连接 URL 必须包含：

```text
http://127.0.0.1:13337/mcp?ext=dbg
```

安装器默认写入不带扩展参数的基础 URL；需要动态调试时，请在 Codex、Claude Code
等客户端配置中将 URL 改为上面的地址，然后重启客户端。

使用 stdio 代理时可显式指定 IDA RPC：

```powershell
uv run ida-pro-mcp --ida-rpc "http://127.0.0.1:13337?ext=dbg"
```

## 动态调试流程

建议 Agent 按以下顺序调用：

```text
1. dbg_diagnose                 检查调试器、目标配置和远程连接
2. dbg_set_process_options      设置目标路径、参数和工作目录
3. dbg_start_process_until_event 启动目标并等待首次事件
4. dbg_get_snapshot             获取寄存器、调用栈和反汇编
5. dbg_add_temp_bp_and_continue 运行到关键地址
6. dbg_read_around              检查寄存器或指针附近内存
7. dbg_continue_until_event     继续到下一事件并重复分析
```

Windows 版 IDA 调试 Linux ELF 时，需要远程 Linux 调试器，并且 `path` 与
`start_dir` 必须是远程 Linux 主机上的绝对路径。

## 当前边界

- 调试器后端仍由 IDA 提供，本项目不会绕过目标格式和操作系统限制。
- 事件只在 MCP 调用等待期间轮询，不是常驻后台事件流。
- 不使用 Debugger Hook，因此不会记录 MCP 未轮询期间的全部中间事件。
- `dbg_pty_*` 当前使用本机进程管道，不直接控制远程 Linux 目标的终端。
- 启动远程目标前，需要用户准备目标文件、依赖库和 IDA remote debug server。

## 验证与报告

- [全部 MCP 工具实测报告](reports/ida_mcp_live_tool_report.md)
- [调试器与上游差异报告](reports/ida_mcp_debugger_and_fork_delta.md)

核心测试：

```powershell
$env:IDADIR = "C:\Program Files\IDA Professional 9.2"
ida-mcp-test tests/crackme03.elf --category api_dbg_loop --quiet
ida-mcp-test tests/typed_fixture.elf --category trace --quiet
python -m pytest tests/test_mcp_spec_tools_list.py tests/test_mcp_spec_schema_generation.py
```

## 上游与许可证

- 上游项目：[mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
- 当前分叉：[NUDTSECURITY/ida-pro-mcp](https://github.com/NUDTSECURITY/ida-pro-mcp)
- 许可证：[MIT](LICENSE)

本项目保留上游作者和贡献者信息，并在其 MIT 许可证基础上继续开发。
