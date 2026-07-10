# IDA MCP 调试器验证与分叉差异报告

- 日期：2026-07-10
- IDA 会话：`C:\Users\ZhenyeFan\Desktop\ctfTools\test\attachment\rpc-server.i64`
- MCP 端点：`http://127.0.0.1:13337/mcp?ext=dbg`
- 上游对比基线：`mrexodia/main`，提交 `abb2732`
- 功能实测基线：提交 `6698efc`

## 调试器验证结论

当前载入目标是 ELF64 x86-64 共享对象：

```text
file_type = ELF64 for x86-64 (Shared object)
processor = metapc
debugger = linux
state = not_running
```

因此，这个 IDB 不能使用 Windows 本地调试器直接执行。MCP 可以调用 IDA
的本地调试 API，但 Windows 调试后端无法运行 Linux ELF 目标。

通过 MCP/IDAPython 执行的调试器加载探针结果如下：

```text
load_debugger("win32", False) = False
load_debugger("linux", False) = False
load_debugger("linux", True)  = True
```

结论：

- `win32` 本地调试器不支持当前 ELF 目标。
- Windows 版 IDA 调试该目标时，必须使用远程 Linux 调试器。
- 限制来自目标格式与调试后端，不是 MCP 协议本身。

## 远程调试器验证

首次诊断时，远程 TCP 连接超时：

```text
hostname = 192.168.230.128
port     = 23946
remote_tcp.ok = false
error = TimeoutError: timed out
```

当时的 Windows 网络探针结果为：

```text
PingSucceeded    = True
TcpTestSucceeded = False
InterfaceAlias   = VMware Network Adapter VMnet8
SourceAddress    = 192.168.230.1
```

启动远程调试服务后，MCP 诊断结果变为：

```text
remote_tcp.ok = true
issues = []
```

但启动目标仍返回：

```text
dbg_start_current_file_until_event({"timeout_ms": 5000})
=> "Debugger start was cancelled"
dbg_status()
=> {"state": "not_running"}
```

远程调试服务已经可达，但 IDA 中的远程进程参数仍需使用 Linux 主机上的有效
路径、工作目录、加载器路径与启动参数。MCP 读取到的配置为：

```text
path      = rpc-server
args      = --library-path . ./rpc-server -H 127.0.0.1 -p 50052 -m 1
start_dir = C:\Users\ZhenyeFan\Desktop\ctfTools\test\attachment
hostname  = 192.168.230.128
port      = 23946
```

其中 `start_dir` 是 Windows 路径，在远程 Linux 主机上无效。再次调用
`dbg_start_process_until_event` 前，应将其改成远程主机中存放 `rpc-server`
及其运行时依赖的 Linux 目录。

## IDA 输出信息解释

IDA 终端中出现的信息与本次探针行为一致：

```text
.text:000055555555748D: Too many lines
connect: ... when connecting to 192.168.230.128:23946
```

- `Too many lines` 来自工具覆盖测试期间的大量反编译或反汇编文本渲染，属于
  输出截断提示，不表示调试器故障。
- `connect` 错误来自远程端口 `23946` 尚不可达时的首次连接尝试。
- 操作由 MCP RPC 调用触发，并非在 IDA 终端中手工输入命令，因此终端不会显示
  完整的 CLI 命令记录，只会显示 IDA 后端日志。

## 与上游项目相同的部分

相对于 `mrexodia/main`，本项目继承了以下核心能力：

- 标准输入输出与 HTTP 两种 MCP 代理服务。
- IDA 图形界面插件及本地 RPC 桥接层。
- 静态分析、反编译、反汇编、交叉引用、内存、类型、注释、补丁、栈变量、
  IDAPython、综合分析和特征码工具。
- 安装器、客户端配置及大部分测试框架。
- 截至 `abb2732` 的上游修复，包括适配 IDA 图形界面的 `idb_save` 实现。

## 本分叉独有的部分

相对于 `mrexodia/main`，当时的代码差异为：

```text
12 files changed, 2577 insertions(+), 311 deletions(-)
```

主要独有提交为：

```text
db0db0c feat(debug): add MCP-driven debugger event loop and interactive CLI I/O
4e06eb6 docs(debug): harden MCP debugger release notes
15674e3 fix(debug): keep MCP debugger loop polling-only
533c06f docs: sync README with current implementation and add Chinese translation
5aaee13 Merge branch 'mrexodia:main' into main
5b932a3 同步项目远程仓库地址到 NUDTSECURITY
6698efc 补充 IDA MCP 实测工具报告
73f2233 补充调试器验证与分叉差异报告
```

主要独有文件与功能如下：

- `src/ida_pro_mcp/ida_mcp/api_dbg_loop.py`
  - 提供 MCP 驱动的调试事件游标与轮询机制。
  - 提供调试进程参数读写和调试环境诊断。
  - 提供启动、附加、等待、继续等结构化调试操作。
  - 提供寄存器、调用栈、模块与邻近内存快照。
  - 提供 `dbg_pty_*` 交互式 CLI 进程控制。
- `src/ida_pro_mcp/ida_mcp/tests/test_api_dbg_loop.py`
  - 覆盖新增的调试事件循环 API。
- `README.zh.md`
  - 提供中文项目说明。
- `README.md` 与 `skills/idapython/SKILL.md`
  - 说明新增的 MCP 动态调试流程。
- `reports/ida_mcp_live_tool_report.md`
  - 提供全部 109 个 MCP 工具的实测证据。
- `pyproject.toml`
  - 将项目仓库元数据指向 `NUDTSECURITY/ida-pro-mcp`。

本分叉的核心差异不是一般性的 IDA 自动化，而是面向 MCP Agent 的动态调试
控制：事件轮询、状态快照、可控的继续/等待流程，以及通过 `dbg_pty_*` 实现的
标准输入输出交互。
