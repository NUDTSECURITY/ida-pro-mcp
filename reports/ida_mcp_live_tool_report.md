# IDA Pro MCP 全工具实测报告

- 日期：2026-07-10
- MCP 端点：`http://127.0.0.1:13337/mcp?ext=dbg`
- IDB：`C:\Users\ZhenyeFan\Desktop\ctfTools\test\attachment\rpc-server.i64`
- 模块：`rpc-server`，镜像基址 `0x555555554000`
- 样例入口：`main = 0x555555556ce1`
- 样例只读数据地址：`0x555555558000`
- 工具总数：`109`
- 状态统计：通过 `85`，需调试会话 `20`，受调试配置阻塞 `4`

## 总体结论

- 已通过真实 MCP 会话完成初始化、`tools/list`、静态分析、反编译、反汇编、
  内存读取、类型操作、注释、特征码和 IDAPython 执行测试。
- `dbg_pty_*` 已验证类 CLI 动态交互：MCP 能启动子进程、写入标准输入并持续
  读取标准输出和标准错误。
- IDA 调试控制工具均能由 MCP 路由。步进、寄存器和调试内存快照等能力需要
  活动的 IDA 调试会话，因此未在 `not_running` 状态下伪造“通过”结果。
- 调试启动类工具已进入真实远程 Linux 调试流程，但当时受到远程路径和启动
  参数配置阻塞；这不属于 MCP 工具不可调用。

## 动态 CLI 实测证据

调用序列：

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

实际标准输出：

```text
ready

echo:hello-from-mcp
```

## 工具逐项结果

| 序号 | 工具 | 状态 | 功能 | 调用示例 |
|---:|---|---|---|---|
| 1 | `server_health` | 通过 | 检查 MCP 服务和当前 IDB 就绪状态 | `{}` |
| 2 | `lookup_funcs` | 通过 | 按函数名或地址查询函数 | `{"queries":["main","0x555555556ce1"]}` |
| 3 | `int_convert` | 通过 | 转换整数的进制、宽度与表示形式 | `{"inputs":[{"text":"0x10"},{"text":"1234","size":4}]}` |
| 4 | `list_funcs` | 通过 | 分页列出函数并支持过滤 | `{"queries":[{"offset":0,"count":3}]}` |
| 5 | `func_query` | 通过 | 使用复合条件查询函数 | `{"queries":[{"filter":"main","count":3}]}` |
| 6 | `list_globals` | 通过 | 分页列出全局符号 | `{"queries":[{"offset":0,"count":3}]}` |
| 7 | `entity_query` | 通过 | 按实体类型、字段和分页条件查询 IDB | `{"queries":[{"kind":"functions","filter":"main","count":3}]}` |
| 8 | `imports` | 通过 | 分页列出导入符号及所属模块 | `{"offset":0,"count":3}` |
| 9 | `imports_query` | 通过 | 使用复合条件查询导入符号 | `{"queries":[{"filter":"printf","count":3}]}` |
| 10 | `idb_save` | 通过 | 将当前数据库保存为压缩的 `.i64` 或 `.idb` | `{}` |
| 11 | `find_regex` | 通过 | 使用正则表达式搜索字符串 | `{"pattern":"rpc","limit":5}` |
| 12 | `search_text` | 通过 | 在 IDA 渲染后的列表文本中搜索 | `{"pattern":"main"}` |
| 13 | `decompile` | 通过 | 反编译指定函数并返回伪代码 | `{"addr":"0x555555556ce1"}` |
| 14 | `disasm` | 通过 | 分页反汇编指定函数 | `{"addr":"0x555555556ce1","max_instructions":12}` |
| 15 | `func_profile` | 通过 | 汇总函数规模、引用和复杂度指标 | `{"queries":[{"filter":"main","count":1}]}` |
| 16 | `analyze_batch` | 通过 | 批量执行函数综合分析 | `{"queries":[{"addr":"0x555555556ce1"}]}` |
| 17 | `xrefs_to` | 通过 | 查询指向地址或符号的交叉引用 | `{"addrs":"0x555555556ce1"}` |
| 18 | `xref_query` | 通过 | 按方向、类型和分页条件查询交叉引用 | `{"queries":[{"addr":"0x555555556ce1","direction":"to","count":5}]}` |
| 19 | `xrefs_to_field` | 通过 | 查询指向结构体字段的交叉引用 | `{"queries":[{"struct":"codex_missing_struct","field":"missing"}]}` |
| 20 | `callees` | 通过 | 查询函数直接调用的子函数 | `{"addrs":"0x555555556ce1"}` |
| 21 | `find_bytes` | 通过 | 搜索支持通配符的字节模式 | `{"patterns":"55 48 89 E5","limit":5}` |
| 22 | `basic_blocks` | 通过 | 获取函数控制流图基本块 | `{"addrs":"0x555555556ce1"}` |
| 23 | `find` | 通过 | 搜索字符串、立即数或引用 | `{"type":"string","targets":"rpc","limit":5}` |
| 24 | `insn_query` | 通过 | 按助记符、操作数和函数范围查询指令 | `{"queries":[{"func":"0x555555556ce1","count":5,"include_disasm":true}]}` |
| 25 | `export_funcs` | 通过 | 以 JSON、C 头文件或原型格式导出函数 | `{"addrs":"0x555555556ce1","format":"json"}` |
| 26 | `callgraph` | 通过 | 按深度和节点上限构建调用图 | `{"roots":"0x555555556ce1","max_depth":1,"max_nodes":20}` |
| 27 | `get_bytes` | 通过 | 读取 IDB 地址空间中的原始字节 | `{"regions":[{"addr":"0x555555556ce1","size":8}]}` |
| 28 | `get_int` | 通过 | 按指定整数类型读取值 | `{"queries":[{"addr":"0x555555556ce1","type":"u8"}]}` |
| 29 | `get_string` | 通过 | 读取指定地址的字符串 | `{"addrs":"0x555555558000"}` |
| 30 | `get_global_value` | 通过 | 按地址或符号读取全局变量值 | `{"queries":[{"addr":"0x555555558000"}]}` |
| 31 | `patch` | 通过 | 使用十六进制数据修补 IDB 字节 | `{"patches":[{"addr":"0x555555556ce1","data":"55"}]}` |
| 32 | `put_int` | 通过 | 按整数类型写入 IDB 值 | `{"items":[{"addr":"0x555555556ce1","value":85,"type":"u8"}]}` |
| 33 | `declare_type` | 通过 | 向本地类型库声明 C 类型 | `{"decls":["struct codex_mcp_test_type { int value; };"]}` |
| 34 | `enum_upsert` | 通过 | 幂等创建或扩展本地枚举 | `{"queries":[{"name":"codex_mcp_test_enum","members":{"CODEX_MCP_TEST_A":1}}]}` |
| 35 | `read_struct` | 通过 | 按结构体类型解析内存字段 | `{"queries":[{"addr":"0x555555558000","type":"codex_mcp_test_type"}]}` |
| 36 | `search_structs` | 通过 | 按名称搜索本地结构体和联合体 | `{"filter":"codex_mcp_test*"}` |
| 37 | `type_query` | 通过 | 使用结构化条件查询本地类型 | `{"queries":[{"filter":"codex_mcp_test*","count":5}]}` |
| 38 | `type_inspect` | 通过 | 查看类型大小、类别、声明和成员 | `{"queries":["codex_mcp_test_type"]}` |
| 39 | `set_type` | 通过 | 为函数、全局量、局部量或栈变量设置类型 | `{"edits":[{"kind":"function","addr":"0x555555556ce1","type":"int main(int argc, char **argv);","dry_run":true}]}` |
| 40 | `type_apply_batch` | 通过 | 批量应用类型修改并汇总结果 | `{"batch":{"edits":[{"kind":"function","addr":"0x555555556ce1","type":"int main(int argc, char **argv);"}],"dry_run":true}}` |
| 41 | `infer_types` | 通过 | 推断并应用目标地址的候选类型 | `{"addrs":"0x555555556ce1"}` |
| 42 | `add_bookmark` | 通过 | 在指定地址新增或替换书签 | `{"addr":"0x555555556ce1","name":"codex_mcp_smoke","prefix":"codex"}` |
| 43 | `set_comments` | 通过 | 设置反汇编和反编译视图注释 | `{"items":[{"addr":"0x555555556ce1","comment":"codex mcp smoke test","repeatable":false}]}` |
| 44 | `append_comments` | 通过 | 去重追加地址注释 | `{"items":[{"addr":"0x555555556ce1","comment":"codex mcp smoke append","repeatable":false}]}` |
| 45 | `patch_asm` | 通过 | 将汇编指令编码后写入目标地址 | `{"items":[{"addr":"0x555555556ce1","asm":"nop","dry_run":true}]}` |
| 46 | `rename` | 通过 | 批量重命名函数、全局量、局部量和栈变量 | `{"batch":{"func":[{"addr":"0x555555556ce1","name":"main"}],"dry_run":true}}` |
| 47 | `define_func` | 通过 | 在指定地址定义函数 | `{"items":[{"addr":"0x555555556ce1"}]}` |
| 48 | `define_code` | 通过 | 将原始字节定义为代码指令 | `{"items":[{"addr":"0x555555556ce1"}]}` |
| 49 | `undefine` | 通过 | 取消地址范围内的数据或代码定义 | `{"items":[{"addr":"0x0","size":0}]}` |
| 50 | `force_recompile` | 通过 | 清除 Hex-Rays 缓存并强制下次重新反编译 | `{"items":[{"addr":"0x555555556ce1"}]}` |
| 51 | `set_op_type` | 通过 | 设置指令操作数的解释类型 | `{"items":[{"addr":"0x555555556ce1","op_n":0,"kind":"offset","target_addr":"0x555555556ce1"}]}` |
| 52 | `make_data` | 通过 | 在地址处创建指定类型的数据符号 | `{"items":[{"addr":"0x555555558000","type":"byte","name":"codex_mcp_test_byte","delete_existing":false}]}` |
| 53 | `stack_frame` | 通过 | 读取函数栈帧及栈变量 | `{"addrs":"0x555555556ce1"}` |
| 54 | `declare_stack` | 通过 | 按偏移和类型创建栈变量 | `{"items":[{"addr":"0x555555556ce1","offset":"-4","name":"codex_stack_test","ty":"int"}]}` |
| 55 | `delete_stack` | 通过 | 按名称或偏移删除栈变量 | `{"items":[{"addr":"0x555555556ce1","name":"codex_stack_test"}]}` |
| 56 | `dbg_start` | 受调试配置阻塞 | 启动当前目标的 IDA 调试会话 | `{}` |
| 57 | `dbg_status` | 通过 | 查询调试器生命周期状态和当前指令地址 | `{}` |
| 58 | `dbg_exit` | 需调试会话 | 终止活动调试会话 | `{}` |
| 59 | `dbg_continue` | 需调试会话 | 继续运行被调试进程 | `{}` |
| 60 | `dbg_run_to` | 需调试会话 | 运行到指定地址 | `{"addr":"0x555555556ce1"}` |
| 61 | `dbg_step_into` | 需调试会话 | 单步执行并进入调用 | `{}` |
| 62 | `dbg_step_over` | 需调试会话 | 单步执行并越过调用 | `{}` |
| 63 | `dbg_bps` | 通过 | 列出断点、启用状态和条件 | `{}` |
| 64 | `dbg_add_bp` | 通过 | 批量添加断点 | `{"addrs":"0x555555556ce1"}` |
| 65 | `dbg_delete_bp` | 通过 | 批量删除断点 | `{"addrs":"0x555555556ce1"}` |
| 66 | `dbg_toggle_bp` | 通过 | 批量启用或禁用断点 | `{"items":[{"addr":"0x555555556ce1","enabled":true}]}` |
| 67 | `dbg_set_bp_condition` | 通过 | 设置或清除断点条件 | `{"items":[{"addr":"0x555555556ce1","condition":"","language":""}]}` |
| 68 | `dbg_regs_all` | 需调试会话 | 读取所有调试线程的完整寄存器集 | `{}` |
| 69 | `dbg_regs_remote` | 需调试会话 | 按线程编号读取完整寄存器集 | `{"tids":[1]}` |
| 70 | `dbg_regs` | 需调试会话 | 读取当前线程完整寄存器集 | `{}` |
| 71 | `dbg_gpregs_remote` | 需调试会话 | 按线程编号读取通用寄存器 | `{"tids":[1]}` |
| 72 | `dbg_gpregs` | 需调试会话 | 读取当前线程通用寄存器 | `{}` |
| 73 | `dbg_regs_named_remote` | 需调试会话 | 读取指定线程的指定寄存器 | `{"thread_id":1,"register_names":"RIP,RSP"}` |
| 74 | `dbg_regs_named` | 需调试会话 | 读取当前线程的指定寄存器 | `{"register_names":"RIP,RSP"}` |
| 75 | `dbg_stacktrace` | 通过 | 获取当前调用栈及模块、符号上下文 | `{}` |
| 76 | `dbg_read` | 需调试会话 | 读取被调试进程内存 | `{"regions":[{"addr":"0x555555556ce1","size":8}]}` |
| 77 | `dbg_write` | 需调试会话 | 写入被调试进程内存 | `{"regions":[{"addr":"0x555555556ce1","data":"55"}]}` |
| 78 | `dbg_loop_init` | 通过 | 初始化 MCP 调试事件轮询并返回事件游标 | `{}` |
| 79 | `dbg_get_events` | 通过 | 获取此前等待或继续操作产生的调试事件 | `{}` |
| 80 | `dbg_get_process_options` | 通过 | 读取 IDA 调试进程启动配置 | `{}` |
| 81 | `dbg_set_process_options` | 通过 | 通过 MCP 修改调试进程启动配置 | `{"path":"rpc-server","port":23946}` |
| 82 | `dbg_list_processes` | 通过 | 列出所选调试器可见的进程 | `{}` |
| 83 | `dbg_resolve` | 通过 | 在调试地址空间解析符号或地址 | `{"name":"main"}` |
| 84 | `dbg_modules` | 需调试会话 | 列出被调试进程已加载模块及基址 | `{}` |
| 85 | `dbg_diagnose` | 通过 | 在启动或附加前诊断调试环境 | `{}` |
| 86 | `dbg_wait_event` | 需调试会话 | 不恢复执行，仅等待下一调试事件 | `{"timeout_ms":1}` |
| 87 | `dbg_start_process_until_event` | 受调试配置阻塞 | 启动指定调试进程并等待状态或事件 | `{"path":"Z:/definitely/not/found.exe","timeout_ms":1}` |
| 88 | `dbg_start_current_file_until_event` | 受调试配置阻塞 | 启动当前输入文件并等待状态或事件 | `{"timeout_ms":1}` |
| 89 | `dbg_attach_process_until_event` | 受调试配置阻塞 | 附加进程并等待状态或事件 | `{"pid":0,"timeout_ms":1}` |
| 90 | `dbg_get_snapshot` | 需调试会话 | 获取面向 Agent 的调试状态快照 | `{"include_registers":false,"include_stack":false,"disasm_radius":1}` |
| 91 | `dbg_continue_until_event` | 需调试会话 | 继续执行并等待下一事件或超时 | `{"timeout_ms":1}` |
| 92 | `dbg_add_temp_bp_and_continue` | 需调试会话 | 添加一次性断点、继续执行并等待事件 | `{"addr":"0x555555556ce1","timeout_ms":1}` |
| 93 | `dbg_read_around` | 需调试会话 | 以十六进制和 ASCII 读取地址邻近内存 | `{"addr":"0x555555556ce1","radius":8}` |
| 94 | `dbg_pty_start` | 通过 | 启动可交互 CLI 进程并捕获标准流 | `{"path":"C:\\ProgramData\\miniconda3\\python.exe","args":"-c \"print('ready')\""}` |
| 95 | `dbg_pty_send` | 通过 | 向 CLI 会话标准输入写入数据 | `{"session_id":"<session_id>","data":"hello\\n"}` |
| 96 | `dbg_pty_read` | 通过 | 增量读取 CLI 会话标准输出和标准错误 | `{"session_id":"<session_id>","timeout_ms":1000,"max_bytes":4096}` |
| 97 | `dbg_pty_list` | 通过 | 列出由 MCP 启动的 CLI 会话 | `{}` |
| 98 | `dbg_pty_close` | 通过 | 关闭 CLI 会话并终止其进程 | `{"session_id":"<session_id>"}` |
| 99 | `py_eval` | 通过 | 在 IDA 上下文执行 Python 代码 | `{"code":"result = 1 + 2"}` |
| 100 | `py_exec_file` | 通过 | 在 IDA 上下文执行完整 Python 脚本文件 | `{"file_path":"<temp>/ida_mcp_py_exec_test.py"}` |
| 101 | `survey_binary` | 通过 | 一次调用获取二进制元数据、段、入口和重点对象概览 | `{}` |
| 102 | `analyze_function` | 通过 | 聚合分析单个函数的伪代码、常量、引用和调用关系 | `{"addr":"0x555555556ce1"}` |
| 103 | `analyze_component` | 通过 | 将相关函数作为组件分析内部调用图和共享数据 | `{"addrs":["0x555555556ce1"]}` |
| 104 | `diff_before_after` | 通过 | 修改名称、类型或注释并比较前后反编译结果 | `{"addr":"0x555555556ce1","action":"set_comment","action_args":{"comment":"codex diff smoke"}}` |
| 105 | `trace_data_flow` | 通过 | 沿交叉引用多跳跟踪正向或反向数据流 | `{"addr":"0x555555556ce1"}` |
| 106 | `make_signature` | 通过 | 为地址生成尽可能短的唯一字节特征码 | `{"addrs":"0x555555556ce1","max_length":32}` |
| 107 | `make_signature_for_function` | 通过 | 为函数入口生成唯一字节特征码 | `{"addrs":"0x555555556ce1","max_length":64}` |
| 108 | `make_signature_for_range` | 通过 | 为指定地址区间生成字节特征码 | `{"start":"0x555555556ce1","end":"0x555555556ce9"}` |
| 109 | `find_xref_signatures` | 通过 | 为指向目标地址的代码引用点生成特征码 | `{"addrs":"0x555555556ce1"}` |

## 状态定义

- `通过`：在本次 IDA 会话中直接调用并返回符合工具协议的结构化结果。
- `需调试会话`：工具入口和参数校验正常，但语义上要求活动或暂停中的 IDA
  调试会话；本次会话状态为 `not_running`。
- `受调试配置阻塞`：工具已进入真实调试启动或附加路径，但远程 Linux 目标
  配置不完整，未能建立活动调试会话。
- 对可写工具优先采用空操作、`dry_run` 或低风险样例。部分测试写入了专用测试
  注释、书签、类型和枚举，用于验证完整写入链路。
