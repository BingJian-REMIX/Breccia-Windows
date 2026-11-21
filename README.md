# BRECCIA // PE STRUCTURE & SECURITY INSPECTOR

Windows PE 结构、安全透视、静态逆向与动态调试工具。C# / WPF。静态部分只读解析；动态部分由你显式 `LAUNCH` / `ATTACH` 才会运行目标。

NuGet 依赖：**PeNet 6.1.2**（PE 结构解析）、**Iced 1.22.0**（x86/x64 反汇编，纯托管无原生 DLL）。
UI、主题、交互全部原生 WPF，无第三方控件库 / MVVM 框架。

## 环境要求

- Windows
- .NET 10 SDK（构建）或 .NET 10 Desktop Runtime（仅运行已编译版本）
- 目标框架 `net10.0-windows`（满足 .NET 8+；PeNet 6.1.2 只发布 `net10.0` lib）

## 构建与运行

```bash
git clone https://cnb.cool/RLRS-Studio/Breccia-Windows.git
cd Breccia-Windows
dotnet restore
dotnet run -c Release
```

直接带文件启动：

```bash
dotnet run -c Release -- "C:/Windows/System32/notepad.exe"
```

发布（framework-dependent，win-x64，多文件）：

```bash
dotnet publish Breccia.csproj -c Release -r win-x64 --self-contained false \
  -p:PublishSingleFile=false -p:DebugType=none -o publish
```

产物是 `Breccia.exe`（apphost，约 160 KB）+ `Breccia.dll` + `PeNet.dll` + `Iced.dll` + 两个 json，需 .NET 10 桌面运行时。

不要用 `PublishSingleFile` 分发：单文件会先把托管程序集解出再加载，叠加调试器行为，杀软启发式命中率明显更高（见「杀软误报」）。`bin/`、`obj/`、`publish/` 均不纳入版本库。

## 使用

拖入 `.exe` / `.dll` / `.sys` 到顶部区域，或点击该区域 / 按 `Ctrl+O` 选择文件。

| 操作 | 快捷键 / 入口 |
|---|---|
| 打开文件 | `Ctrl+O`、点击 Drop Zone、拖拽、命令行参数 |
| 导出 JSON | `Ctrl+S` 或 `EXPORT JSON` |
| 导出 TXT | `EXPORT TXT` |
| 聚焦搜索 | `Ctrl+F` |
| 展开 / 折叠全部 | `EXPAND ALL` / `COLLAPSE ALL` |
| 复制节点 / 子树 | TreeView 右键菜单 |

搜索框实时过滤当前标签页的报告树，保留命中节点及其祖先链。

报告区分三个标签，`Ctrl+1` / `Ctrl+2` / `Ctrl+3` 或点击切换：

| 标签 | 内容 |
|---|---|
| `STRUCTURE` | PE 结构、安全透视、风险摘要 |
| `REVERSE` | 反汇编、函数、IAT 交叉引用、字符串 |
| `DYNAMIC` | 内置调试器：启动 / 附加、断点、单步、寄存器、内存 |

## 分析能力

**PE 结构（17 个分组）**：标识、DOS/NT/Optional 头、14 个数据目录、节区（VA / RAW / Flags / Shannon 熵）、导入表、延迟导入、导出表、资源与版本信息、重定位、调试目录与 PDB 路径、TLS 回调、Load Config、CLR 元数据流、x64 异常表、Authenticode 证书、SHA256 / SHA1 / MD5 / ImpHash / TypeRefHash、风险摘要。

**安全透视**：节名壳标记（UPX / VMP / ASPack / Themida …）、高熵节（≥ 7.0）、W+X 节、入口点落点异常、导入表稀疏、ASLR / DEP 位、签名校验、30 个敏感 API 三级分类（一律 `#EF4444` 红字）、注入链组合检测、TLS 回调 → 0–100 风险分与置顶风险摘要。

**深度逆向（`REVERSE` 标签，10 个分组）**：

| 分组 | 内容 |
|---|---|
| DISASSEMBLY | 入口点 + 函数序言（x86 `55 8B EC`、x64 `48 89 5C 24` 等）+ 敏感调用点所在函数，Iced 线性反汇编；每行 `地址 / 原始字节 / 指令`，敏感调用行标红并注明 `DLL!API` |
| FUNCTIONS | 函数清单：RVA、指令数、callee 数、`SYSCALL` / `PEB` / `RDTSC` / `CPUID` / `INT3` 标记 |
| CALL GRAPH | 内部边数、按出入度排序的 hub 函数、边样例 |
| IAT XREFS | 遍历导入描述符还原 IAT 槽地址，再用 `FF 15` 全节区扫描定位调用点；敏感 API 逐条列出调用地址，其余导入汇总 |
| STRINGS | ASCII / UTF-16LE 字符串按类别分组：URL、IP、命令行/LOLBin、注册表、文件路径、反虚拟化、可疑指示、模块名、User-Agent |
| TOOLCHAIN | 入口点字节签名（UPX / ASPack / MEW）、编译器线索（MSVC/Universal CRT、MinGW、Delphi、VB6、Go、Rust）、动态解析检测 |
| RICH HEADER | 解析 DOS stub 中的 Rich 头（XOR key、product/build、对象计数） |
| OVERLAY | 最后节区之后的附加数据：偏移、大小、熵、预览字节 |
| ENTROPY MAP | 每节区 48 段分块熵条形图（`▁`–`█`），高熵段标红 |
| ANOMALIES | 节区越界 / VA 重叠、序号导入、壳指纹、直接 `syscall`、敏感调用点、PEB 读取、RDTSC+CPUID、反虚拟化字符串、LOLBin 引用、高熵 overlay |

逆向发现项会计入风险分（敏感调用点、直接 syscall、壳指纹、PEB 读取、overlay 等各自独立权重）。

## 动态调试（`DYNAMIC` 标签）

`LAUNCH` 用 `DEBUG_ONLY_THIS_PROCESS` 启动当前加载的文件，在 OEP 自动下断；`ATTACH` 接管已有 pid（同用户进程）。

| 操作 | 入口 |
|---|---|
| 启动 / 附加 | `LAUNCH`（无会话时 `F5` 等同）/ `ATTACH` + PID |
| 运行 / 单步 / 步过 | `F5` / `F7` / `F8` |
| 断点 | `F9` 在光标处开关；`0xCC` 写入目标代码页，移除时还原 |
| 跟随地址 | 地址栏输入 `0x...` 后 `GO`；留空 = 回到 RIP；点击树里的模块 / 断点地址也可跟随 |
| 动态 IAT | `IAT`：按内存中的导入描述符还原每个槽的解析地址，并校验目标是否落在声明的 DLL 内（`out-of-module` = 转发导出或 hook，逐条看） |
| 内存导出 | `DUMP`：导出光标所在已提交区域（上限 64 MB） |

面板：左 = SESSION / MODULES / THREADS / BREAKPOINTS / IAT / EVENTS；中 = 光标处反汇编（Iced）+ 十六进制内存；右 = 寄存器 + EFLAGS 位。

实现要点：

- 调试循环独占一个后台线程，`CreateProcess` / `DebugActiveProcess` 必须在同一线程（Windows 只认创建者线程收事件）。
- x64 与 WOW64 双上下文：`CONTEXT` 必须 16 字节对齐，否则 `GetThreadContext` 返回 `ERROR_INVALID_HANDLE`；32 位目标走 `Wow64GetThreadContext`，断点异常码是 `0x4000001F`（不是 `0x80000003`）。
- 断点命中后先还原原始字节、回退 IP，再在 `Run` 时用单步越过断点并重新写回，避免同一断点无限命中。
- 首次异常只对致命码（AV / 非法指令 / 除零 / 特权指令 / fastfail / 加载失败）停下，`0x406D1388`（MSVC 线程命名）这类运行时簿记异常直接放行。
- 单步用 EFLAGS.TF；步过对 `call` 在下一指令下临时断点，其余指令单步。

**动态调试会真实执行目标进程。不可信样本请放进虚拟机 / 快照。** 断点写入会改动目标代码页，移除断点或结束会话即还原。

## 杀软误报（必读）

程序本身实现了一个调试器，运行时的调用序列是：

```
CreateProcess(DEBUG_ONLY_THIS_PROCESS) → OpenProcess → ReadProcessMemory
→ VirtualProtectEx(PAGE_EXECUTE_READWRITE) → WriteProcessMemory → 修改目标代码页
```

这与进程注入器 / 内存补丁器同构，行为引擎会直接判定并**结束进程**（不是删除文件，文件通常还在）。国内杀软（火绒等）默认开启行为防护，命中后会弹窗并终止 Breccia。

已做的降误报措施：

- 分发改为多文件（不再单文件自解压到临时目录）；
- 补全 `Product` / `Company` / `Version` / `Description` 版本资源（无版本信息的 PE 会被加分）；
- 发布不带 PDB。

仍需你手动加白，因为调试行为本身无法去掉（去掉等于删掉功能）：

1. 火绒 → 防护中心 → 信任区 → 添加文件 `publish\Breccia.exe`，并添加目录 `publish\`；
2. 或在行为拦截弹窗里选「允许程序运行」；
3. 加白后重新启动 Breccia；已拦截过的进程需要重启程序。

自行核验：源码全量在仓库，可 `dotnet build` 自己编译对比；`publish/Breccia.exe` 的 SHA256 见发布提交说明。

静态两个标签（`STRUCTURE` / `REVERSE`）不碰目标进程，只读取文件，不会被行为引擎拦截。

## 工程结构

| 文件 | 职责 |
|---|---|
| `PeAnalyzer.cs` | 纯数据层：模型 + PE 解析 + 安全规则 + 风险评分 |
| `ReAnalyzer.cs` | 逆向数据层：反汇编、函数识别、IAT 交叉引用、字符串、指纹、Rich header、overlay、熵图、异常 |
| `Dyn/NativeDebug.cs` | Win32 调试 API 的 P/Invoke 与结构布局（`DEBUG_EVENT`、`CONTEXT`、`MEMORY_BASIC_INFORMATION`） |
| `Dyn/DebugSession.cs` | 调试引擎：事件循环、断点、单步、上下文、内存、动态 IAT 解析、导出 |
| `MainWindow.xaml` / `.xaml.cs` | 暗黑无边框 UI、三标签渲染与交互 |
| `MainWindow.Dynamic.cs` | `DYNAMIC` 标签的渲染与命令转发（`partial class MainWindow`） |
| `App.xaml` / `.xaml.cs` | 应用入口、命令行参数加载、未处理异常落盘（`%TEMP%reccia-crash.log`） |
| `Breccia.csproj` | `net10.0-windows` + `UseWPF` + PeNet + Iced + 版本资源 |

PeNet 的集合属性可空且 lazy 解析对畸形 PE 会抛异常，所有可选结构统一走 `Arr<T>` / `Safe<T>` 防御式读取；Iced 解码遇 `INVALID` 立即停止，单个函数最多 4 KB / 56 条指令。

导出说明：TXT 报告包含 STRUCTURE 与 REVERSE 两部分；JSON 只含结构与风险（`ReSummary` 汇总逆向计数），避免把数千条反汇编行塞进机器可读报告。

## 已知限制

- 风险分是启发式透视结果，不是恶意判定。系统 DLL 会偏高（例如 `kernel32.dll` 因导入并调用注入类 API 得 85/CRITICAL）。
- 静态反汇编是线性反汇编 + 序言启发式，**不是**控制流图重建：不处理代码与数据混排、间接跳转表、混淆代码；加壳程序的指令视图不可信。
- 反汇编上限：24 个函数 / 约 1100 条指令；超出部分不展开。IAT 交叉引用是全节区扫描，不受该上限影响。
- 字符串只覆盖 ASCII 与 UTF-16LE（ASCII 范围），不含 UTF-16 中文与代码页字符串；显示上限 600 条（按可疑度与长度排序）。
- 壳指纹只有 UPX / ASPack / MEW 三条入口签名 + 节名匹配，不是 PEiD 签名库。
- 只支持 x86 / x64 反汇编；ARM64 镜像跳过反汇编，仍做字符串与结构分析。
- 导出表 > 500 项、重定位 > 25 块在树内截断显示。
- 动态调试不做：内存 dump 重建 PE（unpacking）、调用栈回溯、硬件断点、全量 trace、多线程独立控制（停在任何事件时全部线程都被系统挂起，只读当前线程上下文）。
- 动态调试只支持 x86 / x64；ARM64 目标无法启动 / 附加。
- `ATTACH` 对其它用户的进程需要 `SeDebugPrivilege`（本程序未提权，未提权时附加会失败）。
- 内存视图每次读取 256 字节；反汇编窗口 22 条指令；不跟随跨页指令。
- 未接入在线查毒、YARA 引擎、MVVM 框架或单元测试。
