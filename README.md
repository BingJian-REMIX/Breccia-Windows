# BRECCIA // PE STRUCTURE & SECURITY INSPECTOR

Windows PE 结构分析与安全透视工具。C# / WPF，纯静态解析，不执行被分析文件。

唯一 NuGet 依赖：**PeNet 6.1.2**。UI、主题、交互全部原生 WPF，无第三方控件库 / MVVM 框架。

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

生成单文件可执行程序（framework-dependent，win-x64）：

```bash
dotnet publish Breccia.csproj -c Release -r win-x64 --self-contained false \
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish
```

`publish/Breccia.exe` 约 430 KB，内含 PeNet，运行时需与 .NET 10 桌面运行时配合。`bin/`、`obj/`、`publish/` 均不纳入版本库。

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

搜索框实时过滤报告树，保留命中节点及其祖先链。

## 分析能力

**PE 结构（17 个分组）**：标识、DOS/NT/Optional 头、14 个数据目录、节区（VA / RAW / Flags / Shannon 熵）、导入表、延迟导入、导出表、资源与版本信息、重定位、调试目录与 PDB 路径、TLS 回调、Load Config、CLR 元数据流、x64 异常表、Authenticode 证书、SHA256 / SHA1 / MD5 / ImpHash / TypeRefHash、风险摘要。

**安全透视**：节名壳标记（UPX / VMP / ASPack / Themida …）、高熵节（≥ 7.0）、W+X 节、入口点落点异常、导入表稀疏、ASLR / DEP 位、签名校验、30 个敏感 API 三级分类（一律 `#EF4444` 红字）、注入链组合检测、TLS 回调 → 0–100 风险分与置顶风险摘要。

## 工程结构

| 文件 | 职责 |
|---|---|
| `PeAnalyzer.cs` | 纯数据层：模型 + PE 解析 + 安全规则 + 风险评分 |
| `MainWindow.xaml` / `.xaml.cs` | 暗黑无边框 UI、渲染与交互 |
| `App.xaml` / `.xaml.cs` | 应用入口、命令行参数加载 |
| `Breccia.csproj` | `net10.0-windows` + `UseWPF` + PeNet |

PeNet 的集合属性可空且 lazy 解析对畸形 PE 会抛异常，所有可选结构统一走 `Arr<T>` / `Safe<T>` 防御式读取。

## 已知限制

- 风险分是启发式透视结果，不是恶意判定。系统 DLL 会偏高（例如 `kernel32.dll` 因导入注入类 API 得 55/HIGH）。
- 查壳基于节名与熵值特征，不做特征码扫描；伪装节名或纯代码混淆不覆盖。
- 导出表 > 500 项、重定位 > 25 块在树内截断显示。
- 未接入在线查毒、YARA 引擎、MVVM 框架或单元测试。
