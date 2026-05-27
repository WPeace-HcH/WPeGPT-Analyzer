# WPeGPT-Analyzer

一个可移植的 **SKILL 技能**，驱动 IDA 配合 [WPeGPT](https://github.com/WPeace-HcH/WPeGPT) AI 插件，对二进制可执行文件进行全自动的逆向分析。支持 PE 和 ELF 格式，提供三种分析模式。

> 可被任何支持 SKILL 机制的 AI Agent 加载使用。

## 功能

自动启动 IDA 并利用 WPeGPT 插件驱动 AI 进行分析。输出结构化报告，包括：

- **程序用途** — AI 综合判定的程序分类和行为特征
- **网络 IoC** — IP、域名、URL、端口（检测到网络行为时）
- **可疑函数** — 按可疑度排序的函数列表及关键发现
- **漏洞评估** — 带风险等级的漏洞分析（vuln 模式）

## 分析模式

| 模式 | 说明 | 耗时 |
|------|------|------|
| `light`（默认） | 全局扫描 + 关键路径函数分析 | 2~5 分钟 |
| `full` | 全局扫描 + 关键路径 + 全量函数分析 | 10~30 分钟 |
| `vuln` | 关键路径函数漏洞分析 | 5~20 分钟 |

## 前置条件

- **IDA**（推荐 7.6+），已安装 WPeGPT 插件并能够正常使用
- **Python 3**，已安装 `openai` 和 `httpx` 包
- **WPeGPT** — 本技能能力的主要驱动 IDA 插件（[安装指南](https://github.com/WPeace-HcH/WPeGPT)）
- **Windows** — 目前支持 Windows 环境（PowerShell 或 Batch）

## 快速开始

### 1. 在 IDA 中安装 WPeGPT

将 [WPeGPT 插件](https://github.com/WPeace-HcH/WPeGPT) 安装到 IDA 的 `plugins/` 目录：

```
<ida_dir>/plugins/
├── WPeGPT.py
└── WPeGPT_Config/
    ├── config.py
    └── wpe_ai_controller.py
```

在 `config.py` 中配置 WPeGPT 所使用的 AI 模型及 API 密钥。

### 2. 配置 SKILL

SKILL 运行时将会进行自检配置信息并询问路径，你也可以提前手工在 `/config/config.ini` 文件中填写你的路径：

```ini
[paths]
ida_dir=path\to\IDA
python_path=path\to\python.exe
```

### 3. 加载技能

将此项目添加到你的 AI Agent 的 Skill 目录。使用时会自动：
1. 验证依赖
2. 检测二进制架构
3. 启动 IDA 并运行分析
4. 读取并总结报告

你可以直接说：*"使用 wpegpt 技能分析 C:\samples\malware.exe"*、*"帮我大致分析 C:\samples\malware.exe"*、*"深度分析 suspicious.dll"* 或 *"检查 target.exe 的漏洞"*。（经测试 Agent 调用 SKILL 会出现不主动调用的情况，最好主动告知 AI 使用技能或 "/wpegpt-analyzer" 直接调用）

报告将保存到 `<binary_dir>/<filename>_WPeAI_Results/`。

## 工作原理

```
┌─────────────────────────────────────────────────────┐
│                       调用方                        │
│  ┌───────────────────────────────────────────────┐  │
│  │  wpegpt_analyze                               │  │
│  │  1. 检测二进制文件架构（PE/ELF，32/64位）      │  │
│  │  2. 启动 IDA + WPeGPT                         │  │
│  │  3. 轮询 WPeServer TCP 端口                   │  │
│  │  4. 运行 wpe_ai_controller                    │  │
│  └──────────────────────┬────────────────────────┘  │
└─────────────────────────┼───────────────────────────┘
                          │
               ┌──────────▼──────────┐
               │   WPeServer (TCP)   │  ← 嵌入 IDA 内部
               └──────────┬──────────┘
                          │
               ┌──────────▼──────────┐
               │  wpe_ai_controller  │  ← 外部驱动
               └──────────┬──────────┘
                          │
               ┌──────────▼──────────┐
               │      AI Model       │  ← DeepSeek / GPT 等
               └─────────────────────┘
```

## 项目结构

```
wpegpt-analyzer/
├── SKILL.md                  # 技能定义
├── config/
│   └── config.ini.example    # 配置模板（可复制为 config.ini 并配置使用）
└── scripts/
    ├── wpegpt_analyze.ps1    # PowerShell 启动脚本
    └── wpegpt_analyze.bat    # Batch 启动脚本（备用）
```
