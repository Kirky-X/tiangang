# Tiangang（天罡）— SAST 静态应用安全测试套件

> 面向 AI agent 的专业 SAST 套件：自动检测语言，调度 Semgrep + 语言专属扫描器 + 全生态 SCA/密钥扫描双通道，统一产出人类可读报告。**用工具、读输出、解释输出**，而非用肉眼扫代码冒充安全审查。

[![version](https://img.shields.io/github/v/tag/Kirky-X/tiangang?style=flat-square)](https://github.com/Kirky-X/tiangang/tags) [![license](https://img.shields.io/github/license/Kirky-X/tiangang?style=flat-square)](LICENSE) [![python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square)](scripts/)

中文 | [English](README_EN.md)

## ✨ 功能特性

- **四步工作流**（`scripts/` 四个脚本，逐步输入输出衔接）：`detect_languages` 检测语言 → `install_tools` 补齐工具 → `run_scan` 运行扫描 → `generate_report` 统一报告
- **通用 SAST**：Semgrep（语言无关，始终运行，捕获硬编码密钥等跨语言模式）；CodeQL（深度扫描，opt-in，不进默认流程，见 `references/codeql.md`）
- **SCA + 密钥双通道**（无论检测到哪些语言都运行）：Trivy 全生态依赖 CVE（安装链钉定 v0.74.0 并校验 SHA256，DB 陈旧信号物化到 `trivy-version.json`，零结果不再误读为"安全"）；Gitleaks + Trufflehog 独立密钥双通道，与 Semgrep `p/secrets` 解耦——parser 层只保留 rule id/detector name，凭证原文绝不落盘进报告（`redact.py` 为 defense in depth）
- **10 种语言专属扫描器**：Python→Bandit；Java→FindSecBugs；Go→Gosec；C/C++→Flawfinder+Cppcheck；Ruby→Brakeman；PHP→Psalm；.NET→Security Code Scan；Rust→cargo-audit+Miri；JS/TS→njsscan+retire.js+eslint-plugin-security；IaC→checkov+tfsec
- **AI 代码审查（OCR，单独触发）**：`--ocr` 全文件审计 / `--ocr-delegate` git diff 审查，SAST 完成后独立运行，捕获逻辑 bug、性能与可维护性问题
- **Agent 代码库反模式规则**：`--agent-rules` 加载 `rules/agent-antipatterns.yml`，把 12-factor-agents 架构违规（框架黑盒实例化、缺失 intent dispatch、无显式循环的图编排等）作为 SAST 信号
- **工程化能力**：`--ci` 模式（退出码反映严重级别 + GitHub Actions annotations）、`--gate` 门禁阈值、`--diff-only` 增量扫描（哈希缓存）、`--format md|html|json`、`--trend` 趋势对比、`--triage` LLM 误报过滤提示词、三层 finding 去重与多工具确认标记
- **失败显性化**：工具缺失/安装失败/被跳过均在报告标注原因；清洁扫描只反映工具覆盖范围，绝不说成"代码是安全的"

## 📦 安装

```bash
# 方式 1：从本仓库根一键部署（同步到 ~/.zcode/skills/ 与 ~/.claude/skills/，LF 强制归一）
bash scripts/sync-skills.sh tiangang

# 方式 2：手动拷贝到 agent 技能目录
cp -r tiangang/ ~/.zcode/skills/tiangang/
```

首跑依赖：仅需 Python 3.8+（脚本层标准库）。扫描器本体（Semgrep/Bandit/Trivy 等）由 `scripts/install_tools.sh` 首次运行时按需安装；OCR 需 `npm install -g @alibaba-group/open-code-review` 并配置 LLM API 密钥（`AGNES_TOKEN` 或 `OCR_LLM_TOKEN`）。

## 🚀 快速开始

前置：skill 已部署；对目标目录依次执行四步（脚本路径以 `{SKILL_DIR}` 为安装目录）。

```bash
# 1. 检测语言（用户已说明语言可跳过，直接传 --langs）
python3 {SKILL_DIR}/scripts/detect_languages.py <target-dir> --json

# 2. 安装缺失工具（command -v 预检，安全可重跑）
bash {SKILL_DIR}/scripts/install_tools.sh python go    # 或 all

# 3. 运行扫描（Semgrep 始终运行 + SCA/密钥通道 + 语言专属工具）
python3 {SKILL_DIR}/scripts/run_scan.py <target-dir> --out results
#    CI 门禁：--ci --gate high；增量：--diff-only --since HEAD~1；agent 库：--agent-rules

# 4. 生成统一报告（md|html|json|all）
python3 {SKILL_DIR}/scripts/generate_report.py results --out report.md
#    趋势：--trend；LLM 误报过滤提示词：--triage
```

自然语言触发（在支持 skills 的 agent 会话中）："安全审查这个项目"、"扫一下硬编码密钥"、"发布前安全检查"、"对 agent 代码库做 SAST"。

## ✅ 测试与验证

pytest 实测（2026-09-13，Python 3.12）：

```text
$ python3 -m pytest tests -q
.......................................................................  [100%]
503 passed in 11.13s
```

11 个测试文件覆盖：语言检测覆盖率、报告生成、run_scan 调度、SARIF 输出、redact 脱敏、OCR 集成、密钥双通道吸收（strix absorption）、修复回归与优化项等。

冒烟实测：`detect_languages.py` 对含 `requirements.txt` 的样本目录正确返回 `{"languages": ["python"]}`；`install_tools.sh` 中 Trivy 安装函数校验下载二进制的 SHA256 checksum（`TRIVY_VERSION="0.74.0"`）。

## 📁 目录结构

```text
tiangang/
├── SKILL.md                 # 入口：四步工作流 + OCR 触发 + 报告解读纪律
├── skill.json               # 元数据（v0.2.1，MIT）
├── references/
│   ├── tools.md             # 全语言工具表：检测信号/安装命令/扫描命令/输出格式
│   ├── codeql.md            # CodeQL 深度扫描独立流程（opt-in 才读）
│   └── agent-semgrep-rules.md  # agent 反模式规则集说明
├── rules/
│   └── agent-antipatterns.yml  # 物化的 Semgrep agent 反模式规则
├── scripts/
│   ├── detect_languages.py  # 步骤 1：manifest 强信号 + 扩展名弱信号检测语言
│   ├── install_tools.sh     # 步骤 2：只装缺失工具；Trivy 钉 v0.74.0 + checksum 校验
│   ├── run_scan.py          # 步骤 3：插件化调度（ToolPlugin），--ci/--gate/--diff-only/--ocr
│   ├── generate_report.py   # 步骤 4：多格式解析 → 统一报告（--trend/--triage）
│   ├── sarif_report.py      # SARIF 汇总
│   └── redact.py            # 通用正则脱敏（defense in depth）
├── open-code-review/        # OCR 集成参考
└── tests/                   # pytest 套件（503 用例，11 文件）
```

## 🔮 边界

- **代码质量/风格/架构审查与 PR 审查编排（`review pr`）归 [diting](../diting/)**：本 skill 只做安全扫描，不做通用代码评审
- **OCR 不自动触发**：仅在用户显式请求 AI 代码审查时作为 SAST 之后的独立步骤运行
- **CodeQL 不进默认流程**：需要构建查询数据库、明显更慢，仅用户点名"深度审计"或点名 CodeQL 时走 `references/codeql.md` 独立流程
- **清洁扫描 ≠ 安全**：报告只陈述实际检查范围（哪些工具、哪些语言），覆盖盲区如实标注

## 📄 License 与归属

MIT License（© 2026 Kirky-X）。SCA/密钥通道设计吸收自 source-aware SAST playbook（strix）；OCR 层基于开源项目 [open-code-review](https://github.com/alibaba/open-code-review)（`@alibaba-group/open-code-review`），快照收录于 `open-code-review/`。
