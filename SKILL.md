---
name: tiangang
description: "专业 SAST 安全审查工具集，运行 Semgrep/CodeQL/各语言专属扫描器产出统一报告，可选叠加 AI 代码审查（OCR）。触发词：安全审查/漏洞扫描/SAST/代码安全检查/hardcoded secrets/SQL injection/unsafe eval/buffer overflow/insecure deserialization/发布前安全检查/AI代码审查。"
license: MIT
---

# 安全审查

针对代码库运行成熟、专用的静态分析安全工具——不是从零开始用眼睛扫文件做代码审查。每种语言都有专用工具是有原因的：Bandit 知道 Python 的 `pickle`/`eval` 陷阱，Gosec 知道 Go 特有的 SQL 注入模式，依此类推。靠人工读代码去复现那种覆盖范围，会漏掉这些工具能自动捕获的问题。用工具；读它们的输出；解释它。

## 详细说明

支持的语言和工具：
- **通用 SAST**：Semgrep（语言无关，始终运行）、CodeQL（深度扫描，opt-in）
- **通用 SCA + 密钥扫描通道**（无论检测到哪些语言都运行）：Trivy（全生态依赖 CVE）、Gitleaks + Trufflehog（独立密钥扫描双通道，避免依赖 Semgrep `p/secrets` 单一通道）
- **Python**：Bandit
- **Java**：FindSecBugs
- **Go**：Gosec
- **C/C++**：Flawfinder / Cppcheck
- **Ruby**：Brakeman
- **PHP**：Psalm
- **.NET**：Security Code Scan
- **Rust**：cargo-audit / Miri
- **JavaScript/TypeScript**：njsscan / retire.js / eslint-plugin-security
- **IaC（基础设施即代码）**：checkov / tfsec（Terraform/Kubernetes/Docker/CloudFormation）
- **AI 代码审查**（单独触发，`--ocr` / `--ocr-delegate`）：open-code-review / OCR（LLM 驱动，扫描完成后独立运行，捕获逻辑 bug、性能问题、可维护性 concern——与 SAST 互补）

整体流程：自动检测目标目录中的语言，指导安装缺失的工具，运行扫描并生成报告——不要让用户自己先说出工具名。

## 工作流程

下面四步对应 `scripts/` 中的四个脚本。按顺序运行——每一步的输出喂给下一步。

### 1. 检测语言

```bash
python3 scripts/detect_languages.py <target-dir> --json
```

遍历目标目录，匹配清单文件（`requirements.txt`、`go.mod`、`Cargo.toml` 等——强信号）和文件扩展名计数（弱信号，按最小文件数过滤，避免单个游离脚本拉入无关工具），返回所有高于噪声阈值检测到的语言。一个项目可能是多语言的（例如 Python 后端 + Go 边车）——全部扫描，不只是主导语言。完整检测表见 `references/tools.md`。

如果用户已经告诉你目标的语言，可以跳过这一步直接把 `--langs` 传给下一步——但如果他们没说，或者你不确定代码库和他们说的一致（例如他们说"这是 Python 项目"但还有一个大型 `go.mod`），运行检测而不是猜测。

### 2. 确保工具已安装

```bash
bash scripts/install_tools.sh <lang1> <lang2> ...     # or: bash scripts/install_tools.sh all
```

先用 `command -v` 检查每个相关工具，只安装缺失的——可安全重复运行。有些工具无法自动安装，因为它们需要项目特定的接入而不是独立 CLI：

- **FindSecBugs**（Java）需要加入项目的 Maven/Gradle 构建，或对已编译的 `.class` 文件运行
- **Security Code Scan**（.NET）是 Roslyn 分析器，通过 `dotnet add package` 加入
- **Psalm**（PHP）需要现有 `composer.json` 才能挂钩

对于这些，脚本会打印该做什么而不是静默跳过——检查它的输出，在合适的地方主动提出为用户改构建文件，而不是留下一个他们还得回来处理的手动步骤。

如果某个工具安装失败（无法访问其包注册表、缺少系统包管理器等），直白地告诉用户而不是静默地以残缺工具集继续——报告会注明哪些工具没运行，但用户应该在拿到看起来完整但实际并不完整的报告前就知道*为什么*。

### 3. 运行扫描

```bash
python3 scripts/run_scan.py <target-dir> [--out <results-dir>] [--langs python,go,...]
# CI 模式: 退出码反映 finding 严重级别, 输出 GitHub Actions annotations
python3 scripts/run_scan.py <target-dir> --ci --gate high
# 增量模式: 只扫描 git 变更文件
python3 scripts/run_scan.py <target-dir> --diff-only --since HEAD~1
```

运行 Semgrep（始终运行——语言无关，能捕获 hardcoded secrets 等各语言专属工具不查的问题）加上通用 SCA/密钥扫描通道（trivy/gitleaks/trufflehog，无论检测到哪些语言都运行）和第 2 步中可用的语言专属工具。把每个工具的原始输出（SARIF 或 JSON，见 `references/tools.md`）写入 results 目录，同时写入 `scan_manifest.json` 记录哪些运行了、哪些被跳过。被跳过的工具不会让运行失败——带着"这里有什么没覆盖"的清晰说明的局部扫描，比拒绝产出任何东西更有用。

**密钥扫描双通道**:gitleaks 和 trufflehog 形成独立密钥检测通道,与 Semgrep `p/secrets` 规则集解耦 —— 单一通道 = 单点失败。两个工具的输出 parser 在 message 中**只保留 rule id / detector name / verified 标志**,绝不写入 `Secret`/`Match`/`Raw`/`Redacted` 原文,从 parser 层切断 secret-on-disk 路径(`redact.py` 是 defense in depth)。

**SCA DB 陈旧信号**:trivy 在 DB 过期时返回零结果,而零结果在 DB 过期时是可疑信号而非"安全"。`run_scan.py` 把 `trivy version --format json` 写入 `trivy-version.json`,让 `VulnerabilityDB.UpdatedAt` 成为可见信号,报告可显式标注是否需要 `trivy db update`。

对于实现 LLM agent 的代码库（LangChain、CrewAI、AutoGen、langgraph 等），在 `--config auto` 之外加载 agent 反模式 Semgrep 规则集，把 12-factor-agents 架构违规作为 SAST 信号捕获——规则说明见 `references/agent-semgrep-rules.md`，物化后的规则文件位于 `rules/agent-antipatterns.yml`。`run_scan.py` 支持 `--agent-rules` 开关自动加载该规则集，所以当目标看起来像 agent 代码时加上该开关即可，或单独跑一次 Semgrep。

**这一步不运行 CodeQL。** CodeQL 需要先构建编译后的查询数据库，明显更慢——把它当作 opt-in 的深度扫描。如果用户要求"深度"或"彻底"审计，或明确点名 CodeQL，读 `references/codeql.md` 并单独运行那个流程，在生成报告前把它的 SARIF 输出写入同一个 results 目录。

### 4. 生成报告

```bash
python3 scripts/generate_report.py <results-dir> [--out report.md] [--format md|html|json|all]
# 包含趋势对比
python3 scripts/generate_report.py <results-dir> --trend
# 生成 LLM 误报过滤提示词
python3 scripts/generate_report.py <results-dir> --triage
```

解析 results 目录中的每个原始工具输出（SARIF、Bandit JSON、Cppcheck XML、cargo-audit JSON、Trivy/Gitleaks/Trufflehog/Retire JSON/JSONL——如果接入新工具，扩展脚本中的 `PARSERS`），汇总成一份 Markdown 报告：按严重程度的汇总表、未运行工具的列表及原因、按严重程度再按文件分组的发现。把这份文件作为交付物呈现给用户——不要把原始工具输出粘到对话里，这一步的全部意义就是把五种工具各自奇奇怪怪的格式变成人类能读的一份东西。

**密钥扫描输出的 secret-on-disk 防护**:gitleaks 的 `Secret`/`Match`、trufflehog 的 `Raw`/`Redacted` 字段携带凭证原文。`generate_report.py` 的 parser 在 message 中只保留 rule id / detector name / verified 标志,**绝不**把凭证原文写入报告 —— `redact.py` 的通用正则脱敏是 defense in depth,parser 层是第一道防线。这是一个 P0 安全要求:安全工具自身的输出不能成为 secret-on-disk 的载体。

## AI 代码审查（单独触发）

在确定性 SAST 扫描**完成后**，可单独触发 AI 驱动的代码审查层。OCR（open-code-review）读取 Git diff 或全文件，通过 LLM 分析生成结构化、行级精度的审查意见——捕获逻辑 bug、性能问题、可维护性 concern 等 SAST 模式匹配不触及的问题。

**OCR 不会自动触发**——只在用户显式请求时作为独立后续步骤运行。正常安全扫描始终先完成，OCR 在其后单独执行。

```bash
# 1. 先运行正常安全扫描（不含 OCR）
python3 scripts/run_scan.py <target-dir>
# 2. 单独触发 AI 代码审查
python3 scripts/run_scan.py <target-dir> --ocr
# 或 Git diff 审查
python3 scripts/run_scan.py <target-dir> --ocr-delegate
```

**两种模式**：
- `--ocr`：`ocr scan` 模式，审计整个目录的全文件，不需要 git 历史。适合审计不熟悉的代码库。支持按子目录分批扫描 + 失败重试。
- `--ocr-delegate`：`ocr review` 模式，审查 git diff（staged + unstaged + untracked 变更）。适合 PR/commit 审查。

**可选参数**：
- `--ocr-background TEXT`：追加审查背景（与自动检测的项目类型背景合并）
- `--ocr-delay N`：批次间延迟秒数（默认 5，防止速率限制）
- `--ocr-retry N`：失败重试轮次（默认 2）
- `--ocr-timeout N`：单文件超时分钟数（默认 60）

**前提条件**：
- `ocr` CLI 已安装（`npm install -g @alibaba-group/open-code-review`，或运行 `install_tools.sh`）
- 配置 LLM API 密钥（`export AGNES_TOKEN=<key>` 或 `export OCR_LLM_TOKEN=<key>`）
- 可选配置：`OCR_LLM_URL`、`OCR_LLM_MODEL`、`OCR_LLM_PROTOCOL`

**委托工作流**（交互式，不需要自动化管道）：
```bash
# 1. 预览哪些文件会被审查
ocr delegate preview --from main --to feature-branch
# 2. 获取审查规则（按文件分组）
ocr delegate rule <path1> <path2> ...
# 3. 获取 diff 并审查
git diff <merge-base>..<to> -- <path>
```

## 报告之后

不要只把文件交出去。先带用户过一遍 critical 或 high 严重程度的发现——这些值得用一两句大白话解释（脆弱模式是什么、大致为什么危险，例如"第 42 行直接拼接用户输入构造 SQL 查询——这是典型的注入点"）。如果用户愿意，主动提出帮忙修最高优先级的发现；不要假设他们只想要一个列表。

如果扫描没发现任何问题，不要把它说成"代码是安全的"——说明实际检查了什么（哪些工具、哪些语言），一次干净的扫描反映的是这些工具的覆盖范围，而不是没有漏洞的保证。无法安装或运行的工具意味着覆盖盲区——对这些盲区坦白，而不是让一份干净的报告暗示它实际并不具备的覆盖度。

## 参考文件

- `references/tools.md` — 每种语言的工具、检测信号、安装命令、扫描命令、输出格式完整表。在脚本未处理的手动安装或调用任何工具前读这个，或当脚本的安装/扫描命令需要针对用户特定环境调整时（例如没有 `apt`、有代理、气隙机）。
- `references/codeql.md` — 独立、更重的 CodeQL 流程：CLI 设置、数据库创建、运行安全查询套件。只在深度/opt-in 扫描时读这个。
- `references/agent-semgrep-rules.md` — 自定义 Semgrep 规则集，把 12-factor-agents 架构反模式（框架黑盒实例化、缺失 intent dispatch、无显式循环的图编排、缺失错误压缩、状态散落、缺失 context serializer、中断式 human contact）映射为 SAST 信号。规则文件物化为 `rules/agent-antipatterns.yml`，扫描 agent 代码库时（LangChain、CrewAI、langgraph、AutoGen 等）通过 `run_scan.py --agent-rules` 自动加载，或作为 `--config rules/agent-antipatterns.yml` 与 `--config auto` 一起加载。
