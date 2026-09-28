# 攻击面覆盖表（Attack Surface Coverage Map）

把 cf-security-audit-skill 的 12 域攻击面分类蒸馏成静态映射：攻击域 → tiangang 现有检测工具/规则集 → 归属。`generate_report.py` 中的 `COVERAGE_MAP` 是同一份映射的机器可读侧，与本表必须同步维护——新增工具时两处一起改，否则对应域的覆盖会被低估。

覆盖小节由报告生成器纯确定性查表产出（`coverage_by_domain()`，不调用模型）：`covered` = 域内全部工具出现在 `scan_manifest.json` 的 `ran` 中且退出码为 0；`partial` = 部分如此；`not covered`（未覆盖）= 全部缺失/跳过/失败，或该域没有映射通道。`not covered` 只说明本次扫描在该域没有通道，不构成该域安全的证据——与报告里 `## Tools not run` 是同一纪律：把发现当作 partial，而不是 exhaustive。

## 12 域映射总表

| # | 攻击域 | 参考文件 | 攻击面要点 | tiangang 检测通道 | 归属 |
|---|---|---|---|---|---|
| 1 | 普通攻击类 | ATTACK-CLASSES.md | 注入、访问控制、资源与文件处理、加密与密钥、业务逻辑、功能滥用与数据泄露、链式漏洞 | semgrep（离线回退 `p/security-audit` + `p/secrets`）+ 各语言 SAST（bandit/gosec/flawfinder/cppcheck/brakeman/psalm/findsecbugs/security-code-scan/njsscan/eslint-security）+ gitleaks/trufflehog 独立密钥通道 | SAST 主通道覆盖已知模式；业务逻辑、链式漏洞、功能滥用静态规则不可达，需人工或 OCR |
| 2 | 内存安全 / 二进制 / 内核 | MEMORY-SAFETY-AND-BINARY.md | 越界、整型溢出、生命周期、FFI/ABI、二进制加载、特权接口 | flawfinder + cppcheck（C/C++）、miri（Rust UB，需 nightly）、codeql（opt-in） | C/C++/Rust SAST 可达；内核/固件、二进制加载器与 JIT 无通道 |
| 3 | AI / LLM / agent | AI-AND-LLM.md | 上下文注入、记忆投毒、动作绑定、工具 schema、MCP 身份 | semgrep-agent（`rules/agent-antipatterns.yml`，`--agent-rules` opt-in）+ ocr（AI 代码审查，opt-in） | agent 架构反模式走规则、语义类走 OCR；上下文/记忆投毒类需 OCR 深查 |
| 4 | HTTP 协议与身份认证 | WEB-PROTOCOL-AND-AUTH.md | HTTP 解析/缓存、会话、JWT/OAuth/OIDC/SAML、MFA/passkey、API key/mTLS | semgrep + brakeman/psalm/findsecbugs/njsscan/eslint-security | SAST 弱信号（已知缺陷模式可达）；请求走私、联邦身份与会话状态机逻辑需人工或 OCR |
| 5 | 客户端与浏览器 | CLIENT-SIDE.md | DOM、原型污染、postMessage/跨源、service worker、浏览器存储、CORS | eslint-security + retire（前端依赖 CVE）+ semgrep | 前端依赖 CVE 与 security/* lint 可达；DOM/跨源逻辑需人工或 OCR |
| 6 | 供应链与发布 | SUPPLY-CHAIN-AND-RELEASE.md | 依赖解析、构建输入、CI、签名与更新 | trivy + cargo-audit + retire（依赖 CVE）+ gitleaks/trufflehog（提交内容中的密钥） | SCA + 密钥通道可达；CI 工作流与发布/签名流水线逻辑无通道 |
| 7 | 云与部署 | CLOUD-AND-DEPLOYMENT.md | IAM、IaC、容器/K8s、边缘/无服务器、配置与密钥生命周期 | checkov + tfsec（IaC） | IaC 通道可达；运行时 IAM 策略、云控制面等部署侧事实属 needs_validation（源码不可见） |
| 8 | 协议 / RPC / 消息 | PROTOCOLS-RPC-AND-MESSAGING.md | 帧解析、schema、RPC 身份、broker 隔离、重放/乱序 | semgrep + findsecbugs + gosec | SAST 弱信号；自定义协议状态机与 broker/队列配置无通道 |
| 9 | 资源耗尽与可用性 | RESOURCE-EXHAUSTION-AND-AVAILABILITY.md | 计算放大、资源累积、配额/调度、故障恢复 | 无专属静态通道 | tiangang 结构性盲区，恒报 `not covered`；需本地沙箱内的压测/容量审查或 OCR |
| 10 | 数据隔离与生命周期 | DATA-ISOLATION-AND-LIFECYCLE.md | 租户隔离、派生数据、导出/备份/迁移、删除/撤销 | semgrep + brakeman/psalm/findsecbugs | SAST 弱信号（注入/越权模式可达）；租户隔离与生命周期逻辑需人工或 OCR |
| 11 | 桌面 / 移动 / 本地 IPC | DESKTOP-MOBILE-AND-LOCAL-IPC.md | 深链、WebView 桥、导出组件、特权助手、Unix socket/XPC/Binder | 无专属静态通道 | tiangang 结构性盲区，恒报 `not covered`；需人工或 OCR |
| 12 | 验证与报告纪律 | VALIDATION-AND-REPORTING.md | 候选验证、三态裁决、严重度锚点、反拔高 | `generate_report.py --triage`（true_positive/false_positive/needs_validation 三态 verdict + 反拔高纪律 + 严重度锚点） | 报告层流程纪律，非检测通道——不进 `COVERAGE_MAP`，不参与覆盖小节 |

## 与报告生成器的对应关系

`COVERAGE_MAP` 的 `tools` 字段与 `run_scan.py` 注册并写入 `scan_manifest.json` 的工具名一一对应。`coverage_by_domain()` 按上表查 `ran`/`skipped`（`ran` 但退出码非 0 的工具不算覆盖，与 `## Tools attempted but failed` 同一语义：覆盖缺失）；`render_coverage_section()` 在报告的 `## Tools not run` / `## Tools attempted but failed` 之后输出 `## Attack surface coverage` 小节。查表是纯确定性的——同一 manifest 永远渲染同一标注。

新增工具时：先接入 `run_scan.py` 与 `generate_report.py` 的 `PARSERS`（见 tools.md 开头说明），再把工具名加进 `COVERAGE_MAP` 对应域的 `tools` 与上表的检测通道列。
