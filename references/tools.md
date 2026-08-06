# 按语言划分的安全扫描工具

对每种语言,该表给出:工具、如何检查它是否已安装、如何安装、运行扫描的命令,以及它的发现输出到哪里(格式 + 典型路径)。`run_scan.py` 使用的正是这一组命令——如果在这里新增工具,也要把它接入 `run_scan.py` 和 `generate_report.py`,这样报告解析器才能理解它的输出。

每条扫描命令都把机器可读的输出(SARIF 或 JSON)写入文件而非依赖 stdout,因为 `generate_report.py` 解析的是文件,不是终端文本。

## 通用(所有语言)

**Semgrep** —— 无论什么语言都第一个运行的工具。它有覆盖几乎所有东西的规则集,能捕获语言专属 linter 漏掉的跨语言问题(硬编码密钥、不安全配置、通用注入模式)。

- 检查:`command -v semgrep`
- 安装:`uv tool install semgrep`(或 `pipx install semgrep`,如果 pipx 可用且更偏好它)
- 扫描:`semgrep scan --config auto --sarif --output <out>/semgrep.sarif <target>`
  - 如果离线或 `--config auto` 连不上 Semgrep 的 registry,回退到
    `semgrep scan --config p/security-audit --config p/secrets --sarif --output <out>/semgrep.sarif <target>`,
    它使用打包好的规则集,在规则包缓存完成后不需要网络调用。
- 输出:SARIF,位于 `<out>/semgrep.sarif`

## 通用 SCA + 密钥扫描通道

**这三个工具无论检测到哪些语言都运行** —— 依赖 CVE 和硬编码凭证是跨语言问题，把它们的检测独立于语言专属工具之外，避免依赖 Semgrep 的 `p/secrets` 规则集作为唯一通道。吸收自 strix 的 source-aware SAST playbook：单一通道 = 单点失败。

**Trivy** —— 全生态依赖 CVE 扫描（SCA）
- 检查:`command -v trivy`
- 安装:`curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin`
- 扫描:
  - 先跑 `trivy version --format json > <out>/trivy-version.json`,把 `VulnerabilityDB.UpdatedAt` 写到磁盘 —— 一个 DB 陈旧的 trivy 会返回零结果,而零结果在 DB 过期时是**可疑信号**而非"安全"。把这个信号物化到 results 目录,让报告能显式标注 DB 是否需要刷新。
  - 再跑 `trivy fs --scanners vuln --offline-scan --format json --output <out>/trivy.json <target>`。`--scanners vuln` 聚焦依赖 CVE(密钥由 gitleaks/trufflehog 通道负责);`--offline-scan` 让 per-package advisory 查询走本地 DB,扫描本身在受限网络下也能跑(DB 刷新单独走 `trivy db update`)。
- 输出:JSON,位于 `<out>/trivy.json`(扫描结果)+ `<out>/trivy-version.json`(DB 陈旧信号)
- 捕获:依赖树中所有已公开 CVE 的库版本,覆盖 npm/pip/go/cargo/maven 等主流生态。

**Gitleaks** —— 通用密钥扫描（独立通道）
- 检查:`command -v gitleaks`
- 安装:`go install github.com/gitleaks/gitleaks/v8@latest`(需要 `$GOPATH/bin` 在 PATH 上)
- 扫描:`gitleaks detect --source <target> --report-format json --report-path <out>/gitleaks.json --no-banner`
- 输出:JSON,位于 `<out>/gitleaks.json`
- 捕获:AWS/GCP/Slack/Stripe 等带可识别前缀的 token、PEM 私钥块、`password = "..."`/`api_key: '...'` 等带 keyword 前缀的标签式赋值。
- **退出码语义**:rc=1 表示**发现了密钥**(是 finding 不是 failure)。`run_scan.py` 在输出文件存在时把 rc=1 归一化为 0,避免 manifest 出现误导性的"失败"条目。
- **secret-on-disk 防护**:gitleaks 的 `Secret`/`Match` 字段携带凭证原文。`generate_report.py` 的 parser 只把 `rule_id` 写入 finding message,**绝不**把 `Secret`/`Match` 放进报告 —— `redact.py` 是 defense in depth,parser 层就先切断泄露路径。

**Trufflehog** —— 通用密钥扫描（验证 + JSONL）
- 检查:`command -v trufflehog`
- 安装:`go install github.com/trufflesecurity/trufflehog/v3@latest`(需要 `$GOPATH/bin` 在 PATH 上)
- 扫描:`trufflehog filesystem --no-update --json --no-verification <target> > <out>/trufflehog.jsonl`
  - `--no-update` 跳过 detector signature DB 在线更新(离线可跑);`--no-verification` 跳过 live credential 验证 —— 我们要的是"找到候选,排队轮换",而不是让 trufflehog 拿凭证去对真实服务发认证请求(那会把凭证暴露到 access log,且可能触发反爆破锁)。
- 输出:JSONL,位于 `<out>/trufflehog.jsonl`(每行一个 JSON finding,跳过非 JSON 行)
- 捕获:gitleaks 规则集之外的额外 detector —— trufflehog 的 detector 库覆盖 700+ 凭证类型,与 gitleaks 的规则式匹配形成互补。
- **secret-on-disk 防护**:trufflehog 的 `Raw`/`Redacted` 字段同样携带凭证原文。parser 只把 `DetectorName` + `Verified` 标志写入 finding message,`Raw`/`Redacted` 不进报告。

## Python —— Bandit

- 检测:`requirements.txt`、`pyproject.toml`、`setup.py`、`Pipfile`,或 `.py` 文件占多数
- 检查:`command -v bandit`
- 安装:`uv tool install bandit`
- 扫描:`bandit -r <target> -f json -o <out>/bandit.json -x '*/tests/*,*/venv/*,*/.venv/*'`
- 输出:JSON,位于 `<out>/bandit.json`
- 捕获:`eval`/`exec`、硬编码口令/密钥、弱加密(用于安全场景的 MD5/SHA1)、不安全反序列化(`pickle`、`yaml.load`)、shell 注入(`subprocess` 配 `shell=True`)、SQL 字符串拼接。

## Java —— FindSecBugs(SpotBugs 插件)

- 检测:`pom.xml`、`build.gradle`/`build.gradle.kts`,或 `.java` 文件占多数
- 检查:`command -v spotbugs` 以及 FindSecBugs 插件 jar 是否存在
- 安装:FindSecBugs 以 SpotBugs 插件形式分发,不是独立 CLI。两条路径:
  1. **Maven 项目**:把 `spotbugs-maven-plugin` 配上 FindSecBugs 作为插件依赖加入
     `pom.xml`,然后 `mvn compile spotbugs:check`。如果用户还没有这段配置,把确切的 XML 片段给他们
     (见下方),而不是悄悄改他们的构建文件。
  2. **独立使用**:从 GitHub releases 下载 SpotBugs CLI + FindSecBugs 插件 jar,运行
     `spotbugs -textui -pluginList findsecbugs-plugin.jar -sarif -output <out>/findsecbugs.sarif <compiled-classes-dir>`。
     注意这需要*已编译的* `.class` 文件,不是源码——先构建项目
     (`mvn compile` / `gradle compileJava`)。
- 输出:SARIF(配 `-sarif`)或 XML,位于 `<out>/findsecbugs.sarif`
- 如果项目在当前环境里无法构建,明确说明这一点,而不是报告一个假的"无发现"——无法构建的项目意味着扫描根本没有运行。

如果用户希望把 FindSecBugs 接入构建,可以给他们的 Maven pom.xml 片段:
```xml
<plugin>
  <groupId>com.github.spotbugs</groupId>
  <artifactId>spotbugs-maven-plugin</artifactId>
  <configuration>
    <plugins>
      <plugin>
        <groupId>com.h3xstream.findsecbugs</groupId>
        <artifactId>findsecbugs-plugin</artifactId>
        <version>LATEST</version>
      </plugin>
    </plugins>
  </configuration>
</plugin>
```

## Go —— Gosec

- 检测:`go.mod`,或 `.go` 文件占多数
- 检查:`command -v gosec`
- 安装:`go install github.com/securego/gosec/v2/cmd/gosec@latest`(需要 `$GOPATH/bin` 在
  `PATH` 上,或用完整路径运行该二进制)
- 扫描:`gosec -fmt=sarif -out=<out>/gosec.sarif ./...`(在模块根目录下运行)
- 输出:SARIF,位于 `<out>/gosec.sarif`
- 捕获:字符串拼接造成的 SQL 注入、路径穿越、用于安全场景的弱随机数生成、硬编码凭证、`os/exec` 的不安全使用。

## C / C++ —— Flawfinder + Cppcheck

两个都跑——它们捕获的东西不同。Flawfinder 是对危险函数调用的快速模式匹配;Cppcheck 做更深的静态分析,包含一些数据流分析。

**Flawfinder**
- 检查:`command -v flawfinder`
- 安装:`uv tool install flawfinder`
- 扫描:`flawfinder --sarif <target> > <out>/flawfinder.sarif`
- 输出:SARIF(配 `--sarif`)或 CSV(配 `--csv`)
- 捕获:`strcpy`/`gets`/`sprintf` 等易导致缓冲区溢出的调用、格式串漏洞。

**Cppcheck**
- 检查:`command -v cppcheck`
- 安装:`apt-get install -y cppcheck`(Debian/Ubuntu)——如果当前环境里 apt 不可用,
  告诉用户通过他们的系统包管理器或从源码安装。
- 扫描:`cppcheck --enable=warning,portability --xml --xml-version=2 <target> 2> <out>/cppcheck.xml`
  (Cppcheck 把 XML 写到 stderr,因此需要重定向)
- 输出:XML,位于 `<out>/cppcheck.xml`
- 捕获:缓冲区越界、空指针解引用、use-after-free、未初始化变量。

## Ruby —— Brakeman

- 检测:`Gemfile` + `app/` 或 `config/routes.rb`(Rails 特征),或 `.rb` 文件占多数
- 检查:`command -v brakeman`
- 安装:`gem install brakeman`
- 扫描:`brakeman -f sarif -o <out>/brakeman.sarif <target>`
- 输出:SARIF,位于 `<out>/brakeman.sarif`
- 捕获:SQL 注入、mass assignment、不安全重定向、跨站脚本、不安全反序列化——全部是 Rails 专属模式,所以 Brakeman 只对 Rails 应用有用,对普通 Ruby 脚本无效(对纯 Ruby,更多依赖 Semgrep)。

## PHP —— Psalm(security 插件)

- 检测:`composer.json`,或 `.php` 文件占多数
- 检查:`command -v psalm`
- 安装:`composer require --dev vimeo/psalm psalm/plugin-security` 然后
  `vendor/bin/psalm-plugin enable psalm/plugin-security`(需要项目里已有
  `composer.json`;如果没有,Psalm 无法运行——回退到 Semgrep 的 PHP 规则集)
- 扫描:`psalm --taint-analysis --report=<out>/psalm.sarif`
- 输出:SARIF(配 `--report=*.sarif`),位于 `<out>/psalm.sarif`
- 捕获(通过污点分析):SQL 注入、XSS、命令注入、不安全文件包含,从用户输入端到端追踪到危险 sink。

## .NET (C#) —— Security Code Scan

- 检测:`.csproj`、`.sln`,或 `.cs` 文件占多数
- 检查:在 `.csproj` 中查找已引用的 analyzer,或 `dotnet list package` 查找
  `SecurityCodeScan.VS2019`
- 安装:在项目目录中 `dotnet add package SecurityCodeScan.VS2019`(它是 Roslyn
  analyzer,所以挂入 `dotnet build` 而非作为独立 CLI 运行)
- 扫描:`dotnet build /p:TreatWarningsAsErrors=false /clp:ErrorsOnly` 并从构建输出中捕获 analyzer
  警告,或使用 `dotnet build -warnaserror:SCS0001-SCS9999` 让特定规则使构建失败。没有原生 SARIF 导出——从构建日志中解析
  `SCSxxxx` 警告码并自行映射到 `<out>/security-code-scan.json`(需手动整理为下列 JSON 形状后保存为 security-code-scan.json)。
- 捕获:SQL 注入、弱加密/哈希、XXE、路径穿越、不安全反序列化、硬编码口令、用于 token 的弱随机性。

## Rust —— cargo-audit(依赖 CVE)+ Miri(内存安全)

这两者检查的东西不同:cargo-audit 是软件组成分析(依赖树中已知的 CVE),Miri 是一个解释器,捕获 `unsafe` 代码中的未定义行为。如果项目有任何 `unsafe` 块,两个都跑;否则通常 cargo-audit 就够了。

**cargo-audit**
- 检查:`cargo audit --version`
- 安装:`cargo install cargo-audit`
- 扫描:`cargo audit --json > <out>/cargo-audit.json`(在有 `Cargo.lock` 的目录下运行)
- 输出:JSON,位于 `<out>/cargo-audit.json`
- 捕获:带有已发布 RUSTSEC 公告的依赖——过时或有漏洞的 crate,而非项目自身代码中的 bug。

**Miri**
- 检查:`cargo +nightly miri --version`
- 安装:`rustup +nightly component add miri`(需要 nightly 工具链;Miri 不在
  stable 上发布)
- 扫描:`cargo +nightly miri test 2> <out>/miri.log`(Miri 在一个解释器下运行你的测试套件,
  在 UB 发生时标记——它不做静态分析,所以只能捕获被你的测试覆盖到的内容。测试越多 = 覆盖越广。)
- 输出:纯文本日志,位于 `<out>/miri.log`,从中解析 `error: Undefined Behavior` 块
- 只有项目含有 `unsafe` 块时才值得运行——先用 `grep -r "unsafe" --include=*.rs`
  检查,如果没有则跳过 Miri 并注明原因。

## JavaScript / TypeScript —— njsscan + retire.js + eslint-plugin-security

三个工具覆盖不同维度：njsscan 做模式匹配（rules-as-code），retire.js 做 SCA（已知 CVE 的库版本），eslint-plugin-security 做规则化 lint（与项目 ESLint 配置集成）。

**njsscan**
- 检查:`command -v njsscan`
- 安装:`uv tool install njsscan`(独立 Python CLI,无项目侵入)
- 扫描:`njsscan --sarif <target> > <out>/njsscan.sarif`
- 输出:SARIF,位于 `<out>/njsscan.sarif`
- 捕获:Node 调用 `eval`、`child_process.exec` 配字符串拼接、`dangerouslySetInnerHTML`、`serialize-javascript` 等前端/Node 专属模式。

**retire.js** —— JavaScript 依赖 CVE 扫描（SCA）
- 检查:`command -v retire`
- 安装:`npm install -g retire`
- 扫描:`retire --path <target> --outputformat json --outputpath <out>/retire.json`
- 输出:JSON,位于 `<out>/retire.json`
- 捕获:已知 CVE 的 JS 库版本（jquery、lodash、angular 等）。与 trivy 的 npm lockfile 扫描互补 —— retire 能发现 `vendor/`、`dist/`、CDN 拷贝等**未在 package-lock.json 中**但实际部署的副本。吸收自 strix 的 source-aware SAST playbook。
- 一个组件若有多个 CVE,parser 拆成多个 finding（one-finding-per-CVE）,与 trivy 的形态一致,便于按 CVE 在跨工具去重后汇总。

**eslint-plugin-security**
- 检测:`package.json` 存在,且 eslint 配置文件（`eslint.config.js`/`.eslintrc.*`）中引用了 `eslint-plugin-security` 或 `plugin:security`
- 安装:`npm install --save-dev eslint eslint-plugin-security`(必须在项目内安装,不能 -g)
- 扫描:`npx --no-install eslint --format json --output-file <out>/eslint-security.json .`(在项目根目录运行;`--no-install` 避免静默下载)
- 输出:JSON,位于 `<out>/eslint-security.json`
- 捕获:`eval`、`child_process.exec` 字符串拼接、`crypto.createCipher`（弱加密）、`Math.random`（用于安全场景）等。
- 与 FindSecBugs / Security Code Scan 同模式:工具是项目内的 devDependency,挂入项目的 ESLint 配置才能跑。脚本不会静默修改 `package.json` —— 没有接入的项目会跳过并打印操作指引。

## IaC —— checkov + tfsec

两个工具覆盖不同维度：checkov 做广覆盖（Terraform/Kubernetes/Docker/CloudFormation/ARM），tfsec 做 Terraform 深度分析（provider 专属安全规则）。

**checkov**
- 检查：`command -v checkov`
- 安装：`uv tool install checkov`
- 扫描：`checkov --directory <target> --output json --quiet --compact > <out>/checkov.json`
- 输出：JSON，位于 `<out>/checkov.json`
- 捕获：Terraform 不安全默认配置、K8s 缺失安全上下文、Docker 最佳实践违规、CloudFormation 资源 misconfiguration、密码策略缺失等。
- **退出码语义**：rc=1 表示发现了 finding（不是 failure）。`run_scan.py` 在输出文件存在时把 rc=1 归一化为 0。

**tfsec**
- 检查：`command -v tfsec`
- 安装：`go install github.com/aquasecurity/tfsec/cmd/tfsec@latest`
- 扫描：`tfsec <target> --format json --out <out>/tfsec.json --soft-fail`
- 输出：JSON，位于 `<out>/tfsec.json`
- 捕获：Terraform 专属安全规则——AWS S3 桶公开访问、Azure NSG 规则过宽、GCP IAM 权限过大、硬编码凭证等。

## AI 代码审查 —— open-code-review (OCR)

AI 驱动的代码审查工具，读取 Git diff 并生成结构化、行级精度的审查意见。与确定性 SAST 工具互补——捕获逻辑 bug、性能问题、可维护性 concern 等 SAST 不覆盖的维度。通过 `--ocr` 或 `--ocr-delegate` opt-in 启用，不默认运行。

- 检查：`command -v ocr`
- 安装：`npm install -g @alibaba-group/open-code-review`
- LLM 配置：`ocr config provider` 然后 `ocr config model`（scan/review 模式需要；delegate 模式不需要）
- 扫描（全文件审计，不需要 git）：
  - `ocr scan --format json --output <out>/ocr.json <target>`
- 审查（Git diff 模式，需要 git 仓库）：
  - `ocr review --format json --audience agent > <out>/ocr.json`（在 target 目录下运行）
- 委托模式（无需 LLM API，让宿主 agent 做审查）：
  - `ocr delegate preview` → 确定审查文件列表
  - `ocr delegate rule <paths>` → 获取审查规则
  - 详见 SKILL.md 的 OCR 委托工作流说明
- 输出：JSON，位于 `<out>/ocr.json`
- 捕获：逻辑 bug、安全漏洞、性能问题、可维护性 concern、风格问题——LLM 驱动的动态分析，覆盖 SAST 模式匹配不触及的跨文件上下文问题。
- **退出码语义**：rc=1 表示发现了 finding（不是 failure）。`run_scan.py` 在输出文件存在时把 rc=1 归一化为 0。
- **secret-on-disk 防护**：OCR 的 `content` 字段可能包含代码片段。`generate_report.py` 的 parser 层 + `redact.py` 的通用脱敏确保凭证不进报告。
- **自定义规则**：支持项目级 `.opencodereview/rule.json`，通过路径匹配 + 自然语言规则补充内置审查规则。

## 检测参考（由 `detect_languages.py` 使用）

| 语言 | 强信号(manifest 文件) | 弱信号(扩展名占多数) |
|---|---|---|
| Python | `requirements.txt`、`pyproject.toml`、`setup.py`、`Pipfile` | `.py` |
| Java | `pom.xml`、`build.gradle`、`build.gradle.kts` | `.java` |
| Go | `go.mod` | `.go` |
| C/C++ | `CMakeLists.txt`、`Makefile`、`configure.ac`、`meson.build` | `.c`、`.h`、`.cpp`、`.hpp`、`.cc` |
| Ruby | `Gemfile` | `.rb` |
| PHP | `composer.json` | `.php` |
| .NET | `.csproj`、`.sln` | `.cs` |
| Rust | `Cargo.toml` | `.rs` |
| IaC | `main.tf`、`terraform.tf`、`Chart.yaml`、`Dockerfile`、`docker-compose.yml` | `.tf`、`.hcl` |
| Kotlin | — | `.kt`、`.kts` |
| Swift | — | `.swift` |
| Scala | — | `.scala` |
| Dart | — | `.dart` |
| Elixir | — | `.ex`、`.exs` |

一个项目可能(且经常)包含不止一种语言——例如 Python 后端配一个小的 Go 服务。把所有高于噪声阈值检测到的语言全部扫描,不要只扫主导语言。
