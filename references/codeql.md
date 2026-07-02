# CodeQL —— 可选深度扫描

CodeQL 比本 skill 中的其他工具都更重:它需要先从目标代码库构建一个编译后的查询数据库才能运行任何查询,在大项目上速度慢,CLI 是约 200MB 的下载而非通过包管理器安装。把它当作 opt-in 的"深度"扫描,而非默认扫描的一部分——只有当用户要求更深的扫描或明确点名 CodeQL 时才构建 CodeQL 数据库。

## 安装

- 检查:`command -v codeql`
- 安装:无包管理器安装方式。从
  [CodeQL releases 页面](https://github.com/github/codeql-action/releases)(或
  `github.com/github/codeql-cli-binaries`)下载 CLI bundle 并加入 `PATH`。在一台全新机器上:
  ```bash
  git clone https://github.com/github/codeql.git ~/codeql-repo   # query packs
  # download+unzip the CLI bundle for your platform from the releases page, then:
  export PATH="$PATH:/path/to/codeql-bundle/codeql"
  ```
- 如果环境的网络策略屏蔽了 `github.com`/`codeload.github.com`,CodeQL 在该环境里就无法安装——直白地说明这一点,改用 Semgrep + 语言专属工具,而不是假装扫描已运行。

## 运行扫描

两步流程——先构建数据库,再分析它:

```bash
# 1. Build a database (language must be one CodeQL supports: cpp, csharp, go, java,
#    javascript, python, ruby, rust)
codeql database create <db-path> --language=<lang> --source-root=<target>

# 2. Run the standard security query suite against it
codeql database analyze <db-path> \
  codeql/<lang>-queries:codeql-suites/<lang>-security-and-quality.qls \
  --format=sarif-latest --output=<out>/codeql-<lang>.sarif
```

对于编译型语言(Java、C/C++、C#、Go、Rust),数据库创建需要真正去构建项目——CodeQL 会追踪编译器。如果构建失败,数据库会是空的或不完整的;这种情况下不要报告"无发现",而要报告构建(因此也就是扫描)失败了。对于解释型语言(Python、JavaScript/TypeScript、Ruby),不需要构建步骤——`database create` 只索引源码。

## 输出

SARIF 输出到 `<out>/codeql-<lang>.sarif`,多语言项目每种语言一个文件。
`generate_report.py` 解析 CodeQL SARIF 的方式与解析 Semgrep/Gosec/Brakeman SARIF 完全相同,因此不需要单独的报告逻辑——只需确保在运行 `generate_report.py` 之前,该文件与其他所有输出落在同一个 `<out>/` 目录里。

## 何时真正使用它

CodeQL 的价值在于深度的过程间污点追踪——它能把用户输入跨多个函数调用一路追踪到危险 sink,这是模式匹配工具做不到的。对于发布前安全审查或处理敏感数据的代码库,这份搭建成本是值得的。对于快速的 pre-commit 检查通常是大材小用——Semgrep + 语言专属 linter 在零头时间里就能给出不错的覆盖。如果用户没有说"深度"或"彻底"或明确点名 CodeQL,不要默认上它——告诉用户它可用并询问。
