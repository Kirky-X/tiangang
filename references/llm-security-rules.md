# LLM Security Semgrep Ruleset

把 Cloudflare security-audit 的 AI-AND-LLM 攻击面（间接注入、工具参数注入 sink、不安全输出渲染）降级为 Semgrep 规则，集成进 Tiangang 的 Semgrep 扫描流水线。taint source 是 LLM 调用返回值与检索/工具输出文本，sink 覆盖 shell、代码执行、SQL、URL fetch、文件路径、模板渲染、HTML 渲染；另加一条 prompt 拼接信号规则覆盖间接注入/来源混淆面。

## 设计原则

- **强 sink 规则报 HIGH**（`severity: ERROR`）：模型/检索输出流入 shell 执行、eval/exec、SQL execute、模板字符串渲染（SSTI）、HTML 渲染（XSS）
- **弱信号规则只报 MID**（`severity: WARNING`）：URL fetch（SSRF 面）、写模式文件路径、prompt 拼接信号
- 弱信号刻意压低严重度，避免误报淹没真正的高优先级问题（与 `agent-antipatterns.yml` 同一取舍）
- source 用命名启发式（`metavariable-regex`）圈定 LLM/agent/检索/工具调用，必须叠加 source→sink 完整数据流才成 finding——单独的 LLM 调用、单独的危险函数都不报
- sink 侧统一 `focus-metavariable`：只有命令/查询串/URL/路径/渲染内容本身被 taint 才报，参数化 SQL 的绑定参数、请求 body 等被 taint 不触发
- 这些规则是 AI-AND-LLM 攻击面的静态可判定子集，权限/意图语义类问题刻意不成规则（见注意事项），建议配合人工审核使用

## 规则清单

### Rule 1: LLM Output to Shell（模型输出流入 shell 执行）

- **检测**: taint：LLM 调用返回值/检索或工具输出文本 → `os.system` / `os.popen` / `subprocess.getoutput` / `subprocess.*(..., shell=True)`
- **严重度**: HIGH
- **AI-AND-LLM 对应**: Tool-argument injection into a downstream sink
- **注意**: `subprocess` 走 argv 数组（无 `shell=True`）刻意不报——没有 shell 元字符解释；`shlex.quote` / `int` / `float` 视为净化，净化后的拼接不再触发
- **Semgrep 规则**:

```yaml
rules:
  - id: llm-sec-output-to-shell
    mode: taint
    languages: [python]
    severity: ERROR
    message: "LLM/检索输出流入 shell 执行 sink。验证是否用参数数组替代 shell=True 或 shlex.quote 收敛（AI-AND-LLM: Tool-argument injection）。"
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $OBJ.invoke(...)
              - pattern: $OBJ.run(...)
              - pattern: $OBJ.generate(...)
              - pattern: $OBJ.chat(...)
              - pattern: $OBJ.complete(...)
              - pattern: $OBJ.predict(...)
              - pattern: $OBJ.create(...)
              - pattern: $OBJ(...)
          - metavariable-regex:
              metavariable: $OBJ
              # 只匹配 LLM/agent 相关命名，排除 os.system/subprocess 等普通调用
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
      - patterns:
          - pattern-either:
              - pattern: $OBJ.get_relevant_documents(...)
              - pattern: $OBJ.similarity_search(...)
              - pattern: $OBJ.retrieve(...)
              - pattern: $OBJ.search(...)
              - pattern: $OBJ.query(...)
              - pattern: $OBJ.fetch(...)
              - pattern: $OBJ.run_tool(...)
              - pattern: $OBJ.execute_tool(...)
              - pattern: $OBJ.call_tool(...)
          - metavariable-regex:
              metavariable: $OBJ
              # 检索/工具输出文本：RAG 文档、向量库、工具调用返回（AI-AND-LLM: Indirect injection）
              regex: "(?i)^.*(retriev|vector|rag|knowledge|memory|search|index|scraper|reader|browser|web|mcp).*$"
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: os.system($CMD, ...)
              - pattern: os.popen($CMD, ...)
              - pattern: subprocess.getoutput($CMD, ...)
              - pattern: subprocess.getstatusoutput($CMD, ...)
          - focus-metavariable: $CMD
      - patterns:
          - pattern-either:
              - pattern: subprocess.call($CMD, ..., shell=True, ...)
              - pattern: subprocess.run($CMD, ..., shell=True, ...)
              - pattern: subprocess.Popen($CMD, ..., shell=True, ...)
              - pattern: subprocess.check_call($CMD, ..., shell=True, ...)
              - pattern: subprocess.check_output($CMD, ..., shell=True, ...)
          - focus-metavariable: $CMD
    pattern-sanitizers:
      - pattern-either:
          - pattern: shlex.quote($X)
          - pattern: int($X)
          - pattern: float($X)
```

### Rule 2: LLM Output to Code Exec（模型输出流入动态代码执行）

- **检测**: taint：LLM 调用返回值/检索或工具输出文本 → `eval` / `exec` / `compile`
- **严重度**: HIGH
- **AI-AND-LLM 对应**: Tool-argument injection into a downstream sink
- **注意**: 模型输出作为代码执行等价于注入成功，无净化可用，只有结构化输出解析是正确修法
- **Semgrep 规则**:

```yaml
rules:
  - id: llm-sec-output-to-code-exec
    mode: taint
    languages: [python]
    severity: ERROR
    message: "LLM/检索输出流入 eval/exec/compile 动态执行 sink。模型输出不可作为代码执行，应解析为结构化输出（AI-AND-LLM: Tool-argument injection）。"
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $OBJ.invoke(...)
              - pattern: $OBJ.run(...)
              - pattern: $OBJ.generate(...)
              - pattern: $OBJ.chat(...)
              - pattern: $OBJ.complete(...)
              - pattern: $OBJ.predict(...)
              - pattern: $OBJ.create(...)
              - pattern: $OBJ(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
      - patterns:
          - pattern-either:
              - pattern: $OBJ.get_relevant_documents(...)
              - pattern: $OBJ.similarity_search(...)
              - pattern: $OBJ.retrieve(...)
              - pattern: $OBJ.search(...)
              - pattern: $OBJ.query(...)
              - pattern: $OBJ.fetch(...)
              - pattern: $OBJ.run_tool(...)
              - pattern: $OBJ.execute_tool(...)
              - pattern: $OBJ.call_tool(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(retriev|vector|rag|knowledge|memory|search|index|scraper|reader|browser|web|mcp).*$"
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: eval($CODE, ...)
              - pattern: exec($CODE, ...)
              - pattern: compile($CODE, ...)
          - focus-metavariable: $CODE
```

### Rule 3: LLM Output to SQL（模型输出流入 SQL execute）

- **检测**: taint：LLM 调用返回值/检索或工具输出文本 → `execute` / `executemany` / `executescript` / `sqlalchemy.text` 的查询串参数
- **严重度**: HIGH
- **AI-AND-LLM 对应**: Tool-argument injection into a downstream sink
- **注意**: 参数化查询（query 为字面量、值走绑定参数）刻意不报：`focus-metavariable` 把 sink 收敛到查询串本身；`int` / `float` 数值化视为净化
- **Semgrep 规则**:

```yaml
rules:
  - id: llm-sec-output-to-sql
    mode: taint
    languages: [python]
    severity: ERROR
    message: "LLM/检索输出流入 SQL execute sink。应改用参数化查询，模型输出拼进 SQL 串（含 f-string）视为注入（AI-AND-LLM: Tool-argument injection）。"
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $OBJ.invoke(...)
              - pattern: $OBJ.run(...)
              - pattern: $OBJ.generate(...)
              - pattern: $OBJ.chat(...)
              - pattern: $OBJ.complete(...)
              - pattern: $OBJ.predict(...)
              - pattern: $OBJ.create(...)
              - pattern: $OBJ(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
      - patterns:
          - pattern-either:
              - pattern: $OBJ.get_relevant_documents(...)
              - pattern: $OBJ.similarity_search(...)
              - pattern: $OBJ.retrieve(...)
              - pattern: $OBJ.search(...)
              - pattern: $OBJ.query(...)
              - pattern: $OBJ.fetch(...)
              - pattern: $OBJ.run_tool(...)
              - pattern: $OBJ.execute_tool(...)
              - pattern: $OBJ.call_tool(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(retriev|vector|rag|knowledge|memory|search|index|scraper|reader|browser|web|mcp).*$"
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $CUR.execute($QUERY, ...)
              - pattern: $CUR.executemany($QUERY, ...)
              - pattern: $CUR.executescript($QUERY, ...)
              - pattern: sqlalchemy.text($QUERY, ...)
          - focus-metavariable: $QUERY
    pattern-sanitizers:
      - pattern-either:
          - pattern: int($X)
          - pattern: float($X)
```

### Rule 4: LLM Output to URL Fetch（模型输出流入 URL 请求）

- **检测**: taint：LLM 调用返回值/检索或工具输出文本 → `requests` / `urllib.request.urlopen` / `httpx` 的 URL 参数位
- **严重度**: MID
- **AI-AND-LLM 对应**: Tool-argument injection into a downstream sink
- **注意**: 弱信号只报 MID：模型驱动的抓取常是 agent 的正当功能，缺陷在于缺域名/协议白名单，需审核者验证。只盯 URL 参数位，body/params 携带模型输出不报
- **Semgrep 规则**:

```yaml
rules:
  - id: llm-sec-output-to-url-fetch
    mode: taint
    languages: [python]
    severity: WARNING
    message: "LLM/检索输出流入 URL fetch sink。验证是否有域名/协议白名单校验，防 SSRF 与内网探测（AI-AND-LLM: Tool-argument injection）。"
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $OBJ.invoke(...)
              - pattern: $OBJ.run(...)
              - pattern: $OBJ.generate(...)
              - pattern: $OBJ.chat(...)
              - pattern: $OBJ.complete(...)
              - pattern: $OBJ.predict(...)
              - pattern: $OBJ.create(...)
              - pattern: $OBJ(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
      - patterns:
          - pattern-either:
              - pattern: $OBJ.get_relevant_documents(...)
              - pattern: $OBJ.similarity_search(...)
              - pattern: $OBJ.retrieve(...)
              - pattern: $OBJ.search(...)
              - pattern: $OBJ.query(...)
              - pattern: $OBJ.fetch(...)
              - pattern: $OBJ.run_tool(...)
              - pattern: $OBJ.execute_tool(...)
              - pattern: $OBJ.call_tool(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(retriev|vector|rag|knowledge|memory|search|index|scraper|reader|browser|web|mcp).*$"
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: requests.get($URL, ...)
              - pattern: requests.post($URL, ...)
              - pattern: requests.put($URL, ...)
              - pattern: requests.patch($URL, ...)
              - pattern: requests.delete($URL, ...)
              - pattern: requests.head($URL, ...)
              - pattern: requests.options($URL, ...)
              - pattern: requests.request($METHOD, $URL, ...)
              - pattern: urllib.request.urlopen($URL, ...)
              - pattern: urlopen($URL, ...)
              - pattern: httpx.get($URL, ...)
              - pattern: httpx.post($URL, ...)
              - pattern: httpx.request($METHOD, $URL, ...)
          - focus-metavariable: $URL
```

### Rule 5: LLM Output to File Write（模型输出流入写模式文件路径）

- **检测**: taint：LLM 调用返回值/检索或工具输出文本 → 写/追加/创建模式 `open()` 的路径参数
- **严重度**: MID
- **AI-AND-LLM 对应**: Tool-argument injection into a downstream sink
- **注意**: 弱信号只报 MID：agent 落盘模型产物常是设计内行为，缺陷在于 handler 缺路径白名单/目录约束，需审核者验证。只读路径与「内容写入固定路径」刻意不报
- **Semgrep 规则**:

```yaml
rules:
  - id: llm-sec-output-to-file-write
    mode: taint
    languages: [python]
    severity: WARNING
    message: "LLM/检索输出流入写模式文件路径 sink。验证 handler 是否校验路径白名单/目录约束，防任意路径写入（AI-AND-LLM: Tool-argument injection）。"
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $OBJ.invoke(...)
              - pattern: $OBJ.run(...)
              - pattern: $OBJ.generate(...)
              - pattern: $OBJ.chat(...)
              - pattern: $OBJ.complete(...)
              - pattern: $OBJ.predict(...)
              - pattern: $OBJ.create(...)
              - pattern: $OBJ(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
      - patterns:
          - pattern-either:
              - pattern: $OBJ.get_relevant_documents(...)
              - pattern: $OBJ.similarity_search(...)
              - pattern: $OBJ.retrieve(...)
              - pattern: $OBJ.search(...)
              - pattern: $OBJ.query(...)
              - pattern: $OBJ.fetch(...)
              - pattern: $OBJ.run_tool(...)
              - pattern: $OBJ.execute_tool(...)
              - pattern: $OBJ.call_tool(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(retriev|vector|rag|knowledge|memory|search|index|scraper|reader|browser|web|mcp).*$"
    pattern-sinks:
      - patterns:
          - pattern: open($PATH, $MODE, ...)
          - metavariable-regex:
              metavariable: $MODE
              # 只匹配写/追加/创建模式；只读路径不在本规则范围
              regex: "['\"][wax+]"
          - focus-metavariable: $PATH
      - patterns:
          - pattern: open($PATH, ..., mode=$MODE, ...)
          - metavariable-regex:
              metavariable: $MODE
              regex: "['\"][wax+]"
          - focus-metavariable: $PATH
```

### Rule 6: LLM Output to Template Render（模型输出流入模板字符串渲染）

- **检测**: taint：LLM 调用返回值/检索或工具输出文本 → `render_template_string` / `from_string` / `Template()` 的模板串参数
- **严重度**: HIGH
- **AI-AND-LLM 对应**: Insecure output rendering
- **注意**: 模板串被 taint 即 SSTI（模板语法等价代码执行）；`render_template("静态.html", 变量=输出)` 走变量参数不报
- **Semgrep 规则**:

```yaml
rules:
  - id: llm-sec-output-to-template-render
    mode: taint
    languages: [python]
    severity: ERROR
    message: "LLM/检索输出流入模板字符串渲染 sink（SSTI）。模板串必须静态，动态内容走变量参数（AI-AND-LLM: Insecure output rendering）。"
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $OBJ.invoke(...)
              - pattern: $OBJ.run(...)
              - pattern: $OBJ.generate(...)
              - pattern: $OBJ.chat(...)
              - pattern: $OBJ.complete(...)
              - pattern: $OBJ.predict(...)
              - pattern: $OBJ.create(...)
              - pattern: $OBJ(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
      - patterns:
          - pattern-either:
              - pattern: $OBJ.get_relevant_documents(...)
              - pattern: $OBJ.similarity_search(...)
              - pattern: $OBJ.retrieve(...)
              - pattern: $OBJ.search(...)
              - pattern: $OBJ.query(...)
              - pattern: $OBJ.fetch(...)
              - pattern: $OBJ.run_tool(...)
              - pattern: $OBJ.execute_tool(...)
              - pattern: $OBJ.call_tool(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(retriev|vector|rag|knowledge|memory|search|index|scraper|reader|browser|web|mcp).*$"
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: render_template_string($TPL, ...)
              - pattern: flask.render_template_string($TPL, ...)
              - pattern: $ENV.from_string($TPL)
              - pattern: Template($TPL, ...)
          - focus-metavariable: $TPL
```

### Rule 7: LLM Output to HTML Render（模型输出流入 HTML 渲染）

- **检测**: taint：LLM 调用返回值/检索或工具输出文本 → `innerHTML` / `outerHTML` / `document.write` / `insertAdjacentHTML` / React `dangerouslySetInnerHTML`（javascript/typescript）
- **严重度**: HIGH
- **AI-AND-LLM 对应**: Insecure output rendering
- **注意**: 默认转义路径 `textContent` 与框架插值不报；`DOMPurify.sanitize` / `sanitizeHtml` 视为净化
- **Semgrep 规则**:

```yaml
rules:
  - id: llm-sec-output-to-html-render
    mode: taint
    languages: [javascript, typescript]
    severity: ERROR
    message: "LLM/检索输出流入 HTML 渲染 sink（XSS）。默认用 textContent/框架转义，富文本必须过 DOMPurify（AI-AND-LLM: Insecure output rendering）。"
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $OBJ.invoke(...)
              - pattern: $OBJ.run(...)
              - pattern: $OBJ.generate(...)
              - pattern: $OBJ.chat(...)
              - pattern: $OBJ.complete(...)
              - pattern: $OBJ.predict(...)
              - pattern: $OBJ.create(...)
              - pattern: $OBJ(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
      - patterns:
          - pattern-either:
              - pattern: $OBJ.get_relevant_documents(...)
              - pattern: $OBJ.similarity_search(...)
              - pattern: $OBJ.retrieve(...)
              - pattern: $OBJ.search(...)
              - pattern: $OBJ.query(...)
              - pattern: $OBJ.fetch(...)
              - pattern: $OBJ.run_tool(...)
              - pattern: $OBJ.execute_tool(...)
              - pattern: $OBJ.call_tool(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(retriev|vector|rag|knowledge|memory|search|index|scraper|reader|browser|web|mcp).*$"
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $EL.innerHTML = $HTML
              - pattern: $EL.outerHTML = $HTML
              - pattern: document.write($HTML)
              - pattern: document.writeln($HTML)
              - pattern: $EL.insertAdjacentHTML($POS, $HTML)
          - focus-metavariable: $HTML
      - patterns:
          - pattern: "{ __html: $HTML }"
          - focus-metavariable: $HTML
    pattern-sanitizers:
      - pattern-either:
          - pattern: DOMPurify.sanitize($X)
          - pattern: sanitizeHtml($X)
```

### Rule 8: Prompt Concat Signal（prompt 拼接信号）

- **检测**: 调用点把 f-string / `+` 拼接 / `str.format` / `%` 格式化的结果直接放进 LLM 调用的 prompt 参数位（含 `chat.completions.create` 的 `messages` content 深层）
- **严重度**: MID
- **AI-AND-LLM 对应**: Prompt role and provenance confusion / Indirect injection through retrieved or ingested content
- **注意**: 退化策略：Semgrep 无法静态判断拼接内容是否攻击者可控、来源标注是否在拼接中丢失，规则只标记「调用点拼接」这一特征作为信号，由审核者验证定界与来源标注。prompt 先拼好再传变量的跨语句形态识别不到，见注意事项
- **Semgrep 规则**:

```yaml
rules:
  - id: llm-sec-prompt-concat-signal
    languages: [python]
    severity: WARNING
    message: "调用点拼接动态内容进 LLM prompt（间接注入/来源混淆信号）。验证拼接内容是否保留来源标注与定界符、系统指令是否可被覆盖（AI-AND-LLM: Prompt role and provenance confusion；弱信号，由审核者验证）。"
    pattern-either:
      - patterns:
          - pattern-either:
              - pattern: $OBJ.invoke($PROMPT, ...)
              - pattern: $OBJ.run($PROMPT, ...)
              - pattern: $OBJ.generate($PROMPT, ...)
              - pattern: $OBJ.chat($PROMPT, ...)
              - pattern: $OBJ.complete($PROMPT, ...)
              - pattern: $OBJ.predict($PROMPT, ...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
          - metavariable-pattern:
              metavariable: $PROMPT
              pattern-either:
                # f-string / + 拼接 / format / % 四种调用点拼接形态
                - pattern: 'f"...{$X}..."'
                - pattern: $A + $B
                - pattern: $S.format(...)
                - pattern: $A % $B
      - patterns:
          - pattern-either:
              - pattern: $OBJ.invoke(..., prompt=$PROMPT, ...)
              - pattern: $OBJ.run(..., prompt=$PROMPT, ...)
              - pattern: $OBJ.generate(..., prompt=$PROMPT, ...)
              - pattern: $OBJ.complete(..., prompt=$PROMPT, ...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
          - metavariable-pattern:
              metavariable: $PROMPT
              pattern-either:
                - pattern: 'f"...{$X}..."'
                - pattern: $A + $B
                - pattern: $S.format(...)
                - pattern: $A % $B
      - patterns:
          - pattern: $OBJ.create(..., messages=$MSGS, ...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
          - metavariable-pattern:
              metavariable: $MSGS
              # 深度匹配 messages 结构里任意位置的 f-string 插值
              pattern: <... f"...{$X}..." ...>
```

## 使用方式

规则集已落库为 `rules/llm-security.yml`（8 条规则合并到单一 `rules:` 键下）。与 `agent-antipatterns.yml` 同构，在 Semgrep 调用中通过 `--config` 参数加载，单独跑一次 LLM 安全扫描：

```bash
semgrep scan --config rules/llm-security.yml --sarif --output <out>/llm-security.sarif <target>
```

规则自测/门禁命令（fixture 命中数要求：`vuln_chain.py` >= 3、`prompt_concat.py` >= 1、`clean.py` = 0）。注意须从 tiangang 的父目录运行并带 `tiangang/` 路径前缀，原因见注意事项最后一条：

```bash
semgrep scan --json --metrics=off --config tiangang/rules/llm-security.yml tiangang/tests/fixtures/llm_security
```

`tests/fixtures/` 尚未入库（untracked）时，上面这条目录形态命令会静默 0 命中且无任何 error——semgrep 目录扫描只覆盖 git 跟踪文件。此时对三个 fixture 显式传路径运行即可（入库后目录形态恢复可用；`git check-ignore` 已确认 fixtures 不在忽略表中）：

```bash
semgrep scan --json --metrics=off --config tiangang/rules/llm-security.yml tiangang/tests/fixtures/llm_security/vuln_chain.py tiangang/tests/fixtures/llm_security/prompt_concat.py tiangang/tests/fixtures/llm_security/clean.py
```

输出 SARIF/JSON 与其他工具落入同一目录后，`generate_report.py` 会自动解析并合并进统一报告。

## 完整规则文件

以下为 `rules/llm-security.yml` 的完整内容（可直接保存使用）：

```yaml
rules:
  # LLM/Agent 安全 taint 规则集（AI-AND-LLM 攻击面的静态可判定子集）。
  # source = LLM 调用返回值 / 检索或工具输出文本；sink = shell / 代码执行 / SQL / URL fetch / 文件路径 / 模板渲染 / HTML 渲染。
  # action binding、confused deputy、MCP metadata 当策略等需要权限语义的攻击面无法 taint 化，刻意不成规则（见 references/llm-security-rules.md 注意事项）。

  - id: llm-sec-output-to-shell
    mode: taint
    languages: [python]
    severity: ERROR
    message: "LLM/检索输出流入 shell 执行 sink。验证是否用参数数组替代 shell=True 或 shlex.quote 收敛（AI-AND-LLM: Tool-argument injection）。"
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $OBJ.invoke(...)
              - pattern: $OBJ.run(...)
              - pattern: $OBJ.generate(...)
              - pattern: $OBJ.chat(...)
              - pattern: $OBJ.complete(...)
              - pattern: $OBJ.predict(...)
              - pattern: $OBJ.create(...)
              - pattern: $OBJ(...)
          - metavariable-regex:
              metavariable: $OBJ
              # 只匹配 LLM/agent 相关命名，排除 os.system/subprocess 等普通调用
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
      - patterns:
          - pattern-either:
              - pattern: $OBJ.get_relevant_documents(...)
              - pattern: $OBJ.similarity_search(...)
              - pattern: $OBJ.retrieve(...)
              - pattern: $OBJ.search(...)
              - pattern: $OBJ.query(...)
              - pattern: $OBJ.fetch(...)
              - pattern: $OBJ.run_tool(...)
              - pattern: $OBJ.execute_tool(...)
              - pattern: $OBJ.call_tool(...)
          - metavariable-regex:
              metavariable: $OBJ
              # 检索/工具输出文本：RAG 文档、向量库、工具调用返回（AI-AND-LLM: Indirect injection）
              regex: "(?i)^.*(retriev|vector|rag|knowledge|memory|search|index|scraper|reader|browser|web|mcp).*$"
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: os.system($CMD, ...)
              - pattern: os.popen($CMD, ...)
              - pattern: subprocess.getoutput($CMD, ...)
              - pattern: subprocess.getstatusoutput($CMD, ...)
          - focus-metavariable: $CMD
      - patterns:
          - pattern-either:
              - pattern: subprocess.call($CMD, ..., shell=True, ...)
              - pattern: subprocess.run($CMD, ..., shell=True, ...)
              - pattern: subprocess.Popen($CMD, ..., shell=True, ...)
              - pattern: subprocess.check_call($CMD, ..., shell=True, ...)
              - pattern: subprocess.check_output($CMD, ..., shell=True, ...)
          - focus-metavariable: $CMD
    pattern-sanitizers:
      - pattern-either:
          - pattern: shlex.quote($X)
          - pattern: int($X)
          - pattern: float($X)

  - id: llm-sec-output-to-code-exec
    mode: taint
    languages: [python]
    severity: ERROR
    message: "LLM/检索输出流入 eval/exec/compile 动态执行 sink。模型输出不可作为代码执行，应解析为结构化输出（AI-AND-LLM: Tool-argument injection）。"
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $OBJ.invoke(...)
              - pattern: $OBJ.run(...)
              - pattern: $OBJ.generate(...)
              - pattern: $OBJ.chat(...)
              - pattern: $OBJ.complete(...)
              - pattern: $OBJ.predict(...)
              - pattern: $OBJ.create(...)
              - pattern: $OBJ(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
      - patterns:
          - pattern-either:
              - pattern: $OBJ.get_relevant_documents(...)
              - pattern: $OBJ.similarity_search(...)
              - pattern: $OBJ.retrieve(...)
              - pattern: $OBJ.search(...)
              - pattern: $OBJ.query(...)
              - pattern: $OBJ.fetch(...)
              - pattern: $OBJ.run_tool(...)
              - pattern: $OBJ.execute_tool(...)
              - pattern: $OBJ.call_tool(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(retriev|vector|rag|knowledge|memory|search|index|scraper|reader|browser|web|mcp).*$"
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: eval($CODE, ...)
              - pattern: exec($CODE, ...)
              - pattern: compile($CODE, ...)
          - focus-metavariable: $CODE

  - id: llm-sec-output-to-sql
    mode: taint
    languages: [python]
    severity: ERROR
    message: "LLM/检索输出流入 SQL execute sink。应改用参数化查询，模型输出拼进 SQL 串（含 f-string）视为注入（AI-AND-LLM: Tool-argument injection）。"
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $OBJ.invoke(...)
              - pattern: $OBJ.run(...)
              - pattern: $OBJ.generate(...)
              - pattern: $OBJ.chat(...)
              - pattern: $OBJ.complete(...)
              - pattern: $OBJ.predict(...)
              - pattern: $OBJ.create(...)
              - pattern: $OBJ(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
      - patterns:
          - pattern-either:
              - pattern: $OBJ.get_relevant_documents(...)
              - pattern: $OBJ.similarity_search(...)
              - pattern: $OBJ.retrieve(...)
              - pattern: $OBJ.search(...)
              - pattern: $OBJ.query(...)
              - pattern: $OBJ.fetch(...)
              - pattern: $OBJ.run_tool(...)
              - pattern: $OBJ.execute_tool(...)
              - pattern: $OBJ.call_tool(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(retriev|vector|rag|knowledge|memory|search|index|scraper|reader|browser|web|mcp).*$"
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $CUR.execute($QUERY, ...)
              - pattern: $CUR.executemany($QUERY, ...)
              - pattern: $CUR.executescript($QUERY, ...)
              - pattern: sqlalchemy.text($QUERY, ...)
          - focus-metavariable: $QUERY
    pattern-sanitizers:
      - pattern-either:
          - pattern: int($X)
          - pattern: float($X)

  - id: llm-sec-output-to-url-fetch
    mode: taint
    languages: [python]
    severity: WARNING
    message: "LLM/检索输出流入 URL fetch sink。验证是否有域名/协议白名单校验，防 SSRF 与内网探测（AI-AND-LLM: Tool-argument injection）。"
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $OBJ.invoke(...)
              - pattern: $OBJ.run(...)
              - pattern: $OBJ.generate(...)
              - pattern: $OBJ.chat(...)
              - pattern: $OBJ.complete(...)
              - pattern: $OBJ.predict(...)
              - pattern: $OBJ.create(...)
              - pattern: $OBJ(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
      - patterns:
          - pattern-either:
              - pattern: $OBJ.get_relevant_documents(...)
              - pattern: $OBJ.similarity_search(...)
              - pattern: $OBJ.retrieve(...)
              - pattern: $OBJ.search(...)
              - pattern: $OBJ.query(...)
              - pattern: $OBJ.fetch(...)
              - pattern: $OBJ.run_tool(...)
              - pattern: $OBJ.execute_tool(...)
              - pattern: $OBJ.call_tool(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(retriev|vector|rag|knowledge|memory|search|index|scraper|reader|browser|web|mcp).*$"
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: requests.get($URL, ...)
              - pattern: requests.post($URL, ...)
              - pattern: requests.put($URL, ...)
              - pattern: requests.patch($URL, ...)
              - pattern: requests.delete($URL, ...)
              - pattern: requests.head($URL, ...)
              - pattern: requests.options($URL, ...)
              - pattern: requests.request($METHOD, $URL, ...)
              - pattern: urllib.request.urlopen($URL, ...)
              - pattern: urlopen($URL, ...)
              - pattern: httpx.get($URL, ...)
              - pattern: httpx.post($URL, ...)
              - pattern: httpx.request($METHOD, $URL, ...)
          - focus-metavariable: $URL

  - id: llm-sec-output-to-file-write
    mode: taint
    languages: [python]
    severity: WARNING
    message: "LLM/检索输出流入写模式文件路径 sink。验证 handler 是否校验路径白名单/目录约束，防任意路径写入（AI-AND-LLM: Tool-argument injection）。"
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $OBJ.invoke(...)
              - pattern: $OBJ.run(...)
              - pattern: $OBJ.generate(...)
              - pattern: $OBJ.chat(...)
              - pattern: $OBJ.complete(...)
              - pattern: $OBJ.predict(...)
              - pattern: $OBJ.create(...)
              - pattern: $OBJ(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
      - patterns:
          - pattern-either:
              - pattern: $OBJ.get_relevant_documents(...)
              - pattern: $OBJ.similarity_search(...)
              - pattern: $OBJ.retrieve(...)
              - pattern: $OBJ.search(...)
              - pattern: $OBJ.query(...)
              - pattern: $OBJ.fetch(...)
              - pattern: $OBJ.run_tool(...)
              - pattern: $OBJ.execute_tool(...)
              - pattern: $OBJ.call_tool(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(retriev|vector|rag|knowledge|memory|search|index|scraper|reader|browser|web|mcp).*$"
    pattern-sinks:
      - patterns:
          - pattern: open($PATH, $MODE, ...)
          - metavariable-regex:
              metavariable: $MODE
              # 只匹配写/追加/创建模式；只读路径不在本规则范围
              regex: "['\"][wax+]"
          - focus-metavariable: $PATH
      - patterns:
          - pattern: open($PATH, ..., mode=$MODE, ...)
          - metavariable-regex:
              metavariable: $MODE
              regex: "['\"][wax+]"
          - focus-metavariable: $PATH

  - id: llm-sec-output-to-template-render
    mode: taint
    languages: [python]
    severity: ERROR
    message: "LLM/检索输出流入模板字符串渲染 sink（SSTI）。模板串必须静态，动态内容走变量参数（AI-AND-LLM: Insecure output rendering）。"
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $OBJ.invoke(...)
              - pattern: $OBJ.run(...)
              - pattern: $OBJ.generate(...)
              - pattern: $OBJ.chat(...)
              - pattern: $OBJ.complete(...)
              - pattern: $OBJ.predict(...)
              - pattern: $OBJ.create(...)
              - pattern: $OBJ(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
      - patterns:
          - pattern-either:
              - pattern: $OBJ.get_relevant_documents(...)
              - pattern: $OBJ.similarity_search(...)
              - pattern: $OBJ.retrieve(...)
              - pattern: $OBJ.search(...)
              - pattern: $OBJ.query(...)
              - pattern: $OBJ.fetch(...)
              - pattern: $OBJ.run_tool(...)
              - pattern: $OBJ.execute_tool(...)
              - pattern: $OBJ.call_tool(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(retriev|vector|rag|knowledge|memory|search|index|scraper|reader|browser|web|mcp).*$"
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: render_template_string($TPL, ...)
              - pattern: flask.render_template_string($TPL, ...)
              - pattern: $ENV.from_string($TPL)
              - pattern: Template($TPL, ...)
          - focus-metavariable: $TPL

  - id: llm-sec-output-to-html-render
    mode: taint
    languages: [javascript, typescript]
    severity: ERROR
    message: "LLM/检索输出流入 HTML 渲染 sink（XSS）。默认用 textContent/框架转义，富文本必须过 DOMPurify（AI-AND-LLM: Insecure output rendering）。"
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $OBJ.invoke(...)
              - pattern: $OBJ.run(...)
              - pattern: $OBJ.generate(...)
              - pattern: $OBJ.chat(...)
              - pattern: $OBJ.complete(...)
              - pattern: $OBJ.predict(...)
              - pattern: $OBJ.create(...)
              - pattern: $OBJ(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
      - patterns:
          - pattern-either:
              - pattern: $OBJ.get_relevant_documents(...)
              - pattern: $OBJ.similarity_search(...)
              - pattern: $OBJ.retrieve(...)
              - pattern: $OBJ.search(...)
              - pattern: $OBJ.query(...)
              - pattern: $OBJ.fetch(...)
              - pattern: $OBJ.run_tool(...)
              - pattern: $OBJ.execute_tool(...)
              - pattern: $OBJ.call_tool(...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(retriev|vector|rag|knowledge|memory|search|index|scraper|reader|browser|web|mcp).*$"
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $EL.innerHTML = $HTML
              - pattern: $EL.outerHTML = $HTML
              - pattern: document.write($HTML)
              - pattern: document.writeln($HTML)
              - pattern: $EL.insertAdjacentHTML($POS, $HTML)
          - focus-metavariable: $HTML
      - patterns:
          - pattern: "{ __html: $HTML }"
          - focus-metavariable: $HTML
    pattern-sanitizers:
      - pattern-either:
          - pattern: DOMPurify.sanitize($X)
          - pattern: sanitizeHtml($X)

  - id: llm-sec-prompt-concat-signal
    languages: [python]
    severity: WARNING
    message: "调用点拼接动态内容进 LLM prompt（间接注入/来源混淆信号）。验证拼接内容是否保留来源标注与定界符、系统指令是否可被覆盖（AI-AND-LLM: Prompt role and provenance confusion；弱信号，由审核者验证）。"
    pattern-either:
      - patterns:
          - pattern-either:
              - pattern: $OBJ.invoke($PROMPT, ...)
              - pattern: $OBJ.run($PROMPT, ...)
              - pattern: $OBJ.generate($PROMPT, ...)
              - pattern: $OBJ.chat($PROMPT, ...)
              - pattern: $OBJ.complete($PROMPT, ...)
              - pattern: $OBJ.predict($PROMPT, ...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
          - metavariable-pattern:
              metavariable: $PROMPT
              pattern-either:
                # f-string / + 拼接 / format / % 四种调用点拼接形态
                - pattern: 'f"...{$X}..."'
                - pattern: $A + $B
                - pattern: $S.format(...)
                - pattern: $A % $B
      - patterns:
          - pattern-either:
              - pattern: $OBJ.invoke(..., prompt=$PROMPT, ...)
              - pattern: $OBJ.run(..., prompt=$PROMPT, ...)
              - pattern: $OBJ.generate(..., prompt=$PROMPT, ...)
              - pattern: $OBJ.complete(..., prompt=$PROMPT, ...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
          - metavariable-pattern:
              metavariable: $PROMPT
              pattern-either:
                - pattern: 'f"...{$X}..."'
                - pattern: $A + $B
                - pattern: $S.format(...)
                - pattern: $A % $B
      - patterns:
          - pattern: $OBJ.create(..., messages=$MSGS, ...)
          - metavariable-regex:
              metavariable: $OBJ
              regex: "(?i)^.*(llm|agent|chain|model|client|completion|chat|gpt|claude|gemini|ollama|generator|assistant|bot|tool).*$"
          - metavariable-pattern:
              metavariable: $MSGS
              # 深度匹配 messages 结构里任意位置的 f-string 插值
              pattern: <... f"...{$X}..." ...>
```

## 注意事项

- 强 sink 规则报 HIGH（`severity: ERROR`），弱信号规则只报 MID（`severity: WARNING`），与 `agent-semgrep-rules.md` 的严重度映射一致
- source 是命名启发式：`$OBJ.create` / `$OBJ(...)` 臂按命名圈定，Django `Model.objects.create(...)`、`boto3.client(...)` 等非 LLM 调用也会被当作 source——但必须继续流入 Rule 1-7 的 sink 才成 finding，单独出现不报；误报靠 sink 侧 `focus-metavariable` 收敛
- Rule 8 是「信号由审核者验证」的退化策略，与 agent 规则集 Rule 3/4/6 的取舍同源（Semgrep 无法可靠断言「来源标注是否丢失」「内容是否攻击者可控」，规则退化为标记相关特征）；它只识别调用点直接拼接，`prompt = f"...{q}"` 后再 `llm.invoke(prompt)` 的跨语句形态需要数据流，识别不到，由审核者按 MID 信号人工回溯
- AI-AND-LLM 中需要权限/意图语义的攻击面刻意不成规则：MCP 元数据与工具描述当策略（这些字段能引导模型但不能授权能力，要查的是确定性 allowlist 与 handler 授权）、action-confirmation 绑定、confused-deputy 权限、跨会话/跨租户上下文渗透、持久记忆投毒写侧——静态 taint 对它们不可判定，硬写成 pattern 只会产生噪声，由 tiangang 之外的 review/人工流程覆盖
- `subprocess.run(argv数组)`（无 `shell=True`）与参数化 SQL（`execute(字面量, (值,))`）刻意不报：前者无 shell 元字符解释，后者查询语义不受值影响
- 扫描环境注意：semgrep 默认 semgrepignore 忽略 `tests/` 全树（含 `tests/fixtures/`），且目录扫描只扫 git 跟踪文件。因此 fixture 自测/门禁要从 tiangang 父目录以 `tiangang/tests/fixtures/llm_security` 前缀路径运行（默认忽略表的模式锚定在 cwd，带前缀的路径不命中），且 fixture 文件需已入库；对单个 fixture 文件显式传路径可绕过这两层过滤
