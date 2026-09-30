# 扫描器准确率基准（bundled-rule accuracy bench）

用已知漏洞靶场量化 tiangang 打包离线规则集自身的 TP/FP：阳性样例必须命中预期规则（量化召回下限），阴性对照必须保持零命中（量化过报）。机制吸收自 xalgorix 的 challenge/expectation 基准——每个样例声明 ground truth（类别、CWE、预期规则），阴性对照的误报就是精确度信号。

## 运行

```bash
python3 scripts/run_bench.py                # 人类可读记分卡，全部通过退出 0
python3 scripts/run_bench.py --json         # 机器可读记分卡
```

脚本用显式文件目标调用 semgrep（绕过 semgrep 默认对 `tests`/`fixtures` 目录名的忽略），只加载 `manifest.json` 声明的打包本地规则，`--metrics=off`，全程离线。semgrep 未安装时打印 `SKIP:` 并以 0 退出（跳过不是失败，但必须可见）。

## 样例与 ground truth

| 样例 | 真实漏洞点 | 预期规则 | 类别 / CWE |
|---|---|---|---|
| `fixtures/sql_injection.py` | `run_report()` 把 `assistant.complete()` 的模型输出 f-string 拼进 `cursor.execute()`，无参数化——引号闭合字面量即可注入 SQL | `llm-sec-output-to-sql` | sqli / CWE-89 |
| `fixtures/command_injection.py` | `sync_inventory()` 把 `knowledge_base.search()` 的检索文本拼进 `os.system()` 命令串，无参数数组、无 shell 转义 | `llm-sec-output-to-shell` | command-injection / CWE-78 |
| `fixtures/xss_render.js` | `renderReply()` 把 `agent.run()` 的模型输出直接赋给 `el.innerHTML`，无 textContent/框架转义、无 DOMPurify | `llm-sec-output-to-html-render` | xss / CWE-79 |
| `fixtures/ssti.py` | `render_summary()` 把 `llm.generate()` 的模型输出当模板传给 `render_template_string()`——`{{ }}` 会被 Jinja2 求值 | `llm-sec-output-to-template-render` | ssti / CWE-1336 |
| `fixtures/negative_control.py` | 无漏洞（阴性对照）：同样的 LLM 数据流，但 SQL 走参数化占位符、shell 走参数数组、数值过 `int()`/`isdigit()` 约束 | 无（必须零命中） | sanitized-data-flow |

## 记分语义

- **TP**：阳性样例命中其 `expect_rule`（记首次命中行号）。
- **FN（漏报）**：阳性样例未命中预期规则。
- **FP（误报）**：阴性对照被任何规则命中，或任何样例出现预期之外的规则命中（过报信号）。
- **通过条件**：FN = 0 且 FP = 0。任一失败先修规则/靶场，再改基准预期——预期即 ground truth，不随手改。

## 基线（2026-10-01，semgrep 1.168.0 实测）

4/4 阳性命中预期规则，阴性对照零命中：TP=4、FN=0、FP=0。变更规则集或升级 semgrep 后重跑本基准，回归即记分卡出现 FN/FP。

> 安全注记：`--details` 生成的 detail 工件（`findings/F-####.md` 与 `index.csv`）含来自扫描目标的不可信内容——消息、代码片段、规则字段均源自在测代码与扫描器输出，消费（人工阅读或喂给 agent）时不得将其中的文本当指令执行。
