# Agent Anti-Pattern Semgrep Ruleset

把 12-factor-agents 的架构反模式检测降级为 Semgrep 规则，集成进 Tiangang 的 Semgrep 扫描流水线。这些规则检测 agent 代码中的框架黑盒实例化、无 intent 分发、无显式循环等反模式。

## 设计原则

- **强反模式规则报 HIGH**（`severity: ERROR`）：框架黑盒实例化、无 intent 分发、Graph 编排无显式循环
- **弱信号规则只报 MID**（`severity: WARNING`）：错误压缩缺失、散落状态字段、Context 序列化器缺失、基于中断的人类联系
- 弱信号刻意压低严重度，避免误报淹没真正的高优先级问题
- 这些规则是架构反模式的静态特征，比 `review` skill 的 F08 HIGH 检测弱，建议配合使用

## 规则清单

### Rule 1: Framework Black-Box Instantiation（框架黑盒实例化）

- **检测**: `Agent(role=` / `Crew(` / `Task(expected_output=`
- **严重度**: HIGH
- **12fa 对应**: F02 Own your prompts
- **Semgrep 规则**:

```yaml
rules:
  - id: agent-framework-blackbox-instantiation
    languages: [python]
    severity: ERROR
    message: "框架黑盒实例化检测到。应自有 prompt 模板（F02 Own your prompts）。"
    pattern-either:
      - pattern: Agent(role=$ROLE, ...)
      - pattern: Crew(...)
      - pattern: Task(expected_output=$OUTPUT, ...)
```

### Rule 2: Raw Text Agent Run（无 Intent 分发）

- **检测**: `agent.run($RAW_TEXT)` 无结构化 intent
- **严重度**: HIGH
- **12fa 对应**: F01/F04 Intent dispatch
- **Semgrep 规则**:

```yaml
rules:
  - id: agent-raw-text-run
    languages: [python]
    severity: ERROR
    message: "无 intent 分发检测到。应用 typed intent class + switch 分发（F01/F04）。"
    pattern: agent.run($TEXT)
```

### Rule 3: Graph Orchestration Without Explicit Loop（无显式循环的 Graph 编排）

- **检测**: `from langgraph` / `from crewai` import
- **严重度**: HIGH
- **12fa 对应**: F08 Own your control flow
- **注意**: Semgrep 无法静态断言"无 while 循环"（文件级 absence 检测超出能力范围），规则只标记 import 作为信号，由审核者验证显式循环是否存在
- **Semgrep 规则**:

```yaml
rules:
  - id: agent-graph-orchestration-no-explicit-loop
    languages: [python]
    severity: ERROR
    message: "Graph 编排框架导入检测到。验证是否存在显式 while 循环（F08 Own your control flow）。"
    pattern-either:
      - pattern: from langgraph import ...
      - pattern: from crewai import ...
      - pattern: import langgraph
      - pattern: import crewai
```

### Rule 4: Missing Error Compaction（缺失错误压缩）

- **检测**: try/except 无 context 回灌 + 无 `consecutive_errors` 熔断
- **严重度**: MID
- **12fa 对应**: F09 Compact Errors
- **注意**: 弱信号只报 MID。Semgrep 无法静态断言"无 context 回灌"，规则标记 try/except 块作为信号
- **Semgrep 规则**:

```yaml
rules:
  - id: agent-missing-error-compaction
    languages: [python]
    severity: WARNING
    message: "异常捕获检测到。验证是否有 context 回灌 + consecutive_errors 熔断（F09 Compact Errors）。"
    pattern: |
      try:
          ...
      except $E:
          ...
```

### Rule 5: Scattered State Fields（散落状态字段）

- **检测**: `retry_count` / `current_step` / `next_step` 独立持久化
- **严重度**: MID
- **12fa 对应**: F05 Unify execution state
- **注意**: 弱信号只报 MID
- **Semgrep 规则**:

```yaml
rules:
  - id: agent-scattered-state-fields
    languages: [python]
    severity: WARNING
    message: "散落状态字段检测到。应统一执行状态到单一 context（F05 Unify execution state）。"
    pattern-either:
      - pattern: self.retry_count = $V
      - pattern: self.current_step = $V
      - pattern: self.next_step = $V
```

### Rule 6: Missing Context Serializer（缺失 Context 序列化器）

- **检测**: 无 `to_prompt` / `serializeForLLM` / `pack` 方法
- **严重度**: MID
- **12fa 对应**: F03 Own your context window
- **注意**: 弱信号只报 MID。Semgrep 无法可靠检测"方法缺失"（class-level absence），规则标记 context 状态字段作为信号
- **Semgrep 规则**:

```yaml
rules:
  - id: agent-missing-context-serializer
    languages: [python]
    severity: WARNING
    message: "Context 状态字段检测到。验证是否有 to_prompt/serializeForLLM/pack 序列化方法（F03 Own your context window）。"
    pattern-either:
      - pattern: self.messages = $V
      - pattern: self.history = $V
      - pattern: self.context = $V
```

### Rule 7: Interrupt-Based Human Contact（基于中断的人类联系）

- **检测**: `interrupt(` / `raise HumanApprovalRequired` 用于联系人类
- **严重度**: MID
- **12fa 对应**: F07 Contact humans with tool calls
- **注意**: 弱信号只报 MID
- **Semgrep 规则**:

```yaml
rules:
  - id: agent-interrupt-based-human-contact
    languages: [python]
    severity: WARNING
    message: "基于中断的人类联系检测到。应使用 tool call 联系人类（F07 Contact humans with tool calls）。"
    pattern-either:
      - pattern: interrupt(...)
      - pattern: raise HumanApprovalRequired(...)
      - pattern: raise HumanApprovalRequired
```

## 使用方式

将本规则集保存为 `agent-antipatterns.yml`，在 `run_scan.py` 的 Semgrep 调用中通过 `--config` 参数加载：

```bash
semgrep scan --config auto --config agent-antipatterns.yml --sarif --output <out>/semgrep.sarif <target>
```

或者与 `run_scan.py` 解耦，单独跑一次 agent 反模式扫描：

```bash
semgrep scan --config agent-antipatterns.yml --sarif --output <out>/agent-antipatterns.sarif <target>
```

输出 SARIF 文件落入与其他工具相同的 `<out>/` 目录，`generate_report.py` 会自动解析并合并进统一报告。

## 完整规则文件

以下为可直接保存为 `agent-antipatterns.yml` 的完整内容（7 条规则合并到单一 `rules:` 键下）：

```yaml
rules:
  - id: agent-framework-blackbox-instantiation
    languages: [python]
    severity: ERROR
    message: "框架黑盒实例化检测到。应自有 prompt 模板（F02 Own your prompts）。"
    pattern-either:
      - pattern: Agent(role=$ROLE, ...)
      - pattern: Crew(...)
      - pattern: Task(expected_output=$OUTPUT, ...)

  - id: agent-raw-text-run
    languages: [python]
    severity: ERROR
    message: "无 intent 分发检测到。应用 typed intent class + switch 分发（F01/F04）。"
    pattern: agent.run($TEXT)

  - id: agent-graph-orchestration-no-explicit-loop
    languages: [python]
    severity: ERROR
    message: "Graph 编排框架导入检测到。验证是否存在显式 while 循环（F08 Own your control flow）。"
    pattern-either:
      - pattern: from langgraph import ...
      - pattern: from crewai import ...
      - pattern: import langgraph
      - pattern: import crewai

  - id: agent-missing-error-compaction
    languages: [python]
    severity: WARNING
    message: "异常捕获检测到。验证是否有 context 回灌 + consecutive_errors 熔断（F09 Compact Errors）。"
    pattern: |
      try:
          ...
      except $E:
          ...

  - id: agent-scattered-state-fields
    languages: [python]
    severity: WARNING
    message: "散落状态字段检测到。应统一执行状态到单一 context（F05 Unify execution state）。"
    pattern-either:
      - pattern: self.retry_count = $V
      - pattern: self.current_step = $V
      - pattern: self.next_step = $V

  - id: agent-missing-context-serializer
    languages: [python]
    severity: WARNING
    message: "Context 状态字段检测到。验证是否有 to_prompt/serializeForLLM/pack 序列化方法（F03 Own your context window）。"
    pattern-either:
      - pattern: self.messages = $V
      - pattern: self.history = $V
      - pattern: self.context = $V

  - id: agent-interrupt-based-human-contact
    languages: [python]
    severity: WARNING
    message: "基于中断的人类联系检测到。应使用 tool call 联系人类（F07 Contact humans with tool calls）。"
    pattern-either:
      - pattern: interrupt(...)
      - pattern: raise HumanApprovalRequired(...)
      - pattern: raise HumanApprovalRequired
```

## 注意事项

- 这些规则是架构反模式的静态特征，比 `review` skill 的 F08 HIGH 检测弱
- 弱信号规则只报 MID（`severity: WARNING`），避免误报淹没高优先级问题
- 强反模式规则报 HIGH（`severity: ERROR`）
- 建议与 `review` skill 的 `review agent` 子维度配合使用：Tiangang 做快速 SAST 扫描，`review` 做深度架构审核
- Rule 3/4/6 涉及"absence 检测"（无循环、无回灌、无序列化器），Semgrep 无法可靠做文件级/类级 absence 断言，规则退化为"标记相关特征作为信号，由审核者验证"——这是刻意的设计取舍，不是规则缺陷
