"""阴性对照（negative control）：同样的 LLM 数据流，全部 sink 已正确消毒。

本文件与阳性样例使用相同形态的数据流（LLM/检索输出进入 SQL、shell），
但每个 sink 都有源码可见的消毒层：
  - SQL 走参数化查询（占位符 + 参数元组），查询串是静态字面量；
  - shell 走参数数组（shell=False 语义），用户/模型数据永远不进 shell 解析器；
  - 数值先过 int()/isdigit() 约束。
正确结果：零 finding。若本文件被任何 llm-sec-* / web-base-* 规则命中，
说明规则集过报（FP 信号），优先修规则而不是放行。
"""

import os
import sqlite3
import subprocess


class Assistant:
    """模拟 LLM 客户端——chat() 返回模型生成的文本。"""

    def chat(self, prompt):
        return "answer for: " + prompt


def lookup_notes(question):
    assistant = Assistant()
    answer = assistant.chat(question)
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notes WHERE body = ?", (answer,))
    return cursor.fetchall()


def set_limit(raw):
    assistant = Assistant()
    answer = assistant.chat(raw)
    limit = int(answer) if answer.isdigit() else 10
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events LIMIT ?", (limit,))
    return cursor.fetchall()


def ping_host(raw):
    assistant = Assistant()
    answer = assistant.chat(raw)
    subprocess.run(["ping", "-c", "1", answer], check=False)
    return os.path.exists("/etc/hosts")
