"""已知漏洞靶场：LLM 输出拼接进 SQL execute sink（SQL 注入）。

真实漏洞点：run_report() 把 assistant.complete() 返回的模型输出不经参数化
直接 f-string 拼进 SQL 语句，cursor.execute() 只收到一个字符串参数——
模型输出中的引号可闭合字面量并注入任意 SQL（CWE-89）。
预期命中：llm-sec-output-to-sql（ERROR）。
"""

import sqlite3


class Assistant:
    """模拟 LLM 客户端——complete() 返回模型生成的文本。"""

    def complete(self, prompt):
        return "generated text for: " + prompt


def run_report(question):
    assistant = Assistant()
    answer = assistant.complete(question)
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM reports WHERE note = '{answer}'")
    return cursor.fetchall()
