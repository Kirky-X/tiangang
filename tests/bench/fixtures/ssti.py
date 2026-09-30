"""已知漏洞靶场：LLM 输出流入模板字符串渲染 sink（SSTI）。

真实漏洞点：render_summary() 把 llm.generate() 返回的模型输出作为模板
传给 render_template_string()——模型输出中的 {{ ... }} / {% ... %} 会被
Jinja2 当模板语法求值，可触发服务端模板注入直通 RCE（CWE-1336）。
预期命中：llm-sec-output-to-template-render（ERROR）。
"""

from flask import render_template_string


class ChatModel:
    """模拟 LLM 客户端——generate() 返回模型生成的文本。"""

    def generate(self, prompt):
        return "summary of: " + prompt


def render_summary(topic):
    llm = ChatModel()
    summary = llm.generate(topic)
    return render_template_string(summary)
