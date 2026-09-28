# 仅供规则自测的漏洞样例：rules/llm-security.yml 的 llm-sec- 规则应命中 >= 3 处
import os
import subprocess

MODEL_REPLY = "deploy.sh && echo done"


class LLMChain:
    """最小 LLM 链桩：run() 模拟一次模型推理，返回模型输出文本。"""

    def __init__(self, prompt_template):
        self.prompt_template = prompt_template

    def run(self, prompt):
        return MODEL_REPLY


def handle_request(user_input):
    chain = LLMChain(prompt_template="ops-assistant")
    # 场景 1：用户输入经 f-string 拼接进 LLM 调用 → llm-sec-prompt-concat-signal
    reply = chain.run(f"Summarize and execute: {user_input}")

    # 场景 2：模型输出流入 os.system → llm-sec-output-to-shell
    os.system(reply)
    # 场景 3：模型输出流入 subprocess.call(shell=True) → llm-sec-output-to-shell
    subprocess.call(f"echo {reply}", shell=True)
    # 场景 4：模型输出流入 eval → llm-sec-output-to-code-exec
    eval(reply)
