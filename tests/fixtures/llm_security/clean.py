# 仅供规则自测的正确样例：rules/llm-security.yml 的 llm-sec- 规则应 0 命中
import os
import shlex
import subprocess

from openai import OpenAI

ALLOWED_COMMANDS = {"ls": ["ls", "-la"], "disk": ["df", "-h"]}


def summarize(client, text):
    # prompt 为字面量/普通变量，不含调用点拼接 → 信号规则不命中
    reply = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": text}],
    )
    # 模型输出只做返回，不流入任何 sink → taint 规则不命中
    return reply.choices[0].message.content


def run_allowed_command(name):
    # 命令来自白名单且走 argv 数组，无 shell=True → 不命中
    subprocess.run(ALLOWED_COMMANDS[name], check=True)


def announce_reply(client):
    reply = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "Summarize the repository README"}],
    )
    text = reply.choices[0].message.content
    # 模型输出经 shlex.quote 净化后才进 shell → 不命中
    os.system("echo " + shlex.quote(text))
