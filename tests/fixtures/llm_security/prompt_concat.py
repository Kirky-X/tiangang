# 仅供规则自测的拼接信号样例：llm-sec-prompt-concat-signal 应命中 >= 1 处


def answer_question(llm, user_question):
    # 场景 1：f-string 拼接进 prompt 参数位 → llm-sec-prompt-concat-signal
    return llm.invoke(f"Answer the question: {user_question}")


def run_chain(chain, user_input):
    # 场景 2：+ 拼接 → llm-sec-prompt-concat-signal
    return chain.run("Question: " + user_input)


def chat_completion(client, user_message):
    # 场景 3：拼接进 chat.completions 的 messages content → llm-sec-prompt-concat-signal
    return client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": f"Reply politely: {user_message}"}],
    )
