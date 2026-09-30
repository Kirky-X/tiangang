/**
 * 已知漏洞靶场：LLM 输出流入 HTML 渲染 sink（存储型 XSS）。
 *
 * 真实漏洞点：renderReply() 把 agent.run() 返回的模型输出直接赋给
 * el.innerHTML，未走 textContent/框架默认转义，也未过 DOMPurify——
 * 模型输出中的 <script>/<img onerror> 会在页面上下文执行（CWE-79）。
 * 预期命中：llm-sec-output-to-html-render（ERROR）。
 */

class AgentClient {
  async run(input) {
    return `reply for ${input}`;
  }
}

async function renderReply(userInput) {
  const agent = new AgentClient();
  const reply = await agent.run(userInput);
  const log = document.getElementById("chat-log");
  log.innerHTML = reply;
}
