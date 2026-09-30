"""已知漏洞靶场：检索（RAG）输出流入 shell 执行 sink（命令注入）。

真实漏洞点：sync_inventory() 把 knowledge_base.search() 返回的检索文本
直接拼进传给 os.system() 的命令串，未走参数数组也未做 shell 转义——
被检索文档中携带的元字符可注入任意命令（CWE-78）。
预期命中：llm-sec-output-to-shell（ERROR）。
"""

import os


class KnowledgeBase:
    """模拟向量库/检索服务——search() 返回文档文本。"""

    def search(self, query):
        return "doc text for " + query


def sync_inventory(sku):
    knowledge_base = KnowledgeBase()
    doc = knowledge_base.search(sku)
    os.system("inventory-sync --sku " + doc)
