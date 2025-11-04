# api/compose_answer.py
from typing import List, Dict, Any
from datetime import datetime
from openai import AzureOpenAI

AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
AZURE_OPENAI_API_KEY  = os.getenv("AZURE_OPENAI_API_KEY")
AZURE_OPENAI_API_VER  = os.getenv("AZURE_OPENAI_API_VERSION", "2025-01-01-preview")
GPT_DEPLOYMENT        = os.getenv("AZURE_OPENAI_GPT_DEPLOYMENT", "gpt-4o-mvp")  # your deployment name

def _format_docs_for_prompt(docs: List[Dict[str, Any]]) -> str:
    lines = []
    for d in docs:
        lines.append(
            f"Title: {d['title']}\n"
            f"Content: {d['content']}\n"
            f"Summary: {d['summary']}\n"
            f"Source: {d['source']}"
        )
    return "\n".join(lines)

def generate_logs_answer(user_query: str, log_docs: List[Dict[str, Any]]) -> str:
    policy_context = "No relevant policies fetched in this view."
    log_context = _format_docs_for_prompt(log_docs) if log_docs else "No relevant logs found."
    today = datetime.now().strftime("%B %d, %Y")

    prompt = (
        "You are an HR/IT compliance assistant.\n"
        f"Use current date: {today}.\n\n"
        f"Query: {user_query}\n\n"
        f"Policy Context (rules): {policy_context}\n\n"
        f"Log Context (events):\n{log_context}\n\n"
        "Response: give a concise, actionable summary. "
        "If there are clear risks/violations, state them; otherwise suggest next steps (broaden time, different systems, etc.)."
    )

    client = AzureOpenAI(
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        api_key=AZURE_OPENAI_API_KEY,
        api_version=AZURE_OPENAI_API_VER,
    )

    resp = client.chat.completions.create(
        model=GPT_DEPLOYMENT,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
    )
    return resp.choices[0].message.content
