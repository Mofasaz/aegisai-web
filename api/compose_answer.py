from __future__ import annotations
from typing import List, Dict
from datetime import datetime
from openai import AzureOpenAI
import os

# Env (match your existing names)
AZURE_OPENAI_ENDPOINT  = os.getenv("AZURE_OPENAI_ENDPOINT")
AZURE_OPENAI_API_KEY   = os.getenv("AZURE_OPENAI_API_KEY")
AZURE_OPENAI_API_VER   = os.getenv("AZURE_OPENAI_API_VERSION", "2025-01-01-preview")
GPT_DEPLOYMENT         = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mvp")  # set to your chat deployment

def _fmt_block(docs: List[Dict]) -> str:
    lines = []
    for d in docs:
        lines.append(
            f"Title: {d.get('title','')}\n"
            f"Content: {d.get('content','')}\n"
            f"Summary: {d.get('summary','')}\n"
            f"Source: {d.get('source','')}"
        )
    return "\n\n".join(lines)

def compose_answer(query: str, policy_docs: List[Dict], log_docs: List[Dict]) -> str:
    today = datetime.now().strftime("%B %d, %Y")
    policy_block = _fmt_block(policy_docs) if policy_docs else "No relevant policies found."
    log_block    = _fmt_block(log_docs)    if log_docs    else "No relevant logs found—consider broadening search."

    prompt = f"""You are a compliance assistant. Combine insights from policies (rules) and logs (events).
Current date: {today}

User Query:
{query}

Policy Context:
{policy_block}

Log Context:
{log_block}

Write a concise, executive-friendly answer. If logs indicate potential violations, say what/when/who and reference the relevant policies. If evidence is weak or missing, say what to check next."""
    client = AzureOpenAI(
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        api_key=AZURE_OPENAI_API_KEY,
        api_version=AZURE_OPENAI_API_VER,
    )
    resp = client.chat.completions.create(
        model=GPT_DEPLOYMENT,
        messages=[{"role":"user","content": prompt}],
        temperature=0.1,
    )
    return resp.choices[0].message.content.strip()
