# api/ask_pipeline.py
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone

import os
from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient

from openai import AzureOpenAI

# Reuse your NL interpreter + retriever (already in your repo)
from analyze_nl import interpret_query, GST_TZ
from retrieval.azure_events_retriever import (
    _to_dt, _iso_z, _embed_query,  # we reuse your helpers
)

# =========================
# ENV / CONFIG
# =========================
AZURE_SEARCH_ENDPOINT   = os.getenv("AZURE_SEARCH_ENDPOINT")
AZURE_SEARCH_API_KEY    = os.getenv("AZURE_SEARCH_API_KEY")
INDEX_POLICIES          = os.getenv("AZURE_POLICIES_INDEX", "aegisai-policies-indx")
INDEX_LOGS              = os.getenv("AZURE_EVENTS_INDEX",   "aegisai-logs-indx")

AZURE_OPENAI_ENDPOINT   = os.getenv("AZURE_OPENAI_ENDPOINT")
AZURE_OPENAI_API_KEY    = os.getenv("AZURE_OPENAI_API_KEY")
AZURE_OPENAI_API_VERSION= os.getenv("AZURE_OPENAI_API_VERSION", "2025-01-01-preview")
GPT_DEPLOYMENT          = os.getenv("AZURE_OPENAI_GPT_DEPLOYMENT")  # e.g., gpt-4o or gpt-4.1-mini

TOPK_POLICIES = 5
TOPK_LOGS     = 30

# Policies index expected fields (be defensive—fill gracefully if missing)
POLICY_SELECT = [
    "policy_id","clause_id","policy_title","policy_summary","clause_text",
    "department","section","visibility","allowed_grades"
]
# Logs index fields (match your schema)
LOGS_SELECT = [
    "event_id","timestamp","action","status",
    "user_role","system","location","log_summary","title"
]

# For Azure Search hybrid vector
def _mk_vector_query(vec: Optional[List[float]], field: str, k: int) -> Optional[dict]:
    if not vec:
        return None
    # SDK accepts dict shape for vector queries
    return {"kind": "vector", "vector": vec, "k": k, "fields": field}

# Build OData filter for logs based on parsed NL
def _build_odata_filter(time_min: Optional[datetime], time_max: Optional[datetime],
                        filters: Dict[str, Any], not_filters: Dict[str, Any]) -> Optional[str]:
    parts: List[str] = []
    if time_min:
        parts.append(f"timestamp ge {_iso_z(_to_dt(time_min))}")
    if time_max:
        parts.append(f"timestamp le {_iso_z(_to_dt(time_max))}")
    for k, v in (filters or {}).items():
        if v is None or v == "":
            continue
        parts.append(f"{k} eq '{str(v).replace(\"'\", \"''\")}'")
    for k, v in (not_filters or {}).items():
        if v is None or v == "":
            continue
        parts.append(f"{k} ne '{str(v).replace(\"'\", \"''\")}'")
    return " and ".join(parts) if parts else None


@dataclass
class RetrievedDoc:
    title: str
    content: str
    summary: str
    source: str
    meta: Dict[str, Any]


def _search_policies(query: str, top_k: int = TOPK_POLICIES) -> List[RetrievedDoc]:
    client = SearchClient(
        endpoint=AZURE_SEARCH_ENDPOINT,
        index_name=INDEX_POLICIES,
        credential=AzureKeyCredential(AZURE_SEARCH_API_KEY),
    )

    # Hybrid: vector + lexical query_text
    vec = _embed_query(query)
    vq  = _mk_vector_query(vec, field="policy_vector", k=top_k)  # <- your vector field name
    results = client.search(
        search_text=query or "*",
        top=top_k,
        select=POLICY_SELECT,
        vector_queries=([vq] if vq else None),
        query_type="simple",     # don’t use 'full' when search_text could be "*"
        search_mode="any",
    )

    out: List[RetrievedDoc] = []
    for r in results:
        get = r.get if hasattr(r, "get") else lambda k, d=None: getattr(r, k, d)
        doc = RetrievedDoc(
            title   = get("policy_title", "") or f"[{get('policy_id','?')}/{get('clause_id','?')}]",
            content = get("clause_text", "") or "",
            summary = get("policy_summary", "") or "No summary available.",
            source  = f"{get('department','N/A')} > {get('section','N/A')}",
            meta    = {
                "policy_id": get("policy_id"),
                "clause_id": get("clause_id"),
                "visibility": get("visibility"),
                "allowed_grades": get("allowed_grades"),
            }
        )
        out.append(doc)
    return out


def _search_logs_nl(user_query: str, top_k: int = TOPK_LOGS) -> Tuple[List[RetrievedDoc], Dict[str, Any]]:
    """
    Uses your natural-language interpreter to produce:
      - search_text = user_query + must_terms
      - OData filter from time window / filters / not_filters
      - Always hybrid (vector if available) and partial lexical
    """
    intent = interpret_query(user_query)

    # combine lexical terms
    query_text = " ".join([t for t in [intent.get("search_text") or "", *intent.get("must_terms", [])] if t]).strip() or "*"

    time_min = intent.get("time_min")
    time_max = intent.get("time_max")
    odata    = _build_odata_filter(time_min, time_max, intent.get("filters") or {}, intent.get("not_filters") or {})

    client = SearchClient(
        endpoint=AZURE_SEARCH_ENDPOINT,
        index_name=INDEX_LOGS,
        credential=AzureKeyCredential(AZURE_SEARCH_API_KEY),
    )

    # Vector + lexical
    vec = _embed_query(query_text)
    vq  = _mk_vector_query(vec, field="log_vector", k=top_k)  # <- your logs vector field name
    # Prefer SIMPLE when query may be "*"; use search_mode="any" for partial token match
    results = client.search(
        search_text=query_text,
        filter=odata,
        top=top_k,
        order_by=["timestamp desc"],
        select=LOGS_SELECT,
        vector_queries=([vq] if vq else None),
        query_type=("simple" if query_text == "*" else "full"),
        search_mode="any",
        search_fields=["action","user_role","system","location","status","title","log_summary"],  # index-aware
    )

    out: List[RetrievedDoc] = []
    for r in results:
        get = r.get if hasattr(r, "get") else lambda k, d=None: getattr(r, k, d)
        ts  = get("timestamp")
        ts_s = ts if isinstance(ts, str) else (ts.isoformat().replace("+00:00", "Z") if ts else "")
        out.append(RetrievedDoc(
            title   = get("event_id", "") or f"Event: {get('action','N/A')}",
            content = get("status", "") or "",
            summary = get("log_summary", "") or "",
            source  = f"{get('system','N/A')} - {get('user_role','N/A')} @ {ts_s}",
            meta    = {
                "event_id": get("event_id"),
                "timestamp": ts_s,
                "action": get("action"),
                "status": get("status"),
                "user_role": get("user_role"),
                "system": get("system"),
                "location": get("location"),
                "title": get("title"),
            }
        ))
    return out, intent


def _format_policy_citations(policy_docs: List[RetrievedDoc]) -> List[Dict[str, Any]]:
    cites: List[Dict[str, Any]] = []
    for d in policy_docs:
        cites.append({
            "policy_id": d.meta.get("policy_id"),
            "clause_id": d.meta.get("clause_id"),
            "title": d.title,
            "section": d.source,
            "visibility": d.meta.get("visibility") or "internal",
            "allowed_grades": d.meta.get("allowed_grades") or [],
        })
    return cites


def _format_log_highlights(log_docs: List[RetrievedDoc]) -> List[Dict[str, Any]]:
    highs: List[Dict[str, Any]] = []
    for d in log_docs:
        meta = d.meta or {}
        highs.append({
            "policy_id": meta.get("system") or "logs",         # keeps UI slots consistent
            "clause_id": meta.get("event_id") or meta.get("title") or "event",
            "snippet":   f"{d.source} — {meta.get('action','?')}/{meta.get('status','?')} ({meta.get('location','?')})",
        })
    return highs


def generate_combined_answer(user_query: str,
                             policies: List[RetrievedDoc],
                             logs: List[RetrievedDoc]) -> str:
    policy_context = "\n\n".join(
        [f"Title: {d.title}\nContent: {d.content}\nSummary: {d.summary}\nSource: {d.source}" for d in policies]
    ) or "No relevant policies found."

    log_context = "\n\n".join(
        [f"Event: {d.title}\nStatus: {d.content}\nSummary: {d.summary}\nSource: {d.source}" for d in logs]
    ) or "No relevant logs found—consider broadening search or checking data ingestion."

    today = datetime.now(tz=GST_TZ).strftime("%B %d, %Y")
    prompt = f"""You are an HR+Security compliance copilot. Combine *Policies* (rules) and *Logs* (events) to answer clearly and conservatively.
Date (GST): {today}

Query:
{user_query}

POLICY CONTEXT:
{policy_context}

LOG CONTEXT:
{log_context}

Write:
1) A short, factual answer (2–4 bullets).
2) If any likely violations, say which policy area and why.
3) Actionable next steps (audit, notify, or accept with rationale).

Keep it concise and concrete. Use simple language and avoid speculation.
"""

    client = AzureOpenAI(
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        api_key=AZURE_OPENAI_API_KEY,
        api_version=AZURE_OPENAI_API_VERSION,
    )
    resp = client.chat.completions.create(
        model=GPT_DEPLOYMENT,
        messages=[{"role":"user","content":prompt}],
        temperature=0.1,
    )
    return (resp.choices[0].message.content or "").strip()


def run_ask_pipeline(user_query: str) -> Dict[str, Any]:
    """
    Returns a dict shaped for your UI:
      {
        "answer": "...",
        "citations": [ {policy_id, clause_id, title, section, visibility, allowed_grades}, ... ],
        "highlights": [ {policy_id, clause_id, snippet}, ... ],
        "confidence": 0.78,            # optional heuristic
        "judge_score": 0.75,           # optional heuristic
        "correlation_id": "...",       # optional
      }
    """
    # 1) Retrieve
    policy_docs = _search_policies(user_query, top_k=TOPK_POLICIES)
    log_docs, intent = _search_logs_nl(user_query, top_k=TOPK_LOGS)

    # 2) Compose + generate
    answer = generate_combined_answer(user_query, policy_docs, log_docs)

    # 3) Evidence formatting
    citations  = _format_policy_citations(policy_docs)
    highlights = _format_log_highlights(log_docs)

    # 4) Lightweight confidence heuristic (based on recall breadth)
    conf = 0.55
    if policy_docs and log_docs:
        conf = 0.78
    elif policy_docs or log_docs:
        conf = 0.66

    return {
        "answer": answer,
        "citations": citations,
        "highlights": highlights,
        "confidence": conf,
        "judge_score": conf - 0.03,  # placeholder; wire your judge later
    }
