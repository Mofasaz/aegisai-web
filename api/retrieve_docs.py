from __future__ import annotations
from typing import List, Dict, Any, Optional
from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient
from api.analyze_nl import interpret_query
from retrieval.azure_events_retriever import search_events

# Simple DTO for UI
Doc = Dict[str, Any]

VECTOR_FIELDS = {
    "policies": "policy_vector",   # <- match your index schema
    "logs":     "log_vector",      # <- match your index schema
}

def make_search_client(endpoint: str, index_name: str, api_key: str) -> SearchClient:
    return SearchClient(endpoint=endpoint, index_name=index_name, credential=AzureKeyCredential(api_key))

def retrieve_docs(
    client: SearchClient,
    query: str,
    index_type: str = "policies",
    top_k: int = 3,
    *,
    vectorized_query=None,         # Optional: pass a VectorizedQuery/ dict if you already built it
    filters: Optional[str] = None, # OData filter string (for logs)
    search_fields: Optional[list[str]] = None,  # optional narrowing
) -> List[Doc]:
    """
    Hybrid search (lexical + vector if provided).
    Returns simple dicts ready for UI / LLM prompting.
    """
    kwargs = {
        "search_text": query or "*",
        "top": top_k,
        "select": ["*"]
    }
    if filters:
        kwargs["filter"] = filters
    if vectorized_query:
        kwargs["vector_queries"] = [vectorized_query]
    if search_fields:
        kwargs["search_fields"] = search_fields
        kwargs["search_mode"] = "any"  # partial token hits

    results = client.search(**kwargs)

    docs: List[Doc] = []
    if index_type == "policies":
        for r in results:
            docs.append({
                "title":   r.get("policy_title", "") or r.get("title", ""),
                "content": r.get("clause_text", "") or r.get("content", ""),
                "summary": r.get("policy_summary", "No summary available."),
                "source":  " > ".join([x for x in [
                            r.get("department", "N/A"),
                            r.get("section", "N/A")
                          ] if x]),
                "raw": dict(r)
            })
    elif index_type == "logs":
        for r in results:
            docs.append({
                "title":   r.get("event_id") or f"Event: {r.get('action', 'N/A')}",
                "content": r.get("status", ""),
                "summary": r.get("log_summary", "No summary available."),
                "source":  f"{r.get('system','N/A')} – {r.get('user_role','N/A')} @ {r.get('timestamp','N/A')}",
                "raw": dict(r)
            })
    return docs

def make_vector_query(vector: list[float], field: str, k: int = 5) -> dict:
    # Azure SDK accepts dict shape for vector queries
    return {"kind": "vector", "vector": vector, "k": k, "fields": field}
