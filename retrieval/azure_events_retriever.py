# retrieval/azure_events_retriever.py
import os
from typing import List, Optional, Tuple, Dict, Any
from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient

# Required env
EVENTS_ENDPOINT = os.getenv("AZURE_SEARCH_ENDPOINT")
EVENTS_KEY      = os.getenv("AZURE_SEARCH_API_KEY")
EVENTS_INDEX    = os.getenv("AZURE_EVENTS_INDEX", "aegisai-logs-indx")

# Optional: vector mode (hybrid)
USE_EVENTS_VECTOR = os.getenv("EVENTS_USE_VECTOR", "false").lower() == "true"
AOAI_ENDPOINT     = os.getenv("AZURE_OPENAI_ENDPOINT")
AOAI_KEY          = os.getenv("AZURE_OPENAI_API_KEY")
AOAI_API_VERSION  = os.getenv("AZURE_OPENAI_API_VERSION", "2025-01-01-preview")
AOAI_EMBED_DEPLOY = os.getenv("AZURE_OPENAI_EMBED_DEPLOYMENT")  # e.g., text-embedding-3-large

_client = SearchClient(
    endpoint=EVENTS_ENDPOINT,
    index_name=EVENTS_INDEX,
    credential=AzureKeyCredential(EVENTS_KEY),
)

def get_events_by_ids(ids: List[str]) -> List[Dict[str, Any]]:
    if not ids:
        return []

    out: List[Dict[str, Any]] = []

    # 1) Fast path: try get_document per id (best when ids count is modest)
    try:
        for eid in ids:
            try:
                d = _evt_client.get_document(key=eid)
                out.append({
                    "event_id": d.get("event_id"),
                    "timestamp": d.get("timestamp"),
                    "action": d.get("action"),
                    "status": d.get("status"),
                    "user_role": d.get("user_role"),
                    "system": d.get("system"),
                    "location": d.get("location"),
                })
            except Exception:
                # If a particular ID is missing, just skip it
                pass
        if out:
            return out
    except Exception:
        # If the service/SDK version doesn’t support get_document, fall back to filter
        pass

    # 2) Fallback: OR-filter in small batches
    def _fetch_batch(batch: list[str]) -> list[dict]:
        if not batch:
            return []
        # Escape single quotes for OData literal strings
        parts = [f"event_id eq '{x.replace(\"'\",\"''\")}'" for x in batch]
        flt = " or ".join(parts)
    
        results = _evt_client.search(
            search_text="*",
            filter=flt,
            query_type="simple",
            top=len(batch),
            select=["event_id","timestamp","action","status","user_role","system","location"],
        )
    
        out = []
        for r in results:
            # r is a SearchResult; .get works if it’s dict-like, else use getattr fallback
            get = r.get if hasattr(r, "get") else lambda k, d=None: getattr(r, k, d)
            out.append({
                "event_id":  get("event_id"),
                "timestamp": get("timestamp"),
                "action":    get("action"),
                "status":    get("status"),
                "user_role": get("user_role"),
                "system":    get("system"),
                "location":  get("location"),
            })
        return out


def _sel(d, k, default=None):
    """Safe getter for Azure Search result (SearchResult acts like dict/object)."""
    try:
        return d[k]
    except Exception:
        # support dotted fields if needed in future (not used here)
        return getattr(d, k, default)

def _build_time_filter(time_min: Optional[str], time_max: Optional[str]) -> Optional[str]:
    parts = []
    if time_min:
        parts.append(f"timestamp ge {time_min!r}")  # '2025-10-30T00:00:00Z'
    if time_max:
        parts.append(f"timestamp le {time_max!r}")
    return " and ".join(parts) if parts else None

# --- Vector helpers (optional) ---
def _embed_query(q: str) -> Optional[List[float]]:
    """Return embedding vector for q using Azure OpenAI if configured; else None."""
    if not (USE_EVENTS_VECTOR and AOAI_ENDPOINT and AOAI_KEY and AOAI_EMBED_DEPLOY):
        return None
    try:
        from openai import AzureOpenAI
        client = AzureOpenAI(
            api_key=AOAI_KEY,
            api_version=AOAI_API_VERSION,
            azure_endpoint=AOAI_ENDPOINT,
            timeout=30,
        )
        resp = client.embeddings.create(
            model=AOAI_EMBED_DEPLOY,    # deployment name
            input=q or "",
        )
        return resp.data[0].embedding
    except Exception:
        return None

def _vector_query(q: str) -> Tuple[Optional[dict], Optional[str]]:
    """
    Returns (vector_queries, explanation) for Azure Search.
    We target your 'log_vector' field with profile 'default' as per index json.
    """
    vec = _embed_query(q)
    if not vec:
        return None, None
    # Azure SDK 11.6.0b* uses dict for vector query shape:
    # {"kind":"vector", "vector": [floats], "k": 50, "fields": "log_vector"}
    vq = {"kind": "vector", "vector": vec, "k": 50, "fields": "log_vector"}
    return vq, "vector(log_vector)"

# --- Main search ---
def search_events(
    query: Optional[str],
    time_min: Optional[str],
    time_max: Optional[str],
    top: int = 50,
) -> List[dict]:
    """
    Matches your aegisai-logs-indx fields:
      event_id (key), timestamp (DateTimeOffset), action, user_role, system, location, status
    Also supports hybrid (keyword + vector on log_vector) if EVENTS_USE_VECTOR=true.
    """
    flt = _build_time_filter(time_min, time_max)

    select_fields = [
        "event_id", "timestamp", "action", "status",
        "user_role", "system", "location",
        # You also have: title, id, log_summary, AzureSearch_DocumentKey; fetch if needed.
    ]

    # Hybrid strategy:
    # - If vector enabled and we have a query → include vectorQueries + search_text (empty or query)
    # - Else fall back to keyword search over indexed searchable fields (action, user_role, system, location, title, status, log_summary)
    vector_queries = None
    if USE_EVENTS_VECTOR and (query or "").strip():
        vq, _ = _vector_query(query or "")
        if vq:
            vector_queries = [vq]

    # IMPORTANT: when using vector-only in Azure Search, set search_text=None;
    # for hybrid, you can pass a lightweight search_text to combine (requires service version that supports hybrid).
    search_text = (query or "*") if not vector_queries else None

    results = _client.search(
        search_text=search_text,
        filter=flt,
        top=top,
        order_by=["timestamp desc"],
        select=select_fields,
        query_type="simple",
        vector_queries=vector_queries,  # None if vector disabled/unavailable
    )

    out: List[dict] = []
    for r in results:
        out.append({
            "event_id":  _sel(r, "event_id"),
            "timestamp": _sel(r, "timestamp"),
            "action":    _sel(r, "action"),
            "status":    _sel(r, "status"),
            "user_role": _sel(r, "user_role"),
            "system":    _sel(r, "system"),
            "location":  _sel(r, "location"),
            # risk_context not present in your index—left out intentionally
        })
    return out
