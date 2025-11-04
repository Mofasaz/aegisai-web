# retrieval/azure_events_retriever.py
from __future__ import annotations
import os
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any, Union
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

SEARCH_FIELDS = ["action","user_role","system","location","status","title","log_summary"]

def _mk_lex_query(base_text: str | None,
                  facet_terms: dict[str, str] | None,
                  fuzzy: bool,
                  wildcards: bool) -> tuple[str, bool]:
    toks: list[str] = []

    def _explode(s: str):
        return [t for t in (s or "").replace("/", " ").replace("_", " ").split() if t]

    # 1) from user text
    for t in _explode(base_text or ""):
        if len(t) >= 3:
            piece = t
            if wildcards: piece = f"{piece}*"
            if fuzzy:     piece = f"{piece}~2"
            toks.append(piece)
        else:
            toks.append(t)

    # 2) soft-inject facet values
    for _, v in (facet_terms or {}).items():
        for t in _explode(str(v)):
            if len(t) >= 3:
                piece = t
                if wildcards: piece = f"{piece}*"
                if fuzzy:     piece = f"{piece}~2"
                toks.append(piece)
            else:
                toks.append(t)

    q = " ".join(dict.fromkeys(toks)).strip() or "*"

    # IMPORTANT: if the query collapses to "*", prefer simple query_type.
    used_full = (q != "*")
    return q, used_full

def _coerce_ts(v):
    return _to_dt(v)


def _to_dt(v):
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if not v:
        return None
    s = str(v)
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _esc(val: Any) -> str:
    # Escape single quotes for OData
    return str(val).replace("'", "''")

def _iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    
def get_events_by_ids(ids: List[str]) -> List[Dict[str, Any]]:
    if not ids:
        return []

    out: List[Dict[str, Any]] = []

    # 1) Fast path: try get_document per id (best when ids count is modest)
    try:
        for eid in ids:
            try:
                d = _client.get_document(key=eid)
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
        parts = ["event_id eq '{}'".format(x.replace("'", "''")) for x in batch]
        flt = " or ".join(parts)
    
        results = _client.search(
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

def _build_time_filter(time_min: Optional[Union[str, datetime]],
                       time_max: Optional[Union[str, datetime]]) -> List[str]:
    parts: List[str] = []
    dt_min = _to_dt(time_min)
    dt_max = _to_dt(time_max)
    if dt_min:
        # NO quotes for DateTimeOffset
        parts.append(f"timestamp ge {_iso_z(dt_min)}")
    if dt_max:
        parts.append(f"timestamp le {_iso_z(dt_max)}")
    return parts


def _build_filter_odata(
    time_min: Optional[Union[str, datetime]],
    time_max: Optional[Union[str, datetime]],
    filters: Optional[Dict[str, Any]] = None,
    not_filters: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    parts: List[str] = []
    # time window
    parts.extend(_build_time_filter(time_min, time_max))

    # positive equals
    for field, value in (filters or {}).items():
        if value is None or value == "":
            continue
        parts.append(f"{field} eq '{_esc(value)}'")

    # negative equals
    for field, value in (not_filters or {}).items():
        if value is None or value == "":
            continue
        parts.append(f"{field} ne '{_esc(value)}'")

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
    time_min: Optional[datetime],
    time_max: Optional[datetime],
    *,
    top: int = 50,
    filters: Optional[Dict[str, Any]] = None,
    not_filters: Optional[Dict[str, Any]] = None,
    relax: bool = True,
    partial: bool = True,   # NEW: default to partial token matching
) -> List[dict]:
    """
    Hybrid search with progressive relaxation so partials/fuzzy still return results.
    Passes:
      1) strict: hard OData filters + plain lexical (no fuzzy/wildcards)
      2) fuzzy:  same filters + fuzzy + wildcard on lexical
      3) soft facets: drop equals-filters from OData, push them as lexical soft terms
      4) widen time: extend window (e.g., -7 days) if still empty
      5) drop NOT filters last resort
    Always includes vector query if available.
    """
    # Build vector
    vector_queries = None
    if USE_EVENTS_VECTOR and (query or "").strip():
        vq, _ = _vector_query(query or "")
        if vq:
            vector_queries = [vq]

    # Runner
    def _run(search_text: str | None,
             odata: str | None,
             qtype: str,
             mode: str,
             search_fields: List[str]) -> list[dict]:
        # If search_text collapses to "*", use query_type="simple" to avoid Lucene parse surprises
        qtype_eff = "simple" if (not search_text or search_text.strip() == "*") else qtype
        results = _client.search(
            search_text=search_text,
            filter=odata,
            top=top,
            order_by=["timestamp desc"],
            select=["event_id","timestamp","action","status","user_role","system","location","title","log_summary"],
            query_type=qtype_eff,                 # 'simple' or 'full'
            search_mode=("any" if partial else "all"),  # 'any' so partial token hits count
            search_fields=SEARCH_FIELDS,
            vector_queries=vector_queries,
        )
        out = []
        for r in results:
            out.append({
                "event_id":  _sel(r, "event_id"),
                "timestamp": _sel(r, "timestamp"),
                "action":    _sel(r, "action"),
                "status":    _sel(r, "status"),
                "user_role": _sel(r, "user_role"),
                "system":    _sel(r, "system"),
                "location":  _sel(r, "location"),
                "title":     _sel(r, "title"),
                "log_summary": _sel(r, "log_summary"),
            })
        return out

    # Pass 1: strict lexical, strict OData
    odata1 = _build_filter_odata(time_min, time_max, filters, not_filters)
    q1, used_full1 = _mk_lex_query(query, None, fuzzy=False, wildcards=False)
    rows = _run(q1, odata1, qtype=("full" if used_full1 else "simple"), mode=("any" if partial else "all"), search_fields=SEARCH_FIELDS)
    if rows or not relax:
        return rows

    # Pass 2: fuzzy + wildcard, same OData
    q2, used_full2 = _mk_lex_query(query, None, fuzzy=True, wildcards=True)
    rows = _run(q2, odata1, qtype=("full" if used_full2 else "simple"), mode=("any" if partial else "all"), search_fields=SEARCH_FIELDS)
    if rows:
        return rows

    # Pass 3: soft facets — drop equals filters from OData and inject as lexical
    # Keep ONLY time window hard-filtered (and NOT filters still active here)
    odata3 = _build_filter_odata(time_min, time_max, filters=None, not_filters=not_filters)
    q3, used_full3 = _mk_lex_query(query, (filters or {}), fuzzy=True, wildcards=True)
    rows = _run(q3, odata3, qtype=("full" if used_full3 else "simple"), mode=("any" if partial else "all"), search_fields=SEARCH_FIELDS)
    if rows:
        return rows

    # Pass 4: widen time window (go 7 days back) + soft facets
    if time_min or time_max:
        from datetime import timedelta
        tmin_wide = _to_dt(time_min) - timedelta(days=7) if time_min else None
        tmax_wide = _to_dt(time_max)
        odata4 = _build_filter_odata(tmin_wide, tmax_wide, filters=None, not_filters=not_filters)
        rows = _run(q3, odata4, qtype=("full" if used_full3 else "simple"), mode=("any" if partial else "all"), search_fields=SEARCH_FIELDS)
        if rows:
            return rows

    # Pass 5: last resort—drop NOT filters as well
    odata5 = _build_filter_odata(time_min, time_max, filters=None, not_filters=None)
    rows = _run(q3, odata5, qtype=("full" if used_full3 else "simple"), mode=("any" if partial else "all"), search_fields=SEARCH_FIELDS)
    return rows
