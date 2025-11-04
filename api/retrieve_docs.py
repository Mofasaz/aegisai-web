# api/retrieve_docs.py
from typing import List, Dict, Any, Optional
from api.analyze_nl import interpret_query
from retrieval.azure_events_retriever import search_events

def _join_query_parts(search_text: Optional[str], must_terms: list[str]) -> Optional[str]:
    q = " ".join([x for x in [(search_text or ""), *must_terms] if x]).strip()
    return q or None

def retrieve_logs_docs(user_query: str, top_k: int = 20) -> List[Dict[str, Any]]:
    """
    Runs your NL interpreter + hybrid search and converts results to UI-friendly 'docs':
      { title, content, summary, source, raw }
    """
    intent = interpret_query(user_query or "")

    # Build hybrid lexical text (plain + must_terms) – vector is added inside search_events
    search_text = _join_query_parts(intent.get("search_text"), intent.get("must_terms", []))

    rows = search_events(
        query=search_text,
        time_min=intent.get("time_min"),
        time_max=intent.get("time_max"),
        top=top_k,
        filters=intent.get("filters") or {},
        not_filters=intent.get("not_filters") or {},
        relax=True,         # progressive relaxation on
        partial=True,       # partial token matching ('any')
    )

    # Optional post-filter for “outside/inside hours” (local GST)
    # (We keep this here so your UI can pass *only* the NL and still get the hour band logic.)
    events = rows
    if intent.get("inside_hours") or intent.get("outside_hours"):
        from analyze_nl import outside_hours_predicate, GST_TZ
        from datetime import datetime
        def _to_dt_utc(v):
            if isinstance(v, datetime):
                return v
            try:
                return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
            except Exception:
                return None

        if intent.get("inside_hours"):
            sh, eh = intent["inside_hours"]
            events = []
            for ev in rows:
                ts = _to_dt_utc(ev.get("timestamp"))
                if ts and not outside_hours_predicate(ts, sh, eh):
                    events.append(ev)

        if intent.get("outside_hours"):
            sh, eh = intent["outside_hours"]
            events = []
            for ev in rows:
                ts = _to_dt_utc(ev.get("timestamp"))
                if ts and outside_hours_predicate(ts, sh, eh):
                    events.append(ev)

    # Map to UI docs
    docs: List[Dict[str, Any]] = []
    for r in events:
        title = r.get("event_id") or f"Event: {r.get('action', 'N/A')}"
        docs.append({
            "title":   title,
            "content": r.get("status", "") or "",                     # short content line
            "summary": r.get("log_summary") or "No summary available.",
            "source":  f"{r.get('system', 'N/A')} - {r.get('user_role', 'N/A')} @ {r.get('timestamp', 'N/A')}",
            "raw":     r,                                             # keep original for drill-down
        })
    return docs
