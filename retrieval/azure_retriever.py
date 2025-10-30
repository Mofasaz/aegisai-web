import os
from azure.search.documents import SearchClient
from azure.core.credentials import AzureKeyCredential

ENDPOINT = os.getenv("AZURE_SEARCH_ENDPOINT")
INDEX    = os.getenv("AZURE_SEARCH_INDEX")
KEY      = os.getenv("AZURE_SEARCH_API_KEY")

_client = SearchClient(endpoint=ENDPOINT, index_name=INDEX, credential=AzureKeyCredential(KEY))

def _normalize_grade(g: str) -> str:
    g = (g or "").strip().upper()
    return g if g.startswith("G") else f"G{g}"

def _doc_get(d, k, default=None):
    # Azure Search returns SearchResult; treat it safely
    try:
        return d[k]
    except Exception:
        return getattr(d, k, default)

def get_chunks(query: str, user_grade: str, top: int = 5):
    g = _normalize_grade(user_grade)
    flt = f"allowed_grades/any(x: x eq '{g}')"

    results = _client.search(
        search_text=query,
        filter=flt,
        query_type="simple",   # use 'semantic' only if you configured it on the index
        top=top,
        select=[
            "policy_id",
            "clause_id",
            "title_data_column",
            "section",
            "clause_text",
            "visibility",
            "allowed_grades",
            "department",
        ],
    )

    chunks = []
    for r in results:
        # Map your index fields -> keys your ask() expects
        chunks.append({
            "policy_id":       _doc_get(r, "policy_id"),
            "clause_id":       _doc_get(r, "clause_id"),
            "title":           _doc_get(r, "title_data_column"),  # mapped
            "section":         _doc_get(r, "section"),
            "clause_text":     _doc_get(r, "clause_text"),        # mapped
            "visibility":      _doc_get(r, "visibility"),
            "allowed_grades":  _doc_get(r, "allowed_grades") or [],
            "department":      _doc_get(r, "department"),
        })
    return chunks
