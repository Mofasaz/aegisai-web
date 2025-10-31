import os
from azure.search.documents import SearchClient
from azure.core.credentials import AzureKeyCredential
from azure.search.documents.models import VectorizedQuery
from azure.core.exceptions import HttpResponseError
from openai import AzureOpenAI
from typing import Tuple, List, Dict

ENDPOINT = os.getenv("AZURE_SEARCH_ENDPOINT")
INDEX    = os.getenv("AZURE_SEARCH_INDEX")
KEY      = os.getenv("AZURE_SEARCH_API_KEY")

if not all([ENDPOINT, INDEX, KEY]):
    raise RuntimeError("Azure Search is not configured: set AZURE_SEARCH_ENDPOINT, AZURE_SEARCH_INDEX, AZURE_SEARCH_API_KEY")
    
_client = SearchClient(endpoint=ENDPOINT, index_name=INDEX, credential=AzureKeyCredential(KEY))
_aoai_client = None

# ---- Add to retrieval/azure_retriever.py -----------------------------------
from typing import Tuple, List, Dict

def count_restricted_hits(query: str, top:int = 5) -> Tuple[int, List[Dict]]:
    """
    Returns (#hits, lite-metadata) for restricted policies that match the query.
    NOTE: This does NOT return clause_text; it's only for telemetry/anomaly logging.
    """
    results = _client.search(
        search_text=query,
        filter="visibility eq 'restricted'",
        query_type="simple",
        top=top,
        select=["policy_id", "clause_id", "policy_title", "section", "visibility"]
    )
    hits = []
    for r in results:
        hits.append({
            "policy_id":    _doc_get(r, "policy_id"),
            "clause_id":    _doc_get(r, "clause_id"),
            "title":        _doc_get(r, "policy_title"),
            "section":      _doc_get(r, "section"),
            "visibility":   _doc_get(r, "visibility"),
        })
    return len(hits), hits

# Lazy Embedding client
def _get_aoai():
    global _aoai_client
    if _aoai_client is None:
        _aoai_client = AzureOpenAI(
            api_key=os.getenv("AZURE_OPENAI_API_KEY"),
            api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2025-01-01-preview"),
            azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
        )
    return _aoai_client

_EMBED_DEPLOY = os.getenv("AZURE_OPENAI_EMBED_DEPLOYMENT")  # e.g., textemb3 (1536 dims)

def _normalize_grade(g: str) -> str:
    return (g or "").strip()

def _policy_filter_for_grade(g: str) -> str:
    """
    visibility != 'restricted'  → allowed (no grade check)
    visibility == 'restricted' → must match allowed_grades
    """
    # 'visibility' is stored in lower case and 'allowed_grades' in upper case
    return (
        "(visibility ne 'restricted') "
        f"or (visibility eq 'restricted' and allowed_grades/any(x: x eq '{g}'))"
    )

def _doc_get(d, k, default=None):
    # Azure Search returns SearchResult; treat it safely
    try:
        return d[k]
    except Exception:
        return getattr(d, k, default)

def _embed_query(text: str) -> list[float]:
    _aoai = _get_aoai()
    out = _aoai.embeddings.create(model=_EMBED_DEPLOY, input=text)
    return out.data[0].embedding

def get_chunks_vector(query: str, user_grade: str, top: int = 5, k: int = 20, hybrid: bool = True):
    """
    Vector or hybrid (text + vector) retrieval using 'embedding' field.
    - top: final number of docs returned to caller
    - k: neighbors to pull from vector stage before optional hybrid re-rank on server
    """
    g = _normalize_grade(user_grade)
    flt = _policy_filter_for_grade(g)

    qvec = _embed_query(query)
    vq = VectorizedQuery(vector=qvec, k_nearest_neighbors=k, fields="content_vector")

    try:
        if hybrid:
            # HYBRID: combine sparse (text) + dense (vector)
            results = _client.search(
                search_text=query,                  # sparse term matching
                vector_queries=[vq],                # dense vector nearest neighbors
                filter=flt,
                query_type="simple",
                top=top,
                select=[
                    "policy_id","clause_id","clause_text","section",
                    "visibility","allowed_grades","department","policy_title"
                ],
            )
        else:
            # VECTOR-ONLY
            results = _client.search(
                search_text=None,
                vector_queries=[vq],
                filter=flt,
                top=top,
                select=[
                    "policy_id","clause_id","clause_text","section",
                    "visibility","allowed_grades","department","policy_title"
                ],
            )

        out = []
        for r in results:
            out.append({
                "policy_id":       _doc_get(r, "policy_id"),
                "clause_id":       _doc_get(r, "clause_id"),
                "title":           _doc_get(r, "policy_title"),
                "section":         _doc_get(r, "section"),
                "clause_text":     _doc_get(r, "clause_text"),
                "visibility":      _doc_get(r, "visibility"),
                "allowed_grades":  _doc_get(r, "allowed_grades") or [],
                "department":      _doc_get(r, "department"),
                # Optional: include scores
                # "score":           _doc_get(r, "@search.score")
            })
        return out

    except HttpResponseError as e:
        # Bubble up for clearer error in /ask
        raise

def get_chunks(query: str, user_grade: str, top: int = 5):
    g = _normalize_grade(user_grade)
    flt = _policy_filter_for_grade(g)

    results = _client.search(
        search_text=query,
        filter=flt,
        query_type="simple",   # use 'semantic' only if you configured it on the index
        top=top,
        select=[
            "policy_id",
            "clause_id",
            "policy_title",
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
            "title":           _doc_get(r, "policy_title"),  # mapped
            "section":         _doc_get(r, "section"),
            "clause_text":     _doc_get(r, "clause_text"),        # mapped
            "visibility":      _doc_get(r, "visibility"),
            "allowed_grades":  _doc_get(r, "allowed_grades") or [],
            "department":      _doc_get(r, "department"),
        })
    return chunks
