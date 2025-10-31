import os, uuid, json, re
from pathlib import Path
from fastapi import FastAPI, HTTPException, Response, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from api.models import *
from api.chains import get_llm
from rules.engine import analyze_events
from retrieval.azure_retriever import get_chunks, get_chunks_vector, count_restricted_hits
from datetime import datetime, timezone
from rules.intent import match_risky_intent
from api.auth import require_user, UserPrincipal

try:
    from integrations.powerbi import push_rows
except Exception:
    def push_rows(rows):
        # safe no-op fallback
        import logging, json
        logging.info("[telemetry] (noop) %s", json.dumps({"rows": rows})[:500])


app = FastAPI(title="AegisAI", docs_url="/docs", redoc_url="/redoc")
USE_VECTOR = os.getenv("USE_VECTOR", "true").lower() == "true"

@app.get("/me")
def me(user: UserPrincipal = Depends(require_user)):
    return {
        "oid": user.oid,
        "name": user.name,
        "upn": user.upn,
        "roles": user.roles,
        "grade": user.grade
    }

@app.get("/healthz")
def healthz():
    return {"status": "ok"}  

def push_rows(rows: list[dict]):
    url = os.getenv("POWERBI_PUSH_URL")
    if not url:
        return
    try:
        import requests
        requests.post(url, json=rows, timeout=4)
    except Exception:
        pass

def _llm_judge(answer: str, snippets: list[str]) -> dict:
    """Tiny LLM judge returning JSON: {'grounding_score': float, 'issues': [..]}"""
    try:
        llm = get_llm()
        sys = ("You are a strict policy auditor. Score groundedness 0..1 ONLY from provided snippets. "
               "Return JSON: {\"grounding_score\": float, \"issues\": [string]}. No extra text.")
        user = f"Answer:\n{answer}\n\nSnippets:\n" + "\n---\n".join(snippets)
        out = llm.invoke([{"role":"system","content":sys},{"role":"user","content":user}])
        return json.loads(getattr(out, "content", str(out)))
    except Exception:
        return {"grounding_score": 0.6, "issues": ["judge_error"]}

def _compute_confidence(chunks: list[dict], judge_score: float, restricted_removed: int) -> float:
    """Blend simple retrieval heuristics with judge score."""
    # Heuristic from retrieval:
    base = 0.35 + min(len(chunks), 5) * 0.1   # 0.45..0.85 depending on number of chunks
    base = min(base, 0.9)
    if restricted_removed > 0:
        base -= 0.05
    # Blend with judge score
    conf = 0.5 * base + 0.5 * float(judge_score or 0.6)
    return round(max(0.0, min(conf, 1.0)), 2)

@app.post("/ask", response_model=AskResponseV2)
def ask(req: AskRequest, response: Response, user: UserPrincipal = Depends(require_user)):
    # 0) Derive grade from token; allow body fallback for demos
    effective_grade = user.grade or getattr(req, "user_grade", None)
        
    # 1) Attach a correlation id for end-to-end tracing (also echoed in JSON)
    corr = str(uuid.uuid4())
    response.headers["X-Correlation-Id"] = corr
    try:
        if USE_VECTOR:
            chunks = get_chunks_vector(req.query, effective_grade, top=5, k=20, hybrid=True)
        else:
            chunks = get_chunks(req.query, effective_grade)  # your existing keyword retriever
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Policy search failed: {type(e).__name__}: {e}")

    # 2a) Peek at restricted hits (meta only; no text leak)
    restricted_count, restricted_meta = 0, []
    try:
        restricted_count, restricted_meta = count_restricted_hits(req.query)
    except Exception:
        restricted_count, restricted_meta = 0, []
        # non-fatal: telemetry peek failing must not block Q&A
        pass
        
    # 3) Risky intent detection (simple regex bank)
    risky_pat = match_risky_intent(req.query)
    reasons: list[str] = []
    if risky_pat:
        reasons.append(f"risky_intent:{risky_pat}")
    if not chunks and restricted_count > 0:
        reasons.append("restricted_probe")

    # 4) Push anomaly row to Power BI if anything suspicious
    if reasons:
        try:
            row = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "user_id": user.upn or user.oid or "",  # fill with AAD UPN later if you add auth
                "user_grade": (effective_grade or ""),
                "query": req.query,
                "reason": ";".join(reasons),
                "restricted_hits": restricted_count,
                "top_policies": ", ".join([f"{m.get('policy_id','')}/{m.get('clause_id','')}" for m in restricted_meta[:3]]),
                "risk_score": 70 if "restricted_probe" in reasons else 50,
                "correlation_id": corr,
            }
            push_rows([row])
        except Exception:
            # never fail the user’s request because telemetry failed
            pass

    # 5) If nothing visible to the user, return enriched “no content” reply
    if not chunks:
        return AskResponseV2(
            answer="No matching policy content found.",
            citations=[],
            highlights=[],
            reasoning="No clause matched your visibility for this query.",
            confidence=None,
            restricted_probe=("restricted_probe" in reasons),
            risk_reasons=reasons or None,
            correlation_id=corr,
        )

    # 6) Build context and call LLM
    #    Expect each chunk to have: policy_id, clause_id, clause_text, title (mapped from policy_title), section, visibility, allowed_grades
    ctx = "\n\n".join([f"[{c['policy_id']}/{c['clause_id']}] {c['clause_text']}" for c in chunks])

    llm = get_llm()
    msg = [
        {"role": "system",
         "content": "You are a policy assistant. Answer ONLY from the provided policy context. "
                    "Cite clause IDs in brackets like [EK-XXX/CLAUSE-YY]. "
                    "Respond as concise BULLET POINTS (use '• ' at the start of each line)."},
        {"role": "user", "content": f"Q: {req.query}\n\nContext:\n{ctx}"}
    ]
    out = llm.invoke(msg)
    answer = getattr(out, "content", str(out))

    # 7) LLM judge + confidence
    judge = _llm_judge(answer, [c["clause_text"] for c in chunks[:3]])
    restricted_removed = 1 if ("restricted_probe" in reasons) else 0
    confidence = _compute_confidence(chunks, judge.get("grounding_score", 0.6), restricted_removed)
    
    # 8) Shape citations + UX highlights
    #citations = [
    #    Citation(**{k: v for k, v in c.items() if k in {"policy_id", "clause_id", "title", "section", "visibility", "allowed_grades"}})
    #    for c in chunks
    #]
    #highlights = [
    #    {
    #        "policy_id": c["policy_id"],
    #        "clause_id": c["clause_id"],
    #        # small, safe preview (no more than ~180 chars)
    #        "snippet": (c.get("clause_text", "")[:180] + ("…" if len(c.get("clause_text", "")) > 180 else ""))
    #    }
    #    for c in chunks[:5]
    #]
    citations = []
    for c in chunks:
        citations.append(Citation(
            policy_id=c["policy_id"],
            clause_id=c["clause_id"],
            title=c.get("title") or c.get("policy_title"),
            section=c.get("section"),
            visibility=c.get("visibility"),
            allowed_grades=c.get("allowed_grades") or []
        ))

    highlights = [{
        "policy_id": c["policy_id"],
        "clause_id": c["clause_id"],
        "snippet": (c.get("clause_text", "")[:220] + ("…" if len(c.get("clause_text", "")) > 220 else "")),
    } for c in chunks[:5]]

    # 9) Return enriched JSON
    reasons_ext = (judge.get("issues") or []) + reasons
    return AskResponseV2(
        answer=answer,
        citations=citations,
        highlights=highlights,
        reasoning="Answer strictly derived from matched policy clauses.",
        confidence=confidence,  # placeholder; later blend vector/reranker scores
        restricted_probe=("restricted_probe" in reasons),
        risk_reasons=(reasons_ext or None),
        correlation_id=corr,
    )   
    #    if not chunks:
    #        return AskResponse(answer="No matching policy content found.", citations=[])
    #    ctx = "\n\n".join([f"[{c['policy_id']}/{c['clause_id']}] {c['clause_text']}" for c in chunks])
    #    llm = get_llm()
    #    msg = [
    #        {"role":"system","content":"Answer ONLY from provided policy context. Cite clause IDs."},
    #        {"role":"user","content": f"Q: {req.query}\n\nContext:\n{ctx}"}
    #    ]
    #    out = llm.invoke(msg)
    #    citations = [Citation(**{k:v for k,v in c.items() if k in {"policy_id","clause_id","title","section","visibility","allowed_grades"}}) for c in chunks]
    #    return AskResponse(answer=getattr(out, 'content', str(out)), citations=citations)
            
    # except Exception as e:
       # raise HTTPException(status_code=500, detail=f"Policy search failed: {type(e).__name__}: {e}")

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    anomalies = analyze_events(req.events)
    return AnalyzeResponse(anomalies=anomalies)

@app.post("/narrative", response_model=NarrativeResponse)
def narrative(req: NarrativeRequest):
    items = []
    for it in req.items:
        # quick link: use signals + resource as query to find related policy chunks
        q = " ".join(it.signals + [it.event.action or "", it.event.resource or ""]).strip()
        chunks = get_chunks(q, req.items[0].event.role)  # simple proxy; in Azure use grade claim
        policy_refs = [LinkedPolicy(policy_id=c['policy_id'], clause_id=c['clause_id']) for c in chunks[:3]]
        story = f"{it.event.role} in {it.event.user_dept} performed {it.event.action} on {it.event.resource}. Signals: {', '.join(it.signals)}. Related clauses: " + ", ".join([f"{p.policy_id}/{p.clause_id}" for p in policy_refs])
        rem = ["Notify line manager", "Quarantine or reverse action if possible", "Schedule policy refresher"]
        items.append(NarrativeItem(event_id=it.event.event_id, narrative=story, remediation=rem, linked_policies=policy_refs))
    return NarrativeResponse(items=items)

@app.post("/attest", response_model=AttestResponse)
def attest(req: AttestRequest):
    now = datetime.now(timezone.utc).isoformat()
    # offline: just return ok; Azure phase will push to Power BI
    return AttestResponse(status="ok", attested_at=now)

@app.post("/anomalies/push", response_model=AnomalyPushResponse)
def push_anomalies(req: AnomalyPushRequest):
    # offline: stubbed success; Azure phase uses powerbi.push_rows
    return AnomalyPushResponse(status="ok", count=len(req.items))

# ----- STATIC (after API), with absolute path -----
BASE_DIR = Path(__file__).resolve().parent.parent
PUBLIC_DIR = BASE_DIR / "public"

if PUBLIC_DIR.exists():
    # Serve root (/) explicitly so /docs keeps working
    @app.get("/")
    def root():
        return FileResponse(PUBLIC_DIR / "index.html")

    # Also serve /ui/* for assets
    app.mount("/ui", StaticFiles(directory=str(PUBLIC_DIR), html=True), name="ui")
else:
    @app.get("/")
    def root_placeholder():
        return JSONResponse({"status": "ok", "note": "public/ not found; visit /docs"})

 









