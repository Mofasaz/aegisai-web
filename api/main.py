import os
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from api.models import *
from api.chains import get_llm
from rules.engine import analyze_events
from retrieval.azure_retriever import get_chunks, get_chunks_vector
from datetime import datetime, timezone

app = FastAPI(title="AegisAI", docs_url="/docs", redoc_url="/redoc")
USE_VECTOR = os.getenv("USE_VECTOR", "true").lower() == "true"

@app.get("/healthz")
def healthz():
    return {"status": "ok"}  

@app.post("/ask", response_model=AskResponse)
def ask(req: AskRequest):
    try:
        if USE_VECTOR:
            chunks = get_chunks_vector(req.query, req.user_grade, top=5, k=20, hybrid=True)
        else:
            chunks = get_chunks(req.query, req.user_grade)  # your existing keyword retriever

        if not chunks:
            return AskResponse(answer="No matching policy content found.", citations=[])
        ctx = "\n\n".join([f"[{c['policy_id']}/{c['clause_id']}] {c['clause_text']}" for c in chunks])
        llm = get_llm()
        msg = [
            {"role":"system","content":"Answer ONLY from provided policy context. Cite clause IDs."},
            {"role":"user","content": f"Q: {req.query}\n\nContext:\n{ctx}"}
        ]
        out = llm.invoke(msg)
        citations = [Citation(**{k:v for k,v in c.items() if k in {"policy_id","clause_id","title","section","visibility","allowed_grades"}}) for c in chunks]
        return AskResponse(answer=getattr(out, 'content', str(out)), citations=citations)
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Policy search failed: {type(e).__name__}: {e}")

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

 





