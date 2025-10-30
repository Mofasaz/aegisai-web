from fastapi import FastAPI
from api.models import *
from api.chains import get_llm
from rules.engine import analyze_events
from retrieval.local_retriever import get_chunks
from datetime import datetime, timezone

app = FastAPI(title="AegisAI")

from fastapi.staticfiles import StaticFiles
app.mount("/", StaticFiles(directory="public", html=True), name="public")

@app.get("/healthz")
def healthz():
    return {"status": "ok"}  

@app.post("/ask", response_model=AskResponse)
def ask(req: AskRequest):
    # offline: local retriever; azure phase swaps to Azure Search
    chunks = get_chunks(req.query, req.user_grade)
    if not chunks:
        return AskResponse(answer="No matching policy content found.", citations=[])
    ctx = "\n\n".join([f"[{c['policy_id']}/{c['clause_id']}] {c['chunk_text']}" for c in chunks])
    llm = get_llm()
    msg = [
        {"role":"system","content":"Answer ONLY from provided policy context. Cite clause IDs."},
        {"role":"user","content": f"Q: {req.query}\n\nContext:\n{ctx}"}
    ]
    out = llm.invoke(msg)
    citations = [Citation(**{k:v for k,v in c.items() if k in {"policy_id","clause_id","title","section","visibility","allowed_grades"}}) for c in chunks]
    return AskResponse(answer=getattr(out, 'content', str(out)), citations=citations)

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

 