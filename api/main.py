import os, uuid, json, re, yaml, logging
from pathlib import Path
from fastapi import FastAPI, HTTPException, Response, Depends, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from openai import AzureOpenAI

from api.models import *
from api.chains import get_llm
from rules.engine import *
from retrieval.azure_retriever import get_chunks, get_chunks_vector, count_restricted_hits
from retrieval.azure_events_retriever import search_events, _to_dt, get_events_by_ids
from rules.intent import match_risky_intent
from api.auth import require_user, UserPrincipal
from api.analyze_nl import interpret_query, outside_hours_predicate

try:
    from integrations.powerbi import push_rows
except Exception:
    def push_rows(rows):
        # safe no-op fallback
        import logging, json
        logging.info("[telemetry] (noop) %s", json.dumps({"rows": rows})[:500])


app = FastAPI(title="AegisAI", docs_url="/docs", redoc_url="/redoc")
USE_VECTOR = os.getenv("USE_VECTOR", "true").lower() == "true"
RULES_FILE = os.getenv("RULES_FILE", "rules/rules.yaml")
ENABLE_LLM_POLICY_CHECK = os.getenv("ENABLE_LLM_POLICY_CHECK", "true").lower() == "true"

# --- Violation judge helpers ---
LOW_SIGNAL_WORDS = {"success"}  # "success" alone rarely implies a violation
DENY_WORDS  = ("block", "failed", "failure", "timeout", "unsafe", "risk", "data_delete", "data_export", "access_denied", "unauthorized","forbid", "forbidden", "prohibit", "prohibited", "deny", "blocked", "not allowed")

logger = logging.getLogger("aegisai.analyze")
if not logger.handlers:
    handler = logging.StreamHandler()
    fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s")
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

from openai import AzureOpenAI

def llm_remediation_from_context(ev: "LogEvent", policy_refs: list[LinkedPolicy]) -> list[str]:
    texts = []
    for p in policy_refs:
        if p.clause_text:
            label = f"[{p.policy_id}/{p.clause_id}]"
            title = f" — {p.title}" if p.title else ""
            section = f" — {p.section}" if p.section else ""
            texts.append(f"{label}{title}{section}\n{p.clause_text}")
    if not texts:
        # Fallback if we have no text to compare
        return ["Notify line manager", "Reverse/quarantine action if possible", "Schedule policy refresher"]

    context = "\n\n---\n\n".join(texts)
    ev_line = (
        f"Role={ev.user_role or 'N/A'} | System={ev.system or 'N/A'} | "
        f"Action={ev.action or 'N/A'} | Status={ev.status or 'N/A'} | "
        f"Location={ev.location or 'N/A'} | Time={ev.timestamp or 'N/A'}"
    )

    prompt = f"""
You are a compliance assistant. Compare the event against the policy citations and produce 3–5 specific, actionable remediation steps.

Event:
{ev_line}

Policy citations:
{context}

Rules:
- Be concrete (who does what, where, within what time).
- Reference the relevant clause IDs only when helpful (short code like [P1/C3]).
- Prefer reversible / low-risk steps first, then escalations.
- Output plain bullet lines, no numbering, no extra commentary.
"""

    try:
        client = AzureOpenAI(
            api_key=os.getenv("AZURE_OPENAI_API_KEY"),
            api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2025-01-01-preview"),
            azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
        )
        resp = client.chat.completions.create(
            model=os.getenv("AZURE_OPENAI_DEPLOYMENT"),  # your deployment name
            messages=[{"role":"user","content":prompt}],
            temperature=0.1
        )
        txt = resp.choices[0].message.content.strip()
        # Split into bullets safely
        lines = [l.strip(" -*\u2022").strip() for l in txt.splitlines() if l.strip()]
        return [l for l in lines if l]
    except Exception as e:
        logger.info(
                f"llm_remediation_from_context failed | error={e}"
            )
        # safe fallback
        return ["Notify line manager", "Reverse/quarantine action if possible", "Schedule targeted policy refresher"]


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Return detailed Pydantic validation errors so 422s are explainable.
    Shows which field failed and echoes the raw body that caused it.
    """
    try:
        body_bytes = await request.body()
        body_text = body_bytes.decode("utf-8", errors="replace")
    except Exception:
        body_text = "<unavailable>"

    return JSONResponse(
        status_code=422,
        content={
            "detail": exc.errors(),   # list of error objects with loc/msg/type
            "body": body_text         # raw request body to help debugging
        },
    )
    
@app.get("/auth/whoami")
def whoami(user: UserPrincipal = Depends(require_user)):
    return user
    
@app.get("/me")
def me(user: UserPrincipal = Depends(require_user)):
    return {
        "oid": user.oid,
        "name": user.name,
        "upn": user.upn,
        "roles": user.roles,
        "grade": user.grade
    }

@app.on_event("startup")
def _load_rules_startup():
    try:
        os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
        if not os.path.exists(RULES_FILE):
            # Seed empty file for demo environments
            with open(RULES_FILE, "w", encoding="utf-8") as f:
                f.write("rules: []\n")
        rules = load_rules_from_file(RULES_FILE)
        set_rules(rules)
        # optional: store in app.state for introspection
        app.state.rules_path = RULES_FILE
    except Exception as e:
        # Don’t block app boot: you can still serve /ask without rules
        print(f"[WARN] Failed to load rules at startup: {e}")

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

def count_restricted_hits(query: str) -> tuple[int, list[dict]]:
    """
    Returns (count, meta_list) of restricted documents that match the query.
    Meta list includes only policy_id/clause_id; no clause_text to avoid leaks.
    """
    from azure.search.documents import SearchClient
    from azure.core.credentials import AzureKeyCredential

    endpoint = os.getenv("AZURE_SEARCH_ENDPOINT")
    index = os.getenv("AZURE_SEARCH_INDEX")
    key = os.getenv("AZURE_SEARCH_API_KEY")
    if not (endpoint and index and key):
        return 0, []

    client = SearchClient(endpoint=endpoint, index_name=index, credential=AzureKeyCredential(key))
    # visibility == 'restricted' (case-insensitive via tolower)
    flt = "tolower(visibility) eq 'restricted'"
    results = client.search(
        search_text=query or "*",
        filter=flt,
        query_type="simple",
        top=5,
        select=["policy_id", "clause_id"]  # no text leakage
    )
    meta = []
    cnt = 0
    for r in results:
        cnt += 1
        # robust extraction
        pid = getattr(r, "policy_id", None) or r.get("policy_id")
        cid = getattr(r, "clause_id", None) or r.get("clause_id")
        meta.append({"policy_id": pid, "clause_id": cid})
    return cnt, meta

RULES_FILE = os.getenv("RULES_FILE", "data/rules.yaml")

def _ensure_rules_file():
    os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
    if not os.path.exists(RULES_FILE):
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            f.write("rules: []\n")

def _validate_rule_dict(d: Dict[str, Any]) -> List[str]:
    """
    Lightweight validation to keep schema consistent with your engine.
    Expected top-level fields (recommendation):
      id, name, description, match, conditions, severity, risk_points, remediation
    """
    warns = []
    required = ["id", "name", "description", "match", "conditions", "severity", "risk_points", "remediation"]
    for k in required:
        if k not in d:
            warns.append(f"Missing key: {k}")

    # structure hints
    if "match" in d and not isinstance(d["match"], dict):
        warns.append("match should be an object with arrays like actions/roles/systems/locations/status.")
    if "conditions" in d and not isinstance(d["conditions"], dict):
        warns.append("conditions should be an object (e.g., shift_hours_gt, last_30d_failed_logins_gt, window_minutes, logic).")
    if "remediation" in d and not isinstance(d["remediation"], list):
        warns.append("remediation should be a list of steps.")
    return warns

def _llm_rule_yaml_from_prompt(prompt: str, category: Optional[str], severity: Optional[str]) -> str:
    """
    Ask your LLM to produce a single YAML rule document (no markdown fences).
    """
    llm = get_llm()
    sys = {
        "role": "system",
        "content": (
            "You are a compliance rule generator. Produce ONLY valid YAML (no markdown fences). "
            "Output a SINGLE rule object (not a list). Keys must be:\n"
            "id, name, description, match, conditions, severity, risk_points, remediation\n\n"
            "Schema example:\n"
            "id: R-ACC-001\n"
            "name: Off-hour Crew Portal Access\n"
            "description: Flag off-hour access to Crew Scheduling Portal by Cabin Crew\n"
            "match:\n"
            "  actions: [login, access]\n"
            "  roles: [Cabin Crew]\n"
            "  systems: [Crew Scheduling Portal]\n"
            "  locations: []\n"
            "  status: []\n"
            "conditions:\n"
            "  window_minutes: 1440\n"
            "  shift_hours_gt: 10\n"
            "  last_30d_failed_logins_gt: 2\n"
            "  logic: AND\n"
            "severity: high\n"
            "risk_points: 70\n"
            "remediation:\n"
            "  - Notify line manager\n"
            "  - Require policy refresh"
        )
    }
    user = {
        "role": "user",
        "content": (
            f"Natural language requirement:\n{prompt}\n\n"
            f"Category hint: {category or 'n/a'}\n"
            f"Preferred severity (optional): {severity or 'n/a'}\n"
            "Return only a single YAML rule object."
        )
    }
    out = llm.invoke([sys, user])
    return getattr(out, "content", str(out)).strip()

def _policy_sanity_check(new_rule: Dict[str, Any], role: str | None) -> Tuple[List[str], List[str]]:
    """
    Deterministic (no LLM) sanity pass: if nearby clauses strongly 'permit' something
    the rule tries to 'deny', raise a warning/error. Vice-versa too.
    """
    errs, warns = [], []
    q_terms = [new_rule.get("action"), new_rule.get("system"), new_rule.get("resource"), new_rule.get("category")]
    q = " ".join([t for t in q_terms if t]).strip()
    if not q:
        return errs, warns

    if USE_VECTOR and callable(get_chunks_vector):
        clauses = get_chunks_vector(q, role or "", top=8, k=40, hybrid=True)
    clauses = get_chunks(q, role or "")[:8]
    
    if not clauses:
        warns.append("No related policies found for this scope; please review.")
        return errs, list(dict.fromkeys(warns))

    # compress clauses text
    texts = []
    for c in clauses:
        txt = (c.get("clause_text") or c.get("content") or "").strip()
        if txt:
            texts.append(txt.lower())

    combined = " \n".join(texts)
    rule_text = " ".join(str(new_rule.get(k, "")) for k in ("effect", "decision", "severity", "action_on_violation", "description")).lower()

    policy_allows = any(w in combined for w in ALLOW_WORDS)
    policy_denies  = any(w in combined for w in DENY_WORDS)

    rule_is_denyish  = any(w in rule_text for w in DENY_WORDS) or ("high" in rule_text and "block" in rule_text)
    rule_is_allowish = any(w in rule_text for w in ALLOW_WORDS) or ("log only" in rule_text)

    if policy_allows and rule_is_denyish:
        errs.append("Policy clauses appear to permit this behavior, but the suggested rule would deny/block it.")
    if policy_denies and rule_is_allowish:
        warns.append("Policy clauses appear to prohibit this behavior, but the suggested rule is weak (allow/log). Consider raising severity.")

    return list(dict.fromkeys(errs)), list(dict.fromkeys(warns))


def _is_potentially_risky(ev: LogEvent, risk_score: int | None, signals: list[str]) -> bool:
    """
    Fast pass: return True only if the event is *worth* deeper judgment.
    """
    if (risk_score or 0) >= 60:
        return True
    a = (ev.action or "").lower()
    s = (ev.status or "").lower()
    if a in RISKY_ACTIONS and s != "success":
        return True
    # obvious non-risky: everything is success and no suspicious signals
    if s == "success" and not signals:
        return False
    # if success but suspicious action (e.g., data_delete) — still check
    if s == "success" and a in {"data_delete", "data_export"}:
        return True
    # fallback: moderate risk score threshold
    return (risk_score or 0) >= 40


def _llm_violation_judge(ev: LogEvent, clause_snippets: list[str]) -> dict:
    """
    Ask the LLM: is this a policy violation? Returns a dict:
      { "violation": bool, "reason": str, "remediation": list[str] }
    Uses your chat model (NOT the embedding model).
    """
    from openai import AzureOpenAI

    client = AzureOpenAI(
        api_key=os.getenv("AZURE_OPENAI_API_KEY"),
        azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
        api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2025-01-01-preview"),
    )
    gpt_deployment = os.getenv("AZURE_OPENAI_CHAT_DEPLOYMENT")

    # Keep the prompt short, grounded, and force JSON
    policy_context = "\n\n".join(
        f"- CLAUSE #{i+1}:\n{c.strip()}" for i, c in enumerate(clause_snippets[:4]) if c
    ) or "No matching clauses."

    ev_text = (
        f"event_id={ev.event_id}, role={ev.user_role}, action={ev.action}, status={ev.status}, "
        f"system={ev.system}, location={ev.location}, timestamp={ev.timestamp}"
    )

    sys = (
        "You are a strict policy compliance judge. Decide if the event violates any given policy clauses. "
        "If not a violation, return violation=false and an empty remediation list."
    )
    usr = f"""EVENT:
{ev_text}

POLICY CLAUSES:
{policy_context}

Return strict JSON with keys: violation (bool), reason (string max 200 chars),
remediation (list of 1-4 short imperative steps; empty if no violation)."""

    resp = client.chat.completions.create(
        model=gpt_deployment,
        temperature=0,
        response_format={"type": "json_object"},
        messages=[
            {"role":"system","content": sys},
            {"role":"user","content": usr}
        ],
    )
    try:
        import json
        data = json.loads(resp.choices[0].message.content)
        # ensure shape
        return {
            "violation": bool(data.get("violation", False)),
            "reason": str(data.get("reason", "")).strip(),
            "remediation": [str(x).strip() for x in (data.get("remediation") or []) if str(x).strip()][:4],
        }
    except Exception:
        # fail-safe: treat as non-violation
        return {"violation": False, "reason": "Judge unavailable", "remediation": []}

def _to_dt_loose(v: Optional[str | datetime]) -> Optional[datetime]:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except Exception:
        return None

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
        reasons = list(dict.fromkeys(reasons))
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
        judge_score=float(judge.get("grounding_score", 0.6)),
        judge_issues=judge.get("issues") or None,
    )

@app.post("/rules/suggest", response_model=RuleSuggestResponse)
def suggest_rule(req: RuleSuggestRequest, user: UserPrincipal = Depends(require_user)):
    # Generate YAML via LLM
    raw_yaml = _llm_rule_yaml_from_prompt(req.prompt, req.category, req.severity)

    # Parse & validate
    parsed = None
    warns: List[str] = []
    try:
        parsed = yaml.safe_load(raw_yaml)
        if not isinstance(parsed, dict):
            raise ValueError("LLM did not return a YAML object; got list or scalar.")
        warns = _validate_rule_dict(parsed)
        # Auto-inject severity if missing but user hinted
        if "severity" not in parsed and req.severity:
            parsed["severity"] = req.severity
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML from model: {e}")

    # Normalize: if id missing, synthesize one
    if "id" not in parsed or not parsed["id"]:
        parsed["id"] = f"R-AUTO-{uuid.uuid4().hex[:6].upper()}"

    # Rule vs existing rules: duplicates & contradictions
    existing = [normalize_rule_dict(r) for r in load_rules_from_file(RULES_FILE)]
    dup_errs, dup_warns = validate_against_existing(parsed, existing)

    # Rule vs policy clauses: deterministic sanity
    role_for_query = parsed.get("role")
    pol_errs, pol_warns = _policy_sanity_check(parsed, role_for_query)

    # Optional LLM gate (secondary)
    llm_errs, llm_warns = [], []
    if ENABLE_LLM_POLICY_CHECK:
        # fetch same clauses once more so we don't re-query inside helper
        q = " ".join(filter(None, [parsed.get("action"), parsed.get("system"), parsed.get("resource"), parsed.get("category")]))
        if USE_VECTOR and callable(get_chunks_vector):
            clauses = get_chunks_vector(q, role_for_query or "", top=8, k=40, hybrid=True)
        clauses = get_chunks(q, role_for_query or "")[:8]
        
        rule_yaml_for_llm = yaml.safe_dump(parsed, sort_keys=False, allow_unicode=True)
        le, lw = llm_policy_conflict_check(rule_yaml_for_llm, clauses)
        llm_errs, llm_warns = le, lw

    # Combine messages (de-duped, order-preserving)
    def _dedupe(xs: List[str]) -> List[str]:
        return list(dict.fromkeys(x.strip() for x in xs if x and x.strip()))

    all_errors   = _dedupe(dup_errs + pol_errs + llm_errs)
    all_warnings = _dedupe(warns + dup_warns + pol_warns + llm_warns)

    # If there are hard errors (id clash / direct contradiction), block
    if all_errors:
        normalized_yaml = yaml.safe_dump(parsed, sort_keys=False, allow_unicode=True)
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Rule suggestion conflicts with current configuration/policies.",
                "errors": all_errors,
                "warnings": all_warnings,
                "yaml": normalized_yaml
            }
        )
        
    # Re-dump to normalized YAML
    normalized_yaml = yaml.safe_dump(parsed, sort_keys=False, allow_unicode=True)

    return RuleSuggestResponse(yaml=normalized_yaml, parsed=parsed, warnings=(all_warnings or None))

@app.post("/rules/apply", response_model=RuleApplyResponse)
def apply_rule(req: RuleApplyRequest, user: UserPrincipal = Depends(require_user)):
    """
    Append the proposed rule to data/rules.yaml under 'rules:'.
    NOTE: On Azure App Service, '/home/site/wwwroot' is redeployed on each build;
    use this only for demo. For persistence, wire a Storage/DB later.
    """
    try:
        new_rule = yaml.safe_load(req.yaml)
        if not isinstance(new_rule, dict):
            raise ValueError("YAML must be a single object.")
        warns = _validate_rule_dict(new_rule)
        if warns:
            # still allow save, but report the warnings
            pass
        _ensure_rules_file()
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        if "rules" not in doc or not isinstance(doc["rules"], list):
            doc["rules"] = []
        # Prevent duplicates on id
        existing_ids = {r.get("id") for r in doc["rules"] if isinstance(r, dict)}
        if new_rule.get("id") in existing_ids:
            raise HTTPException(status_code=409, detail=f"Rule id already exists: {new_rule.get('id')}")
        doc["rules"].append(new_rule)
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            yaml.safe_dump(doc, f, sort_keys=False, allow_unicode=True)
        msg = "Saved to rules.yaml"
        set_rules(load_rules_from_file(RULES_FILE))  # hot-reload in memory
        if warns: msg += f" (warnings: {', '.join(warns)})"
        return RuleApplyResponse(status="ok", message=msg)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to apply rule: {e}")

@app.post("/rules/reload")
@app.get("/rules/reload")
def reload_rules(user: UserPrincipal = Depends(require_user)):
    """
    Re-read YAML from disk and refresh the in-memory rules cache.
    Returns the rule count now active.
    """
    try:
        rules = load_rules_from_file(RULES_FILE)
        set_rules(rules)
        return {"status": "ok", "count": len(rules), "source": RULES_FILE}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reload rules: {e}")

@app.get("/rules/list")
def list_rules(user: UserPrincipal = Depends(require_user)):
    return {"rules": get_rules(), "count": len(get_rules())}

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    """
    Two modes:
    - If req.events has items: analyze those (your current flow).
    - Else: pull events from Azure AI Search logs index (aegisai-logs-indx), then analyze.
    """
    now_utc = datetime.now(timezone.utc)
    # Mode A: direct events (paste-in) – optional
    if req.events:
        events = [
            LogEvent(
                event_id=e.event_id,
                timestamp=e.timestamp,
                action=e.action,
                status=e.status,
                user_role=e.user_role,
                system=e.system,
                location=e.location,
                risk_context=e.risk_context if isinstance(e.risk_context, dict) else None,
                user_dept=None, resource=None, target=None, source_ip=None, auth=None,
            ) for e in req.events
        ]
        anomalies = analyze_events(events)
        return AnalyzeResponse(anomalies=anomalies)

    
    # Step 1: interpret NL if present
    intent = interpret_query(req.query)

    # Step 2: pick effective time window: explicit > NL-inferred > none
    time_min = req.time_min or intent.get("time_min")
    time_max = req.time_max or intent.get("time_max")

    # If the user left everything empty, default to last 30 days
    if not req.query and not time_min and not time_max:
        time_max = datetime.now(timezone.utc)
        time_min = time_max - timedelta(days=30)

    # Step 3: build search args
    search_text = " ".join(
        [x for x in [(intent.get("search_text") or ""), *intent.get("must_terms", [])] if x]
    ).strip() or None

    
    # You can mix text + filters. For Azure Search:
    #   - use 'search' for text, 'filter' for OData eq on fields like user_role/status
    #   - filter dates with timestamp ge/le in UTC if set
    # Implement this inside your retriever; example signature:
    # search_events(text: str, time_min: Optional[datetime], time_max: Optional[datetime], filters: dict, top: int) -> List[dict]
    try:
        raw_events = search_events(
            query=search_text,
            time_min=time_min,
            time_max=time_max,
            top=req.top,
            filters=intent.get("filters") or {},
            not_filters=intent.get("not_filters") or {},
            relax=True,       # keep progressive widening
            partial=True,     # allow partial token hits (search_mode="any")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Logs search failed: {type(e).__name__}: {e}") 

        
    # 5) Optional hour-band filtering (inside/non-peak/outside)
    events = raw_events
    """
    if intent.get("inside_hours"):
        sh, eh = intent["inside_hours"]
        events = []
        for ev in raw_events:
            ts = _to_dt(ev.get("timestamp"))
            if ts and not outside_hours_predicate(ts, sh, eh):
                events.append(ev)

    if intent.get("outside_hours"):
        sh, eh = intent["outside_hours"]
        filt = []
        for ev in events:
            ts = _to_dt(ev.get("timestamp"))
            if ts and outside_hours_predicate(ts, sh, eh):
                filt.append(ev)
        events = filt
    """

    # 6) Map result → LogEvent (engine-friendly)
    log_events: List[LogEvent] = []
    for d in events:
        ts = d.get("timestamp")
        dt = _to_dt(ts)
        ts_out = dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else (str(ts or ""))
        log_events.append(LogEvent(
            event_id = d.get("event_id"),
            timestamp = ts_out,
            action = d.get("action"),
            status = d.get("status"),
            user_role = d.get("user_role"),
            system = d.get("system"),
            location = d.get("location"),
            user_dept=None, resource=None, target=None, source_ip=None, auth=None,
            risk_context = d.get("risk_context") if isinstance(d.get("risk_context"), dict) else None,
        ))

    # 7) Map LogEvent → Anomaly (UI-friendly)
    def _signals_for_event(ev: LogEvent) -> list[str]:
        sigs: list[str] = []
        a = (ev.action or "").lower()
        s = (ev.status or "").lower()
        if s == "failed": sigs.append("failed")
        if a in {"access_denied", "login", "logout", "session_timeout"}: sigs.append(a)
        if a in {"data_delete", "data_download", "data_export", "file_upload", "file_transfer"}: sigs.append(a)
        if a in {"vpn_connect", "security_scan"}: sigs.append(a)
        return sigs or ["event"]
    
    def _risk_for_signals(sigs: list[str]) -> int:
        base = 30
        if "failed" in sigs: base += 25
        if "access_denied" in sigs: base += 30
        if any(x in sigs for x in ("data_delete","data_download","data_export")): base += 15
        if "vpn_connect" in sigs: base += 10
        if "security_scan" in sigs: base += 5
        return max(10, min(95, base))

    def getf(obj, key, default=None):
        """dict-safe / pydantic-safe getter."""
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)
    
    anomalies: list[Anomaly] = []
    for e in log_events:
        sigs = _signals_for_event(e)
        risk = _risk_for_signals(sigs)
        # human explain string seen in UI’s “Explain” column
        explain = (
            f"{e.user_role or '—'} {e.action or '—'} "
            f"on {e.system or '—'} @ {e.location or '—'} "
            f"({e.status or '—'}, {e.timestamp or '—'})"
        )
        anomalies.append(Anomaly(
            event_id=e.event_id or "",
            signals=sigs,
            risk_score=risk,
            explain=explain
        ))

    #anomalies = analyze_events(log_events)
    return AnalyzeResponse(anomalies=anomalies)


@app.post("/narrative", response_model=NarrativeResponse)
def narrative(req: NarrativeRequest):
    items = []
    for it in req.items:
        # quick link: use signals + resource as query to find related policy chunks
        q = " ".join(it.signals + [it.event.action or "", it.event.resource or ""]).strip()
        chunks = get_chunks(q, req.items[0].event.role)  # simple proxy; in Azure use grade claim
        policy_refs = [LinkedPolicy(policy_id=c['policy_id'], clause_id=c['clause_id'], clause_text=c["clause_text"], title=c["title"], section=c["section"]) for c in chunks[:3]]
        story = f"{it.event.role} in {it.event.user_dept} performed {it.event.action} on {it.event.resource}. Signals: {', '.join(it.signals)}. Related clauses: " + ", ".join([f"{p.policy_id}/{p.clause_id}" for p in policy_refs])
        rem = ["Notify line manager", "Quarantine or reverse action if possible", "Schedule policy refresher"]
        items.append(NarrativeItem(event_id=it.event.event_id, narrative=story, remediation=rem, linked_policies=policy_refs))
    return NarrativeResponse(items=items)


@app.post("/narrative/from_anomalies", response_model=NarrativeResponse)
def narrative_from_anomalies(req: NarrativeFromAnomaliesRequest):
    # 1) fetch the full events from Search by IDs
    ids = [it.event_id for it in req.items]
    try:
        docs = get_events_by_ids(ids)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fetch events failed: {type(e).__name__}: {e}")

    # index by id for quick lookup
    by_id = {d["event_id"]: d for d in docs}

    items: list[NarrativeItem] = []
    for it in req.items:
        d = by_id.get(it.event_id)
        if not d:
            # skip silently; or raise if you prefer strict mode
            continue

        # Build a LogEvent (your model is lenient with optional fields)
        ev = LogEvent(
            event_id=d.get("event_id"),
            timestamp=str(d.get("timestamp")),
            action=d.get("action"),
            status=d.get("status"),
            user_role=d.get("user_role"),
            system=d.get("system"),
            location=d.get("location"),
        )

        # quick policy linking (reuse your current get_chunks logic)
        q = " ".join(filter(None, [ev.action, ev.system, ev.user_role]))  # tiny heuristic
        if USE_VECTOR and callable(get_chunks_vector):
            chunks = get_chunks_vector(q, ev.user_role or "", top=3, k=20, hybrid=True)
        else:
            chunks = get_chunks(q, ev.user_role or "")[:3]

        clause_snippets = []
        policy_refs = []
        for c in (chunks or []):
            policy_refs.append(LinkedPolicy(policy_id=c["policy_id"], clause_id=c["clause_id"], clause_text=c["clause_text"], title=c["title"], section=c["section"]))
            txt = (c.get("clause_text") or "").strip()
            if txt:
                clause_snippets.append(txt)

        # Decide if we should judge at all
        risky = _is_potentially_risky(ev, getattr(it, "risk_score", None), getattr(it, "signals", []) or [])

        violation = False
        reason = ""
        remediation: list[str] = []

        if risky and clause_snippets:
            verdict = _llm_violation_judge(ev, clause_snippets)
            violation = bool(verdict.get("violation"))
            reason = (verdict.get("reason") or "").strip()
            remediation = verdict.get("remediation") or []

        # Narrative text (include short clause extract so UI shows the actual rule line)
        def _short(s, n=220):
            return (s[:n] + "…") if s and len(s) > n else (s or "")

        clause_excerpt = _short(" | ".join(clause_snippets)) if clause_snippets else "No matching clause text."

        if violation:
            story = (
                f"⚠️ Potential violation detected: {ev.user_role or 'User'} performed {ev.action} "
                f"on {ev.system or 'system'} at {ev.location or 'N/A'}. "
                f"{('Reason: ' + reason) if reason else ''} "
                f"\nClause: {clause_excerpt}"
            )
        else:
            story = (
                f"✓ No violation: {ev.user_role or 'User'} performed {ev.action} "
                f"on {ev.system or 'system'} at {ev.location or 'N/A'}. "
                f"{('Reason: ' + reason) if reason else 'Within policy / insufficient risk signals.'} "
                f"\nClause: {clause_excerpt}"
            )
            remediation = []  # ensure empty for no-violation

        """
        story = (
            f"{ev.user_role or 'User'} in {ev.location or 'N/A'} performed {ev.action} "
            f"on {ev.system or 'system'}. Signals: {', '.join(it.signals)}. "
            f"Linked policies: " + ", ".join([f"{p.policy_id}/{p.clause_id}" for p in policy_refs]) if policy_refs else "Linked policies: none."
        )
        """
        
        #rem = ["Notify line manager", "Quarantine/reverse if possible", "Schedule targeted policy refresher"]
        # ——— LLM remediation grounded in citations ———
        """
        rem = llm_remediation_from_context(ev, policy_refs)
        
        items.append(NarrativeItem(
            event_id=ev.event_id, narrative=story, remediation=rem, linked_policies=policy_refs
        ))
        """
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

 

































































