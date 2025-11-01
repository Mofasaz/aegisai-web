from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

# /ask
class AskRequest(BaseModel):
    query: str
    user_grade: Optional[str] = Field(None, description="For demo/testing; Azure phase uses token claim")

class Citation(BaseModel):
    policy_id: str
    clause_id: str
    title: Optional[str] = None
    section: Optional[str] = None
    visibility: Optional[str] = None
    allowed_grades: Optional[List[str]] = None

class AskResponse(BaseModel):
    answer: str
    citations: List[Citation]

class Highlight(BaseModel):
    policy_id: str
    clause_id: str
    snippet: str

class AskResponseV2(BaseModel):
    # keep original fields for backward compatibility
    answer: str
    citations: List[Citation] = Field(default_factory=list)

    # new, optional enrichments
    highlights: Optional[List[Highlight]] = None
    reasoning: Optional[str] = None
    confidence: Optional[float] = None
    restricted_probe: Optional[bool] = None
    risk_reasons: Optional[List[str]] = None
    correlation_id: Optional[str] = None
    judge_score: Optional[float] = None         # raw groundedness from the LLM judge (0..1)
    judge_issues: Optional[List[str]] = None    # textual notes the judge returned

# /analyze
class LogEvent(BaseModel):
    # core
    event_id: str
    timestamp: str                  # ISO8601 with Z or ±offset
    action: str                     # e.g., login, access_denied, data_access, data_delete, file_upload ...
    status: Optional[str] = None    # success | failed

    # your schema
    role: Optional[str] = Field(None, alias="user_role")
    system: Optional[str] = None
    location: Optional[str] = None

    # legacy/back-compat optional fields
    user_dept: Optional[str] = None
    resource: Optional[str] = None
    target: Optional[str] = None
    source_ip: Optional[str] = None
    auth: Optional[Dict[str, Any]] = None
    risk_context: Optional[Dict[str, Any]] = None

    # v2 style
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    
class Config:
    allow_population_by_field_name = True
    extra = "allow"

class Anomaly(BaseModel):
    event_id: str
    signals: List[str]
    risk_score: int
    explain: str

class AnalyzeRequest(BaseModel):
    events: List[LogEvent]
    # NEW (optional) — if events are not supplied, the API will fetch from Azure Search
    query: Optional[str] = None          # e.g., "login failed" or "*" for all
    time_min: Optional[str] = None       # ISO8601, e.g., "2025-10-23T00:00:00Z"
    time_max: Optional[str] = None       # ISO8601, e.g., "2025-10-26T00:00:00Z"
    top: Optional[int] = 50              # cap number of events fetched

class AnalyzeResponse(BaseModel):
    anomalies: List[Anomaly]

# /narrative
class NarrativeRequestItem(BaseModel):
    event: LogEvent
    signals: List[str]
    risk_score: int

class LinkedPolicy(BaseModel):
    policy_id: str
    clause_id: str

class NarrativeItem(BaseModel):
    event_id: str
    narrative: str
    remediation: List[str]
    linked_policies: List[LinkedPolicy]

class NarrativeRequest(BaseModel):
    items: List[NarrativeRequestItem]

class NarrativeResponse(BaseModel):
    items: List[NarrativeItem]

# /attest
class AttestRequest(BaseModel):
    policy_id: str
    clause_id: str
    answer_hash: Optional[str] = None

class AttestResponse(BaseModel):
    status: str
    attested_at: str

# /anomalies/push (Azure phase)
class AnomalyPushItem(BaseModel):
    ts: str
    event_id: str
    user_dept: str
    role: str
    signals: List[str]
    risk_score: int

class AnomalyPushRequest(BaseModel):
    items: List[AnomalyPushItem]

class AnomalyPushResponse(BaseModel):
    status: str
    count: int

# ---------- Rules: Suggest / Apply ----------

class RuleSuggestRequest(BaseModel):
    prompt: str
    category: Optional[str] = None     # e.g., "access", "auth", "download"
    severity: Optional[str] = None     # e.g., "low"|"medium"|"high"|"critical"

class RuleSuggestResponse(BaseModel):
    yaml: str
    parsed: Optional[Dict[str, Any]] = None
    warnings: Optional[List[str]] = None

class RuleApplyRequest(BaseModel):
    yaml: str

class RuleApplyResponse(BaseModel):
    status: str
    message: Optional[str] = None










