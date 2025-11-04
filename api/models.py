from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, conint, validator
from datetime import datetime

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
    event_id: Optional[str] = None
    timestamp: Optional[str] = None                  # ISO8601 with Z or ±offset
    action: Optional[str] = None                     # e.g., login, access_denied, data_access, data_delete, file_upload ...
    status: Optional[str] = None    # success | failed

    # your schema
    user_role: Optional[str] = None
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
    signals: List[str] = []
    risk_score: int = 0
    explain: Optional[str] = None

def _parse_dt(v: Optional[str]) -> Optional[datetime]:
    if v in (None, "", "null"):  # accept nulls
        return None
    if isinstance(v, datetime):
        return v
    try:
        # accept '...Z' or offsetless
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except Exception:
        return None  # let validator surface issue
        
class AnalyzeRequest(BaseModel):
    query: Optional[str] = None
    time_min: Optional[datetime] = None
    time_max: Optional[datetime] = None
    top: conint(gt=0, le=500) = 50
    events: list[LogEvent] = Field(default_factory=list)
    # accept strings for time_min/time_max
    @validator("time_min", pre=True)
    def _vm(cls, v): return _parse_dt(v)
    @validator("time_max", pre=True)
    def _vx(cls, v): return _parse_dt(v)

class AnalyzeResponse(BaseModel):
    anomalies: List[Anomaly] = []

# /narrative
class NarrativeRequestItem(BaseModel):
    event: LogEvent
    signals: List[str]
    risk_score: int

class LinkedPolicy(BaseModel):
    policy_id: str
    clause_id: str
    clause_text: Optional[str] = None      # ← short snippet / clause text

class NarrativeFromAnomaliesItem(BaseModel):
    event_id: str
    signals: List[str]
    risk_score: int

class NarrativeFromAnomaliesRequest(BaseModel):
    items: List[NarrativeFromAnomaliesItem]
    
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
















