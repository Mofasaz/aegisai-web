from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

# /ask
class AskRequest(BaseModel):
    query: str
    user_grade: Optional[str] = Field(None, description="For demo/testing; Azure phase uses token claim")

class Citation(BaseModel):
    policy_id: str
    clause_id: str
    title: Optional[str] | None = Field(default=None, alias="title_Data_Column")
    section: Optional[str] = None
    visibility: Optional[str] = None
    allowed_grades: Optional[List[str]] = None
    model_config = dict(populate_by_name=True)

class AskResponse(BaseModel):
    answer: str
    citations: List[Citation]

# /analyze
class LogEvent(BaseModel):
    event_id: str
    user_dept: str
    role: str
    timestamp: str
    action: str
    resource: Optional[str] = None
    target: Optional[str] = None
    source_ip: Optional[str] = None
    auth: Optional[Dict[str, Any]] = None
    risk_context: Optional[Dict[str, Any]] = None

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





