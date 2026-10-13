from pydantic import BaseModel, Field
from typing import Optional

class ActionData(BaseModel):
    name: Optional[str] = None
    tags: list[str] = Field(default_factory=list)

class Action(BaseModel):
    action_type: str
    description: str = ""
    target: Optional[str] = None
    destination: Optional[str] = None
    data: Optional[ActionData] = None
    third_party: bool = False
    metadata: Optional[dict] = None

class AnalyzeRequest(BaseModel):
    session_id: Optional[str] = None
    task_id: Optional[str] = None
    action: Action

class AnalyzeResponse(BaseModel):
    decision: str  # ALLOW, RESTRICT, BLOCK
    reasons: list[str]
    risk_level: str  # low, medium, high
    risk_score: float = Field(ge=0.0, le=1.0)
    applied_policies: list[str]
    triggered_rule: str
    affected_resource: Optional[str] = None
    audit_event_id: str
