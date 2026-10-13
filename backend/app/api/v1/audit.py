from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional

from backend.app.models.audit import AuditEvent
from backend.app.db.session import get_db

router = APIRouter()

@router.get("/audit/events")
def list_audit_events(
    limit: int = Query(default=100, le=1000),
    session_id: Optional[str] = None,
    decision: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Return audit events, newest first."""
    query = db.query(AuditEvent).order_by(AuditEvent.timestamp.desc())
    if session_id:
        query = query.filter(AuditEvent.session_id == session_id)
    if decision:
        query = query.filter(AuditEvent.decision == decision.upper())
    events = query.limit(limit).all()
    return [
        {
            "event_id": e.event_id,
            "session_id": e.session_id,
            "task_id": e.task_id,
            "action_type": e.action_type,
            "action_description": e.action_description,
            "target": e.target,
            "destination": e.destination,
            "decision": e.decision,
            "risk_level": e.risk_level,
            "risk_score": e.risk_score,
            "reasons": e.reasons,
            "applied_policies": e.applied_policies,
            "triggered_rule": e.triggered_rule,
            "affected_resource": e.affected_resource,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        }
        for e in events
    ]
