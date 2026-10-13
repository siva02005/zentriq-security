from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from backend.app.schemas.analyze import AnalyzeRequest, AnalyzeResponse
from backend.app.security.engine import analyze_action
from backend.app.db.session import get_db
from backend.app.core.logging import logger

router = APIRouter()

@router.post("/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest, db: Session = Depends(get_db)):
    """Analyze an AI agent action and return a security decision."""
    logger.info(f"Analyze request: action_type={payload.action.action_type}, session={payload.session_id}, task={payload.task_id}")
    response = analyze_action(payload, db)
    logger.info(f"Decision: {response.decision}, rule: {response.triggered_rule}")
    return response
