from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.models.policy import Policy
from backend.app.schemas.policy import PolicyResponse
from backend.app.db.session import get_db

router = APIRouter()

@router.get("/policies", response_model=list[PolicyResponse])
def list_policies(db: Session = Depends(get_db)):
    """Return all active security policies."""
    policies = db.query(Policy).filter(Policy.enabled == True).order_by(Policy.priority).all()
    return [PolicyResponse.model_validate(p) for p in policies]
