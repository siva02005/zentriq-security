import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from backend.app.security.models import Relevance, Decision, RiskLevel
from backend.app.security.relevance import classify_relevance, ESCALATION_KEYWORDS
from backend.app.security.risk import compute_risk
from backend.app.schemas.analyze import AnalyzeRequest, AnalyzeResponse
from backend.app.models.audit import AuditEvent
from backend.app.models.policy import Policy
from backend.app.core.logging import logger


def analyze_action(request: AnalyzeRequest, db: Session) -> AnalyzeResponse:
    """Core deterministic security engine.
    Same request always produces the same decision.
    Fails closed: any unexpected state -> BLOCK."""
    try:
        action = request.action
        data_tags = action.data.tags if action.data else []
        affected_resource = action.target or action.destination or None

        # --- Step 0: Missing context check ---
        if not request.task_id and not request.session_id:
            return _finalize(
                db=db,
                request=request,
                decision=Decision.BLOCK,  # We'll override to RESTRICT below
                reasons=["Missing task and session context; failing closed"],
                risk_level=RiskLevel.MEDIUM,
                risk_score=0.5,
                applied_policies=["context-required"],
                triggered_rule="rule.context.missing-task.restrict",
                affected_resource=affected_resource,
                override_decision=Decision.RESTRICT,
            )

        # --- Step 1: Permission escalation check ---
        action_lower = action.action_type.lower()
        desc_lower = action.description.lower()
        combined = f"{action_lower} {desc_lower}"
        escalation_matches = [kw for kw in ESCALATION_KEYWORDS if kw in combined]
        if escalation_matches:
            # Check if the action_type itself is an escalation type
            escalation_action_types = {"write", "delete", "exec", "upload", "escalate", "grant", "privesc"}
            if action_lower in escalation_action_types or any(
                kw in desc_lower for kw in ["escalat", "privesc", "privilege", "grant admin", "sudo", "root access"]
            ):
                relevance = classify_relevance(action.action_type, action.description, request.task_id, request.session_id)
                risk_level, risk_score = compute_risk(relevance, data_tags, action.third_party, action.destination)
                return _finalize(
                    db=db,
                    request=request,
                    decision=Decision.BLOCK,
                    reasons=[
                        f"Permission escalation detected: {', '.join(escalation_matches)}",
                        f"Action type '{action.action_type}' involves privileged operations"
                    ],
                    risk_level=RiskLevel.HIGH,
                    risk_score=max(risk_score, 0.8),
                    applied_policies=["block-permission-escalation"],
                    triggered_rule="rule.permission.escalation.block",
                    affected_resource=affected_resource,
                )

        # --- Step 2: Classify relevance ---
        relevance = classify_relevance(
            action.action_type, action.description,
            request.task_id, request.session_id
        )

        # --- Step 3: Compute risk ---
        risk_level, risk_score = compute_risk(
            relevance, data_tags, action.third_party, action.destination
        )

        # --- Step 4: Apply decision rules ---
        reasons: list[str] = []
        applied_policies: list[str] = []
        decision: Decision
        triggered_rule: str

        if relevance == Relevance.DANGEROUS:
            decision = Decision.BLOCK
            reasons.append(f"Action classified as DANGEROUS")
            reasons.append(f"Action type: {action.action_type}, description indicates harmful intent")
            applied_policies.append("block-unrelated-upload")
            triggered_rule = "rule.relevance.dangerous.block"

        elif relevance == Relevance.UNRELATED:
            # Check if it's an upload/external send with sensitive data
            if action_lower in ("upload", "external_send", "external_upload"):
                has_sensitive = bool({t.lower() for t in data_tags} & {
                    "pii", "credentials", "secret", "password", "api_key",
                    "token", "ssn", "credit_card", "health", "financial",
                    "confidential", "sensitive"
                })
                if has_sensitive:
                    decision = Decision.BLOCK
                    reasons.append("External upload/send of sensitive data detected")
                    reasons.append(f"Sensitive tags found: {data_tags}")
                    reasons.append(f"Destination: {action.destination or 'unknown'}")
                    applied_policies.append("block-unrelated-upload")
                    triggered_rule = "rule.relevance.dangerous.block"
                else:
                    decision = Decision.BLOCK
                    reasons.append("Unrelated external upload/send action")
                    reasons.append(f"Action has no task relevance and targets external destination")
                    applied_policies.append("block-unrelated-upload")
                    triggered_rule = "rule.relevance.unrelated-upload.block"
            elif action_lower in ("read_file", "read"):
                decision = Decision.RESTRICT
                reasons.append("File access is unrelated to current task")
                reasons.append(f"Action '{action.action_type}' on target '{action.target}' is not task-relevant")
                applied_policies.append("restrict-unrelated-file-access")
                triggered_rule = "rule.relevance.unrelated-file.restrict"
            else:
                decision = Decision.RESTRICT
                reasons.append(f"Action '{action.action_type}' is unrelated to current task")
                applied_policies.append("restrict-unrelated-file-access")
                triggered_rule = "rule.relevance.unrelated-action.restrict"

        elif relevance == Relevance.POTENTIALLY_RELEVANT:
            if risk_level == RiskLevel.HIGH:
                decision = Decision.RESTRICT
                reasons.append("Action is potentially relevant but high risk")
                applied_policies.append("restrict-unrelated-file-access")
                triggered_rule = "rule.risk.high-risk-potential.restrict"
            else:
                decision = Decision.ALLOW
                reasons.append("Action is potentially relevant with acceptable risk")
                applied_policies.append("allow-task-relevant-low-risk")
                triggered_rule = "rule.relevance.task-relevant-low-risk.allow"

        elif relevance == Relevance.RELEVANT:
            if risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM):
                decision = Decision.ALLOW
                reasons.append("Action is task-relevant with low risk")
                applied_policies.append("allow-task-relevant-low-risk")
                triggered_rule = "rule.relevance.task-relevant-low-risk.allow"
            else:
                decision = Decision.RESTRICT
                reasons.append("Action is task-relevant but high risk")
                applied_policies.append("restrict-unrelated-file-access")
                triggered_rule = "rule.risk.relevant-high-risk.restrict"
        else:
            # Fail closed
            decision = Decision.BLOCK
            reasons.append("Unknown relevance classification; failing closed")
            applied_policies.append("fail-closed")
            triggered_rule = "rule.engine.fail-closed.block"

        # --- Step 5: Third-party check ---
        # third_party alone must NEVER be the only reason for a BLOCK
        if action.third_party:
            reasons.append("Action involves third-party service")
            if decision == Decision.ALLOW:
                # Check if there's an approved-third-party policy
                applied_policies.append("allow-approved-third-party")

        return _finalize(
            db=db,
            request=request,
            decision=decision,
            reasons=reasons,
            risk_level=risk_level,
            risk_score=risk_score,
            applied_policies=applied_policies,
            triggered_rule=triggered_rule,
            affected_resource=affected_resource,
        )

    except Exception as e:
        # Fail closed on any unexpected error
        logger.error(f"Engine error: {e}")
        return _finalize(
            db=db,
            request=request,
            decision=Decision.BLOCK,
            reasons=[f"Internal engine error; failing closed"],
            risk_level=RiskLevel.HIGH,
            risk_score=1.0,
            applied_policies=["fail-closed"],
            triggered_rule="rule.engine.error.block",
            affected_resource=None,
        )


def _finalize(
    db: Session,
    request: AnalyzeRequest,
    decision: Decision,
    reasons: list[str],
    risk_level: RiskLevel,
    risk_score: float,
    applied_policies: list[str],
    triggered_rule: str,
    affected_resource: str | None,
    override_decision: Decision | None = None,
) -> AnalyzeResponse:
    """Create audit event and return response."""
    final_decision = override_decision if override_decision else decision
    event_id = str(uuid.uuid4())

    # Persist audit event
    try:
        audit_event = AuditEvent(
            event_id=event_id,
            session_id=request.session_id,
            task_id=request.task_id,
            action_type=request.action.action_type,
            action_description=request.action.description,
            target=request.action.target,
            destination=request.action.destination,
            decision=final_decision.value,
            risk_level=risk_level.value,
            risk_score=risk_score,
            reasons=reasons,
            applied_policies=applied_policies,
            triggered_rule=triggered_rule,
            affected_resource=affected_resource,
        )
        db.add(audit_event)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to persist audit event: {e}")
        db.rollback()

    return AnalyzeResponse(
        decision=final_decision.value,
        reasons=reasons,
        risk_level=risk_level.value,
        risk_score=risk_score,
        applied_policies=applied_policies,
        triggered_rule=triggered_rule,
        affected_resource=affected_resource,
        audit_event_id=event_id,
    )
