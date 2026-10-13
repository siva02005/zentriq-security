"""Tests for the ZENTRIQ deterministic security engine."""
import pytest
from backend.app.security.engine import analyze_action
from backend.app.schemas.analyze import AnalyzeRequest, Action, ActionData


class TestRelevantReadAllow:
    """Relevant read -> ALLOW with correct triggered_rule."""

    def test_relevant_read_file_allows(self, db):
        request = AnalyzeRequest(
            session_id="session-1",
            task_id="task-1",
            action=Action(
                action_type="read_file",
                description="Reading config file for task",
                target="/app/config.yaml",
            )
        )
        response = analyze_action(request, db)
        assert response.decision == "ALLOW"
        assert response.triggered_rule == "rule.relevance.task-relevant-low-risk.allow"
        assert response.audit_event_id
        assert response.risk_level in ("low", "medium")

    def test_relevant_query_allows(self, db):
        request = AnalyzeRequest(
            session_id="session-1",
            task_id="task-1",
            action=Action(
                action_type="query",
                description="Querying database for user records",
                target="users_table",
            )
        )
        response = analyze_action(request, db)
        assert response.decision == "ALLOW"
        assert "allow" in response.triggered_rule


class TestUnrelatedFileRestrict:
    """Unrelated file action -> RESTRICT."""

    def test_unrelated_action_restricts(self, db):
        request = AnalyzeRequest(
            session_id="session-1",
            task_id="task-1",
            action=Action(
                action_type="install",
                description="installing random package",
                target="malware-pkg",
            )
        )
        response = analyze_action(request, db)
        assert response.decision == "RESTRICT"
        assert "restrict" in response.triggered_rule


class TestExternalUploadSensitiveBlock:
    """External upload of sensitive data -> BLOCK."""

    def test_upload_sensitive_data_blocks(self, db):
        request = AnalyzeRequest(
            session_id="session-1",
            task_id="task-1",
            action=Action(
                action_type="upload",
                description="uploading user data externally",
                target="user_data.csv",
                destination="external-s3-bucket",
                data=ActionData(name="user_export", tags=["pii", "credentials"]),
                third_party=True,
            )
        )
        response = analyze_action(request, db)
        assert response.decision == "BLOCK"
        assert response.risk_level == "high"
        assert response.audit_event_id

    def test_external_send_sensitive_blocks(self, db):
        request = AnalyzeRequest(
            session_id="session-1",
            task_id="task-1",
            action=Action(
                action_type="external_send",
                description="sending secrets to webhook",
                destination="https://webhook.external.com",
                data=ActionData(name="secrets", tags=["secret", "api_key"]),
            )
        )
        response = analyze_action(request, db)
        assert response.decision == "BLOCK"


class TestPermissionEscalationBlock:
    """Permission escalation -> BLOCK."""

    def test_escalation_blocks(self, db):
        request = AnalyzeRequest(
            session_id="session-1",
            task_id="task-1",
            action=Action(
                action_type="escalate",
                description="escalating privileges to root",
                target="system",
            )
        )
        response = analyze_action(request, db)
        assert response.decision == "BLOCK"
        assert response.triggered_rule == "rule.permission.escalation.block"

    def test_privesc_in_description_blocks(self, db):
        request = AnalyzeRequest(
            session_id="session-1",
            task_id="task-1",
            action=Action(
                action_type="exec",
                description="privesc to admin user",
                target="system",
            )
        )
        response = analyze_action(request, db)
        assert response.decision == "BLOCK"
        assert response.triggered_rule == "rule.permission.escalation.block"


class TestMissingTaskRestrict:
    """Missing task/session context -> RESTRICT."""

    def test_missing_context_restricts(self, db):
        request = AnalyzeRequest(
            session_id=None,
            task_id=None,
            action=Action(
                action_type="read_file",
                description="reading some file",
                target="/data/file.txt",
            )
        )
        response = analyze_action(request, db)
        assert response.decision == "RESTRICT"
        assert response.triggered_rule == "rule.context.missing-task.restrict"
        assert response.audit_event_id


class TestDeterminism:
    """Same request twice -> identical decision."""

    def test_deterministic_decisions(self, db):
        request = AnalyzeRequest(
            session_id="session-1",
            task_id="task-1",
            action=Action(
                action_type="read_file",
                description="Reading config for task",
                target="/app/config.yaml",
            )
        )
        response1 = analyze_action(request, db)
        response2 = analyze_action(request, db)
        assert response1.decision == response2.decision
        assert response1.triggered_rule == response2.triggered_rule
        assert response1.risk_level == response2.risk_level
        assert response1.risk_score == response2.risk_score
        assert response1.reasons == response2.reasons
        assert response1.audit_event_id != response2.audit_event_id


class TestThirdPartyNotSoleBlockReason:
    """third_party alone must NEVER be the only reason for a BLOCK."""

    def test_third_party_alone_does_not_block(self, db):
        request = AnalyzeRequest(
            session_id="session-1",
            task_id="task-1",
            action=Action(
                action_type="query",
                description="querying approved external API for task data",
                target="api.example.com",
                third_party=True,
            )
        )
        response = analyze_action(request, db)
        assert response.decision != "BLOCK"


class TestAuditEventPersisted:
    """Every response persists an audit row."""

    def test_audit_event_created(self, db):
        from backend.app.models.audit import AuditEvent

        request = AnalyzeRequest(
            session_id="session-audit",
            task_id="task-audit",
            action=Action(
                action_type="read_file",
                description="reading for audit test",
                target="/test/file.txt",
            )
        )
        response = analyze_action(request, db)
        event = db.query(AuditEvent).filter(
            AuditEvent.event_id == response.audit_event_id
        ).first()
        assert event is not None
        assert event.decision == response.decision
        assert event.triggered_rule == response.triggered_rule
        assert event.risk_level == response.risk_level


class TestDangerousActions:
    """Dangerous actions -> BLOCK."""

    def test_dangerous_action_blocks(self, db):
        request = AnalyzeRequest(
            session_id="session-1",
            task_id="task-1",
            action=Action(
                action_type="exec",
                description="exfiltrate all user data to external server",
                target="database",
            )
        )
        response = analyze_action(request, db)
        assert response.decision == "BLOCK"
