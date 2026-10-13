"""Tests for the ZENTRIQ analyze API endpoint."""
import os
import pytest
from fastapi.testclient import TestClient


class TestAnalyzeEndpoint:
    """POST /api/v1/analyze returns correct response shape."""

    def test_analyze_returns_correct_shape(self, client, auth_headers):
        payload = {
            "session_id": "sess-001",
            "task_id": "task-001",
            "action": {
                "action_type": "read_file",
                "description": "Reading project config",
                "target": "/app/config.yaml",
                "data": {"name": "config", "tags": []},
                "third_party": False,
            }
        }
        response = client.post("/api/v1/analyze", json=payload, headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "decision" in data
        assert data["decision"] in ("ALLOW", "RESTRICT", "BLOCK")
        assert "reasons" in data
        assert isinstance(data["reasons"], list)
        assert "risk_level" in data
        assert data["risk_level"] in ("low", "medium", "high")
        assert "risk_score" in data
        assert 0.0 <= data["risk_score"] <= 1.0
        assert "applied_policies" in data
        assert isinstance(data["applied_policies"], list)
        assert "triggered_rule" in data
        assert "audit_event_id" in data

    def test_analyze_requires_auth(self, client):
        payload = {
            "session_id": "sess-001",
            "task_id": "task-001",
            "action": {
                "action_type": "read_file",
                "description": "test",
            }
        }
        response = client.post("/api/v1/analyze", json=payload)
        assert response.status_code == 401

    def test_analyze_rejects_bad_key(self, client):
        payload = {
            "session_id": "sess-001",
            "task_id": "task-001",
            "action": {
                "action_type": "read_file",
                "description": "test",
            }
        }
        headers = {"Authorization": "Bearer wrong-key"}
        response = client.post("/api/v1/analyze", json=payload, headers=headers)
        assert response.status_code == 401


class TestPoliciesEndpoint:
    def test_policies_returns_list(self, client, auth_headers):
        response = client.get("/api/v1/policies", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)


class TestAuditEndpoint:
    def test_audit_returns_list(self, client, auth_headers):
        response = client.get("/api/v1/audit/events", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_audit_populated_after_analyze(self, client, auth_headers):
        payload = {
            "session_id": "sess-audit",
            "task_id": "task-audit",
            "action": {
                "action_type": "read_file",
                "description": "reading for audit test",
                "target": "/test/file.txt",
            }
        }
        client.post("/api/v1/analyze", json=payload, headers=auth_headers)
        response = client.get("/api/v1/audit/events", headers=auth_headers)
        events = response.json()
        assert len(events) >= 1
        assert events[0]["session_id"] == "sess-audit"


class TestHealthEndpoint:
    def test_health(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "zentriq"
