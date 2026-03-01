"""
Tests de la API REST — Guardian Backend
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ── /api/v1/evaluate ─────────────────────────────────────────────────────────

def test_evaluate_safe_context():
    r = client.post("/api/v1/evaluate", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["score"] == 0
    assert body["level"] == "LOW"
    assert body["reasons"] == []
    assert body["recommended_action"] != ""


def test_evaluate_scam_scenario():
    r = client.post("/api/v1/evaluate", json={
        "overlay_detected": True,
        "wifi_known": False,
        "tls_valid": False,
        "recent_failed_logins": 5,
        "triggered_by": "login_attempt",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["level"] == "CRITICAL"
    assert body["score"] == 100
    assert len(body["reasons"]) > 0


def test_evaluate_invalid_payload():
    r = client.post("/api/v1/evaluate", json={"recent_failed_logins": -1})
    assert r.status_code == 422   # Pydantic validation error


def test_evaluate_returns_all_fields():
    r = client.post("/api/v1/evaluate", json={"wifi_known": False})
    body = r.json()
    assert "score" in body
    assert "level" in body
    assert "reasons" in body
    assert "recommended_action" in body


# ── /api/v1/rules ─────────────────────────────────────────────────────────────

def test_list_rules_returns_list():
    r = client.get("/api/v1/rules")
    assert r.status_code == 200
    rules = r.json()
    assert isinstance(rules, list)
    assert len(rules) > 0


def test_rules_have_required_fields():
    r = client.get("/api/v1/rules")
    for rule in r.json():
        assert "name" in rule
        assert "points" in rule
        assert "description" in rule
        assert rule["points"] > 0


# ── /api/v1/report ────────────────────────────────────────────────────────────

def test_report_accepted():
    r = client.post("/api/v1/report", json={
        "event_type": "scam_popup",
        "app_package": "com.fake.bank",
        "device_id": "abc123",
    })
    assert r.status_code == 200
    assert r.json()["status"] == "received"


def test_report_minimal_payload():
    r = client.post("/api/v1/report", json={"event_type": "phishing_sms"})
    assert r.status_code == 200
