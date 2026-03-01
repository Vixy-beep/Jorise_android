"""
Tests del motor de scoring de riesgo — Guardian Backend
"""

import pytest
from app.scoring.engine import evaluate, ContextSnapshot, RiskLevel


def ctx(**kwargs) -> ContextSnapshot:
    """Helper: crea un ContextSnapshot con valores seguros por defecto."""
    return ContextSnapshot(**kwargs)


# ── Riesgo BAJO ──────────────────────────────────────────────────────────────

def test_all_safe_is_low():
    result = evaluate(ctx())
    assert result.level == RiskLevel.LOW
    assert result.score == 0
    assert result.reasons == []


def test_vpn_alone_is_low():
    result = evaluate(ctx(vpn_active=True))
    assert result.level == RiskLevel.LOW
    assert result.score == 10


def test_unusual_hour_alone_is_low():
    result = evaluate(ctx(unusual_hour=True))
    assert result.level == RiskLevel.LOW
    assert result.score == 10


# ── Riesgo MEDIO ─────────────────────────────────────────────────────────────

def test_unknown_wifi_is_low():
    # 20 pts → still LOW (threshold for MEDIUM is >30)
    result = evaluate(ctx(wifi_known=False))
    assert result.level == RiskLevel.LOW
    assert result.score == 20


def test_unknown_wifi_plus_unusual_hour_is_medium():
    result = evaluate(ctx(wifi_known=False, unusual_hour=True))
    assert result.score == 30
    assert result.level == RiskLevel.LOW   # borde exacto en 30 = LOW


def test_unknown_wifi_unusual_hour_failed_login():
    result = evaluate(ctx(wifi_known=False, unusual_hour=True, recent_failed_logins=1))
    assert result.score == 40
    assert result.level == RiskLevel.MEDIUM


# ── Riesgo ALTO ───────────────────────────────────────────────────────────────

def test_overlay_detected_is_medium():
    # 40 pts → MEDIUM (threshold for HIGH is >60)
    result = evaluate(ctx(overlay_detected=True))
    assert result.level == RiskLevel.MEDIUM
    assert result.score == 40


def test_tls_invalid_is_medium():
    # 35 pts → MEDIUM (threshold for HIGH is >60)
    result = evaluate(ctx(tls_valid=False))
    assert result.level == RiskLevel.MEDIUM
    assert result.score == 35


def test_overlay_plus_unknown_wifi_is_high():
    result = evaluate(ctx(overlay_detected=True, wifi_known=False))
    assert result.score == 60
    assert result.level == RiskLevel.MEDIUM   # borde exacto en 60 = MEDIUM


# ── Riesgo CRÍTICO ────────────────────────────────────────────────────────────

def test_overlay_plus_wifi_plus_dns_is_critical():
    result = evaluate(ctx(
        overlay_detected=True,
        wifi_known=False,
        dns_standard=False,
    ))
    assert result.score == 75
    assert result.level == RiskLevel.HIGH


def test_full_attack_scenario_is_critical():
    """Escenario: overlay activo + WiFi desconocida + TLS inválido + 3 login fallidos."""
    result = evaluate(ctx(
        overlay_detected=True,
        wifi_known=False,
        tls_valid=False,
        recent_failed_logins=3,
    ))
    assert result.level == RiskLevel.CRITICAL
    assert result.score == 100   # capped at 100


def test_score_capped_at_100():
    """El score nunca supera 100 aunque las reglas sumen más."""
    result = evaluate(ctx(
        overlay_detected=True,
        wifi_known=False,
        tls_valid=False,
        dns_standard=False,
        new_sensitive_permission=True,
        unknown_app_foreground=True,
        developer_options=True,
        unusual_hour=True,
        unusual_location=True,
        recent_failed_logins=5,
    ))
    assert result.score == 100


# ── Razones ───────────────────────────────────────────────────────────────────

def test_reasons_are_populated():
    result = evaluate(ctx(wifi_known=False, overlay_detected=True))
    assert len(result.reasons) == 2
    assert any("WiFi" in r for r in result.reasons)
    assert any("overlay" in r.lower() or "popup" in r.lower() or "scam" in r.lower() for r in result.reasons)


def test_recommended_action_not_empty():
    for level_flag in [
        {},
        {"wifi_known": False},
        {"overlay_detected": True},
        {"overlay_detected": True, "tls_valid": False, "recent_failed_logins": 5},
    ]:
        result = evaluate(ctx(**level_flag))
        assert result.recommended_action != ""
