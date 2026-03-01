from pydantic import BaseModel, Field
from typing import List, Optional


# ── Request ──────────────────────────────────────────────────────────────────

class ContextSnapshotRequest(BaseModel):
    """Payload que envía la app Android al backend."""

    # Red
    wifi_known: bool = True
    dns_standard: bool = True
    tls_valid: bool = True
    vpn_active: bool = False

    # Dispositivo
    overlay_detected: bool = False
    new_sensitive_permission: bool = False
    unknown_app_foreground: bool = False
    developer_options: bool = False

    # Comportamiento
    unusual_hour: bool = False
    unusual_location: bool = False
    recent_failed_logins: int = Field(default=0, ge=0)

    # Metadatos opcionales
    device_id: Optional[str] = ""
    app_package: Optional[str] = ""
    triggered_by: Optional[str] = ""

    model_config = {"json_schema_extra": {
        "example": {
            "wifi_known": False,
            "dns_standard": True,
            "tls_valid": True,
            "overlay_detected": True,
            "triggered_by": "login_attempt",
        }
    }}


# ── Response ─────────────────────────────────────────────────────────────────

class RiskScoreResponse(BaseModel):
    score: int = Field(..., ge=0, le=100, description="Puntuación de riesgo 0–100")
    level: str = Field(..., description="LOW | MEDIUM | HIGH | CRITICAL")
    reasons: List[str]
    recommended_action: str


# ── Rules ─────────────────────────────────────────────────────────────────────

class RuleResponse(BaseModel):
    name: str
    points: int
    description: str


# ── Report ────────────────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    """Reporte anónimo enviado desde el dispositivo para mejorar las reglas."""
    device_id: str = ""
    event_type: str         # ej: "scam_popup", "phishing_sms", "fake_app"
    app_package: str = ""
    notes: str = ""
