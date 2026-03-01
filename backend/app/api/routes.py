"""
Guardian API — Rutas v1

POST /evaluate     → Evalúa un ContextSnapshot y devuelve un RiskScore
GET  /rules        → Lista todas las reglas activas
POST /report       → Acepta un reporte anónimo de evento de scam
"""

from fastapi import APIRouter
from app.api.schemas import ContextSnapshotRequest, RiskScoreResponse, RuleResponse, ReportRequest
from app.scoring.engine import evaluate, ContextSnapshot
from app.scoring.rules import RULES

router = APIRouter()


@router.post("/evaluate", response_model=RiskScoreResponse, summary="Evaluar contexto")
def evaluate_context(payload: ContextSnapshotRequest):
    """
    Recibe las señales del dispositivo, calcula el Risk Score y devuelve
    el nivel de riesgo con las razones y la acción recomendada.
    """
    ctx = ContextSnapshot(
        wifi_known=payload.wifi_known,
        dns_standard=payload.dns_standard,
        tls_valid=payload.tls_valid,
        vpn_active=payload.vpn_active,
        overlay_detected=payload.overlay_detected,
        new_sensitive_permission=payload.new_sensitive_permission,
        unknown_app_foreground=payload.unknown_app_foreground,
        developer_options=payload.developer_options,
        unusual_hour=payload.unusual_hour,
        unusual_location=payload.unusual_location,
        recent_failed_logins=payload.recent_failed_logins,
        device_id=payload.device_id or "",
        app_package=payload.app_package or "",
        triggered_by=payload.triggered_by or "",
    )
    result = evaluate(ctx)
    return RiskScoreResponse(**result.as_dict)


@router.get("/rules", response_model=list[RuleResponse], summary="Listar reglas activas")
def list_rules():
    """Devuelve todas las reglas de evaluación activas en el engine."""
    return [RuleResponse(name=r.name, points=r.points, description=r.description) for r in RULES]


@router.post("/report", summary="Reportar evento de scam")
def report_event(payload: ReportRequest):
    """
    Acepta reportes anónimos de eventos de scam desde los dispositivos.
    En producción: persiste en DB para análisis de patrones.
    """
    # TODO: persistir en DB + análisis de patrones
    print(f"[REPORT] {payload.event_type} | pkg={payload.app_package} | device={payload.device_id[:8] if payload.device_id else 'anon'}")
    return {"status": "received", "message": "Gracias por el reporte."}
