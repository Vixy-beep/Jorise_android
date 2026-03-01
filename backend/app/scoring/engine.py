"""
Guardian — Motor de scoring de riesgo.

Recibe un ContextSnapshot del dispositivo Android y devuelve un RiskScore
con nivel (LOW / MEDIUM / HIGH / CRITICAL), puntuación 0–100 y razones.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List

from app.scoring.rules import RULES, Rule


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ContextSnapshot:
    """Señales recibidas desde el dispositivo Android."""

    # Red
    wifi_known: bool = True          # ¿El SSID está en la lista conocida del usuario?
    dns_standard: bool = True        # ¿El DNS es un servidor estándar (8.8.8.8, 1.1.1.1…)?
    tls_valid: bool = True           # ¿Los últimos certificados TLS eran válidos?
    vpn_active: bool = False         # ¿Hay una VPN activa?

    # Dispositivo
    overlay_detected: bool = False   # ¿Se detectó un overlay/popup de scam?
    new_sensitive_permission: bool = False  # ¿Una app pidió permiso sensible reciente?
    unknown_app_foreground: bool = False    # ¿Hay una app desconocida en primer plano?
    developer_options: bool = False  # ¿Opciones de desarrollador activas?

    # Comportamiento
    unusual_hour: bool = False       # ¿Fuera del horario típico del usuario?
    unusual_location: bool = False   # ¿Ubicación desconocida (sin GPS continuo)?
    recent_failed_logins: int = 0    # Intentos fallidos recientes

    # Metadatos opcionales
    device_id: str = ""              # Hash anónimo del dispositivo
    app_package: str = ""            # Paquete de la app que disparó la evaluación
    triggered_by: str = ""          # Acción que disparó la evaluación


@dataclass
class RiskScore:
    score: int                       # 0–100
    level: RiskLevel
    reasons: List[str] = field(default_factory=list)
    recommended_action: str = ""

    @property
    def as_dict(self):
        return {
            "score": self.score,
            "level": self.level.value,
            "reasons": self.reasons,
            "recommended_action": self.recommended_action,
        }


def _score_to_level(score: int) -> RiskLevel:
    if score <= 30:
        return RiskLevel.LOW
    if score <= 60:
        return RiskLevel.MEDIUM
    if score <= 80:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _recommended_action(level: RiskLevel) -> str:
    return {
        RiskLevel.LOW:      "Flujo normal — sin fricción adicional.",
        RiskLevel.MEDIUM:   "Mostrar aviso en lenguaje simple y agregar delay de 5 s.",
        RiskLevel.HIGH:     "Solicitar validación extra (PIN / biométrico) antes de continuar.",
        RiskLevel.CRITICAL: "Bloqueo temporal y notificación al usuario.",
    }[level]


def evaluate(ctx: ContextSnapshot) -> RiskScore:
    """Evalúa un ContextSnapshot y devuelve un RiskScore."""
    total = 0
    reasons: List[str] = []

    for rule in RULES:
        fired, points, reason = rule.evaluate(ctx)
        if fired:
            total += points
            reasons.append(reason)

    # Cap en 100
    total = min(total, 100)
    level = _score_to_level(total)

    return RiskScore(
        score=total,
        level=level,
        reasons=reasons,
        recommended_action=_recommended_action(level),
    )
