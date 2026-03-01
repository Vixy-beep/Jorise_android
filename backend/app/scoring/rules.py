"""
Guardian — Reglas de evaluación de riesgo.

Cada regla es una función que recibe un ContextSnapshot y devuelve:
  (fired: bool, points: int, reason: str)

Para agregar una regla nueva basta con añadirla a la lista RULES.
"""

from dataclasses import dataclass
from typing import Callable, Tuple


@dataclass
class Rule:
    name: str
    points: int
    description: str
    _fn: Callable

    def evaluate(self, ctx) -> Tuple[bool, int, str]:
        fired = self._fn(ctx)
        return fired, self.points if fired else 0, self.description


# ── Definición de reglas ────────────────────────────────────────────────────

RULES = [
    # Red
    Rule("wifi_unknown",        points=20, description="Conectado a red WiFi desconocida",
         _fn=lambda c: not c.wifi_known),

    Rule("dns_nonstandard",     points=15, description="DNS no estándar detectado (posible DNS hijacking)",
         _fn=lambda c: not c.dns_standard),

    Rule("tls_invalid",         points=35, description="Certificado TLS inválido o autofirmado",
         _fn=lambda c: not c.tls_valid),

    Rule("vpn_active",          points=10, description="VPN activa — contexto de red alterado",
         _fn=lambda c: c.vpn_active),

    # Dispositivo
    Rule("overlay_detected",    points=40, description="Overlay/popup sospechoso detectado (posible scam)",
         _fn=lambda c: c.overlay_detected),

    Rule("new_sensitive_perm",  points=25, description="Permiso sensible concedido recientemente a una app",
         _fn=lambda c: c.new_sensitive_permission),

    Rule("unknown_app_fg",      points=20, description="App desconocida en primer plano",
         _fn=lambda c: c.unknown_app_foreground),

    Rule("dev_options",         points=10, description="Opciones de desarrollador activas (riesgo de ADB)",
         _fn=lambda c: c.developer_options),

    # Comportamiento
    Rule("unusual_hour",        points=10, description="Acción fuera del horario habitual del usuario",
         _fn=lambda c: c.unusual_hour),

    Rule("unusual_location",    points=15, description="Acción desde ubicación inusual",
         _fn=lambda c: c.unusual_location),

    Rule("failed_logins_1",     points=10, description="1–2 intentos de login fallidos recientes",
         _fn=lambda c: 1 <= c.recent_failed_logins <= 2),

    Rule("failed_logins_many",  points=30, description="3+ intentos de login fallidos recientes",
         _fn=lambda c: c.recent_failed_logins >= 3),
]
