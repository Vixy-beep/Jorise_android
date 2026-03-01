package com.guardian.app.scoring

/**
 * Motor de scoring de riesgo — evaluación local (sin backend).
 *
 * Misma lógica de reglas que el backend Python.
 * Se puede sincronizar via /api/v1/rules cuando hay conexión.
 */
object RiskEngine {

    private data class Rule(
        val name: String,
        val points: Int,
        val description: String,
        val condition: (ContextSnapshot) -> Boolean,
    )

    private val RULES = listOf(
        // Red
        Rule("wifi_unknown",       20, "Conectado a red WiFi desconocida")             { !it.wifiKnown },
        Rule("dns_nonstandard",    15, "DNS no estándar (posible DNS hijacking)")       { !it.dnsStandard },
        Rule("tls_invalid",        35, "Certificado TLS inválido o autofirmado")        { !it.tlsValid },
        Rule("vpn_active",         10, "VPN activa — red alterada")                    { it.vpnActive },

        // Dispositivo
        Rule("overlay_detected",   40, "Overlay/popup sospechoso activo")              { it.overlayDetected },
        Rule("new_sensitive_perm", 25, "Permiso sensible concedido recientemente")     { it.newSensitivePermission },
        Rule("unknown_app_fg",     20, "App desconocida en primer plano")              { it.unknownAppForeground },
        Rule("dev_options",        10, "Opciones de desarrollador habilitadas")        { it.developerOptions },

        // Comportamiento
        Rule("unusual_hour",       10, "Acción fuera del horario habitual")            { it.unusualHour },
        Rule("unusual_location",   15, "Acción desde ubicación inusual")              { it.unusualLocation },
        Rule("failed_logins_1",    10, "1–2 intentos de login fallidos recientes")    { it.recentFailedLogins in 1..2 },
        Rule("failed_logins_many", 30, "3+ intentos de login fallidos recientes")     { it.recentFailedLogins >= 3 },
    )

    fun evaluate(ctx: ContextSnapshot): RiskScore {
        var total = 0
        val reasons = mutableListOf<String>()

        for (rule in RULES) {
            if (rule.condition(ctx)) {
                total += rule.points
                reasons.add(rule.description)
            }
        }

        total = total.coerceAtMost(100)
        val level = scoreToLevel(total)

        return RiskScore(
            score = total,
            level = level,
            reasons = reasons,
            recommendedAction = recommendedAction(level),
        )
    }

    private fun scoreToLevel(score: Int) = when {
        score <= 30 -> RiskLevel.LOW
        score <= 60 -> RiskLevel.MEDIUM
        score <= 80 -> RiskLevel.HIGH
        else        -> RiskLevel.CRITICAL
    }

    private fun recommendedAction(level: RiskLevel) = when (level) {
        RiskLevel.LOW      -> "Todo parece normal. Podés continuar."
        RiskLevel.MEDIUM   -> "Hay algo que no parece normal. Revisá antes de continuar."
        RiskLevel.HIGH     -> "Detectamos algo sospechoso. Confirmá tu identidad para seguir."
        RiskLevel.CRITICAL -> "Bloqueamos la acción por tu seguridad. Revisá tu dispositivo."
    }
}
