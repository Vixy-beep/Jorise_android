package com.guardian.app.scoring

/**
 * Señales de contexto recolectadas localmente en el dispositivo.
 * Este objeto es lo que se evalúa en el motor local y,
 * opcionalmente, se envía al backend para mayor análisis.
 */
data class ContextSnapshot(
    // Red
    val wifiKnown: Boolean = true,
    val dnsStandard: Boolean = true,
    val tlsValid: Boolean = true,
    val vpnActive: Boolean = false,

    // Dispositivo
    val overlayDetected: Boolean = false,
    val newSensitivePermission: Boolean = false,
    val unknownAppForeground: Boolean = false,
    val developerOptions: Boolean = false,

    // Comportamiento
    val unusualHour: Boolean = false,
    val unusualLocation: Boolean = false,
    val recentFailedLogins: Int = 0,

    // Metadatos
    val deviceId: String = "",
    val appPackage: String = "",
    val triggeredBy: String = "",
)

enum class RiskLevel(val label: String, val emoji: String) {
    LOW("Bajo", "🟢"),
    MEDIUM("Medio", "🟡"),
    HIGH("Alto", "🟠"),
    CRITICAL("Crítico", "🔴"),
}

data class RiskScore(
    val score: Int,
    val level: RiskLevel,
    val reasons: List<String>,
    val recommendedAction: String,
)
