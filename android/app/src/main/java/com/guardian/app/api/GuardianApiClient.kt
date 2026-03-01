package com.guardian.app.api

import com.guardian.app.scoring.ContextSnapshot
import com.guardian.app.scoring.RiskLevel
import com.guardian.app.scoring.RiskScore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Cliente HTTP mínimo para comunicarse con el backend Guardian.
 * Sin dependencias externas (solo stdlib) — para el MVP.
 * TODO: migrar a Retrofit + OkHttp cuando el proyecto escale.
 */
class GuardianApiClient(private val baseUrl: String = BASE_URL) {

    suspend fun evaluate(ctx: ContextSnapshot): Result<RiskScore> = withContext(Dispatchers.IO) {
        runCatching {
            val body = JSONObject().apply {
                put("wifi_known",              ctx.wifiKnown)
                put("dns_standard",            ctx.dnsStandard)
                put("tls_valid",               ctx.tlsValid)
                put("vpn_active",              ctx.vpnActive)
                put("overlay_detected",        ctx.overlayDetected)
                put("new_sensitive_permission",ctx.newSensitivePermission)
                put("unknown_app_foreground",  ctx.unknownAppForeground)
                put("developer_options",       ctx.developerOptions)
                put("unusual_hour",            ctx.unusualHour)
                put("unusual_location",        ctx.unusualLocation)
                put("recent_failed_logins",    ctx.recentFailedLogins)
                put("device_id",               ctx.deviceId)
                put("app_package",             ctx.appPackage)
                put("triggered_by",            ctx.triggeredBy)
            }.toString()

            val response = post("$baseUrl/api/v1/evaluate", body)
            parseRiskScore(JSONObject(response))
        }
    }

    suspend fun reportEvent(deviceId: String, eventType: String, appPackage: String = ""): Result<Unit> =
        withContext(Dispatchers.IO) {
            runCatching {
                val body = JSONObject().apply {
                    put("device_id",   deviceId)
                    put("event_type",  eventType)
                    put("app_package", appPackage)
                }.toString()
                post("$baseUrl/api/v1/report", body)
                Unit
            }
        }

    // ── HTTP helpers ──────────────────────────────────────────────────────

    private fun post(url: String, body: String): String {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            setRequestProperty("Content-Type", "application/json")
            connectTimeout = 5_000
            readTimeout    = 10_000
            doOutput = true
        }
        conn.outputStream.use { it.write(body.toByteArray()) }
        return conn.inputStream.bufferedReader().readText()
    }

    private fun parseRiskScore(json: JSONObject): RiskScore {
        val level = when (json.getString("level")) {
            "LOW"      -> RiskLevel.LOW
            "MEDIUM"   -> RiskLevel.MEDIUM
            "HIGH"     -> RiskLevel.HIGH
            else       -> RiskLevel.CRITICAL
        }
        val reasons = buildList {
            val arr = json.getJSONArray("reasons")
            repeat(arr.length()) { add(arr.getString(it)) }
        }
        return RiskScore(
            score             = json.getInt("score"),
            level             = level,
            reasons           = reasons,
            recommendedAction = json.getString("recommended_action"),
        )
    }

    companion object {
        // Cambiar por URL real en producción — o leer de config.xml
        const val BASE_URL = "http://10.0.2.2:8000"   // localhost desde emulador Android
    }
}
