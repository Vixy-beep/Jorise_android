package com.guardian.app.signals

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings
import com.guardian.app.scoring.ContextSnapshot
import com.guardian.app.storage.KnownNetworksStore
import java.util.Calendar

/**
 * Recolecta señales pasivas del dispositivo y la red.
 *
 * NO lee mensajes, fotos ni datos privados.
 * Solo lee estado de red, permisos y configuración del sistema.
 */
class SignalCollector(private val context: Context) {

    fun collect(triggeredBy: String = ""): ContextSnapshot {
        return ContextSnapshot(
            wifiKnown            = isWifiKnown(),
            dnsStandard          = isDnsStandard(),
            tlsValid             = true,                // Se actualiza desde GuardianAccessibilityService
            vpnActive            = isVpnActive(),
            overlayDetected      = false,               // Se actualiza desde GuardianAccessibilityService
            newSensitivePermission = false,             // TODO: monitorear via PackageManager
            unknownAppForeground = false,               // TODO: monitorear via UsageStatsManager
            developerOptions     = isDeveloperOptionsEnabled(),
            unusualHour          = isUnusualHour(),
            unusualLocation      = false,               // TODO: historial de ubicaciones (sin GPS continuo)
            recentFailedLogins   = 0,                   // TODO: contador local persistido
            deviceId             = getAnonymousDeviceId(),
            triggeredBy          = triggeredBy,
        )
    }

    // ── Señales de red ────────────────────────────────────────────────────

    private fun isWifiKnown(): Boolean {
        val wifiManager = context.applicationContext
            .getSystemService(Context.WIFI_SERVICE) as? WifiManager
            ?: return true

        val ssid = wifiManager.connectionInfo?.ssid?.trim('"') ?: return true
        if (ssid.isBlank() || ssid == "<unknown ssid>") return true

        return KnownNetworksStore(context).isKnown(ssid)
    }

    private fun isDnsStandard(): Boolean {
        // DNS estándar conocidos
        val standardDns = setOf(
            "8.8.8.8", "8.8.4.4",          // Google
            "1.1.1.1", "1.0.0.1",          // Cloudflare
            "9.9.9.9",                      // Quad9
            "208.67.222.222",               // OpenDNS
        )
        // TODO: leer DNS activo via LinkProperties
        // Por ahora: safe default = true
        return true
    }

    private fun isVpnActive(): Boolean {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return false
        val network = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }

    // ── Señales de dispositivo ────────────────────────────────────────────

    private fun isDeveloperOptionsEnabled(): Boolean {
        return Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
        ) != 0
    }

    // ── Señales de comportamiento ─────────────────────────────────────────

    /** Considera "inusual" entre 00:00 y 06:00. Ajustar por historial del usuario. */
    private fun isUnusualHour(): Boolean {
        val hour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY)
        return hour in 0..5
    }

    // ── Metadatos ─────────────────────────────────────────────────────────

    private fun getAnonymousDeviceId(): String {
        val androidId = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ANDROID_ID
        ) ?: return ""
        // Solo los primeros 8 chars del hash — no PII
        return androidId.hashCode().toString(16).take(8)
    }
}
