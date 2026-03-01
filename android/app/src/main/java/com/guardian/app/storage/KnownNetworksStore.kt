package com.guardian.app.storage

import android.content.Context

/**
 * Almacena localmente la lista de redes WiFi conocidas del usuario.
 * Se persiste en SharedPreferences — sin servidor, sin sincronización.
 */
class KnownNetworksStore(context: Context) {

    private val prefs = context.getSharedPreferences("guardian_networks", Context.MODE_PRIVATE)

    fun isKnown(ssid: String): Boolean {
        return prefs.getStringSet(KEY, emptySet())?.contains(ssid) == true
    }

    fun add(ssid: String) {
        val current = prefs.getStringSet(KEY, mutableSetOf())?.toMutableSet() ?: mutableSetOf()
        current.add(ssid)
        prefs.edit().putStringSet(KEY, current).apply()
    }

    fun remove(ssid: String) {
        val current = prefs.getStringSet(KEY, mutableSetOf())?.toMutableSet() ?: mutableSetOf()
        current.remove(ssid)
        prefs.edit().putStringSet(KEY, current).apply()
    }

    fun getAll(): Set<String> {
        return prefs.getStringSet(KEY, emptySet()) ?: emptySet()
    }

    companion object {
        private const val KEY = "known_ssids"
    }
}
