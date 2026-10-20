package com.bluviper.securevault.autofill

import org.json.JSONArray
import org.json.JSONObject

/**
 * Lightweight credential item representation for native autofill matching.
 */
data class AutofillCredential(
    val id: String,
    val type: String,
    val service: String,
    val user: String,
    val pass: String,
    val url: String?,
    val category: String?
)

/**
 * Transient in-memory session cache.
 * Cleared on auto-lock, app termination, or timeout.
 */
object VaultMemoryCache {

    private var cachedCredentials: List<AutofillCredential>? = null
    private var lastUnlockedTimestamp: Long = 0
    private const val SESSION_TIMEOUT_MS = 5 * 60 * 1000 // 5 minutes default

    fun setUnlockedCredentials(credentials: List<AutofillCredential>) {
        cachedCredentials = credentials
        lastUnlockedTimestamp = System.currentTimeMillis()
    }

    fun setFromPlaintextJson(jsonStr: String) {
        val list = mutableListOf<AutofillCredential>()
        try {
            val array = JSONArray(jsonStr)
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                val type = obj.optString("type", "login")
                if (type == "login") {
                    list.add(
                        AutofillCredential(
                            id = obj.optString("id", i.toString()),
                            type = type,
                            service = obj.optString("service", ""),
                            user = obj.optString("user", ""),
                            pass = obj.optString("pass", ""),
                            url = obj.optString("url", null),
                            category = obj.optString("category", null)
                        )
                    )
                }
            }
            setUnlockedCredentials(list)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun getCredentials(): List<AutofillCredential>? {
        if (System.currentTimeMillis() - lastUnlockedTimestamp > SESSION_TIMEOUT_MS) {
            clear()
            return null
        }
        return cachedCredentials
    }

    fun isUnlocked(): Boolean {
        return getCredentials() != null
    }

    fun clear() {
        cachedCredentials = null
        lastUnlockedTimestamp = 0
    }

    /**
     * Finds credentials matching a package name or web domain.
     */
    fun findMatches(packageName: String?, webDomain: String?): List<AutofillCredential> {
        val all = getCredentials() ?: return emptyList()
        if (packageName == null && webDomain == null) return all

        val cleanDomain = webDomain?.lowercase()?.removePrefix("www.") ?: ""
        val cleanPkg = packageName?.lowercase() ?: ""

        // Extract root domain without tld (e.g. "spotify.com" -> "spotify")
        val domainKeyword = if (cleanDomain.isNotEmpty()) {
            cleanDomain.split(".").firstOrNull { it.length > 2 } ?: cleanDomain
        } else ""

        // Extract app keyword from package (e.g. "com.spotify.music" -> "spotify")
        val pkgKeyword = if (cleanPkg.isNotEmpty()) {
            cleanPkg.split(".").firstOrNull { it != "com" && it != "org" && it != "android" && it.length > 2 } ?: cleanPkg
        } else ""

        return all.filter { cred ->
            val service = cred.service.lowercase()
            val url = cred.url?.lowercase() ?: ""

            // Match domain
            if (cleanDomain.isNotEmpty() && (url.contains(cleanDomain) || service.contains(cleanDomain) || service.contains(domainKeyword))) {
                return@filter true
            }

            // Match package
            if (pkgKeyword.isNotEmpty() && (service.contains(pkgKeyword) || url.contains(pkgKeyword))) {
                return@filter true
            }

            false
        }.ifEmpty {
            // If no specific match, return top credentials for user selection
            all.take(5)
        }
    }
}
