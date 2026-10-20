package com.bluviper.securevault.bridge

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import android.util.AtomicFile
import android.webkit.JavascriptInterface
import android.webkit.WebView
import com.bluviper.securevault.MainActivity
import com.bluviper.securevault.crypto.KeystoreHelper
import com.bluviper.securevault.crypto.VaultCrypto
import com.bluviper.securevault.crypto.VaultPayload
import java.io.File
import java.nio.charset.StandardCharsets

/**
 * JavaScript Interface attached to WebView as `window.AndroidVaultBridge`.
 * Provides atomic file I/O in app-private storage, biometric auth integration,
 * and secure clipboard manipulation with Android 13+ sensitive content flags.
 */
class AndroidVaultBridge(
    private val activity: MainActivity,
    private val webView: WebView
) {
    private val vaultFile = File(activity.filesDir, "vault.json")
    private val atomicVaultFile = AtomicFile(vaultFile)

    @JavascriptInterface
    fun getPlatform(): String {
        return "android"
    }

    /**
     * Atomically saves the encrypted vault JSON to app-private storage.
     */
    @JavascriptInterface
    fun saveVault(ciphertextJson: String): Boolean {
        return try {
            val bytes = ciphertextJson.toByteArray(StandardCharsets.UTF_8)
            val fos = atomicVaultFile.startWrite()
            try {
                fos.write(bytes)
                atomicVaultFile.finishWrite(fos)
                true
            } catch (e: Exception) {
                atomicVaultFile.failWrite(fos)
                false
            }
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    /**
     * Reads the encrypted vault JSON from app-private storage.
     * Returns null if no vault file exists yet.
     */
    @JavascriptInterface
    fun loadVault(): String? {
        if (!vaultFile.exists()) return null
        return try {
            val bytes = atomicVaultFile.readFully()
            String(bytes, StandardCharsets.UTF_8)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    @JavascriptInterface
    fun hasVault(): Boolean {
        return vaultFile.exists() && vaultFile.length() > 0
    }

    @JavascriptInterface
    fun isBiometricAvailable(): Boolean {
        return KeystoreHelper.isBiometricAvailable(activity)
    }

    @JavascriptInterface
    fun hasBiometricKey(): Boolean {
        return KeystoreHelper.hasBiometricKey(activity)
    }

    /**
     * Prompts biometric authentication to wrap and store the derived AES master key.
     */
    @JavascriptInterface
    fun requestEnableBiometric(masterPassword: String, callbackJs: String) {
        activity.runOnUiThread {
            activity.enrollBiometric(masterPassword) { success, errorMsg ->
                val escaped = errorMsg?.replace("'", "\\'") ?: ""
                webView.evaluateJavascript("$callbackJs($success, '$escaped')", null)
            }
        }
    }

    /**
     * Prompts biometric authentication to unwrap the AES master key and decrypt the vault.
     */
    @JavascriptInterface
    fun requestBiometricUnlock(callbackJs: String) {
        activity.runOnUiThread {
            activity.unlockWithBiometric { success, decryptedJson, errorMsg ->
                val escapedJson = decryptedJson?.replace("'", "\\'")?.replace("\n", "\\n") ?: ""
                val escapedErr = errorMsg?.replace("'", "\\'") ?: ""
                webView.evaluateJavascript(
                    "$callbackJs($success, '$escapedJson', '$escapedErr')",
                    null
                )
            }
        }
    }

    /**
     * Copies text to clipboard, setting EXTRA_IS_SENSITIVE on Android 13+ (API 33+)
     * so that the OS keyboard and clipboard history will not persist credentials.
     */
    @JavascriptInterface
    fun copyToClipboard(label: String, text: String, isSensitive: Boolean) {
        activity.runOnUiThread {
            val clipboard = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText(label, text)
            if (isSensitive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                clip.description.extras = PersistableBundle().apply {
                    putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                }
            }
            clipboard.setPrimaryClip(clip)
        }
    }
}
