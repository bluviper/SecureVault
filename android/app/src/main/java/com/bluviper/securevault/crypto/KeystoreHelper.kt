package com.bluviper.securevault.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Manages hardware-backed key wrapping via the Android Keystore.
 * When biometric unlock is enabled, the 256-bit AES vault key is encrypted
 * using a hardware key gated by BiometricPrompt (AUTH_BIOMETRIC_STRONG).
 */
object KeystoreHelper {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "SecureVaultBiometricMasterKey"
    private const val PREFS_NAME = "securevault_keystore_prefs"
    private const val PREF_WRAPPED_KEY = "wrapped_aes_key"
    private const val PREF_KEYSTORE_IV = "keystore_gcm_iv"

    private const val GCM_TAG_LENGTH_BITS = 128

    fun isBiometricAvailable(context: Context): Boolean {
        val biometricManager = BiometricManager.from(context)
        return biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) == BiometricManager.BIOMETRIC_SUCCESS
    }

    fun hasBiometricKey(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.contains(PREF_WRAPPED_KEY) && prefs.contains(PREF_KEYSTORE_IV)
    }

    private fun getOrCreateHardwareKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (keyStore.containsAlias(KEY_ALIAS)) {
            val entry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
            if (entry != null) return entry.secretKey
        }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            // Invalidates key if user alters enrolled fingerprints in OS settings
            .setInvalidatedByBiometricEnrollment(true)

        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }

    /**
     * Initializes a Cipher in ENCRYPT mode to wrap the AES vault key.
     * To be passed into BiometricPrompt.CryptoObject(cipher).
     */
    fun initBiometricEncryptCipher(): Cipher {
        val secretKey = getOrCreateHardwareKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher
    }

    /**
     * Initializes a Cipher in DECRYPT mode to unwrap the AES vault key.
     * To be passed into BiometricPrompt.CryptoObject(cipher).
     */
    fun initBiometricDecryptCipher(context: Context): Cipher? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val ivBase64 = prefs.getString(PREF_KEYSTORE_IV, null) ?: return null
        val iv = Base64.getDecoder().decode(ivBase64)

        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val secretKey = (keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
            ?: return null

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        return cipher
    }

    /**
     * Saves the wrapped AES vault key after BiometricPrompt authentication succeeds.
     */
    fun saveWrappedMasterKey(context: Context, cipher: Cipher, rawMasterKey: ByteArray): Boolean {
        return try {
            val wrapped = cipher.doFinal(rawMasterKey)
            val iv = cipher.iv

            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString(PREF_WRAPPED_KEY, Base64.getEncoder().encodeToString(wrapped))
                .putString(PREF_KEYSTORE_IV, Base64.getEncoder().encodeToString(iv))
                .commit()
            true
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    /**
     * Unwraps the AES vault key using the authenticated Cipher from BiometricPrompt.
     */
    fun unwrapMasterKey(context: Context, cipher: Cipher): ByteArray? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val wrappedBase64 = prefs.getString(PREF_WRAPPED_KEY, null) ?: return null
        val wrapped = Base64.getDecoder().decode(wrappedBase64)

        return try {
            cipher.doFinal(wrapped)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * Clears all wrapped keys and preferences.
     */
    fun clearBiometricKey(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit().clear().apply()
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS)
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}
