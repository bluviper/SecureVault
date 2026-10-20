package com.bluviper.securevault.crypto

import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Data container representing the encrypted .vault payload format.
 * Exactly matches Web Crypto API output: { salt: base64, iv: base64, data: base64 }
 */
data class VaultPayload(
    val saltBase64: String,
    val ivBase64: String,
    val dataBase64: String
) {
    fun toJson(): String {
        val obj = JSONObject()
        obj.put("salt", saltBase64)
        obj.put("iv", ivBase64)
        obj.put("data", dataBase64)
        return obj.toString()
    }

    companion object {
        fun fromJson(jsonStr: String): VaultPayload {
            val obj = JSONObject(jsonStr)
            return VaultPayload(
                saltBase64 = obj.getString("salt"),
                ivBase64 = obj.getString("iv"),
                dataBase64 = obj.getString("data")
            )
        }
    }
}

/**
 * Cryptographic engine providing 100% interoperability with SecureVault's Web Crypto implementation:
 * - PBKDF2-HMAC-SHA256 (600,000 iterations, 256-bit key)
 * - AES-256-GCM (12-byte IV, 128-bit auth tag, NoPadding)
 */
object VaultCrypto {

    const val PBKDF2_ITERATIONS = 600_000
    private const val KEY_LENGTH_BITS = 256
    private const val GCM_IV_LENGTH_BYTES = 12
    private const val GCM_TAG_LENGTH_BITS = 128
    private const val SALT_LENGTH_BYTES = 16

    private val secureRandom = SecureRandom()
    private val b64Encoder = Base64.getEncoder()
    private val b64Decoder = Base64.getDecoder()

    fun generateSalt(): ByteArray {
        val salt = ByteArray(SALT_LENGTH_BYTES)
        secureRandom.nextBytes(salt)
        return salt
    }

    fun generateIv(): ByteArray {
        val iv = ByteArray(GCM_IV_LENGTH_BYTES)
        secureRandom.nextBytes(iv)
        return iv
    }

    /**
     * Derives a 256-bit AES SecretKey from a Master Password using PBKDF2-HMAC-SHA256.
     */
    fun deriveKey(masterPassword: CharArray, salt: ByteArray, iterations: Int = PBKDF2_ITERATIONS): SecretKey {
        val keySpec = PBEKeySpec(masterPassword, salt, iterations, KEY_LENGTH_BITS)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val keyBytes = factory.generateSecret(keySpec).encoded
        keySpec.clearPassword()
        return SecretKeySpec(keyBytes, "AES")
    }

    /**
     * Encrypts plaintext string using a derived AES key and generates a fresh 12-byte IV.
     */
    fun encryptWithKey(plaintext: String, aesKey: SecretKey, salt: ByteArray): VaultPayload {
        val iv = generateIv()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec)

        val plaintextBytes = plaintext.toByteArray(StandardCharsets.UTF_8)
        val ciphertextBytes = cipher.doFinal(plaintextBytes)

        return VaultPayload(
            saltBase64 = b64Encoder.encodeToString(salt),
            ivBase64 = b64Encoder.encodeToString(iv),
            dataBase64 = b64Encoder.encodeToString(ciphertextBytes)
        )
    }

    /**
     * Decrypts a VaultPayload using the supplied 256-bit AES SecretKey.
     */
    fun decryptWithKey(payload: VaultPayload, aesKey: SecretKey): String {
        val iv = b64Decoder.decode(payload.ivBase64)
        val ciphertext = b64Decoder.decode(payload.dataBase64)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec)

        val decryptedBytes = cipher.doFinal(ciphertext)
        return String(decryptedBytes, StandardCharsets.UTF_8)
    }

    /**
     * Convenience method to decrypt directly with Master Password.
     */
    fun decrypt(payload: VaultPayload, masterPassword: CharArray, iterations: Int = PBKDF2_ITERATIONS): String {
        val salt = b64Decoder.decode(payload.saltBase64)
        val key = deriveKey(masterPassword, salt, iterations)
        return decryptWithKey(payload, key)
    }

    /**
     * Convenience method to encrypt directly with Master Password.
     */
    fun encrypt(
        plaintext: String,
        masterPassword: CharArray,
        customSalt: ByteArray? = null,
        iterations: Int = PBKDF2_ITERATIONS
    ): VaultPayload {
        val salt = customSalt ?: generateSalt()
        val key = deriveKey(masterPassword, salt, iterations)
        return encryptWithKey(plaintext, key, salt)
    }
}
