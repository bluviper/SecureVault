package com.bluviper.securevault

import com.bluviper.securevault.crypto.VaultCrypto
import com.bluviper.securevault.crypto.VaultPayload
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import javax.crypto.AEADBadTagException

class VaultCryptoTest {

    @Test
    fun testKeyDerivationAndRoundtripEncryption() {
        val masterPassword = "correct-horse-battery-staple".toCharArray()
        val plaintext = """[{"id":"1","title":"GitHub","username":"alice","password":"secretpassword"}]"""

        // Use reduced iterations for fast unit test execution
        val iterations = 5000
        val payload = VaultCrypto.encrypt(plaintext, masterPassword, iterations = iterations)

        assertNotNull(payload.saltBase64)
        assertNotNull(payload.ivBase64)
        assertNotNull(payload.dataBase64)
        assertNotEquals(plaintext, payload.dataBase64)

        // Decrypt with correct password
        val decrypted = VaultCrypto.decrypt(payload, masterPassword, iterations = iterations)
        assertEquals(plaintext, decrypted)
    }

    @Test
    fun testPayloadJsonSerialization() {
        val original = VaultPayload(
            saltBase64 = "c2FsdHNhbHRzYWx0",
            ivBase64 = "MTIzNDU2Nzg5MDEy",
            dataBase64 = "ZW5jcnlwdGVkZGF0YQ=="
        )
        val jsonStr = original.toJson()
        val parsed = VaultPayload.fromJson(jsonStr)

        assertEquals(original.saltBase64, parsed.saltBase64)
        assertEquals(original.ivBase64, parsed.ivBase64)
        assertEquals(original.dataBase64, parsed.dataBase64)
    }

    @Test
    fun testWrongPasswordThrowsAuthenticationError() {
        val correctPassword = "StrongMasterPassword!99".toCharArray()
        val wrongPassword = "WrongPassword!99".toCharArray()
        val plaintext = "Sensitive data"

        val iterations = 5000
        val payload = VaultCrypto.encrypt(plaintext, correctPassword, iterations = iterations)

        try {
            VaultCrypto.decrypt(payload, wrongPassword, iterations = iterations)
            fail("Decryption with wrong password should fail with AEADBadTagException or Exception")
        } catch (e: Exception) {
            // Expected: AES-GCM authentication tag mismatch
            assertTrue(
                e is AEADBadTagException ||
                e.cause is AEADBadTagException ||
                e.javaClass.simpleName.contains("BadTag") ||
                e.javaClass.simpleName.contains("Padding")
            )
        }
    }

    @Test
    fun testEncryptAndDecryptWithDerivedKey() {
        val masterPassword = "TestKeyWrapping123!".toCharArray()
        val salt = VaultCrypto.generateSalt()
        val aesKey = VaultCrypto.deriveKey(masterPassword, salt, iterations = 5000)

        val plaintext = "Testing direct AES key decryption"
        val payload = VaultCrypto.encryptWithKey(plaintext, aesKey, salt)
        val decrypted = VaultCrypto.decryptWithKey(payload, aesKey)

        assertEquals(plaintext, decrypted)
    }
}
