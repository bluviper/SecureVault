package com.bluviper.securevault

import com.bluviper.securevault.autofill.VaultMemoryCache
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class AutofillMatchingTest {

    private val sampleVaultJson = """
        [
            {
                "id": "1",
                "type": "login",
                "service": "GitHub",
                "user": "alice@github.com",
                "pass": "super-secret-123",
                "url": "https://github.com/login",
                "category": "Development"
            },
            {
                "id": "2",
                "type": "login",
                "service": "Spotify Music",
                "user": "alice_tunes",
                "pass": "music-pass-456",
                "url": "https://accounts.spotify.com",
                "category": "Entertainment"
            },
            {
                "id": "3",
                "type": "card",
                "service": "Visa Gold",
                "user": "Alice",
                "pass": "4111222233334444"
            }
        ]
    """.trimIndent()

    @Before
    fun setUp() {
        VaultMemoryCache.clear()
        VaultMemoryCache.setFromPlaintextJson(sampleVaultJson)
    }

    @Test
    fun testCredentialsParsingFiltersNonLogins() {
        val creds = VaultMemoryCache.getCredentials()
        assertNotNull(creds)
        // Login items only (excludes cards, identities, ssh from standard autofill)
        assertEquals(2, creds!!.size)
        assertEquals("GitHub", creds[0].service)
        assertEquals("Spotify Music", creds[1].service)
    }

    @Test
    fun testDomainMatching() {
        val matches = VaultMemoryCache.findMatches(null, "github.com")
        assertEquals(1, matches.size)
        assertEquals("GitHub", matches[0].service)
        assertEquals("alice@github.com", matches[0].user)
    }

    @Test
    fun testPackageNameMatching() {
        val matches = VaultMemoryCache.findMatches("com.spotify.music", null)
        assertEquals(1, matches.size)
        assertEquals("Spotify Music", matches[0].service)
        assertEquals("alice_tunes", matches[0].user)
    }

    @Test
    fun testSubdomainMatching() {
        val matches = VaultMemoryCache.findMatches(null, "accounts.spotify.com")
        assertEquals(1, matches.size)
        assertEquals("Spotify Music", matches[0].service)
    }

    @Test
    fun testClearWipesCredentials() {
        assertTrue(VaultMemoryCache.isUnlocked())
        VaultMemoryCache.clear()
        assertFalse(VaultMemoryCache.isUnlocked())
        assertEquals(null, VaultMemoryCache.getCredentials())
    }
}
