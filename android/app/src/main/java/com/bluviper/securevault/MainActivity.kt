package com.bluviper.securevault

import android.annotation.SuppressLint
import android.os.Bundle
import android.view.WindowManager
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import com.bluviper.securevault.bridge.AndroidVaultBridge
import com.bluviper.securevault.crypto.KeystoreHelper
import com.bluviper.securevault.crypto.VaultCrypto
import com.bluviper.securevault.crypto.VaultPayload
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.charset.StandardCharsets

class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView
    private val scope = CoroutineScope(Dispatchers.Main)

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Security baseline: prevent screenshots and recents snapshot previews
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        webView = WebView(this).apply {
            settings.apply {
                javaScriptEnabled = true
                domStorageEnabled = true
                allowFileAccess = false
                allowContentAccess = false
                mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
                cacheMode = WebSettings.LOAD_DEFAULT
            }
            webViewClient = object : WebViewClient() {
                // Keep local navigation sandboxed within the asset bundle
            }
        }

        setContentView(webView)

        val bridge = AndroidVaultBridge(this, webView)
        webView.addJavascriptInterface(bridge, "AndroidVaultBridge")

        // Load the offline single-file package from assets
        webView.loadUrl("file:///android_asset/index.html")

        // Handle native back press inside the WebView if possible
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (webView.canGoBack()) {
                    webView.goBack()
                } else {
                    finish()
                }
            }
        })
    }

    /**
     * Enrolls biometric unlock: derives AES key from master password and wraps it
     * via hardware Keystore inside BiometricPrompt.CryptoObject.
     */
    fun enrollBiometric(masterPassword: String, onResult: (Boolean, String?) -> Unit) {
        val vaultFile = File(filesDir, "vault.json")
        if (!vaultFile.exists()) {
            onResult(false, "Vault file not found. Save vault before enabling biometrics.")
            return
        }

        scope.launch(Dispatchers.IO) {
            try {
                val jsonStr = vaultFile.readText(StandardCharsets.UTF_8)
                val payload = VaultPayload.fromJson(jsonStr)
                val salt = java.util.Base64.getDecoder().decode(payload.saltBase64)
                val derivedKey = VaultCrypto.deriveKey(masterPassword.toCharArray(), salt)

                val encryptCipher = KeystoreHelper.initBiometricEncryptCipher()
                val cryptoObject = BiometricPrompt.CryptoObject(encryptCipher)

                withContext(Dispatchers.Main) {
                    val executor = ContextCompat.getMainExecutor(this@MainActivity)
                    val prompt = BiometricPrompt(
                        this@MainActivity,
                        executor,
                        object : BiometricPrompt.AuthenticationCallback() {
                            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                val authenticatedCipher = result.cryptoObject?.cipher
                                if (authenticatedCipher == null) {
                                    onResult(false, "Cipher not available")
                                    return
                                }
                                val saved = KeystoreHelper.saveWrappedMasterKey(
                                    this@MainActivity,
                                    authenticatedCipher,
                                    derivedKey.encoded
                                )
                                onResult(saved, if (saved) null else "Failed to save wrapped key")
                            }

                            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                                onResult(false, errString.toString())
                            }
                        }
                    )

                    val promptInfo = BiometricPrompt.PromptInfo.Builder()
                        .setTitle(getString(R.string.biometric_prompt_title))
                        .setSubtitle(getString(R.string.biometric_prompt_subtitle))
                        .setNegativeButtonText(getString(R.string.biometric_prompt_cancel))
                        .build()

                    prompt.authenticate(promptInfo, cryptoObject)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    onResult(false, e.localizedMessage ?: "Failed to initialize biometric enrollment")
                }
            }
        }
    }

    /**
     * Unlocks vault using biometric authentication: unwraps AES key and decrypts
     * vault directly to JSON string without typing master password.
     */
    fun unlockWithBiometric(onResult: (Boolean, String?, String?) -> Unit) {
        val decryptCipher = KeystoreHelper.initBiometricDecryptCipher(this)
        if (decryptCipher == null) {
            onResult(false, null, "Biometric key not found or expired")
            return
        }

        val executor = ContextCompat.getMainExecutor(this)
        val prompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val cipher = result.cryptoObject?.cipher
                    if (cipher == null) {
                        onResult(false, null, "Biometric cipher error")
                        return
                    }

                    scope.launch(Dispatchers.IO) {
                        try {
                            val rawKeyBytes = KeystoreHelper.unwrapMasterKey(this@MainActivity, cipher)
                                ?: throw IllegalStateException("Failed to unwrap AES key")

                            val vaultFile = File(filesDir, "vault.json")
                            val jsonStr = vaultFile.readText(StandardCharsets.UTF_8)
                            val payload = VaultPayload.fromJson(jsonStr)

                            val aesKey = javax.crypto.spec.SecretKeySpec(rawKeyBytes, "AES")
                            val decryptedPlaintext = VaultCrypto.decryptWithKey(payload, aesKey)

                            withContext(Dispatchers.Main) {
                                onResult(true, decryptedPlaintext, null)
                            }
                        } catch (e: Exception) {
                            withContext(Dispatchers.Main) {
                                onResult(false, null, e.localizedMessage ?: "Decryption failed")
                            }
                        }
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onResult(false, null, errString.toString())
                }
            }
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.biometric_prompt_title))
            .setSubtitle(getString(R.string.biometric_prompt_subtitle))
            .setNegativeButtonText(getString(R.string.biometric_prompt_cancel))
            .build()

        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(decryptCipher))
    }
}
