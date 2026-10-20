package com.bluviper.securevault.autofill

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.service.autofill.Dataset
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import com.bluviper.securevault.R
import com.bluviper.securevault.crypto.KeystoreHelper
import com.bluviper.securevault.crypto.VaultCrypto
import com.bluviper.securevault.crypto.VaultPayload
import java.io.File
import java.nio.charset.StandardCharsets

/**
 * Invisible/translucent activity displayed to authenticate the user via Biometrics
 * when an Autofill dataset requires unlocking.
 */
class AutofillAuthActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val usernameId = intent.getParcelableExtra<AutofillId>("extra_username_id")
        val passwordId = intent.getParcelableExtra<AutofillId>("extra_password_id")
        val packageName = intent.getStringExtra("extra_package_name")
        val webDomain = intent.getStringExtra("extra_web_domain")

        if (!KeystoreHelper.hasBiometricKey(this)) {
            Toast.makeText(this, "Please open SecureVault and enroll fingerprint unlock", Toast.LENGTH_LONG).show()
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }

        val decryptCipher = KeystoreHelper.initBiometricDecryptCipher(this)
        if (decryptCipher == null) {
            setResult(Activity.RESULT_CANCELED)
            finish()
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
                        setResult(Activity.RESULT_CANCELED)
                        finish()
                        return
                    }

                    try {
                        val rawKeyBytes = KeystoreHelper.unwrapMasterKey(this@AutofillAuthActivity, cipher)
                            ?: throw IllegalStateException("Failed to unwrap key")

                        val vaultFile = File(filesDir, "vault.json")
                        val jsonStr = vaultFile.readText(StandardCharsets.UTF_8)
                        val payload = VaultPayload.fromJson(jsonStr)

                        val aesKey = javax.crypto.spec.SecretKeySpec(rawKeyBytes, "AES")
                        val decryptedPlaintext = VaultCrypto.decryptWithKey(payload, aesKey)

                        VaultMemoryCache.setFromPlaintextJson(decryptedPlaintext)
                        val matches = VaultMemoryCache.findMatches(packageName, webDomain)

                        if (matches.isNotEmpty()) {
                            val cred = matches.first()
                            val datasetBuilder = Dataset.Builder()

                            val presentation = RemoteViews(packageName, R.layout.autofill_dataset_item).apply {
                                setTextViewText(R.id.autofill_title, cred.service.ifEmpty { "Login" })
                                setTextViewText(R.id.autofill_subtitle, cred.user)
                            }

                            if (usernameId != null && cred.user.isNotEmpty()) {
                                datasetBuilder.setValue(usernameId, AutofillValue.forText(cred.user), presentation)
                            }
                            if (passwordId != null && cred.pass.isNotEmpty()) {
                                datasetBuilder.setValue(passwordId, AutofillValue.forText(cred.pass), presentation)
                            }

                            val resultIntent = Intent().apply {
                                putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, datasetBuilder.build())
                            }
                            setResult(Activity.RESULT_OK, resultIntent)
                        } else {
                            setResult(Activity.RESULT_CANCELED)
                        }
                    } catch (e: Exception) {
                        e.printStackTrace()
                        setResult(Activity.RESULT_CANCELED)
                    }
                    finish()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    setResult(Activity.RESULT_CANCELED)
                    finish()
                }
            }
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.biometric_prompt_title))
            .setSubtitle("Confirm fingerprint to autofill credentials")
            .setNegativeButtonText("Cancel")
            .build()

        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(decryptCipher))
    }
}
