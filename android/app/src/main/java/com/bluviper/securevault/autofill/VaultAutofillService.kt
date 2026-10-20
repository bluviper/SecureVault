package com.bluviper.securevault.autofill

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import com.bluviper.securevault.R
import com.bluviper.securevault.crypto.KeystoreHelper

/**
 * System-wide Autofill service for SecureVault.
 * Provides credentials into foreground apps and browsers directly from the native .vault engine.
 */
class VaultAutofillService : AutofillService() {

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        val contexts = request.fillContexts
        if (contexts.isEmpty()) {
            callback.onSuccess(null)
            return
        }

        val structure = contexts.last().structure
        val parsed = AutofillStructureParser.parse(structure)

        if (parsed.usernameId == null && parsed.passwordId == null) {
            callback.onSuccess(null)
            return
        }

        val responseBuilder = FillResponse.Builder()

        if (VaultMemoryCache.isUnlocked()) {
            val matches = VaultMemoryCache.findMatches(parsed.packageName, parsed.webDomain)
            if (matches.isEmpty()) {
                callback.onSuccess(null)
                return
            }

            for (cred in matches) {
                val datasetBuilder = Dataset.Builder()
                val presentation = RemoteViews(packageName, R.layout.autofill_dataset_item).apply {
                    setTextViewText(R.id.autofill_title, cred.service.ifEmpty { "Login" })
                    setTextViewText(R.id.autofill_subtitle, cred.user)
                }

                if (parsed.usernameId != null && cred.user.isNotEmpty()) {
                    datasetBuilder.setValue(parsed.usernameId, AutofillValue.forText(cred.user), presentation)
                }
                if (parsed.passwordId != null && cred.pass.isNotEmpty()) {
                    datasetBuilder.setValue(parsed.passwordId, AutofillValue.forText(cred.pass), presentation)
                }

                responseBuilder.addDataset(datasetBuilder.build())
            }

            // Allow saving newly entered credentials
            val requiredIds = listOfNotNull(parsed.usernameId, parsed.passwordId).toTypedArray()
            if (requiredIds.isNotEmpty()) {
                val saveInfo = SaveInfo.Builder(
                    SaveInfo.SAVE_DATA_TYPE_PASSWORD or SaveInfo.SAVE_DATA_TYPE_USERNAME,
                    requiredIds
                ).build()
                responseBuilder.setSaveInfo(saveInfo)
            }

            callback.onSuccess(responseBuilder.build())
        } else if (KeystoreHelper.hasBiometricKey(this)) {
            // Vault is locked: provide biometric authentication prompt
            val authIntent = Intent(this, AutofillAuthActivity::class.java).apply {
                putExtra("extra_username_id", parsed.usernameId)
                putExtra("extra_password_id", parsed.passwordId)
                putExtra("extra_package_name", parsed.packageName)
                putExtra("extra_web_domain", parsed.webDomain)
            }

            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE
            } else {
                PendingIntent.FLAG_CANCEL_CURRENT
            }

            val pendingIntent = PendingIntent.getActivity(
                this,
                1001,
                authIntent,
                flags
            )

            val authPresentation = RemoteViews(packageName, R.layout.autofill_auth_item)
            val authIds = listOfNotNull(parsed.usernameId, parsed.passwordId).toTypedArray()

            responseBuilder.setAuthentication(
                authIds,
                pendingIntent.intentSender,
                authPresentation
            )

            callback.onSuccess(responseBuilder.build())
        } else {
            // Locked and no biometrics enrolled yet
            callback.onSuccess(null)
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // Save request acknowledged; user saving is managed via the app UI
        callback.onSuccess()
    }
}
