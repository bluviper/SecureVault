package com.bluviper.securevault.credentials

import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.service.credentials.BeginCreateCredentialRequest
import android.service.credentials.BeginCreateCredentialResponse
import android.service.credentials.BeginGetCredentialRequest
import android.service.credentials.BeginGetCredentialResponse
import android.service.credentials.ClearCredentialStateRequest
import android.service.credentials.CredentialProviderService
import androidx.annotation.RequiresApi

/**
 * Android 14+ (API 34+) Credential Provider Service.
 * Registers SecureVault with Android 14's unified Credential Manager so it appears
 * directly in Settings > Passwords & accounts alongside other credential managers.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class VaultCredentialProviderService : CredentialProviderService() {

    override fun onBeginGetCredential(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, android.credentials.GetCredentialException>
    ) {
        val response = BeginGetCredentialResponse.Builder().build()
        callback.onResult(response)
    }

    override fun onBeginCreateCredential(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, android.credentials.CreateCredentialException>
    ) {
        val response = BeginCreateCredentialResponse.Builder().build()
        callback.onResult(response)
    }

    override fun onClearCredentialState(
        request: ClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, android.credentials.ClearCredentialStateException>
    ) {
        callback.onResult(null)
    }
}
