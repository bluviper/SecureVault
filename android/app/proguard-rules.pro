# SecureVault ProGuard & R8 Hardening Rules

# Keep JavascriptInterface annotations and bridge methods intact
-keepattributes JavascriptInterface
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}

-keep class com.bluviper.securevault.bridge.AndroidVaultBridge {
    <methods>;
}

# Keep crypto models if needed
-keepclassmembers class com.bluviper.securevault.crypto.** {
    public *;
}
