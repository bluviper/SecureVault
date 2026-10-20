package com.bluviper.securevault.autofill

import android.app.assist.AssistStructure
import android.os.Build
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId

/**
 * Parsed field information extracted from an Android AssistStructure.
 */
data class ParsedAutofillStructure(
    val packageName: String?,
    val webDomain: String?,
    val usernameId: AutofillId?,
    val passwordId: AutofillId?,
    val focusedId: AutofillId?
)

object AutofillStructureParser {

    /**
     * Traverses the AssistStructure view hierarchy to identify username and password fields.
     */
    fun parse(structure: AssistStructure): ParsedAutofillStructure {
        var webDomain: String? = null
        var usernameId: AutofillId? = null
        var passwordId: AutofillId? = null
        var focusedId: AutofillId? = null

        val nodeCount = structure.windowNodeCount
        for (i in 0 until nodeCount) {
            val windowNode = structure.getWindowNodeAt(i)
            val root = windowNode.rootViewNode

            val result = traverseNode(root)
            if (result.webDomain != null && webDomain == null) {
                webDomain = result.webDomain
            }
            if (result.usernameId != null && usernameId == null) {
                usernameId = result.usernameId
            }
            if (result.passwordId != null && passwordId == null) {
                passwordId = result.passwordId
            }
            if (result.focusedId != null && focusedId == null) {
                focusedId = result.focusedId
            }
        }

        val packageName = structure.activityComponent?.packageName

        return ParsedAutofillStructure(
            packageName = packageName,
            webDomain = webDomain,
            usernameId = usernameId,
            passwordId = passwordId,
            focusedId = focusedId
        )
    }

    private fun traverseNode(node: AssistStructure.ViewNode): ParsedAutofillStructure {
        var webDomain = node.webDomain
        var usernameId: AutofillId? = null
        var passwordId: AutofillId? = null
        var focusedId: AutofillId? = if (node.isFocused) node.autofillId else null

        if (isPasswordField(node)) {
            passwordId = node.autofillId
        } else if (isUsernameField(node)) {
            usernameId = node.autofillId
        }

        val childCount = node.childCount
        for (i in 0 until childCount) {
            val child = node.getChildAt(i)
            val childResult = traverseNode(child)

            if (childResult.webDomain != null && webDomain == null) {
                webDomain = childResult.webDomain
            }
            if (childResult.usernameId != null && usernameId == null) {
                usernameId = childResult.usernameId
            }
            if (childResult.passwordId != null && passwordId == null) {
                passwordId = childResult.passwordId
            }
            if (childResult.focusedId != null && focusedId == null) {
                focusedId = childResult.focusedId
            }
        }

        return ParsedAutofillStructure(
            packageName = null,
            webDomain = webDomain,
            usernameId = usernameId,
            passwordId = passwordId,
            focusedId = focusedId
        )
    }

    private fun isPasswordField(node: AssistStructure.ViewNode): Boolean {
        // 1. Check autofill hints
        val hints = node.autofillHints
        if (hints != null) {
            for (hint in hints) {
                if (hint.equals(View.AUTOFILL_HINT_PASSWORD, ignoreCase = true)) {
                    return true
                }
            }
        }

        // 2. Check input type
        val inputType = node.inputType
        val isPasswordType = (inputType and InputType.TYPE_MASK_CLASS) == InputType.TYPE_CLASS_TEXT &&
                ((inputType and InputType.TYPE_MASK_VARIATION) == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                 (inputType and InputType.TYPE_MASK_VARIATION) == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
                 (inputType and InputType.TYPE_MASK_VARIATION) == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)
        if (isPasswordType) return true

        // 3. Check view ID / hint heuristics
        val idEntry = node.idEntry?.lowercase() ?: ""
        val hintText = node.hint?.toString()?.lowercase() ?: ""
        return idEntry.contains("password") || idEntry.contains("passwd") || hintText.contains("password")
    }

    private fun isUsernameField(node: AssistStructure.ViewNode): Boolean {
        // 1. Check autofill hints
        val hints = node.autofillHints
        if (hints != null) {
            for (hint in hints) {
                if (hint.equals(View.AUTOFILL_HINT_USERNAME, ignoreCase = true) ||
                    hint.equals(View.AUTOFILL_HINT_EMAIL_ADDRESS, ignoreCase = true)) {
                    return true
                }
            }
        }

        // 2. Check input type
        val inputType = node.inputType
        val isEmailType = (inputType and InputType.TYPE_MASK_CLASS) == InputType.TYPE_CLASS_TEXT &&
                (inputType and InputType.TYPE_MASK_VARIATION) == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
        if (isEmailType) return true

        // 3. Check view ID / hint heuristics
        val idEntry = node.idEntry?.lowercase() ?: ""
        val hintText = node.hint?.toString()?.lowercase() ?: ""
        return idEntry.contains("username") || idEntry.contains("user") ||
               idEntry.contains("email") || idEntry.contains("login") ||
               hintText.contains("username") || hintText.contains("email")
    }
}
