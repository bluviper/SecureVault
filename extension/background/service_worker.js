// SecureVault Extension Background Service Worker (Manifest V3)

let sessionKey = null;
let sessionVaultData = null;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'STORE_SESSION') {
        sessionVaultData = message.vaultData;
        sendResponse({ success: true });
    } else if (message.type === 'GET_SESSION') {
        sendResponse({ vaultData: sessionVaultData });
    } else if (message.type === 'CLEAR_SESSION') {
        sessionVaultData = null;
        sendResponse({ success: true });
    } else if (message.type === 'AUTOFILL_PAGE') {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0] && tabs[0].id) {
                chrome.tabs.sendMessage(tabs[0].id, {
                    type: 'FILL_CREDENTIALS',
                    username: message.username,
                    password: message.password
                }).catch(err => {
                    console.log("Could not autofill tab:", err);
                });
            }
        });
        sendResponse({ success: true });
    }
    return true;
});
