// SecureVault Content Script — Detects password fields & auto-fills credentials

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'FILL_CREDENTIALS') {
        const { username, password } = message;
        let filledUser = false;
        let filledPass = false;

        // 1. Find password inputs
        const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]'));
        
        passwordInputs.forEach(passInput => {
            if (password) {
                setValueWithEvents(passInput, password);
                filledPass = true;
            }

            // 2. Find associated username input in the same form or previous siblings
            if (username && !filledUser) {
                const form = passInput.closest('form');
                let userInput = null;

                if (form) {
                    userInput = form.querySelector('input[type="text"], input[type="email"], input[name*="user"], input[name*="email"], input[autocomplete="username"]');
                }
                
                if (!userInput) {
                    const allInputs = Array.from(document.querySelectorAll('input[type="text"], input[type="email"]'));
                    userInput = allInputs.find(inp => inp.name.toLowerCase().includes('user') || inp.name.toLowerCase().includes('email') || inp.placeholder.toLowerCase().includes('email') || inp.placeholder.toLowerCase().includes('user'));
                }

                if (userInput) {
                    setValueWithEvents(userInput, username);
                    filledUser = true;
                }
            }
        });

        sendResponse({ success: filledPass || filledUser });
    }
    return true;
});

/**
 * Sets input value and dispatches native React/Vue-compatible input & change events.
 */
function setValueWithEvents(element, value) {
    const valueSetter = Object.getOwnPropertyDescriptor(element, 'value')?.set ||
                        Object.getOwnPropertyDescriptor(Object.getPrototypeOf(element), 'value')?.set;
    
    if (valueSetter) {
        valueSetter.call(element, value);
    } else {
        element.value = value;
    }

    element.dispatchEvent(new Event('input', { bubbles: true }));
    element.dispatchEvent(new Event('change', { bubbles: true }));
    element.dispatchEvent(new Event('blur', { bubbles: true }));
}
