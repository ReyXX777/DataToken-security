// Store the token and sensitive data
let tokenVault = [];
let auditLogs = [];

// Tokenization function
function tokenizeData(sensitiveData) {
    // Generate a simple token (in practice, use a more complex algorithm)
    let token = Math.random().toString(36).substring(2, 12);
    tokenVault.push({ sensitiveData, token });
    
    // Log tokenization activity
    auditLogs.push(`Tokenized: ${sensitiveData} -> ${token}`);

    return token;
}

// Show token in the UI
document.getElementById('tokenize-btn').addEventListener('click', function() {
    let sensitiveData = document.getElementById('sensitive-data').value;
    if (sensitiveData) {
        let token = tokenizeData(sensitiveData);
        document.getElementById('token-value').innerText = token;
        document.getElementById('sensitive-data').value = ''; // Clear input field
    }
});

// Vault Lightbox logic
document.getElementById('view-vault-btn').addEventListener('click', function() {
    let vaultList = document.getElementById('vault-list');
    vaultList.innerHTML = ''; // Clear existing list
    tokenVault.forEach(item => {
        let li = document.createElement('li');
        li.innerText = `Sensitive Data: ${item.sensitiveData}, Token: ${item.token}`;
        vaultList.appendChild(li);
    });
    document.getElementById('vault-lightbox').style.display = 'flex';
});

// Logs Lightbox logic
document.getElementById('view-logs-btn').addEventListener('click', function() {
    let logsList = document.getElementById('logs-list');
    logsList.innerHTML = ''; // Clear existing list
    auditLogs.forEach(log => {
        let li = document.createElement('li');
        li.innerText = log;
        logsList.appendChild(li);
    });
    document.getElementById('logs-lightbox').style.display = 'flex';
});

// Close lightboxes
document.querySelectorAll('.close').forEach(closeBtn => {
    closeBtn.addEventListener('click', function() {
        this.parentElement.parentElement.style.display = 'none';
    });
});
