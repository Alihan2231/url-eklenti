// ViorsLinkScan - URL Security Scanner Extension

// Global variables
let currentView = 'scanner-view';
let scanHistory = [];
let currentResult = null;
let threatTypes = [
    "MALWARE", 
    "SOCIAL_ENGINEERING", 
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION"
];
let apiKey = '';

// Initialize when document is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Load settings from storage
    loadSettings();
    
    // Initialize scan form
    initScanForm();
    
    // Initialize UI buttons
    initButtons();
    
    // Check if there's a URL in the active tab
    getCurrentTabUrl();
});

// Initialize scan form
function initScanForm() {
    document.getElementById('url-scan-form').addEventListener('submit', function(e) {
        e.preventDefault();
        
        const urlInput = document.getElementById('url-input');
        let url = urlInput.value.trim();
        
        if (url === '') {
            showToast('Hata', 'Lütfen bir URL giriniz.', 'error');
            return false;
        }
        
        // Add protocol if missing
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'http://' + url;
            urlInput.value = url;
        }
        
        scanUrl(url);
    });
    
    // Scan current tab button
    document.getElementById('scan-current-button').addEventListener('click', function() {
        getCurrentTabUrl(true);
    });
}

// Initialize UI buttons
function initButtons() {
    // Show history button
    document.getElementById('show-history').addEventListener('click', function() {
        showView('history-view');
        loadHistory();
    });
    
    // Back from history button
    document.getElementById('back-from-history').addEventListener('click', function() {
        showView('scanner-view');
    });
    
    // Show settings button
    document.getElementById('show-settings').addEventListener('click', function() {
        showView('settings-view');
    });
    
    // Back from settings button
    document.getElementById('back-from-settings').addEventListener('click', function() {
        showView('scanner-view');
    });
    
    // Settings form submit
    document.getElementById('settings-form').addEventListener('submit', function(e) {
        e.preventDefault();
        saveSettings();
    });
    
    // Back to scan button
    document.getElementById('back-to-scan').addEventListener('click', function() {
        showView('scanner-view');
    });
    
    // Copy result button
    document.getElementById('copy-result').addEventListener('click', function() {
        copyResult();
    });
}

// Switch view
function showView(viewId) {
    // Hide all views
    document.querySelectorAll('.view').forEach(view => {
        view.classList.remove('active');
    });
    
    // Show requested view
    document.getElementById(viewId).classList.add('active');
    currentView = viewId;
}

// Get current tab URL
function getCurrentTabUrl(scanImmediate = false) {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        const currentTab = tabs[0];
        if (currentTab && currentTab.url) {
            const url = currentTab.url;
            document.getElementById('url-input').value = url;
            
            if (scanImmediate) {
                scanUrl(url);
            }
        }
    });
}

// Scan URL for threats
function scanUrl(url) {
    // Check if API key is set
    if (!apiKey) {
        showToast('API Anahtarı Gerekli', 'Lütfen ayarlardan Google Safe Browsing API anahtarınızı ekleyin.', 'error');
        showView('settings-view');
        return;
    }
    
    // Show spinner
    document.getElementById('spinner').style.display = 'block';
    document.getElementById('scan-button').disabled = true;
    document.getElementById('scan-current-button').disabled = true;
    
    // Check if URL is in history and less than 24h old
    const cachedResult = checkUrlInHistory(url);
    if (cachedResult) {
        showResult(cachedResult);
        return;
    }
    
    // Get selected threat types
    const selectedThreats = [];
    if (document.getElementById('check-malware').checked) selectedThreats.push("MALWARE");
    if (document.getElementById('check-phishing').checked) selectedThreats.push("SOCIAL_ENGINEERING");
    if (document.getElementById('check-unwanted').checked) selectedThreats.push("UNWANTED_SOFTWARE");
    if (document.getElementById('check-harmful').checked) selectedThreats.push("POTENTIALLY_HARMFUL_APPLICATION");
    
    // If no threats selected, use all
    if (selectedThreats.length === 0) {
        selectedThreats.push(...threatTypes);
    }
    
    // Prepare request payload
    const payload = {
        client: {
            clientId: "viorslink-scan-extension",
            clientVersion: "1.0.0"
        },
        threatInfo: {
            threatTypes: selectedThreats,
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{"url": url}]
        }
    };
    
    // Make API request
    fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
        method: 'POST',
        body: JSON.stringify(payload),
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`API hatası: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        // Process API response
        const isSafe = !data.matches || data.matches.length === 0;
        const threats = [];
        
        if (!isSafe && data.matches) {
            data.matches.forEach(match => {
                if (match.threatType) {
                    threats.push(match.threatType);
                }
            });
        }
        
        // Create result object
        const scanResult = {
            id: generateId(),
            url: url,
            is_safe: isSafe,
            threat_types: threats,
            timestamp: new Date().toISOString(),
            raw_result: data
        };
        
        // Save to history
        saveToHistory(scanResult);
        
        // Show result
        showResult(scanResult);
    })
    .catch(error => {
        console.error('Error checking URL:', error);
        showToast('Hata', `URL kontrol edilemedi: ${error.message}`, 'error');
        
        // Hide spinner
        document.getElementById('spinner').style.display = 'none';
        document.getElementById('scan-button').disabled = false;
        document.getElementById('scan-current-button').disabled = false;
    });
}

// Show scan result
function showResult(result) {
    // Hide spinner
    document.getElementById('spinner').style.display = 'none';
    document.getElementById('scan-button').disabled = false;
    document.getElementById('scan-current-button').disabled = false;
    
    // Save current result
    currentResult = result;
    
    // Update result view
    const iconContainer = document.getElementById('result-icon-container');
    const statusBadge = document.getElementById('result-status-badge');
    const resultTitle = document.getElementById('result-title');
    const urlDisplay = document.getElementById('scanned-url');
    const threatContainer = document.getElementById('threat-container');
    
    // Clear previous content
    iconContainer.innerHTML = '';
    statusBadge.innerHTML = '';
    threatContainer.innerHTML = '';
    threatContainer.style.display = 'none';
    
    // Set icon and badge based on result
    if (result.is_safe) {
        iconContainer.innerHTML = '<i class="fas fa-shield-alt text-safe" style="font-size: 4rem;"></i>';
        statusBadge.innerHTML = '<span class="badge bg-success p-2 fs-6 rounded-pill">GÜVENLİ</span>';
        resultTitle.innerHTML = '<span class="text-safe fw-bold">URL GÜVENLİ</span>';
    } else {
        iconContainer.innerHTML = '<i class="fas fa-exclamation-triangle text-threat" style="font-size: 4rem;"></i>';
        statusBadge.innerHTML = '<span class="badge bg-danger p-2 fs-6 rounded-pill">TEHLİKELİ</span>';
        resultTitle.innerHTML = '<span class="text-threat fw-bold">TEHLİKELİ URL TESPİT EDİLDİ!</span>';
        
        // Show threats
        if (result.threat_types.length > 0) {
            threatContainer.style.display = 'block';
            threatContainer.innerHTML = '<h5 class="text-threat mb-3"><i class="fas fa-virus me-2"></i>Tespit Edilen Tehditler</h5>';
            
            result.threat_types.forEach(threat => {
                let icon = 'question-circle';
                let description = 'Bilinmeyen tehdit türü';
                
                // Set icon and description based on threat type
                if (threat === "MALWARE") {
                    icon = 'bug';
                    description = 'Kötü amaçlı yazılım - bilgisayarınıza zarar verebilir veya bilgilerinizi çalabilir.';
                } else if (threat === "SOCIAL_ENGINEERING") {
                    icon = 'user-ninja';
                    description = 'Sosyal mühendislik (phishing) - kişisel bilgilerinizi çalmaya çalışan sahte site.';
                } else if (threat === "UNWANTED_SOFTWARE") {
                    icon = 'puzzle-piece';
                    description = 'İstenmeyen yazılım - bilgisayarınıza istenmeyen yazılım yükleyebilir.';
                } else if (threat === "POTENTIALLY_HARMFUL_APPLICATION") {
                    icon = 'radiation';
                    description = 'Potansiyel olarak zararlı uygulama - cihazınıza zarar verebilir.';
                }
                
                // Create threat item
                const threatItem = document.createElement('div');
                threatItem.className = 'threat-item';
                threatItem.innerHTML = `
                    <div class="threat-icon">
                        <i class="fas fa-${icon}"></i>
                    </div>
                    <div class="threat-content">
                        <h5>${threat}</h5>
                        <p>${description}</p>
                    </div>
                `;
                
                threatContainer.appendChild(threatItem);
            });
        }
    }
    
    // Set URL
    urlDisplay.textContent = result.url;
    
    // Show result view
    showView('result-view');
}

// Generate unique ID
function generateId() {
    return 'xxxx-xxxx-xxxx-xxxx'.replace(/x/g, function() {
        return Math.floor(Math.random() * 16).toString(16);
    });
}

// Check if URL is in history
function checkUrlInHistory(url) {
    loadHistory();
    
    if (!scanHistory || scanHistory.length === 0) {
        return null;
    }
    
    // Look for recent URL scan in history
    for (const scan of scanHistory) {
        if (scan.url === url) {
            // Check if less than 24h old
            const scanDate = new Date(scan.timestamp);
            const now = new Date();
            const diffHours = (now - scanDate) / (1000 * 60 * 60);
            
            if (diffHours < 24) {
                return scan;
            }
        }
    }
    
    return null;
}

// Save scan to history
function saveToHistory(scan) {
    loadHistory();
    
    // Add to history
    scanHistory.unshift(scan);
    
    // Limit history to 100 items
    if (scanHistory.length > 100) {
        scanHistory = scanHistory.slice(0, 100);
    }
    
    // Save to storage
    chrome.storage.local.set({scanHistory: scanHistory}, function() {
        console.log('Scan saved to history');
    });
}

// Load history from storage
function loadHistory() {
    // First, try to load from memory
    if (scanHistory && scanHistory.length > 0) {
        displayHistory();
        return;
    }
    
    // Otherwise, load from storage
    chrome.storage.local.get('scanHistory', function(data) {
        if (data.scanHistory) {
            scanHistory = data.scanHistory;
        } else {
            scanHistory = [];
        }
        
        displayHistory();
    });
}

// Display history
function displayHistory() {
    const historyList = document.getElementById('history-list');
    const noHistory = document.getElementById('no-history');
    
    // Clear previous content
    historyList.innerHTML = '';
    
    // Show/hide no history message
    if (!scanHistory || scanHistory.length === 0) {
        noHistory.style.display = 'block';
        initHistoryChart(0, 0);
        return;
    } else {
        noHistory.style.display = 'none';
    }
    
    // Count stats for chart
    let safeCount = 0;
    let unsafeCount = 0;
    
    // Populate history list
    scanHistory.forEach(scan => {
        // Update stats
        if (scan.is_safe) {
            safeCount++;
        } else {
            unsafeCount++;
        }
        
        // Create history item
        const item = document.createElement('div');
        item.className = 'history-item';
        
        // Format date
        const scanDate = new Date(scan.timestamp);
        const formattedDate = scanDate.toLocaleDateString() + ' ' + scanDate.toLocaleTimeString();
        
        // Create HTML content
        item.innerHTML = `
            <div class="d-flex justify-content-between align-items-center mb-2">
                <div class="url-truncate" style="max-width: 250px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-size: 0.85rem;">
                    ${scan.url}
                </div>
                <div>
                    ${scan.is_safe 
                        ? '<span class="badge rounded-pill bg-success"><i class="fas fa-shield-alt me-1"></i>GÜVENLİ</span>' 
                        : '<span class="badge rounded-pill bg-danger"><i class="fas fa-exclamation-triangle me-1"></i>TEHLİKELİ</span>'}
                </div>
            </div>
            <div class="d-flex justify-content-between align-items-center">
                <small class="text-muted">${formattedDate}</small>
                <div>
                    <button class="btn btn-sm btn-outline-light me-1" data-url="${scan.url}" title="URL'yi Kopyala">
                        <i class="fas fa-copy"></i>
                    </button>
                    <button class="btn btn-sm btn-scanner rescan-btn" data-url="${scan.url}" title="Yeniden Tara">
                        <i class="fas fa-search"></i>
                    </button>
                </div>
            </div>
        `;
        
        // Add to list
        historyList.appendChild(item);
        
        // Add event listeners
        item.querySelector('[title="URL\'yi Kopyala"]').addEventListener('click', function() {
            copyToClipboard(this.getAttribute('data-url'));
            showToast('Kopyalandı', 'URL panoya kopyalandı.');
        });
        
        item.querySelector('.rescan-btn').addEventListener('click', function() {
            document.getElementById('url-input').value = this.getAttribute('data-url');
            showView('scanner-view');
            scanUrl(this.getAttribute('data-url'));
        });
    });
    
    // Initialize chart
    initHistoryChart(safeCount, unsafeCount);
}

// Initialize history chart
function initHistoryChart(safeCount, unsafeCount) {
    const chartCanvas = document.getElementById('history-chart');
    
    // Clear previous chart
    if (window.historyChart) {
        window.historyChart.destroy();
    }
    
    // Create new chart
    window.historyChart = new Chart(chartCanvas, {
        type: 'doughnut',
        data: {
            labels: ['Güvenli URL\'ler', 'Tehlikeli URL\'ler'],
            datasets: [{
                data: [safeCount, unsafeCount],
                backgroundColor: ['#4CAF50', '#ef3340'],
                borderColor: ['#43A047', '#d12130'],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        font: {
                            family: "'Poppins', sans-serif",
                            size: 11,
                            weight: 500
                        },
                        color: '#f5f5f5'
                    }
                },
                title: {
                    display: false
                }
            }
        }
    });
}

// Save settings
function saveSettings() {
    // Get values
    apiKey = document.getElementById('api-key').value.trim();
    
    // Threat types
    const malware = document.getElementById('check-malware').checked;
    const phishing = document.getElementById('check-phishing').checked;
    const unwanted = document.getElementById('check-unwanted').checked;
    const harmful = document.getElementById('check-harmful').checked;
    
    // Save to storage
    chrome.storage.local.set({
        apiKey: apiKey,
        threatSettings: {
            malware: malware,
            phishing: phishing,
            unwanted: unwanted,
            harmful: harmful
        }
    }, function() {
        showToast('Başarılı', 'Ayarlar kaydedildi.');
        showView('scanner-view');
    });
}

// Load settings
function loadSettings() {
    chrome.storage.local.get(['apiKey', 'threatSettings'], function(data) {
        if (data.apiKey) {
            apiKey = data.apiKey;
            document.getElementById('api-key').value = apiKey;
        }
        
        if (data.threatSettings) {
            document.getElementById('check-malware').checked = data.threatSettings.malware !== false;
            document.getElementById('check-phishing').checked = data.threatSettings.phishing !== false;
            document.getElementById('check-unwanted').checked = data.threatSettings.unwanted !== false;
            document.getElementById('check-harmful').checked = data.threatSettings.harmful !== false;
        }
    });
}

// Copy result to clipboard
function copyResult() {
    if (!currentResult) return;
    
    const url = currentResult.url;
    const status = currentResult.is_safe ? 'Güvenli' : 'Tehlikeli';
    const threats = currentResult.threat_types.length > 0 
        ? currentResult.threat_types.join(', ') 
        : 'Yok';
    const timestamp = new Date(currentResult.timestamp).toLocaleString();
    
    const reportText = `ViorsLinkScan URL GÜVENLİK TARAMA RAPORU\n` +
                     `-----------------------------------\n` +
                     `URL: ${url}\n` +
                     `Durum: ${status}\n` +
                     `Tehditler: ${threats}\n` +
                     `Tarih: ${timestamp}\n` +
                     `ViorsLinkScan ile kontrol edildi.`;
    
    copyToClipboard(reportText);
    showToast('Kopyalandı', 'Rapor panoya kopyalandı.');
}

// Copy text to clipboard
function copyToClipboard(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
}

// Show toast message
function showToast(title, message, type = 'success') {
    const toastEl = document.getElementById('toast');
    const titleEl = document.getElementById('toast-title');
    const messageEl = document.getElementById('toast-message');
    
    // Set content
    titleEl.textContent = title;
    messageEl.textContent = message;
    
    // Set type
    if (type === 'error') {
        titleEl.previousElementSibling.className = 'fas fa-exclamation-circle text-danger me-2';
    } else {
        titleEl.previousElementSibling.className = 'fas fa-check-circle text-success me-2';
    }
    
    // Show toast
    const toast = new bootstrap.Toast(toastEl);
    toast.show();
}
