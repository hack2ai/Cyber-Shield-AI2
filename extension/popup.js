// Cyber Shield AI browser investigation companion. Keep browser input untrusted.
let currentTabUrl = '';
let latestResult = null;

const $ = (id) => document.getElementById(id);

function normalizeApiUrl(value) {
    const raw = String(value || '').trim();
    if (!raw) return null;
    try {
        const parsed = new URL(raw);
        if (parsed.protocol !== 'https:') return null;
        if (parsed.username || parsed.password) return null;
        parsed.pathname = parsed.pathname.replace(/\/+$/, '');
        parsed.search = '';
        parsed.hash = '';
        return parsed.toString().replace(/\/$/, '');
    } catch {
        return null;
    }
}

function classifyTarget(url) {
    if (!url) return 'Unknown';
    try {
        const parsed = new URL(url);
        if (parsed.protocol === 'http:' || parsed.protocol === 'https:') return 'URL / Domain';
        return parsed.protocol.replace(':', '').toUpperCase();
    } catch {
        return 'Indicator';
    }
}

function normalizeResult(data) {
    const rawScore = Number(data?.threatScore);
    const score = Number.isFinite(rawScore) ? Math.max(0, Math.min(100, Math.round(rawScore))) : 0;
    let classification = typeof data?.classification === 'string' ? data.classification.trim() : '';
    const valid = ['Safe', 'Suspicious', 'Phishing', 'Malicious'];
    if (!valid.includes(classification)) {
        classification = score >= 80 ? 'Malicious' : score >= 60 ? 'Phishing' : score >= 35 ? 'Suspicious' : 'Safe';
    }
    return { ...data, threatScore: score, classification };
}

function showError(message) {
    $('error-banner').textContent = String(message).slice(0, 400);
    $('error-banner').classList.remove('hidden');
}

function setScanning(active) {
    const button = $('scan-btn');
    button.disabled = active;
    button.querySelector('.btn-text').textContent = active ? 'Analyzing indicator…' : 'Analyze current page';
    $('engine-state').textContent = active ? 'Engine: running' : 'Engine: ready';
    if (active) $('results-panel').classList.add('hidden');
}

async function getStoredApiUrl() {
    const stored = await chrome.storage.local.get(['apiUrl']);
    return normalizeApiUrl(stored.apiUrl);
}

document.addEventListener('DOMContentLoaded', async () => {
    const apiUrlInput = $('api-url');
    const stored = await chrome.storage.local.get(['apiUrl']);
    if (stored.apiUrl) apiUrlInput.value = stored.apiUrl;

    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab = tabs?.[0];
    currentTabUrl = tab?.url || '';
    $('current-url').textContent = currentTabUrl || 'Unable to read active tab URL';
    $('target-type').textContent = `Target: ${classifyTarget(currentTabUrl)}`;
    $('scan-btn').disabled = !/^https?:\/\//i.test(currentTabUrl);
    if (!currentTabUrl) showError('The active tab URL could not be read.');

    $('scan-btn').addEventListener('click', scanCurrentPage);

    $('toggle-settings').addEventListener('click', () => {
        const settingsVisible = !$('settings-view').classList.contains('hidden');
        $('settings-view').classList.toggle('hidden', settingsVisible);
        $('main-view').classList.toggle('hidden', !settingsVisible);
        $('toggle-settings').textContent = settingsVisible ? 'Configuration' : 'Back to analysis';
    });

    $('save-settings').addEventListener('click', async () => {
        const apiUrl = normalizeApiUrl(apiUrlInput.value);
        if (!apiUrl) {
            showError('API gateway must be a valid HTTPS origin without credentials, query strings, or fragments.');
            return;
        }
        await chrome.storage.local.set({ apiUrl });
        $('engine-state').textContent = 'Engine: configured';
        $('toggle-settings').click();
    });

    $('open-soc').addEventListener('click', async () => {
        const apiUrl = await getStoredApiUrl();
        if (!apiUrl) {
            showError('Configure the HTTPS SOC gateway URL first.');
            return;
        }
        const destination = `${apiUrl}/?indicator=${encodeURIComponent(currentTabUrl)}`;
        await chrome.tabs.create({ url: destination });
    });

    $('copy-target').addEventListener('click', async () => {
        try {
            await navigator.clipboard.writeText(currentTabUrl);
            $('copy-target').textContent = 'Copied';
            setTimeout(() => $('copy-target').textContent = 'Copy indicator', 1000);
        } catch {
            showError('Could not copy the indicator.');
        }
    });
});

async function scanCurrentPage() {
    const apiUrl = await getStoredApiUrl();
    if (!apiUrl) {
        showError('Configure a valid HTTPS API gateway before starting an investigation.');
        $('toggle-settings').click();
        return;
    }
    if (!/^https?:\/\//i.test(currentTabUrl)) {
        showError('Only normal HTTP(S) web pages can be analyzed from the extension.');
        return;
    }

    setScanning(true);
    try {
        const response = await fetch(`${apiUrl}/api/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: currentTabUrl })
        });
        const payload = await response.json().catch(() => null);
        if (!response.ok) throw new Error(payload?.error || `Analysis service returned ${response.status}`);
        latestResult = normalizeResult(payload);
        displayResults(latestResult);
    } catch (error) {
        console.error('Cyber Shield analysis failed', error);
        showError(`Analysis unavailable: ${error instanceof Error ? error.message : 'unknown service error'}`);
        setScanning(false);
    }
}

function displayResults(data) {
    setScanning(false);
    $('error-banner').classList.add('hidden');
    $('results-panel').classList.remove('hidden');

    const score = data.threatScore;
    const classification = data.classification;
    $('risk-score').textContent = score;
    $('classification-status').textContent = classification;
    $('confidence').textContent = data.riskModel?.confidence ? `${data.riskModel.confidence} confidence` : 'Normalized';
    $('indicator-count').textContent = Array.isArray(data.riskIndicators) ? data.riskIndicators.length : 0;

    const level = classification === 'Malicious' || classification === 'Phishing' || score >= 60 ? 'danger' : classification === 'Suspicious' || score >= 35 ? 'warning' : 'safe';
    $('risk-score').className = `score ${level}`;
    $('verdict').className = `verdict ${level}`;
    $('verdict').textContent = classification === 'Malicious' ? 'Malicious indicator' : classification === 'Phishing' ? 'Phishing risk' : classification === 'Suspicious' ? 'Suspicious indicator' : 'No high-confidence threat';
    $('classification-status').className = `value ${level}`;

    const heuristics = data?.raw?.heuristics || {};
    $('tld-status').textContent = heuristics.suspiciousTLD ? 'Flagged' : 'No signal';
    $('tld-status').className = `value ${heuristics.suspiciousTLD ? 'warning' : 'safe'}`;

    const ssl = data?.raw?.ssl;
    $('ssl-status').textContent = ssl?.authorized === undefined ? 'Unavailable' : ssl.authorized ? 'Trusted' : 'Untrusted';
    $('ssl-status').className = `value ${ssl?.authorized === undefined ? '' : ssl.authorized ? 'safe' : 'danger'}`;
    $('recommendation').textContent = data.recommendation || 'Review the full SOC assessment for additional evidence.';
    $('engine-state').textContent = 'Engine: complete';
}
