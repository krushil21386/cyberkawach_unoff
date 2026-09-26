/**
 * Main application logic — wires the UI to the API.
 * Supports full website-wide language toggling in real-time.
 */

(function () {
    'use strict';

    // ─── DOM references ───
    const form = document.getElementById('analyze-form');
    const messageInput = document.getElementById('message-input');
    const inputType = document.getElementById('input-type');
    const userState = document.getElementById('user-state');
    const urlsInput = document.getElementById('urls-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const sampleBtn = document.getElementById('sample-btn');
    const samplesDropdown = document.getElementById('samples-dropdown');
    const samplesList = document.getElementById('samples-list');
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    const healthStatus = document.getElementById('health-status');

    // Result panels
    const riskBanner = document.getElementById('risk-banner');
    const riskCircle = document.getElementById('risk-circle');
    const riskScore = document.getElementById('risk-score');
    const riskLevel = document.getElementById('risk-level');
    const riskCategory = document.getElementById('risk-category');
    const riskMeta = document.getElementById('risk-meta');
    const explanationSource = document.getElementById('explanation-source');
    const explanationContent = document.getElementById('explanation-content');
    const evidenceCount = document.getElementById('evidence-count');
    const evidenceList = document.getElementById('evidence-list');
    const threatIntelList = document.getElementById('threat-intel-list');
    const urlPanel = document.getElementById('url-panel');
    const urlList = document.getElementById('url-list');
    const responseContent = document.getElementById('response-content');
    const stateButtons = document.getElementById('state-buttons');
    const attackPathPanel = document.getElementById('attack-path-panel');
    const attackPathContent = document.getElementById('attack-path-content');
    const metaTime = document.getElementById('meta-time');
    const metaModules = document.getElementById('meta-modules');
    const metaIncidentId = document.getElementById('meta-incident-id');

    // ─── State ───
    let currentResult = null;

    // Helper for translation lookup
    const t = (k, def) => (window.I18N ? window.I18N.t(k, def) : def);

    // ─── Health check ───
    async function checkHealth() {
        try {
            await API.health();
            healthStatus.textContent = t('systemOnline', 'System Online');
            healthStatus.classList.remove('error');
        } catch (e) {
            healthStatus.textContent = t('systemOffline', 'Backend Offline');
            healthStatus.classList.add('error');
        }
    }

    // ─── Render sample messages according to active language ───
    function renderSamples() {
        if (!samplesList || !window.I18N) return;
        const currentSamples = I18N.getSamples();
        samplesList.innerHTML = currentSamples
            .map(s => `<button type="button" class="sample-item" data-id="${Components.escapeHtml(s.id)}">${Components.escapeHtml(s.label)}</button>`)
            .join('');
    }

    // ─── Language selector (i18n) ───
    const langSelect = document.getElementById('lang-select');
    if (langSelect && window.I18N) {
        langSelect.value = I18N.currentLang;
        langSelect.addEventListener('change', (e) => {
            I18N.setLanguage(e.target.value);
        });
    }

    // Re-render samples and active results when language changes
    window.addEventListener('languageChanged', (e) => {
        renderSamples();
        if (currentResult) {
            renderResults(currentResult);
        }
        checkHealth();
    });

    // ─── Toggle samples dropdown ───
    sampleBtn.addEventListener('click', () => {
        samplesDropdown.hidden = !samplesDropdown.hidden;
    });

    // ─── Load sample into form ───
    samplesList.addEventListener('click', (e) => {
        const btn = e.target.closest('.sample-item');
        if (!btn) return;

        const currentSamples = I18N.getSamples();
        const sample = currentSamples.find(s => s.id === btn.dataset.id);
        if (!sample) return;

        messageInput.value = sample.message;
        if (sample.input_type) inputType.value = sample.input_type;
        samplesDropdown.hidden = true;
        messageInput.focus();
    });

    // ─── Screenshot OCR Upload ───
    const screenshotInput = document.getElementById('screenshot-upload');
    const uploadStatus = document.getElementById('upload-status');

    if (screenshotInput) {
        screenshotInput.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            uploadStatus.hidden = false;
            uploadStatus.style.color = 'var(--color-primary, #3b82f6)';
            const scanningTemplate = t('ocrScanning', 'Scanning {file} with OCR engine...');
            uploadStatus.textContent = scanningTemplate.replace('{file}', file.name);

            const formData = new FormData();
            formData.append('file', file);

            try {
                const resp = await fetch('/api/upload/screenshot', {
                    method: 'POST',
                    body: formData,
                });

                if (!resp.ok) {
                    const err = await resp.json().catch(() => ({}));
                    uploadStatus.style.color = '#ef4444';
                    uploadStatus.textContent = `${t('ocrFail', 'Upload failed: ')}${err.detail || 'Error processing file'}`;
                    return;
                }

                const res = await resp.json();
                if (res.extracted_text) {
                    messageInput.value = res.extracted_text;
                    inputType.value = 'chat';
                    uploadStatus.style.color = '#10b981';
                    const successTemplate = t('ocrSuccess', "✓ Successfully extracted text from {file}. Review below and click 'Analyze Message'.");
                    uploadStatus.textContent = successTemplate.replace('{file}', file.name);
                } else {
                    uploadStatus.style.color = 'var(--color-text-secondary)';
                    uploadStatus.textContent = `✓ ${file.name} uploaded.`;
                }
            } catch (err) {
                uploadStatus.style.color = '#ef4444';
                uploadStatus.textContent = `${t('ocrFail', 'Upload failed: ')}${err.message}`;
            }
        });
    }

    // ─── Form submission ───
    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const message = messageInput.value.trim();
        if (!message) return;

        const urls = urlsInput.value.split('\n').map(u => u.trim()).filter(Boolean);

        // Show loading
        loading.hidden = false;
        results.hidden = true;
        analyzeBtn.disabled = true;
        analyzeBtn.textContent = t('analyzingBtn', 'Analyzing...');

        try {
            const currentLang = window.I18N ? window.I18N.currentLang : 'en';
            const result = await API.analyze(
                message,
                inputType.value,
                userState.value,
                urls,
                currentLang
            );

            currentResult = result;
            renderResults(result);

            // Asynchronously fetch OSINT enrichment without blocking main analysis display
            if (result.incident_id) {
                API.getIncidentOsint(result.incident_id).then(osintData => {
                    if (osintData && osintData.status !== 'disabled' && osintData.evidence && osintData.evidence.length > 0) {
                        currentResult.evidence = (currentResult.evidence || []).concat(osintData.evidence);
                        evidenceCount.textContent = currentResult.evidence.length;
                        evidenceList.innerHTML = currentResult.evidence
                            .sort((a, b) => (b.confidence || 0) - (a.confidence || 0))
                            .map(item => Components.evidenceItem(item))
                            .join('');
                    }
                }).catch(() => {});
            }
        } catch (err) {
            alert(`Analysis failed: ${err.message}\n\nMake sure the backend is running on port 8000.`);
        } finally {
            loading.hidden = true;
            analyzeBtn.disabled = false;
            analyzeBtn.innerHTML = `
                <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                <span>${t('analyzeBtn', 'Analyze Message')}</span>
            `;
        }
    });

    // ─── Render full results ───
    function renderResults(data) {
        results.hidden = false;

        // Risk banner
        const risk = Components.riskBanner(data.risk, data.fraud_category);
        riskBanner.setAttribute('data-level', risk.rawLevel || risk.level);
        riskScore.textContent = risk.scorePercent;
        riskLevel.textContent = risk.level;
        riskCategory.textContent = risk.categoryLabel;
        riskMeta.textContent = `${data.modules_executed?.length || 0} modules executed · ${data.processing_time_ms?.toFixed(0) || '?'}ms`;

        // Explanation
        if (data.explanation) {
            const sourceKey = data.explanation.is_fallback ? 'sourceDeterministic' : 'sourceGemini';
            explanationSource.textContent = t(sourceKey, data.explanation.is_fallback ? 'Deterministic' : 'Gemini');
            explanationContent.innerHTML = Components.explanation(data.explanation);
        } else {
            explanationSource.textContent = '';
            explanationContent.innerHTML = `<p style="color: var(--color-text-tertiary)">${t('noExplanation', 'No explanation available.')}</p>`;
        }

        // Evidence items
        evidenceCount.textContent = data.evidence?.length || 0;
        evidenceList.innerHTML = (data.evidence || [])
            .sort((a, b) => (b.confidence || 0) - (a.confidence || 0))
            .map(item => Components.evidenceItem(item))
            .join('');

        // Threat intelligence
        threatIntelList.innerHTML = (data.threat_intel || [])
            .map(ti => Components.threatIntelItem(ti))
            .join('');

        if (!data.threat_intel?.length) {
            threatIntelList.innerHTML = `<p style="color: var(--color-text-tertiary); font-size: 0.8125rem;">${t('noThreatIntel', 'No threat intelligence data.')}</p>`;
        }

        // URLs
        if (data.urls && data.urls.length) {
            urlPanel.hidden = false;
            urlList.innerHTML = data.urls.map(u => Components.urlItem(u)).join('');
        } else {
            urlPanel.hidden = true;
        }

        // Adaptive response
        responseContent.innerHTML = Components.response(data.response);

        // Fraud DNA Campaign card & Police Export Dossier
        if (data.fraud_dna) {
            responseContent.innerHTML += Components.fraudDna(data.fraud_dna);
        }
        if (data.incident_id) {
            responseContent.innerHTML += Components.exportButton(data.incident_id);
        }

        // Update state buttons
        const currentState = data.response?.user_state || 'received';
        stateButtons.querySelectorAll('.btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.state === currentState);
        });

        // Attack path
        if (data.explanation?.attack_path?.length) {
            attackPathPanel.hidden = false;
            attackPathContent.innerHTML = Components.attackPath(data.explanation.attack_path);
        } else {
            attackPathPanel.hidden = true;
        }

        // Meta
        metaTime.textContent = `${data.processing_time_ms?.toFixed(0) || '?'}ms`;
        metaModules.textContent = `Modules: ${(data.modules_executed || []).join(', ')}`;
        metaIncidentId.textContent = data.incident_id || '';

        if (data.modules_failed?.length) {
            metaModules.textContent += ` | Failed: ${data.modules_failed.join(', ')}`;
        }

        // Scroll to results
        riskBanner.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // ─── State switcher (demo feature) ───
    stateButtons.addEventListener('click', async (e) => {
        const btn = e.target.closest('[data-state]');
        if (!btn || !currentResult) return;

        const newState = btn.dataset.state;

        try {
            const updated = await API.updateState(currentResult.incident_id, newState);
            currentResult = updated;

            // Re-render response section
            responseContent.innerHTML = Components.response(updated.response);
            if (updated.fraud_dna) {
                responseContent.innerHTML += Components.fraudDna(updated.fraud_dna);
            }
            if (updated.incident_id) {
                responseContent.innerHTML += Components.exportButton(updated.incident_id);
            }

            stateButtons.querySelectorAll('.btn').forEach(b => {
                b.classList.toggle('active', b.dataset.state === newState);
            });
        } catch (err) {
            console.error('State update failed:', err);
        }
    });

    // ─── Initialize ───
    if (window.I18N) {
        I18N.applyTranslations();
    }
    renderSamples();
    checkHealth();

    // Periodic health check
    setInterval(checkHealth, 30000);
})();
