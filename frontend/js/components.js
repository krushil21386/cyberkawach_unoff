/**
 * UI component renderers — pure functions that return HTML strings.
 * Each evidence item renders as its own labeled element with source.
 * Fully integrated with I18N for dynamic multi-lingual website rendering.
 */

const Components = {
    /**
     * Render the risk score banner.
     */
    riskBanner(risk, category) {
        const scorePercent = Math.round((risk.score || 0) * 100);
        const rawLevel = (risk.level || 'UNKNOWN').toUpperCase();
        const rawCategory = (category || 'unknown').toLowerCase();

        const t = (k, def) => (window.I18N ? window.I18N.t(k, def) : def);
        const level = t(`level_${rawLevel}`, rawLevel);
        const categoryLabel = t(`cat_${rawCategory}`, rawCategory.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()));

        return { level, rawLevel, scorePercent, categoryLabel };
    },

    /**
     * Render a single evidence item.
     */
    evidenceItem(item) {
        const confidencePercent = Math.round((item.confidence || 0) * 100);
        const description = item.description || item.finding || '';
        const type = item.type || item.module || 'osint';
        const source = item.source || item.module || 'OSINT';
        return `
            <div class="evidence-item">
                <div class="evidence-type-indicator" data-type="${this.escapeHtml(type)}"></div>
                <div class="evidence-body">
                    <div class="evidence-source">${this.escapeHtml(source)}</div>
                    <div class="evidence-description">${this.escapeHtml(description)}</div>
                </div>
                <div class="evidence-confidence">${confidencePercent}%</div>
            </div>
        `;
    },

    /**
     * Render a threat intel item.
     */
    threatIntelItem(ti) {
        let statusClass = 'error';
        let rawStatus = 'Unavailable';

        if (ti.match === true) {
            statusClass = 'match';
            rawStatus = 'MATCH';
        } else if (ti.match === false) {
            statusClass = 'clean';
            rawStatus = 'Clean';
        }

        const t = (k, def) => (window.I18N ? window.I18N.t(k, def) : def);
        const statusText = t(`status_${rawStatus}`, rawStatus);

        const sourceLabel = {
            'safe_browsing': 'Google Safe Browsing',
            'phishtank': 'PhishTank',
            'urlhaus': 'URLhaus',
            'abuseipdb': 'AbuseIPDB',
        }[ti.source] || ti.source;

        const details = ti.error
            ? `Error: ${this.escapeHtml(ti.error)}`
            : this.escapeHtml(ti.details || '');

        return `
            <div class="threat-intel-item">
                <div class="threat-intel-source">${this.escapeHtml(sourceLabel)}</div>
                <span class="threat-intel-status ${statusClass}">${this.escapeHtml(statusText)}</span>
                <div class="threat-intel-details">${details}</div>
            </div>
        `;
    },

    /**
     * Render URL analysis items.
     */
    urlItem(urlSignal) {
        const signalTags = (urlSignal.signals || [])
            .map(s => `<span class="url-signal-tag">${this.escapeHtml(s.replace(/_/g, ' '))}</span>`)
            .join('');

        return `
            <div class="url-item">
                <div class="url-domain">${this.escapeHtml(urlSignal.domain || urlSignal.url)}</div>
                ${signalTags ? `<div class="url-signals">${signalTags}</div>` : ''}
            </div>
        `;
    },

    /**
     * Render the explanation section.
     */
    explanation(expl) {
        const t = (k, def) => (window.I18N ? window.I18N.t(k, def) : def);
        if (!expl) return `<p style="color: var(--color-text-tertiary)">${t('noExplanation', 'No explanation available.')}</p>`;

        let html = '';

        if (expl.summary) {
            html += `<p class="explanation-summary">${this.escapeHtml(expl.summary)}</p>`;
        }

        if (expl.reasons && expl.reasons.length) {
            html += `
                <div class="explanation-section">
                    <div class="explanation-section-title">${t('keyReasons', 'Key Reasons')}</div>
                    <ul class="explanation-list">
                        ${expl.reasons.map(r => `<li>${this.escapeHtml(r)}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        if (expl.uncertainty) {
            html += `<div class="explanation-uncertainty">${this.escapeHtml(expl.uncertainty)}</div>`;
        }

        return html;
    },

    /**
     * Render the attack path.
     */
    attackPath(steps) {
        if (!steps || !steps.length) return '';

        const stepsHtml = steps.map((step, i) => `
            <div class="attack-path-step">
                <div class="attack-path-number">${i + 1}</div>
                <div class="attack-path-text">${this.escapeHtml(step)}</div>
            </div>
        `).join('');

        const t = (k, def) => (window.I18N ? window.I18N.t(k, def) : def);

        return `
            <div class="attack-path-container">
                <div style="font-size: 0.85rem; font-weight: 600; color: var(--color-text-secondary); margin-bottom: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em;">
                    ${t('multiStageProgression', 'Multi-Stage Threat Progression')}
                </div>
                <div class="attack-path-steps">${stepsHtml}</div>
            </div>
        `;
    },

    /**
     * Render Fraud DNA syndicate campaign alert card.
     */
    fraudDna(dna) {
        if (!dna || !dna.campaign_id) return '';
        const t = (k, def) => (window.I18N ? window.I18N.t(k, def) : def);

        const relatedHtml = dna.related_incidents && dna.related_incidents.length
            ? `<div style="margin-top: 0.4rem; font-size: 0.8125rem; color: var(--color-text-secondary);">${dna.related_incidents.length} related incidents: <code>${dna.related_incidents.slice(0, 3).map(id => this.escapeHtml(id)).join(', ')}</code></div>`
            : `<div style="margin-top: 0.4rem; font-size: 0.8125rem; color: var(--color-text-secondary);">${t('firstOccurrence', 'First tracked occurrence for this threat signature.')}</div>`;

        return `
            <div class="card" style="border-left: 4px solid #f59e0b; margin-top: 1rem; padding: 1rem; background: rgba(245, 158, 11, 0.06); border-radius: var(--radius-sm, 6px);">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.4rem;">
                    <div style="font-weight: 600; color: #f59e0b; display: flex; align-items: center; gap: 0.5rem; font-size: 0.95rem;">
                        <span>${t('syndicateAlert', '🧬 Fraud DNA Syndicate Campaign Alert')}</span>
                    </div>
                    <span style="background: rgba(245, 158, 11, 0.2); color: #d97706; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-family: monospace; font-weight: bold;">${this.escapeHtml(dna.campaign_id)}</span>
                </div>
                <div style="font-size: 0.8125rem; color: var(--color-text-secondary);">
                    ${t('infrastructureFingerprint', 'Infrastructure Fingerprint')}: <code>${this.escapeHtml(dna.fingerprint || 'N/A')}</code>
                </div>
                ${relatedHtml}
            </div>
        `;
    },

    /**
     * Render Police Complaint Export Button.
     */
    exportButton(incidentId) {
        if (!incidentId) return '';
        const t = (k, def) => (window.I18N ? window.I18N.t(k, def) : def);
        return `
            <div style="margin-top: 1.25rem; text-align: center;">
                <a href="/api/incidents/${encodeURIComponent(incidentId)}/export?format=html" target="_blank" class="btn" style="display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.6rem 1.25rem; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 0.875rem; background: #1e3a8a; color: #93c5fd; border: 1px solid #3b82f6;">
                    <span>${t('exportBtn', '📄 Download 1930 / Cyber Police Complaint Dossier')}</span>
                </a>
            </div>
        `;
    },

    /**
     * Render the adaptive response.
     */
    response(resp) {
        const t = (k, def) => (window.I18N ? window.I18N.t(k, def) : def);
        if (!resp) return `<p style="color: var(--color-text-tertiary)">${t('noExplanation', 'No response guidance available.')}</p>`;

        const rawUrgency = (resp.urgency || 'normal').toUpperCase();
        const urgencyClass = (resp.urgency || 'normal').toLowerCase();
        const listClass = urgencyClass === 'critical' || urgencyClass === 'urgent' ? 'urgent' : 'normal';
        const urgencyText = t(`urgency_${rawUrgency}`, rawUrgency);

        let html = `<span class="response-urgency-badge ${urgencyClass}">${this.escapeHtml(urgencyText)}</span>`;

        if (resp.immediate_actions && resp.immediate_actions.length) {
            html += `
                <div class="response-section">
                    <div class="response-section-title">${t('immediateActions', 'Immediate Actions')}</div>
                    <ul class="response-list ${listClass}">
                        ${resp.immediate_actions.map(a => `<li>${this.escapeHtml(a)}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        if (resp.recovery_steps && resp.recovery_steps.length) {
            html += `
                <div class="response-section">
                    <div class="response-section-title">${t('recoverySteps', 'Recovery Steps')}</div>
                    <ul class="response-list normal">
                        ${resp.recovery_steps.map(s => `<li>${this.escapeHtml(s)}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        if (resp.reporting_info && resp.reporting_info.length) {
            html += `
                <div class="response-section">
                    <div class="response-section-title">${t('reportThis', 'Report This')}</div>
                    <ul class="response-list normal">
                        ${resp.reporting_info.map(r => `<li>${this.escapeHtml(r)}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        return html;
    },

    /**
     * HTML-escape for safe rendering.
     */
    escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = String(str);
        return div.innerHTML;
    },
};
