/**
 * analysis.js - AI Analysis interactions
 * AI-NIDS SOC Dashboard
 */

/**
 * Trigger AI analysis for a specific alert.
 * Works on both the analysis list page and the detail page.
 */
function triggerAnalysis(alertId) {
    // Find the button that was clicked
    const btn = document.querySelector(`[data-alert-id="${alertId}"]`) ||
                document.getElementById('analyze-detail-btn');

    // Show loading state on button
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Analyzing...';
    }

    // Show loading overlay on detail page
    const loadingEl = document.getElementById('analysis-loading');
    const noAnalysisEl = document.getElementById('no-analysis-state');
    const contentEl = document.getElementById('analysis-content');

    if (loadingEl) loadingEl.style.display = 'flex';
    if (noAnalysisEl) noAnalysisEl.style.display = 'none';

    // Make the API call
    fetch(`/analysis/${alertId}/analyze`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // On the detail page, show inline
            if (contentEl) {
                contentEl.textContent = data.analysis;
                contentEl.style.display = 'block';
                if (loadingEl) loadingEl.style.display = 'none';
            }

            // On the list page, show in the result container
            const resultContainer = document.getElementById('analysis-result-container');
            const resultContent = document.getElementById('analysis-result-content');
            if (resultContainer && resultContent) {
                resultContent.textContent = data.analysis;
                resultContainer.style.display = 'block';
                resultContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }

            // Update the row's AI status badge
            const row = document.getElementById(`alert-row-${alertId}`);
            if (row) {
                const statusCell = row.querySelectorAll('td')[6]; // AI Status column
                if (statusCell) {
                    statusCell.innerHTML = '<span class="badge badge-low"><span class="badge-dot"></span> Analyzed</span>';
                }
            }

            // Restore button
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '🤖 Re-Analyze';
            }

            showFlash('AI analysis completed successfully.', 'success');
        } else {
            throw new Error(data.error || 'Analysis failed');
        }
    })
    .catch(error => {
        console.error('Analysis error:', error);

        if (loadingEl) loadingEl.style.display = 'none';
        if (noAnalysisEl) noAnalysisEl.style.display = 'block';

        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '🤖 Retry Analysis';
        }

        showFlash('Analysis failed: ' + error.message, 'error');
    });
}

/**
 * Show a flash notification.
 */
function showFlash(message, type) {
    // Create flash container if not exists
    let container = document.querySelector('.flash-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'flash-container';
        document.body.appendChild(container);
    }

    const flash = document.createElement('div');
    flash.className = `flash-message ${type}`;
    flash.innerHTML = `<span>${type === 'success' ? '✓' : '✕'}</span> ${message}`;
    flash.addEventListener('click', () => flash.remove());

    container.appendChild(flash);

    // Auto-dismiss
    setTimeout(() => {
        flash.style.animation = 'slideIn 0.3s ease reverse';
        setTimeout(() => flash.remove(), 300);
    }, 5000);
}
