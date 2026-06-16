/**
 * dashboard.js - Dashboard auto-refresh and mini chart
 * AI-NIDS SOC Dashboard
 */

// ─── Chart Colors ────────────────────────────────────────────────
const CHART_COLORS = {
    high:    { bg: 'rgba(239, 68, 68, 0.8)',  border: '#ef4444' },
    medium:  { bg: 'rgba(245, 158, 11, 0.8)', border: '#f59e0b' },
    low:     { bg: 'rgba(34, 197, 94, 0.8)',   border: '#22c55e' },
    accent:  { bg: 'rgba(99, 102, 241, 0.8)',  border: '#6366f1' },
};

const SEVERITY_COLORS_BG = ['rgba(239, 68, 68, 0.75)', 'rgba(245, 158, 11, 0.75)', 'rgba(34, 197, 94, 0.75)'];
const SEVERITY_COLORS_BORDER = ['#ef4444', '#f59e0b', '#22c55e'];

// ─── Initialize Severity Donut Chart ─────────────────────────────
function initSeverityChart(data) {
    const canvas = document.getElementById('severityMiniChart');
    if (!canvas) return;

    const labels = data.map(d => d.severity_label);
    const values = data.map(d => d.count);
    const bgColors = labels.map(label => {
        if (label === 'High') return SEVERITY_COLORS_BG[0];
        if (label === 'Medium') return SEVERITY_COLORS_BG[1];
        return SEVERITY_COLORS_BG[2];
    });
    const borderColors = labels.map(label => {
        if (label === 'High') return SEVERITY_COLORS_BORDER[0];
        if (label === 'Medium') return SEVERITY_COLORS_BORDER[1];
        return SEVERITY_COLORS_BORDER[2];
    });

    window.severityChartInstance = new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: bgColors,
                borderColor: borderColors,
                borderWidth: 2,
                hoverOffset: 8,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#8892a8',
                        padding: 16,
                        font: {
                            family: 'Inter',
                            size: 12,
                            weight: '500'
                        },
                        usePointStyle: true,
                        pointStyleWidth: 10,
                    }
                },
                tooltip: {
                    backgroundColor: '#1a1f35',
                    titleColor: '#e8ecf4',
                    bodyColor: '#8892a8',
                    borderColor: 'rgba(255,255,255,0.1)',
                    borderWidth: 1,
                    cornerRadius: 8,
                    padding: 12,
                    titleFont: { family: 'Inter', weight: '600' },
                    bodyFont: { family: 'Inter' },
                }
            },
            animation: {
                animateRotate: true,
                duration: 1200,
                easing: 'easeOutQuart'
            }
        }
    });
}

// ─── Animated Counters ───────────────────────────────────────────
function animateCounters() {
    document.querySelectorAll('[data-counter]').forEach(el => {
        const target = parseInt(el.getAttribute('data-counter'), 10);
        const duration = 1200;
        const start = performance.now();

        function update(now) {
            const elapsed = now - start;
            const progress = Math.min(elapsed / duration, 1);
            // Ease out quad
            const eased = 1 - (1 - progress) * (1 - progress);
            el.textContent = Math.round(target * eased);

            if (progress < 1) {
                requestAnimationFrame(update);
            }
        }

        requestAnimationFrame(update);
    });
}

// Run counters on page load
document.addEventListener('DOMContentLoaded', animateCounters);

// ─── Auto-Refresh Dashboard ─────────────────────────────────────
function refreshDashboard() {
    fetch('/api/stats')
        .then(res => res.json())
        .then(stats => {
            const cards = document.querySelectorAll('.stat-value[data-counter]');
            const values = [stats.total, stats.high, stats.medium, stats.low];
            cards.forEach((card, idx) => {
                if (values[idx] !== undefined) {
                    card.setAttribute('data-counter', values[idx]);
                    card.textContent = values[idx];
                }
            });

            const changeEls = document.querySelectorAll('.stat-change span');
            if (changeEls[0]) {
                changeEls[0].textContent = `📅 ${stats.recent_24h} in last 24h`;
            }
            if (changeEls[3]) {
                changeEls[3].textContent = `✅ ${stats.analyzed} analyzed by AI`;
            }

            // Update Quick Stats
            const q1h = document.getElementById('quick-alerts-1h');
            if(q1h) q1h.textContent = stats.recent_1h;
            const q24h = document.getElementById('quick-alerts-24h');
            if(q24h) q24h.textContent = stats.recent_24h;
            const qai = document.getElementById('quick-ai-analyzed');
            if(qai) qai.textContent = stats.analyzed;
        })
        .catch(err => console.warn('Dashboard stats refresh failed:', err));

    fetch('/api/alerts?limit=10')
        .then(res => res.json())
        .then(data => {
            const tbody = document.querySelector('#recent-alerts-table tbody');
            if (!tbody) return;
            
            if (data.alerts && data.alerts.length > 0) {
                tbody.innerHTML = '';
                data.alerts.forEach(alert => {
                    const tr = document.createElement('tr');
                    const time = alert.timestamp ? alert.timestamp.substring(0, 19).replace('T', ' ') : '';
                    const sig = alert.signature.length > 50 ? alert.signature.substring(0, 50) + '...' : alert.signature;
                    
                    tr.innerHTML = `
                        <td class="text-mono text-sm">${time}</td>
                        <td>
                            <span class="badge badge-${(alert.severity_label || 'low').toLowerCase()}">
                                <span class="badge-dot"></span>
                                ${alert.severity_label || 'Low'}
                            </span>
                        </td>
                        <td>${sig}</td>
                        <td class="text-mono">${alert.src_ip}</td>
                        <td class="text-mono">${alert.dest_ip}</td>
                        <td><span class="badge badge-info">${alert.protocol}</span></td>
                        <td>
                            <a href="/analysis/${alert.id}" class="btn btn-secondary btn-sm" data-tooltip="View Details">🔍</a>
                        </td>
                    `;
                    tbody.appendChild(tr);
                });
            } else {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="7">
                            <div class="empty-state" style="padding: 30px;">
                                <div class="empty-icon">📭</div>
                                <div class="empty-text">No alerts yet. Start Suricata to begin monitoring.</div>
                            </div>
                        </td>
                    </tr>
                `;
            }
        })
        .catch(err => console.warn('Dashboard alerts refresh failed:', err));

    fetch('/api/severity')
        .then(res => res.json())
        .then(data => {
            if (window.severityChartInstance) {
                const labels = data.map(d => d.severity_label);
                const values = data.map(d => d.count);
                const bgColors = labels.map(label => {
                    if (label === 'High') return SEVERITY_COLORS_BG[0];
                    if (label === 'Medium') return SEVERITY_COLORS_BG[1];
                    return SEVERITY_COLORS_BG[2];
                });
                const borderColors = labels.map(label => {
                    if (label === 'High') return SEVERITY_COLORS_BORDER[0];
                    if (label === 'Medium') return SEVERITY_COLORS_BORDER[1];
                    return SEVERITY_COLORS_BORDER[2];
                });
                window.severityChartInstance.data.labels = labels;
                window.severityChartInstance.data.datasets[0].data = values;
                window.severityChartInstance.data.datasets[0].backgroundColor = bgColors;
                window.severityChartInstance.data.datasets[0].borderColor = borderColors;
                window.severityChartInstance.update();
            }
        })
        .catch(err => console.warn('Dashboard severity refresh failed:', err));
}
