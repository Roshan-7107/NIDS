/**
 * analytics.js - Chart.js visualizations for Analytics page
 * AI-NIDS SOC Dashboard
 */

// ─── Shared Chart Configuration ──────────────────────────────────
const chartDefaults = {
    font: {
        family: 'Inter',
        size: 12,
    },
    color: '#8892a8',
};

const tooltipConfig = {
    backgroundColor: '#1a1f35',
    titleColor: '#e8ecf4',
    bodyColor: '#8892a8',
    borderColor: 'rgba(255,255,255,0.1)',
    borderWidth: 1,
    cornerRadius: 8,
    padding: 12,
    titleFont: { family: 'Inter', weight: '600', size: 13 },
    bodyFont: { family: 'Inter', size: 12 },
};

const gridConfig = {
    color: 'rgba(255, 255, 255, 0.04)',
    drawBorder: false,
};

// Palette for bar charts
const barPalette = [
    'rgba(99, 102, 241, 0.75)',
    'rgba(139, 92, 246, 0.75)',
    'rgba(59, 130, 246, 0.75)',
    'rgba(14, 165, 233, 0.75)',
    'rgba(6, 182, 212, 0.75)',
    'rgba(20, 184, 166, 0.75)',
    'rgba(34, 197, 94, 0.75)',
    'rgba(132, 204, 22, 0.75)',
    'rgba(245, 158, 11, 0.75)',
    'rgba(239, 68, 68, 0.75)',
];

const barPaletteBorder = [
    '#6366f1', '#8b5cf6', '#3b82f6', '#0ea5e9', '#06b6d4',
    '#14b8a6', '#22c55e', '#84cc16', '#f59e0b', '#ef4444',
];

// ─── Initialize All Charts ───────────────────────────────────────
function initAllCharts(severityData, attackTypeData, topIpsData, timelineData) {
    Chart.defaults.font.family = 'Inter';
    Chart.defaults.color = '#8892a8';

    initSeverityDoughnut(severityData);
    initAttackTypeChart(attackTypeData);
    initTopIpsChart(topIpsData);
    initTimelineChart(timelineData);
}

// ─── Severity Distribution (Doughnut) ────────────────────────────
function initSeverityDoughnut(data) {
    const canvas = document.getElementById('severityChart');
    if (!canvas) return;

    const sevColors = {
        'High':   { bg: 'rgba(239, 68, 68, 0.8)',  border: '#ef4444' },
        'Medium': { bg: 'rgba(245, 158, 11, 0.8)', border: '#f59e0b' },
        'Low':    { bg: 'rgba(34, 197, 94, 0.8)',   border: '#22c55e' },
    };

    const labels = data.map(d => d.severity_label);
    const values = data.map(d => d.count);
    const bgColors = labels.map(l => (sevColors[l] || sevColors['Low']).bg);
    const borderColors = labels.map(l => (sevColors[l] || sevColors['Low']).border);

    new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: bgColors,
                borderColor: borderColors,
                borderWidth: 2,
                hoverOffset: 12,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '60%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#8892a8',
                        padding: 20,
                        font: { family: 'Inter', size: 13, weight: '500' },
                        usePointStyle: true,
                        pointStyleWidth: 10,
                    }
                },
                tooltip: tooltipConfig,
            },
            animation: {
                animateRotate: true,
                duration: 1500,
                easing: 'easeOutQuart'
            }
        }
    });
}

// ─── Attack Types (Horizontal Bar) ───────────────────────────────
function initAttackTypeChart(data) {
    const canvas = document.getElementById('attackTypeChart');
    if (!canvas) return;

    const labels = data.map(d => {
        // Truncate long category names
        const cat = d.category;
        return cat.length > 30 ? cat.substring(0, 28) + '…' : cat;
    });
    const values = data.map(d => d.count);

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Alert Count',
                data: values,
                backgroundColor: barPalette.slice(0, data.length),
                borderColor: barPaletteBorder.slice(0, data.length),
                borderWidth: 1,
                borderRadius: 6,
                barPercentage: 0.7,
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: tooltipConfig,
            },
            scales: {
                x: {
                    grid: gridConfig,
                    ticks: { color: '#8892a8', font: { family: 'Inter', size: 11 } },
                    beginAtZero: true,
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#8892a8', font: { family: 'Inter', size: 11 } },
                }
            },
            animation: {
                duration: 1200,
                easing: 'easeOutQuart'
            }
        }
    });
}

// ─── Top Source IPs (Bar) ────────────────────────────────────────
function initTopIpsChart(data) {
    const canvas = document.getElementById('topIpsChart');
    if (!canvas) return;

    const labels = data.map(d => d.ip);
    const values = data.map(d => d.count);

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Alert Count',
                data: values,
                backgroundColor: function(ctx) {
                    const chart = ctx.chart;
                    const { ctx: canvasCtx, chartArea } = chart;
                    if (!chartArea) return barPalette[0];
                    const gradient = canvasCtx.createLinearGradient(0, chartArea.bottom, 0, chartArea.top);
                    gradient.addColorStop(0, 'rgba(99, 102, 241, 0.3)');
                    gradient.addColorStop(1, 'rgba(139, 92, 246, 0.8)');
                    return gradient;
                },
                borderColor: '#8b5cf6',
                borderWidth: 1,
                borderRadius: 6,
                barPercentage: 0.6,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: tooltipConfig,
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: {
                        color: '#8892a8',
                        font: { family: 'JetBrains Mono', size: 10 },
                        maxRotation: 45,
                    },
                },
                y: {
                    grid: gridConfig,
                    ticks: { color: '#8892a8', font: { family: 'Inter', size: 11 } },
                    beginAtZero: true,
                }
            },
            animation: {
                duration: 1200,
                easing: 'easeOutQuart'
            }
        }
    });
}

// ─── Alert Timeline (Line) ──────────────────────────────────────
function initTimelineChart(data) {
    const canvas = document.getElementById('timelineChart');
    if (!canvas) return;

    const labels = data.map(d => {
        const date = new Date(d.date);
        return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    });
    const values = data.map(d => d.count);

    new Chart(canvas, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Alerts',
                data: values,
                fill: true,
                backgroundColor: function(ctx) {
                    const chart = ctx.chart;
                    const { ctx: canvasCtx, chartArea } = chart;
                    if (!chartArea) return 'rgba(99, 102, 241, 0.1)';
                    const gradient = canvasCtx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
                    gradient.addColorStop(0, 'rgba(99, 102, 241, 0.3)');
                    gradient.addColorStop(1, 'rgba(99, 102, 241, 0.02)');
                    return gradient;
                },
                borderColor: '#6366f1',
                borderWidth: 2.5,
                pointBackgroundColor: '#6366f1',
                pointBorderColor: '#0a0e1a',
                pointBorderWidth: 2,
                pointRadius: 5,
                pointHoverRadius: 8,
                tension: 0.4,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    ...tooltipConfig,
                    mode: 'index',
                    intersect: false,
                },
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: '#8892a8', font: { family: 'Inter', size: 11 } },
                },
                y: {
                    grid: gridConfig,
                    ticks: { color: '#8892a8', font: { family: 'Inter', size: 11 } },
                    beginAtZero: true,
                }
            },
            interaction: {
                mode: 'nearest',
                axis: 'x',
                intersect: false,
            },
            animation: {
                duration: 1500,
                easing: 'easeOutQuart'
            }
        }
    });
}
