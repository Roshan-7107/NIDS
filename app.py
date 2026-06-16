"""
app.py - Flask Web Application for AI-NIDS

Main application entry point. Provides the SOC dashboard,
analytics visualizations, AI analysis interface, and
incident report management through a web UI.
"""

import os
import sys
import json
import logging
# pyrefly: ignore [missing-import]
from flask import (Flask, render_template, request, jsonify,redirect, url_for, Response, flash)
from datetime import datetime

from database import Database
from suricata_monitor import SuricataMonitor, PacketSniffer
from ai_engine import AIEngine
from report_generator import ReportGenerator

# ─── Logging ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ─── Application Setup ──────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize components
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Allow user to specify custom Suricata log path via environment variable
EVE_PATH = os.environ.get('EVE_JSON_PATH', os.path.join(BASE_DIR, 'logs', 'eve.json'))
custom_eve_configured = 'EVE_JSON_PATH' in os.environ

db = Database()
db.init_db()

ai_engine = AIEngine()
report_gen = ReportGenerator(db)

# Start Suricata monitor (watches for eve.json)
monitor = SuricataMonitor(EVE_PATH, db)

stats = db.get_dashboard_stats()
if stats['total'] == 0:
    logger.info("Database is empty. Waiting for real live traffic alerts...")

# Start monitor (will wait for eve.json if it doesn't exist)
monitor.start()

# Start internal packet sniffer if we are using the default path (demo/no Suricata) or if explicitly requested
use_internal_sniffer = os.environ.get('USE_INTERNAL_SNIFFER', 'true').lower() == 'true'
if not custom_eve_configured or use_internal_sniffer:
    sniffer = PacketSniffer(EVE_PATH)
    sniffer.start()
else:
    sniffer = None


# ═══════════════════════════════════════════════════════════════════
# TEMPLATE ROUTES
# ═══════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    """Redirect root to dashboard."""
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    """Main SOC dashboard with stats and recent alerts."""
    stats = db.get_dashboard_stats()
    recent_alerts = db.get_recent_alerts(limit=10)
    severity_dist = db.get_severity_distribution()
    ai_available = ai_engine.is_available()

    return render_template('dashboard.html',
                           stats=stats,
                           recent_alerts=recent_alerts,
                           severity_dist=severity_dist,
                           ai_available=ai_available,
                           active_page='dashboard')


@app.route('/analytics')
def analytics():
    """Analytics page with charts and visualizations."""
    severity_dist = db.get_severity_distribution()
    attack_types = db.get_attack_type_stats(limit=10)
    top_ips = db.get_top_source_ips(limit=10)
    timeline = db.get_timeline_data(days=7)
    stats = db.get_dashboard_stats()

    return render_template('analytics.html',
                           severity_dist=severity_dist,
                           attack_types=attack_types,
                           top_ips=top_ips,
                           timeline=timeline,
                           stats=stats,
                           active_page='analytics')


@app.route('/analysis')
def analysis():
    """AI analysis page — browse alerts and trigger analysis."""
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity', None, type=int)
    search = request.args.get('search', None, type=str)
    per_page = 15

    alerts = db.get_alerts(limit=per_page, offset=(page - 1) * per_page,
                           severity=severity, search=search)
    total = db.get_alerts_count(severity=severity, search=search)
    total_pages = max(1, (total + per_page - 1) // per_page)

    ai_available = ai_engine.is_available()

    return render_template('analysis.html',
                           alerts=alerts,
                           page=page,
                           total_pages=total_pages,
                           total=total,
                           severity=severity,
                           search=search or '',
                           ai_available=ai_available,
                           active_page='analysis')


@app.route('/analysis/<int:alert_id>')
def analysis_detail(alert_id):
    """Detailed view of a single alert with AI analysis."""
    alert = db.get_alert_by_id(alert_id)
    if not alert:
        flash('Alert not found.', 'error')
        return redirect(url_for('analysis'))

    ai_available = ai_engine.is_available()

    return render_template('analysis_detail.html',
                           alert=alert,
                           ai_available=ai_available,
                           active_page='analysis')


@app.route('/analysis/<int:alert_id>/analyze', methods=['POST'])
def trigger_analysis(alert_id):
    """Trigger AI analysis for a specific alert."""
    alert = db.get_alert_by_id(alert_id)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404

    analysis_text = ai_engine.analyze_alert(alert)
    db.update_ai_analysis(alert_id, analysis_text)

    return jsonify({
        'success': True,
        'alert_id': alert_id,
        'analysis': analysis_text
    })


@app.route('/reports')
def reports():
    """Reports page — view and generate incident reports."""
    all_reports = db.get_reports(limit=20)
    stats = db.get_dashboard_stats()

    return render_template('reports.html',
                           reports=all_reports,
                           stats=stats,
                           active_page='reports')


@app.route('/reports/generate', methods=['POST'])
def generate_report():
    """Generate a new report."""
    report_type = request.form.get('report_type', 'summary')
    alert_id = request.form.get('alert_id', None, type=int)

    if report_type == 'incident' and alert_id:
        report = report_gen.generate_incident_report(alert_id)
    else:
        report = report_gen.generate_summary_report()

    if report:
        flash('Report generated successfully.', 'success')
    else:
        flash('Failed to generate report.', 'error')

    return redirect(url_for('reports'))


@app.route('/reports/<int:report_id>/download')
def download_report(report_id):
    """Download a report as a text file."""
    report = db.get_report_by_id(report_id)
    if not report:
        flash('Report not found.', 'error')
        return redirect(url_for('reports'))

    content = report_gen.format_for_download(report)
    filename = f"NIDS_Report_{report_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    return Response(
        content,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )


# ═══════════════════════════════════════════════════════════════════
# API ROUTES (JSON)
# ═══════════════════════════════════════════════════════════════════

@app.route('/api/stats')
def api_stats():
    """JSON endpoint for dashboard statistics (AJAX refresh)."""
    stats = db.get_dashboard_stats()
    return jsonify(stats)


@app.route('/api/alerts')
def api_alerts():
    """JSON endpoint for alerts with filtering."""
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    severity = request.args.get('severity', None, type=int)
    search = request.args.get('search', None, type=str)

    alerts = db.get_alerts(limit=limit, offset=offset,
                           severity=severity, search=search)
    total = db.get_alerts_count(severity=severity, search=search)

    return jsonify({
        'alerts': alerts,
        'total': total,
        'limit': limit,
        'offset': offset
    })


@app.route('/api/timeline')
def api_timeline():
    """JSON endpoint for timeline chart data."""
    days = request.args.get('days', 7, type=int)
    timeline = db.get_timeline_data(days=days)
    return jsonify(timeline)


@app.route('/api/severity')
def api_severity():
    """JSON endpoint for severity distribution."""
    dist = db.get_severity_distribution()
    return jsonify(dist)


@app.route('/api/top-ips')
def api_top_ips():
    """JSON endpoint for top source IPs."""
    limit = request.args.get('limit', 10, type=int)
    ips = db.get_top_source_ips(limit=limit)
    return jsonify(ips)


@app.route('/api/attack-types')
def api_attack_types():
    """JSON endpoint for attack type statistics."""
    attack_types = db.get_attack_type_stats(limit=10)
    return jsonify(attack_types)


@app.route('/api/ai-status')
def api_ai_status():
    """Check if the AI engine (Ollama) is available."""
    return jsonify({
        'available': ai_engine.is_available(),
        'model': ai_engine.model,
        'base_url': ai_engine.base_url
    })


# ═══════════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    return render_template('base.html',
                           error_code=404,
                           error_message='Page not found',
                           active_page=''), 404


@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    return render_template('base.html',
                           error_code=500,
                           error_message='Internal server error',
                           active_page=''), 500


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("  AI-Powered Network Intrusion Detection System")
    logger.info("  Starting SOC Dashboard...")
    logger.info("=" * 60)
    logger.info(f"  Dashboard:  http://127.0.0.1:5000")
    logger.info(f"  Suricata:   Monitoring {EVE_PATH}")
    logger.info(f"  Ollama:     {'Connected' if ai_engine.is_available() else 'Not available (fallback mode)'}")
    logger.info("=" * 60)

    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
