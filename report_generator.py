"""
report_generator.py - Incident Report Generator for AI-NIDS

Generates structured security incident reports from alerts
and AI analyses. Supports individual incident reports and
aggregate summary reports.
"""

from datetime import datetime
import json
import logging

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates formatted security incident reports."""

    def __init__(self, db):
        """
        Initialize the report generator.

        Args:
            db: Database instance for retrieving data
        """
        self.db = db

    def generate_incident_report(self, alert_id):
        """
        Generate a detailed incident report for a specific alert.

        Args:
            alert_id: Database ID of the alert

        Returns:
            Report dictionary with all fields, or None if alert not found
        """
        alert = self.db.get_alert_by_id(alert_id)
        if not alert:
            return None

        report = {
            'title': f"Incident Report - {alert['signature']}",
            'report_type': 'incident',
            'alert_ids': str(alert_id),
            'total_alerts': 1,
            'severity_summary': alert.get('severity_label', 'Unknown'),
            'content': self._format_incident_content(alert)
        }

        # Save to database
        report_id = self.db.save_report(report)
        report['id'] = report_id
        report['created_at'] = datetime.now().isoformat()

        return report

    def generate_summary_report(self):
        """
        Generate an aggregate summary report of all recent alerts.

        Returns:
            Report dictionary with summary statistics
        """
        stats = self.db.get_dashboard_stats()
        recent_alerts = self.db.get_recent_alerts(limit=50)
        top_ips = self.db.get_top_source_ips(limit=5)
        attack_types = self.db.get_attack_type_stats(limit=10)
        severity_dist = self.db.get_severity_distribution()

        alert_ids = ','.join(str(a['id']) for a in recent_alerts[:20])

        severity_summary = ', '.join(
            f"{s['severity_label']}: {s['count']}" for s in severity_dist
        )

        report = {
            'title': f"Security Summary Report - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            'report_type': 'summary',
            'alert_ids': alert_ids,
            'total_alerts': stats['total'],
            'severity_summary': severity_summary,
            'content': self._format_summary_content(stats, recent_alerts, top_ips, attack_types, severity_dist)
        }

        # Save to database
        report_id = self.db.save_report(report)
        report['id'] = report_id
        report['created_at'] = datetime.now().isoformat()

        return report

    def _format_incident_content(self, alert):
        """Format a detailed incident report for a single alert."""
        ai_section = ""
        if alert.get('ai_analysis'):
            ai_section = f"""
=====================================
AI THREAT ANALYSIS
=====================================
{alert['ai_analysis']}
"""
        else:
            ai_section = """
=====================================
AI THREAT ANALYSIS
=====================================
Not yet analyzed. Trigger AI analysis from the Analysis page.
"""

        return f"""
╔═══════════════════════════════════════════════════════════════╗
║              SECURITY INCIDENT REPORT                         ║
║              AI-Powered Network Intrusion Detection System    ║
╚═══════════════════════════════════════════════════════════════╝

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Report Type: Individual Incident

=====================================
ALERT DETAILS
=====================================
Alert ID:        #{alert['id']}
Timestamp:       {alert.get('timestamp', 'N/A')}
Signature:       {alert.get('signature', 'N/A')}
Signature ID:    {alert.get('signature_id', 'N/A')}
Category:        {alert.get('category', 'N/A')}
Severity:        {alert.get('severity_label', 'N/A')} (Level {alert.get('severity', 'N/A')})

=====================================
NETWORK DETAILS
=====================================
Source IP:       {alert.get('src_ip', 'N/A')}
Source Port:     {alert.get('src_port', 'N/A')}
Destination IP:  {alert.get('dest_ip', 'N/A')}
Destination Port:{alert.get('dest_port', 'N/A')}
Protocol:        {alert.get('protocol', 'N/A')}
{ai_section}
=====================================
RESPONSE ACTIONS
=====================================
1. Review the alert details and AI analysis above
2. Investigate source IP for additional suspicious activity
3. Check destination host for signs of compromise
4. Update firewall rules if confirmed malicious
5. Document findings in incident tracking system

=====================================
END OF REPORT
=====================================
"""

    def _format_summary_content(self, stats, alerts, top_ips, attack_types, severity_dist):
        """Format an aggregate summary report."""
        # Top IPs section
        top_ips_text = ""
        for idx, ip in enumerate(top_ips, 1):
            top_ips_text += f"  {idx}. {ip['ip']} — {ip['count']} alerts\n"

        # Attack types section
        attack_types_text = ""
        for idx, at in enumerate(attack_types, 1):
            attack_types_text += f"  {idx}. {at['category']} — {at['count']} alerts\n"

        # Severity breakdown
        severity_text = ""
        for s in severity_dist:
            bar_len = min(s['count'], 40)
            bar = '█' * bar_len
            severity_text += f"  {s['severity_label']:8s} │ {bar} {s['count']}\n"

        # Recent alerts
        recent_text = ""
        for a in alerts[:10]:
            recent_text += f"  [{a.get('severity_label', '?'):6s}] {a.get('timestamp', '')[:19]} | {a.get('signature', 'Unknown')[:50]}\n"

        return f"""
╔═══════════════════════════════════════════════════════════════╗
║              SECURITY SUMMARY REPORT                          ║
║              AI-Powered Network Intrusion Detection System    ║
╚═══════════════════════════════════════════════════════════════╝

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Report Type: Aggregate Summary

=====================================
OVERALL STATISTICS
=====================================
Total Alerts:       {stats['total']}
High Severity:      {stats['high']}
Medium Severity:    {stats['medium']}
Low Severity:       {stats['low']}
Alerts (24h):       {stats['recent_24h']}
Alerts (1h):        {stats['recent_1h']}
AI Analyzed:        {stats['analyzed']}

=====================================
SEVERITY DISTRIBUTION
=====================================
{severity_text}
=====================================
TOP SOURCE IPs
=====================================
{top_ips_text}
=====================================
TOP ATTACK TYPES
=====================================
{attack_types_text}
=====================================
RECENT ALERTS (Last 10)
=====================================
{recent_text}
=====================================
RECOMMENDATIONS
=====================================
1. Investigate high-severity alerts immediately
2. Block or monitor top source IPs showing malicious patterns
3. Review and update Suricata rulesets
4. Run AI analysis on unanalyzed alerts for deeper insights
5. Schedule regular security assessments

=====================================
END OF REPORT
=====================================
"""

    def format_for_download(self, report):
        """
        Format a report for text file download.

        Args:
            report: Report dictionary

        Returns:
            Plain text string suitable for saving as .txt
        """
        return report.get('content', 'No report content available.')
