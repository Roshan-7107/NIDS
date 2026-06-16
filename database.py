"""
database.py - SQLite Database Layer for AI-NIDS

Provides thread-safe database operations for storing and retrieving
Suricata alerts, AI analyses, and incident reports.
All queries use parameterized statements to prevent SQL injection.
"""

import sqlite3
import threading
import os
from datetime import datetime, timedelta


class Database:
    """Thread-safe SQLite database manager for the AI-NIDS system."""

    def __init__(self, db_path=None):
        """
        Initialize the database connection.

        Args:
            db_path: Path to SQLite database file. Defaults to ./database/alerts.db
        """
        if db_path is None:
            db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database', 'alerts.db')
        self.db_path = db_path
        self.lock = threading.Lock()

        # Ensure database directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

    def _get_connection(self):
        """Create a new database connection for the current thread."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def init_db(self):
        """Create database tables if they don't exist."""
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()

                # Alerts table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        src_ip TEXT,
                        dest_ip TEXT,
                        src_port INTEGER,
                        dest_port INTEGER,
                        protocol TEXT,
                        signature TEXT,
                        signature_id INTEGER,
                        severity INTEGER DEFAULT 3,
                        severity_label TEXT DEFAULT 'Low',
                        category TEXT,
                        raw_json TEXT,
                        ai_analysis TEXT,
                        analyzed_at TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Reports table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS reports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL,
                        report_type TEXT DEFAULT 'incident',
                        content TEXT,
                        alert_ids TEXT,
                        severity_summary TEXT,
                        total_alerts INTEGER DEFAULT 0,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Indexes for performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_signature_id ON alerts(signature_id)')

                conn.commit()
            finally:
                conn.close()

    def insert_alert(self, alert):
        """
        Insert a new alert into the database.

        Args:
            alert: Dictionary with alert fields

        Returns:
            The ID of the inserted alert
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO alerts (timestamp, src_ip, dest_ip, src_port, dest_port,
                                       protocol, signature, signature_id, severity,
                                       severity_label, category, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert.get('timestamp', datetime.now().isoformat()),
                    alert.get('src_ip', ''),
                    alert.get('dest_ip', ''),
                    alert.get('src_port', 0),
                    alert.get('dest_port', 0),
                    alert.get('protocol', ''),
                    alert.get('signature', ''),
                    alert.get('signature_id', 0),
                    alert.get('severity', 3),
                    alert.get('severity_label', 'Low'),
                    alert.get('category', 'Unknown'),
                    alert.get('raw_json', '{}')
                ))
                conn.commit()
                return cursor.lastrowid
            finally:
                conn.close()

    def get_alerts(self, limit=50, offset=0, severity=None, search=None):
        """
        Retrieve alerts with optional filtering and pagination.

        Args:
            limit: Maximum number of results
            offset: Pagination offset
            severity: Filter by severity level (1, 2, or 3)
            search: Search term for signature/category

        Returns:
            List of alert dictionaries
        """
        with self.lock:
            conn = self._get_connection()
            try:
                query = 'SELECT * FROM alerts WHERE 1=1'
                params = []

                if severity is not None:
                    query += ' AND severity = ?'
                    params.append(severity)

                if search:
                    query += ' AND (signature LIKE ? OR category LIKE ? OR src_ip LIKE ?)'
                    search_term = f'%{search}%'
                    params.extend([search_term, search_term, search_term])

                query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
                params.extend([limit, offset])

                cursor = conn.cursor()
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()

    def get_alert_by_id(self, alert_id):
        """
        Retrieve a single alert by ID.

        Args:
            alert_id: The alert's database ID

        Returns:
            Alert dictionary or None
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM alerts WHERE id = ?', (alert_id,))
                row = cursor.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def get_dashboard_stats(self):
        """
        Get aggregate statistics for the dashboard.

        Returns:
            Dictionary with total, severity counts, and recent counts
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()

                # Total alerts
                cursor.execute('SELECT COUNT(*) as total FROM alerts')
                total = cursor.fetchone()['total']

                # By severity
                cursor.execute('''
                    SELECT severity, severity_label, COUNT(*) as count
                    FROM alerts GROUP BY severity ORDER BY severity
                ''')
                severity_counts = {row['severity_label']: row['count'] for row in cursor.fetchall()}

                # Recent 24 hours
                yesterday = (datetime.now() - timedelta(days=1)).isoformat()
                cursor.execute('SELECT COUNT(*) as count FROM alerts WHERE timestamp > ?', (yesterday,))
                recent_24h = cursor.fetchone()['count']

                # Recent 1 hour
                one_hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
                cursor.execute('SELECT COUNT(*) as count FROM alerts WHERE timestamp > ?', (one_hour_ago,))
                recent_1h = cursor.fetchone()['count']

                # Analyzed count
                cursor.execute('SELECT COUNT(*) as count FROM alerts WHERE ai_analysis IS NOT NULL')
                analyzed = cursor.fetchone()['count']

                return {
                    'total': total,
                    'high': severity_counts.get('High', 0),
                    'medium': severity_counts.get('Medium', 0),
                    'low': severity_counts.get('Low', 0),
                    'recent_24h': recent_24h,
                    'recent_1h': recent_1h,
                    'analyzed': analyzed
                }
            finally:
                conn.close()

    def get_top_source_ips(self, limit=10):
        """
        Get the top source IPs by alert count.

        Args:
            limit: Number of top IPs to return

        Returns:
            List of dicts with ip and count
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT src_ip as ip, COUNT(*) as count
                    FROM alerts
                    WHERE src_ip IS NOT NULL AND src_ip != ''
                    GROUP BY src_ip
                    ORDER BY count DESC
                    LIMIT ?
                ''', (limit,))
                return [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()

    def get_severity_distribution(self):
        """
        Get alert counts grouped by severity.

        Returns:
            List of dicts with severity_label and count
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT severity_label, COUNT(*) as count
                    FROM alerts
                    GROUP BY severity_label
                    ORDER BY severity
                ''')
                return [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()

    def get_attack_type_stats(self, limit=10):
        """
        Get alert counts grouped by attack category.

        Args:
            limit: Number of top categories to return

        Returns:
            List of dicts with category and count
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT category, COUNT(*) as count
                    FROM alerts
                    WHERE category IS NOT NULL AND category != '' AND category != 'Unknown'
                    GROUP BY category
                    ORDER BY count DESC
                    LIMIT ?
                ''', (limit,))
                return [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()

    def get_timeline_data(self, days=7):
        """
        Get alert counts grouped by date for timeline charts.

        Args:
            days: Number of days to look back

        Returns:
            List of dicts with date and count
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                start_date = (datetime.now() - timedelta(days=days)).isoformat()
                cursor.execute('''
                    SELECT DATE(timestamp) as date, COUNT(*) as count
                    FROM alerts
                    WHERE timestamp > ?
                    GROUP BY DATE(timestamp)
                    ORDER BY date
                ''', (start_date,))
                return [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()

    def update_ai_analysis(self, alert_id, analysis_text):
        """
        Store the AI analysis result for an alert.

        Args:
            alert_id: The alert's database ID
            analysis_text: The Llama 3 analysis text
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE alerts SET ai_analysis = ?, analyzed_at = ?
                    WHERE id = ?
                ''', (analysis_text, datetime.now().isoformat(), alert_id))
                conn.commit()
            finally:
                conn.close()

    def get_recent_alerts(self, limit=10):
        """
        Get the most recent alerts.

        Args:
            limit: Number of recent alerts to return

        Returns:
            List of alert dictionaries
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM alerts
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (limit,))
                return [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()

    def get_alerts_count(self, severity=None, search=None):
        """Get total count of alerts with optional filters."""
        with self.lock:
            conn = self._get_connection()
            try:
                query = 'SELECT COUNT(*) as count FROM alerts WHERE 1=1'
                params = []

                if severity is not None:
                    query += ' AND severity = ?'
                    params.append(severity)

                if search:
                    query += ' AND (signature LIKE ? OR category LIKE ? OR src_ip LIKE ?)'
                    search_term = f'%{search}%'
                    params.extend([search_term, search_term, search_term])

                cursor = conn.cursor()
                cursor.execute(query, params)
                return cursor.fetchone()['count']
            finally:
                conn.close()

    def save_report(self, report):
        """
        Save a generated incident report.

        Args:
            report: Dictionary with report fields

        Returns:
            The ID of the saved report
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO reports (title, report_type, content, alert_ids,
                                        severity_summary, total_alerts)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    report.get('title', 'Incident Report'),
                    report.get('report_type', 'incident'),
                    report.get('content', ''),
                    report.get('alert_ids', ''),
                    report.get('severity_summary', ''),
                    report.get('total_alerts', 0)
                ))
                conn.commit()
                return cursor.lastrowid
            finally:
                conn.close()

    def get_reports(self, limit=20):
        """
        Retrieve generated reports.

        Args:
            limit: Maximum number of reports

        Returns:
            List of report dictionaries
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM reports
                    ORDER BY created_at DESC
                    LIMIT ?
                ''', (limit,))
                return [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()

    def get_report_by_id(self, report_id):
        """
        Retrieve a single report by ID.

        Args:
            report_id: The report's database ID

        Returns:
            Report dictionary or None
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM reports WHERE id = ?', (report_id,))
                row = cursor.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()
