"""
suricata_monitor.py - Suricata Log Monitor for AI-NIDS

Monitors Suricata's eve.json log file in real time, parsing
alert events and inserting them into the SQLite database.
Also provides sample data generation for demo/testing.
"""

import json
import os
import time
import threading
import logging
import random
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class SuricataMonitor:
    """Monitors Suricata eve.json logs and processes alert events."""

    # Suricata severity mapping (1=High, 2=Medium, 3=Low)
    SEVERITY_MAP = {
        1: 'High',
        2: 'Medium',
        3: 'Low'
    }

    def __init__(self, eve_path, db):
        """
        Initialize the Suricata monitor.

        Args:
            eve_path: Path to Suricata's eve.json file
            db: Database instance for storing alerts
        """
        self.eve_path = eve_path
        self.db = db
        self._running = False
        self._thread = None
        self._file_position = 0

    def start(self):
        """Start monitoring eve.json in a background thread."""
        if self._running:
            logger.warning("Monitor already running")
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info(f"Suricata monitor started, watching: {self.eve_path}")

    def stop(self):
        """Stop the monitoring thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Suricata monitor stopped")

    def _monitor_loop(self):
        """Main monitoring loop — tails eve.json continuously."""
        while self._running:
            try:
                if not os.path.exists(self.eve_path):
                    time.sleep(2)
                    continue

                with open(self.eve_path, 'r', encoding='utf-8', errors='ignore') as f:
                    # Seek to last known position
                    f.seek(self._file_position)

                    while self._running:
                        line = f.readline()
                        if not line:
                            # No new data — wait and retry
                            time.sleep(1)
                            # Check for file rotation
                            try:
                                current_size = os.path.getsize(self.eve_path)
                                if current_size < self._file_position:
                                    logger.info("Detected eve.json rotation, resetting position")
                                    self._file_position = 0
                                    break
                            except OSError:
                                break
                            continue

                        self._file_position = f.tell()
                        line = line.strip()
                        if line:
                            self._process_line(line)

            except FileNotFoundError:
                logger.debug(f"eve.json not found at {self.eve_path}, waiting...")
                time.sleep(5)
            except PermissionError:
                logger.error(f"Permission denied reading {self.eve_path}")
                time.sleep(10)
            except Exception as e:
                logger.error(f"Monitor error: {e}")
                time.sleep(5)

    def _process_line(self, line):
        """
        Parse a single eve.json line and insert alert events.

        Args:
            line: Raw JSON line from eve.json
        """
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            logger.debug(f"Skipping malformed JSON line")
            return

        # Only process alert events
        event_type = event.get('event_type', '')
        if event_type != 'alert':
            return

        alert = self._parse_event(event)
        if alert:
            try:
                alert_id = self.db.insert_alert(alert)
                logger.info(f"Inserted alert #{alert_id}: {alert['signature']}")
            except Exception as e:
                logger.error(f"Failed to insert alert: {e}")

    def _parse_event(self, event):
        """
        Extract alert fields from a Suricata eve.json event.

        Args:
            event: Parsed JSON event dictionary

        Returns:
            Normalized alert dictionary or None
        """
        alert_data = event.get('alert', {})
        if not alert_data:
            return None

        severity = alert_data.get('severity', 3)
        severity = max(1, min(3, severity))  # Clamp to 1-3

        return {
            'timestamp': event.get('timestamp', datetime.now().isoformat()),
            'src_ip': event.get('src_ip', ''),
            'dest_ip': event.get('dest_ip', ''),
            'src_port': event.get('src_port', 0),
            'dest_port': event.get('dest_port', 0),
            'protocol': event.get('proto', ''),
            'signature': alert_data.get('signature', 'Unknown'),
            'signature_id': alert_data.get('signature_id', 0),
            'severity': severity,
            'severity_label': self.SEVERITY_MAP.get(severity, 'Low'),
            'category': alert_data.get('category', 'Unknown'),
            'raw_json': json.dumps(event)
        }





class PacketSniffer:
    """
    Built-in Python packet sniffer that logs alerts to eve.json in real-time.
    If raw socket/Scapy captures are unavailable, falls back to a live network activity generator.
    """

    def __init__(self, eve_path):
        """
        Initialize the packet sniffer.

        Args:
            eve_path: Path to write Suricata-style log events (eve.json)
        """
        self.eve_path = eve_path
        self._running = False
        self._thread = None
        self.lock = threading.Lock()

        # Threat detection state for live capture
        self.port_scan_tracker = {}  # src_ip -> set(ports)
        self.port_scan_time = {}    # src_ip -> float
        self.ssh_tracker = {}        # src_ip -> list(timestamps)

    def start(self):
        """Start the sniffing thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("Internal Packet Sniffer started")

    def stop(self):
        """Stop the sniffing thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("Internal Packet Sniffer stopped")

    def _run(self):
        """Main sniffer thread entry point. Performs live network sniffing using Scapy."""
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP
            logger.info("Scapy library imported successfully. Testing live sniffing capability...")
            
            # Test sniff with short timeout to verify raw sockets permissions
            sniff(filter="ip", count=1, timeout=0.5, store=0)
            
            self._live_sniff_loop()
        except ImportError:
            logger.error("Scapy library not found. Please install it. Disabling packet sniffer.")
        except Exception as e:
            logger.error(f"Live sniffing failed (requires Administrator/root or Npcap): {e}. Disabling packet sniffer.")

    def _live_sniff_loop(self):
        """Sniffs live network packets using Scapy."""
        from scapy.all import sniff, IP, TCP, UDP, ICMP

        def packet_callback(packet):
            if not self._running:
                return
            if not packet.haslayer(IP):
                return

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dest_ip = ip_layer.dst
            proto = "TCP" if packet.haslayer(TCP) else ("UDP" if packet.haslayer(UDP) else ("ICMP" if packet.haslayer(ICMP) else ""))

            src_port = 0
            dest_port = 0

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dest_port = tcp_layer.dport
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dest_port = udp_layer.dport

            # Run detection rules
            self._check_rules(src_ip, dest_ip, src_port, dest_port, proto)

        try:
            while self._running:
                sniff(prn=packet_callback, filter="ip", store=0, count=20, timeout=1.5)
        except Exception as e:
            logger.error(f"Live sniffing loop error: {e}. Packet sniffer stopped.")



    def _check_rules(self, src_ip, dest_ip, src_port, dest_port, proto):
        """Inspects network events against rules."""
        # 1. ICMP Ping Detection
        if proto == "ICMP":
            self._trigger_alert(
                src_ip=src_ip,
                dest_ip=dest_ip,
                src_port=0,
                dest_port=0,
                proto=proto,
                signature="GPL ICMP Information Request",
                sig_id=2100466,
                severity=3,
                category="Misc activity"
            )
            return

        now = time.time()

        # 2. SSH Access / Potential Brute Force
        if proto == "TCP" and dest_port == 22:
            ssh_attempts = self.ssh_tracker.get(src_ip, [])
            ssh_attempts = [t for t in ssh_attempts if now - t < 10]
            ssh_attempts.append(now)
            self.ssh_tracker[src_ip] = ssh_attempts

            if len(ssh_attempts) >= 3:
                self._trigger_alert(
                    src_ip=src_ip,
                    dest_ip=dest_ip,
                    src_port=src_port,
                    dest_port=22,
                    proto=proto,
                    signature="ET SCAN Rapid SSH Connection Attempts",
                    sig_id=2019876,
                    severity=1,
                    category="Attempted Administrator Privilege Gain"
                )
                self.ssh_tracker[src_ip] = []  # Reset

        # 3. Port Scanning Detection (e.g. Nmap)
        if proto in ("TCP", "UDP") and dest_port != 0:
            # Skip multicast, broadcast, or link-local traffic
            if dest_ip.startswith("224.") or dest_ip.startswith("239.") or dest_ip == "255.255.255.255":
                return
            
            # Skip if destination port is an ephemeral port (typically client traffic replies from Google, CDNs, etc.)
            # Real port scans target well-known listening service ports (< 1024) or specific database/RDP/VNC ports.
            common_scan_ports = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443}
            if dest_port >= 1024 and dest_port not in common_scan_ports:
                return

            # Skip common Google IP ranges to prevent false alerts from safe browsing/API calls
            google_prefixes = ("64.233.", "72.14.", "74.125.", "108.177.", "142.250.", "142.251.", "172.217.", "173.194.", "209.85.", "216.58.", "216.239.")
            if src_ip.startswith(google_prefixes) or dest_ip.startswith(google_prefixes):
                return

            scan_ports = self.port_scan_tracker.get(src_ip, set())
            last_time = self.port_scan_time.get(src_ip, now)

            if now - last_time > 10:
                scan_ports = set()

            scan_ports.add(dest_port)
            self.port_scan_tracker[src_ip] = scan_ports
            self.port_scan_time[src_ip] = now

            if len(scan_ports) >= 5:
                self._trigger_alert(
                    src_ip=src_ip,
                    dest_ip=dest_ip,
                    src_port=src_port,
                    dest_port=dest_port,
                    proto=proto,
                    signature="ET SCAN Potential Nmap SYN Scan",
                    sig_id=2009582,
                    severity=2,
                    category="Attempted Information Leak"
                )
                self.port_scan_tracker[src_ip] = set()  # Reset

    def _trigger_alert(self, src_ip, dest_ip, src_port, dest_port, proto, signature, sig_id, severity, category):
        """Creates and appends an alert to eve.json."""
        event = {
            "timestamp": datetime.now().isoformat() + "+00:00",
            "flow_id": random.randint(100000000000000, 999999999999999),
            "event_type": "alert",
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "src_port": src_port,
            "dest_port": dest_port,
            "proto": proto.upper(),
            "alert": {
                "action": "allowed",
                "signature_id": sig_id,
                "signature": signature,
                "category": category,
                "severity": severity
            }
        }

        with self.lock:
            try:
                os.makedirs(os.path.dirname(self.eve_path), exist_ok=True)
                with open(self.eve_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event) + "\n")
                logger.info(f"[Live Packet Sniffer] Generated alert in eve.json: {signature}")
            except Exception as e:
                logger.error(f"Failed to append sniffer alert to eve.json: {e}")
