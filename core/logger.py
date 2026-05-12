#!/usr/bin/env python3
"""
NetSentinel - Logger
Handles logging of alerts and traffic statistics.
"""

import os
import json
from datetime import datetime


class Logger:
    def __init__(self, log_path="logs/netsentinel.log"):
        self.log_path = log_path
        self.alert_count = 0

        # Create logs directory if not exists
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        # Write session header
        self._write(f"\n{'='*60}")
        self._write(f"NetSentinel Session Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self._write(f"{'='*60}\n")

    def _write(self, message):
        """Writes a message to the log file."""
        try:
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(message + '\n')
        except Exception as e:
            print(f"[!] Log write error: {e}")

    def log_alert(self, alert):
        """Logs an alert to file."""
        self.alert_count += 1
        log_line = (
            f"[{alert['time']}] "
            f"[{alert['severity']}] "
            f"ALERT #{alert['id']} | "
            f"{alert['type']} | "
            f"{alert['src_ip']} -> {alert['dst_ip']} | "
            f"{alert['details']}"
        )
        self._write(log_line)

    def log_info(self, message):
        """Logs an informational message."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self._write(f"[{timestamp}] [INFO] {message}")

    def log_summary(self, stats):
        """Logs session summary."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self._write(f"\n{'='*60}")
        self._write(f"Session Summary: {timestamp}")
        self._write(f"Total Packets : {stats.get('total_packets', 0)}")
        self._write(f"Total Alerts  : {self.alert_count}")
        self._write(f"{'='*60}\n")

    def get_log_path(self):
        return self.log_path