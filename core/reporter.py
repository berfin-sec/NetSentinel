#!/usr/bin/env python3
"""
NetSentinel - Reporter
Generates HTML reports from detection results.
"""

import os
from datetime import datetime


class Reporter:
    def __init__(self, detector, logger):
        self.detector = detector
        self.logger = logger

    def generate_html(self, output_dir="reports"):
        """Generates an HTML report."""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = os.path.join(output_dir, f"report_{timestamp}.html")

        alerts = self.detector.alerts
        stats = self.detector.stats

        # Severity colors
        severity_colors = {
            'LOW': '#3498db',
            'MEDIUM': '#f39c12',
            'HIGH': '#e67e22',
            'CRITICAL': '#e74c3c'
        }

        # Build alerts table rows
        alert_rows = ""
        for alert in alerts:
            color = severity_colors.get(alert['severity'], '#95a5a6')
            alert_rows += f"""
            <tr>
                <td>{alert['id']}</td>
                <td>{alert['time']}</td>
                <td><span class="badge" style="background:{color}">{alert['severity']}</span></td>
                <td><strong>{alert['type']}</strong></td>
                <td>{alert['src_ip']}</td>
                <td>{alert['dst_ip']}</td>
                <td>{alert['details']}</td>
            </tr>"""

        # Build top talkers rows
        talker_rows = ""
        for ip, count in stats['top_talkers'].most_common(10):
            talker_rows += f"<tr><td>{ip}</td><td>{count:,}</td></tr>"

        # Build alert type rows
        alert_type_rows = ""
        for alert_type, count in stats['alerts'].most_common():
            color = '#e74c3c' if count > 5 else '#f39c12'
            alert_type_rows += f"<tr><td>{alert_type}</td><td style='color:{color}'><strong>{count}</strong></td></tr>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetSentinel Report - {timestamp}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #0a0e1a; color: #e0e0e0; }}
        .header {{ background: linear-gradient(135deg, #1a1f35, #0d1117); padding: 30px; border-bottom: 2px solid #e74c3c; }}
        .header h1 {{ color: #e74c3c; font-size: 2em; }}
        .header p {{ color: #888; margin-top: 5px; }}
        .container {{ max-width: 1200px; margin: 30px auto; padding: 0 20px; }}
        .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: #1a1f35; border-radius: 10px; padding: 20px; text-align: center; border: 1px solid #2a3050; }}
        .card .number {{ font-size: 2.5em; font-weight: bold; color: #e74c3c; }}
        .card .label {{ color: #888; margin-top: 5px; font-size: 0.9em; }}
        .section {{ background: #1a1f35; border-radius: 10px; padding: 20px; margin-bottom: 25px; border: 1px solid #2a3050; }}
        .section h2 {{ color: #e74c3c; margin-bottom: 15px; font-size: 1.2em; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #0d1117; color: #e74c3c; padding: 10px; text-align: left; font-size: 0.85em; }}
        td {{ padding: 10px; border-bottom: 1px solid #2a3050; font-size: 0.85em; }}
        tr:hover {{ background: #212840; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; color: white; font-size: 0.75em; font-weight: bold; }}
        .no-alerts {{ color: #2ecc71; text-align: center; padding: 30px; font-size: 1.1em; }}
        .footer {{ text-align: center; color: #444; padding: 20px; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ NetSentinel IDS Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 
           Total Packets: {stats['total_packets']:,} | 
           Total Alerts: {len(alerts)}</p>
    </div>

    <div class="container">
        <div class="cards">
            <div class="card">
                <div class="number">{stats['total_packets']:,}</div>
                <div class="label">Total Packets</div>
            </div>
            <div class="card">
                <div class="number">{len(alerts)}</div>
                <div class="label">Total Alerts</div>
            </div>
            <div class="card">
                <div class="number">{stats['tcp_packets']:,}</div>
                <div class="label">TCP Packets</div>
            </div>
            <div class="card">
                <div class="number">{stats['udp_packets']:,}</div>
                <div class="label">UDP Packets</div>
            </div>
        </div>

        <div class="section">
            <h2>🚨 Alerts</h2>
            {"<table><tr><th>#</th><th>Time</th><th>Severity</th><th>Type</th><th>Source IP</th><th>Destination</th><th>Details</th></tr>" + alert_rows + "</table>" if alerts else '<div class="no-alerts">✅ No threats detected!</div>'}
        </div>

        <div class="section">
            <h2>📊 Alert Types</h2>
            {"<table><tr><th>Type</th><th>Count</th></tr>" + alert_type_rows + "</table>" if alert_type_rows else '<div class="no-alerts">✅ No alerts triggered</div>'}
        </div>

        <div class="section">
            <h2>📡 Top 10 Most Active IPs</h2>
            {"<table><tr><th>IP Address</th><th>Packet Count</th></tr>" + talker_rows + "</table>" if talker_rows else '<p style="color:#888">No data available</p>'}
        </div>

        <div class="section">
            <h2>📈 Traffic Breakdown</h2>
            <table>
                <tr><th>Protocol</th><th>Packets</th></tr>
                <tr><td>TCP</td><td>{stats['tcp_packets']:,}</td></tr>
                <tr><td>UDP</td><td>{stats['udp_packets']:,}</td></tr>
                <tr><td>ICMP</td><td>{stats['icmp_packets']:,}</td></tr>
                <tr><td>ARP</td><td>{stats['arp_packets']:,}</td></tr>
            </table>
        </div>
    </div>

    <div class="footer">
        <p>NetSentinel IDS v1.0 | github.com/berfin-sec/NetSentinel</p>
    </div>
</body>
</html>"""

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)

        return report_path