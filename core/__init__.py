#!/usr/bin/env python3
"""
NetSentinel - Threat Detector
Core detection engine for identifying network attacks.
"""

import time
from datetime import datetime
from collections import defaultdict, Counter


class ThreatDetector:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

        # Traffic counters
        self.packet_count = 0
        self.alert_count = 0
        self.start_time = time.time()

        # IP tracking
        self.syn_tracker = defaultdict(list)        # IP -> [timestamps]
        self.icmp_tracker = defaultdict(list)       # IP -> [timestamps]
        self.port_scan_tracker = defaultdict(set)   # IP -> {ports}
        self.brute_force_tracker = defaultdict(list) # IP -> [timestamps]
        self.arp_table = {}                          # IP -> MAC
        self.dns_tracker = defaultdict(list)        # IP -> [queries]

        # Statistics
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'arp_packets': 0,
            'alerts': Counter(),
            'top_talkers': Counter(),
            'blocked_ips': set(),
        }

        # Alerts list
        self.alerts = []

    def process_packet(self, packet):
        """Main packet processing function."""
        self.stats['total_packets'] += 1

        try:
            # ARP packets
            if packet.haslayer('ARP'):
                self.stats['arp_packets'] += 1
                self._check_arp_spoofing(packet)

            # IP packets
            if packet.haslayer('IP'):
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                self.stats['top_talkers'][src_ip] += 1

                # TCP
                if packet.haslayer('TCP'):
                    self.stats['tcp_packets'] += 1
                    self._check_syn_flood(packet, src_ip, dst_ip)
                    self._check_port_scan(packet, src_ip, dst_ip)
                    self._check_brute_force(packet, src_ip, dst_ip)

                # UDP
                elif packet.haslayer('UDP'):
                    self.stats['udp_packets'] += 1
                    self._check_dns_anomaly(packet, src_ip)

                # ICMP
                elif packet.haslayer('ICMP'):
                    self.stats['icmp_packets'] += 1
                    self._check_icmp_flood(packet, src_ip, dst_ip)

        except Exception:
            pass

    def _alert(self, alert_type, src_ip, dst_ip, details, severity="MEDIUM"):
        """Creates and logs an alert."""
        self.alert_count += 1
        self.stats['alerts'][alert_type] += 1

        alert = {
            'id': self.alert_count,
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': alert_type,
            'severity': severity,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'details': details,
        }
        self.alerts.append(alert)

        # Severity colors
        severity_icons = {
            'LOW': '[!]',
            'MEDIUM': '[!!]',
            'HIGH': '[!!!]',
            'CRITICAL': '[CRITICAL]'
        }
        icon = severity_icons.get(severity, '[!]')

        msg = (f"{icon} ALERT #{self.alert_count} | {alert_type} | "
               f"{src_ip} -> {dst_ip} | {details}")
        print(msg)
        self.logger.log_alert(alert)

    def _check_syn_flood(self, packet, src_ip, dst_ip):
        """Detects SYN flood attacks."""
        if packet['TCP'].flags == 'S':  # SYN flag
            now = time.time()
            self.syn_tracker[src_ip].append(now)

            # Keep only last 10 seconds
            self.syn_tracker[src_ip] = [
                t for t in self.syn_tracker[src_ip]
                if now - t < self.config.get('syn_window', 10)
            ]

            threshold = self.config.get('syn_threshold', 100)
            if len(self.syn_tracker[src_ip]) >= threshold:
                self._alert(
                    "SYN FLOOD",
                    src_ip, dst_ip,
                    f"{len(self.syn_tracker[src_ip])} SYN packets in 10 seconds",
                    "CRITICAL"
                )
                self.syn_tracker[src_ip] = []  # Reset after alert

    def _check_port_scan(self, packet, src_ip, dst_ip):
        """Detects port scanning."""
        if packet['TCP'].flags in ['S', 'F', 'N']:  # SYN, FIN, NULL
            dst_port = packet['TCP'].dport
            self.port_scan_tracker[src_ip].add(dst_port)

            threshold = self.config.get('port_scan_threshold', 20)
            if len(self.port_scan_tracker[src_ip]) >= threshold:
                self._alert(
                    "PORT SCAN",
                    src_ip, dst_ip,
                    f"{len(self.port_scan_tracker[src_ip])} unique ports scanned",
                    "HIGH"
                )
                self.port_scan_tracker[src_ip] = set()  # Reset after alert

    def _check_brute_force(self, packet, src_ip, dst_ip):
        """Detects brute-force attacks on common ports."""
        brute_force_ports = self.config.get('brute_force_ports', [22, 21, 3389, 5900, 23])
        dst_port = packet['TCP'].dport

        if dst_port in brute_force_ports and packet['TCP'].flags == 'S':
            now = time.time()
            self.brute_force_tracker[src_ip].append(now)

            # Keep only last 60 seconds
            self.brute_force_tracker[src_ip] = [
                t for t in self.brute_force_tracker[src_ip]
                if now - t < self.config.get('brute_force_window', 60)
            ]

            threshold = self.config.get('brute_force_threshold', 10)
            if len(self.brute_force_tracker[src_ip]) >= threshold:
                service = {22: 'SSH', 21: 'FTP', 3389: 'RDP',
                          5900: 'VNC', 23: 'Telnet'}.get(dst_port, str(dst_port))
                self._alert(
                    "BRUTE FORCE",
                    src_ip, dst_ip,
                    f"{len(self.brute_force_tracker[src_ip])} attempts on {service} port {dst_port}",
                    "HIGH"
                )
                self.brute_force_tracker[src_ip] = []

    def _check_icmp_flood(self, packet, src_ip, dst_ip):
        """Detects ICMP flood (Ping of Death / Ping Flood)."""
        now = time.time()
        self.icmp_tracker[src_ip].append(now)

        self.icmp_tracker[src_ip] = [
            t for t in self.icmp_tracker[src_ip]
            if now - t < self.config.get('icmp_window', 10)
        ]

        threshold = self.config.get('icmp_threshold', 50)
        if len(self.icmp_tracker[src_ip]) >= threshold:
            self._alert(
                "ICMP FLOOD",
                src_ip, dst_ip,
                f"{len(self.icmp_tracker[src_ip])} ICMP packets in 10 seconds",
                "HIGH"
            )
            self.icmp_tracker[src_ip] = []

    def _check_arp_spoofing(self, packet, ):
        """Detects ARP spoofing attacks."""
        if packet['ARP'].op == 2:  # ARP reply
            src_ip = packet['ARP'].psrc
            src_mac = packet['ARP'].hwsrc

            if src_ip in self.arp_table:
                if self.arp_table[src_ip] != src_mac:
                    self._alert(
                        "ARP SPOOFING",
                        src_ip, "broadcast",
                        f"MAC changed: {self.arp_table[src_ip]} -> {src_mac}",
                        "CRITICAL"
                    )
            else:
                self.arp_table[src_ip] = src_mac

    def _check_dns_anomaly(self, packet, src_ip):
        """Detects DNS anomalies."""
        if packet.haslayer('DNS') and packet['DNS'].qr == 0:
            try:
                query = packet['DNS'].qd.qname.decode(errors='replace').rstrip('.')
                now = time.time()
                self.dns_tracker[src_ip].append(now)

                self.dns_tracker[src_ip] = [
                    t for t in self.dns_tracker[src_ip]
                    if now - t < self.config.get('dns_window', 10)
                ]

                threshold = self.config.get('dns_threshold', 50)
                if len(self.dns_tracker[src_ip]) >= threshold:
                    self._alert(
                        "DNS FLOOD",
                        src_ip, "DNS server",
                        f"{len(self.dns_tracker[src_ip])} DNS queries in 10 seconds",
                        "MEDIUM"
                    )
                    self.dns_tracker[src_ip] = []
            except Exception:
                pass

    def print_summary(self):
        """Prints detection summary."""
        elapsed = time.time() - self.start_time
        print(f"\n{'='*60}")
        print(f"  NETSENTINEL SUMMARY")
        print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}")
        print(f"\n[*] TRAFFIC STATISTICS")
        print(f"  Total packets  : {self.stats['total_packets']:,}")
        print(f"  TCP packets    : {self.stats['tcp_packets']:,}")
        print(f"  UDP packets    : {self.stats['udp_packets']:,}")
        print(f"  ICMP packets   : {self.stats['icmp_packets']:,}")
        print(f"  ARP packets    : {self.stats['arp_packets']:,}")
        print(f"  Duration       : {elapsed:.1f} seconds")

        if self.alerts:
            print(f"\n[!!!] ALERTS TRIGGERED ({len(self.alerts)} total)")
            for alert_type, count in self.stats['alerts'].most_common():
                print(f"  {alert_type:<20}: {count} alerts")
        else:
            print(f"\n[OK] No threats detected.")

        if self.stats['top_talkers']:
            print(f"\n[*] TOP 5 TALKERS")
            for ip, count in self.stats['top_talkers'].most_common(5):
                print(f"  {ip:<20}: {count:,} packets")

        print(f"\n{'='*60}\n")