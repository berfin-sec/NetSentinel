#!/usr/bin/env python3
"""
NetSentinel - Real-time Network Intrusion Detection System (IDS)
Monitors network traffic and detects attacks in real-time.
WARNING: Use only on networks you are authorized to monitor.
Requirement: pip install scapy colorama
"""

import sys
import time
import argparse
import threading
from datetime import datetime
from collections import defaultdict, Counter

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw
    from scapy.layers.http import HTTPRequest
except ImportError:
    print("[!] Scapy is not installed. Run: pip install scapy")
    sys.exit(1)

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False

from core.detector import ThreatDetector
from core.logger import Logger
from core.reporter import Reporter
from core.config import Config


def banner():
    b = """
███╗   ██╗███████╗████████╗    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
██╔██╗ ██║█████╗     ██║       ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
██║╚██╗██║██╔══╝     ██║       ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
██║ ╚████║███████╗   ██║       ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
    """
    print(b)
    print("  Real-time Network Intrusion Detection System v1.0")
    print("  WARNING: Use only on networks you are authorized to monitor.\n")


def main():
    parser = argparse.ArgumentParser(
        description="NetSentinel - Real-time IDS",
        epilog=(
            "Examples:\n"
            "  python netsentinel.py\n"
            "  python netsentinel.py -i eth0\n"
            "  python netsentinel.py -i eth0 --report\n"
            "  python netsentinel.py --config rules/custom.json"
        )
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface (default: auto)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (default: unlimited)")
    parser.add_argument("--config", default="rules/config.json",
                        help="Config file path (default: rules/config.json)")
    parser.add_argument("--report", action="store_true",
                        help="Generate HTML report after capture")
    parser.add_argument("--log", default="logs/netsentinel.log",
                        help="Log file path (default: logs/netsentinel.log)")

    args = parser.parse_args()

    banner()

    # Load config
    config = Config(args.config)

    # Initialize components
    logger = Logger(args.log)
    detector = ThreatDetector(config, logger)
    reporter = Reporter(detector, logger)

    print(f"[*] Interface  : {args.interface or 'auto'}")
    print(f"[*] Config     : {args.config}")
    print(f"[*] Log file   : {args.log}")
    print(f"[*] Started    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Monitoring... (Ctrl+C to stop)\n")
    print("-" * 70)

    try:
        sniff(
            iface=args.interface,
            prn=detector.process_packet,
            count=args.count,
            store=False
        )
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[!] Error: {e}")
        print("[!] Try running as administrator/root.")
        sys.exit(1)

    print("\n" + "-" * 70)
    detector.print_summary()

    if args.report:
        report_path = reporter.generate_html()
        print(f"\n[OK] Report saved: {report_path}")


if __name__ == "__main__":
    main()