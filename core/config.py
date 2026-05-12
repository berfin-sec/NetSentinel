#!/usr/bin/env python3
"""
NetSentinel - Config
Handles configuration loading and default values.
"""

import json
import os


# Default configuration
DEFAULT_CONFIG = {
    # SYN Flood detection
    "syn_threshold": 100,       # SYN packets per window to trigger alert
    "syn_window": 10,           # Time window in seconds

    # Port scan detection
    "port_scan_threshold": 20,  # Unique ports to trigger alert

    # Brute force detection
    "brute_force_threshold": 10,  # Connection attempts to trigger alert
    "brute_force_window": 60,     # Time window in seconds
    "brute_force_ports": [22, 21, 3389, 5900, 23],  # SSH, FTP, RDP, VNC, Telnet

    # ICMP flood detection
    "icmp_threshold": 50,       # ICMP packets per window to trigger alert
    "icmp_window": 10,          # Time window in seconds

    # DNS anomaly detection
    "dns_threshold": 50,        # DNS queries per window to trigger alert
    "dns_window": 10,           # Time window in seconds
}


class Config:
    def __init__(self, config_path="rules/config.json"):
        self.config_path = config_path
        self.config = DEFAULT_CONFIG.copy()
        self._load()

    def _load(self):
        """Loads config from JSON file if it exists."""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                    self.config.update(user_config)
                print(f"[*] Config loaded: {self.config_path}")
            except Exception as e:
                print(f"[!] Config load error: {e}. Using defaults.")
        else:
            print(f"[*] No config file found. Using default settings.")
            self._save_default()

    def _save_default(self):
        """Saves default config to file."""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(DEFAULT_CONFIG, f, indent=2)
            print(f"[*] Default config saved: {self.config_path}")
        except Exception as e:
            print(f"[!] Could not save config: {e}")

    def get(self, key, default=None):
        """Gets a config value."""
        return self.config.get(key, default)

    def set(self, key, value):
        """Sets a config value."""
        self.config[key] = value

    def show(self):
        """Prints current configuration."""
        print("\n[*] CURRENT CONFIGURATION")
        print("-" * 40)
        for key, value in self.config.items():
            print(f"  {key:<30}: {value}")
        print("-" * 40)