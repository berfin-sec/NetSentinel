\---



\## ⚙️ Installation



```bash

git clone https://github.com/berfin-sec/NetSentinel.git

cd NetSentinel

pip install -r requirements.txt

```



\---



\## 🚀 Usage



```bash

\# Basic usage (auto-detect interface)

python netsentinel.py



\# Specify network interface

python netsentinel.py -i eth0



\# Generate HTML report after capture

python netsentinel.py -i eth0 --report



\# Custom config file

python netsentinel.py --config rules/custom.json



\# Capture only 1000 packets

python netsentinel.py -c 1000 --report

```



\---



\## 🚨 Alert Severity Levels



| Level | Description |

|-------|-------------|

| 🔵 LOW | Informational alerts |

| 🟡 MEDIUM | Suspicious activity |

| 🟠 HIGH | Likely attack detected |

| 🔴 CRITICAL | Active attack in progress |



\---



\## ⚙️ Configuration



Edit `rules/config.json` to customize detection thresholds:



```json

{

&#x20; "syn\_threshold": 100,

&#x20; "syn\_window": 10,

&#x20; "port\_scan\_threshold": 20,

&#x20; "brute\_force\_threshold": 10,

&#x20; "brute\_force\_window": 60,

&#x20; "brute\_force\_ports": \[22, 21, 3389, 5900, 23],

&#x20; "icmp\_threshold": 50,

&#x20; "icmp\_window": 10,

&#x20; "dns\_threshold": 50,

&#x20; "dns\_window": 10

}

```



\---



\## 🆚 Comparison with SecToolkit



| Feature | SecToolkit | NetSentinel |

|---------|-----------|-------------|

| Monitoring | Passive | Real-time |

| Execution | Manual | Continuous |

| Threats | Single check | Multi-engine |

| Output | Terminal | Terminal + HTML report |

| Rules | Hardcoded | Configurable JSON |



\---



\## ⚠️ Legal Disclaimer



This tool is developed for \*\*educational purposes\*\* and \*\*ethical security research only\*\*.

Always get proper authorization before monitoring any network.



\---



\## 📜 License



MIT License---



\## ⚙️ Installation



```bash

git clone https://github.com/berfin-sec/NetSentinel.git

cd NetSentinel

pip install -r requirements.txt

```



\---



\## 🚀 Usage



```bash

\# Basic usage (auto-detect interface)

python netsentinel.py



\# Specify network interface

python netsentinel.py -i eth0



\# Generate HTML report after capture

python netsentinel.py -i eth0 --report



\# Custom config file

python netsentinel.py --config rules/custom.json



\# Capture only 1000 packets

python netsentinel.py -c 1000 --report

```



\---



\## 🚨 Alert Severity Levels



| Level | Description |

|-------|-------------|

| 🔵 LOW | Informational alerts |

| 🟡 MEDIUM | Suspicious activity |

| 🟠 HIGH | Likely attack detected |

| 🔴 CRITICAL | Active attack in progress |



\---



\## ⚙️ Configuration



Edit `rules/config.json` to customize detection thresholds:



```json

{

&#x20; "syn\_threshold": 100,

&#x20; "syn\_window": 10,

&#x20; "port\_scan\_threshold": 20,

&#x20; "brute\_force\_threshold": 10,

&#x20; "brute\_force\_window": 60,

&#x20; "brute\_force\_ports": \[22, 21, 3389, 5900, 23],

&#x20; "icmp\_threshold": 50,

&#x20; "icmp\_window": 10,

&#x20; "dns\_threshold": 50,

&#x20; "dns\_window": 10

}

```



\---



\## 🆚 Comparison with SecToolkit



| Feature | SecToolkit | NetSentinel |

|---------|-----------|-------------|

| Monitoring | Passive | Real-time |

| Execution | Manual | Continuous |

| Threats | Single check | Multi-engine |

| Output | Terminal | Terminal + HTML report |

| Rules | Hardcoded | Configurable JSON |



\---



\## ⚠️ Legal Disclaimer



This tool is developed for \*\*educational purposes\*\* and \*\*ethical security research only\*\*.

Always get proper authorization before monitoring any network.



\---



\## 📜 License



MIT License

