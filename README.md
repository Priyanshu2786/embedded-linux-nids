# Embedded Linux Network Intrusion Detection & Automated Response Agent

A lightweight Linux-based Network Intrusion Detection System (NIDS) that monitors network traffic, detects suspicious activities, calculates risk, stores security events, and automatically blocks high-risk IP addresses.

## Features

* Real-time TCP/UDP packet monitoring using **libpcap**
* Suspicious port detection
* Port scan detection
* Connection-rate anomaly detection
* Cumulative risk scoring
* SQLite security-event logging
* Automatic IP blocking using **nftables**
* JSON-based configuration
* Command-line interface (CLI)

## Technologies

* **C++17**
* **Linux/Debian**
* **libpcap**
* **SQLite**
* **nftables**
* **CMake**
* **Nmap**

## Architecture

```text
Attack VM
192.168.56.102
      |
      | Network Traffic
      ↓
NIDS VM
192.168.56.101
      |
  Packet Monitor
      ↓
Connection Tracker
      ↓
Detector
      ↓
Risk Engine
   ↙       ↘
SQLite    nftables
   ↓         ↓
 CLI      IP Block
```

## Detection & Risk Scoring

| Event           | Score |
| --------------- | ----: |
| Suspicious Port |   +20 |
| Port Scan       |   +40 |
| Connection Rate |   +30 |

```text
0–19   NORMAL
20–59  SUSPICIOUS
60–100 HIGH
```

Risk indicators are maintained per source IP for a 60-second window.

## Configuration


Important settings:

```text
Interface            : enp0s8
Scan Threshold       : 10 ports / 5 seconds
Connection Threshold : 100 / 10 seconds
Auto Block           : Enabled
Block Duration       : 60 seconds
```

Suspicious ports:

```text
21, 23, 445, 3389, 5900
```


## Attack Simulation

From the Attack VM:

```bash
nmap -p 20-40 192.168.56.101
```

The NIDS detects the port scan and can automatically block:

```text
Event      : PORT_SCAN_DETECTED
Risk Score : 60/100
Risk Level : HIGH
Action     : BLOCKED
```

## CLI

Commands:

```bash
./cli/nids-cli status
./cli/nids-cli alerts
./cli/nids-cli stats
sudo ./cli/nids-cli blocked
```


## Project Structure

```text
embedded-linux-nids/
├── include/
├── src/
├── config/
├── data/
├── logs/
├── cli/
├── tests/
└── CMakeLists.txt
```

## Conclusion

This project demonstrates a lightweight Linux-based security system capable of **network monitoring, intrusion detection, risk assessment, database logging, and automated firewall response**.
