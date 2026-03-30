# webgaurd-edr
WebGuard EDR Pro is a hybrid desktop application designed to bridge the gap between traditional browser sandboxes and OS-level security. It features a Python kernel for deep system monitoring, an incremental machine-learning model for anomaly detection, and a hardware-accelerated, dark-theme UI built with standard web technologies.  ## ✨ Features
# 🛡️ WebGuard EDR Pro

> A lightweight, AI-driven Endpoint Detection and Response (EDR) prototype running entirely locally.

WebGuard EDR Pro is a hybrid desktop application designed to bridge the gap between traditional browser sandboxes and OS-level security. It features a Python kernel for deep system monitoring, an incremental machine-learning model for anomaly detection, and a hardware-accelerated, dark-theme UI built with standard web technologies.

## ✨ Features

* **🧠 AI Threat Scoring (Incremental Learning):** Utilizes an `SGDClassifier` (Scikit-Learn) that continuously trains itself on your local network traffic. It flags anomalous socket connections and adjusts its neural weights based on user feedback.
* **🌐 Live Phishing Sandbox:** An interactive heuristic engine that calculates real-time risk scores for URLs by analyzing IP usage, subdomain depth, and malicious keyword patterns.
* **🛑 RAT & Reverse Shell Interception:** Actively monitors OS-level network sockets using `psutil`. It intercepts unauthorized connections on known malicious ports (e.g., 4444, 3389) and allows you to one-click terminate the rogue process.
* **📥 File System Hook:** Monitors the local Downloads folder to instantly quarantine dangerous dropped payloads (`.bat`, `.vbs`, `.exe`).
* **📋 Clipboard Heuristics:** Protects against crypto-hijacking malware by monitoring the clipboard for swapped cryptocurrency wallet addresses and known phishing domains.
* **⚡ Native UI Bridge:** Uses `pywebview` to wrap a sleek HTML/CSS/JS dashboard into a native Windows executable, providing real-time telemetry (CPU/RAM) without the overhead of Electron.

## 🛠️ Tech Stack

* **Backend Kernel:** Python 3.12
* **Machine Learning:** `scikit-learn`, `numpy`
* **System Telemetry:** `psutil`, `pyperclip`
* **Frontend UI:** HTML5, CSS3, Vanilla JavaScript
* **App Bridge & Compiler:** `pywebview`, `PyInstaller`

## 🚀 Installation & Setup

**1. Clone the repository:**
```bash
git clone [https://github.com/yourusername/WebGuard-EDR.git](https://github.com/yourusername/WebGuard-EDR.git)
cd WebGuard-EDR
