# 🛡️ Biubo WAF

<p align="center">
  <img src="assets/biubo_waf_banner.svg" alt="Biubo WAF Banner" width="800px">
  <br>
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Release-v1.0.0--alpha-orange.svg" alt="Release">
  <img src="https://img.shields.io/badge/AI-LLM_Integrated-purple.svg" alt="AI">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome">
  <br>
  <b>A Web Application Firewall that Thinks, Remembers, and Visualizes.</b>
</p>

---

## ⚡ What is Biubo WAF?

**Biubo WAF** is not just another rule-based filter. It is an **Intelligence-First Proxy** that bridges the gap between high-speed security and modern AI intuition. It sits as a guardian in front of your applications, watching every request through a dual lens of **Regex Performance** and **LLM Awareness**.

> [!TIP]
> **Zero-Zero Setup**: No SQL, No Redis, No complex Nginx configs. Just Python and the power of AI.

---

## 🎬 See it in Action

### 1. 🧠 Intelligence You Can Trust
Biubo WAF monitors every packet. From complex obfuscated payloads to sudden anomalies, watch it neutralize threats in milliseconds before they even reach your server.
> **![AI Detection Demo](assets/GIF_01_AI_DETECTION.gif)**
> *Attack detected and IP instantly isolated using high-speed signature and semantic correlation.*

### 2. 🎥 Visual Forensics (The "DVR" for Security)
Stop guessing. Watch exactly what the attacker did on your site with our integrated `rrweb` session playback.
> **![Visual Replay Demo](assets/GIF_02_RRWEB_REPLAY.gif)**
> *Recording Idea: Hacker types on a form -> Gets blocked -> Admin opens Dashboard -> Clicks "Play" -> Watch the "video" of the hacker's mouse moves and typing.*

---

## ✨ Key Features

| Feature | Description | Status |
| :--- | :--- | :--- |
| **Dual-Path Detection** | Regex (Fast Path) + LLM (Deep Path) for maximum coverage. | ✅ |
| **Visual Session Replay** | Integrated `rrweb` to record and playback malicious sessions. | ✅ |
| **JS Challenge** | Client-side Challenge-Response to stop headless bots. | ✅ |
| **Self-Contained DB** | Lightning-fast Msgpack storage with write-behind flushing. | ✅ |
| **Dynamic Dashboard** | Modern, responsive console for real-time traffic monitoring. | ✅ |

---

## 🧱 Architecture & Flow

```mermaid
graph LR
    A[Client Traffic] --> B[Biubo Gateway]
    subgraph Engine
        B --> C{Regex Match?}
        C -- No --> D{LLM Opinion?}
        D -- Hacker --> E[BLOCK]
        C -- Yes --> E
        D -- Normal --> F[PASS]
    end
    F --> G[Your Backend]
    E --> H[Visual Log + rrweb]
```

---

## 🚀 Quick Start

### One-Step Installation
```bash
# Clone the repository
git clone https://github.com/BiuboWAF/Biubo.git
cd Biubo

# Run the interactive setup
python setup.py

# Start protecting
python main.py
```

---

## 📑 Documentation Links

-   [**Developer Guide**](DEVELOPER.md) - How the engine works internally.
-   [**Roadmap**](ROADMAP.md) - Our vision for P1/P2/P3.
-   [**Contributing**](CONTRIBUTING.md) - We need your code and ideas!

---

## 📄 License

Biubo WAF is open-source software licensed under the **MIT License**.

<p align="center">
  Built with ❤️ for a more secure, intelligent web.
</p>
