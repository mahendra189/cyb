# 💀 CyberSec Hacker Agent

**An autonomous, elite white-hat cyber security expert and hacker AI powered by LangGraph and Ollama.**

This interactive CLI agent assists security professionals and researchers in deep reconnaissance, penetration testing, network scanning, threat intelligence, and custom scripting. It leverages local AI models (via Ollama) to ensure privacy while providing powerful autonomous capabilities.

---

## 🚀 Features

*   **Autonomous Reconnaissance:** Automatically selects and runs the right tools based on your target and objectives.
*   **Rich CLI Interface:** Includes a beautiful terminal UI with status spinners, markdown formatting, and color-coding powered by `rich`.
*   **Local AI (Privacy-First):** Uses Ollama models (e.g., `llama3.2`, `qwen2.5`) to process data locally. No cloud API keys required!
*   **Built-in OSINT Tools:**
    *   DNS Lookups & IP Geolocation
    *   HTTP Headers Fingerprinting
    *   Nmap (Port & Service Scanning)
    *   theHarvester (Emails & Subdomains)
    *   Masscan (Fast Port Scanning)
    *   Nuclei (Vulnerability Scanning)
    *   Gitleaks (Secrets Detection in Repos)
    *   Subfinder (Subdomain Enumeration)
    *   WafW00f (WAF Fingerprinting)
    *   Feroxbuster (Directory/Content Discovery)
    *   Shodan (Internet-facing device mapping)
*   **Arbitrary Shell Execution (with Safeguards!) 🛡️:** The agent can write and execute its own shell scripts or use tools not explicitly coded into the framework.
    *   **User Approval:** Like GitHub Copilot or VS Code agents, it will **prompt you for permission** before running any shell commands.
    *   **Hard-coded Guardrails:** Automatically blocks destructive commands (e.g., `rm -rf`, `mkfs`, `halt`).

---

## 🛠️ Prerequisites

1.  **Python 3.12+**
2.  **uv** (Python package manager, recommended)
3.  **Ollama** installed and running locally.
    *   Download from: [https://ollama.com/](https://ollama.com/)
    *   Pull a model that supports tool calling (e.g., `llama3.2`):
        ```bash
        ollama pull llama3.2
        ```
4.  **CLI Tools (Optional but highly recommended):**
    For the agent to use its extended toolset, ensure the following are installed and accessible in your system's `PATH`:
    *   `nmap`
    *   `masscan`
    *   `nuclei`
    *   `subfinder`
    *   `theHarvester`
    *   `gitleaks`
    *   `wafw00f`
    *   `feroxbuster`
    *   `shodan` (requires an API key configured via `shodan init <API_KEY>`)

---

## 📦 Installation

1. Clone the repository and navigate into the project directory:
   ```bash
   git clone <your-repo-url>
   cd cyb
   ```

2. Sync the dependencies using `uv` (or pip):
   ```bash
   # If you have uv installed:
   uv sync
   
   # Or manually:
   pip install -r requirements.txt
   ```

---

## 🕹️ Usage

1. Start the Ollama service in the background (if not already running):
   ```bash
   ollama serve
   ```

2. Run the agent:
   ```bash
   uv run app.py
   ```

3. Type your prompt into the CLI. For example:
   * *"Do a quick DNS and IP lookup on example.com"*
   * *"Scan scanme.nmap.org for open web ports and tell me what server they are running."*
   * *"Run subfinder on target.com and checking if any discovered subdomains are using a WAF."*
   * *"Write a python script to check if port 8080 is open on localhost and execute it."*

---

## ⚠️ Disclaimer

This tool is intended for **authorized auditing and educational purposes only**. You must have explicit permission to scan, footprint, or test the targets you provide. Do not use this tool to attack infrastructure or networks you do not own or have written authorization to test.

*The author of this repository is not responsible for any misuse or damage caused by this software.*