# 🤝 Contributing to Biubo WAF

First off, thank you for considering contributing to Biubo WAF! It's people like you that make the open-source community such an amazing place to learn, inspire, and create.

## 🌈 How Can I Contribute?

### 🛡️ I'm a Security Researcher
-   **New Rules**: Found a bypass? Or a new CVE? Update `src/core/engine/rules.py` with more robust regex patterns.
-   **Bypass Testing**: Try to bypass the WAF and report your findings (or better yet, give us the fix!).
-   **Security Hardening**: Audit our dashboard and API for vulnerabilities.

### 🐍 I'm a Python Developer
-   **Async Refactoring**: The LLM call is currently blocking. We'd love to see a non-blocking/queue implementation.
-   **Core Optimizations**: Help us optimize the Proxy performance.
-   **Database Drivers**: Add support for Redis or Postgres backends.

### 🎨 I'm a Frontend/UI Wizard
-   **Dashboard UX**: Our dashboard is functional but could look more "Cyber-Sec".
-   **Translations**: Help us localize the WAF into more languages.
-   **Visualizations**: Improve the attack map or the stats charts.

## 🚀 Getting Started

1.  **Fork** the repository.
2.  **Clone** your fork: `git clone https://github.com/your-username/Biubo_WAF.git`
3.  **Branch**: `git checkout -b feature/cool-new-feature`
4.  **Dev Environment**: Follow the [DEVELOPER.md](DEVELOPER.md) to set up your environment.
5.  **Commit**: Make sure your commit messages are descriptive.
6.  **Pull Request**: Open a PR against the `main` branch.

## 📮 Community

If you have questions or want to discuss ideas:
-   Open a **Discussion** on GitHub.
-   Join our community (Add your Discord/Telegram links here if applicable).

## 📄 Code of Conduct

Help us keep Biubo WAF a welcoming and inclusive project for everyone. Please be respectful and professional in all interactions.

---
**Thank you for making Biubo WAF stronger!**
