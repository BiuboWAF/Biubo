# 🗺️ Biubo WAF Roadmap

This is the future of Biubo WAF. We are an ambitious, independent project and we have big plans.

## 🏁 Phase 1: Foundations (Current)
-   [x] **Regex Detection**: High-performance SQLI, XSS, RCE rules.
-   [x] **LLM Intelligence**: Secondary analysis using OpenAI/Qwen.
-   [x] **Visual Replay**: Integrated `rrweb` sessions.
-   [x] **Dashboard**: Basic monitoring and control.

## 🏃 Phase 2: Performance & Scalability (Upcoming)
-   [ ] **Asynchronous AI Detection**: Queue-based LLM analysis to avoid request blocking.
-   [ ] **Docker Support**: Containerized deployment with `docker-compose`.
-   [ ] **Storage Drivers**: Optional Redis/PostgreSQL support for high-traffic logs.
-   [ ] **SSL Management**: Automated Let's Encrypt certificates directly in the WAF.

## 🛡️ Phase 3: Advanced Defense (Future)
-   [ ] **Behavioral Profiling**: Use AI to detect abnormal user behavior (e.g., rapid navigation).
-   [ ] **Automatic Patching**: Use AI to suggest code fixes for detected vulnerabilities.
-   [ ] **Cluster Support**: Sync configuration across multiple WAF nodes.
-   [ ] **WAF API**: Expose detection status to backend applications (to block users at the app level).

## 🌍 Phase 4: Ecosystem & Plugins
-   [ ] **Plugin System**: Allow community members to write custom detection rules or log exporters.
-   [ ] **Mobile Dashboard**: A mobile app or optimized UI for on-the-go security management.

---
**Want to help us get there faster?** Check our [CONTRIBUTING.md](CONTRIBUTING.md) and join the movement!
