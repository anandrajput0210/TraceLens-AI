# TraceLens AI

> From security findings to the risks that actually matter.

TraceLens AI is a context-aware security risk intelligence platform that helps developers understand which security findings deserve attention first.

Traditional security scanners can identify many potential security issues, but the same type of finding can have very different importance depending on where it exists in an application.

TraceLens adds repository context to security findings by analyzing:

- Environment
- Exposure
- Static code-relationship hints (not proof of runtime or public reachability)
- Security severity
- Detection confidence
- Repository relationships

It then combines these signals into a **Context Risk Score** and prioritizes findings through an interactive dashboard.

---

## Problem

Security scanners can produce many findings, but developers still need to answer:

> **Which finding should I fix first, and why?**

A hardcoded credential in an isolated test file does not necessarily have the same contextual priority as a similar credential associated with production configuration and a publicly reachable application path.

Traditional severity alone does not capture all of this repository context.

---

## Solution

TraceLens analyzes a repository and connects security findings with application context.

```text
Repository
    ↓
File Discovery
    ↓
Security Detection
    ↓
Application Relationship Graph
    ↓
Environment + Exposure + Reachability
    ↓
Context Risk Score
    ↓
Prioritized Findings
    ↓
Risk Explanation

## Quick start

For the fastest local demo, install Docker Desktop and run:

```bash
docker compose up --build
```

Then open `http://localhost:3000` and upload a ZIP of `demo-repo`. Gemini is optional: scanning and contextual ranking work without an API key; AI explanations require `GEMINI_API_KEY` in the root `.env` file. See [DEPLOYMENT.md](DEPLOYMENT.md) for configuration and limitations.
