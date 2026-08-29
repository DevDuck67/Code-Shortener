# ⚡ GitHub & Code URL Shortener — Fast, Secure & Serverless Link Shortener ([gcode.buzz](https://gcode.buzz/))

[![Live Demo](https://img.shields.io/badge/Live_Demo-gcode.buzz-2ea043?style=for-the-badge&logo=google-chrome&logoColor=white)](https://gcode.buzz/)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare_Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![JavaScript](https://img.shields.io/badge/JavaScript-ES2024-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)](https://developer.mozilla.org/)
[![UI Style](https://img.shields.io/badge/Design-Apple_Liquid_Glass-007AFF?style=for-the-badge&logo=apple&logoColor=white)](https://apple.com)
[![Latency](https://img.shields.io/badge/Edge_Latency-%3C20ms-brightgreen?style=for-the-badge&logo=speedtest&logoColor=white)](https://cloudflare.com)

> **The modern, open-source Git.io alternative.** A high-performance, serverless URL shortener engineered for **GitHub repositories, Gists, raw code files, documentation, and web links**. Powered by **Cloudflare Workers** and **KV Storage** at the edge, featuring an **Apple iOS-inspired Liquid Glass UI**, real-time visitor telemetry, and military-grade edge security.

---

## 📌 Table of Contents

- [Overview & Architecture](#-overview--architecture)
- [Key Features](#-key-features)
- [Live Performance Benchmarks](#-live-performance-benchmarks)
- [Security & Anti-Abuse Shield](#-security--anti-abuse-shield)
- [Privacy & Telemetry Compliance (GDPR / ePrivacy)](#-privacy--telemetry-compliance-gdpr--eprivacy)
- [REST API Reference](#-rest-api-reference)
- [Project Structure](#-project-structure)
- [Quick Deployment Guide](#-quick-deployment-guide)
  - [Method 1: Cloudflare Web Dashboard (Zero Terminal)](#method-1-cloudflare-web-dashboard-zero-terminal)
  - [Method 2: Wrangler CLI (Developer Flow)](#method-2-wrangler-cli-developer-flow)
- [License](#-license)

---

## 🔍 Overview & Architecture

Traditional URL shorteners rely on heavy relational databases and centralized servers, introducing latency and single points of failure. **`gcode.buzz`** runs directly on Cloudflare’s global Anycast edge network (330+ locations), resolving short links in under **20 milliseconds** without cold starts.

```text
[ User / Developer ] 
        │
        ▼ (HTTPS / Anycast DNS)
[ Cloudflare Global Edge (<20ms) ] ───► [ Cloudflare KV Store (Key-Value) ]
        │
        ├─► Instant 302 Redirection
        ├─► Background Async Telemetry (`ctx.waitUntil`) ──► [ Real-time Visitor Stream ]
        └─► Server-Side Rendered (SSR) Mission Control
```

---

## 🌟 Key Features

* **⚡ Sub-20ms Global Redirection**: Distributed edge routing eliminates database round-trips and server lag.
* **🎨 Apple iOS Liquid Glass UI**: Multi-layered frosted glassmorphism (`backdrop-filter: blur(48px) saturate(210%)`), responsive ambient glow spheres, and micro-animations with [Lucide Icons](https://lucide.dev) & [Canvas Confetti](https://github.com/catdad/canvas-confetti).
* **📱 Instant QR Code Generator**: Generates high-definition, scannable QR codes automatically for every generated short link.
* **📊 Mission Control & Real-Time Telemetry (`/admin`)**:
  * **Deep Click Stream**: Logs Visitor IP, Edge Geo-Location (City/Country), Device Type (Desktop/Mobile), OS, Browser, Referrer, and Timestamps.
  * **Route Management**: Search, monitor total hits, and delete short links with one click.
  * **Zero Latency Overhead**: Analytics recording runs asynchronously in the background via `ctx.waitUntil()`.
* **🧠 Next-Gen SEO & AI-Search Indexing**: Pre-configured `Schema.org JSON-LD` structured semantic data, OpenGraph meta cards, Twitter cards, `/robots.txt`, and `/sitemap.xml` for indexability across Google, Bing, ChatGPT, Perplexity, Gemini, and Claude.

---

## ⚡ Live Performance Benchmarks

| Metric | Traditional Shorteners | **`gcode.buzz` (Cloudflare Edge)** |
| :--- | :--- | :--- |
| **Global TTFB (Time to First Byte)** | 180ms – 450ms | **< 20ms** |
| **Cold Starts** | 500ms – 2s | **0ms (Instant Edge Execution)** |
| **Uptime & Availability** | 99.9% | **99.99% (Global Edge Anycast)** |
| **Database Scalability** | Requires scaling/sharding | **Unlimited Global KV Read Scale** |
| **Privacy Compliance** | Third-party tracking cookies | **Zero tracking cookies (GDPR Compliant)** |

---

## 🛡️ Security & Anti-Abuse Shield

* **Anti-SSRF & Open-Redirect Protection**: Validates and cleans any destination URL enforcing `https://` and valid domain extensions, while strictly blocking internal IP ranges (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`, `127.0.0.1`, `localhost`) to prevent Server-Side Request Forgery.
* **Payload & Buffer Overflow Defense**: Hard request body limit of 8KB, max URL length of 2048 characters, and max custom slug length of 30 characters.
* **XSS & Injection Shielding**: All inputs and rendered outputs are thoroughly sanitized and HTML-escaped (`&`, `<`, `>`, `"`, `'`).
* **Anti-Brute Force Protection**: IP rate-limiting on URL generation and authentication attempts.
* **Timing-Attack Resistance**: Authentication verifies credentials using constant-time cryptographic comparisons and SHA-256 tokens.
* **Hardened Security Headers (OWASP Top 10)**: Enforces `X-Frame-Options: DENY`, `Strict-Transport-Security` (HSTS), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, and strict `Content-Security-Policy`.

---

## 🔒 Privacy & Telemetry Compliance (GDPR / ePrivacy)

This project is engineered to respect visitor privacy while delivering actionable operational analytics:

* **Zero Third-Party Tracking**: No marketing pixels, Google Analytics, social widgets, or advertising cookies are embedded.
* **Ephemeral Rolling Buffer (Minimal Data Retention)**: Telemetry logs are stored in a self-trimming ring buffer capped at the **latest 150 click events**. Older records are permanently discarded automatically.
* **Cookie-Less Public Interface**: Visitors using the public shortening interface receive zero cookies.
* **Strictly Necessary Admin Session**: The `gcode_admin` cookie is used solely for secure administrative authentication under the *Strictly Necessary Cookie Exemption* (ePrivacy Directive 2002/58/EC Art. 5(3)).
* **Owner Data Governance**: The repository owner retains complete control over all data stored in their own Cloudflare KV instance with a built-in one-click log purging mechanism (`/admin/clear-logs`).

---

## 🔌 REST API Reference

### 1. Create a Short Link
```http
POST /api/shorten
Content-Type: application/json

{
  "url": "https://github.com/torvalds/linux",
  "slug": "linux-kernel" // Optional custom alias
}
```

#### Success Response (`200 OK`):
```json
{
  "success": true,
  "slug": "linux-kernel",
  "shortUrl": "https://gcode.buzz/linux-kernel",
  "target": "https://github.com/torvalds/linux"
}
```

---

## 📂 Project Structure

```text
shortener/
├── src/
│   └── worker.js        # Single-file Serverless Engine (API, Frontend, Admin & Telemetry)
├── wrangler.toml        # Cloudflare Wrangler configuration
├── package.json         # Scripts and dependencies
├── .env.example         # Reference environment variables
├── .gitignore           # Ignored build & environment files
├── LICENSE              # MIT License
└── README.md            # Comprehensive documentation
```

---

## 🚀 Quick Deployment Guide

You can deploy your own instance for free in less than 3 minutes using either the **Cloudflare Web Dashboard** or the **Wrangler CLI**.

### Method 1: Cloudflare Web Dashboard (Zero Terminal)

1. **Sign Up**: Create a free account at [dash.cloudflare.com](https://dash.cloudflare.com).
2. **Create KV Namespaces**:
   - Go to **Storage & Databases** $\rightarrow$ **KV**.
   - Create two namespaces: `URLS_KV` and `ANALYTICS_KV`.
3. **Create Worker**:
   - Go to **Compute (Workers & Pages)** $\rightarrow$ **Create Application** $\rightarrow$ **Create Worker**.
   - Click **Deploy**.
4. **Bind KV & Admin Password**:
   - In Worker **Settings** $\rightarrow$ **Variables and Secrets** / **Bindings**:
     - **KV Namespace**: Variable name = `URLS`, Namespace = `URLS_KV`
     - **KV Namespace**: Variable name = `ANALYTICS`, Namespace = `ANALYTICS_KV`
     - **Secret / Variable**: Variable name = `ADMIN_PASSWORD`, Value = *(Your master password)*
5. **Paste Code**:
   - Click **Edit Code**, replace everything with the content of [`src/worker.js`](src/worker.js), and click **Deploy**.
6. **Add Custom Domain** *(Optional)*:
   - In **Settings** $\rightarrow$ **Domains & Routes**, bind your domain (e.g. `gcode.buzz`). SSL certificates are provisioned automatically.

---

### Method 2: Wrangler CLI (Developer Flow)

```bash
# 1. Clone the repository
git clone https://github.com/your-username/github-url-shortener.git
cd github-url-shortener

# 2. Install dependencies
npm install

# 3. Authenticate with Cloudflare
npx wrangler login

# 4. Create KV Namespaces
npx wrangler kv:namespace create URLS_KV
npx wrangler kv:namespace create ANALYTICS_KV

# 5. Deploy to the Edge
npm run deploy
```

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.

---

<p align="center">
  Built with ❤️ for developers and open-source creators by <a href="https://gcode.buzz">gcode.buzz</a>
</p>
