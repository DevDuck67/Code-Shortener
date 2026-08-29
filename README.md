# GitHub & Code Shortener (`GCode.buzz`)

[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare_Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![JavaScript](https://img.shields.io/badge/JavaScript-ES2024-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)](https://developer.mozilla.org/)
[![Apple iOS 26 Glass](https://img.shields.io/badge/UI_Style-Apple_Liquid_Glass-007AFF?style=for-the-badge&logo=apple&logoColor=white)](https://apple.com)

> A modern, lightning-fast, and secure URL shortener tailored specifically for **GitHub repositories, Gists, raw files, and code snippets**. Built with a serverless edge architecture on **Cloudflare Workers** and **KV Storage**, featuring an **Apple iOS 26 Liquid Glass** user interface and real-time visitor telemetry.

---

## 🌟 Key Features

* **⚡ Ultra-Low Latency Edge Redirection**: Resolves short links in under 20ms across Cloudflare's global edge network (330+ cities).
* **🎨 Apple iOS 26 Liquid Glass UI**: Multi-layered frosted glassmorphism (`backdrop-filter: blur(48px) saturate(210%)`), dynamic ambient glow spheres, and micro-interactions powered by [Lucide Icons](https://lucide.dev) and [Canvas Confetti](https://github.com/catdad/canvas-confetti).
* **📱 Instant QR Code Generation**: Generates high-resolution QR codes automatically for every shortened link.
* **📊 Mission Control & Live Telemetry (`/admin`)**:
  * Real-time Click Stream: Tracks **IP Address**, **Timestamp**, **City**, **Country**, **Device Type** (Desktop/Mobile), **OS**, **Browser**, and **Referrer**.
  * Route Management: View all links with individual click counters and one-click deletion.
  * Zero-Latency Impact: Deep analytics logging runs asynchronously in the background via `ctx.waitUntil()`.
* **🧠 Next-Gen SEO & AI-Search Optimization**: Integrated `Schema.org JSON-LD` structured markup, OpenGraph cards, Twitter cards, `/robots.txt`, and `/sitemap.xml` for maximum discoverability by search engines and LLMs (ChatGPT, Claude, Perplexity, Gemini).

---

## 🛡️ Military-Grade Security Architecture

* **Anti-SSRF & Open-Redirect Protection**: Validates and cleans any destination URL enforcing `https://` and valid domain extensions, while strictly blocking internal IP ranges (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`, `127.0.0.1`, `localhost`) to prevent SSRF vulnerabilities.
* **Payload & Buffer Overflow Defense**: Hard request body limit of 8KB, max URL length of 2048 characters, and max slug length of 30 characters.
* **XSS & Injection Shielding**: All inputs and rendered outputs are thoroughly sanitized and HTML-escaped (`&`, `<`, `>`, `"`, `'`).
* **Anti-Brute Force Protection**: IP rate-limiting on admin authentication (maximum 5 failed attempts per 15 minutes).
* **Timing-Attack Resistance**: Authentication verifies passwords using constant-time string comparison (`timingSafeEqual`) and SHA-256 cryptographic hashing.
* **Hardened Security Headers**: Enforces `X-Frame-Options: DENY`, `Strict-Transport-Security` (HSTS), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, and strict `Content-Security-Policy`.

---

## 🔒 Privacy & Telemetry Compliance (GDPR / ePrivacy)

This project is engineered to respect end-user privacy while providing actionable operational observability:

* **Zero Third-Party Tracking**: No marketing pixels, Google Analytics, social widgets, or advertising cookies are embedded.
* **Ephemeral Rolling Buffer (Minimal Data Retention)**: Telemetry logs are stored in a self-trimming ring buffer capped at the **latest 150 click events**. Older records are permanently discarded automatically.
* **Cookie-Less Public Interface**: Visitors using the public shortening interface receive zero cookies.
* **Strictly Necessary Admin Session**: The `gcode_admin` cookie is utilized solely for secure administrative authentication under the *Strictly Necessary Cookie Exemption* (ePrivacy Directive 2002/58/EC Art. 5(3)).
* **Owner Data Governance**: The repository owner retains complete control over all data stored in their own Cloudflare KV instance with a built-in one-click log purging mechanism (`/admin/clear-logs`).

---

## 📂 Project Structure

```text
shortener/
├── src/
│   └── worker.js        # Full Serverless Application (Edge API, Frontend, Admin & Telemetry)
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

---

### Method A: Cloudflare Web Dashboard (No terminal needed)

1. **Create Cloudflare Account**: Sign up at [dash.cloudflare.com](https://dash.cloudflare.com) (100% Free).
2. **Create KV Namespaces**:
   * Navigate to **Storage & Databases** $\rightarrow$ **KV**.
   * Click **Create a Namespace** and create two namespaces:
     * `URLS_KV`
     * `ANALYTICS_KV`
3. **Create Worker**:
   * Navigate to **Compute (Workers & Pages)** $\rightarrow$ **Create Application** $\rightarrow$ **Create Worker**.
   * Choose **"Start with Hello World!"** and click **Deploy**.
4. **Configure Bindings & Admin Key**:
   * Go to your Worker $\rightarrow$ **Settings** $\rightarrow$ **Variables and Secrets** (or **Bindings** tab).
   * Click **Add binding +** and add:
     * **KV Namespace**: Variable name = `URLS`, Namespace = `URLS_KV`
     * **KV Namespace**: Variable name = `ANALYTICS`, Namespace = `ANALYTICS_KV`
     * **Secret / Text blob**: Variable name = `ADMIN_PASSWORD`, Value = *(Your master password)*
   * Click **Save and Deploy**.
5. **Paste the Code**:
   * Click **Edit Code**, delete the default code, paste the contents of [`src/worker.js`](src/worker.js), and click **Deploy**.
6. **Attach Custom Domain**:
   * In your Worker $\rightarrow$ **Settings** $\rightarrow$ **Domains & Routes** $\rightarrow$ Click **Add Custom Domain** (e.g. `gcode.buzz`). Cloudflare provisions the SSL certificate automatically.

---

### Method B: Wrangler CLI (Developer Workflow)

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/github-url-shortener.git
   cd github-url-shortener
   npm install
   ```

2. **Authenticate with Cloudflare**:
   ```bash
   npx wrangler login
   ```

3. **Create KV Namespaces**:
   ```bash
   npx wrangler kv:namespace create URLS_KV
   npx wrangler kv:namespace create ANALYTICS_KV
   ```
   *Copy the returned IDs into your `wrangler.toml` file:*
   ```toml
   kv_namespaces = [
     { binding = "URLS", id = "YOUR_URLS_KV_NAMESPACE_ID" },
     { binding = "ANALYTICS", id = "YOUR_ANALYTICS_KV_NAMESPACE_ID" }
   ]
   ```

4. **Set your Admin Password Secret**:
   ```bash
   npx wrangler secret put ADMIN_PASSWORD
   ```

5. **Start Local Development Server**:
   ```bash
   npm run dev
   ```

6. **Deploy to Production**:
   ```bash
   npm run deploy
   ```

---

## 📡 REST API Reference

### Shorten a URL

* **Endpoint**: `POST /api/shorten`
* **Headers**: `Content-Type: application/json`

#### Request Body:
```json
{
  "url": "https://github.com/torvalds/linux",
  "slug": "kernel" // Optional custom alias (3-30 characters)
}
```

#### Success Response (`200 OK`):
```json
{
  "success": true,
  "slug": "kernel",
  "shortUrl": "https://gcode.buzz/kernel",
  "target": "https://github.com/torvalds/linux"
}
```

#### Error Response (`400 Bad Request`):
```json
{
  "error": "Invalid URL. Only official GitHub, Gist, and Raw URLs (https://) are accepted."
}
```

---

## 🔒 Security Best Practices Checklist

* [x] Enforce HTTPS with HSTS Preload.
* [x] No SQL injection vulnerabilities (Cloudflare Key-Value architecture).
* [x] Automated Rate Limiting on public creation & admin login.
* [x] Timing-safe token comparison against timing attacks.
* [x] Cross-Site Scripting (XSS) prevention with strict CSP.

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).
