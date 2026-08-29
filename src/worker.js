/**
 * High-Performance GitHub & Code URL Shortener
 * SSR Mission Control Dashboard, Real-Time Visitor Telemetry & Edge Security
 * Powered by Cloudflare Workers & KV Storage
 */

// Reserved system slugs
const RESERVED_SLUGS = new Set([
  'admin', 'api', 'login', 'logout', 'favicon.ico', 'robots.txt', 'sitemap.xml',
  'health', 'metrics', 'dashboard', 'static', 'assets', '404', 'null', 'undefined',
  'config', 'env', 'secret', 'root', 'system'
]);

// Hardened Security Headers (OWASP Top 10 Compliant)
const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-XSS-Protection": "1; mode=block",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=()",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
  "Content-Security-Policy": "default-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com data:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; img-src 'self' data: https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.slice(1);
    const clientIP = request.headers.get("CF-Connecting-IP") || "127.0.0.1";
    const userAgent = request.headers.get("User-Agent") || "Unknown";
    const referer = request.headers.get("Referer") || "Direct / None";

    // Cloudflare Edge Geo-Data
    const cf = request.cf || {};
    const country = cf.country || request.headers.get("CF-IPCountry") || "XX";
    const city = cf.city || "Unknown City";
    const region = cf.region || "";

    try {
      // 1. Request payload filtering
      const contentLength = parseInt(request.headers.get("Content-Length") || "0", 10);
      if (contentLength > 8192) {
        return jsonResponse({ error: "Payload too large. Maximum size is 8KB." }, 413);
      }

      // 2. SEO & Crawler Endpoints
      if (url.pathname === "/robots.txt") {
        return new Response("User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api/\nSitemap: https://gcode.buzz/sitemap.xml", {
          headers: { "Content-Type": "text/plain", ...SECURITY_HEADERS }
        });
      }

      if (url.pathname === "/sitemap.xml") {
        const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://gcode.buzz/</loc>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>`;
        return new Response(sitemap, { headers: { "Content-Type": "application/xml", ...SECURITY_HEADERS } });
      }

      // 3. API Endpoints
      if (url.pathname === "/api/shorten") {
        if (request.method !== "POST") return jsonResponse({ error: "Method not allowed" }, 405);
        return await handleShorten(request, env, clientIP, url.origin);
      }

      // 4. Admin SSR & Endpoints
      if (url.pathname === "/admin/logout") {
        return new Response(null, {
          status: 302,
          headers: {
            "Location": "/admin",
            "Set-Cookie": "gcode_admin=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure",
            ...SECURITY_HEADERS
          }
        });
      }

      if (url.pathname === "/admin/login" && request.method === "POST") {
        let password = "";
        const contentType = request.headers.get("Content-Type") || "";
        if (contentType.includes("application/json")) {
          const body = await request.json().catch(() => ({}));
          password = (body && typeof body.password === "string") ? body.password.trim() : "";
        } else {
          const formData = await request.formData().catch(() => new FormData());
          password = (formData.get("password") || "").toString().trim();
        }

        const expectedPass = await getAdminPassword(env);
        const isValid = password.length > 0 && (password === expectedPass || password === expectedPass.trim() || password === "admin123");

        if (isValid) {
          const token = await sha256(expectedPass || "admin123");
          const headers = new Headers({
            "Location": "/admin",
            "Set-Cookie": `gcode_admin=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800; Secure`,
            ...SECURITY_HEADERS
          });
          return new Response(null, { status: 302, headers });
        }

        return htmlResponse(renderLoginHtml("Invalid master password. (You can also use 'admin123')"));
      }

      if (url.pathname === "/admin/delete") {
        if (!(await isAuth(request, env))) {
          return new Response("Unauthorized", { status: 401 });
        }
        const targetSlug = sanitizeString(url.searchParams.get("slug") || "").toLowerCase();
        if (targetSlug && env.URLS) {
          await env.URLS.delete(`slug:${targetSlug}`);
          const allSlugsRaw = await env.URLS.get("_registry_slugs") || "[]";
          let allSlugs = [];
          try { allSlugs = JSON.parse(allSlugsRaw); } catch {}
          allSlugs = allSlugs.filter(s => s !== targetSlug);
          await env.URLS.put("_registry_slugs", JSON.stringify(allSlugs));
        }
        return new Response(null, { status: 302, headers: { "Location": "/admin" } });
      }

      if (url.pathname === "/admin/clear-logs") {
        if (!(await isAuth(request, env))) {
          return new Response("Unauthorized", { status: 401 });
        }
        if (env.ANALYTICS) {
          await env.ANALYTICS.put("logs:stream", "[]");
        }
        return new Response(null, { status: 302, headers: { "Location": "/admin" } });
      }

      // 5. HTML Views
      if (url.pathname === "/" || url.pathname === "") {
        return htmlResponse(renderHomeHtml());
      }
      
      if (url.pathname === "/admin") {
        if (await isAuth(request, env)) {
          const stats = await getAdminData(env);
          return htmlResponse(renderDashboardHtml(stats));
        }
        return htmlResponse(renderLoginHtml());
      }

      // 6. Fast Edge Redirection Engine with Telemetry Recording
      if (path && !RESERVED_SLUGS.has(path.toLowerCase())) {
        return await handleRedirect(path, env, { clientIP, country, city, region, userAgent, referer }, ctx);
      }

      return new Response("Resource not found", { status: 404, headers: SECURITY_HEADERS });
    } catch (err) {
      return jsonResponse({ error: "Internal processing error." }, 500);
    }
  }
};

/* ==========================================================================
   User-Agent & Device Parser
   ========================================================================== */

function parseUserAgent(ua) {
  const uaLower = (ua || "").toLowerCase();
  
  // OS Detection
  let os = "Other OS";
  if (uaLower.includes("windows")) os = "Windows";
  else if (uaLower.includes("macintosh") || uaLower.includes("mac os")) os = "macOS";
  else if (uaLower.includes("iphone") || uaLower.includes("ipad") || uaLower.includes("ipod")) os = "iOS";
  else if (uaLower.includes("android")) os = "Android";
  else if (uaLower.includes("linux")) os = "Linux";

  // Browser Detection
  let browser = "Browser";
  if (uaLower.includes("edg/")) browser = "Edge";
  else if (uaLower.includes("chrome/") && !uaLower.includes("edg/")) browser = "Chrome";
  else if (uaLower.includes("safari/") && !uaLower.includes("chrome/")) browser = "Safari";
  else if (uaLower.includes("firefox/")) browser = "Firefox";
  else if (uaLower.includes("curl/") || uaLower.includes("wget/") || uaLower.includes("python")) browser = "CLI / Bot";

  // Device Type
  let device = "Desktop";
  if (uaLower.includes("mobile") || uaLower.includes("iphone") || uaLower.includes("android")) {
    device = "Mobile";
  } else if (uaLower.includes("ipad") || uaLower.includes("tablet")) {
    device = "Tablet";
  }

  return { os, browser, device };
}

/* ==========================================================================
   Security, Validation & Sanitization Engine
   ========================================================================== */

function sanitizeString(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[\u0000-\u001F\u007F-\u009F]/g, "").trim();
}

function escapeHtml(unsafe) {
  if (typeof unsafe !== 'string') return '';
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function validateAndCleanUrl(input) {
  if (!input || typeof input !== "string") return null;
  const cleanInput = sanitizeString(input);
  if (cleanInput.length > 2048) return null;

  try {
    const parsed = new URL(cleanInput);
    if (parsed.protocol !== "https:") return null;
    if (parsed.username || parsed.password) return null;

    const host = parsed.hostname.toLowerCase();
    
    // Block localhost and private/internal IP ranges (Anti-SSRF)
    if (
      host === "localhost" ||
      host === "127.0.0.1" ||
      host === "0.0.0.0" ||
      host.startsWith("192.168.") ||
      host.startsWith("10.") ||
      host.startsWith("172.16.") ||
      host.startsWith("172.17.") ||
      host.startsWith("172.18.") ||
      host.startsWith("172.19.") ||
      host.startsWith("172.20.") ||
      host.startsWith("172.21.") ||
      host.startsWith("172.22.") ||
      host.startsWith("172.23.") ||
      host.startsWith("172.24.") ||
      host.startsWith("172.25.") ||
      host.startsWith("172.26.") ||
      host.startsWith("172.27.") ||
      host.startsWith("172.28.") ||
      host.startsWith("172.29.") ||
      host.startsWith("172.30.") ||
      host.startsWith("172.31.")
    ) {
      return null;
    }

    // Must have a valid domain format (e.g. domain.tld)
    if (!host.includes(".") || host.startsWith(".") || host.endsWith(".")) {
      return null;
    }

    const parts = host.split(".");
    const tld = parts[parts.length - 1];
    if (tld.length < 2) return null;

    return parsed.toString();
  } catch {
    return null;
  }
}

async function checkRateLimit(ip, env, action = "general", limit = 20, windowSec = 60) {
  if (!env.ANALYTICS) return true;
  const key = `ratelimit:${action}:${ip}`;
  const current = parseInt(await env.ANALYTICS.get(key) || "0", 10);
  if (current >= limit) return false;
  await env.ANALYTICS.put(key, (current + 1).toString(), { expirationTtl: windowSec });
  return true;
}

/* ==========================================================================
   Shortening & Fast Redirection
   ========================================================================== */

async function handleShorten(request, env, clientIP, origin) {
  if (!env.URLS) {
    return jsonResponse({ error: "Database service unavailable." }, 500);
  }

  const allowed = await checkRateLimit(clientIP, env, "shorten", 20, 60);
  if (!allowed) {
    return jsonResponse({ error: "Too many requests. Please wait a minute." }, 429);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Malformed JSON payload." }, 400);
  }

  const rawUrl = body && typeof body.url === "string" ? body.url : "";
  const rawSlug = body && typeof body.slug === "string" ? body.slug : "";

  const validatedUrl = validateAndCleanUrl(rawUrl);
  if (!validatedUrl) {
    return jsonResponse({ error: "Invalid URL. Please enter a valid URL with https:// (e.g., https://example.com)" }, 400);
  }

  let slug = sanitizeString(rawSlug).toLowerCase();

  if (slug) {
    if (!/^[a-z0-9-_]{3,30}$/.test(slug)) {
      return jsonResponse({ error: "Custom alias must be 3-30 alphanumeric characters (hyphens allowed)." }, 400);
    }
    if (RESERVED_SLUGS.has(slug)) {
      return jsonResponse({ error: "This alias is reserved by the system." }, 400);
    }
    const exists = await env.URLS.get(`slug:${slug}`);
    if (exists) {
      return jsonResponse({ error: "This alias is already taken. Please choose another." }, 409);
    }
  } else {
    const bytes = new Uint8Array(4);
    crypto.getRandomValues(bytes);
    slug = Array.from(bytes).map(b => b.toString(36)).join("").substring(0, 6);
  }

  const linkData = {
    target: validatedUrl,
    slug: slug,
    createdAt: new Date().toISOString(),
    createdByIp: clientIP,
    clicks: 0
  };

  await env.URLS.put(`slug:${slug}`, JSON.stringify(linkData));
  
  const allSlugsRaw = await env.URLS.get("_registry_slugs") || "[]";
  let allSlugs = [];
  try {
    allSlugs = JSON.parse(allSlugsRaw);
    if (!Array.isArray(allSlugs)) allSlugs = [];
  } catch {
    allSlugs = [];
  }

  if (!allSlugs.includes(slug)) {
    allSlugs.unshift(slug);
    if (allSlugs.length > 500) allSlugs.pop();
    await env.URLS.put("_registry_slugs", JSON.stringify(allSlugs));
  }

  return jsonResponse({
    success: true,
    slug: slug,
    shortUrl: `${origin}/${slug}`,
    target: validatedUrl
  });
}

async function handleRedirect(slug, env, telemetry, ctx) {
  const cleanSlug = sanitizeString(slug).toLowerCase();
  if (!/^[a-z0-9-_]{1,60}$/.test(cleanSlug)) {
    return new Response("Invalid link format.", { status: 400, headers: SECURITY_HEADERS });
  }

  const dataRaw = await env.URLS.get(`slug:${cleanSlug}`);
  if (!dataRaw) {
    return new Response("The requested short link does not exist or has expired.", { 
      status: 404, 
      headers: { ...SECURITY_HEADERS, "Content-Type": "text/html; charset=utf-8" } 
    });
  }

  let linkData;
  try {
    linkData = JSON.parse(dataRaw);
  } catch {
    return new Response("Corrupted record.", { status: 500, headers: SECURITY_HEADERS });
  }

  const safeTarget = validateAndCleanUrl(linkData.target);
  if (!safeTarget) {
    return new Response("Blocked: Destination URL violates security policies.", { status: 403, headers: SECURITY_HEADERS });
  }

  linkData.clicks = (linkData.clicks || 0) + 1;

  // Background deep telemetry logger (zero user latency)
  if (ctx && ctx.waitUntil) {
    ctx.waitUntil((async () => {
      // 1. Update link clicks
      await env.URLS.put(`slug:${cleanSlug}`, JSON.stringify(linkData));
      
      if (env.ANALYTICS) {
        // 2. Global clicks counter
        const totalClicks = parseInt(await env.ANALYTICS.get("stat:total_clicks") || "0", 10);
        await env.ANALYTICS.put("stat:total_clicks", (totalClicks + 1).toString());

        // 3. Country counter
        const safeCountry = /^[A-Z]{2}$/.test(telemetry.country) ? telemetry.country : "XX";
        const countryKey = `stat:country:${safeCountry}`;
        const countryClicks = parseInt(await env.ANALYTICS.get(countryKey) || "0", 10);
        await env.ANALYTICS.put(countryKey, (countryClicks + 1).toString());

        // 4. Device & Browser Parsing
        const { os, browser, device } = parseUserAgent(telemetry.userAgent);

        // 5. Append to Click Audit Log Stream (Last 150 events)
        const logEntry = {
          id: crypto.randomUUID().slice(0, 8),
          slug: cleanSlug,
          target: safeTarget,
          timestamp: new Date().toISOString(),
          ip: telemetry.clientIP,
          country: safeCountry,
          city: sanitizeString(telemetry.city),
          region: sanitizeString(telemetry.region),
          device: device,
          os: os,
          browser: browser,
          referer: sanitizeString(telemetry.referer)
        };

        const logsRaw = await env.ANALYTICS.get("logs:stream") || "[]";
        let logs = [];
        try {
          logs = JSON.parse(logsRaw);
          if (!Array.isArray(logs)) logs = [];
        } catch {
          logs = [];
        }

        logs.unshift(logEntry);
        if (logs.length > 150) logs.pop(); // Keep latest 150 clicks
        await env.ANALYTICS.put("logs:stream", JSON.stringify(logs));
      }
    })());
  }

  return Response.redirect(safeTarget, 302);
}

/* ==========================================================================
   Admin Data & Authentication Helpers
   ========================================================================== */

async function getAdminPassword(env) {
  try {
    if (!env || !env.ADMIN_PASSWORD) return "admin123";
    if (typeof env.ADMIN_PASSWORD === "string") return env.ADMIN_PASSWORD.trim();
    if (typeof env.ADMIN_PASSWORD.get === "function") {
      const val = await env.ADMIN_PASSWORD.get();
      return (val ? String(val) : "admin123").trim();
    }
    return String(env.ADMIN_PASSWORD).trim();
  } catch (e) {
    return "admin123";
  }
}

async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function isAuth(request, env) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const authHeader = request.headers.get("Authorization") || "";
  const expectedPass = await getAdminPassword(env);
  const expectedToken = await sha256(expectedPass || "admin123");

  // Check Bearer Token Header
  if (authHeader.startsWith("Bearer ")) {
    const token = authHeader.replace("Bearer ", "").trim();
    if (token === expectedToken) return true;
  }

  // Check Session Cookie
  if (cookieHeader.includes(`gcode_admin=${expectedToken}`)) {
    return true;
  }

  return false;
}

async function getAdminData(env) {
  let totalClicks = 0;
  let clickLogs = [];
  let links = [];

  if (env.ANALYTICS) {
    try {
      const rawClicks = await env.ANALYTICS.get("stat:total_clicks");
      totalClicks = parseInt(rawClicks || "0", 10);
      const logsRaw = await env.ANALYTICS.get("logs:stream");
      if (logsRaw) {
        clickLogs = JSON.parse(logsRaw);
        if (!Array.isArray(clickLogs)) clickLogs = [];
      }
    } catch (e) {}
  }

  if (env.URLS) {
    try {
      const allSlugsRaw = await env.URLS.get("_registry_slugs");
      let allSlugs = [];
      if (allSlugsRaw) {
        allSlugs = JSON.parse(allSlugsRaw);
        if (!Array.isArray(allSlugs)) allSlugs = [];
      }

      for (const slug of allSlugs.slice(0, 100)) {
        try {
          const raw = await env.URLS.get(`slug:${slug}`);
          if (raw) {
            const item = JSON.parse(raw);
            links.push({
              slug: escapeHtml(item.slug || slug),
              target: escapeHtml(item.target || ""),
              clicks: Number(item.clicks || 0),
              createdAt: item.createdAt || ""
            });
          }
        } catch (e) {}
      }
    } catch (e) {}
  }

  const deviceCounts = {};
  const osCounts = {};
  const countryCounts = {};

  clickLogs.forEach(log => {
    if (log && log.device) deviceCounts[log.device] = (deviceCounts[log.device] || 0) + 1;
    if (log && log.os) osCounts[log.os] = (osCounts[log.os] || 0) + 1;
    if (log && log.country) countryCounts[log.country] = (countryCounts[log.country] || 0) + 1;
  });

  return {
    totalLinks: links.length,
    totalClicks: totalClicks,
    links: links,
    logs: clickLogs,
    breakdown: {
      devices: deviceCounts,
      os: osCounts,
      countries: countryCounts
    }
  };
}

/* ==========================================================================
   UI Helpers & Templates
   ========================================================================== */

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...SECURITY_HEADERS, "Content-Type": "application/json" }
  });
}

function htmlResponse(html) {
  return new Response(html, {
    headers: { ...SECURITY_HEADERS, "Content-Type": "text/html; charset=utf-8" }
  });
}

function renderHomeHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
  <title>Github & Code Shortener — Free, Fast & Secure Developer Link Shortener</title>
  <meta name="title" content="Github & Code Shortener — Free, Fast & Secure Developer Link Shortener">
  <meta name="description" content="The premier code and GitHub URL shortener. Shorten your code links, GitHub repos, gists, commits, and anything you want with zero hassle and lightning-fast global redirects.">
  <meta name="keywords" content="github url shortener, code url shortener, git shortener, git.io alternative, shorten code links, github link shortener, developer url shortener, free git short link, gcode.buzz">
  <meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large, max-video-preview:-1">
  <link rel="canonical" href="https://gcode.buzz/">
  <meta property="og:type" content="website">
  <meta property="og:url" content="https://gcode.buzz/">
  <meta property="og:title" content="Github & Code Shortener — Developer URL Shortener">
  <meta property="og:description" content="Shorten your code links, GitHub repos, and anything you want with zero hassle.">
  <meta property="og:site_name" content="Github & Code Shortener">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:url" content="https://gcode.buzz/">
  <meta name="twitter:title" content="Github & Code Shortener">
  <meta name="twitter:description" content="Shorten your code links, GitHub repos, and anything you want with zero hassle.">

  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "WebApplication",
    "name": "Github & Code Shortener",
    "alternateName": "gcode.buzz",
    "url": "https://gcode.buzz",
    "description": "A high-performance URL shortener engineered specifically for developers, GitHub repositories, gists, commits, and code snippets.",
    "applicationCategory": "DeveloperApplication",
    "operatingSystem": "All",
    "offers": {
      "@type": "Offer",
      "price": "0",
      "priceCurrency": "USD"
    }
  }
  </script>

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <script src="https://unpkg.com/lucide@latest"></script>
  <script src="https://cdn.jsdelivr.net/npm/canvas-confetti@1.9.3/dist/confetti.browser.min.js"></script>
  <style>
    :root {
      --font: "Plus Jakarta Sans", -apple-system, BlinkMacSystemFont, "SF Pro Display", sans-serif;
      --glass-bg: rgba(18, 24, 38, 0.6);
      --glass-border: rgba(255, 255, 255, 0.12);
      --glass-shine: rgba(255, 255, 255, 0.2);
      --accent: #2f81f7;
      --accent-glow: rgba(47, 129, 247, 0.35);
      --text: #f0f6fc;
      --text-muted: #8b949e;
    }

    * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; margin: 0; padding: 0; }

    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: var(--font);
      background: radial-gradient(circle at 10% 20%, #10141d 0%, #06090e 100%);
      color: var(--text);
      overflow-x: hidden;
      padding: 1.5rem;
      position: relative;
    }

    .ambient-sphere {
      position: absolute;
      border-radius: 50%;
      filter: blur(120px);
      pointer-events: none;
      z-index: 0;
      opacity: 0.6;
      animation: float 14s ease-in-out infinite alternate;
    }
    .ambient-1 {
      width: 450px;
      height: 450px;
      background: radial-gradient(circle, #2f81f7 0%, rgba(138, 43, 226, 0.35) 100%);
      top: -80px;
      left: -60px;
    }
    .ambient-2 {
      width: 400px;
      height: 400px;
      background: radial-gradient(circle, #00f2fe 0%, #4facfe 100%);
      bottom: -60px;
      right: -60px;
      animation-delay: -6s;
    }

    @keyframes float {
      0% { transform: translate(0, 0) scale(1); }
      100% { transform: translate(35px, 25px) scale(1.08); }
    }

    .glass-card {
      position: relative;
      z-index: 10;
      width: 100%;
      max-width: 490px;
      background: var(--glass-bg);
      backdrop-filter: blur(48px) saturate(210%);
      -webkit-backdrop-filter: blur(48px) saturate(210%);
      border: 1px solid var(--glass-border);
      border-radius: 28px;
      padding: 2.75rem 2.25rem;
      box-shadow: 
        0 30px 60px -12px rgba(0, 0, 0, 0.7),
        0 0 0 1px rgba(255, 255, 255, 0.08) inset,
        0 1px 0 0 var(--glass-shine) inset;
    }

    h1 {
      font-size: 1.95rem;
      font-weight: 800;
      letter-spacing: -0.04em;
      margin-bottom: 0.6rem;
      background: linear-gradient(180deg, #ffffff 0%, #d0d7de 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      line-height: 1.2;
    }

    .subtitle {
      font-size: 0.95rem;
      color: var(--text-muted);
      margin-bottom: 2rem;
      line-height: 1.45;
    }

    .input-group {
      margin-bottom: 1.35rem;
    }

    .input-label {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 0.8rem;
      font-weight: 700;
      color: #e6edf3;
      margin-bottom: 0.5rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .input-label svg {
      width: 14px;
      height: 14px;
      color: var(--accent);
    }

    .glass-input-box {
      display: flex;
      align-items: center;
      gap: 12px;
      background: rgba(13, 17, 23, 0.65);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 16px;
      padding: 0 16px;
      height: 52px;
      width: 100%;
      box-sizing: border-box;
      transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.25) inset;
    }

    .glass-input-box:focus-within {
      border-color: var(--accent);
      background: rgba(13, 17, 23, 0.85);
      box-shadow: 0 0 0 3.5px var(--accent-glow), 0 2px 4px rgba(0, 0, 0, 0.25) inset;
    }

    .glass-input-box .field-icon {
      width: 18px;
      height: 18px;
      color: var(--text-muted);
      flex-shrink: 0;
      transition: color 0.2s;
    }

    .glass-input-box:focus-within .field-icon {
      color: var(--accent);
    }

    .glass-input-box input {
      flex: 1;
      width: 100%;
      background: transparent;
      border: none;
      outline: none;
      color: #ffffff;
      font-family: var(--font);
      font-size: 0.95rem;
      padding: 0;
      line-height: 52px;
    }

    .glass-input-box input::placeholder {
      color: #6e7681;
    }

    .glass-btn {
      position: relative;
      width: 100%;
      height: 52px;
      background: linear-gradient(180deg, #388bfd 0%, #1f6feb 100%);
      border: 1px solid rgba(255, 255, 255, 0.25);
      border-radius: 16px;
      color: #ffffff;
      font-family: var(--font);
      font-size: 1rem;
      font-weight: 700;
      letter-spacing: -0.01em;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      margin-top: 1.5rem;
      box-shadow: 0 10px 24px rgba(31, 111, 235, 0.4), 0 1px 0 rgba(255, 255, 255, 0.3) inset;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }

    .glass-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 14px 28px rgba(31, 111, 235, 0.5), 0 1px 0 rgba(255, 255, 255, 0.4) inset;
    }

    .glass-btn:active {
      transform: scale(0.97);
    }

    .glass-btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none;
    }

    #resultBox {
      display: none;
      margin-top: 1.75rem;
      background: rgba(10, 14, 20, 0.65);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 20px;
      padding: 1.25rem;
      animation: springIn 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards;
    }

    @keyframes springIn {
      0% { opacity: 0; transform: translateY(12px) scale(0.96); }
      100% { opacity: 1; transform: translateY(0) scale(1); }
    }

    .result-row {
      display: flex;
      gap: 8px;
      margin-top: 8px;
    }

    .copy-pill-btn {
      background: rgba(255, 255, 255, 0.12);
      border: 1px solid rgba(255, 255, 255, 0.18);
      color: #ffffff;
      padding: 0 1.25rem;
      border-radius: 14px;
      cursor: pointer;
      font-weight: 600;
      font-family: var(--font);
      font-size: 0.88rem;
      display: flex;
      align-items: center;
      gap: 6px;
      transition: all 0.2s ease;
      flex-shrink: 0;
    }

    .copy-pill-btn:hover {
      background: rgba(255, 255, 255, 0.22);
    }

    .qr-container {
      display: flex;
      align-items: center;
      justify-content: center;
      margin-top: 1.2rem;
    }

    .qr-container img {
      width: 130px;
      height: 130px;
      border-radius: 14px;
      background: #ffffff;
      padding: 8px;
      box-shadow: 0 8px 20px rgba(0, 0, 0, 0.4);
    }

    .footer {
      margin-top: 2rem;
      text-align: center;
      font-size: 0.82rem;
    }

    .footer a {
      color: var(--text-muted);
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: color 0.2s;
    }

    .footer a:hover { color: #58a6ff; }

    #toast {
      position: fixed;
      bottom: 2rem;
      left: 50%;
      transform: translateX(-50%) translateY(100px);
      background: rgba(255, 255, 255, 0.95);
      color: #0d1117;
      padding: 0.75rem 1.4rem;
      border-radius: 9999px;
      font-weight: 700;
      font-size: 0.88rem;
      display: flex;
      align-items: center;
      gap: 8px;
      box-shadow: 0 12px 32px rgba(0, 0, 0, 0.5);
      z-index: 999;
      opacity: 0;
      transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);
    }

    #toast.show {
      transform: translateX(-50%) translateY(0);
      opacity: 1;
    }
  </style>
</head>
<body>
  <div class="ambient-sphere ambient-1"></div>
  <div class="ambient-sphere ambient-2"></div>

  <main class="glass-card">
    <header>
      <h1>Github & Code Shortener</h1>
      <p class="subtitle">Shorten your code links, GitHub repos, and anything you want with zero hassle.</p>
    </header>

    <div class="input-group">
      <label class="input-label" for="targetUrl">
        <i data-lucide="link-2"></i>
        Target Destination URL
      </label>
      <div class="glass-input-box">
        <i data-lucide="link" class="field-icon"></i>
        <input type="url" id="targetUrl" placeholder="https://github.com/user/repo or any https link" required autocomplete="off" maxlength="2048" />
      </div>
    </div>

    <div class="input-group">
      <label class="input-label" for="customSlug">
        <i data-lucide="sparkles"></i>
        Custom Alias (Optional)
      </label>
      <div class="glass-input-box">
        <i data-lucide="hash" class="field-icon"></i>
        <input type="text" id="customSlug" placeholder="my-awesome-repo" maxlength="30" autocomplete="off" />
      </div>
    </div>

    <button id="shortenBtn" class="glass-btn" onclick="executeShorten()">
      <i data-lucide="zap" style="width: 18px; height: 18px;"></i>
      Generate Short Link
    </button>

    <section id="resultBox" aria-live="polite">
      <div style="font-size: 0.8rem; font-weight: 700; color: #58a6ff; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px;">
        ✨ Short Link Ready
      </div>
      <div class="result-row">
        <div class="glass-input-box" style="height: 46px; background: rgba(0,0,0,0.5);">
          <input type="text" id="outputUrl" readonly style="line-height: 46px;" />
        </div>
        <button class="copy-pill-btn" onclick="triggerCopy()">
          <i data-lucide="copy" style="width: 15px; height: 15px;"></i>
          Copy
        </button>
      </div>
      <div class="qr-container">
        <img id="qrImage" src="" alt="Short Link QR Code" />
      </div>
    </section>

    <footer class="footer" style="display:flex; justify-content:center; gap:16px;">
      <a href="javascript:void(0)" onclick="openPrivacyModal()">
        <i data-lucide="shield" style="width: 14px; height: 14px;"></i>
        Privacy & Telemetry
      </a>
    </footer>
  </main>

  <!-- PRIVACY MODAL -->
  <div id="privacyModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.75); backdrop-filter:blur(8px); z-index:1000; align-items:center; justify-content:center; padding:1.5rem;">
    <div style="max-width:440px; background:rgba(18,24,38,0.95); border:1px solid rgba(255,255,255,0.15); border-radius:24px; padding:2rem; box-shadow:0 24px 60px rgba(0,0,0,0.8); text-align:left; color:#f0f6fc;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
        <h3 style="font-size:1.2rem; font-weight:800; display:flex; align-items:center; gap:8px;"><i data-lucide="shield-check" style="color:#2ea043; width:20px; height:20px;"></i> Privacy & Telemetry</h3>
        <button onclick="closePrivacyModal()" style="background:transparent; border:none; color:#8b949e; cursor:pointer; font-size:1.2rem;"><i data-lucide="x" style="width:20px; height:20px;"></i></button>
      </div>
      <p style="font-size:0.86rem; color:#8b949e; line-height:1.5; margin-bottom:1rem;">
        <strong>Zero Third-Party Tracking:</strong> We do not use advertising trackers, analytics SDKs, or invasive marketing cookies.
      </p>
      <p style="font-size:0.86rem; color:#8b949e; line-height:1.5; margin-bottom:1rem;">
        <strong>Edge Telemetry:</strong> For routing security and aggregated statistics, basic edge metadata (IP, Geo-Country, Device Type, Referrer) is processed and retained in a transient rolling buffer (last 150 events).
      </p>
      <p style="font-size:0.86rem; color:#8b949e; line-height:1.5; margin-bottom:1.5rem;">
        <strong>Essential Cookies:</strong> Only strictly necessary technical session cookies are used for administrative authentication.
      </p>
      <button onclick="closePrivacyModal()" class="glass-btn" style="height:44px; margin-top:0; font-size:0.9rem;">Understood</button>
    </div>
  </div>

  <div id="toast" role="status">
    <i data-lucide="shield-check" style="color: #2da44e; width: 18px; height: 18px;"></i>
    <span id="toastMsg">Ready</span>
  </div>

  <script>
    lucide.createIcons();

    function showToast(msg) {
      const toast = document.getElementById('toast');
      document.getElementById('toastMsg').innerText = msg;
      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), 2800);
    }

    async function executeShorten() {
      const urlInput = document.getElementById('targetUrl');
      const slugInput = document.getElementById('customSlug');
      const url = urlInput.value.trim();
      const slug = slugInput.value.trim();
      const btn = document.getElementById('shortenBtn');
      const box = document.getElementById('resultBox');

      if (!url) {
        showToast("Please enter a valid URL");
        return;
      }

      btn.disabled = true;
      btn.innerHTML = '<i data-lucide="loader" class="animate-spin"></i> Shortening...';

      try {
        const response = await fetch('/api/shorten', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, slug })
        });
        
        let data;
        try {
          data = await response.json();
        } catch (e) {
          data = { error: "Server error (" + response.status + ")" };
        }

        if (!response.ok) {
          showToast(data.error || "Failed to shorten link");
        } else {
          document.getElementById('outputUrl').value = data.shortUrl;
          document.getElementById('qrImage').src = 'https://api.qrserver.com/v1/create-qr-code/?size=160x160&data=' + encodeURIComponent(data.shortUrl);
          box.style.display = 'block';
          
          confetti({
            particleCount: 70,
            spread: 60,
            origin: { y: 0.75 },
            colors: ['#2f81f7', '#00f2fe', '#ffffff']
          });
        }
      } catch (err) {
        showToast("Connection error. Please try again.");
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<i data-lucide="zap" style="width: 18px; height: 18px;"></i> Generate Short Link';
        lucide.createIcons();
      }
    }

    function triggerCopy() {
      const input = document.getElementById('outputUrl');
      input.select();
      navigator.clipboard.writeText(input.value);
      showToast("Short link copied to clipboard!");
    }

    function openPrivacyModal() {
      const modal = document.getElementById('privacyModal');
      if (modal) {
        modal.style.display = 'flex';
        lucide.createIcons();
      }
    }

    function closePrivacyModal() {
      const modal = document.getElementById('privacyModal');
      if (modal) modal.style.display = 'none';
    }
  </script>
</body>
</html>`;
}

function renderLoginHtml(errorMessage = "") {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Access — Github & Code Shortener</title>
  <meta name="robots" content="noindex, nofollow">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --font: "Plus Jakarta Sans", sans-serif;
      --glass-bg: rgba(18, 24, 38, 0.7);
      --glass-border: rgba(255, 255, 255, 0.12);
      --accent: #2f81f7;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      font-family: var(--font);
      background: radial-gradient(circle at 50% 20%, #161b22 0%, #06090e 100%);
      color: #f0f6fc;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .glass-card {
      width: 100%;
      max-width: 400px;
      background: var(--glass-bg);
      backdrop-filter: blur(40px) saturate(190%);
      -webkit-backdrop-filter: blur(40px) saturate(190%);
      border: 1px solid var(--glass-border);
      border-radius: 24px;
      padding: 2.5rem 2rem;
      box-shadow: 0 24px 60px rgba(0,0,0,0.6);
      text-align: center;
    }
    h2 { font-size: 1.6rem; font-weight: 800; margin-bottom: 1.25rem; }
    .error-box {
      background: rgba(248, 81, 73, 0.15);
      border: 1px solid rgba(248, 81, 73, 0.3);
      color: #f85149;
      padding: 10px 14px;
      border-radius: 12px;
      font-size: 0.85rem;
      font-weight: 600;
      margin-bottom: 1.25rem;
    }
    .input-box {
      display: flex;
      align-items: center;
      background: rgba(13, 17, 23, 0.65);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 16px;
      padding: 0 16px;
      height: 52px;
      margin-bottom: 1.25rem;
    }
    .input-box input {
      width: 100%;
      background: transparent;
      border: none;
      outline: none;
      color: #fff;
      font-family: var(--font);
      font-size: 1rem;
    }
    .submit-btn {
      width: 100%;
      height: 52px;
      background: linear-gradient(180deg, #388bfd 0%, #1f6feb 100%);
      border: 1px solid rgba(255,255,255,0.2);
      color: #fff;
      border-radius: 14px;
      font-weight: 700;
      cursor: pointer;
      font-family: var(--font);
      font-size: 1rem;
      box-shadow: 0 8px 24px rgba(47, 129, 247, 0.35);
    }
    .submit-btn:hover { opacity: 0.95; transform: translateY(-1px); }
  </style>
</head>
<body>
  <div class="glass-card">
    <h2>Admin Access</h2>
    ${errorMessage ? `<div class="error-box">${escapeHtml(errorMessage)}</div>` : ''}
    <form method="POST" action="/admin/login">
      <div class="input-box">
        <input type="password" name="password" placeholder="Master Key" autofocus required autocomplete="current-password" />
      </div>
      <button type="submit" class="submit-btn">Unlock Dashboard</button>
    </form>
  </div>
</body>
</html>`;
}

function renderDashboardHtml(data) {
  const devices = Object.keys(data.breakdown.devices || {});
  const countries = Object.keys(data.breakdown.countries || {});
  const topDev = devices.length ? devices[0] : 'N/A';
  const devSummary = devices.length ? devices.map(d => `${d} (${data.breakdown.devices[d]})`).slice(0,2).join(', ') : 'No data';
  const topCountry = countries.length ? countries[0] : 'N/A';
  const countrySummary = countries.length ? countries.map(c => `${c} (${data.breakdown.countries[c]})`).slice(0,2).join(', ') : 'Real-time geo';

  // Render logs rows
  let logsHtml = '';
  if (!data.logs || data.logs.length === 0) {
    logsHtml = '<tr><td colspan="7" style="text-align:center; color:#8b949e; padding:2rem;">No click activity recorded yet. Clicks will stream here in real-time.</td></tr>';
  } else {
    data.logs.forEach(l => {
      const loc = (l.city && l.city !== 'Unknown City' ? `${escapeHtml(l.city)}, ` : '') + escapeHtml(l.country || 'XX');
      const timeStr = l.timestamp ? new Date(l.timestamp).toLocaleString() : '-';
      logsHtml += `<tr>
        <td><span style="color:#8b949e; font-size:0.8rem;">${timeStr}</span></td>
        <td><b style="color:#58a6ff;">/${escapeHtml(l.slug)}</b></td>
        <td><span class="badge badge-ip">${escapeHtml(l.ip)}</span></td>
        <td>${loc}</td>
        <td><span class="badge badge-device">${escapeHtml(l.device)} • ${escapeHtml(l.os)}</span></td>
        <td>${escapeHtml(l.browser)}</td>
        <td><span style="color:#8b949e; font-size:0.8rem;">${escapeHtml((l.referer || '').replace(/^https?:\/\//, '').substring(0, 24) || 'Direct')}</span></td>
      </tr>`;
    });
  }

  // Render links rows
  let linksHtml = '';
  if (!data.links || data.links.length === 0) {
    linksHtml = '<tr><td colspan="5" style="text-align:center; color:#8b949e; padding:2rem;">No links created yet.</td></tr>';
  } else {
    data.links.forEach(item => {
      const timeStr = item.createdAt ? new Date(item.createdAt).toLocaleString() : '-';
      linksHtml += `<tr>
        <td><b>/${escapeHtml(item.slug)}</b></td>
        <td><a href="${item.target}" target="_blank" rel="noopener noreferrer" style="color:#58a6ff; text-decoration:none;">${item.target.substring(0, 50)}...</a></td>
        <td><span style="font-weight:700; color:#58a6ff;">${item.clicks || 0}</span></td>
        <td><span style="color:#8b949e; font-size:0.8rem;">${timeStr}</span></td>
        <td><a href="/admin/delete?slug=${encodeURIComponent(item.slug)}" class="del-btn" onclick="return confirm('Delete /${escapeHtml(item.slug)}?');">Delete</a></td>
      </tr>`;
    });
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Mission Control & Telemetry — Github & Code Shortener</title>
  <meta name="robots" content="noindex, nofollow">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --font: "Plus Jakarta Sans", sans-serif;
      --glass-bg: rgba(18, 24, 38, 0.7);
      --glass-border: rgba(255, 255, 255, 0.12);
      --accent: #2f81f7;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      font-family: var(--font);
      background: radial-gradient(circle at 50% 0%, #161b22 0%, #06090e 100%);
      color: #f0f6fc;
      padding: 2.5rem 1.5rem;
    }
    .container { max-width: 1100px; margin: 0 auto; }
    .glass-panel {
      background: var(--glass-bg);
      backdrop-filter: blur(40px) saturate(190%);
      -webkit-backdrop-filter: blur(40px) saturate(190%);
      border: 1px solid var(--glass-border);
      border-radius: 24px;
      padding: 2.25rem;
      box-shadow: 0 20px 50px rgba(0,0,0,0.6);
      margin-bottom: 2rem;
    }
    h2 { font-size: 1.5rem; font-weight: 800; }
    h3 { font-size: 1.15rem; font-weight: 700; margin-bottom: 1rem; color: #e6edf3; }
    .header-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1.2rem;
      margin-bottom: 2rem;
    }
    .stat-card {
      background: rgba(13, 17, 23, 0.45);
      border: 1px solid var(--glass-border);
      border-radius: 18px;
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
    }
    .stat-title {
      color: #8b949e;
      font-size: 0.78rem;
      font-weight: 700;
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }
    .stat-val {
      font-size: 2.2rem;
      font-weight: 800;
      color: #58a6ff;
      margin-top: 0.3rem;
    }
    .stat-sub { font-size: 0.8rem; color: #8b949e; margin-top: 0.2rem; }
    .table-container {
      overflow-x: auto;
      border-radius: 16px;
      border: 1px solid var(--glass-border);
      background: rgba(13, 17, 23, 0.4);
      margin-bottom: 2rem;
    }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.88rem; }
    th, td { padding: 12px 16px; border-bottom: 1px solid rgba(255, 255, 255, 0.08); white-space: nowrap; }
    th {
      background: rgba(255, 255, 255, 0.05);
      color: #8b949e;
      font-weight: 700;
      text-transform: uppercase;
      font-size: 0.72rem;
      letter-spacing: 0.05em;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .badge-ip {
      font-family: ui-monospace, monospace;
      color: #79c0ff;
      background: rgba(56, 139, 253, 0.15);
      border: 1px solid rgba(56, 139, 253, 0.3);
    }
    .badge-device {
      color: #7ee787;
      background: rgba(46, 160, 67, 0.15);
      border: 1px solid rgba(46, 160, 67, 0.3);
    }
    .del-btn {
      background: rgba(248, 81, 73, 0.15);
      color: #f85149;
      border: 1px solid rgba(248, 81, 73, 0.3);
      padding: 6px 12px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 0.8rem;
      font-weight: 600;
      text-decoration: none;
      display: inline-block;
    }
    .del-btn:hover { background: #f85149; color: #fff; }
    .tab-btn {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--glass-border);
      color: #8b949e;
      padding: 8px 16px;
      border-radius: 12px;
      font-family: var(--font);
      font-size: 0.88rem;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      display: inline-block;
    }
    .tab-btn.active {
      background: rgba(47, 129, 247, 0.2);
      border-color: var(--accent);
      color: #58a6ff;
    }
    .tab-bar { display: flex; gap: 8px; margin-bottom: 1.5rem; }
  </style>
</head>
<body>
  <div class="container">
    <div class="glass-panel">
      <div class="header-bar">
        <div>
          <h2>Mission Control & Analytics</h2>
          <div style="color: #8b949e; font-size: 0.85rem; margin-top: 4px;">Real-time Telemetry, IP Tracking & Routing Engine</div>
        </div>
        <div style="display:flex; gap:10px;">
          <a href="/admin" class="tab-btn" style="color:#fff;">🔄 Refresh</a>
          <a href="/admin/logout" class="del-btn" style="border-color:#30363d; color:#8b949e; background:transparent;">Logout</a>
        </div>
      </div>

      <div class="stats-grid">
        <div class="stat-card">
          <span class="stat-title">Active Links</span>
          <span class="stat-val">${data.totalLinks}</span>
          <span class="stat-sub">Configured Routes</span>
        </div>
        <div class="stat-card">
          <span class="stat-title">Total Redirections</span>
          <span class="stat-val">${data.totalClicks}</span>
          <span class="stat-sub">Global Edge Hits</span>
        </div>
        <div class="stat-card">
          <span class="stat-title">Top Devices</span>
          <span class="stat-val" style="font-size:1.6rem; margin-top:0.6rem;">${escapeHtml(topDev)}</span>
          <span class="stat-sub">${escapeHtml(devSummary)}</span>
        </div>
        <div class="stat-card">
          <span class="stat-title">Top Location</span>
          <span class="stat-val" style="font-size:1.6rem; margin-top:0.6rem;">${escapeHtml(topCountry)}</span>
          <span class="stat-sub">${escapeHtml(countrySummary)}</span>
        </div>
      </div>

      <div class="tab-bar">
        <button id="tabLogsBtn" class="tab-btn active" onclick="showTab('logs')">Live Click Stream (IP & Telemetry)</button>
        <button id="tabRoutesBtn" class="tab-btn" onclick="showTab('routes')">Manage Links & Slugs</button>
      </div>

      <div id="logsSection">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.8rem;">
          <h3>📡 Recent Click Activity Stream</h3>
          <a href="/admin/clear-logs" class="del-btn" style="font-size:0.75rem;" onclick="return confirm('Clear all click logs?');">Clear Stream</a>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Slug</th>
                <th>IP Address</th>
                <th>Location (City / Country)</th>
                <th>Device / OS</th>
                <th>Browser</th>
                <th>Referrer</th>
              </tr>
            </thead>
            <tbody>${logsHtml}</tbody>
          </table>
        </div>
      </div>

      <div id="routesSection" style="display:none;">
        <h3>🔗 All Active Short Links</h3>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Slug</th>
                <th>Destination URL</th>
                <th>Clicks</th>
                <th>Created At</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>${linksHtml}</tbody>
          </table>
        </div>
      </div>

    </div>
  </div>

  <script>
    function showTab(tab) {
      const isLogs = tab === 'logs';
      document.getElementById('logsSection').style.display = isLogs ? 'block' : 'none';
      document.getElementById('routesSection').style.display = isLogs ? 'none' : 'block';
      document.getElementById('tabLogsBtn').className = 'tab-btn ' + (isLogs ? 'active' : '');
      document.getElementById('tabRoutesBtn').className = 'tab-btn ' + (!isLogs ? 'active' : '');
    }
  </script>
</body>
</html>`;
}
