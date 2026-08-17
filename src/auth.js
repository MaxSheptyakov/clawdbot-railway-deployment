// Wrapper authentication shared by /setup and the dashboard proxy.
//
// Basic auth alone is not enough here: the Control UI sends its own
// `Authorization: Bearer <gateway token>` on API/SSE calls, which replaces the
// browser's cached Basic credentials. The wrapper then saw a non-Basic scheme,
// answered 401 + WWW-Authenticate, and Chrome re-opened the login dialog on every
// such request — an endless password prompt on top of an already-loaded page.
//
// After one successful password entry we issue a signed session cookie. Cookies are
// attached by the browser to *every* same-origin request (XHR, SSE and even WebSocket
// handshakes) regardless of what Authorization header the app sets, so the dialog
// never comes back.

import crypto from "node:crypto";

export const AUTH_COOKIE = "openclaw_dash";
export const AUTH_REALM = "OpenClaw";
export const AUTH_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export function safeEqual(a, b) {
  const bufA = Buffer.from(String(a ?? ""), "utf8");
  const bufB = Buffer.from(String(b ?? ""), "utf8");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

export function parseCookies(header) {
  const out = {};
  for (const part of String(header || "").split(";")) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    const key = part.slice(0, idx).trim();
    if (!key) continue;
    try {
      out[key] = decodeURIComponent(part.slice(idx + 1).trim());
    } catch {
      out[key] = part.slice(idx + 1).trim();
    }
  }
  return out;
}

// Only top-level navigations may trigger the native browser login dialog.
// Answering an XHR/fetch/SSE 401 with WWW-Authenticate is what produced the popup storm.
export function isBrowserNavigation(req) {
  const headers = req?.headers ?? {};
  const dest = headers["sec-fetch-dest"];
  if (dest) return dest === "document" || dest === "iframe";
  const mode = headers["sec-fetch-mode"];
  if (mode) return mode === "navigate";
  return String(headers.accept || "").includes("text/html");
}

/**
 * @param {object} opts
 * @param {string} [opts.password] wrapper password (SETUP_PASSWORD); empty → everything is open
 * @param {string} [opts.gatewayToken] gateway admin token, accepted as a Bearer credential
 */
export function createAuth({ password, gatewayToken } = {}) {
  const secret = crypto
    .createHash("sha256")
    // Both inputs are stable across restarts, so sessions survive redeploys.
    .update(`${password ?? ""}\n${gatewayToken ?? ""}`)
    .digest();

  function signSession(expiresAt) {
    const mac = crypto.createHmac("sha256", secret).update(String(expiresAt)).digest("hex");
    return `v1.${expiresAt}.${mac}`;
  }

  function verifySession(value) {
    if (!value) return false;
    const parts = String(value).split(".");
    if (parts.length !== 3 || parts[0] !== "v1") return false;
    const expiresAt = Number.parseInt(parts[1], 10);
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return false;
    return safeEqual(value, signSession(expiresAt));
  }

  /** @returns {"open"|"cookie"|"password"|"token"|null} */
  function authorize(req) {
    if (!password) return "open";

    const headers = req?.headers ?? {};
    if (verifySession(parseCookies(headers.cookie)[AUTH_COOKIE])) return "cookie";

    const header = headers.authorization || "";
    const sep = header.indexOf(" ");
    const scheme = (sep > 0 ? header.slice(0, sep) : "").toLowerCase();
    const value = sep > 0 ? header.slice(sep + 1).trim() : "";

    if (scheme === "basic" && value) {
      const decoded = Buffer.from(value, "base64").toString("utf8");
      const idx = decoded.indexOf(":");
      return safeEqual(idx >= 0 ? decoded.slice(idx + 1) : "", password) ? "password" : null;
    }

    // Non-browser clients (CLI, remote gateway clients) authenticate with the gateway token.
    if (scheme === "bearer" && value && gatewayToken && safeEqual(value, gatewayToken)) {
      return "token";
    }

    return null;
  }

  function sessionCookie(req) {
    const forwardedProto = String(req?.headers?.["x-forwarded-proto"] || "").split(",")[0].trim();
    const secure = forwardedProto === "https" || req?.socket?.encrypted === true;
    const attrs = [
      `${AUTH_COOKIE}=${signSession(Date.now() + AUTH_TTL_MS)}`,
      "Path=/",
      "HttpOnly",
      "SameSite=Lax",
      `Max-Age=${Math.floor(AUTH_TTL_MS / 1000)}`,
    ];
    if (secure) attrs.push("Secure");
    return attrs.join("; ");
  }

  function issueSession(req, res) {
    res.append("Set-Cookie", sessionCookie(req));
  }

  function deny(req, res, message = "Auth required") {
    if (isBrowserNavigation(req)) {
      res.set("WWW-Authenticate", `Basic realm="${AUTH_REALM}"`);
    }
    return res.status(401).type("text/plain").send(message);
  }

  return { authorize, deny, issueSession, sessionCookie, signSession, verifySession };
}
