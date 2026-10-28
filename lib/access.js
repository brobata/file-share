/**
 * @file access.js
 * @description Origin-side verification of the Cloudflare Access JWT
 *   (Cf-Access-Jwt-Assertion). Cloudflare Access already gates the tunnel, but
 *   checking the signed assertion here means a request that reaches the
 *   tunnel's origin some other way (misconfigured Access app, bypass rule,
 *   anything else on this box talking to 127.0.0.1) still can't get in.
 *   Fails closed: missing config, bad signature, wrong aud/iss, expired, or an
 *   email outside the allowlist all reject.
 */
const { createRemoteJWKSet, jwtVerify } = require("jose");

// One JWKS fetcher per URL; jose caches the keys and refetches on unknown kid
const jwksCache = new Map();
function getJwks(url) {
  let jwks = jwksCache.get(url);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(url), { timeoutDuration: 5000, cooldownDuration: 30000 });
    jwksCache.set(url, jwks);
  }
  return jwks;
}

function normalizeTeamDomain(teamDomain) {
  let d = String(teamDomain || "").trim().replace(/\/+$/, "");
  if (d && !/^https:\/\//i.test(d)) d = "https://" + d.replace(/^http:\/\//i, "");
  return d;
}

/**
 * Returns a usable access config or null if anything required is missing.
 * Shape in data/config.json:
 *   "access": { "teamDomain": "brobata.cloudflareaccess.com", "aud": "<AUD tag>",
 *               "allowedEmails": ["a@example.com"] }
 */
function resolveAccessConfig(access) {
  if (!access || typeof access !== "object") return null;
  const issuer = normalizeTeamDomain(access.teamDomain);
  const aud = typeof access.aud === "string" ? access.aud.trim() : "";
  const emails = Array.isArray(access.allowedEmails)
    ? access.allowedEmails.filter((e) => typeof e === "string" && e.trim()).map((e) => e.trim().toLowerCase())
    : [];
  if (!issuer || !aud || !emails.length) return null;
  // Env override exists only so tests can point at a local JWKS server;
  // honoured only under NODE_ENV=test so it can't swap keys in production
  const override = process.env.NODE_ENV === "test" ? process.env.FILESHARE_ACCESS_JWKS_URL : "";
  const jwksUrl = override || `${issuer}/cdn-cgi/access/certs`;
  return { issuer, aud, emails, jwksUrl };
}

/** Resolves to the verified (lowercased) email, or throws. */
async function verifyAccessJwt(token, resolved) {
  if (!resolved) throw new Error("Access not configured");
  if (!token || typeof token !== "string") throw new Error("Missing Access assertion");
  const { payload } = await jwtVerify(token, getJwks(resolved.jwksUrl), {
    issuer: resolved.issuer,
    audience: resolved.aud,
    algorithms: ["RS256"],
    requiredClaims: ["exp"],
  });
  const email = typeof payload.email === "string" ? payload.email.trim().toLowerCase() : "";
  if (!email || !resolved.emails.includes(email)) throw new Error("Email not allowed");
  return email;
}

module.exports = { resolveAccessConfig, verifyAccessJwt, normalizeTeamDomain };
