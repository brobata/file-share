const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs/promises");
const fsSync = require("fs");
const os = require("os");
const crypto = require("crypto");
const { AsyncLocalStorage } = require("async_hooks");
const archiver = require("archiver");
const bcrypt = require("bcryptjs");
const compression = require("compression");
const helmet = require("helmet");
const { verifyTotp } = require("./lib/totp");
const { resolveAccessConfig, verifyAccessJwt } = require("./lib/access");

const app = express();

// --- Tunnel (files.brobata.com via Cloudflare Tunnel + Access) ---
// cloudflared always adds cf-connecting-ip (and Access adds the JWT header);
// LAN requests never carry them. Any one of the three marks a request as
// "via tunnel". Spoofing them from the LAN only makes the request stricter.
const TUNNEL_HOSTS = new Set(["files.brobata.com"]);

function isTunnelRequest(req) {
  if (req._viaTunnel !== undefined) return req._viaTunnel;
  const h = req.headers;
  const host = String(h.host || "").toLowerCase().replace(/:\d+$/, "");
  req._viaTunnel = !!(h["cf-connecting-ip"] || h["cf-access-jwt-assertion"] || TUNNEL_HOSTS.has(host));
  return req._viaTunnel;
}

// Per-request "came through the tunnel" flag for code that never sees req
// (safePath). Lost context reads as tunnel: stricter, never looser.
const requestCtx = new AsyncLocalStorage();
app.use((req, _res, next) => requestCtx.run({ tunnel: isTunnelRequest(req) }, next));

/** Full-filesystem mode applies to LAN/tailnet only. Through the tunnel every
 *  path stays inside sharedDir: writing ~/bin, a project's code or a pm2 app
 *  would be a shell on this box for whoever holds a stolen session. */
function fullFsAllowed(ctx = requestCtx.getStore()) {
  return config.allowFullFilesystem && !!ctx && !ctx.tunnel;
}

// Runs before everything else (static files included): a tunnel request
// without a valid Access assertion for an allowed email gets a bare 403.
app.use(async (req, res, next) => {
  if (!isTunnelRequest(req)) return next();
  try {
    req.accessEmail = await verifyAccessJwt(req.headers["cf-access-jwt-assertion"], resolveAccessConfig(config.access));
  } catch (err) {
    // Log the reason (never the token) so a misconfigured Access app is debuggable
    console.warn(`Tunnel request rejected (${req.method} ${req.path}): ${err.code || err.message}`);
    return res.status(403).type("text/plain").send("Forbidden");
  }
  next();
});

// --- Compression & Security Headers ---
app.use(compression());
app.use(helmet({
  contentSecurityPolicy: false, // inline styles/scripts in single-file SPA
  crossOriginEmbedderPolicy: false, // allow loading file previews
}));

// --- Cookie helpers ---
function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(";").forEach((c) => {
    const [name, ...rest] = c.trim().split("=");
    if (!name) return;
    const value = rest.join("=");
    // A malformed % sequence (possibly from another app on this host) must not throw
    try {
      cookies[name] = decodeURIComponent(value);
    } catch {
      cookies[name] = value;
    }
  });
  return cookies;
}

function setAuthCookie(res, req, token, rememberMe) {
  const tunnel = isTunnelRequest(req);
  // Via tunnel (shared laptop): session cookie only, always Secure
  const maxAge = rememberMe && !tunnel ? 30 * 24 * 60 * 60 : "";
  const secure = tunnel || req.secure || req.headers["x-forwarded-proto"] === "https";
  let cookie = `auth=${token}; Path=/; HttpOnly; SameSite=Strict`;
  if (secure) cookie += "; Secure";
  if (maxAge) cookie += `; Max-Age=${maxAge}`;
  res.setHeader("Set-Cookie", cookie);
}

function clearAuthCookie(res, req) {
  const secure = isTunnelRequest(req) || req.secure || req.headers["x-forwarded-proto"] === "https";
  res.setHeader("Set-Cookie", "auth=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" + (secure ? "; Secure" : ""));
}

// --- Config system ---
// Overridable so tests can run against a temp dir instead of the real data/
const CONFIG_PATH = process.env.FILESHARE_CONFIG_PATH
  ? path.resolve(process.env.FILESHARE_CONFIG_PATH)
  : path.join(__dirname, "data", "config.json");
const CONFIG_BACKUP_PATH = CONFIG_PATH + ".bak";
const REVOKED_PATH = path.join(path.dirname(CONFIG_PATH), "revoked.json");
const BCRYPT_ROUNDS = 12;
const MIN_PASSWORD_LENGTH = 8;

function loadConfig() {
  const defaults = {
    port: 4040,
    sharedDir: path.join(os.homedir(), "shared"),
    allowFullFilesystem: false,
    username: "admin",
  };

  let fileConfig = {};
  try {
    const raw = fsSync.readFileSync(CONFIG_PATH, "utf8");
    fileConfig = JSON.parse(raw);
  } catch (err) {
    if (err.code !== "ENOENT") {
      // Config file exists but is corrupted — try backup
      console.error("WARNING: config.json is corrupted, attempting backup restore");
      try {
        const backupRaw = fsSync.readFileSync(CONFIG_BACKUP_PATH, "utf8");
        fileConfig = JSON.parse(backupRaw);
        // Restore from backup (holds secrets: owner-only)
        fsSync.writeFileSync(CONFIG_PATH, backupRaw, { mode: 0o600 });
        fsSync.chmodSync(CONFIG_PATH, 0o600);
        console.log("Restored config from backup");
      } catch {
        console.error("CRITICAL: No valid config or backup found. Starting fresh.");
      }
    }
  }

  const merged = { ...defaults, ...fileConfig };

  // Generate a separate token secret if missing
  if (!merged.tokenSecret) {
    merged.tokenSecret = crypto.randomBytes(32).toString("hex");
    merged._tokenSecretGenerated = true;
  }

  // ENV overrides
  if (process.env.PORT) merged.port = parseInt(process.env.PORT, 10);
  if (process.env.SHARED_DIR) merged.sharedDir = process.env.SHARED_DIR;
  if (process.env.ALLOW_FULL_FILESYSTEM !== undefined) {
    merged.allowFullFilesystem = process.env.ALLOW_FULL_FILESYSTEM === "true" || process.env.ALLOW_FULL_FILESYSTEM === "1";
  }

  // If PASSWORD env var is set and no password hash exists, auto-configure
  if (process.env.PASSWORD && !merged.passwordHash) {
    merged.passwordHash = bcrypt.hashSync(process.env.PASSWORD, BCRYPT_ROUNDS);
    merged.salt = "bcrypt"; // marker indicating bcrypt is used
    if (!merged.username) merged.username = "admin";
    saveConfig(merged);
  }

  return merged;
}

function saveConfig(cfg) {
  const dir = path.dirname(CONFIG_PATH);
  if (!fsSync.existsSync(dir)) {
    fsSync.mkdirSync(dir, { recursive: true });
  }
  // The server never changes totpSecret or access; scripts/set-totp.js and
  // hand edits do, possibly while this process runs with an older copy in
  // memory. The file wins, so a settings save before the restart can't wipe
  // (or roll back) a fresh enrollment. Adopt it in memory too.
  try {
    const onDisk = JSON.parse(fsSync.readFileSync(CONFIG_PATH, "utf8"));
    if (onDisk.totpSecret) cfg.totpSecret = onDisk.totpSecret;
    if (onDisk.access) cfg.access = onDisk.access;
  } catch {}
  const persist = {
    port: cfg.port,
    username: cfg.username,
    sharedDir: cfg.sharedDir,
    allowFullFilesystem: cfg.allowFullFilesystem,
    passwordHash: cfg.passwordHash,
    salt: cfg.salt,
    tokenSecret: cfg.tokenSecret,
    // Only written when set, so an un-enrolled config stays as it was
    ...(cfg.totpSecret ? { totpSecret: cfg.totpSecret } : {}),
    ...(cfg.access ? { access: cfg.access } : {}),
  };
  const data = JSON.stringify(persist, null, 2);

  // Atomic write: write to temp, then rename. The file holds the password
  // hash, token secret and TOTP secret, so every copy is 0600 (writeFile's
  // mode only applies on create, hence the explicit chmod for a leftover .tmp).
  const tmpPath = CONFIG_PATH + ".tmp";
  // Backup existing config before overwriting
  if (fsSync.existsSync(CONFIG_PATH)) {
    try {
      fsSync.copyFileSync(CONFIG_PATH, CONFIG_BACKUP_PATH);
      fsSync.chmodSync(CONFIG_BACKUP_PATH, 0o600);
    } catch {}
  }
  fsSync.writeFileSync(tmpPath, data, { mode: 0o600 });
  fsSync.chmodSync(tmpPath, 0o600);
  fsSync.renameSync(tmpPath, CONFIG_PATH);
}

function isConfigured() {
  return !!(config.passwordHash && config.salt);
}

function verifyPassword(password) {
  if (!config.passwordHash || !config.salt) return false;
  // Support bcrypt hashes (start with $2) and legacy SHA-256
  if (config.passwordHash.startsWith("$2")) {
    return bcrypt.compareSync(password, config.passwordHash);
  }
  // Legacy SHA-256 path
  const hash = crypto.createHash("sha256").update(password + config.salt).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(config.passwordHash));
}

function upgradePasswordHash(password) {
  // Upgrade legacy SHA-256 hash to bcrypt on successful login
  if (config.passwordHash && !config.passwordHash.startsWith("$2")) {
    config.passwordHash = bcrypt.hashSync(password, BCRYPT_ROUNDS);
    config.salt = "bcrypt";
    saveConfig(config);
  }
}

// Token system: HMAC-based with per-token expiry using dedicated secret.
// LAN tokens: "issuedAt.expiryMs.hmac" (unchanged, so existing sessions survive).
// Tunnel tokens: "tun.issuedAt.expiryMs.hmac" (the scope is covered by the HMAC).
// Via the tunnel only tun-scoped tokens are accepted, so a LAN session (no
// TOTP, up to 30 days) can never be replayed through files.brobata.com.
const TUNNEL_TOKEN_SCOPE = "tun";
const TUNNEL_TOKEN_MAX_MS = 12 * 60 * 60 * 1000;
const MAX_TOKEN_MS = 30 * 24 * 60 * 60 * 1000;

function signToken(payload) {
  return crypto.createHmac("sha256", config.tokenSecret).update(payload).digest("hex");
}

function generateAuthToken(rememberMe, { tunnel = false } = {}) {
  const issuedAt = Date.now().toString();
  if (tunnel) {
    const payload = `${TUNNEL_TOKEN_SCOPE}.${issuedAt}.${TUNNEL_TOKEN_MAX_MS}`;
    return payload + "." + signToken(payload);
  }
  const expiryMs = rememberMe ? MAX_TOKEN_MS.toString() : (24 * 60 * 60 * 1000).toString();
  const payload = issuedAt + "." + expiryMs;
  return payload + "." + signToken(payload);
}

// Returns { hmac, expiresAt, tunnel } for a well-formed, correctly signed,
// unexpired token, else null. Revocation is checked in validateAuthToken.
function parseAuthToken(token) {
  if (!token || typeof token !== "string" || !config.tokenSecret) return null;
  const parts = token.split(".");
  let scope = "";
  if (parts.length === 4 && parts[0] === TUNNEL_TOKEN_SCOPE) scope = parts.shift();
  if (parts.length !== 3) return null;
  const [issuedAt, expiryMs, hmac] = parts;
  const payload = (scope ? scope + "." : "") + issuedAt + "." + expiryMs;
  const hmacBuf = Buffer.from(hmac);
  const expectedBuf = Buffer.from(signToken(payload));
  // timingSafeEqual throws on length mismatch, which would turn a bad cookie into a 500
  if (hmacBuf.length !== expectedBuf.length) return null;
  if (!crypto.timingSafeEqual(hmacBuf, expectedBuf)) return null;
  const issued = parseInt(issuedAt, 10);
  let expiry = parseInt(expiryMs, 10);
  if (!Number.isFinite(issued) || !Number.isFinite(expiry)) return null;
  // Defense in depth: a tunnel token never lives longer than 12h
  if (scope && (expiry <= 0 || expiry > TUNNEL_TOKEN_MAX_MS)) expiry = TUNNEL_TOKEN_MAX_MS;
  if (expiry > 0 && Date.now() - issued > expiry) return null;
  // expiry 0 never comes from generateAuthToken; cap its revocation entry anyway
  const expiresAt = issued + (expiry > 0 ? expiry : MAX_TOKEN_MS);
  return { hmac, expiresAt, tunnel: !!scope };
}

function validateAuthToken(token, { tunnel = false } = {}) {
  const parsed = parseAuthToken(token);
  if (!parsed) return false;
  if (tunnel && !parsed.tunnel) return false;
  return !isTokenRevoked(parsed.hmac);
}

// Request-aware check used by every authenticated route
function isRequestAuthed(req) {
  const cookies = parseCookies(req.headers.cookie);
  return validateAuthToken(cookies.auth, { tunnel: isTunnelRequest(req) });
}

// --- Token revocation (logout) ---
// Tokens are stateless, so logout used to only clear the cookie and a copied
// cookie stayed valid for its full life. Logout now records the token's HMAC
// with its expiry in revoked.json (0600); expired entries are pruned on load
// and on every write, so the file stays small.
let revokedTokens = new Map(); // hmac -> expiresAt (ms)

function loadRevokedTokens() {
  revokedTokens = new Map();
  try {
    const raw = JSON.parse(fsSync.readFileSync(REVOKED_PATH, "utf8"));
    const now = Date.now();
    for (const [hmac, expiresAt] of Object.entries(raw || {})) {
      if (typeof expiresAt === "number" && expiresAt > now) revokedTokens.set(hmac, expiresAt);
    }
  } catch (err) {
    if (err.code !== "ENOENT") console.error("WARNING: revoked.json unreadable, starting with an empty revocation list");
  }
}

function saveRevokedTokens() {
  const now = Date.now();
  for (const [hmac, expiresAt] of revokedTokens) {
    if (expiresAt <= now) revokedTokens.delete(hmac);
  }
  const dir = path.dirname(REVOKED_PATH);
  if (!fsSync.existsSync(dir)) fsSync.mkdirSync(dir, { recursive: true });
  const tmp = REVOKED_PATH + ".tmp";
  fsSync.writeFileSync(tmp, JSON.stringify(Object.fromEntries(revokedTokens)), { mode: 0o600 });
  fsSync.chmodSync(tmp, 0o600);
  fsSync.renameSync(tmp, REVOKED_PATH);
}

function isTokenRevoked(hmac) {
  const expiresAt = revokedTokens.get(hmac);
  if (expiresAt === undefined) return false;
  if (expiresAt <= Date.now()) {
    revokedTokens.delete(hmac);
    return false;
  }
  return true;
}

// Only signed, unexpired tokens are recorded, so an unauthenticated caller
// can't grow the file with junk.
function revokeAuthToken(token) {
  const parsed = parseAuthToken(token);
  if (!parsed) return false;
  revokedTokens.set(parsed.hmac, parsed.expiresAt);
  saveRevokedTokens();
  return true;
}

let config = loadConfig();
// Ensure tokenSecret is persisted if newly generated
if (config._tokenSecretGenerated) {
  delete config._tokenSecretGenerated;
  saveConfig(config);
}
loadRevokedTokens();

// Last accepted TOTP time step, so an observed code can't be replayed.
// In memory is enough: a restart only reopens the current ±30s window.
let lastTotpStep = -1;

// --- Rate limiting ---
const rateLimitMap = new Map();
const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW = 60 * 1000;
const RATE_LIMIT_MAP_MAX = 10000;

function rateLimit(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress;
  const now = Date.now();
  let entry = rateLimitMap.get(ip);

  if (!entry || now > entry.resetTime) {
    if (rateLimitMap.size >= RATE_LIMIT_MAP_MAX && !entry) {
      return res.status(429).json({ error: "Too many requests" });
    }
    entry = { count: 0, resetTime: now + RATE_LIMIT_WINDOW };
    rateLimitMap.set(ip, entry);
  }

  entry.count++;

  if (entry.count > RATE_LIMIT_MAX) {
    const retryAfter = Math.ceil((entry.resetTime - now) / 1000);
    res.setHeader("Retry-After", retryAfter);
    return res.status(429).json({ error: "Too many attempts. Try again in " + retryAfter + "s" });
  }

  next();
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap) {
    if (now > entry.resetTime) rateLimitMap.delete(ip);
  }
}, 5 * 60 * 1000).unref();

// --- Machine info ---
function getMachineInfo() {
  const hostname = os.hostname();
  const interfaces = os.networkInterfaces();
  let ipAddress = "127.0.0.1";

  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === "IPv4" && !iface.internal) {
        ipAddress = iface.address;
        break;
      }
    }
  }

  return { hostname, ipAddress, port: config.port, defaultDir: config.sharedDir };
}

async function getDiskUsage(dir = config.sharedDir) {
  try {
    const stats = await fs.statfs(dir);
    const total = stats.blocks * stats.bsize;
    const free = stats.bfree * stats.bsize;
    const used = total - free;
    return { total, free, used, percent: Math.round((used / total) * 100) };
  } catch {
    return null;
  }
}

// --- Path security ---

// Validate a filename component (no path separators, no traversal)
function validateName(name) {
  if (!name || typeof name !== "string") {
    throw new Error("Name is required");
  }
  if (name.length > 255) {
    throw new Error("Name too long");
  }
  if (name.includes("/") || name.includes("\\") || name.includes("\0")) {
    throw new Error("Invalid characters in name");
  }
  if (name === "." || name === "..") {
    throw new Error("Invalid name");
  }
  return name;
}

// Sanitize an uploaded filename
function sanitizeFilename(name) {
  // Extract just the basename (strip any path components)
  let sanitized = path.basename(name);
  // Remove null bytes
  sanitized = sanitized.replace(/\0/g, "");
  // Fallback if empty after sanitization
  if (!sanitized || sanitized === "." || sanitized === "..") {
    sanitized = "upload_" + Date.now();
  }
  return sanitized;
}

// Sanitize a relative path from a folder upload. Returns { dir, base } where
// dir is a forward-slash relative directory (possibly empty) and base is the
// sanitized filename. Throws on traversal attempts.
function sanitizeRelativePath(name) {
  if (!name || typeof name !== "string") {
    return { dir: "", base: sanitizeFilename(name || "") };
  }
  if (name.includes("\0")) throw new Error("Invalid path");
  // Normalize separators and strip any leading slashes/dots
  const parts = name.replace(/\\/g, "/").split("/").filter(Boolean);
  const segments = [];
  for (const part of parts) {
    if (part === "." || part === "..") throw new Error("Invalid path");
    if (part.length > 255) throw new Error("Name too long");
    segments.push(part);
  }
  if (!segments.length) return { dir: "", base: "upload_" + Date.now() };
  const base = sanitizeFilename(segments.pop());
  return { dir: segments.join("/"), base };
}

// Sensitive paths denied even in full-filesystem mode
const DENIED_PATHS = ["/etc/shadow", "/etc/gshadow"];
const DENIED_PREFIXES = ["/proc", "/sys", "/dev"];

// Hidden paths (any segment starting with ".") are off limits everywhere:
// ~/.ssh/authorized_keys, ~/.bashrc, .env, .git/hooks... A write there is a
// shell takeover, a read leaks credentials. Applies on the LAN too.
function hasHiddenSegment(p) {
  return p.split(/[\\/]+/).some((seg) => seg.startsWith("."));
}

// The lexical check alone is beaten by a symlink (~/keys -> ~/.ssh), so the
// checks also run on the real path. For a path that doesn't exist yet, that's
// the real path of the deepest existing part plus the rest. A dangling
// symlink (~/notes -> ~/.ssh/authorized_keys2, target missing) is followed by
// hand, since realpath can't resolve it but a write would go through it.
// Returns null when it can't tell (loop, permission error): callers fail closed.
const MAX_SYMLINK_HOPS = 40;
function realTarget(resolved, hops = 0) {
  if (hops > MAX_SYMLINK_HOPS) return null;
  let current = resolved;
  const tail = [];
  for (;;) {
    try {
      return path.join(fsSync.realpathSync(current), ...tail);
    } catch (err) {
      if (err.code !== "ENOENT" && err.code !== "ENOTDIR") return null;
      let st = null;
      try { st = fsSync.lstatSync(current); } catch {}
      if (st && st.isSymbolicLink()) {
        const target = path.resolve(path.dirname(current), fsSync.readlinkSync(current));
        return realTarget(path.join(target, ...tail), hops + 1);
      }
      const parent = path.dirname(current);
      if (parent === current) return path.join(current, ...tail);
      tail.unshift(path.basename(current));
      current = parent;
    }
  }
}

function isUnder(p, dir) {
  return p === dir || p.startsWith(dir + path.sep);
}

// The app's own folder (code + data/) is off limits too: data/config.json
// holds the TOTP secret, token secret and password hash, and rewriting
// server.js or revoked.json would undo every other guard.
const PROTECTED_DIRS = [...new Set(
  [__dirname, path.dirname(CONFIG_PATH)].flatMap((d) => {
    const abs = path.resolve(d);
    try { return [abs, fsSync.realpathSync(abs)]; } catch { return [abs]; }
  })
)];

function isForbiddenPath(p) {
  return hasHiddenSegment(p) || PROTECTED_DIRS.some((dir) => isUnder(p, dir));
}

// `req` is passed where the async context can be lost (multer's busboy
// callbacks fire outside it after the first chunk).
function safePath(requestedPath, req) {
  if (requestedPath !== undefined && requestedPath !== null && typeof requestedPath !== "string") {
    throw new Error("Invalid path");
  }
  const fullFs = fullFsAllowed(req ? { tunnel: isTunnelRequest(req) } : undefined);
  const resolved = path.resolve(
    fullFs ? "/" : config.sharedDir,
    requestedPath || (fullFs ? "/" : "")
  );

  if (resolved.includes("\0")) {
    throw new Error("Invalid path");
  }

  if (isForbiddenPath(resolved)) {
    throw new Error("Access denied");
  }
  const real = realTarget(resolved);
  if (real === null || isForbiddenPath(real)) {
    throw new Error("Access denied");
  }

  if (fullFs) {
    // Deny access to sensitive system files even in full-fs mode
    for (const denied of DENIED_PATHS) {
      if (resolved === denied) throw new Error("Access denied");
    }
    for (const prefix of DENIED_PREFIXES) {
      if (resolved.startsWith(prefix + "/") || resolved === prefix) {
        throw new Error("Access denied");
      }
    }
    return resolved;
  }

  // Boundary-safe containment check: a plain startsWith would let
  // /home/user/shared-private slip past a /home/user/shared jail
  const base = path.resolve(config.sharedDir);
  if (resolved !== base && !resolved.startsWith(base + path.sep)) {
    throw new Error("Access denied");
  }
  // ...and where it really leads: a symlink inside the shared folder that
  // points out of it (made on the LAN, or a relative link moved up a level)
  // must not carry a jailed session out.
  let realBase = base;
  try { realBase = fsSync.realpathSync(base); } catch { /* missing: compare as-is */ }
  if (!isUnder(real, realBase) && !isUnder(real, base)) {
    throw new Error("Access denied");
  }
  return resolved;
}

// Get list of mounted drives/volumes
async function getMountedDrives() {
  const drives = [];
  try {
    if (process.platform === "linux") {
      const mounts = await fs.readFile("/proc/mounts", "utf8");
      const lines = mounts.split("\n");
      const seen = new Set();

      for (const line of lines) {
        const parts = line.split(" ");
        if (parts.length < 2) continue;
        const mountPoint = parts[1];

        if (seen.has(mountPoint)) continue;
        if (mountPoint.startsWith("/sys") ||
            mountPoint.startsWith("/proc") ||
            mountPoint.startsWith("/dev") ||
            mountPoint.startsWith("/run") ||
            mountPoint.startsWith("/snap") ||
            mountPoint === "/boot/efi") continue;

        seen.add(mountPoint);

        try {
          await fs.access(mountPoint, fsSync.constants.R_OK);
          const stats = await fs.statfs(mountPoint);
          const total = stats.blocks * stats.bsize;
          const free = stats.bfree * stats.bsize;

          if (total < 100 * 1024 * 1024) continue;

          drives.push({
            path: mountPoint,
            name: mountPoint === "/" ? "Root" : path.basename(mountPoint) || mountPoint,
            total,
            free,
            used: total - free,
          });
        } catch {
          // Skip inaccessible mounts
        }
      }
    }
  } catch (err) {
    console.error("Error getting drives:", err.message);
  }

  const defaultPaths = [
    { path: os.homedir(), name: "Home" },
    { path: config.sharedDir, name: "Shared" },
  ];

  for (const dp of defaultPaths) {
    if (!drives.find(d => d.path === dp.path)) {
      try {
        await fs.access(dp.path, fsSync.constants.R_OK);
        const stats = await fs.statfs(dp.path);
        drives.push({
          path: dp.path,
          name: dp.name,
          total: stats.blocks * stats.bsize,
          free: stats.bfree * stats.bsize,
          used: (stats.blocks - stats.bfree) * stats.bsize,
        });
      } catch {
        // Skip if not accessible
      }
    }
  }

  drives.sort((a, b) => {
    if (a.path === "/") return -1;
    if (b.path === "/") return 1;
    if (a.path === os.homedir()) return -1;
    if (b.path === os.homedir()) return 1;
    if (a.path === config.sharedDir) return -1;
    if (b.path === config.sharedDir) return 1;
    return a.name.localeCompare(b.name);
  });

  return drives;
}

// Get folder tree for a directory (immediate children only)
async function getFolderTree(dirPath) {
  const folders = [];
  try {
    const resolved = safePath(dirPath);
    const entries = await fs.readdir(resolved, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name.startsWith(".")) continue;

      const fullPath = path.join(resolved, entry.name);

      let hasChildren = false;
      try {
        const subEntries = await fs.readdir(fullPath, { withFileTypes: true });
        hasChildren = subEntries.some(e => e.isDirectory() && !e.name.startsWith("."));
      } catch {
        // Can't read subdirectory
      }

      folders.push({
        name: entry.name,
        path: fullPath,
        hasChildren,
      });
    }

    folders.sort((a, b) => a.name.localeCompare(b.name));
  } catch (err) {
    console.error("Error getting folder tree:", err.message);
  }

  return folders;
}

// Multer storage configuration with filename sanitization
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    try {
      const basePath = safePath(req.query.path || "", req);
      const { dir, base } = sanitizeRelativePath(file.originalname);
      // Refuse a hidden final target before creating any folders for it
      safePath(path.join(basePath, dir, base), req);
      if (!dir) return cb(null, basePath);
      const dest = safePath(path.join(basePath, dir), req);
      fs.mkdir(dest, { recursive: true })
        .then(() => cb(null, dest))
        .catch(() => cb(new Error("Failed to create upload directory")));
    } catch {
      cb(new Error("Invalid path"));
    }
  },
  filename: (req, file, cb) => {
    try {
      const { dir, base } = sanitizeRelativePath(file.originalname);
      const basePath = safePath(req.query.path || "", req);
      const destDir = dir ? safePath(path.join(basePath, dir), req) : basePath;
      // "Keep both": append (1), (2)... instead of overwriting
      const name = req.query.mode === "rename" ? uniqueFilename(destDir, base) : base;
      // Check the final target too: an upload named ".bashrc" into ~ must fail
      safePath(path.join(destDir, name), req);
      cb(null, name);
    } catch {
      cb(new Error("Invalid filename"));
    }
  },
});

function uniqueFilename(dir, base) {
  if (!fsSync.existsSync(path.join(dir, base))) return base;
  const ext = path.extname(base);
  const stem = base.slice(0, base.length - ext.length);
  for (let i = 1; i < 1000; i++) {
    const candidate = `${stem} (${i})${ext}`;
    if (!fsSync.existsSync(path.join(dir, candidate))) return candidate;
  }
  throw new Error("Too many name collisions");
}
const upload = multer({
  storage,
  preservePath: true,
  limits: { fileSize: 500 * 1024 * 1024, files: 2000 },
});

// /api/save has its own 5mb parser; the global parser must not consume its body first
const jsonBodyParser = express.json({ limit: "100kb" });
app.use((req, res, next) => (req.path === "/api/save" ? next() : jsonBodyParser(req, res, next)));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));

// Auth middleware
function requireAuth(req, res, next) {
  if (!isConfigured()) {
    return res.status(503).json({ error: "Not configured", needsSetup: true });
  }
  if (isRequestAuthed(req)) {
    return next();
  }
  res.status(401).json({ error: "Unauthorized" });
}

// --- Unauthenticated endpoints ---

app.get("/api/status", (req, res) => {
  const tunnel = isTunnelRequest(req);
  // The login form shows the code box / hides "Remember me" from these
  res.json({ needsSetup: !isConfigured(), totpRequired: tunnel, rememberMeAllowed: !tunnel });
});

// Setup endpoint - first-run configuration
app.post("/api/setup", rateLimit, (req, res) => {
  if (isConfigured()) {
    return res.status(400).json({ error: "Already configured" });
  }
  // First-run setup sets the password with no second factor: LAN only
  if (isTunnelRequest(req)) {
    return res.status(403).json({ error: "Finish setup from the local network first" });
  }

  const { username, password, sharedDir, allowFullFilesystem } = req.body;
  if (!password || password.length < MIN_PASSWORD_LENGTH) {
    return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters` });
  }

  config.passwordHash = bcrypt.hashSync(password, BCRYPT_ROUNDS);
  config.salt = "bcrypt";
  config.username = (username || "admin").trim().toLowerCase();
  if (sharedDir) config.sharedDir = sharedDir;
  if (allowFullFilesystem !== undefined) config.allowFullFilesystem = !!allowFullFilesystem;

  // Ensure shared directory exists
  try {
    if (!fsSync.existsSync(config.sharedDir)) {
      fsSync.mkdirSync(config.sharedDir, { recursive: true });
    }
  } catch {
    return res.status(400).json({ error: "Cannot create shared directory" });
  }

  saveConfig(config);
  const token = generateAuthToken(true);
  setAuthCookie(res, req, token, true);

  res.json({ ok: true });
});

// Auth endpoint
app.post("/api/auth", rateLimit, (req, res) => {
  if (!isConfigured()) {
    return res.status(503).json({ error: "Not configured", needsSetup: true });
  }
  const { username, password } = req.body;
  const tunnel = isTunnelRequest(req);
  // Via tunnel: never a 30-day cookie on a shared laptop
  const rememberMe = !tunnel && !!req.body.rememberMe;

  let totpStep = null;
  if (tunnel) {
    // Fail closed: internet logins need a second factor, so no secret = no login
    if (!config.totpSecret) {
      return res.status(403).json({ error: "Two-factor code is not set up on the server. Run scripts/set-totp.js on the server first." });
    }
    // Checked before the password so a missing code never reveals whether the password was right
    const code = String(req.body.code || "").replace(/\s+/g, "");
    if (!code) {
      return res.status(400).json({ error: "Enter the 6-digit code from your authenticator app", totpRequired: true });
    }
    totpStep = verifyTotp(config.totpSecret, code, { lastStep: lastTotpStep });
  }

  const expectedUser = (config.username || "admin").toLowerCase();
  const userOk = typeof username === "string" && username.trim().toLowerCase() === expectedUser;
  const passwordOk = userOk && typeof password === "string" && verifyPassword(password);

  if (!passwordOk || (tunnel && totpStep === null)) {
    // One message for every failure: don't say which factor was wrong
    return res.status(401).json({ error: tunnel ? "Invalid credentials or code" : "Invalid credentials" });
  }

  // Burn the step only once both factors passed, so a wrong password can't use up a valid code
  if (tunnel) lastTotpStep = totpStep;
  upgradePasswordHash(password);
  const token = generateAuthToken(rememberMe, { tunnel });
  setAuthCookie(res, req, token, rememberMe);
  res.json({ ok: true });
});

app.get("/api/settings", requireAuth, (_req, res) => {
  res.json({
    username: config.username || "admin",
    sharedDir: config.sharedDir,
    // What this session can do: tunnel sessions are always jailed
    allowFullFilesystem: fullFsAllowed(),
  });
});

app.post("/api/settings", requireAuth, (req, res) => {
  const { currentPassword, newPassword, newUsername } = req.body;
  // Moving the jail (sharedDir: "/") or turning on full access from the
  // internet would undo the tunnel restriction: those are LAN/tailnet only,
  // and silently ignored here so a password change still works remotely.
  const { sharedDir, allowFullFilesystem } = isTunnelRequest(req) ? {} : req.body;

  if (!currentPassword || !verifyPassword(currentPassword)) {
    return res.status(401).json({ error: "Current password is incorrect" });
  }

  if (newUsername !== undefined && newUsername.trim()) {
    config.username = newUsername.trim().toLowerCase();
  }

  if (newPassword) {
    if (newPassword.length < MIN_PASSWORD_LENGTH) {
      return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters` });
    }
    config.passwordHash = bcrypt.hashSync(newPassword, BCRYPT_ROUNDS);
    config.salt = "bcrypt";
    // Rotate the token secret so every other session is logged out;
    // this request gets a fresh cookie below, so this device stays in
    config.tokenSecret = crypto.randomBytes(32).toString("hex");
  }

  if (sharedDir !== undefined && sharedDir !== config.sharedDir) {
    const resolved = path.resolve(sharedDir);
    try {
      if (!fsSync.existsSync(resolved)) {
        fsSync.mkdirSync(resolved, { recursive: true });
      }
      config.sharedDir = resolved;
    } catch {
      return res.status(400).json({ error: "Cannot access directory" });
    }
  }

  if (allowFullFilesystem !== undefined) {
    config.allowFullFilesystem = !!allowFullFilesystem;
  }

  saveConfig(config);

  // Keep the same session kind: a tunnel session stays short and tunnel-scoped
  const tunnel = isTunnelRequest(req);
  const token = generateAuthToken(!tunnel, { tunnel });
  setAuthCookie(res, req, token, !tunnel);

  res.json({ ok: true });
});

// Serve static frontend with caching
app.use("/static", express.static(path.join(__dirname, "public"), { maxAge: "1d", etag: true }));

// Vendored third-party assets (CodeMirror) — long cache, public scope so script tags can reference /vendor/...
app.use("/vendor", express.static(path.join(__dirname, "public", "vendor"), { maxAge: "30d", etag: true, immutable: true }));

// PWA files must be served from root scope
app.get("/sw.js", (_req, res) => res.sendFile(path.join(__dirname, "public", "sw.js")));
app.get("/manifest.json", (_req, res) => res.sendFile(path.join(__dirname, "public", "manifest.json")));
app.get("/icon-192.svg", (_req, res) => res.type("image/svg+xml").sendFile(path.join(__dirname, "public", "icon-192.svg")));
app.get("/icon-512.svg", (_req, res) => res.type("image/svg+xml").sendFile(path.join(__dirname, "public", "icon-512.svg")));
app.get("/icon-maskable.svg", (_req, res) => res.type("image/svg+xml").sendFile(path.join(__dirname, "public", "icon-maskable.svg")));
app.get("/icon-192.png", (_req, res) => res.type("image/png").sendFile(path.join(__dirname, "public", "icon-192.png")));
app.get("/icon-512.png", (_req, res) => res.type("image/png").sendFile(path.join(__dirname, "public", "icon-512.png")));
app.get("/icon-maskable-512.png", (_req, res) => res.type("image/png").sendFile(path.join(__dirname, "public", "icon-maskable-512.png")));

// File extensions that should never be served with their natural MIME type
const UNSAFE_EXTENSIONS = new Set([".html", ".htm", ".svg", ".xml", ".xhtml", ".svgz"]);

// Serve files from any path for previews (auth via cookie)
// Via tunnel, file bytes must not linger in the shared laptop's HTTP cache
// (or Cloudflare's edge cache, which caches by extension)
function noStoreOnTunnel(req, res) {
  if (isTunnelRequest(req)) res.setHeader("Cache-Control", "private, no-store");
}

app.get("/files/{*filepath}", (req, res) => {
  if (!isRequestAuthed(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  noStoreOnTunnel(req, res);
  try {
    let filePath = req.params.filepath || "";
    if (Array.isArray(filePath)) {
      filePath = filePath.join("/");
    }
    // Express 5 already URL-decodes params; decoding again corrupts names containing %
    if (!filePath.startsWith("/")) {
      filePath = "/" + filePath;
    }
    const resolved = safePath(filePath);
    const ext = path.extname(resolved).toLowerCase();

    // Serve potentially dangerous file types as plain text
    if (UNSAFE_EXTENSIONS.has(ext)) {
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.setHeader("X-Content-Type-Options", "nosniff");
    }
    res.sendFile(resolved);
  } catch {
    res.status(400).json({ error: "File not accessible" });
  }
});

// API: System info
app.get("/api/info", requireAuth, async (req, res) => {
  try {
    const machine = getMachineInfo();
    const diskPath = req.query.path ? safePath(req.query.path) : config.sharedDir;
    const disk = await getDiskUsage(diskPath);
    res.json({ machine, disk });
  } catch {
    res.status(400).json({ error: "Failed to get system info" });
  }
});

app.get("/api/drives", requireAuth, async (_req, res) => {
  try {
    const drives = (await getMountedDrives()).filter((d) => fullFsAllowed() || d.path === config.sharedDir);
    res.json(drives);
  } catch {
    res.status(400).json({ error: "Failed to list drives" });
  }
});

app.get("/api/tree", requireAuth, async (req, res) => {
  try {
    const dirPath = req.query.path || "/";
    const folders = await getFolderTree(dirPath);
    res.json(folders);
  } catch {
    res.status(400).json({ error: "Failed to load folder tree" });
  }
});

// API: List directory contents
app.get("/api/list", requireAuth, async (req, res) => {
  try {
    const dir = safePath(req.query.path || config.sharedDir);
    const entries = await fs.readdir(dir, { withFileTypes: true });
    const items = await Promise.all(
      entries.map(async (entry) => {
        // Hidden entries are never listed (the old ?hidden=true is ignored): safePath refuses them anyway
        if (entry.name.startsWith(".")) return null;

        const fullPath = path.join(dir, entry.name);
        let stat;
        try {
          stat = await fs.stat(fullPath);
        } catch {
          return null;
        }
        return {
          name: entry.name,
          isDirectory: entry.isDirectory(),
          size: stat.size,
          modified: stat.mtime,
          created: stat.birthtime,
          permissions: '0' + (stat.mode & 0o777).toString(8),
          path: fullPath,
        };
      })
    );
    res.json(items.filter(Boolean).sort((a, b) => {
      if (a.isDirectory !== b.isDirectory) return a.isDirectory ? -1 : 1;
      return a.name.localeCompare(b.name);
    }));
  } catch {
    res.status(400).json({ error: "Failed to list directory" });
  }
});

// API: Upload files
// API: Check which upload targets already exist, so the client can ask
// before overwriting. Best-effort — the upload itself decides via ?mode=.
app.post("/api/upload-check", requireAuth, (req, res) => {
  try {
    const basePath = safePath(req.body.path || "");
    const files = Array.isArray(req.body.files) ? req.body.files.slice(0, 2000) : [];
    const existing = [];
    for (const rel of files) {
      if (typeof rel !== "string") continue;
      try {
        const { dir, base } = sanitizeRelativePath(rel);
        const target = safePath(path.join(basePath, dir, base));
        if (fsSync.existsSync(target)) existing.push(rel);
      } catch {
        // Invalid names get rejected by the upload itself
      }
    }
    res.json({ existing });
  } catch {
    res.status(400).json({ error: "Check failed" });
  }
});

app.post("/api/upload", requireAuth, upload.array("files", 2000), (req, res) => {
  res.json({ uploaded: req.files.map((f) => f.originalname) });
}, (err, req, res, next) => {
  // Multer errors (file too big, invalid path) must return JSON, not an HTML 500
  if (err instanceof multer.MulterError) {
    const status = err.code === "LIMIT_FILE_SIZE" ? 413 : 400;
    return res.status(status).json({ error: err.message });
  }
  res.status(400).json({ error: err.message || "Upload failed" });
});

// API: Create folder — validates name to prevent path traversal
app.post("/api/mkdir", requireAuth, async (req, res) => {
  try {
    validateName(req.body.name);
    const basePath = safePath(req.body.path || config.sharedDir);
    const dir = path.join(basePath, req.body.name);
    safePath(dir); // re-validate the final path
    await fs.mkdir(dir, { recursive: true });
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// API: Create empty file — validates name to prevent path traversal
app.post("/api/touch", requireAuth, async (req, res) => {
  try {
    validateName(req.body.name);
    const basePath = safePath(req.body.path || config.sharedDir);
    const filePath = path.join(basePath, req.body.name);
    safePath(filePath); // re-validate the final path
    try {
      await fs.access(filePath);
      return res.status(400).json({ error: "File already exists" });
    } catch {
      // Good, doesn't exist
    }
    await fs.writeFile(filePath, "");
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// API: Save text content to an existing file
app.post("/api/save", requireAuth, express.json({ limit: "5mb" }), async (req, res) => {
  try {
    const filePath = safePath(req.body.path);
    const content = typeof req.body.content === "string" ? req.body.content : "";
    const stat = await fs.stat(filePath);
    if (stat.isDirectory()) throw new Error("Cannot save: path is a directory");
    await fs.writeFile(filePath, content, "utf8");
    res.json({ ok: true, size: Buffer.byteLength(content, "utf8") });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// API: Rename file/folder — validates newName to prevent path traversal
app.post("/api/rename", requireAuth, async (req, res) => {
  try {
    validateName(req.body.newName);
    const oldPath = safePath(req.body.oldPath);
    const newPath = path.join(path.dirname(oldPath), req.body.newName);
    safePath(newPath); // re-validate the final path
    await fs.rename(oldPath, newPath);
    res.json({ ok: true, newPath });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// API: Copy file/folder to another location
app.post("/api/copy", requireAuth, async (req, res) => {
  try {
    const sourcePath = safePath(req.body.sourcePath);
    const destPath = safePath(req.body.destPath);

    await fs.access(sourcePath);

    try {
      await fs.access(destPath);
      return res.status(400).json({ error: "File already exists in destination" });
    } catch {
      // Good, destination doesn't exist
    }

    await fs.cp(sourcePath, destPath, { recursive: true });
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "Copy failed" });
  }
});

// API: Move file to another folder
app.post("/api/move", requireAuth, async (req, res) => {
  try {
    const sourcePath = safePath(req.body.sourcePath);
    const destPath = safePath(req.body.destPath);

    await fs.access(sourcePath);

    try {
      await fs.access(destPath);
      return res.status(400).json({ error: "File already exists in destination" });
    } catch {
      // Good, destination doesn't exist
    }

    try {
      await fs.rename(sourcePath, destPath);
    } catch (err) {
      if (err.code === "EXDEV") {
        // rename can't cross filesystems (e.g. moving to a mounted drive)
        await fs.cp(sourcePath, destPath, { recursive: true });
        await fs.rm(sourcePath, { recursive: true, force: true });
      } else {
        throw err;
      }
    }
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "Move failed" });
  }
});

// API: Delete file/folder
app.delete("/api/delete", requireAuth, async (req, res) => {
  try {
    const target = safePath(req.body.path);
    const stat = await fs.stat(target);
    if (stat.isDirectory()) {
      await fs.rm(target, { recursive: true });
    } else {
      await fs.unlink(target);
    }
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "Delete failed" });
  }
});

// MIME type mapping for common file types
const MIME_TYPES = {
  '.txt': 'text/plain',
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.xml': 'application/xml',
  '.pdf': 'application/pdf',
  '.zip': 'application/zip',
  '.gz': 'application/gzip',
  '.tar': 'application/x-tar',
  '.rar': 'application/vnd.rar',
  '.7z': 'application/x-7z-compressed',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav',
  '.ogg': 'audio/ogg',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.mov': 'video/quicktime',
  '.avi': 'video/x-msvideo',
  '.mkv': 'video/x-matroska',
  '.doc': 'application/msword',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.ppt': 'application/vnd.ms-powerpoint',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
};

// Sanitize filename for Content-Disposition header
function safeContentDisposition(filename, type = "attachment") {
  const ascii = filename.replace(/[^\x20-\x7E]/g, "_").replace(/"/g, "'");
  const encoded = encodeURIComponent(filename);
  return `${type}; filename="${ascii}"; filename*=UTF-8''${encoded}`;
}

// API: Logout
// Revokes the token server-side too, so a copy of the cookie dies with it
app.post("/api/logout", (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  try {
    revokeAuthToken(cookies.auth);
  } catch (err) {
    console.error("Failed to record token revocation:", err.message);
    clearAuthCookie(res, req);
    return res.status(500).json({ error: "Signed out on this device, but the server could not revoke the session" });
  }
  clearAuthCookie(res, req);
  res.json({ ok: true });
});

// API: Get file/folder properties with depth/count limits
app.get("/api/properties", requireAuth, async (req, res) => {
  try {
    const target = safePath(req.query.path);
    const stat = await fs.stat(target);
    const props = {
      name: path.basename(target),
      path: target,
      isDirectory: stat.isDirectory(),
      size: stat.size,
      created: stat.birthtime,
      modified: stat.mtime,
      accessed: stat.atime,
      permissions: '0' + (stat.mode & 0o777).toString(8),
    };

    if (stat.isDirectory()) {
      let totalSize = 0;
      let fileCount = 0;
      let folderCount = 0;
      let truncated = false;
      const MAX_FILES = 100000;
      const MAX_DEPTH = 50;

      async function walk(dir, depth) {
        if (truncated || depth > MAX_DEPTH) { truncated = true; return; }
        try {
          const entries = await fs.readdir(dir, { withFileTypes: true });
          for (const entry of entries) {
            if (fileCount + folderCount > MAX_FILES) { truncated = true; return; }
            if (entry.name.startsWith(".")) continue; // hidden paths are off limits, sizes included
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) {
              folderCount++;
              await walk(full, depth + 1);
            } else {
              fileCount++;
              try {
                // lstat: a symlink into a hidden folder must not reveal its target's size
                const s = await fs.lstat(full);
                totalSize += s.size;
              } catch {}
            }
          }
        } catch {}
      }
      await walk(target, 0);
      props.totalSize = totalSize;
      props.fileCount = fileCount;
      props.folderCount = folderCount;
      if (truncated) props.truncated = true;
    }

    res.json(props);
  } catch {
    res.status(400).json({ error: "Failed to get properties" });
  }
});

// API: Download file or folder as ZIP
app.get("/api/download", async (req, res) => {
  if (!isRequestAuthed(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  noStoreOnTunnel(req, res);
  try {
    const file = safePath(req.query.path);
    const stat = await fs.stat(file);
    const fileName = path.basename(file);

    if (stat.isDirectory()) {
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', safeContentDisposition(fileName + ".zip"));
      res.setHeader('X-Content-Type-Options', 'nosniff');

      const archive = archiver('zip', { zlib: { level: 5 } });
      archive.on('error', () => {
        if (!res.headersSent) res.status(500).end();
        else res.destroy();
      });
      // Stop walking/reading the tree if the client cancels the download
      res.on('close', () => archive.destroy());
      archive.pipe(res);
      // A folder ZIP must not carry hidden children (zipping ~ would include ~/.ssh).
      // archiver stores symlinks as links (lstat), so no content leaks through them.
      archive.directory(file, fileName, (entry) => (hasHiddenSegment(entry.name) ? false : entry));
      await archive.finalize();
    } else {
      const ext = path.extname(file).toLowerCase();
      const mimeType = MIME_TYPES[ext] || 'application/octet-stream';

      res.setHeader('Content-Type', mimeType);
      res.setHeader('Content-Disposition', safeContentDisposition(fileName));
      res.setHeader('X-Content-Type-Options', 'nosniff');

      res.download(file, fileName);
    }
  } catch {
    if (!res.headersSent) res.status(400).json({ error: "Download failed" });
  }
});

// Serve the frontend
app.get("/{*splat}", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Ensure shared directory exists on startup
try {
  if (!fsSync.existsSync(config.sharedDir)) {
    fsSync.mkdirSync(config.sharedDir, { recursive: true });
    console.log(`Created shared directory: ${config.sharedDir}`);
  }
} catch (err) {
  console.error(`WARNING: Cannot create shared directory ${config.sharedDir}: ${err.message}`);
}

// --- Start server (plain HTTP) ---
const startLog = () => {
  console.log(`Shared directory: ${config.sharedDir}`);
  console.log(`Full filesystem access: ${config.allowFullFilesystem ? "enabled" : "disabled"}`);
  console.log(`Configured: ${isConfigured() ? "yes" : "no (setup required)"}`);
};

// Listen only when run directly; tests require() the module and listen on a random port
if (require.main === module) {
  const host = process.env.HOST || "0.0.0.0";
  app.listen(config.port, host, () => {
    console.log(`File Explorer running at http://${host}:${config.port}`);
    startLog();
    if (!resolveAccessConfig(config.access)) console.log("Tunnel access: NOT configured (all tunnel requests get 403)");
    if (!config.totpSecret) console.log("Tunnel two-factor: NOT enrolled (tunnel logins refused; run scripts/set-totp.js)");
  });
}

module.exports = {
  app,
  safePath,
  hasHiddenSegment,
  generateAuthToken,
  validateAuthToken,
  revokeAuthToken,
  isTunnelRequest,
  _withRequestContextForTests: (ctx, fn) => requestCtx.run(ctx, fn),
  getConfig: () => config,
  REVOKED_PATH,
  _resetRateLimitForTests: () => rateLimitMap.clear(),
};
