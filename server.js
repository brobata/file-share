const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs/promises");
const fsSync = require("fs");
const os = require("os");
const crypto = require("crypto");
const archiver = require("archiver");
const bcrypt = require("bcryptjs");
const compression = require("compression");
const helmet = require("helmet");

const app = express();

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
  const maxAge = rememberMe ? 30 * 24 * 60 * 60 : "";
  const secure = req.secure || req.headers["x-forwarded-proto"] === "https";
  let cookie = `auth=${token}; Path=/; HttpOnly; SameSite=Strict`;
  if (secure) cookie += "; Secure";
  if (maxAge) cookie += `; Max-Age=${maxAge}`;
  res.setHeader("Set-Cookie", cookie);
}

function clearAuthCookie(res) {
  res.setHeader("Set-Cookie", "auth=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
}

// --- Config system ---
const CONFIG_PATH = path.join(__dirname, "data", "config.json");
const CONFIG_BACKUP_PATH = CONFIG_PATH + ".bak";
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
        // Restore from backup
        fsSync.writeFileSync(CONFIG_PATH, backupRaw);
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
  const persist = {
    port: cfg.port,
    username: cfg.username,
    sharedDir: cfg.sharedDir,
    allowFullFilesystem: cfg.allowFullFilesystem,
    passwordHash: cfg.passwordHash,
    salt: cfg.salt,
    tokenSecret: cfg.tokenSecret,
  };
  const data = JSON.stringify(persist, null, 2);

  // Atomic write: write to temp, then rename
  const tmpPath = CONFIG_PATH + ".tmp";
  // Backup existing config before overwriting
  if (fsSync.existsSync(CONFIG_PATH)) {
    try { fsSync.copyFileSync(CONFIG_PATH, CONFIG_BACKUP_PATH); } catch {}
  }
  fsSync.writeFileSync(tmpPath, data);
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

// Token system: HMAC-based with per-token expiry using dedicated secret
function generateAuthToken(rememberMe) {
  const issuedAt = Date.now().toString();
  const expiryMs = rememberMe ? (30 * 24 * 60 * 60 * 1000).toString() : (24 * 60 * 60 * 1000).toString();
  const payload = issuedAt + "." + expiryMs;
  const hmac = crypto.createHmac("sha256", config.tokenSecret).update(payload).digest("hex");
  return payload + "." + hmac;
}

function validateAuthToken(token) {
  if (!token || !config.tokenSecret) return false;
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [issuedAt, expiryMs, hmac] = parts;
  const payload = issuedAt + "." + expiryMs;
  const expected = crypto.createHmac("sha256", config.tokenSecret).update(payload).digest("hex");
  const hmacBuf = Buffer.from(hmac);
  const expectedBuf = Buffer.from(expected);
  // timingSafeEqual throws on length mismatch, which would turn a bad cookie into a 500
  if (hmacBuf.length !== expectedBuf.length) return false;
  if (!crypto.timingSafeEqual(hmacBuf, expectedBuf)) return false;
  const expiry = parseInt(expiryMs, 10);
  if (expiry > 0) {
    const age = Date.now() - parseInt(issuedAt, 10);
    if (age > expiry) return false;
  }
  return true;
}

let config = loadConfig();
// Ensure tokenSecret is persisted if newly generated
if (config._tokenSecretGenerated) {
  delete config._tokenSecretGenerated;
  saveConfig(config);
}

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

function safePath(requestedPath) {
  const resolved = path.resolve(
    config.allowFullFilesystem ? "/" : config.sharedDir,
    requestedPath || (config.allowFullFilesystem ? "/" : "")
  );

  if (resolved.includes("\0")) {
    throw new Error("Invalid path");
  }

  if (config.allowFullFilesystem) {
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
      const basePath = safePath(req.query.path || "");
      const { dir } = sanitizeRelativePath(file.originalname);
      if (!dir) return cb(null, basePath);
      const dest = safePath(path.join(basePath, dir));
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
      if (req.query.mode === "rename") {
        // "Keep both": append (1), (2)... instead of overwriting
        const basePath = safePath(req.query.path || "");
        const destDir = dir ? safePath(path.join(basePath, dir)) : basePath;
        return cb(null, uniqueFilename(destDir, base));
      }
      cb(null, base);
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
  const cookies = parseCookies(req.headers.cookie);
  if (validateAuthToken(cookies.auth)) {
    return next();
  }
  res.status(401).json({ error: "Unauthorized" });
}

// --- Unauthenticated endpoints ---

app.get("/api/status", (_req, res) => {
  res.json({ needsSetup: !isConfigured() });
});

// Setup endpoint - first-run configuration
app.post("/api/setup", rateLimit, (req, res) => {
  if (isConfigured()) {
    return res.status(400).json({ error: "Already configured" });
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
  const { username, password, rememberMe } = req.body;

  const expectedUser = (config.username || "admin").toLowerCase();
  if ((username || "").trim().toLowerCase() !== expectedUser) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  if (verifyPassword(password)) {
    upgradePasswordHash(password);
    const token = generateAuthToken(!!rememberMe);
    setAuthCookie(res, req, token, !!rememberMe);
    res.json({ ok: true });
  } else {
    res.status(401).json({ error: "Invalid credentials" });
  }
});

app.get("/api/settings", requireAuth, (_req, res) => {
  res.json({
    username: config.username || "admin",
    sharedDir: config.sharedDir,
    allowFullFilesystem: config.allowFullFilesystem,
  });
});

app.post("/api/settings", requireAuth, (req, res) => {
  const { currentPassword, newPassword, newUsername, sharedDir, allowFullFilesystem } = req.body;

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

  const token = generateAuthToken(true);
  setAuthCookie(res, req, token, true);

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
app.get("/files/{*filepath}", (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  if (!validateAuthToken(cookies.auth)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
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
    const drives = await getMountedDrives();
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
    const showHidden = req.query.hidden === "true";
    const entries = await fs.readdir(dir, { withFileTypes: true });
    const items = await Promise.all(
      entries.map(async (entry) => {
        if (!showHidden && entry.name.startsWith(".")) return null;

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
app.post("/api/logout", (_req, res) => {
  clearAuthCookie(res);
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
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) {
              folderCount++;
              await walk(full, depth + 1);
            } else {
              fileCount++;
              try {
                const s = await fs.stat(full);
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
  const cookies = parseCookies(req.headers.cookie);
  if (!validateAuthToken(cookies.auth)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
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
      archive.directory(file, fileName);
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

const host = process.env.HOST || "0.0.0.0";
app.listen(config.port, host, () => {
  console.log(`File Explorer running at http://${host}:${config.port}`);
  startLog();
});
