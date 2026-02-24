const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs/promises");
const fsSync = require("fs");
const os = require("os");
const crypto = require("crypto");
const archiver = require("archiver");

const app = express();

// --- Cookie helpers ---
function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(";").forEach((c) => {
    const [name, ...rest] = c.trim().split("=");
    if (name) cookies[name] = decodeURIComponent(rest.join("="));
  });
  return cookies;
}

function setAuthCookie(res, token, rememberMe) {
  const maxAge = rememberMe ? 30 * 24 * 60 * 60 : "";
  let cookie = `auth=${token}; Path=/; HttpOnly; SameSite=Strict`;
  if (maxAge) cookie += `; Max-Age=${maxAge}`;
  res.setHeader("Set-Cookie", cookie);
}

function clearAuthCookie(res) {
  res.setHeader("Set-Cookie", "auth=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
}

// --- Config system ---
const CONFIG_PATH = path.join(__dirname, "data", "config.json");

function loadConfig() {
  // Priority: ENV vars > config.json > defaults
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
  } catch {
    // No config file yet
  }

  const merged = { ...defaults, ...fileConfig };

  // ENV overrides
  if (process.env.PORT) merged.port = parseInt(process.env.PORT, 10);
  if (process.env.SHARED_DIR) merged.sharedDir = process.env.SHARED_DIR;
  if (process.env.ALLOW_FULL_FILESYSTEM !== undefined) {
    merged.allowFullFilesystem = process.env.ALLOW_FULL_FILESYSTEM === "true" || process.env.ALLOW_FULL_FILESYSTEM === "1";
  }

  // If PASSWORD env var is set and no password hash exists, auto-configure
  if (process.env.PASSWORD && !merged.passwordHash) {
    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto.createHash("sha256").update(process.env.PASSWORD + salt).digest("hex");
    merged.passwordHash = hash;
    merged.salt = salt;
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
    username: cfg.username,
    sharedDir: cfg.sharedDir,
    allowFullFilesystem: cfg.allowFullFilesystem,
    passwordHash: cfg.passwordHash,
    salt: cfg.salt,
  };
  fsSync.writeFileSync(CONFIG_PATH, JSON.stringify(persist, null, 2));
}

function isConfigured() {
  return !!(config.passwordHash && config.salt);
}

function verifyPassword(password) {
  if (!config.passwordHash || !config.salt) return false;
  const hash = crypto.createHash("sha256").update(password + config.salt).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(config.passwordHash));
}

// Token system: HMAC-based with per-token expiry
// Token format: "<issuedAt>.<expiryMs>.<hmac>"
function generateAuthToken(rememberMe) {
  const issuedAt = Date.now().toString();
  const expiryMs = rememberMe ? (30 * 24 * 60 * 60 * 1000).toString() : (24 * 60 * 60 * 1000).toString();
  const payload = issuedAt + "." + expiryMs;
  const hmac = crypto.createHmac("sha256", config.passwordHash).update(payload).digest("hex");
  return payload + "." + hmac;
}

function validateAuthToken(token) {
  if (!token || !config.passwordHash) return false;
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [issuedAt, expiryMs, hmac] = parts;
  const payload = issuedAt + "." + expiryMs;
  const expected = crypto.createHmac("sha256", config.passwordHash).update(payload).digest("hex");
  if (!crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(expected))) return false;
  const expiry = parseInt(expiryMs, 10);
  if (expiry > 0) {
    const age = Date.now() - parseInt(issuedAt, 10);
    if (age > expiry) return false;
  }
  return true;
}

let config = loadConfig();

// --- Rate limiting ---
const rateLimitMap = new Map(); // ip -> { count, resetTime }
const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute

function rateLimit(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress;
  const now = Date.now();
  let entry = rateLimitMap.get(ip);

  if (!entry || now > entry.resetTime) {
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

// Clean up stale rate limit entries every 5 minutes
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

// Get disk usage for a directory
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

// Security: resolve and verify paths
function safePath(requestedPath) {
  if (config.allowFullFilesystem) {
    const resolved = path.resolve(requestedPath || "/");
    if (resolved.includes("\0")) {
      throw new Error("Invalid path");
    }
    return resolved;
  }
  const resolved = path.resolve(config.sharedDir, requestedPath || "");
  if (!resolved.startsWith(config.sharedDir)) {
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
    console.error("Error getting drives:", err);
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
    console.error("Error getting folder tree:", err);
  }

  return folders;
}

// Multer storage configuration
const storage = multer.diskStorage({
  destination: (req, _file, cb) => {
    try {
      const dest = safePath(req.query.path || "");
      cb(null, dest);
    } catch {
      cb(new Error("Invalid path"));
    }
  },
  filename: (_req, file, cb) => {
    cb(null, file.originalname);
  },
});
const upload = multer({ storage, limits: { fileSize: 500 * 1024 * 1024 } });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Auth middleware — reads token from httpOnly cookie
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

// Status endpoint - tells frontend if setup is needed
app.get("/api/status", (_req, res) => {
  res.json({ needsSetup: !isConfigured() });
});

// Setup endpoint - first-run configuration
app.post("/api/setup", rateLimit, (req, res) => {
  if (isConfigured()) {
    return res.status(400).json({ error: "Already configured" });
  }

  const { username, password, sharedDir, allowFullFilesystem } = req.body;
  if (!password || password.length < 1) {
    return res.status(400).json({ error: "Password is required" });
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.createHash("sha256").update(password + salt).digest("hex");

  config.username = (username || "admin").trim().toLowerCase();
  config.passwordHash = hash;
  config.salt = salt;
  if (sharedDir) config.sharedDir = sharedDir;
  if (allowFullFilesystem !== undefined) config.allowFullFilesystem = !!allowFullFilesystem;

  // Ensure shared directory exists
  try {
    if (!fsSync.existsSync(config.sharedDir)) {
      fsSync.mkdirSync(config.sharedDir, { recursive: true });
    }
  } catch (err) {
    return res.status(400).json({ error: "Cannot create shared directory: " + err.message });
  }

  saveConfig(config);
  const token = generateAuthToken(true);
  setAuthCookie(res, token, true);

  res.json({ ok: true });
});

// Auth endpoint - verify username + password, set cookie
app.post("/api/auth", rateLimit, (req, res) => {
  if (!isConfigured()) {
    return res.status(503).json({ error: "Not configured", needsSetup: true });
  }
  const { username, password, rememberMe } = req.body;

  // Validate username
  const expectedUser = (config.username || "admin").toLowerCase();
  if ((username || "").trim().toLowerCase() !== expectedUser) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  if (verifyPassword(password)) {
    const token = generateAuthToken(!!rememberMe);
    setAuthCookie(res, token, !!rememberMe);
    res.json({ ok: true });
  } else {
    res.status(401).json({ error: "Invalid credentials" });
  }
});

// API: Get current settings (non-sensitive)
app.get("/api/settings", requireAuth, (_req, res) => {
  res.json({
    username: config.username || "admin",
    sharedDir: config.sharedDir,
    allowFullFilesystem: config.allowFullFilesystem,
  });
});

// API: Update settings
app.post("/api/settings", requireAuth, (req, res) => {
  const { currentPassword, newPassword, newUsername, sharedDir, allowFullFilesystem } = req.body;

  // Require current password for any settings change
  if (!currentPassword || !verifyPassword(currentPassword)) {
    return res.status(401).json({ error: "Current password is incorrect" });
  }

  // Update username if provided
  if (newUsername !== undefined && newUsername.trim()) {
    config.username = newUsername.trim().toLowerCase();
  }

  // Update password if provided
  if (newPassword) {
    if (newPassword.length < 1) {
      return res.status(400).json({ error: "Password cannot be empty" });
    }
    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto.createHash("sha256").update(newPassword + salt).digest("hex");
    config.passwordHash = hash;
    config.salt = salt;
  }

  // Update shared directory if provided
  if (sharedDir !== undefined && sharedDir !== config.sharedDir) {
    const resolved = path.resolve(sharedDir);
    try {
      if (!fsSync.existsSync(resolved)) {
        fsSync.mkdirSync(resolved, { recursive: true });
      }
      config.sharedDir = resolved;
    } catch (err) {
      return res.status(400).json({ error: "Cannot access directory: " + err.message });
    }
  }

  // Update filesystem access toggle
  if (allowFullFilesystem !== undefined) {
    config.allowFullFilesystem = !!allowFullFilesystem;
  }

  saveConfig(config);

  // Re-issue cookie with new credentials
  const token = generateAuthToken(true);
  setAuthCookie(res, token, true);

  res.json({ ok: true });
});

// Serve static frontend
app.use("/static", express.static(path.join(__dirname, "public")));

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
    filePath = decodeURIComponent(filePath);
    if (!filePath.startsWith("/")) {
      filePath = "/" + filePath;
    }
    const resolved = safePath(filePath);
    res.sendFile(resolved);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// API: System info
app.get("/api/info", requireAuth, async (req, res) => {
  try {
    const machine = getMachineInfo();
    const diskPath = req.query.path ? safePath(req.query.path) : config.sharedDir;
    const disk = await getDiskUsage(diskPath);
    res.json({ machine, disk });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// API: Get mounted drives
app.get("/api/drives", requireAuth, async (req, res) => {
  try {
    const drives = await getMountedDrives();
    res.json(drives);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// API: Get folder tree for a directory
app.get("/api/tree", requireAuth, async (req, res) => {
  try {
    const dirPath = req.query.path || "/";
    const folders = await getFolderTree(dirPath);
    res.json(folders);
  } catch (err) {
    res.status(400).json({ error: err.message });
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
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// API: Upload files
app.post("/api/upload", requireAuth, upload.array("files", 50), (req, res) => {
  res.json({ uploaded: req.files.map((f) => f.originalname) });
});

// API: Create folder
app.post("/api/mkdir", requireAuth, async (req, res) => {
  try {
    const basePath = safePath(req.body.path || config.sharedDir);
    const dir = path.join(basePath, req.body.name);
    await fs.mkdir(dir, { recursive: true });
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// API: Create empty file
app.post("/api/touch", requireAuth, async (req, res) => {
  try {
    const basePath = safePath(req.body.path || config.sharedDir);
    const filePath = path.join(basePath, req.body.name);
    // Don't overwrite existing files
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

// API: Rename file/folder
app.post("/api/rename", requireAuth, async (req, res) => {
  try {
    const oldPath = safePath(req.body.oldPath);
    const newPath = path.join(path.dirname(oldPath), req.body.newName);
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
  } catch (err) {
    res.status(400).json({ error: err.message });
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

    await fs.rename(sourcePath, destPath);
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
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
  } catch (err) {
    res.status(400).json({ error: err.message });
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

// API: Logout — clear auth cookie
app.post("/api/logout", (_req, res) => {
  clearAuthCookie(res);
  res.json({ ok: true });
});

// API: Get file/folder properties
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

    // For directories, calculate recursive size
    if (stat.isDirectory()) {
      let totalSize = 0;
      let fileCount = 0;
      let folderCount = 0;
      async function walk(dir) {
        try {
          const entries = await fs.readdir(dir, { withFileTypes: true });
          for (const entry of entries) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) {
              folderCount++;
              await walk(full);
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
      await walk(target);
      props.totalSize = totalSize;
      props.fileCount = fileCount;
      props.folderCount = folderCount;
    }

    res.json(props);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// API: Download file or folder as ZIP (auth via cookie)
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
      // Stream folder as ZIP
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', `attachment; filename="${fileName}.zip"`);
      res.setHeader('X-Content-Type-Options', 'nosniff');

      const archive = archiver('zip', { zlib: { level: 5 } });
      archive.on('error', (err) => { throw err; });
      archive.pipe(res);
      archive.directory(file, fileName);
      await archive.finalize();
    } else {
      const ext = path.extname(file).toLowerCase();
      const mimeType = MIME_TYPES[ext] || 'application/octet-stream';

      res.setHeader('Content-Type', mimeType);
      res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
      res.setHeader('X-Content-Type-Options', 'nosniff');

      res.download(file, fileName);
    }
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Serve the frontend
app.get("/{*splat}", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(config.port, "0.0.0.0", () => {
  console.log(`File Explorer running at http://0.0.0.0:${config.port}`);
  console.log(`Shared directory: ${config.sharedDir}`);
  console.log(`Full filesystem access: ${config.allowFullFilesystem ? "enabled" : "disabled"}`);
  console.log(`Configured: ${isConfigured() ? "yes" : "no (setup required)"}`);
});
