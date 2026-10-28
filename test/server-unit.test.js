/**
 * @file server-unit.test.js
 * @description safePath hidden-path rejection (lexical + symlink), tunnel
 *   detection, and auth token scope/expiry/revocation in server.js.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { makeSandbox } = require("./helpers");

const sandbox = makeSandbox();
const server = require("../server");
const F = sandbox.filesDir;

test.after(() => sandbox.cleanup());

test("safePath refuses hidden paths for reads", () => {
  for (const p of [
    path.join(F, ".ssh"),
    path.join(F, ".ssh", "authorized_keys"),
    path.join(F, "project", ".env"),
    path.join(F, ".bashrc"),
    path.join(F, "project", "..", ".bashrc"),
    path.join(F, "project", ".git", "config"),
  ]) {
    assert.throws(() => server.safePath(p), /Access denied/, p);
  }
});

test("safePath refuses hidden write targets that don't exist yet", () => {
  for (const p of [
    path.join(F, ".config", "autostart", "x.desktop"),
    path.join(F, "project", ".git", "hooks", "pre-commit"),
    path.join(F, "new-dir", ".profile"),
  ]) {
    assert.throws(() => server.safePath(p), /Access denied/, p);
  }
});

test("safePath refuses a symlink that leads into a hidden dir", () => {
  assert.throws(() => server.safePath(path.join(F, "keys")), /Access denied/);
  assert.throws(() => server.safePath(path.join(F, "keys", "authorized_keys")), /Access denied/);
  assert.throws(() => server.safePath(path.join(F, "keys", "new-file")), /Access denied/);
});

test("safePath refuses dangling symlinks whose target would be hidden", () => {
  assert.throws(() => server.safePath(path.join(F, "notes2.txt")), /Access denied/);
  assert.throws(() => server.safePath(path.join(F, "notes3.txt")), /Access denied/, "chain of links");
});

test("safePath refuses symlink loops (can't tell = deny)", () => {
  const a = path.join(F, "loop-a");
  const b = path.join(F, "loop-b");
  fs.symlinkSync(b, a);
  fs.symlinkSync(a, b);
  assert.throws(() => server.safePath(a), /Access denied/);
});

test("safePath refuses the app's own folder and its config dir", () => {
  const appDir = path.resolve(__dirname, "..");
  assert.throws(() => server.safePath(path.join(appDir, "server.js")), /Access denied/);
  assert.throws(() => server.safePath(appDir), /Access denied/);
  assert.throws(() => server.safePath(sandbox.configPath), /Access denied/);
  assert.throws(() => server.safePath(path.join(sandbox.dataDir, "revoked.json")), /Access denied/);
  // A symlink pointing at the config dir is refused too
  const link = path.join(F, "cfg-link");
  fs.symlinkSync(sandbox.dataDir, link);
  assert.throws(() => server.safePath(path.join(link, "config.json")), /Access denied/);
  // Siblings with a shared prefix are not caught by mistake
  const lan = (fn) => server._withRequestContextForTests({ tunnel: false }, fn);
  assert.equal(lan(() => server.safePath(sandbox.dataDir + "-other")), sandbox.dataDir + "-other");
});

test("full-filesystem mode is LAN-only: tunnel (or no request context) stays in sharedDir", () => {
  const outside = sandbox.dataDir + "-other";
  const lan = (fn) => server._withRequestContextForTests({ tunnel: false }, fn);
  const tun = (fn) => server._withRequestContextForTests({ tunnel: true }, fn);
  assert.equal(lan(() => server.safePath(outside)), outside);
  assert.throws(() => tun(() => server.safePath(outside)), /Access denied/);
  assert.throws(() => tun(() => server.safePath("/etc/hostname")), /Access denied/);
  assert.throws(() => server.safePath(outside), /Access denied/, "lost context fails closed");
  // A link inside the shared folder pointing out of it doesn't carry a jailed
  // session out — existing target or not — but still works on the LAN
  const outDir = sandbox.dataDir + "-escape";
  fs.mkdirSync(outDir, { recursive: true });
  fs.symlinkSync(outDir, path.join(F, "escape"));
  assert.throws(() => tun(() => server.safePath(path.join(F, "escape", "bin", "evil"))), /Access denied/);
  assert.throws(() => tun(() => server.safePath(path.join(F, "escape"))), /Access denied/);
  assert.equal(lan(() => server.safePath(path.join(F, "escape", "x"))), path.join(F, "escape", "x"));
  // Inside sharedDir still works via the tunnel
  assert.equal(tun(() => server.safePath(path.join(F, "project", "notes.txt"))), path.join(F, "project", "notes.txt"));
});

test("safePath still allows normal paths, existing or not", () => {
  assert.equal(server.safePath(path.join(F, "project", "notes.txt")), path.join(F, "project", "notes.txt"));
  assert.equal(server.safePath(path.join(F, "project")), path.join(F, "project"));
  assert.equal(server.safePath(path.join(F, "new", "deep", "file.txt")), path.join(F, "new", "deep", "file.txt"));
  // Names that merely contain a dot are fine
  assert.equal(server.safePath(path.join(F, "a.b", "c..d")), path.join(F, "a.b", "c..d"));
});

test("safePath rejects non-string paths", () => {
  assert.throws(() => server.safePath(["a"]), /Invalid path/);
  assert.throws(() => server.safePath({}), /Invalid path/);
});

test("safePath in shared-dir jail mode also refuses hidden paths", () => {
  const cfg = server.getConfig();
  cfg.allowFullFilesystem = false;
  try {
    assert.throws(() => server.safePath("project/.env"), /Access denied/);
    assert.throws(() => server.safePath(".ssh/authorized_keys"), /Access denied/);
    assert.equal(server.safePath("project/notes.txt"), path.join(F, "project", "notes.txt"));
  } finally {
    cfg.allowFullFilesystem = true;
  }
});

test("hasHiddenSegment", () => {
  assert.equal(server.hasHiddenSegment("/home/x/.ssh/id"), true);
  assert.equal(server.hasHiddenSegment("project/.env"), true);
  assert.equal(server.hasHiddenSegment("/home/x/file.txt"), false);
});

test("isTunnelRequest", () => {
  const req = (headers) => ({ headers });
  assert.equal(server.isTunnelRequest(req({ "cf-connecting-ip": "1.2.3.4" })), true);
  assert.equal(server.isTunnelRequest(req({ "cf-access-jwt-assertion": "x" })), true);
  assert.equal(server.isTunnelRequest(req({ host: "files.brobata.com" })), true);
  assert.equal(server.isTunnelRequest(req({ host: "FILES.BROBATA.COM:443" })), true);
  assert.equal(server.isTunnelRequest(req({ host: "192.168.1.44:4040" })), false);
  assert.equal(server.isTunnelRequest(req({})), false);
});

test("LAN tokens validate, are refused via tunnel, and die on revocation", () => {
  const token = server.generateAuthToken(true);
  assert.equal(server.validateAuthToken(token), true);
  assert.equal(server.validateAuthToken(token, { tunnel: true }), false, "LAN token must not work via tunnel");
  assert.equal(server.revokeAuthToken(token), true);
  assert.equal(server.validateAuthToken(token), false);
  // Persisted 0600, keyed by the HMAC (not the whole token)
  const stat = fs.statSync(server.REVOKED_PATH);
  assert.equal(stat.mode & 0o777, 0o600);
  const saved = JSON.parse(fs.readFileSync(server.REVOKED_PATH, "utf8"));
  assert.ok(saved[token.split(".").pop()] > Date.now());
});

test("tunnel tokens are tun-scoped, valid on both, and revocable", () => {
  const token = server.generateAuthToken(true, { tunnel: true });
  assert.match(token, /^tun\.\d+\.43200000\.[0-9a-f]{64}$/, "12h regardless of rememberMe");
  assert.equal(server.validateAuthToken(token, { tunnel: true }), true);
  assert.equal(server.validateAuthToken(token), true);
  server.revokeAuthToken(token);
  assert.equal(server.validateAuthToken(token, { tunnel: true }), false);
});

test("tampered, malformed and expired tokens are refused; junk is never recorded", () => {
  const secret = server.getConfig().tokenSecret;
  const sign = (p) => p + "." + crypto.createHmac("sha256", secret).update(p).digest("hex");
  const token = server.generateAuthToken(false);
  const [iat, exp, mac] = token.split(".");
  assert.equal(server.validateAuthToken(`${iat}.${Number(exp) * 2}.${mac}`), false, "longer expiry, old hmac");
  assert.equal(server.validateAuthToken(`tun.${iat}.${exp}.${mac}`), false, "scope added without re-signing");
  assert.equal(server.validateAuthToken("garbage"), false);
  assert.equal(server.validateAuthToken(undefined), false);
  assert.equal(server.validateAuthToken(sign(`${Date.now() - 25 * 3600e3}.${24 * 3600e3}`)), false, "expired LAN");
  assert.equal(server.validateAuthToken(sign(`tun.${Date.now() - 13 * 3600e3}.${30 * 24 * 3600e3}`), { tunnel: true }), false, "tunnel token capped at 12h");
  const before = fs.readFileSync(server.REVOKED_PATH, "utf8");
  assert.equal(server.revokeAuthToken("garbage.1.2"), false);
  assert.equal(fs.readFileSync(server.REVOKED_PATH, "utf8"), before);
});
