/**
 * @file integration.test.js
 * @description Boots the real app on a random port against a temp config and
 *   a local JWKS server, then drives it over HTTP: Access JWT gate, TOTP
 *   login via tunnel, short/Secure tunnel cookies, unchanged LAN login,
 *   hidden-path refusal on write routes, and logout revocation.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const http = require("http");
const path = require("path");
const { generateKeyPair, exportJWK, SignJWT } = require("jose");
const { base32Encode, totp } = require("../lib/totp");
const { makeSandbox, TEST_PASSWORD, TEST_AUD, TEST_TEAM, TEST_EMAIL } = require("./helpers");

const TOTP_SECRET = base32Encode(Buffer.from("integration-test-key"));
const sandbox = makeSandbox({ totpSecret: TOTP_SECRET });
const F = sandbox.filesDir;

let base; // http://127.0.0.1:<port>
let appServer;
let jwksServer;
let privateKey;
let otherKey;
let server;

async function signJwt({ email = TEST_EMAIL, aud = TEST_AUD, iss = TEST_TEAM, exp = "5m", key = privateKey } = {}) {
  return new SignJWT({ email })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .setIssuer(iss)
    .setAudience(aud)
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(key);
}

function listen(srv) {
  return new Promise((resolve) => srv.listen(0, "127.0.0.1", () => resolve(srv.address().port)));
}

test.before(async () => {
  const pair = await generateKeyPair("RS256", { extractable: true });
  const jwk = { ...(await exportJWK(pair.publicKey)), kid: "test-key", alg: "RS256", use: "sig" };
  privateKey = pair.privateKey;
  ({ privateKey: otherKey } = await generateKeyPair("RS256"));

  jwksServer = http.createServer((req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  const jwksPort = await listen(jwksServer);
  process.env.FILESHARE_ACCESS_JWKS_URL = `http://127.0.0.1:${jwksPort}/cdn-cgi/access/certs`;

  server = require("../server");
  appServer = http.createServer(server.app);
  base = `http://127.0.0.1:${await listen(appServer)}`;
});

test.after(() => {
  appServer && appServer.close();
  jwksServer && jwksServer.close();
  sandbox.cleanup();
});

// Each test starts with a clean login rate limit (5/min per IP, all of ours are 127.0.0.1)
test.beforeEach(() => server._resetRateLimitForTests());

const TUNNEL = { "cf-connecting-ip": "203.0.113.7", "x-forwarded-proto": "https" };

async function tunnelHeaders(extra = {}) {
  return { ...TUNNEL, "cf-access-jwt-assertion": await signJwt(), ...extra };
}

function post(url, body, headers = {}) {
  return fetch(base + url, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
}

function cookieFrom(res) {
  const set = res.headers.get("set-cookie") || "";
  const m = set.match(/auth=([^;]*)/);
  return m ? m[1] : null;
}

// A fresh, not-yet-used code: the server refuses a step at or before the last accepted one
let codeOffset = 0;
function nextCode() {
  // Steps must strictly increase within the ±1 window: current, then +1
  if (codeOffset > 1) throw new Error("test used more fresh codes than the window allows");
  return totp(TOTP_SECRET, { nowMs: Date.now() + codeOffset++ * 30000 });
}

async function lanLogin(rememberMe = false) {
  const res = await post("/api/auth", { username: "admin", password: TEST_PASSWORD, rememberMe });
  assert.equal(res.status, 200);
  return { res, cookie: cookieFrom(res) };
}

test("tunnel requests without a valid Access JWT get 403 before anything else", async () => {
  for (const url of ["/", "/static/manifest.json", "/api/status", "/sw.js"]) {
    const res = await fetch(base + url, { headers: TUNNEL });
    assert.equal(res.status, 403, url);
  }
  const bad = [
    await signJwt({ aud: "wrong-aud" }),
    await signJwt({ iss: "https://evil.cloudflareaccess.com" }),
    await signJwt({ email: "intruder@example.com" }),
    await signJwt({ exp: Math.floor(Date.now() / 1000) - 60 }),
    await signJwt({ key: otherKey }),
    "not-a-jwt",
  ];
  for (const jwt of bad) {
    const res = await fetch(base + "/api/status", { headers: { ...TUNNEL, "cf-access-jwt-assertion": jwt } });
    assert.equal(res.status, 403);
  }
  // The JWT header alone (no cf-connecting-ip) also marks a tunnel request
  const res = await fetch(base + "/", { headers: { "cf-access-jwt-assertion": "nope" } });
  assert.equal(res.status, 403);
});

test("valid Access JWT (email matched case-insensitively) passes; status asks for a code", async () => {
  const res = await fetch(base + "/api/status", { headers: await tunnelHeaders() });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { needsSetup: false, totpRequired: true, rememberMeAllowed: false });
  const page = await fetch(base + "/", { headers: await tunnelHeaders() });
  assert.equal(page.status, 200);
});

test("tunnel login: no code 400, wrong code 401, right code ok, replay 401", async () => {
  const creds = { username: "admin", password: TEST_PASSWORD, rememberMe: true };

  let res = await post("/api/auth", creds, await tunnelHeaders());
  assert.equal(res.status, 400);
  assert.equal((await res.json()).totpRequired, true);
  assert.equal(cookieFrom(res), null);

  const good = nextCode();
  const wrong = String((Number(good) + 1) % 1e6).padStart(6, "0");
  res = await post("/api/auth", { ...creds, code: wrong }, await tunnelHeaders());
  assert.equal(res.status, 401);

  // Right code, wrong password: refused, and the code is NOT burned
  res = await post("/api/auth", { ...creds, password: "wrong-password", code: good }, await tunnelHeaders());
  assert.equal(res.status, 401);

  res = await post("/api/auth", { ...creds, code: good.slice(0, 3) + " " + good.slice(3) }, await tunnelHeaders());
  assert.equal(res.status, 200);
  const setCookie = res.headers.get("set-cookie");
  assert.match(setCookie, /; Secure/);
  assert.doesNotMatch(setCookie, /Max-Age/, "session cookie even with rememberMe");
  const cookie = cookieFrom(res);
  assert.match(cookie, /^tun\.\d+\.43200000\./);

  res = await post("/api/auth", { ...creds, code: good }, await tunnelHeaders());
  assert.equal(res.status, 401, "same code twice is a replay");

  // The tunnel session works via the tunnel...
  res = await fetch(base + "/api/settings", { headers: await tunnelHeaders({ cookie: `auth=${cookie}` }) });
  assert.equal(res.status, 200);
  // ...but not without the Access JWT
  res = await fetch(base + "/api/settings", { headers: { ...TUNNEL, cookie: `auth=${cookie}` } });
  assert.equal(res.status, 403);

  // Logout revokes it server-side
  res = await post("/api/logout", {}, await tunnelHeaders({ cookie: `auth=${cookie}` }));
  assert.equal(res.status, 200);
  assert.match(res.headers.get("set-cookie"), /Max-Age=0; Secure/);
  res = await fetch(base + "/api/settings", { headers: await tunnelHeaders({ cookie: `auth=${cookie}` }) });
  assert.equal(res.status, 401);
});

test("a LAN session cookie is refused via the tunnel", async () => {
  const { cookie } = await lanLogin(true);
  const res = await fetch(base + "/api/settings", { headers: await tunnelHeaders({ cookie: `auth=${cookie}` }) });
  assert.equal(res.status, 401);
});

test("tunnel login with no TOTP secret configured is refused (fail closed)", async () => {
  const cfg = server.getConfig();
  const saved = cfg.totpSecret;
  delete cfg.totpSecret;
  try {
    const res = await post("/api/auth", { username: "admin", password: TEST_PASSWORD, code: "123456" }, await tunnelHeaders());
    assert.equal(res.status, 403);
    assert.match((await res.json()).error, /set-totp/);
  } finally {
    cfg.totpSecret = saved;
  }
});

test("tunnel request with no access config is refused (fail closed)", async () => {
  const cfg = server.getConfig();
  const saved = cfg.access;
  delete cfg.access;
  try {
    const res = await fetch(base + "/api/status", { headers: await tunnelHeaders() });
    assert.equal(res.status, 403);
  } finally {
    cfg.access = saved;
  }
});

test("LAN behaviour is unchanged: no code, remember-me cookie, no Secure", async () => {
  let res = await fetch(base + "/api/status");
  assert.deepEqual(await res.json(), { needsSetup: false, totpRequired: false, rememberMeAllowed: true });

  const { res: login, cookie } = await lanLogin(true);
  const setCookie = login.headers.get("set-cookie");
  assert.match(setCookie, /Max-Age=2592000/);
  assert.doesNotMatch(setCookie, /Secure/);
  assert.match(cookie, /^\d+\.2592000000\./, "same token format as before");

  res = await post("/api/auth", { username: "admin", password: "nope" });
  assert.equal(res.status, 401);

  res = await fetch(base + "/api/list?path=" + encodeURIComponent(path.join(F, "project")), { headers: { cookie: `auth=${cookie}` } });
  assert.equal(res.status, 200);
  const names = (await res.json()).map((i) => i.name);
  assert.deepEqual(names, ["notes.txt"]);

  // ?hidden=true no longer reveals anything
  res = await fetch(base + "/api/list?hidden=true&path=" + encodeURIComponent(path.join(F, "project")), { headers: { cookie: `auth=${cookie}` } });
  assert.deepEqual((await res.json()).map((i) => i.name), ["notes.txt"]);

  // LAN logout revokes too
  res = await post("/api/logout", {}, { cookie: `auth=${cookie}` });
  assert.equal(res.status, 200);
  res = await fetch(base + "/api/settings", { headers: { cookie: `auth=${cookie}` } });
  assert.equal(res.status, 401);
});

test("write routes refuse hidden paths; nothing is changed", async () => {
  const { cookie } = await lanLogin();
  const h = { cookie: `auth=${cookie}` };
  const keys = path.join(F, ".ssh", "authorized_keys");
  const bashrc = path.join(F, ".bashrc");

  const cases = [
    ["/api/save", { path: keys, content: "PWNED" }],
    ["/api/save", { path: path.join(F, "keys", "authorized_keys"), content: "PWNED" }],
    ["/api/save", { path: path.join(F, "project", ".env"), content: "PWNED" }],
    ["/api/touch", { path: F, name: ".profile" }],
    ["/api/mkdir", { path: F, name: ".config" }],
    ["/api/rename", { oldPath: path.join(F, "project", "notes.txt"), newName: ".bashrc" }],
    ["/api/rename", { oldPath: bashrc, newName: "bashrc" }],
    ["/api/copy", { sourcePath: path.join(F, "project", "notes.txt"), destPath: path.join(F, ".ssh", "authorized_keys2") }],
    ["/api/copy", { sourcePath: keys, destPath: path.join(F, "stolen") }],
    ["/api/move", { sourcePath: path.join(F, "project", "notes.txt"), destPath: path.join(F, ".hidden-notes") }],
    ["/api/move", { sourcePath: path.join(F, ".ssh"), destPath: path.join(F, "ssh") }],
    ["/api/upload-check", { path: F, files: [".bashrc"] }],
  ];
  for (const [url, body] of cases) {
    const res = await post(url, body, h);
    if (url === "/api/upload-check") {
      assert.deepEqual((await res.json()).existing, [], "hidden targets are not reported");
    } else {
      assert.ok(res.status >= 400 && res.status < 500, `${url} ${JSON.stringify(body)} -> ${res.status}`);
    }
  }

  let res = await fetch(base + "/api/delete", { method: "DELETE", headers: { "Content-Type": "application/json", ...h }, body: JSON.stringify({ path: keys }) });
  assert.equal(res.status, 400);

  // Upload: a ".bashrc" file into a normal folder, and a folder upload into ".ssh/"
  for (const name of [".bashrc", ".ssh/authorized_keys", "ok/.env"]) {
    const form = new FormData();
    form.append("files", new Blob(["PWNED"]), name);
    res = await fetch(base + "/api/upload?path=" + encodeURIComponent(F), { method: "POST", headers: h, body: form });
    assert.equal(res.status, 400, `upload ${name}`);
  }
  // Upload destination itself hidden
  const form = new FormData();
  form.append("files", new Blob(["PWNED"]), "x.txt");
  res = await fetch(base + "/api/upload?path=" + encodeURIComponent(path.join(F, ".ssh")), { method: "POST", headers: h, body: form });
  assert.equal(res.status, 400);

  // Reads too
  for (const url of [
    "/files" + keys,
    "/api/download?path=" + encodeURIComponent(keys),
    "/api/properties?path=" + encodeURIComponent(path.join(F, ".ssh")),
    "/api/list?path=" + encodeURIComponent(path.join(F, ".ssh")),
  ]) {
    res = await fetch(base + url, { headers: h });
    assert.equal(res.status, 400, url);
  }
  res = await fetch(base + "/api/tree?path=" + encodeURIComponent(path.join(F, ".ssh")), { headers: h });
  assert.deepEqual(await res.json(), []);

  assert.equal(fs.readFileSync(keys, "utf8"), "ORIGINAL");
  assert.equal(fs.readFileSync(bashrc, "utf8"), "ORIGINAL");
  assert.equal(fs.readFileSync(path.join(F, "project", ".env"), "utf8"), "SECRET=1");
  assert.equal(fs.existsSync(path.join(F, ".profile")), false);
  assert.equal(fs.existsSync(path.join(F, ".config")), false);
  assert.equal(fs.existsSync(path.join(F, "stolen")), false);
  assert.equal(fs.existsSync(path.join(F, "ok")), false, "folder upload must not leave a partial dir");
  assert.equal(fs.readFileSync(path.join(F, "project", "notes.txt"), "utf8"), "hello");

  // Normal writes still work
  res = await post("/api/save", { path: path.join(F, "project", "notes.txt"), content: "edited" }, h);
  assert.equal(res.status, 200);
  assert.equal(fs.readFileSync(path.join(F, "project", "notes.txt"), "utf8"), "edited");
});

test("folder ZIP download leaves hidden children out", async () => {
  const { cookie } = await lanLogin();
  const res = await fetch(base + "/api/download?path=" + encodeURIComponent(path.join(F, "project")), { headers: { cookie: `auth=${cookie}` } });
  assert.equal(res.status, 200);
  const zip = Buffer.from(await res.arrayBuffer());
  assert.ok(zip.includes("notes.txt"));
  assert.ok(!zip.includes(".env"), "hidden .env must not be in the zip");
});

test("tunnel file responses are not cacheable", async () => {
  const code = nextCode();
  let res = await post("/api/auth", { username: "admin", password: TEST_PASSWORD, code }, await tunnelHeaders());
  assert.equal(res.status, 200);
  const cookie = cookieFrom(res);
  res = await fetch(base + "/files" + path.join(F, "project", "notes.txt"), { headers: await tunnelHeaders({ cookie: `auth=${cookie}` }) });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("cache-control"), "private, no-store");
});

test("saving settings keeps totpSecret + access in config.json and writes it 0600", async () => {
  const { cookie } = await lanLogin();
  const res = await post("/api/settings", { currentPassword: TEST_PASSWORD }, { cookie: `auth=${cookie}` });
  assert.equal(res.status, 200);
  const stat = fs.statSync(sandbox.configPath);
  assert.equal(stat.mode & 0o777, 0o600);
  assert.equal(fs.statSync(sandbox.configPath + ".bak").mode & 0o777, 0o600);
  const saved = JSON.parse(fs.readFileSync(sandbox.configPath, "utf8"));
  assert.equal(saved.totpSecret, TOTP_SECRET);
  assert.equal(saved.access.aud, TEST_AUD);
});
