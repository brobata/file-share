/**
 * @file helpers.js
 * @description Shared test setup: a throwaway config dir + file tree under
 *   the OS temp dir, wired in through FILESHARE_CONFIG_PATH / SHARED_DIR
 *   before server.js is required, so tests never touch the real data/ or ~/.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const bcrypt = require("bcryptjs");

const TEST_PASSWORD = "correct-horse-battery";
const TEST_AUD = "test-aud-0123456789";
const TEST_TEAM = "https://example-team.cloudflareaccess.com";
const TEST_EMAIL = "Owner@Example.com";

function makeSandbox({ totpSecret, access = true } = {}) {
  // realpath: on some systems the temp dir itself is a symlink
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "fileshare-test-")));
  const dataDir = path.join(root, "data");
  const filesDir = path.join(root, "files");
  fs.mkdirSync(dataDir);
  fs.mkdirSync(path.join(filesDir, "project"), { recursive: true });
  fs.mkdirSync(path.join(filesDir, ".ssh"));
  fs.writeFileSync(path.join(filesDir, ".ssh", "authorized_keys"), "ORIGINAL");
  fs.writeFileSync(path.join(filesDir, "project", ".env"), "SECRET=1");
  fs.writeFileSync(path.join(filesDir, "project", "notes.txt"), "hello");
  fs.writeFileSync(path.join(filesDir, ".bashrc"), "ORIGINAL");
  // A symlink with an innocent name pointing into a hidden dir
  fs.symlinkSync(path.join(filesDir, ".ssh"), path.join(filesDir, "keys"));

  const config = {
    port: 0,
    username: "admin",
    sharedDir: filesDir,
    allowFullFilesystem: true,
    passwordHash: bcrypt.hashSync(TEST_PASSWORD, 4),
    salt: "bcrypt",
    tokenSecret: "a".repeat(64),
  };
  if (totpSecret) config.totpSecret = totpSecret;
  if (access) config.access = { teamDomain: TEST_TEAM, aud: TEST_AUD, allowedEmails: [TEST_EMAIL] };
  const configPath = path.join(dataDir, "config.json");
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));

  process.env.FILESHARE_CONFIG_PATH = configPath;
  process.env.SHARED_DIR = filesDir;
  delete process.env.PORT;
  delete process.env.PASSWORD;
  delete process.env.ALLOW_FULL_FILESYSTEM;

  return { root, dataDir, filesDir, configPath, cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}

module.exports = { makeSandbox, TEST_PASSWORD, TEST_AUD, TEST_TEAM, TEST_EMAIL };
