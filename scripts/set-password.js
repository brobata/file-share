#!/usr/bin/env node
/**
 * @file set-password.js
 * @description Reset the File-Share password from a terminal on the server.
 *   Prompts twice without echo, bcrypt-hashes it (same rounds as the app) and
 *   writes data/config.json (old copy kept as .bak). The token secret is left
 *   alone, so browsers that are already signed in stay signed in.
 *   `--tunnel` sets a separate username + password for files.brobata.com only
 *   (safe to let a work browser save: it never unlocks the LAN, and the
 *   authenticator code is still required); `--tunnel --remove` goes back to
 *   the main login there. `--tunnel --code-only` drops the username/password
 *   there entirely (Access email code + authenticator code are the login).
 *   `--code-only` does the same for the home network (`--code-only --off`
 *   undoes it).
 *   Restart afterwards: `pm2 restart file-share`.
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const readline = require("readline");
const bcrypt = require("bcryptjs");

const CONFIG_PATH = path.join(__dirname, "..", "data", "config.json");
const BCRYPT_ROUNDS = 12;
const MIN_PASSWORD_LENGTH = 8;

if (!process.stdin.isTTY) {
  console.error("Run this in an interactive terminal (it reads the password without echo).");
  process.exit(1);
}

function askVisible(prompt) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(prompt, (answer) => { rl.close(); resolve(answer.trim()); });
  });
}

function ask(prompt) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => { if (s.startsWith(prompt)) rl.output.write(prompt); };
    rl.question(prompt, (answer) => { rl.close(); process.stdout.write("\n"); resolve(answer); });
  });
}

// Same check as the server: bcrypt, or the legacy salted SHA-256
function matchesMain(config, password) {
  if (!config.passwordHash) return false;
  if (config.passwordHash.startsWith("$2")) return bcrypt.compareSync(password, config.passwordHash);
  const hash = crypto.createHash("sha256").update(password + config.salt).digest("hex");
  return hash === config.passwordHash;
}

function save(config) {
  // Holds the hash and the cookie-signing secret: owner-only.
  fs.copyFileSync(CONFIG_PATH, CONFIG_PATH + ".bak");
  fs.chmodSync(CONFIG_PATH + ".bak", 0o600);
  const tmp = CONFIG_PATH + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(config, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, CONFIG_PATH);
}

(async () => {
  const config = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  const tunnel = process.argv.includes("--tunnel");
  if (process.argv.includes("--remove") && !tunnel) {
    console.error("--remove only works with --tunnel. Nothing changed.");
    process.exit(1);
  }

  if (!tunnel && process.argv.includes("--code-only")) {
    if (process.argv.includes("--off")) {
      delete config.lanCodeOnly;
      save(config);
      console.log("At home File-Share asks for the username and password again. Now run:  pm2 restart file-share");
      return;
    }
    if (!config.totpSecret) {
      console.error("Set up the authenticator first (scripts/set-totp.js), or there is no way in. Nothing changed.");
      process.exit(1);
    }
    config.lanCodeOnly = true;
    save(config);
    console.log("At home File-Share now asks only for the authenticator code (\"remember me\" lasts 90 days). Now run:  pm2 restart file-share");
    return;
  }
  if (tunnel && process.argv.includes("--code-only")) {
    if (!config.totpSecret) {
      console.error("Set up the authenticator first (scripts/set-totp.js), or there is no way in. Nothing changed.");
      process.exit(1);
    }
    delete config.tunnelLogin;
    config.tunnelCodeOnly = true;
    save(config);
    console.log("files.brobata.com now asks only for the authenticator code. Now run:  pm2 restart file-share");
    return;
  }
  if (tunnel && process.argv.includes("--remove")) {
    delete config.tunnelLogin;
    delete config.tunnelCodeOnly;
    save(config);
    console.log("files.brobata.com uses the main login again. Now run:  pm2 restart file-share");
    return;
  }
  let tunnelUser = null;
  if (tunnel) {
    tunnelUser = (await askVisible("Username for files.brobata.com (e.g. your work email): ")).toLowerCase();
    if (!tunnelUser) { console.error("A username is required. Nothing changed."); process.exit(1); }
  } else {
    console.log(`File-Share username: ${config.username || "admin"}`);
  }

  const first = await ask(tunnel ? "New files.brobata.com password: " : "New File-Share password: ");
  if (first.length < MIN_PASSWORD_LENGTH) {
    console.error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters. Nothing changed.`);
    process.exit(1);
  }
  if ((await ask("Type it again: ")) !== first) {
    console.error("Passwords did not match. Nothing changed.");
    process.exit(1);
  }

  if (tunnel) {
    if (matchesMain(config, first)) {
      console.error("That is your main File-Share password. Pick a different one. Nothing changed.");
      process.exit(1);
    }
    config.tunnelLogin = { username: tunnelUser, passwordHash: bcrypt.hashSync(first, BCRYPT_ROUNDS) };
    delete config.tunnelCodeOnly; // a password again
    // Cookies are stateless: a new secret is the only way to end a session
    // still open on a lost laptop. (Signs out LAN browsers too.)
    config.tokenSecret = crypto.randomBytes(32).toString("hex");
  } else {
    if (config.tunnelLogin && bcrypt.compareSync(first, config.tunnelLogin.passwordHash)) {
      console.error("That is your files.brobata.com password. Pick a different one. Nothing changed.");
      process.exit(1);
    }
    config.passwordHash = bcrypt.hashSync(first, BCRYPT_ROUNDS);
    config.salt = "bcrypt";
  }
  save(config);

  console.log("Password saved. Now run:  pm2 restart file-share");
  console.log(tunnel
    ? "(Only files.brobata.com uses it; the main login stops working there. Every browser is signed out, home ones too.)"
    : "(Browsers already signed in stay signed in.)");
})();
