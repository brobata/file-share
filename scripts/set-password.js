#!/usr/bin/env node
/**
 * @file set-password.js
 * @description Reset the File-Share password from a terminal on the server.
 *   Prompts twice without echo, bcrypt-hashes it (same rounds as the app) and
 *   writes data/config.json (old copy kept as .bak). The token secret is left
 *   alone, so browsers that are already signed in stay signed in. Restart
 *   afterwards: `pm2 restart file-share`.
 */
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

function ask(prompt) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => { if (s.startsWith(prompt)) rl.output.write(prompt); };
    rl.question(prompt, (answer) => { rl.close(); process.stdout.write("\n"); resolve(answer); });
  });
}

(async () => {
  const config = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  console.log(`File-Share username: ${config.username || "admin"}`);

  const first = await ask("New File-Share password: ");
  if (first.length < MIN_PASSWORD_LENGTH) {
    console.error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters. Nothing changed.`);
    process.exit(1);
  }
  if ((await ask("Type it again: ")) !== first) {
    console.error("Passwords did not match. Nothing changed.");
    process.exit(1);
  }

  config.passwordHash = bcrypt.hashSync(first, BCRYPT_ROUNDS);
  config.salt = "bcrypt";

  // Holds the hash and the cookie-signing secret: owner-only.
  fs.copyFileSync(CONFIG_PATH, CONFIG_PATH + ".bak");
  fs.chmodSync(CONFIG_PATH + ".bak", 0o600);
  const tmp = CONFIG_PATH + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(config, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, CONFIG_PATH);

  console.log("Password saved. Now run:  pm2 restart file-share");
  console.log("(Browsers already signed in stay signed in.)");
})();
