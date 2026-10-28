#!/usr/bin/env node
/**
 * @file set-totp.js
 * @description Enroll (or re-enroll) the Google Authenticator code that
 *   internet logins through files.brobata.com require. Generates a fresh
 *   20-byte secret, saves it to data/config.json (old copy kept as .bak, both
 *   0600), shows a QR code + setup key, then asks for a code from the app to
 *   confirm it works. Re-running replaces the secret (the old app entry stops
 *   working). Restart afterwards: `pm2 restart file-share`.
 */
const fs = require("fs");
const path = require("path");
const readline = require("readline");
const QRCode = require("qrcode");
const { generateSecret, verifyTotp, otpauthUri } = require("../lib/totp");

// Same override the server honours, so this can be tried on a scratch config
const CONFIG_PATH = process.env.FILESHARE_CONFIG_PATH
  ? path.resolve(process.env.FILESHARE_CONFIG_PATH)
  : path.join(__dirname, "..", "data", "config.json");

// The secret is shown on screen: refuse to run where it would land in a log or pipe
if (!process.stdin.isTTY || !process.stdout.isTTY) {
  console.error("Run this in an interactive terminal (it shows a secret QR code and reads a code).");
  process.exit(1);
}

function ask(prompt) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl.question(prompt, (answer) => { rl.close(); resolve(answer); });
  });
}

(async () => {
  let config;
  try {
    config = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  } catch (err) {
    console.error(`Cannot read ${CONFIG_PATH}: ${err.message}. Finish first-run setup first.`);
    process.exit(1);
  }

  const secret = generateSecret();
  config.totpSecret = secret;

  // Holds the password hash, cookie secret and now the TOTP secret: owner-only.
  fs.copyFileSync(CONFIG_PATH, CONFIG_PATH + ".bak");
  fs.chmodSync(CONFIG_PATH + ".bak", 0o600);
  const tmp = CONFIG_PATH + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(config, null, 2), { mode: 0o600 });
  fs.chmodSync(tmp, 0o600);
  fs.renameSync(tmp, CONFIG_PATH);

  const uri = otpauthUri(secret, { issuer: "SpokeRemote", account: "Files" });
  // "small" packs two rows per line with half blocks: ~45 columns, fits 80
  const qr = await QRCode.toString(uri, { type: "terminal", small: true, errorCorrectionLevel: "L" });

  console.log("\nNew two-factor secret saved. Scan this with Google Authenticator:\n");
  console.log(qr);
  console.log("Or add it by hand (\"Enter a setup key\", time based):");
  console.log(`  Account: SpokeRemote:Files`);
  console.log(`  Key:     ${secret.match(/.{1,4}/g).join(" ")}`);
  console.log(`\nURI: ${uri}\n`);

  const code = (await ask("Type the 6-digit code the app shows now: ")).replace(/\s+/g, "");
  const ok = verifyTotp(secret, code) !== null;
  if (ok) {
    console.log("\nCode verified. Two-factor is set up.");
  } else {
    console.log("\nThat code did not match. The new secret IS saved, so any older app entry no longer works.");
    console.log("Check the phone's clock is set automatically, or re-run this script for a new QR code.");
  }
  console.log("Now run:  pm2 restart file-share   (the server only reads the secret at start)");
  process.exit(ok ? 0 : 1);
})();
