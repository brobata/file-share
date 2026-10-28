/**
 * @file totp.js
 * @description RFC 6238 TOTP (Google Authenticator compatible) on node:crypto,
 *   so the second factor adds no dependency. SHA1, 6 digits, 30s steps by
 *   default. verifyTotp() returns the matched time step so the caller can
 *   refuse a replay of a code that was already accepted.
 */
const crypto = require("crypto");

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// RFC 4648 base32 without padding (what authenticator apps expect)
function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

// Lenient on case, spaces and padding (people paste keys in groups of 4)
function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error("Invalid base32 character");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

// 20 random bytes = the 160-bit key size RFC 4226 recommends for SHA1
function generateSecret() {
  return base32Encode(crypto.randomBytes(20));
}

// RFC 4226 HOTP with dynamic truncation
function hotp(key, counter, digits = 6) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = crypto.createHmac("sha1", key).update(msg).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(bin % 10 ** digits).padStart(digits, "0");
}

function timeStep(nowMs = Date.now(), period = 30) {
  return Math.floor(nowMs / 1000 / period);
}

// `key` is a Buffer (raw) or a base32 string
function totp(key, { nowMs = Date.now(), period = 30, digits = 6 } = {}) {
  const raw = Buffer.isBuffer(key) ? key : base32Decode(key);
  return hotp(raw, timeStep(nowMs, period), digits);
}

/**
 * Check a code against the current step ±window. Returns the matched step
 * number, or null. A step <= lastStep is treated as a replay and rejected.
 */
function verifyTotp(secret, code, { nowMs = Date.now(), period = 30, digits = 6, window = 1, lastStep = -1 } = {}) {
  if (typeof code !== "string" || !new RegExp(`^\\d{${digits}}$`).test(code)) return null;
  let key;
  try {
    key = base32Decode(secret);
  } catch {
    return null;
  }
  if (!key.length) return null;
  const current = timeStep(nowMs, period);
  const given = Buffer.from(code);
  let matched = null;
  // Check every step in the window (no early exit) so timing doesn't reveal which one matched
  for (let step = current - window; step <= current + window; step++) {
    if (step < 0) continue;
    if (crypto.timingSafeEqual(Buffer.from(hotp(key, step, digits)), given) && matched === null) {
      matched = step;
    }
  }
  if (matched === null || matched <= lastStep) return null;
  return matched;
}

function otpauthUri(secret, { issuer = "SpokeRemote", account = "Files", digits = 6, period = 30 } = {}) {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&digits=${digits}&period=${period}`;
}

module.exports = { base32Encode, base32Decode, generateSecret, hotp, totp, timeStep, verifyTotp, otpauthUri };
