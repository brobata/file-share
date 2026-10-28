/**
 * @file totp.test.js
 * @description RFC 6238 SHA1 vectors, the ±1 step window and replay refusal
 *   for lib/totp.js.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const { base32Encode, base32Decode, totp, verifyTotp, generateSecret, otpauthUri, hotp } = require("../lib/totp");

// RFC 6238 Appendix B, SHA1, key = ASCII "12345678901234567890"
const RFC_KEY = Buffer.from("12345678901234567890", "ascii");
const RFC_VECTORS = [
  [59, "94287082"],
  [1111111109, "07081804"],
  [1111111111, "14050471"],
  [1234567890, "89005924"],
  [2000000000, "69279037"],
  [20000000000, "65353130"],
];

test("RFC 6238 SHA1 test vectors (8 digits)", () => {
  for (const [t, expected] of RFC_VECTORS) {
    assert.equal(totp(RFC_KEY, { nowMs: t * 1000, digits: 8 }), expected, `T=${t}`);
  }
});

test("6-digit codes are the low 6 digits of the same value", () => {
  for (const [t, expected] of RFC_VECTORS) {
    assert.equal(totp(RFC_KEY, { nowMs: t * 1000 }), expected.slice(-6), `T=${t}`);
  }
});

test("RFC 4226 HOTP vectors", () => {
  const expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
  expected.forEach((code, counter) => assert.equal(hotp(RFC_KEY, counter), code));
});

test("base32 round-trips and matches RFC 4648", () => {
  assert.equal(base32Encode(Buffer.from("foobar")), "MZXW6YTBOI");
  assert.deepEqual(base32Decode("mzxw 6ytb oi=="), Buffer.from("foobar"));
  const secret = base32Encode(RFC_KEY);
  assert.deepEqual(base32Decode(secret), RFC_KEY);
  // A base32 string key gives the same codes as the raw key
  assert.equal(totp(secret, { nowMs: 59000, digits: 8 }), "94287082");
});

test("generateSecret is 20 random bytes in base32", () => {
  const a = generateSecret();
  assert.match(a, /^[A-Z2-7]{32}$/);
  assert.equal(base32Decode(a).length, 20);
  assert.notEqual(a, generateSecret());
});

test("verifyTotp accepts the current step and ±1, nothing further", () => {
  const secret = base32Encode(RFC_KEY);
  const now = 1111111111 * 1000;
  const step = Math.floor(now / 30000);
  const codeAt = (s) => totp(secret, { nowMs: s * 30000 });
  assert.equal(verifyTotp(secret, codeAt(step), { nowMs: now }), step);
  assert.equal(verifyTotp(secret, codeAt(step - 1), { nowMs: now }), step - 1);
  assert.equal(verifyTotp(secret, codeAt(step + 1), { nowMs: now }), step + 1);
  assert.equal(verifyTotp(secret, codeAt(step - 2), { nowMs: now }), null);
  assert.equal(verifyTotp(secret, codeAt(step + 2), { nowMs: now }), null);
});

test("verifyTotp refuses replays of an accepted step (and older steps)", () => {
  const secret = base32Encode(RFC_KEY);
  const now = 1234567890 * 1000;
  const step = Math.floor(now / 30000);
  const code = totp(secret, { nowMs: now });
  const accepted = verifyTotp(secret, code, { nowMs: now });
  assert.equal(accepted, step);
  assert.equal(verifyTotp(secret, code, { nowMs: now, lastStep: accepted }), null, "same code again");
  // A previous-step code still inside the window is also refused once a later step was used
  const prev = totp(secret, { nowMs: now - 30000 });
  assert.equal(verifyTotp(secret, prev, { nowMs: now, lastStep: accepted }), null);
  // The next step's code is still fine
  const next = totp(secret, { nowMs: now + 30000 });
  assert.equal(verifyTotp(secret, next, { nowMs: now + 30000, lastStep: accepted }), step + 1);
});

test("verifyTotp rejects malformed input", () => {
  const secret = base32Encode(RFC_KEY);
  for (const bad of [undefined, null, 123456, "", "12345", "1234567", "12a456", " 123456"]) {
    assert.equal(verifyTotp(secret, bad), null, String(bad));
  }
  assert.equal(verifyTotp("not base32!", "123456"), null);
  assert.equal(verifyTotp("", "123456"), null);
});

test("otpauth URI has the expected shape", () => {
  assert.equal(
    otpauthUri("JBSWY3DPEHPK3PXP", { issuer: "SpokeRemote", account: "Files" }),
    "otpauth://totp/SpokeRemote:Files?secret=JBSWY3DPEHPK3PXP&issuer=SpokeRemote&digits=6&period=30"
  );
});
