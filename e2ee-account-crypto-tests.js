import {
  generateAccountIdentity,
  wrapPrivateKeyNormal,
  unwrapPrivateKeyNormal,
  generateRecoveryUnlockKey,
  wrapPrivateKeyRecovery,
  unwrapPrivateKeyRecovery,
  randomKeyId,
  validateSixDigitPin
} from "./e2ee-account-crypto.js";

const out = document.getElementById("results");
const rows = [];
function row(name, ok, detail = "") { rows.push({ name, ok, detail }); render(); }
function render() {
  out.innerHTML = rows.map(r => `<div class="test ${r.ok ? "pass" : "fail"}"><strong>${r.ok ? "PASS" : "FAIL"}</strong> — ${escapeHtml(r.name)}${r.detail ? `<div>${escapeHtml(r.detail)}</div>` : ""}</div>`).join("");
}
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c])); }
async function expectFail(name, fn) {
  try { await fn(); row(name, false, "unexpected success"); }
  catch { row(name, true); }
}
async function sharedSecret(privateKey, publicKey) {
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256));
}
function same(a, b) { return a.length === b.length && a.every((v, i) => v === b[i]); }
function tamper(s) {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const raw = atob(padded);
  const bytes = Uint8Array.from(raw, c => c.charCodeAt(0));
  if (!bytes.length) throw new Error("Cannot tamper empty value.");
  bytes[bytes.length - 1] ^= 0x01;
  let changed = "";
  bytes.forEach(b => changed += String.fromCharCode(b));
  return btoa(changed).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function run() {
  rows.length = 0; render();
  const uid = "crypto-test-user";
  const keyId = randomKeyId();
  const password = "Test password 123!";
  const pin = "012345";
  const identity = await generateAccountIdentity();
  const peer = await generateAccountIdentity();
  const baseline = await sharedSecret(identity.pair.privateKey, peer.pair.publicKey);

  try { validateSixDigitPin(pin); row("six-digit PIN preserves leading zero", true); } catch (e) { row("six-digit PIN preserves leading zero", false, e.message); }
  await expectFail("reject non-six-digit PIN", () => Promise.resolve(validateSixDigitPin("12345")));

  const normal = await wrapPrivateKeyNormal({ privatePkcs8: identity.privatePkcs8, password, pin, uid, keyId });
  try {
    const recovered = await unwrapPrivateKeyNormal({ wrapper: normal, password, pin, uid, keyId });
    const secret = await sharedSecret(recovered, peer.pair.publicKey);
    row("normal wrap/unwrap returns same private identity", same(baseline, secret));
  } catch (e) { row("normal wrap/unwrap returns same private identity", false, e.message); }

  await expectFail("wrong password fails", () => unwrapPrivateKeyNormal({ wrapper: normal, password: "wrong", pin, uid, keyId }));
  await expectFail("wrong PIN fails", () => unwrapPrivateKeyNormal({ wrapper: normal, password, pin: "999999", uid, keyId }));
  await expectFail("changed UID/AAD fails", () => unwrapPrivateKeyNormal({ wrapper: normal, password, pin, uid: "other-user", keyId }));
  await expectFail("changed keyId/AAD fails", () => unwrapPrivateKeyNormal({ wrapper: normal, password, pin, uid, keyId: randomKeyId() }));
  await expectFail("tampered ciphertext fails", () => unwrapPrivateKeyNormal({ wrapper: { ...normal, ciphertext: tamper(normal.ciphertext) }, password, pin, uid, keyId }));
  await expectFail("tampered IV fails", () => unwrapPrivateKeyNormal({ wrapper: { ...normal, iv: tamper(normal.iv) }, password, pin, uid, keyId }));
  await expectFail("tampered salt fails", () => unwrapPrivateKeyNormal({ wrapper: { ...normal, salt: tamper(normal.salt) }, password, pin, uid, keyId }));
  await expectFail("malformed base64url rejected", () => unwrapPrivateKeyNormal({ wrapper: { ...normal, ciphertext: "%%%" }, password, pin, uid, keyId }));

  const ruk = generateRecoveryUnlockKey();
  const recovery = await wrapPrivateKeyRecovery({ privatePkcs8: identity.privatePkcs8, recoveryUnlockKey: ruk, uid, keyId });
  try {
    const recovered = await unwrapPrivateKeyRecovery({ wrapper: recovery, recoveryUnlockKey: ruk, uid, keyId });
    const secret = await sharedSecret(recovered, peer.pair.publicKey);
    row("recovery wrapper returns same private identity", same(baseline, secret));
  } catch (e) { row("recovery wrapper returns same private identity", false, e.message); }
  await expectFail("recovery wrapper cannot be transplanted to another UID", () => unwrapPrivateKeyRecovery({ wrapper: recovery, recoveryUnlockKey: ruk, uid: "other-user", keyId }));
  await expectFail("wrong recovery key fails", () => unwrapPrivateKeyRecovery({ wrapper: recovery, recoveryUnlockKey: generateRecoveryUnlockKey(), uid, keyId }));

  try {
    const changed = await wrapPrivateKeyNormal({ privatePkcs8: identity.privatePkcs8, password: "New password 456!", pin: "654321", uid, keyId });
    const recovered = await unwrapPrivateKeyNormal({ wrapper: changed, password: "New password 456!", pin: "654321", uid, keyId });
    const secret = await sharedSecret(recovered, peer.pair.publicKey);
    row("password+PIN re-wrap preserves identity", same(baseline, secret));
  } catch (e) { row("password+PIN re-wrap preserves identity", false, e.message); }

  const failed = rows.filter(r => !r.ok).length;
  document.getElementById("summary").textContent = failed ? `${failed} test(s) failed.` : `All ${rows.length} tests passed.`;
}

run().catch(e => { row("test harness", false, e?.stack || e?.message || String(e)); document.getElementById("summary").textContent = "Test harness failed."; });
