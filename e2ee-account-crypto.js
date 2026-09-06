// FIDUNIO account E2EE v1 cryptographic primitives.
// Pure Web Crypto module: NO Firebase, Firestore, DOM, storage, or lifecycle ownership.

const te = new TextEncoder();
const SCHEMA_VERSION = 1;
const IDENTITY_VERSION = 1;
const WRAPPER_VERSION = 1;
const PBKDF2_ITERATIONS = 600000;

function fail(code, message, cause) {
  const err = new Error(message);
  err.code = code;
  if (cause) err.cause = cause;
  return err;
}

function requireCrypto() {
  if (!globalThis.crypto?.subtle || !globalThis.crypto?.getRandomValues) {
    throw fail("UNSUPPORTED_CRYPTO", "Web Crypto is not available.");
  }
  return globalThis.crypto;
}

function requireText(value, name) {
  if (typeof value !== "string" || !value.length) throw fail("INVALID_INPUT", `${name} is required.`);
  return value;
}

export function validateSixDigitPin(pin) {
  const value = String(pin ?? "");
  if (!/^\d{6}$/.test(value)) throw fail("INVALID_INPUT", "PIN must be exactly six digits.");
  return value;
}

function bytesToBase64Url(bytes) {
  let raw = "";
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < u8.length; i += 0x8000) raw += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  if (typeof value !== "string" || !value.length || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw fail("FORMAT_ERROR", "Invalid base64url value.");
  }
  const pad = (4 - (value.length % 4)) % 4;
  let raw;
  try { raw = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad)); }
  catch (cause) { throw fail("FORMAT_ERROR", "Invalid base64url value.", cause); }
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function aadBytes(purpose, { uid, keyId, schemaVersion = SCHEMA_VERSION, identityVersion = IDENTITY_VERSION, wrapperVersion = WRAPPER_VERSION }) {
  requireText(uid, "uid");
  requireText(keyId, "keyId");
  if (!["normal", "recovery"].includes(purpose)) throw fail("INVALID_INPUT", "Unknown wrapper purpose.");
  return te.encode(JSON.stringify(["FIDUNIO-E2EE-WRAP", 1, purpose, uid, keyId, schemaVersion, identityVersion, wrapperVersion]));
}

function kdfInputBytes(password, pin) {
  requireText(password, "password");
  const six = validateSixDigitPin(pin);
  return te.encode(JSON.stringify(["FIDUNIO-E2EE-KDF", 1, password, six]));
}

async function deriveNormalKey(password, pin, salt) {
  const c = requireCrypto();
  const material = await c.subtle.importKey("raw", kdfInputBytes(password, pin), { name: "PBKDF2" }, false, ["deriveKey"]);
  return c.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function importRuntimePrivateKey(pkcs8Bytes, extractable = false) {
  try {
    return await requireCrypto().subtle.importKey(
      "pkcs8",
      pkcs8Bytes,
      { name: "ECDH", namedCurve: "P-256" },
      extractable,
      ["deriveKey", "deriveBits"]
    );
  } catch (cause) {
    throw fail("FORMAT_ERROR", "Private E2EE key format is invalid.", cause);
  }
}

export async function generateAccountIdentity() {
  const c = requireCrypto();
  const pair = await c.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
  const publicJwk = await c.subtle.exportKey("jwk", pair.publicKey);
  const privatePkcs8 = new Uint8Array(await c.subtle.exportKey("pkcs8", pair.privateKey));
  return { pair, publicJwk, privatePkcs8 };
}

export async function exportPrivatePkcs8(privateKey) {
  try { return new Uint8Array(await requireCrypto().subtle.exportKey("pkcs8", privateKey)); }
  catch (cause) { throw fail("FORMAT_ERROR", "Private key is not exportable for re-wrap.", cause); }
}

export async function wrapPrivateKeyNormal({ privatePkcs8, password, pin, uid, keyId }) {
  const c = requireCrypto();
  const plain = privatePkcs8 instanceof Uint8Array ? privatePkcs8 : new Uint8Array(privatePkcs8);
  if (!plain.length) throw fail("INVALID_INPUT", "Private key bytes are required.");
  const salt = c.getRandomValues(new Uint8Array(16));
  const iv = c.getRandomValues(new Uint8Array(12));
  const key = await deriveNormalKey(password, pin, salt);
  const aad = aadBytes("normal", { uid, keyId });
  const ciphertext = await c.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, key, plain);
  return {
    version: WRAPPER_VERSION,
    ciphertext: bytesToBase64Url(ciphertext),
    salt: bytesToBase64Url(salt),
    iv: bytesToBase64Url(iv),
    kdf: "PBKDF2-HMAC-SHA256",
    iterations: PBKDF2_ITERATIONS,
    wrappingAlgorithm: "AES-256-GCM"
  };
}

function validateNormalWrapper(wrapper) {
  if (!wrapper || wrapper.version !== 1 || wrapper.kdf !== "PBKDF2-HMAC-SHA256" || wrapper.iterations !== PBKDF2_ITERATIONS || wrapper.wrappingAlgorithm !== "AES-256-GCM") {
    throw fail("FORMAT_ERROR", "Unsupported normal wrapper format.");
  }
}

export async function unwrapPrivateKeyNormal({ wrapper, password, pin, uid, keyId, extractable = false }) {
  validateNormalWrapper(wrapper);
  try {
    const c = requireCrypto();
    const salt = base64UrlToBytes(wrapper.salt);
    const iv = base64UrlToBytes(wrapper.iv);
    if (salt.length !== 16 || iv.length !== 12) throw fail("FORMAT_ERROR", "Wrapper salt or IV length is invalid.");
    const ciphertext = base64UrlToBytes(wrapper.ciphertext);
    const key = await deriveNormalKey(password, pin, salt);
    const plain = await c.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aadBytes("normal", { uid, keyId }), tagLength: 128 }, key, ciphertext);
    return await importRuntimePrivateKey(plain, extractable);
  } catch (cause) {
    if (cause?.code === "INVALID_INPUT" || cause?.code === "UNSUPPORTED_CRYPTO") throw cause;
    throw fail("UNLOCK_FAILED", "Unable to unlock the E2EE identity.", cause);
  }
}

export function generateRecoveryUnlockKey() {
  return requireCrypto().getRandomValues(new Uint8Array(32));
}

export async function wrapPrivateKeyRecovery({ privatePkcs8, recoveryUnlockKey, uid, keyId }) {
  const c = requireCrypto();
  const plain = privatePkcs8 instanceof Uint8Array ? privatePkcs8 : new Uint8Array(privatePkcs8);
  const ruk = recoveryUnlockKey instanceof Uint8Array ? recoveryUnlockKey : new Uint8Array(recoveryUnlockKey);
  if (!plain.length || ruk.length !== 32) throw fail("INVALID_INPUT", "Recovery inputs are invalid.");
  const key = await c.subtle.importKey("raw", ruk, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = c.getRandomValues(new Uint8Array(12));
  const ciphertext = await c.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aadBytes("recovery", { uid, keyId }), tagLength: 128 }, key, plain);
  return { version: WRAPPER_VERSION, ciphertext: bytesToBase64Url(ciphertext), iv: bytesToBase64Url(iv), wrappingAlgorithm: "AES-256-GCM", recoveryAuthorityVersion: 1 };
}

export async function unwrapPrivateKeyRecovery({ wrapper, recoveryUnlockKey, uid, keyId, extractable = false }) {
  if (!wrapper || wrapper.version !== 1 || wrapper.wrappingAlgorithm !== "AES-256-GCM") throw fail("FORMAT_ERROR", "Unsupported recovery wrapper format.");
  try {
    const c = requireCrypto();
    const ruk = recoveryUnlockKey instanceof Uint8Array ? recoveryUnlockKey : new Uint8Array(recoveryUnlockKey);
    if (ruk.length !== 32) throw fail("FORMAT_ERROR", "Recovery key length is invalid.");
    const iv = base64UrlToBytes(wrapper.iv);
    if (iv.length !== 12) throw fail("FORMAT_ERROR", "Recovery IV length is invalid.");
    const key = await c.subtle.importKey("raw", ruk, { name: "AES-GCM" }, false, ["decrypt"]);
    const plain = await c.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aadBytes("recovery", { uid, keyId }), tagLength: 128 }, key, base64UrlToBytes(wrapper.ciphertext));
    return await importRuntimePrivateKey(plain, extractable);
  } catch (cause) {
    if (cause?.code === "UNSUPPORTED_CRYPTO") throw cause;
    throw fail("UNLOCK_FAILED", "Unable to recover the E2EE identity.", cause);
  }
}

export async function exportPublicJwk(publicKey) {
  return requireCrypto().subtle.exportKey("jwk", publicKey);
}

export function validatePublicJwk(jwk) {
  if (!jwk || jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || !jwk.x || typeof jwk.y !== "string" || !jwk.y || "d" in jwk) {
    throw fail("FORMAT_ERROR", "Public E2EE key is invalid.");
  }
  return jwk;
}

export async function importPublicJwk(jwk) {
  validatePublicJwk(jwk);
  try { return await requireCrypto().subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, []); }
  catch (cause) { throw fail("FORMAT_ERROR", "Public E2EE key cannot be imported.", cause); }
}

export function randomKeyId() {
  const bytes = requireCrypto().getRandomValues(new Uint8Array(16));
  return bytesToBase64Url(bytes);
}

export const E2EE_V1 = Object.freeze({
  schemaVersion: SCHEMA_VERSION,
  identityVersion: IDENTITY_VERSION,
  wrapperVersion: WRAPPER_VERSION,
  keyAlgorithm: "ECDH-P256",
  kdf: "PBKDF2-HMAC-SHA256",
  iterations: PBKDF2_ITERATIONS,
  wrappingAlgorithm: "AES-256-GCM"
});
