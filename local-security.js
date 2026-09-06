/* FIDUNIO local security helpers.
 * This module deliberately does NOT own an app lock state or render an overlay.
 * app.js state.unlocked remains the single authoritative LOCKED/UNLOCKED state.
 */
const DB_NAME="fidunio-local";
const DB_VERSION=2;
const CONFIG_KEY="local-security-v1";
const LEGACY_CONFIG_KEY="fidunio-local-security-v1";
const AUTH_BYPASS_KEY="fidunio-auth-bypass-once";
const DEFAULT_TIMEOUT_MS=5*60*1000;
const PBKDF2_ITERATIONS=210000;

export const LOCK_TIMEOUTS=Object.freeze([
  {value:0,label:"Immediately"},{value:60*1000,label:"1 min"},{value:5*60*1000,label:"5 min"},
  {value:15*60*1000,label:"15 min"},{value:30*60*1000,label:"30 min"},{value:60*60*1000,label:"1 hr"},{value:-1,label:"Never"}
]);
function idbRequest(req){return new Promise((resolve,reject)=>{req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error);});}
function txDone(tx){return new Promise((resolve,reject)=>{tx.oncomplete=()=>resolve();tx.onerror=()=>reject(tx.error||new Error("IndexedDB transaction failed"));tx.onabort=()=>reject(tx.error||new Error("IndexedDB transaction aborted"));});}
function openDb(){return new Promise((resolve,reject)=>{const req=indexedDB.open(DB_NAME,DB_VERSION);req.onupgradeneeded=()=>{const db=req.result;if(!db.objectStoreNames.contains("meta"))db.createObjectStore("meta");if(!db.objectStoreNames.contains("outbox"))db.createObjectStore("outbox",{keyPath:"id"});if(!db.objectStoreNames.contains("history"))db.createObjectStore("history");};req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error);});}
function defaultConfig(){return{pin:null,timeoutMs:DEFAULT_TIMEOUT_MS,biometric:null};}
function normalizeConfig(value){const cfg=value&&typeof value==="object"?value:{};return{pin:cfg.pin||null,timeoutMs:Number.isFinite(cfg.timeoutMs)?cfg.timeoutMs:DEFAULT_TIMEOUT_MS,biometric:cfg.biometric||null};}
async function writeStoredConfig(config){const db=await openDb();const tx=db.transaction("meta","readwrite");tx.objectStore("meta").put(normalizeConfig(config),CONFIG_KEY);await txDone(tx);}
async function readStoredConfig(){try{const db=await openDb();const stored=await idbRequest(db.transaction("meta","readonly").objectStore("meta").get(CONFIG_KEY));if(stored)return normalizeConfig(stored);}catch(err){console.warn("FIDUNIO local security config read failed",err);}try{const legacy=JSON.parse(localStorage.getItem(LEGACY_CONFIG_KEY)||"null");if(legacy){const migrated=normalizeConfig(legacy);await writeStoredConfig(migrated);try{localStorage.removeItem(LEGACY_CONFIG_KEY);}catch{}return migrated;}}catch{}return defaultConfig();}
let configCache=await readStoredConfig();
let configWriteQueue=Promise.resolve();
function queueConfigMutation(mutator){const run=async()=>{const next=normalizeConfig(configCache);await mutator(next);await writeStoredConfig(next);const db=await openDb();const verify=await idbRequest(db.transaction("meta","readonly").objectStore("meta").get(CONFIG_KEY));if(!verify)throw new Error("Local security settings could not be saved on this device.");configCache=normalizeConfig(verify);return normalizeConfig(configCache);};const result=configWriteQueue.then(run,run);configWriteQueue=result.catch(()=>{});return result;}
function loadConfig(){return normalizeConfig(configCache);}
function bytesToB64Url(bytes){let raw="";bytes.forEach(b=>raw+=String.fromCharCode(b));return btoa(raw).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");}
function b64UrlToBytes(value){const base=String(value||"").replace(/-/g,"+").replace(/_/g,"/");const raw=atob(base+"=".repeat((4-base.length%4)%4));return Uint8Array.from(raw,c=>c.charCodeAt(0));}
function randomBytes(length=32){return crypto.getRandomValues(new Uint8Array(length));}
export function getLocalSecurityStatus(){const cfg=loadConfig();return{hasPin:!!cfg.pin,hasBiometric:!!cfg.biometric?.credentialId,timeoutMs:cfg.timeoutMs};}
export function getLockTimeoutMs(){return loadConfig().timeoutMs;}
export async function setLockTimeoutMs(value){const allowed=new Set(LOCK_TIMEOUTS.map(x=>x.value)),timeoutMs=Number(value);if(!allowed.has(timeoutMs))throw new Error("Unsupported inactivity timeout.");await queueConfigMutation(cfg=>{cfg.timeoutMs=timeoutMs;});activityAt=Date.now();scheduleIdleCheck();}
async function derivePin(pin,salt,iterations=PBKDF2_ITERATIONS){if(!globalThis.crypto?.subtle)throw new Error("Secure PIN storage is not available in this browser.");const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(pin),{name:"PBKDF2"},false,["deriveBits"]);return new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt,iterations},key,256));}
function validPin(pin){return /^\d{4,12}$/.test(String(pin||""));}
function equalBytes(a,b){if(a.length!==b.length)return false;let diff=0;for(let i=0;i<a.length;i++)diff|=a[i]^b[i];return diff===0;}
export async function setLocalPin(pin){pin=String(pin||"");if(!validPin(pin))throw new Error("PIN must contain 4 to 12 digits.");const salt=randomBytes(16),hash=await derivePin(pin,salt);await queueConfigMutation(cfg=>{cfg.pin={salt:bytesToB64Url(salt),hash:bytesToB64Url(hash),iterations:PBKDF2_ITERATIONS};});if(!getLocalSecurityStatus().hasPin)throw new Error("PIN was not saved. Please try again.");}
export async function verifyLocalPin(pin){await configWriteQueue;const cfg=loadConfig();if(!cfg.pin||!validPin(pin))return false;try{return equalBytes(await derivePin(String(pin),b64UrlToBytes(cfg.pin.salt),Number(cfg.pin.iterations)||PBKDF2_ITERATIONS),b64UrlToBytes(cfg.pin.hash));}catch{return false;}}
export async function changeLocalPin(currentPin,newPin){if(!await verifyLocalPin(currentPin))throw new Error("Current PIN is incorrect.");newPin=String(newPin||"");if(!validPin(newPin))throw new Error("PIN must contain 4 to 12 digits.");const salt=randomBytes(16),hash=await derivePin(newPin,salt);await queueConfigMutation(cfg=>{cfg.pin={salt:bytesToB64Url(salt),hash:bytesToB64Url(hash),iterations:PBKDF2_ITERATIONS};});}
export async function removeLocalPin(currentPin){if(!await verifyLocalPin(currentPin))throw new Error("Current PIN is incorrect.");await queueConfigMutation(cfg=>{cfg.pin=null;cfg.biometric=null;});}
export async function platformAuthenticatorAvailable(){try{return!!(window.isSecureContext&&window.PublicKeyCredential&&navigator.credentials&&await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable());}catch{return false;}}
export async function enrollBiometric(){await configWriteQueue;const cfg=loadConfig();if(!cfg.pin)throw new Error("Set a local PIN before enabling device unlock.");if(!await platformAuthenticatorAvailable())throw new Error("Device biometric/passkey unlock is not available in this browser.");const userId=cfg.biometric?.userId?b64UrlToBytes(cfg.biometric.userId):randomBytes(32);const credential=await navigator.credentials.create({publicKey:{challenge:randomBytes(32),rp:{name:"FIDUNIO"},user:{id:userId,name:"fidunio-local",displayName:"FIDUNIO local unlock"},pubKeyCredParams:[{type:"public-key",alg:-7},{type:"public-key",alg:-257}],authenticatorSelection:{authenticatorAttachment:"platform",residentKey:"preferred",userVerification:"required"},timeout:60000,attestation:"none"}});if(!credential?.rawId)throw new Error("Device unlock enrollment was not completed.");await queueConfigMutation(next=>{next.biometric={credentialId:bytesToB64Url(new Uint8Array(credential.rawId)),userId:bytesToB64Url(userId)};});}
export async function verifyBiometric(){await configWriteQueue;const cfg=loadConfig();if(!cfg.biometric?.credentialId||!await platformAuthenticatorAvailable())return false;try{return!!await navigator.credentials.get({publicKey:{challenge:randomBytes(32),allowCredentials:[{type:"public-key",id:b64UrlToBytes(cfg.biometric.credentialId),transports:["internal"]}],userVerification:"required",timeout:60000}});}catch{return false;}}
export async function disableBiometric(){await queueConfigMutation(cfg=>{cfg.biometric=null;});}
export function markSuccessfulAuthBypass(){try{sessionStorage.setItem(AUTH_BYPASS_KEY,"1");}catch{}}
export function consumeSuccessfulAuthBypass(){try{const yes=sessionStorage.getItem(AUTH_BYPASS_KEY)==="1";sessionStorage.removeItem(AUTH_BYPASS_KEY);return yes;}catch{return false;}}
let monitor=null,activityAt=Date.now(),hiddenAt=null,idleTimer=null;
function scheduleIdleCheck(){clearTimeout(idleTimer);if(!monitor||!monitor.isUnlocked())return;const timeout=getLockTimeoutMs();if(timeout<0||timeout===0)return;const remaining=Math.max(0,timeout-(Date.now()-activityAt));idleTimer=setTimeout(()=>{if(!monitor||!monitor.isUnlocked())return;if(Date.now()-activityAt>=getLockTimeoutMs())monitor.onLock("inactivity");else scheduleIdleCheck();},Math.min(remaining+25,2147483000));}
function noteActivity(){if(!monitor?.isUnlocked())return;activityAt=Date.now();scheduleIdleCheck();}
export function noteLocalUnlock(){activityAt=Date.now();hiddenAt=null;scheduleIdleCheck();}
export function installInactivityMonitor({isUnlocked,onLock}){if(monitor)return;monitor={isUnlocked,onLock};["pointerdown","keydown","touchstart"].forEach(name=>window.addEventListener(name,noteActivity,{passive:true}));document.addEventListener("visibilitychange",()=>{if(document.visibilityState==="hidden"){hiddenAt=Date.now();if(isUnlocked()&&getLockTimeoutMs()===0)onLock("background");return;}if(!isUnlocked())return;const timeout=getLockTimeoutMs();if(timeout>=0&&hiddenAt!=null&&Date.now()-hiddenAt>=timeout){onLock("background");return;}activityAt=Date.now();hiddenAt=null;scheduleIdleCheck();});window.addEventListener("pageshow",()=>{if(!isUnlocked())return;const timeout=getLockTimeoutMs();if(timeout>=0&&hiddenAt!=null&&Date.now()-hiddenAt>=timeout){onLock("background");return;}scheduleIdleCheck();});scheduleIdleCheck();}
