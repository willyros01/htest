import {
  isFirebaseConfigured,
  initFirebase,
  createFidunioAccount,
  signInFidunio,
  signOutFidunio,
  getFirebaseUser,
  startDirectConversation,
  subscribeMyConversations,
  subscribeUserDisplayNames,
  subscribeConversationMessages,
  sendCloudMessage,
  updateCloudMessageState,
  getCloudUserProfile,
  getCloudConversation,
  publishCloudE2EEPublicKey,
  publishCloudE2EEDevice,
  getCloudUserDevices,
  listCloudUsers,
  createCloudGroup,
  subscribeMyGroups
} from "./firebase.js";
import {
  LOCK_TIMEOUTS,
  getLocalSecurityStatus,
  setLocalPin, verifyLocalPin, changeLocalPin, removeLocalPin,
  enrollBiometric, verifyBiometric, disableBiometric,
  setLockTimeoutMs, consumeSuccessfulAuthBypass, noteLocalUnlock,
  installInactivityMonitor
} from "./local-security.js";
import { mountNewMessageRecipientPicker } from "./new-message-owner.js";
import { mountSettingsLifecycle } from "./settings-lifecycle.js";
import { bindAuthenticatedAccountE2EE, resetAccountE2EEForSignOut } from "./e2ee-account-runtime.js";
import { prepareAccountDirectMessage,decryptAccountDirectMessage } from "./e2ee-account-message-runtime.js";

/* FIDUNIO single-authority local lock integration */
const app = document.querySelector("#app");
const FIDUNIO_VERSION = globalThis.FIDUNIO_RELEASE?.version || "unknown";

const contacts=[]; // legacy group-info compatibility only; no prototype identities

let state = {
  unlocked:false,
  route:"messages",
  previousRoute:"messages",
  online:navigator.onLine,
  selectedId:null,
  toolsOpen:false,
  newGroupMembers:[],
  newGroupName:"",
  modal:null,
  quickPhrases:["Yes","No","OK","On my way","Running late","Call me"],
  conversations:[],
  messages:{},
  settings:{previews:false,autoLock:true,textSize:"normal",wifiAttachments:true,appearance:"auto"},
  peerTrust:{}
};

const DB_NAME = "fidunio-local";
const DB_VERSION = 2;
const STATE_KEY = "app-state";
let dbPromise = null;
let localKeyPromise = null;
let hydrated = false;
let persistTimer = null;
let firebaseReady = false;
let firebaseError = "";
let firebaseUser = null;
let cloudConversationUnsub = null;
let peerDisplayNameUnsub = ()=>{};
let peerDisplayNameKey = "";
let peerDisplayNames = {};
let cloudGroupUnsub = null;
let groupCandidates = [];
let cloudMessageUnsub = null;
let cloudMessageConversationId = null;
let deviceSecurityInfo = null;
let deviceRegistryStatus = "";
let myRegisteredDevices = [];
let localSecurityMessage = "";
let localSecurityMessageIsError = false;
let unlockError = "";

function setLocalSecurityMessage(message,isError=false){
  localSecurityMessage=String(message||"");
  localSecurityMessageIsError=!!isError;
}
function lockLocalApp(reason="manual"){
  if(!state.unlocked)return;
  state.unlocked=false;
  state.toolsOpen=false;
  state.modal=null;
  unlockError="";
  render();
}
function unlockLocalApp(){
  state.unlocked=true;
  unlockError="";
  noteLocalUnlock();
  render();
}

function openDb(){
  if(dbPromise) return dbPromise;
  dbPromise = new Promise((resolve,reject)=>{
    const req=indexedDB.open(DB_NAME,DB_VERSION);
    req.onupgradeneeded=()=>{
      const db=req.result;
      if(!db.objectStoreNames.contains("meta")) db.createObjectStore("meta");
      if(!db.objectStoreNames.contains("outbox")) db.createObjectStore("outbox",{keyPath:"id"});
      if(!db.objectStoreNames.contains("history")) db.createObjectStore("history");
    };
    req.onsuccess=()=>resolve(req.result);
    req.onerror=()=>reject(req.error);
  });
  return dbPromise;
}
function idbRequest(req){
  return new Promise((resolve,reject)=>{
    req.onsuccess=()=>resolve(req.result);
    req.onerror=()=>reject(req.error);
  });
}
async function getLocalKey(){
  if(localKeyPromise) return localKeyPromise;
  localKeyPromise=(async()=>{
    const db=await openDb();

    // Read in its own transaction. Safari/iOS can auto-close an IndexedDB
    // transaction across an await, so never reuse that transaction after
    // asynchronous key generation.
    let key=await idbRequest(db.transaction("meta","readonly").objectStore("meta").get("local-key"));
    if(key) return key;

    key=await crypto.subtle.generateKey({name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
    const tx=db.transaction("meta","readwrite");
    tx.objectStore("meta").put(key,"local-key");
    await txDone(tx);
    return key;
  })().catch(err=>{
    localKeyPromise=null;
    throw err;
  });
  return localKeyPromise;
}
function bytesToB64(bytes){
  let s=""; bytes.forEach(b=>s+=String.fromCharCode(b)); return btoa(s);
}
function b64ToBytes(s){
  const raw=atob(s); return Uint8Array.from(raw,c=>c.charCodeAt(0));
}
async function encryptLocal(value){
  const key=await getLocalKey();
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const data=new TextEncoder().encode(JSON.stringify(value));
  const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,data);
  return {iv:bytesToB64(iv),ciphertext:bytesToB64(new Uint8Array(cipher))};
}
async function decryptLocal(record){
  const key=await getLocalKey();
  const plain=await crypto.subtle.decrypt(
    {name:"AES-GCM",iv:b64ToBytes(record.iv)},key,b64ToBytes(record.ciphertext)
  );
  return JSON.parse(new TextDecoder().decode(plain));
}
function serializableState(){
  return {
    conversations:state.conversations,
    messages:state.messages,
    settings:state.settings,
    peerTrust:state.peerTrust,
    quickPhrases:state.quickPhrases,
    selectedId:state.selectedId
  };
}
function txDone(tx){
  return new Promise((resolve,reject)=>{
    tx.oncomplete=()=>resolve();
    tx.onerror=()=>reject(tx.error || new Error("IndexedDB transaction failed"));
    tx.onabort=()=>reject(tx.error || new Error("IndexedDB transaction aborted"));
  });
}
async function persistState(){
  if(!hydrated) return;
  try{
    const db=await openDb();
    const encrypted=await encryptLocal(serializableState());
    const tx=db.transaction("meta","readwrite");
    tx.objectStore("meta").put(encrypted,STATE_KEY);
    await txDone(tx);
  }catch(err){ console.warn("Local state persistence failed",err); }
}
function persistSoon(){
  if(!hydrated) return;
  clearTimeout(persistTimer);
  persistTimer=setTimeout(()=>{ persistState(); },80);
}
async function loadPersistedState(){
  try{
    const db=await openDb();
    const encrypted=await idbRequest(db.transaction("meta","readonly").objectStore("meta").get(STATE_KEY));
    if(!encrypted) return;
    const saved=await decryptLocal(encrypted);
    if(saved.conversations) state.conversations=saved.conversations;
    if(saved.messages) state.messages=saved.messages;
    if(saved.settings) state.settings={...state.settings,...saved.settings};
    if(saved.peerTrust && typeof saved.peerTrust==="object") state.peerTrust=saved.peerTrust;
    if(saved.quickPhrases) state.quickPhrases=saved.quickPhrases;
    if(saved.selectedId && state.conversations.some(c=>String(c.id)===String(saved.selectedId))) state.selectedId=saved.selectedId;
  }catch(err){ console.warn("Could not restore local Fidunio state",err); }
}
async function queueOutboxMessage(conversationId,message){
  const db=await openDb();
  const c=state.conversations.find(x=>String(x.id)===String(conversationId));
  const encrypted=await encryptLocal({
    conversationId,
    messageId:message.id,
    text:message.text,
    time:message.time,
    cloud:!!message.cloud,
    conversation:c ? {
      id:c.id,
      name:c.name,
      type:c.type,
      cloud:!!c.cloud,
      peerUid:c.peerUid || c.uid || c.otherUid || null,
      preview:message.text,
      time:message.time,
      unread:0
    } : null
  });
  const tx=db.transaction("outbox","readwrite");
  tx.objectStore("outbox").put({
    id:message.id,
    conversationId,
    createdAt:Date.now(),
    payload:encrypted
  });
  await txDone(tx);
}
async function getOutboxRecords(){
  const db=await openDb();
  return idbRequest(db.transaction("outbox","readonly").objectStore("outbox").getAll());
}
async function removeOutboxMessage(id){
  const db=await openDb();
  const tx=db.transaction("outbox","readwrite");
  tx.objectStore("outbox").delete(id);
  await txDone(tx);
}
async function decryptOutboxRecord(record){
  const payload=await decryptLocal(record.payload);
  return {
    conversationId:payload.conversationId ?? record.conversationId,
    messageId:payload.messageId ?? record.id,
    text:payload.text ?? "",
    time:payload.time ?? "",
    cloud:!!payload.cloud,
    conversation:payload.conversation || null
  };
}
function ensureQueuedMessageFromPayload(payload){
  const conversationId=payload.conversationId;
  let c=state.conversations.find(x=>String(x.id)===String(conversationId));
  if(!c && payload.conversation){
    c={...payload.conversation,id:conversationId};
    state.conversations.unshift(c);
  }
  if(!state.messages[conversationId]) state.messages[conversationId]=[];
  let m=state.messages[conversationId].find(x=>x.id===payload.messageId);
  if(!m){
    m={
      id:payload.messageId,
      mine:true,
      text:payload.text,
      time:payload.time,
      state:"queued",
      cloud:payload.cloud
    };
    state.messages[conversationId].push(m);
  }else if(!["sent","delivered","read"].includes(m.state)){
    m.state="queued";
    m.cloud=payload.cloud;
  }
  if(c){
    c.preview=payload.text || c.preview;
    c.time=payload.time || c.time;
  }
  return {c,m};
}
async function restoreOutboxIntoState(){
  try{
    const records=await getOutboxRecords();
    for(const record of records){
      try{
        const payload=await decryptOutboxRecord(record);
        ensureQueuedMessageFromPayload(payload);
      }catch(err){
        console.warn("Could not restore queued message",record?.id,err);
      }
    }
  }catch(err){
    console.warn("Could not restore Outbox",err);
  }
}

async function cacheCloudHistory(conversationId,messages){
  try{
    const db=await openDb();
    const encrypted=await encryptLocal({
      conversationId,
      messages,
      savedAt:Date.now()
    });
    const tx=db.transaction("history","readwrite");
    tx.objectStore("history").put(encrypted,String(conversationId));
    await txDone(tx);
  }catch(err){
    console.warn("Cloud history cache failed",conversationId,err);
  }
}
async function loadCloudHistory(){
  try{
    const db=await openDb();

    // Safari/iOS may auto-close an IndexedDB transaction as soon as control
    // returns to the event loop. Do not await one request and then issue
    // another request on the same transaction. A single getAll() request is
    // sufficient because each encrypted record contains its conversationId.
    const values=await idbRequest(
      db.transaction("history","readonly").objectStore("history").getAll()
    );

    for(const value of values){
      try{
        const saved=await decryptLocal(value);
        if(!saved?.conversationId || !Array.isArray(saved.messages)) continue;
        const id=saved.conversationId;
        const current=state.messages[id] || [];
        const pending=current.filter(m=>m.cloud && m.mine && ["queued","sending","failed"].includes(m.state));
        const savedIds=new Set(saved.messages.map(m=>m.id));
        state.messages[id]=[
          ...saved.messages,
          ...pending.filter(m=>!savedIds.has(m.id))
        ];
      }catch(err){
        console.warn("Could not restore cached cloud history",err);
      }
    }
  }catch(err){
    console.warn("Could not load cloud history cache",err);
  }
}

function cloudDisplayName(c){
  if(!c?.cloud || !firebaseUser) return c?.name || "Conversation";
  return c.name || "FIDUNIO contact";
}
function mergeCloudConversation(remote){
  const existing=state.conversations.find(c=>String(c.id)===String(remote.id));
  const item={
    id:remote.id,type:"direct",cloud:true,
    // peerUid is part of the conversation's durable identity for E2EE.
    // Never drop it while merging Firestore conversation discovery into
    // an older locally cached conversation.
    peerUid:remote.peerUid || existing?.peerUid || existing?.uid || existing?.otherUid || null,
    name:remote.name || existing?.name || "FIDUNIO contact",
    unread:existing?.unread || 0,
    preview:remote.preview || existing?.preview || "Cloud conversation",
    time:remote.time || existing?.time || ""
  };
  if(item.peerUid&&peerDisplayNames[item.peerUid])item.name=peerDisplayNames[item.peerUid];
  if(existing) Object.assign(existing,item);
  else state.conversations.unshift(item);
  if(!state.messages[item.id]) state.messages[item.id]=[];
  return existing || item;
}
function mergeCloudGroup(remote){
  const existing=state.conversations.find(c=>String(c.id)===String(remote.id));
  const item={...remote,type:"group",cloudGroup:true,unread:existing?.unread||0,preview:remote.preview||existing?.preview||"Group • messaging pending E2EE",time:remote.time||existing?.time||""};
  if(existing)Object.assign(existing,item);else state.conversations.unshift(item);
  if(!state.messages[item.id])state.messages[item.id]=[];
  return existing||item;
}
function beginCloudGroupSubscription(){
  if(cloudGroupUnsub){cloudGroupUnsub();cloudGroupUnsub=null;}
  if(!firebaseUser)return;
  cloudGroupUnsub=subscribeMyGroups(firebaseUser.uid,rows=>{rows.forEach(mergeCloudGroup);persistSoon();if(state.route==="messages"||state.route==="chat"||state.route==="groupInfo")render();},err=>{firebaseError=err?.message||String(err);});
}
function stopPeerDisplayNameSubscription(){
  try{peerDisplayNameUnsub();}catch{}
  peerDisplayNameUnsub=()=>{};
  peerDisplayNameKey="";
  peerDisplayNames={};
}
function syncPeerDisplayNameSubscription(rows){
  const uids=[...new Set((rows||[]).map(r=>r?.peerUid).filter(Boolean))].sort();
  const key=uids.join("|");
  if(key===peerDisplayNameKey)return;
  stopPeerDisplayNameSubscription();
  peerDisplayNameKey=key;
  if(!uids.length)return;
  peerDisplayNameUnsub=subscribeUserDisplayNames(uids,names=>{
    peerDisplayNames=names||{};
    let changed=false;
    for(const c of state.conversations){
      const name=c?.peerUid?peerDisplayNames[c.peerUid]:null;
      if(name&&c.name!==name){c.name=name;changed=true;}
    }
    if(changed){persistSoon();if(state.route==="messages"||state.route==="chat")render();}
  },err=>console.warn("FIDUNIO peer display-name sync unavailable",err));
}
function stopCloudMessageSubscription(){
  if(cloudMessageUnsub){ cloudMessageUnsub(); cloudMessageUnsub=null; }
  cloudMessageConversationId=null;
}
function beginCloudConversationSubscription(){
  if(cloudConversationUnsub){cloudConversationUnsub();cloudConversationUnsub=null;}
  if(!firebaseUser) return;
  cloudConversationUnsub=subscribeMyConversations(firebaseUser.uid, rows=>{
    rows.forEach(mergeCloudConversation);
    syncPeerDisplayNameSubscription(rows);
    // A restored Firestore conversation may repair peerUid for an older
    // local record. Reattach the active chat listener after reconciliation.
    ensureActiveCloudMessageSubscription();
    persistSoon();
    if(state.route==="messages" || state.route==="chat") render();
  }, err=>{
    firebaseError=err?.message || String(err);
    if(state.route==="settings") renderSettings();
  });
}
function ensureActiveCloudMessageSubscription(force=false){
  if(!firebaseUser || state.route!=="chat") return;
  const c=state.conversations.find(x=>String(x.id)===String(state.selectedId));
  if(c?.cloud) beginCloudMessageSubscription(c.id,{force});
}

/* FIDUNIO direct-message E2EE foundation */
const E2EE_VERSION=1;
let deviceKeyPair=null;
let e2eePublishPromise=null;
const peerKeyCache=new Map();
function b64(bytes){ let s=""; const u8=bytes instanceof Uint8Array?bytes:new Uint8Array(bytes); for(let i=0;i<u8.length;i+=0x8000)s+=String.fromCharCode(...u8.subarray(i,i+0x8000)); return btoa(s); }
function unb64(s){ const bin=atob(s),out=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++)out[i]=bin.charCodeAt(i); return out; }
let deviceIdentityMaterialPromise=null;
async function ensureStableDeviceIdentityMaterial(){
  if(deviceIdentityMaterialPromise)return deviceIdentityMaterialPromise;
  deviceIdentityMaterialPromise=(async()=>{
    const db=await openDb();
    const store=db.transaction("meta","readonly").objectStore("meta");
    const keyReq=store.get("e2ee-device-keypair-v1");
    const identityReq=store.get("e2ee-device-identity-v1");
    const [existingKeyPair,existingIdentity]=await Promise.all([idbRequest(keyReq),idbRequest(identityReq)]);
    const hasKeyPair=!!(existingKeyPair?.privateKey&&existingKeyPair?.publicKey&&existingKeyPair?.publicJwk);
    const hasIdentity=!!existingIdentity?.deviceId;
    if(hasKeyPair!==hasIdentity){
      throw new Error("FIDUNIO E2EE identity is incomplete. A deliberate device reset is required; automatic key rotation is blocked.");
    }
    if(hasKeyPair){
      deviceKeyPair=existingKeyPair;
      return{keyPair:existingKeyPair,identity:existingIdentity};
    }
    const kp=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},false,["deriveBits"]);
    const publicJwk=await crypto.subtle.exportKey("jwk",kp.publicKey);
    const createdAt=Date.now();
    const keyPair={privateKey:kp.privateKey,publicKey:kp.publicKey,publicJwk,createdAt};
    const identity={
      deviceId:crypto.randomUUID ? crypto.randomUUID() : `dev-${createdAt}-${b64(crypto.getRandomValues(new Uint8Array(12))).replace(/[^a-zA-Z0-9]/g,"")}`,
      createdAt
    };
    const tx=db.transaction("meta","readwrite");
    const writeStore=tx.objectStore("meta");
    writeStore.put(keyPair,"e2ee-device-keypair-v1");
    writeStore.put(identity,"e2ee-device-identity-v1");
    await txDone(tx);
    deviceKeyPair=keyPair;
    return{keyPair,identity};
  })().catch(err=>{deviceIdentityMaterialPromise=null;throw err;});
  return deviceIdentityMaterialPromise;
}
async function getOrCreateDeviceKeyPair(){
  return (await ensureStableDeviceIdentityMaterial()).keyPair;
}
function canonicalPublicJwk(jwk){
  return JSON.stringify({kty:jwk?.kty||"",crv:jwk?.crv||"",x:jwk?.x||"",y:jwk?.y||""});
}
async function publicKeyFingerprint(jwk){
  const bytes=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(canonicalPublicJwk(jwk)));
  return [...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,"0")).join("").toUpperCase();
}
function formatFingerprint(fp){
  return String(fp||"").match(/.{1,4}/g)?.join(" ")||"";
}
function shortDeviceId(id){
  const s=String(id||"");
  return s.length>12 ? `${s.slice(0,8)}…${s.slice(-4)}` : s;
}
function peerTrustRecord(peerUid){
  if(!peerUid) return null;
  return state.peerTrust?.[peerUid] || null;
}
function peerTrustStatus(peerUid){
  const t=peerTrustRecord(peerUid);
  if(!t?.observedFingerprint) return "unknown";
  if(t.verifiedFingerprint && t.verifiedFingerprint===t.observedFingerprint) return "verified";
  if(t.verifiedFingerprint && t.verifiedFingerprint!==t.observedFingerprint) return "changed";
  return t.previousFingerprint && t.previousFingerprint!==t.observedFingerprint ? "changed-unverified" : "unverified";
}
async function observePeerPublicKey(peerUid,jwk){
  if(!peerUid||!jwk) return null;
  if(!state.peerTrust || typeof state.peerTrust!=="object") state.peerTrust={};
  const fp=await publicKeyFingerprint(jwk);
  const prior=state.peerTrust[peerUid];
  if(!prior){
    state.peerTrust[peerUid]={
      observedFingerprint:fp,
      firstSeenAt:Date.now(),
      lastSeenAt:Date.now(),
      verifiedFingerprint:null,
      verifiedAt:null
    };
    await persistState();
    return state.peerTrust[peerUid];
  }
  if(prior.observedFingerprint!==fp){
    state.peerTrust[peerUid]={
      ...prior,
      previousFingerprint:prior.observedFingerprint||null,
      observedFingerprint:fp,
      changedAt:Date.now(),
      lastSeenAt:Date.now()
    };
    await persistState();
  }else{
    prior.lastSeenAt=Date.now();
  }
  return state.peerTrust[peerUid];
}
async function verifyCurrentPeerKey(peerUid){
  const t=peerTrustRecord(peerUid);
  if(!t?.observedFingerprint) throw new Error("No current contact key is available to verify.");
  state.peerTrust[peerUid]={
    ...t,
    verifiedFingerprint:t.observedFingerprint,
    verifiedAt:Date.now(),
    previousFingerprint:null,
    changedAt:null
  };
  await persistState();
}
function currentConversationSecurityStatus(c=currentConversation()){
  if(!c?.cloud || !c?.peerUid) return "not-applicable";
  return peerTrustStatus(c.peerUid);
}
async function getOrCreateDeviceIdentity(){
  const {keyPair:kp,identity}=await ensureStableDeviceIdentityMaterial();
  const fingerprint=await publicKeyFingerprint(kp.publicJwk);
  deviceSecurityInfo={
    ...identity,
    publicJwk:kp.publicJwk,
    fingerprint,
    label:"FIDUNIO Web device"
  };
  return deviceSecurityInfo;
}
async function deriveDirectKey(peerPublicJwk,conversationId){
  const mine=await getOrCreateDeviceKeyPair();
  const peer=await crypto.subtle.importKey("jwk",peerPublicJwk,{name:"ECDH",namedCurve:"P-256"},false,[]);
  const bits=await crypto.subtle.deriveBits({name:"ECDH",public:peer},mine.privateKey,256);
  const base=await crypto.subtle.importKey("raw",bits,"HKDF",false,["deriveKey"]);
  return crypto.subtle.deriveKey({name:"HKDF",hash:"SHA-256",salt:new TextEncoder().encode("FIDUNIO-E2EE-v1"),info:new TextEncoder().encode(String(conversationId))},base,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
}
async function encryptCloudText(text,peerPublicJwk,conversationId){
  const key=await deriveDirectKey(peerPublicJwk,conversationId),iv=crypto.getRandomValues(new Uint8Array(12));
  const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:new TextEncoder().encode(String(conversationId))},key,new TextEncoder().encode(text));
  return {e2ee:E2EE_VERSION,ciphertext:b64(cipher),iv:b64(iv)};
}
async function decryptCloudText(row,peerPublicJwk,conversationId){
  if(!row?.e2ee||!row?.ciphertext||!row?.iv)return row?.text||"";
  const key=await deriveDirectKey(peerPublicJwk,conversationId);
  const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(row.iv),additionalData:new TextEncoder().encode(String(conversationId))},key,unb64(row.ciphertext));
  return new TextDecoder().decode(plain);
}
async function resolvePeerUidForConversation(conversationId){
  const c=state.conversations.find(x=>String(x.id)===String(conversationId));
  let peerUid=c?.peerUid || c?.uid || c?.otherUid || null;
  if(peerUid || !firebaseUser) return peerUid;

  // Repair older local conversation records that predate peerUid. The
  // Firestore conversation document is authoritative for membership, so we
  // can recover the other member without asking the user to copy an ID again.
  try{
    const remote=await getCloudConversation(conversationId,firebaseUser.uid);
    if(remote){
      const repaired=mergeCloudConversation(remote);
      peerUid=repaired?.peerUid || remote.peerUid || null;
      if(peerUid) await persistState();
    }
  }catch(err){
    console.warn("Could not repair cloud conversation peer identity",conversationId,err);
  }
  return peerUid;
}
async function peerPublicKeyForConversation(conversationId,{refresh=false}={}){
  const peerUid=await resolvePeerUidForConversation(conversationId);
  if(!peerUid)return null;
  if(!refresh && peerKeyCache.has(peerUid))return peerKeyCache.get(peerUid);
  try{
    const profile=await getCloudUserProfile(peerUid);
    const jwk=profile?.e2eePublicJwk||null;
    if(jwk){
      await observePeerPublicKey(peerUid,jwk);
      peerKeyCache.set(peerUid,jwk);
    }
    return jwk;
  }catch{return null;}
}
async function publishMyE2EEKey(){
  if(!firebaseUser)return;
  if(e2eePublishPromise)return e2eePublishPromise;
  const publishingUid=firebaseUser.uid;
  e2eePublishPromise=(async()=>{
    const identity=await getOrCreateDeviceIdentity();
    if(!firebaseUser||firebaseUser.uid!==publishingUid)return;

    // Compatibility publication updates the same authenticated account only.
    await publishCloudE2EEPublicKey(publishingUid,identity.publicJwk);

    // Device registration is idempotent because the stable deviceId is the
    // Firestore document ID. App restarts/updates update this record; they do
    // not create a replacement device identity.
    try{
      await publishCloudE2EEDevice(publishingUid,identity);
      myRegisteredDevices=await getCloudUserDevices(publishingUid);
      deviceRegistryStatus="registered";
    }catch(err){
      deviceRegistryStatus=err?.message||String(err);
      console.warn("Device registry publication failed",err);
    }
    if(state.route==="settings")renderSettings();
  })().finally(()=>{e2eePublishPromise=null;});
  return e2eePublishPromise;
}

function beginCloudMessageSubscription(conversationId,{force=false}={}){
  const wanted=String(conversationId);
  if(
    !force &&
    cloudMessageUnsub &&
    String(cloudMessageConversationId)===wanted
  ) return;

  stopCloudMessageSubscription();
  const c=state.conversations.find(x=>String(x.id)===wanted);
  if(!c?.cloud || !firebaseUser) return;

  cloudMessageConversationId=wanted;
  cloudMessageUnsub=subscribeConversationMessages(
    conversationId,
    firebaseUser.uid,
    async (rows,meta={})=>{
      const existing=state.messages[conversationId] || [];
      if(!meta.fromCache){
        const rawStateById=new Map(rows.map(r=>[r.id,r.state||"sent"]));
        let receiptChanged=false;
        for(const local of existing){if(!local?.mine)continue;const next=rawStateById.get(local.id);if(next&&next!==local.state){local.state=next;receiptChanged=true;}}
        if(receiptChanged&&state.route==="chat"&&String(state.selectedId)===String(conversationId))render();
        if(state.route==="chat"&&String(state.selectedId)===String(conversationId)){
          const unreadRows=rows.filter(r=>r.senderUid!==firebaseUser.uid&&(r.state||"sent")!=="read");
          if(unreadRows.length)await Promise.allSettled(unreadRows.map(r=>updateCloudMessageState(conversationId,r.id,"read")));
        }
      }
      const peerKey=await peerPublicKeyForConversation(conversationId,{refresh:true});
      const remote=[];
      for(const m of rows){
        let text=m.text||"";
        if(m.e2ee===3){
          try{text=await decryptAccountDirectMessage({uid:firebaseUser.uid,peerUid:c.peerUid,conversationId,messageId:m.id,row:m});}
          catch{text="[Encrypted message — account encryption unavailable]";}
        }else if(m.e2ee){
          if(peerKey){try{text=await decryptCloudText(m,peerKey,conversationId);}catch{text="[Encrypted message — key unavailable]";}}
          else text="[Encrypted message — key unavailable]";
        }
        remote.push({id:m.id,mine:m.senderUid===firebaseUser.uid,sender:m.senderName||"",text,time:m.timeLabel||"",state:m.state||"sent",cloud:true,e2ee:!!m.e2ee,senderDeviceId:m.senderDeviceId||null});
      }

      let merged;

      if(meta.fromCache){
        /*
         * IMPORTANT OFFLINE RULE
         * ----------------------
         * Firestore may emit an empty or incomplete cache snapshot on an
         * offline cold start. That is NOT proof that the conversation has no
         * messages. Never let such a snapshot erase the encrypted local copy.
         *
         * Merge anything Firestore does know into the locally restored
         * history, but preserve every existing row that Firestore's cache
         * doesn't currently contain.
         */
        const byId=new Map(existing.map(m=>[m.id,m]));
        for(const m of remote){
          const prior=byId.get(m.id);
          byId.set(m.id, prior ? {...prior,...m} : m);
        }
        merged=[...byId.values()];
      }else{
        /*
         * A server-backed snapshot is authoritative for messages already
         * stored in Firestore. Preserve only local outbound work that has not
         * yet reached the server.
         */
        const remoteIds=new Set(remote.map(m=>m.id));
        const localPending=existing.filter(m=>
          m.cloud && m.mine &&
          ["queued","sending","failed"].includes(m.state) &&
          !remoteIds.has(m.id)
        );
        merged=[...remote,...localPending];
      }

      state.messages[conversationId]=merged;

      const last=merged.at(-1);
      if(last){
        c.preview=last.text;
        c.time=last.time;
      }

      /*
       * Local-first durability:
       * persist the merged result before any read-receipt network work.
       * A network/cache callback must never make local history less durable.
       */
      await cacheCloudHistory(conversationId,merged);
      await persistState();

      const unreadIncoming=merged.filter(m=>!m.mine && m.state!=="read");
      if(
        !meta.fromCache &&
        state.route==="chat" &&
        String(state.selectedId)===String(conversationId)
      ){
        for(const m of unreadIncoming){
          try{ await updateCloudMessageState(conversationId,m.id,"read"); }catch{}
        }
      }

      if(state.route==="chat" && String(state.selectedId)===String(conversationId)) render();
    },
    err=>{
      firebaseError=err?.message || String(err);
      if(state.route==="settings") renderSettings();
    }
  );
}
async function initializeFirebaseLayer(){
  if(!isFirebaseConfigured()) return;
  try{
    await initFirebase(user=>{
      firebaseUser=user;
      firebaseReady=true;
      if(user){
        bindAuthenticatedAccountE2EE(user.uid).catch(err=>console.warn("Account E2EE identity lookup failed",err));
        publishMyE2EEKey().catch(err=>console.warn("Could not publish E2EE key",err));
        beginCloudConversationSubscription();
        beginCloudGroupSubscription();
        ensureActiveCloudMessageSubscription(true);
        if(state.online) scheduleReconnectRecovery();
      }else{
        resetAccountE2EEForSignOut();
        if(cloudConversationUnsub){cloudConversationUnsub();cloudConversationUnsub=null;}
        stopPeerDisplayNameSubscription();
        if(cloudGroupUnsub){cloudGroupUnsub();cloudGroupUnsub=null;}
        stopCloudMessageSubscription();
      }
      if(state.route==="settings" || state.route==="messages") render();
    });
    firebaseReady=true;
    firebaseUser=getFirebaseUser();
    if(firebaseUser) publishMyE2EEKey().catch(err=>console.warn("Could not publish E2EE key",err));
    ensureActiveCloudMessageSubscription(true);
    if(firebaseUser && state.online) scheduleReconnectRecovery();
  }catch(err){
    firebaseError=err?.message || String(err);
  }
}

async function initApp(){
  /*
   * Local-first boot:
   * 1) restore durable app state
   * 2) restore encrypted cloud history
   * 3) reconstruct any queued outbound messages
   * 4) render immediately
   * 5) only then initialize Firebase as a synchronization layer
   *
   * Firebase being offline, slow, uncached, or temporarily empty must never
   * prevent already-downloaded local messages from being shown.
   */
  await loadPersistedState();
  await loadCloudHistory();
  await restoreOutboxIntoState();

  hydrated=true;
  state.online=navigator.onLine;
  if(consumeSuccessfulAuthBypass()) state.unlocked=true;
  installInactivityMonitor({isUnlocked:()=>state.unlocked,onLock:reason=>lockLocalApp(reason)});
  if(state.unlocked) noteLocalUnlock();
  render();

  initializeFirebaseLayer();
  if(state.online) flushQueued();
}

function esc(s=""){ return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function initials(name){ return name.split(" ").slice(0,2).map(x=>x[0]).join("").toUpperCase(); }

function icon2d(name,size=22){
  const common=`width="${size}" height="${size}" viewBox="0 0 24 24" aria-hidden="true" focusable="false"`;
  const icons={
    settings:`<svg ${common}><rect x="3" y="3" width="18" height="18" rx="5" fill="currentColor" opacity=".12"/><path d="M12 8.2a3.8 3.8 0 1 0 0 7.6 3.8 3.8 0 0 0 0-7.6Zm0 2.1a1.7 1.7 0 1 1 0 3.4 1.7 1.7 0 0 1 0-3.4Z" fill="currentColor"/><path d="M12 4.6v2M12 17.4v2M4.6 12h2M17.4 12h2M6.7 6.7l1.4 1.4M15.9 15.9l1.4 1.4M17.3 6.7l-1.4 1.4M8.1 15.9l-1.4 1.4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>`,
    info:`<svg ${common}><rect x="3" y="3" width="18" height="18" rx="6" fill="currentColor" opacity=".12"/><circle cx="12" cy="8" r="1.2" fill="currentColor"/><path d="M12 11v5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>`,
    plus:`<svg ${common}><rect x="3" y="3" width="18" height="18" rx="6" fill="currentColor" opacity=".12"/><path d="M12 7v10M7 12h10" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>`,
    photo:`<svg ${common}><rect x="3" y="4" width="18" height="16" rx="4" fill="currentColor" opacity=".12"/><circle cx="9" cy="9" r="2" fill="currentColor"/><path d="m5.5 17 4.2-4.4 2.7 2.7 2.1-2.1 4 3.8" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
    file:`<svg ${common}><path d="M7 3h7l4 4v14H7a3 3 0 0 1-3-3V6a3 3 0 0 1 3-3Z" fill="currentColor" opacity=".12"/><path d="M14 3v5h5M8 12h8M8 16h6" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
    voice:`<svg ${common}><rect x="8" y="3" width="8" height="12" rx="4" fill="currentColor" opacity=".16"/><path d="M6 11a6 6 0 0 0 12 0M12 17v4M9 21h6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>`,
    location:`<svg ${common}><path d="M12 21s6-5.2 6-11a6 6 0 1 0-12 0c0 5.8 6 11 6 11Z" fill="currentColor" opacity=".14"/><circle cx="12" cy="10" r="2.5" fill="currentColor"/></svg>`,
    contact:`<svg ${common}><rect x="4" y="3" width="16" height="18" rx="4" fill="currentColor" opacity=".12"/><circle cx="12" cy="9" r="3" fill="currentColor"/><path d="M7.5 17c.8-2.3 2.4-3.5 4.5-3.5s3.7 1.2 4.5 3.5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>`,
    checklist:`<svg ${common}><rect x="4" y="4" width="16" height="16" rx="4" fill="currentColor" opacity=".12"/><path d="m7.5 9.5 1.5 1.5 2.5-3M13.5 10h3M7.5 15.5 9 17l2.5-3M13.5 16h3" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
    schedule:`<svg ${common}><rect x="4" y="5" width="16" height="15" rx="4" fill="currentColor" opacity=".12"/><path d="M8 3v4M16 3v4M4 9h16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="14" r="2.4" fill="currentColor"/></svg>`,
    saved:`<svg ${common}><path d="M7 3h10a2 2 0 0 1 2 2v16l-7-4-7 4V5a2 2 0 0 1 2-2Z" fill="currentColor" opacity=".14"/><path d="m12 7 1.2 2.4 2.7.4-2 1.9.5 2.7-2.4-1.3-2.4 1.3.5-2.7-2-1.9 2.7-.4L12 7Z" fill="currentColor"/></svg>`,
    chats:`<svg ${common}><path d="M5 5h14a3 3 0 0 1 3 3v6a3 3 0 0 1-3 3h-8l-5 4v-4H5a3 3 0 0 1-3-3V8a3 3 0 0 1 3-3Z" fill="currentColor" opacity=".18"/><path d="M7 10h10M7 13.5h7" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>`,
    groups:`<svg ${common}><circle cx="9" cy="9" r="3" fill="currentColor"/><circle cx="16.5" cy="10" r="2.4" fill="currentColor" opacity=".72"/><path d="M3.5 19c.8-3.3 2.8-5 5.5-5s4.7 1.7 5.5 5" fill="currentColor" opacity=".18"/><path d="M13 18.5c.6-2.5 2-3.8 4.2-3.8 1.6 0 2.9.8 3.8 2.4" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>`,
    contacts:`<svg ${common}><circle cx="12" cy="8.5" r="3.5" fill="currentColor"/><path d="M5 20c1-4 3.3-6 7-6s6 2 7 6" fill="currentColor" opacity=".2"/></svg>`,
    back:`<svg ${common}><rect x="3" y="3" width="18" height="18" rx="6" fill="currentColor" opacity=".1"/><path d="m13.5 7-5 5 5 5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
    send:`<svg ${common}><path d="M4 5.5 20 12 4 18.5l2.4-5.2L14 12l-7.6-1.3L4 5.5Z" fill="currentColor" opacity=".18"/><path d="M5 6.5 19 12 5 17.5l1.9-4.2L14 12l-7.1-1.3L5 6.5Z" fill="currentColor"/></svg>`
  };
  return icons[name]||"";
}
function toolButton(icon,label){
  return `<button class="tool"><span class="tool-icon">${icon2d(icon,24)}</span><span>${esc(label)}</span></button>`;
}

function nowTime(){ return new Date().toLocaleTimeString([], {hour:"numeric",minute:"2-digit"}); }
function currentConversation(){ return state.conversations.find(x=>String(x.id)===String(state.selectedId)); }
function isGroup(c=currentConversation()){ return c?.type==="group"; }

function shellTop(title,left=`<span class="topbar-spacer"></span>`,right=`<span class="topbar-spacer"></span>`){
  return `<header class="topbar">${left}<h1>${esc(title)}</h1>${right}</header>`;
}
function mainSignOutMarkup(){
  return '<button class="secondary" id="fidunioMainSignOutBtn" type="button" aria-label="Sign Out" style="width:auto;margin:0 6px;padding:8px 12px">Sign Out</button>';
}
function bindMainSignOut(){
  const btn=document.querySelector("#fidunioMainSignOutBtn");
  if(!btn)return;
  btn.onclick=async()=>{
    btn.disabled=true;btn.textContent="Signing Out…";
    try{await signOutFidunio();location.reload();}
    catch(err){btn.disabled=false;btn.textContent="Sign Out";alert(err?.message||String(err));}
  };
}

function applyAppearance(){
  const root=document.documentElement;
  root.classList.remove("text-a","text-aplus","text-aplusplus");
  const textSize=state.settings.textSize || "normal";
  root.classList.add(textSize==="large" ? "text-aplus" : textSize==="xlarge" ? "text-aplusplus" : "text-a");
  const prefersDark=window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  const effective=state.settings.appearance==="auto" ? (prefersDark?"dark":"light") : state.settings.appearance;
  root.dataset.theme=effective;
  const meta=document.querySelector('meta[name="theme-color"]');
  if(meta) meta.setAttribute("content", effective==="dark" ? "#182127" : "#ffffff");
}

function isWideLayout(){
  return window.matchMedia && window.matchMedia("(min-width: 700px)").matches;
}
function renderConversationSidebar(){
  return `
    <aside class="tablet-sidebar">
      <div class="tablet-brand-row">
        <div>
          <div class="tablet-brand-name">FIDUNIO</div>
          <div class="tablet-brand-sub">Private Messaging</div>
        </div>
        <div class="tablet-brand-actions">
          <button class="icon-btn icon-2d" id="tabletSettingsBtn" aria-label="Settings">${icon2d("settings",23)}</button>
          <button class="icon-btn icon-2d" id="tabletNewBtn" aria-label="New conversation">${icon2d("plus",23)}</button>
          ${mainSignOutMarkup()}
        </div>
      </div>
      <div class="tablet-search-wrap">
        <input class="search" id="tabletSearchBox" placeholder="Search conversations" />
      </div>
      <div class="tablet-conversation-list" id="tabletConversationList"></div>
      <nav class="tablet-bottom-nav" aria-label="FIDUNIO sections">
        <button class="tablet-nav-item active" id="tabletMessagesNav">${icon2d("chats",22)}<span>Messages</span></button>
        <button class="tablet-nav-item" id="tabletGroupsNav">${icon2d("groups",22)}<span>Groups</span></button>
        <button class="tablet-nav-item" id="tabletContactsNav">${icon2d("contacts",22)}<span>Contacts</span></button>
        <button class="tablet-nav-item" id="tabletSettingsNav">${icon2d("settings",22)}<span>Settings</span></button>
      </nav>
    </aside>`;
}
function drawTabletConversationList(term=""){
  const list=document.querySelector("#tabletConversationList");
  if(!list) return;
  list.innerHTML=state.conversations
    .filter(c=>c.name.toLowerCase().includes(term.toLowerCase())||c.preview.toLowerCase().includes(term.toLowerCase()))
    .map(c=>`
      <button class="tablet-conversation ${String(c.id)===String(state.selectedId)?"active":""}" data-id="${c.id}">
        <div class="avatar ${c.type==="group"?"group-avatar":""}">${initials(c.name)}</div>
        <div class="tablet-conversation-main">
          <div class="tablet-row-top"><span class="name">${esc(c.name)}</span><span class="meta">${esc(c.time)}</span></div>
          <div class="preview">${c.type==="group"?"Group • ":""}${esc(c.preview)}</div>
        </div>
      </button>`).join("");
  list.querySelectorAll(".tablet-conversation").forEach(btn=>btn.onclick=()=>{
    const raw=btn.dataset.id;
    state.selectedId=/^\d+$/.test(raw)?Number(raw):raw;
    state.route="chat";
    const chosen=state.conversations.find(x=>String(x.id)===String(state.selectedId));
    if(chosen) chosen.unread=0;
    if(chosen?.cloud) beginCloudMessageSubscription(chosen.id,{force:true});
    else stopCloudMessageSubscription();
    render();
  });
}

function render(){
  persistSoon();
  document.querySelectorAll(".modal-backdrop").forEach(el=>el.remove());
  applyAppearance();
  document.body.dataset.route=state.unlocked ? (state.route||"") : "unlock";
  if(!state.unlocked) return renderUnlock();
  const routes={
    messages:renderMessages, chat:renderChat, settings:renderSettings,
    newConversation:renderNewConversation, newGroup:renderNewGroup,
    groupName:renderGroupName, groupInfo:renderGroupInfo
  };
  (routes[state.route]||renderMessages)();
  if(state.modal) renderModal();
}

function renderUnlock(){
  const security=getLocalSecurityStatus();
  if(!security.hasPin){
    app.innerHTML=`
      <main class="app-shell unlock">
        <section class="unlock-card">
          <div class="unlock-brand"><img class="brand-logo" src="fidunio-logo.png" alt="Fidunio logo"></div>
          <h1>Fidunio</h1>
          <p>This installation does not have a local PIN yet. Continue to FIDUNIO, then set one in Settings → Privacy & Access.</p>
          <button class="primary" id="continueBtn">Continue to FIDUNIO</button>
          <div class="small-note">FIDUNIO ${esc(FIDUNIO_VERSION)}</div>
        </section>
      </main>`;
    document.querySelector("#continueBtn").onclick=unlockLocalApp;
    return;
  }
  app.innerHTML=`
    <main class="app-shell unlock">
      <section class="unlock-card">
        <div class="unlock-brand"><img class="brand-logo" src="fidunio-logo.png" alt="Fidunio logo"></div>
        <h1>Unlock FIDUNIO</h1>
        ${security.hasBiometric?'<button class="primary" id="deviceUnlockBtn">Unlock with device</button>':""}
        <label class="form-label" for="localUnlockPin">PIN</label>
        <input class="text-input" id="localUnlockPin" type="password" inputmode="numeric" autocomplete="off" maxlength="12" pattern="[0-9]*" placeholder="4–12 digit PIN">
        <button class="${security.hasBiometric?"secondary":"primary"}" id="localPinUnlockBtn" style="margin-top:12px">Unlock with PIN</button>
        ${unlockError?`<p class="warning-note">${esc(unlockError)}</p>`:""}
        <div class="small-note">FIDUNIO ${esc(FIDUNIO_VERSION)} • Local unlock keeps your Firebase session signed in.</div>
      </section>
    </main>`;
  const input=document.querySelector("#localUnlockPin");
  const pinButton=document.querySelector("#localPinUnlockBtn");
  const tryPin=async()=>{
    pinButton.disabled=true;
    pinButton.textContent="Checking…";
    if(await verifyLocalPin(input.value)){unlockLocalApp();return;}
    unlockError="Incorrect PIN.";
    renderUnlock();
    document.querySelector("#localUnlockPin")?.focus();
  };
  pinButton.onclick=tryPin;
  input.onkeydown=e=>{if(e.key==="Enter")tryPin();};
  const deviceButton=document.querySelector("#deviceUnlockBtn");
  if(deviceButton)deviceButton.onclick=async()=>{
    deviceButton.disabled=true;
    deviceButton.textContent="Waiting for device…";
    if(await verifyBiometric()){unlockLocalApp();return;}
    unlockError="Device unlock was cancelled or unavailable. Use your PIN instead.";
    renderUnlock();
  };
  setTimeout(()=>document.querySelector("#localUnlockPin")?.focus(),0);
}

function renderMessages(){
  if(isWideLayout()){
    let chosen=state.conversations.find(c=>String(c.id)===String(state.selectedId));
    if(!chosen) chosen=state.conversations[0]||null;
    if(chosen){
      state.selectedId=chosen.id;
      state.route="chat";
      chosen.unread=0;
      if(chosen.cloud) beginCloudMessageSubscription(chosen.id,{force:true});
      else stopCloudMessageSubscription();
      return renderChat();
    }
    state.selectedId=null;
    stopCloudMessageSubscription();
    app.innerHTML=`<main class="app-shell tablet-shell">${renderConversationSidebar()}<section class="tablet-chat-pane"><div class="content"><div class="card" style="text-align:center;margin-top:24px"><h2>No conversations yet</h2><p class="small-note">Start a private conversation with another FIDUNIO user.</p><button class="primary" id="emptyNewBtn">New Message</button></div></div></section></main>`;
    drawTabletConversationList();
    const tSearch=document.querySelector("#tabletSearchBox");
    if(tSearch)tSearch.oninput=e=>drawTabletConversationList(e.target.value);
    document.querySelector("#tabletSettingsBtn")?.addEventListener("click",()=>{state.route="settings";render()});
    document.querySelector("#tabletNewBtn")?.addEventListener("click",()=>{state.route="newConversation";render()});
    document.querySelector("#tabletContactsNav")?.addEventListener("click",()=>{state.route="newConversation";render()});
    document.querySelector("#tabletSettingsNav")?.addEventListener("click",()=>{state.route="settings";render()});
    document.querySelector("#emptyNewBtn")?.addEventListener("click",()=>{state.route="newConversation";render()});
    bindMainSignOut();
    return;
  }

  app.innerHTML=`
    <main class="app-shell">
      ${shellTop("Messages",undefined,'<button class="icon-btn icon-2d" id="settingsBtn" aria-label="Settings">'+icon2d("settings",23)+'</button>'+mainSignOutMarkup())}
      <section class="content">
        <input class="search" id="searchBox" placeholder="Search conversations" />
        <div class="conversation-list" id="conversationList"></div>
      </section>
      <button class="fab icon-2d" id="newBtn" aria-label="New conversation">${icon2d("plus",26)}</button>
    </main>`;
  document.querySelector("#settingsBtn").onclick=()=>{state.route="settings";render()};
  document.querySelector("#newBtn").onclick=()=>{state.route="newConversation";render()};
  bindMainSignOut();
  const list=document.querySelector("#conversationList");
  const draw=(term="")=>{
    const rows=state.conversations.filter(c=>(c.name||"").toLowerCase().includes(term.toLowerCase())||(c.preview||"").toLowerCase().includes(term.toLowerCase()));
    list.innerHTML=rows.length?rows.map(c=>`
        <button class="conversation" data-id="${c.id}">
          <div class="avatar ${c.type==="group"?"group-avatar":""}">${initials(c.name||"FIDUNIO")}</div>
          <div>
            <div class="name">${esc(c.name||"FIDUNIO contact")}</div>
            <div class="preview">${c.type==="group"?"Group • ":""}${esc(c.preview||"")}</div>
          </div>
          <div class="meta">${esc(c.time||"")}${c.unread?`<div class="badge">${c.unread}</div>`:""}</div>
        </button>`).join(""):`<div class="card" style="text-align:center"><h2>${term?"No matching conversations":"No conversations yet"}</h2><p class="small-note">${term?"Try another search.":"Start a private conversation with another FIDUNIO user."}</p></div>`;
    list.querySelectorAll(".conversation").forEach(btn=>btn.onclick=()=>{
      const raw=btn.dataset.id;
      state.selectedId=/^\d+$/.test(raw)?Number(raw):raw;
      state.route="chat";
      const chosen=state.conversations.find(x=>String(x.id)===String(state.selectedId));
      if(chosen)chosen.unread=0;
      if(chosen?.cloud)beginCloudMessageSubscription(chosen.id,{force:true});else stopCloudMessageSubscription();
      render();
    });
  };
  draw();
  document.querySelector("#searchBox").oninput=e=>draw(e.target.value);
}

function renderNewConversation(){
  const cloudEnabled=isFirebaseConfigured() && firebaseUser;
  app.innerHTML=`
    <main class="app-shell">
      ${shellTop("New Message",'<button class="back-btn" id="backBtn">‹</button>')}
      <section class="content">
        <div class="action-sheet">
          <button class="big-choice" id="newGroupBtn"><span class="choice-icon">👥</span><span><strong>New Group</strong><span>Create a group and choose its members</span></span></button>
        </div>
        <div class="card">
          <h2>Choose a Person</h2>
          <div id="fidunioRecipientPickerHost"></div>
          ${cloudEnabled?`<p class="small-note">Select a FIDUNIO user by display name.</p><label class="form-label" for="peerUid">Recipient FIDUNIO ID</label><input class="text-input" id="peerUid" autocomplete="off" placeholder="Recipient UID" /><button class="primary" id="cloudDirectBtn">Start Conversation</button><p class="warning-note">Private one-to-one messages are end-to-end encrypted.</p>`:`<p class="small-note">Sign in to FIDUNIO before starting a conversation.</p>`}
        </div>
      </section>
    </main>`;
  document.querySelector("#backBtn").onclick=()=>{stopCloudMessageSubscription();state.route="messages";render()};
  document.querySelector("#newGroupBtn").onclick=()=>{state.newGroupMembers=[];state.newGroupName="";state.route="newGroup";render()};
  const cloudBtn=document.querySelector("#cloudDirectBtn");
  if(cloudBtn)cloudBtn.onclick=async()=>{
    const peerUid=document.querySelector("#peerUid").value.trim();
    if(!peerUid)return alert("Choose a FIDUNIO user first.");
    if(peerUid===firebaseUser.uid)return alert("Choose another FIDUNIO user.");
    cloudBtn.disabled=true;cloudBtn.textContent="Connecting…";
    try{
      const remote=await startDirectConversation(peerUid);
      mergeCloudConversation(remote);
      state.selectedId=remote.id;state.route="chat";
      beginCloudMessageSubscription(remote.id,{force:true});persistSoon();render();
    }catch(err){alert("Could not create the conversation: "+(err?.message||err));cloudBtn.disabled=false;cloudBtn.textContent="Start Conversation";}
  };
  if(cloudEnabled&&cloudBtn){
    mountNewMessageRecipientPicker({
      host:document.querySelector("#fidunioRecipientPickerHost"),
      uidInput:document.querySelector("#peerUid"),
      startButton:cloudBtn
    }).catch(err=>console.warn("New Message recipient picker unavailable",err));
  }
}

function renderNewGroup(){
  if(!firebaseUser){alert("Sign in to a FIDUNIO account before creating a real group.");state.route="newConversation";return render();}
  app.innerHTML=`<main class="app-shell">${shellTop("New Group",'<button class="back-btn" id="backBtn">‹</button>','<button class="text-btn" id="nextBtn">Next</button>')}<section class="content"><input class="search" id="memberSearch" placeholder="Search FIDUNIO users" /><div class="chip-row" id="selectedChips"></div><div class="choice-list" id="memberChoices"><p class="small-note">Loading FIDUNIO users…</p></div></section></main>`;
  document.querySelector("#backBtn").onclick=()=>{state.route="newConversation";render()};
  const draw=(term="")=>{const selected=new Set(state.newGroupMembers),choices=document.querySelector("#memberChoices"),chips=document.querySelector("#selectedChips");if(!choices||!chips)return;chips.innerHTML=state.newGroupMembers.length?groupCandidates.filter(p=>selected.has(p.uid)).map(p=>`<span class="person-chip">${esc(p.displayName||p.email||p.uid)}</span>`).join(""):'<span class="small-note">Select at least 2 people for the group.</span>';choices.innerHTML=groupCandidates.filter(p=>String(p.displayName||p.email||p.uid).toLowerCase().includes(term.toLowerCase())).map(p=>`<button class="member-option ${selected.has(p.uid)?"selected":""}" data-id="${p.uid}"><div class="avatar">${initials(p.displayName||p.email||"U")}</div><div><strong>${esc(p.displayName||p.email||"FIDUNIO user")}</strong><div class="preview">FIDUNIO account</div></div><div class="checkmark">${selected.has(p.uid)?"✓":""}</div></button>`).join("")||'<p class="small-note">No matching FIDUNIO users.</p>';document.querySelectorAll("#memberChoices .member-option").forEach(btn=>btn.onclick=()=>{const id=btn.dataset.id;state.newGroupMembers=selected.has(id)?state.newGroupMembers.filter(x=>x!==id):[...state.newGroupMembers,id];draw(document.querySelector("#memberSearch").value);});document.querySelector("#nextBtn").disabled=state.newGroupMembers.length<2;};
  draw();listCloudUsers().then(rows=>{groupCandidates=rows||[];draw(document.querySelector("#memberSearch")?.value||"");}).catch(err=>{firebaseError=err?.message||String(err);document.querySelector("#memberChoices").innerHTML=`<p class="warning-note">${esc(firebaseError)}</p>`;});document.querySelector("#memberSearch").oninput=e=>draw(e.target.value);document.querySelector("#nextBtn").onclick=()=>{if(state.newGroupMembers.length>=2){state.route="groupName";render();}};
}

function renderGroupName(){
  const selected=groupCandidates.filter(p=>state.newGroupMembers.includes(p.uid));
  app.innerHTML=`<main class="app-shell">${shellTop("Group Details",'<button class="back-btn" id="backBtn">‹</button>')}<section class="content"><div class="card"><label class="form-label" for="groupNameInput">Group name</label><input class="text-input" id="groupNameInput" maxlength="120" placeholder="Enter a group name" value="${esc(state.newGroupName)}" /><div class="section-title">Members</div><div class="chip-row">${selected.map(p=>`<span class="person-chip">${esc(p.displayName||p.email||p.uid)}</span>`).join("")}</div><p class="small-note">New members begin at join time. Real group messaging remains disabled until group E2EE is implemented.</p></div><button class="primary" id="createGroupBtn">Create Group</button></section></main>`;
  document.querySelector("#backBtn").onclick=()=>{state.route="newGroup";render()};const input=document.querySelector("#groupNameInput"),btn=document.querySelector("#createGroupBtn");const validate=()=>{state.newGroupName=input.value;btn.disabled=!input.value.trim()||state.newGroupMembers.length<2;};input.oninput=validate;validate();btn.onclick=async()=>{btn.disabled=true;btn.textContent="Creating…";try{const group=await createCloudGroup(state.newGroupName.trim(),state.newGroupMembers);mergeCloudGroup(group);state.selectedId=group.id;state.newGroupMembers=[];state.newGroupName="";state.route="groupInfo";await persistState();render();}catch(err){alert("Could not create group: "+(err?.message||err));btn.disabled=false;btn.textContent="Create Group";}};
}

function renderChat(){
  const c=currentConversation();
  if(!c){state.selectedId=null;state.route="messages";return renderMessages();}
  const msgs=state.messages[state.selectedId]||[];
  const chatMarkup=`
      <header class="topbar">
        <button class="back-btn icon-2d" id="backBtn" aria-label="Back">${icon2d("back",23)}</button>
        <div class="chat-header-title">
          <strong>${esc(c.name)}</strong>
          <span class="secure">● ${c.cloud?"Cloud":isGroup(c)?`${c.members.length} members • Secure`:"Secure"}</span>
        </div>
        <button class="icon-btn icon-2d" id="infoBtn" aria-label="Info">${icon2d("info",23)}</button>
        ${isWideLayout()?"":mainSignOutMarkup()}
      </header>
      ${state.online?"":'<div class="status-banner">Offline — messages will be queued and sent automatically when connection returns.</div>'}
      ${c.cloud?`<div class="warning-banner">FIDUNIO ${esc(FIDUNIO_VERSION)} E2EE + key verification foundation — test messages only until verified per-device fan-out and forward secrecy are complete.</div>`:""}
      ${c.cloud && currentConversationSecurityStatus(c)==="changed"
        ? '<div class="status-banner">Security warning — this contact\'s previously verified encryption key changed. Verify the new fingerprint before sending.</div>'
        : c.cloud && currentConversationSecurityStatus(c)==="changed-unverified"
          ? '<div class="info-banner">Encryption key changed since first seen. Open Conversation Security to review the current fingerprint.</div>'
          : c.cloud && currentConversationSecurityStatus(c)==="verified"
            ? '<div class="info-banner">Encryption key verified on this device.</div>'
            : ""}
      ${isGroup(c)?'<div class="info-banner">New members see conversation only from their join time unless an admin explicitly grants earlier history.</div>':""}
      <section class="chat" id="chatArea">${msgs.map(m=>renderBubble(m,c)).join("")}</section>
      <section class="composer-wrap">
        <div class="quick-row">${state.quickPhrases.map(q=>`<button class="quick-chip" data-quick="${esc(q)}">${esc(q)}</button>`).join("")}</div>
        <div class="compose-line">
          <button class="more-btn icon-2d" id="moreBtn" aria-label="More tools">${icon2d("plus",24)}</button>
          <textarea id="messageBox" rows="1" placeholder="Type a message…"></textarea>
          <button class="send-btn icon-2d" id="sendBtn" aria-label="Send">${icon2d("send",24)}</button>
        </div>
        <div class="tool-panel ${state.toolsOpen?"open":""}" id="toolPanel">
          ${toolButton("photo","Photo")}${toolButton("file","File")}
          ${toolButton("voice","Voice")}${toolButton("location","Location")}
          ${toolButton("contact","Contact")}${toolButton("checklist","Checklist")}
          ${toolButton("schedule","Schedule")}${toolButton("saved","Saved")}
        </div>
      </section>`;
  if(isWideLayout()){
    app.innerHTML=`<main class="app-shell tablet-shell">${renderConversationSidebar()}<section class="tablet-chat-pane">${chatMarkup}</section></main>`;
    drawTabletConversationList();
    const tSearch=document.querySelector("#tabletSearchBox");
    if(tSearch) tSearch.oninput=e=>drawTabletConversationList(e.target.value);
    const tSettings=document.querySelector("#tabletSettingsBtn");
    if(tSettings) tSettings.onclick=()=>{state.route="settings";render()};
    const tNew=document.querySelector("#tabletNewBtn");
    if(tNew) tNew.onclick=()=>{state.route="newConversation";render()};
    const tMessages=document.querySelector("#tabletMessagesNav");
    if(tMessages) tMessages.onclick=()=>{};
    const tGroups=document.querySelector("#tabletGroupsNav");
    if(tGroups) tGroups.onclick=()=>{state.selectedId=state.conversations.find(x=>x.type==="group")?.id||state.selectedId;state.route="chat";render()};
    const tContacts=document.querySelector("#tabletContactsNav");
    if(tContacts) tContacts.onclick=()=>{state.route="newConversation";render()};
    const tSettingsNav=document.querySelector("#tabletSettingsNav");
    if(tSettingsNav) tSettingsNav.onclick=()=>{state.route="settings";render()};
  }else{
    app.innerHTML=`<main class="app-shell">${chatMarkup}</main>`;
  }
  bindMainSignOut();
  document.querySelector("#backBtn").onclick=()=>{state.route="messages";render()};
  document.querySelector("#infoBtn").onclick=async()=>{
    if(isGroup(c)){state.route="groupInfo";return render();}
    if(c?.cloud){
      await peerPublicKeyForConversation(c.id,{refresh:true});
      state.modal={type:"conversationSecurity",peerUid:c.peerUid,conversationId:c.id};
      return render();
    }
    alert("Conversation details remain a UX placeholder.");
  };
  document.querySelector("#moreBtn").onclick=()=>{state.toolsOpen=!state.toolsOpen;render()};
  document.querySelectorAll(".quick-chip").forEach(btn=>btn.onclick=()=>{
    const box=document.querySelector("#messageBox");box.value=btn.dataset.quick;box.focus();
  });
  document.querySelectorAll(".tool").forEach(btn=>btn.onclick=()=>alert(`${btn.textContent.trim()} is a UX placeholder in FIDUNIO ${FIDUNIO_VERSION}.`));
  const box=document.querySelector("#messageBox");
  box.addEventListener("input",()=>{box.style.height="46px";box.style.height=Math.min(box.scrollHeight,120)+"px"});
  document.querySelector("#sendBtn").onclick=sendCurrent;
  box.addEventListener("keydown",e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();sendCurrent()}});
  requestAnimationFrame(()=>{const a=document.querySelector("#chatArea");a.scrollTop=a.scrollHeight;window.scrollTo(0,document.body.scrollHeight)});
}

function renderBubble(m,c){
  if(m.system) return `<div class="day-divider">${esc(m.text)} • ${esc(m.time)}</div>`;
  const label=m.state==="queued"?"Queued":m.state==="sending"?"Sending":m.state==="sent"?"Sent":
    m.state==="delivered"?"Delivered":m.state==="failed"?"Failed":"Read";
  const cls=m.state==="queued"?"state-queued":m.state==="failed"?"state-failed":"";
  return `<div class="msg-row ${m.mine?"mine":""}">
    ${c.type==="group"&&!m.mine&&m.sender?`<div class="sender-label">${esc(m.sender)}</div>`:""}
    <div class="bubble">
      <div class="msg-text">${esc(m.text)}</div>
      <div class="msg-meta"><span>${esc(m.time)}</span>${m.mine?`<span class="${cls}">${label}</span>`:""}</div>
    </div>
  </div>`;
}

async function sendCurrent(){
  const box=document.querySelector("#messageBox");
  const text=box.value.trim();
  if(!text) return;

  const conversationId=state.selectedId;
  const c=currentConversation();
  const cloud=!!c?.cloud;
  if(c?.cloudGroup){alert("Group messaging is intentionally disabled until group E2EE is implemented.");return;}

  if(cloud && c?.peerUid && !firebaseUser){throw new Error("Sign in before sending an encrypted message.");}

  const m={
    id:crypto.randomUUID(),
    mine:true,
    text,
    time:nowTime(),
    state:(state.online && (!cloud || firebaseUser))?"sending":"queued",
    cloud
  };

  if(!state.messages[conversationId]) state.messages[conversationId]=[];
  state.messages[conversationId].push(m);
  c.preview=text;
  c.time=m.time;

  // The Outbox is authoritative. Do not return from Send until the
  // encrypted queued record is durably committed to IndexedDB.
  await queueOutboxMessage(conversationId,m);
  await persistState();
  render();

  if(state.online){
    if(cloud){
      await flushQueued();
    }else{
      await removeOutboxMessage(m.id);
      simulateDelivery(conversationId,m.id);
    }
  }
}

function simulateDelivery(conversationId,id){
  setTimeout(()=>updateMessageState(conversationId,id,"sent"),700);
  setTimeout(()=>updateMessageState(conversationId,id,"delivered"),1500);
  setTimeout(()=>updateMessageState(conversationId,id,"read"),2600);
}
function updateMessageState(conversationId,id,newState){
  const arr=state.messages[conversationId]||[];
  const m=arr.find(x=>x.id===id);
  if(!m) return;
  m.state=newState;
  persistSoon();
  if(state.route==="chat"&&String(state.selectedId)===String(conversationId)) render();
}
async function flushQueued(){
  if(!state.online) return;

  let records=[];
  try{
    records=await getOutboxRecords();
  }catch(err){
    console.warn("Outbox read failed",err);
    return;
  }

  for(const [i,record] of records.entries()){
    let payload;
    try{
      payload=await decryptOutboxRecord(record);
    }catch(err){
      console.warn("Outbox decrypt failed; record preserved for recovery",record?.id,err);
      continue;
    }

    // Never delete an Outbox record merely because the normal message cache
    // is missing. Rebuild the visible message from the encrypted Outbox.
    const {c,m}=ensureQueuedMessageFromPayload(payload);
    const isCloud=payload.cloud || !!c?.cloud;

    if(isCloud){
      if(!firebaseUser){
        m.state="queued";
        await persistState();
        continue;
      }
      try{
        m.state="sending";
        await persistState();
        if(state.route==="chat"&&String(state.selectedId)===String(payload.conversationId)) render();

        const peerUid=await resolvePeerUidForConversation(payload.conversationId);
        if(!peerUid)throw new Error("Recipient account identity is unavailable.");
        const encrypted=await prepareAccountDirectMessage({uid:firebaseUser.uid,peerUid,conversationId:payload.conversationId,messageId:payload.messageId,text:payload.text});
        await sendCloudMessage(payload.conversationId,{id:payload.messageId,text:"",...encrypted,timeLabel:payload.time,state:"sent"});

        m.state="sent";
        // Remove the Outbox item only after Firestore confirms the write.
        await removeOutboxMessage(payload.messageId);
        await persistState();
      }catch(err){
        // Preserve the Outbox record. A later foreground/online/auth event
        // can retry it without losing the message.
        m.state="failed";
        firebaseError=err?.message || String(err);
        await persistState();
      }
    }else{
      m.state="sending";
      await persistState();
      await removeOutboxMessage(payload.messageId);
      setTimeout(()=>updateMessageState(payload.conversationId,m.id,"sent"),500+i*150);
      setTimeout(()=>updateMessageState(payload.conversationId,m.id,"delivered"),1200+i*150);
      setTimeout(()=>updateMessageState(payload.conversationId,m.id,"read"),2200+i*150);
    }
  }

  render();
}
let reconnectRecoveryTimer1=null;
let reconnectRecoveryTimer2=null;
function scheduleReconnectRecovery(){
  if(reconnectRecoveryTimer1) clearTimeout(reconnectRecoveryTimer1);
  if(reconnectRecoveryTimer2) clearTimeout(reconnectRecoveryTimer2);

  // iOS/Safari may fire "online" slightly before Firebase can complete a
  // request. Flush now, then make two conservative retries. Outbox
  // idempotency keeps this safe; successful records are removed only after
  // Firestore confirms the write.
  flushQueued();
  reconnectRecoveryTimer1=setTimeout(()=>{
    if(state.online && firebaseUser) flushQueued();
  },1500);
  reconnectRecoveryTimer2=setTimeout(()=>{
    if(state.online && firebaseUser) flushQueued();
  },4000);
}
function recoverForegroundCloudSession(){
  state.online=navigator.onLine;
  // Lifecycle recovery is one of the few times we deliberately replace the
  // listener. Normal conversation metadata snapshots no longer restart it.
  ensureActiveCloudMessageSubscription(true);
  if(state.online) scheduleReconnectRecovery();
  render();
}
window.addEventListener("online",()=>{
  state.online=true;
  ensureActiveCloudMessageSubscription(true);
  render();
  scheduleReconnectRecovery();
});
window.addEventListener("offline",()=>{
  state.online=false;
  if(reconnectRecoveryTimer1) clearTimeout(reconnectRecoveryTimer1);
  if(reconnectRecoveryTimer2) clearTimeout(reconnectRecoveryTimer2);
  persistSoon();
  render();
});
document.addEventListener("visibilitychange",()=>{
  if(document.visibilityState==="visible") recoverForegroundCloudSession();
});

let lastWideLayout=isWideLayout();
window.addEventListener("resize",()=>{
  const nowWide=isWideLayout();
  if(nowWide!==lastWideLayout){
    lastWideLayout=nowWide;
    if(state.unlocked && (state.route==="chat" || state.route==="messages")) render();
  }
});

window.addEventListener("pageshow",recoverForegroundCloudSession);

function renderGroupInfo(){
  const c=currentConversation();
  if(!c||c.type!=="group"){state.route="chat";return render()}
  app.innerHTML=`
    <main class="app-shell">
      ${shellTop("Group Info",'<button class="back-btn" id="backBtn">‹</button>')}
      <section class="content">
        <div class="card" style="text-align:center">
          <div class="avatar group-avatar" style="margin:0 auto 10px">${initials(c.name)}</div>
          <h2 style="font-size:22px;margin:0">${esc(c.name)}</h2>
          <p class="small-note">${c.members.length} members • Secure group</p>
          <button class="secondary" id="renameBtn">Rename Group</button>
        </div>
        <div class="card">
          <h2>Members</h2>
          ${c.members.map(m=>`
            <div class="member-card">
              <div class="avatar">${initials(m.name)}</div>
              <div class="row-main">
                <strong>${esc(m.name)}</strong>
                <span>${esc(m.joinedAt)}</span>
                ${m.historyAccess==="from_join"?'<span class="history-lock">Earlier history hidden</span>':
                  m.historyAccess==="all"?'<span class="history-lock">Earlier history available</span>':""}
              </div>
              <div>${m.role!=="Member"?`<span class="role-tag">${esc(m.role)}</span>`:
                `<button class="row-action historyBtn" data-id="${m.id}">History</button>`}</div>
            </div>`).join("")}
          <button class="secondary" id="addMemberBtn">＋ Add Member</button>
        </div>
        <div class="card">
          <h2>Group Controls</h2>
          <div class="row"><div class="row-main"><strong>Mute notifications</strong><span>Silence alerts for this group</span></div><button class="toggle"></button></div>
          <div class="row"><div class="row-main"><strong>Search messages</strong><span>Find text in this conversation</span></div><button class="row-action placeholderBtn">Open</button></div>
          <div class="row"><div class="row-main"><strong>Shared photos & files</strong><span>View shared attachments</span></div><button class="row-action placeholderBtn">Open</button></div>
          <div class="row"><div class="row-main"><strong>Security information</strong><span>Member keys and group-key status</span></div><button class="row-action placeholderBtn">View</button></div>
        </div>
        <button class="danger-btn" id="leaveBtn">Leave Group</button>
      </section>
    </main>`;
  document.querySelector("#backBtn").onclick=()=>{state.route="chat";render()};
  document.querySelector("#renameBtn").onclick=()=>{
    const name=prompt("Rename group:",c.name);
    if(name?.trim()){c.name=name.trim();render()}
  };
  document.querySelector("#addMemberBtn").onclick=()=>openAddMemberModal();
  document.querySelectorAll(".historyBtn").forEach(btn=>btn.onclick=()=>openHistoryModal(btn.dataset.id));
  document.querySelectorAll(".placeholderBtn").forEach(btn=>btn.onclick=()=>alert("This control is represented for UX review and will be implemented in a later prototype."));
  document.querySelector(".toggle").onclick=e=>e.currentTarget.classList.toggle("on");
  document.querySelector("#leaveBtn").onclick=()=>alert(`Leave Group is a UX placeholder in FIDUNIO ${FIDUNIO_VERSION}.`);
}

function openAddMemberModal(){
  const c=currentConversation();
  const currentIds=new Set(c.members.map(m=>m.id));
  const available=contacts.filter(p=>!currentIds.has(p.id));
  state.modal={
    type:"addMember",
    options:available,
    selected:available[0]?.id||null
  };
  render();
}

function openHistoryModal(memberId){
  const c=currentConversation();
  const member=c.members.find(m=>m.id===memberId);
  if(!member)return;
  state.modal={type:"history",memberId,historyChoice:member.historyAccess==="all"?"all":"24h"};
  render();
}

function renderModal(){
  const modal=state.modal;
  const host=document.createElement("div");
  host.className="modal-backdrop";
  if(modal.type==="addMember"){
    host.innerHTML=`
      <div class="modal">
        <h2>Add Member</h2>
        <p>New members begin with access only from the time they join.</p>
        ${modal.options.length?`
          <div class="choice-list">
            ${modal.options.map(p=>`
              <label class="member-option">
                <div class="avatar">${initials(p.name)}</div>
                <div><strong>${esc(p.name)}</strong><div class="preview">No earlier history by default</div></div>
                <input type="radio" name="newMember" value="${p.id}" ${modal.selected===p.id?"checked":""}>
              </label>`).join("")}
          </div>
          <div class="modal-actions">
            <button class="modal-cancel" id="modalCancel">Cancel</button>
            <button class="modal-confirm" id="modalConfirm">Add Member</button>
          </div>`:
          `<p>No additional sample contacts are available in this prototype.</p><button class="secondary" id="modalCancel">Close</button>`}
      </div>`;
    document.body.appendChild(host);
    host.querySelectorAll('input[name="newMember"]').forEach(r=>r.onchange=()=>state.modal.selected=r.value);
    host.querySelector("#modalCancel").onclick=()=>{state.modal=null;host.remove();render()};
    const confirm=host.querySelector("#modalConfirm");
    if(confirm) confirm.onclick=()=>{
      const p=contacts.find(x=>x.id===state.modal.selected);
      if(p){
        const c=currentConversation();
        c.members.push({id:p.id,name:p.name,role:"Member",joinedAt:`Joined ${nowTime()}`,historyAccess:"from_join"});
        state.messages[c.id].push({id:crypto.randomUUID(),system:true,text:`${p.name} joined the group • Earlier messages hidden by default`,time:nowTime()});
        c.preview=`${p.name} joined the group`;c.time=nowTime();
      }
      state.modal=null;render();
    };
  } else if(modal.type==="conversationSecurity"){
    const c=state.conversations.find(x=>String(x.id)===String(modal.conversationId));
    const peerUid=modal.peerUid || c?.peerUid || null;
    const trust=peerTrustRecord(peerUid);
    const status=peerTrustStatus(peerUid);
    const fp=trust?.observedFingerprint||"";
    let peerDevices=[];
    let devicesError="";
    host.innerHTML=`
      <div class="modal">
        <h2>Conversation Security</h2>
        <p><strong>${esc(c?.name||"FIDUNIO contact")}</strong></p>
        <p class="small-note">Compare this fingerprint with your contact using a separate trusted channel, such as an in-person comparison or a call you already trust.</p>
        <label class="form-label">Current public-key fingerprint</label>
        <div class="uid-box">${esc(fp?formatFingerprint(fp):"Key unavailable")}</div>
        <div class="permission-box">
          <div class="row-main">
            <strong>Status</strong>
            <span>${status==="verified"?"Verified on this device":
              status==="changed"?"VERIFIED KEY CHANGED — sending is paused":
              status==="changed-unverified"?"Key changed since first seen":
              status==="unverified"?"Not yet verified":"Key unavailable"}</span>
          </div>
          ${trust?.verifiedFingerprint && trust.verifiedFingerprint!==trust.observedFingerprint ? `
            <div class="row-main">
              <strong>Previously verified</strong>
              <span class="fingerprint-small">${esc(formatFingerprint(trust.verifiedFingerprint))}</span>
            </div>`:""}
        </div>
        <div id="peerDeviceSummary"><p class="small-note">Checking registered devices…</p></div>
        <p class="warning-note">Verification is local to this installation in 0.8.1. It does not yet provide automatic QR/device linking or per-device recipient encryption.</p>
        <div class="modal-actions">
          <button class="modal-cancel" id="modalCancel">Close</button>
          ${fp && status!=="verified" ? '<button class="modal-confirm" id="verifyPeerBtn">Verify Current Key</button>' : ""}
        </div>
      </div>`;
    document.body.appendChild(host);
    host.querySelector("#modalCancel").onclick=()=>{state.modal=null;host.remove();render()};
    const verifyBtn=host.querySelector("#verifyPeerBtn");
    if(verifyBtn) verifyBtn.onclick=async()=>{
      await verifyCurrentPeerKey(peerUid);
      state.modal=null;
      host.remove();
      peerKeyCache.delete(peerUid);
      render();
      if(state.online) flushQueued();
    };
    if(peerUid){
      getCloudUserDevices(peerUid).then(async rows=>{
        peerDevices=rows||[];
        const summary=host.querySelector("#peerDeviceSummary");
        if(!summary) return;
        const matches=[];
        for(const d of peerDevices){
          try{
            const dfp=d.fingerprint || await publicKeyFingerprint(d.publicJwk);
            if(dfp===fp) matches.push(d);
          }catch{}
        }
        summary.innerHTML=`<p class="small-note">Registered devices for this contact: ${peerDevices.length}${matches.length?` • Current compatibility key matches ${matches.length} registered device${matches.length===1?"":"s"}.`:""}</p>`;
      }).catch(err=>{
        devicesError=err?.message||String(err);
        const summary=host.querySelector("#peerDeviceSummary");
        if(summary) summary.innerHTML=`<p class="small-note">Could not read contact device registry: ${esc(devicesError)}</p>`;
      });
    }
  } else if(modal.type==="history"){
    const c=currentConversation();
    const member=c.members.find(m=>m.id===modal.memberId);
    host.innerHTML=`
      <div class="modal">
        <h2>History Access</h2>
        <p>${esc(member.name)} normally sees messages only from the time they joined. As admin, you can explicitly grant earlier history.</p>
        <div class="permission-box">
          ${[
            ["24h","Last 24 hours"],
            ["7d","Last 7 days"],
            ["date","From selected date"],
            ["all","Entire available history"]
          ].map(([v,label])=>`
            <label class="radio-row">
              <input type="radio" name="history" value="${v}" ${modal.historyChoice===v?"checked":""}>
              <span><strong>${label}</strong>${v==="all"?'<div class="small-note">Shares all historical material available to the group.</div>':""}</span>
            </label>`).join("")}
        </div>
        <div class="modal-actions">
          <button class="modal-cancel" id="modalCancel">Cancel</button>
          <button class="modal-confirm" id="modalConfirm">Grant Access</button>
        </div>
      </div>`;
    document.body.appendChild(host);
    host.querySelectorAll('input[name="history"]').forEach(r=>r.onchange=()=>state.modal.historyChoice=r.value);
    host.querySelector("#modalCancel").onclick=()=>{state.modal=null;host.remove();render()};
    host.querySelector("#modalConfirm").onclick=()=>{
      const granted=state.modal.historyChoice;
      member.historyAccess=granted==="all"?"all":granted;
      state.modal=null;
      host.remove();
      render();
    };
  }
  host.onclick=e=>{if(e.target===host){state.modal=null;host.remove();render()}};
}

function renderSettings(){
  app.innerHTML=`
    <main class="app-shell">
      ${shellTop("Settings",'<button class="back-btn" id="backBtn">‹</button>')}
      <section class="content settings">
        <div class="card" id="localSecurityCard"><h2>Privacy & Access</h2>
          ${(()=>{const security=getLocalSecurityStatus();return `
            <div class="row-main"><strong>Local app lock</strong><span>${security.hasPin?"PIN configured on this installation":"PIN not configured"}${security.hasBiometric?" • Device unlock enabled":""}</span></div>
            <label class="form-label" for="lockTimeoutSelect">Lock after inactivity</label>
            <select class="text-input" id="lockTimeoutSelect">${LOCK_TIMEOUTS.map(x=>`<option value="${x.value}" ${security.timeoutMs===x.value?"selected":""}>${esc(x.label)}</option>`).join("")}</select>
            ${!security.hasPin?`
              <label class="form-label" for="newLocalPin">New PIN</label>
              <input class="text-input" id="newLocalPin" type="password" inputmode="numeric" autocomplete="new-password" maxlength="12" pattern="[0-9]*" placeholder="4–12 digits">
              <label class="form-label" for="confirmLocalPin">Confirm PIN</label>
              <input class="text-input" id="confirmLocalPin" type="password" inputmode="numeric" autocomplete="new-password" maxlength="12" pattern="[0-9]*" placeholder="Repeat PIN">
              <button class="primary" id="setLocalPinBtn" style="margin-top:12px">Set PIN</button>
            `:`
              <label class="form-label" for="currentLocalPin">Current PIN</label>
              <input class="text-input" id="currentLocalPin" type="password" inputmode="numeric" autocomplete="off" maxlength="12" pattern="[0-9]*" placeholder="Current PIN">
              <label class="form-label" for="replacementLocalPin">New PIN</label>
              <input class="text-input" id="replacementLocalPin" type="password" inputmode="numeric" autocomplete="new-password" maxlength="12" pattern="[0-9]*" placeholder="4–12 digits">
              <label class="form-label" for="replacementLocalPin2">Confirm new PIN</label>
              <input class="text-input" id="replacementLocalPin2" type="password" inputmode="numeric" autocomplete="new-password" maxlength="12" pattern="[0-9]*" placeholder="Repeat new PIN">
              <button class="secondary" id="changeLocalPinBtn" style="margin-top:12px">Change PIN</button>
              <button class="secondary" id="${security.hasBiometric?"disableBiometricBtn":"enableBiometricBtn"}" style="margin-top:10px">${security.hasBiometric?"Disable Device Unlock":"Enable Device Unlock"}</button>
              <button class="secondary" id="lockNowBtn" style="margin-top:10px">Lock Now</button>
              <button class="danger-btn" id="removeLocalPinBtn" style="margin-top:10px">Remove Local PIN</button>
            `}
            <p class="small-note">The raw PIN is never stored. Device unlock uses WebAuthn/passkeys where the browser and device support a user-verifying platform authenticator.</p>
            ${localSecurityMessage?`<p class="${localSecurityMessageIsError?"warning-note":"small-note"}">${esc(localSecurityMessage)}</p>`:""}
          `})()}
          ${settingRow("Notification message previews","previews")}
        </div>

        <div class="card">
          <h2>Text Size</h2>
          <div class="row-main">
            <strong>Reading size</strong>
            <span>Choose the text size used throughout Fidunio.</span>
          </div>
          <div class="text-size-options" role="group" aria-label="Text size">
            <button class="text-size-btn ${state.settings.textSize==="normal"?"active":""}" data-text-size="normal">A</button>
            <button class="text-size-btn ${state.settings.textSize==="large"?"active":""}" data-text-size="large">A+</button>
            <button class="text-size-btn ${state.settings.textSize==="xlarge"?"active":""}" data-text-size="xlarge">A++</button>
          </div>
          <p class="small-note">A is standard, A+ is large, and A++ is extra large. The setting applies throughout Fidunio.</p>
        </div>

        <div class="card">
          <h2>Appearance</h2>
          <div class="row-main">
            <strong>Day / Night display</strong>
            <span>Auto follows the device or browser appearance and updates when it changes.</span>
          </div>
          <div class="appearance-options">
            <button class="appearance-btn ${state.settings.appearance==="auto"?"active":""}" data-appearance="auto">Auto</button>
            <button class="appearance-btn ${state.settings.appearance==="light"?"active":""}" data-appearance="light">Light</button>
            <button class="appearance-btn ${state.settings.appearance==="dark"?"active":""}" data-appearance="dark">Dark</button>
          </div>
        </div>

        <div class="card"><h2>Data</h2>${settingRow("Large attachments on Wi-Fi only","wifiAttachments")}</div>

        <div class="card">
          <h2>Firebase Account</h2>
          ${!isFirebaseConfigured() ? `
            <p class="small-note"><strong>Not configured.</strong> Complete the current Firebase setup instructions, then verify the existing configured <code>firebase-config.js</code>.</p>
          ` : firebaseUser ? `
            <p class="small-note"><strong>Signed in:</strong> ${esc(firebaseUser.email||"Firebase user")}</p>
            <label class="form-label">Your FIDUNIO ID</label>
            <div class="uid-box">${esc(firebaseUser.uid)}</div>
            <p class="small-note">Copy this ID to the other test device/account. The other account enters it under New Message → FIDUNIO ID.</p>
            <button class="secondary" id="copyUidBtn">Copy FIDUNIO ID</button>
            <button class="danger-btn" id="firebaseSignOutBtn">Sign Out</button>
          ` : `
            <p class="small-note">Use two different email accounts for the two-device test.</p>
            <label class="form-label" for="fbName">Display name</label>
            <input class="text-input" id="fbName" maxlength="50" placeholder="Your display name" />
            <label class="form-label" for="fbEmail">Email</label>
            <input class="text-input" id="fbEmail" type="email" autocomplete="username" placeholder="name@example.com" />
            <label class="form-label" for="fbPassword">Password</label>
            <input class="text-input" id="fbPassword" type="password" autocomplete="current-password" placeholder="At least 6 characters" />
            <div class="auth-actions">
              <button class="primary" id="firebaseSignInBtn">Sign In</button>
              <button class="secondary" id="firebaseCreateBtn">Create Test Account</button>
            </div>
          `}
          ${firebaseError?`<p class="warning-note">${esc(firebaseError)}</p>`:""}
          <p class="warning-note">FIDUNIO ${esc(FIDUNIO_VERSION)} adds contact key verification and key-change detection to the E2EE/device-identity foundation. This is still a test build; do not use sensitive content yet.</p>
        </div>

        ${firebaseUser ? `
        <div class="card">
          <h2>Device Identity</h2>
          ${deviceSecurityInfo ? `
            <div class="row-main">
              <strong>This installation</strong>
              <span>Device ID: ${esc(shortDeviceId(deviceSecurityInfo.deviceId))}</span>
            </div>
            <label class="form-label">Public-key fingerprint</label>
            <div class="uid-box">${esc(formatFingerprint(deviceSecurityInfo.fingerprint))}</div>
            <p class="small-note">The private E2EE key remains local and non-exportable. This fingerprint identifies this installation's public key.</p>
            <p class="small-note">${deviceRegistryStatus==="registered"
              ? `Registered devices for this account: ${myRegisteredDevices.length}`
              : `Device registry: ${esc(deviceRegistryStatus||"initializing…")}`}</p>
          ` : `<p class="small-note">Device identity is initializing…</p>`}
          <p class="warning-note">0.8.0 creates the multi-device identity foundation. Direct-message encryption still uses the compatible 0.7.x account key until per-device recipient fan-out is implemented and tested.</p>
        </div>
        ` : ""}

        <div class="card">
          <h2>Prototype connectivity</h2>
          <p class="small-note">Use airplane mode to test the persistent Outbox. Local demo chats simulate delivery; cloud chats send through Firestore after Firebase is configured and you are signed in.</p>
        </div>

        <div class="card">
          <h2>About</h2>
          <div class="about-box">
            <div class="about-brand"><img class="brand-logo small" src="fidunio-logo.png" alt="Fidunio logo"></div>
            <div class="brand">FIDUNIO</div>
            <div>Private Messaging</div>
            <div class="version">Version ${FIDUNIO_VERSION}</div>
            <div class="small-note">Functional Prototype</div>
          </div>
        </div>

        <div class="version-footer">Fidunio v${FIDUNIO_VERSION}</div>
      </section>
    </main>`;
  document.querySelector("#backBtn").onclick=()=>{state.route="messages";render()};
  document.querySelectorAll(".toggle").forEach(btn=>btn.onclick=()=>{
    const key=btn.dataset.key;state.settings[key]=!state.settings[key];persistSoon();renderSettings();
  });
  document.querySelectorAll(".appearance-btn").forEach(btn=>btn.onclick=()=>{
    state.settings.appearance=btn.dataset.appearance;
    render();
  });
  document.querySelectorAll(".text-size-btn").forEach(btn=>btn.onclick=()=>{
    state.settings.textSize=btn.dataset.textSize;
    render();
  });

  const timeoutSelect=document.querySelector("#lockTimeoutSelect");
  if(timeoutSelect)timeoutSelect.onchange=()=>{
    try{setLockTimeoutMs(Number(timeoutSelect.value));setLocalSecurityMessage("Inactivity lock updated.");renderSettings();}
    catch(err){setLocalSecurityMessage(err?.message||String(err),true);renderSettings();}
  };
  const setPinBtn=document.querySelector("#setLocalPinBtn");
  if(setPinBtn)setPinBtn.onclick=async()=>{
    const pin=document.querySelector("#newLocalPin").value,confirm=document.querySelector("#confirmLocalPin").value;
    if(pin!==confirm){setLocalSecurityMessage("PIN entries do not match.",true);renderSettings();return;}
    setPinBtn.disabled=true;setPinBtn.textContent="Setting…";
    try{await setLocalPin(pin);setLocalSecurityMessage("Local PIN is set on this installation.");renderSettings();}
    catch(err){setLocalSecurityMessage(err?.message||String(err),true);renderSettings();}
  };
  const changePinBtn=document.querySelector("#changeLocalPinBtn");
  if(changePinBtn)changePinBtn.onclick=async()=>{
    const current=document.querySelector("#currentLocalPin").value,next=document.querySelector("#replacementLocalPin").value,confirm=document.querySelector("#replacementLocalPin2").value;
    if(next!==confirm){setLocalSecurityMessage("New PIN entries do not match.",true);renderSettings();return;}
    changePinBtn.disabled=true;changePinBtn.textContent="Changing…";
    try{await changeLocalPin(current,next);setLocalSecurityMessage("Local PIN changed.");renderSettings();}
    catch(err){setLocalSecurityMessage(err?.message||String(err),true);renderSettings();}
  };
  const removePinBtn=document.querySelector("#removeLocalPinBtn");
  if(removePinBtn)removePinBtn.onclick=async()=>{
    const current=document.querySelector("#currentLocalPin").value;
    try{await removeLocalPin(current);setLocalSecurityMessage("Local PIN and device unlock removed.");renderSettings();}
    catch(err){setLocalSecurityMessage(err?.message||String(err),true);renderSettings();}
  };
  const enableBiometricBtn=document.querySelector("#enableBiometricBtn");
  if(enableBiometricBtn)enableBiometricBtn.onclick=async()=>{
    enableBiometricBtn.disabled=true;enableBiometricBtn.textContent="Waiting for device…";
    try{await enrollBiometric();setLocalSecurityMessage("Device unlock enabled.");renderSettings();}
    catch(err){setLocalSecurityMessage(err?.message||String(err),true);renderSettings();}
  };
  const disableBiometricBtn=document.querySelector("#disableBiometricBtn");
  if(disableBiometricBtn)disableBiometricBtn.onclick=()=>{disableBiometric();setLocalSecurityMessage("Device unlock disabled. PIN remains available.");renderSettings();};
  const lockNowBtn=document.querySelector("#lockNowBtn");
  if(lockNowBtn)lockNowBtn.onclick=()=>lockLocalApp("manual");

  const signInBtn=document.querySelector("#firebaseSignInBtn");
  if(signInBtn) signInBtn.onclick=async()=>{
    const email=document.querySelector("#fbEmail").value.trim();
    const password=document.querySelector("#fbPassword").value;
    firebaseError="";
    signInBtn.disabled=true;signInBtn.textContent="Signing in…";
    try{ await signInFidunio(email,password); }
    catch(err){firebaseError=err?.message||String(err);renderSettings();}
  };
  const createBtn=document.querySelector("#firebaseCreateBtn");
  if(createBtn) createBtn.onclick=async()=>{
    const displayName=document.querySelector("#fbName").value.trim();
    const email=document.querySelector("#fbEmail").value.trim();
    const password=document.querySelector("#fbPassword").value;
    if(!displayName) return alert("Enter a display name.");
    firebaseError="";
    createBtn.disabled=true;createBtn.textContent="Creating…";
    try{ await createFidunioAccount(email,password,displayName); }
    catch(err){firebaseError=err?.message||String(err);renderSettings();}
  };
  const signOutBtn=document.querySelector("#firebaseSignOutBtn");
  if(signOutBtn) signOutBtn.onclick=async()=>{await signOutFidunio();firebaseError="";renderSettings();};
  const copyBtn=document.querySelector("#copyUidBtn");
  if(copyBtn) copyBtn.onclick=async()=>{
    try{await navigator.clipboard.writeText(firebaseUser.uid);copyBtn.textContent="Copied";}catch{alert(firebaseUser.uid);}
  };
  mountSettingsLifecycle();
}
function settingRow(label,key){
  return `<div class="row"><span>${esc(label)}</span><button class="toggle ${state.settings[key]?"on":""}" data-key="${key}" aria-label="${esc(label)}"></button></div>`;
}


const appearanceMedia=window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
if(appearanceMedia){
  appearanceMedia.addEventListener?.("change",()=>{
    if(state.settings.appearance==="auto") render();
  });
}
if("serviceWorker" in navigator){
  window.addEventListener("load",()=>navigator.serviceWorker.register("./service-worker.js")
    .catch(err=>console.warn("Service worker registration failed",err)));
}
initApp();

