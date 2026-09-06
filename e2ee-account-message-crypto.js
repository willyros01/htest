// FIDUNIO account-authoritative direct-message cryptography.
// This module owns cryptographic transformation only. It does not initialize Firebase,
// mutate Firestore/UI/local storage, or choose account lifecycle state.

export const ACCOUNT_DM_E2EE_VERSION=3;
export const ACCOUNT_DM_KDF_VERSION=1;

const encoder=new TextEncoder();
const decoder=new TextDecoder();
const BASE64URL_RE=/^[A-Za-z0-9_-]+$/;

function codedError(code,message,cause){
  const error=new Error(message);
  error.code=code;
  if(cause!==undefined)error.cause=cause;
  return error;
}
function requiredString(value,label){
  const clean=String(value??"");
  if(!clean)throw codedError("INVALID_INPUT",`${label} is required.`);
  return clean;
}
function exactPublicJwk(jwk){
  if(!jwk||typeof jwk!=="object"||Array.isArray(jwk))throw codedError("INVALID_INPUT","Peer public key is required.");
  const keys=Object.keys(jwk).sort();
  const expected=["crv","kty","x","y"];
  if(keys.length!==expected.length||keys.some((key,index)=>key!==expected[index]))throw codedError("FORMAT_ERROR","Peer public JWK must contain exactly kty, crv, x and y.");
  if(jwk.kty!=="EC"||jwk.crv!=="P-256"||typeof jwk.x!=="string"||!jwk.x||typeof jwk.y!=="string"||!jwk.y)throw codedError("FORMAT_ERROR","Peer public JWK is not an ECDH P-256 public key.");
  return{kty:"EC",crv:"P-256",x:jwk.x,y:jwk.y};
}
function requirePrivateKey(key){
  if(!key||key.type!=="private"||key.algorithm?.name!=="ECDH"||key.algorithm?.namedCurve!=="P-256"||!key.usages?.includes?.("deriveBits"))throw codedError("INVALID_INPUT","Runtime account E2EE private key is unavailable.");
  return key;
}
function bytesToBase64url(value){
  const bytes=value instanceof Uint8Array?value:new Uint8Array(value);
  let raw="";
  for(let i=0;i<bytes.length;i+=0x8000)raw+=String.fromCharCode(...bytes.subarray(i,i+0x8000));
  return btoa(raw).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
}
function base64urlToBytes(value,label){
  const text=requiredString(value,label);
  if(!BASE64URL_RE.test(text))throw codedError("FORMAT_ERROR",`${label} is malformed base64url.`);
  const pad="=".repeat((4-text.length%4)%4);
  let raw;
  try{raw=atob(text.replace(/-/g,"+").replace(/_/g,"/")+pad);}catch(error){throw codedError("FORMAT_ERROR",`${label} is malformed base64url.`,error);}
  const out=new Uint8Array(raw.length);
  for(let i=0;i<raw.length;i++)out[i]=raw.charCodeAt(i);
  if(bytesToBase64url(out)!==text)throw codedError("FORMAT_ERROR",`${label} is not canonical base64url.`);
  return out;
}
function accountPair(localUid,localKeyId,peerUid,peerKeyId){
  const a=[requiredString(localUid,"Local UID"),requiredString(localKeyId,"Local keyId")];
  const b=[requiredString(peerUid,"Peer UID"),requiredString(peerKeyId,"Peer keyId")];
  if(a[0]===b[0])throw codedError("INVALID_INPUT","Direct-message peers must be different accounts.");
  return[a,b].sort((x,y)=>x[0].localeCompare(y[0])||x[1].localeCompare(y[1]));
}
async function deriveDirectMessageKey({localPrivateKey,localUid,localKeyId,peerPublicJwk,peerUid,peerKeyId,conversationId}){
  if(!globalThis.crypto?.subtle)throw codedError("UNSUPPORTED_CRYPTO","Web Crypto is unavailable.");
  const privateKey=requirePrivateKey(localPrivateKey);
  const conversation=requiredString(conversationId,"Conversation ID");
  const pair=accountPair(localUid,localKeyId,peerUid,peerKeyId);
  let peer;
  try{peer=await crypto.subtle.importKey("jwk",exactPublicJwk(peerPublicJwk),{name:"ECDH",namedCurve:"P-256"},false,[]);}catch(error){if(error?.code)throw error;throw codedError("FORMAT_ERROR","Peer public key could not be imported.",error);}
  let shared;
  try{shared=await crypto.subtle.deriveBits({name:"ECDH",public:peer},privateKey,256);}catch(error){throw codedError("INVALID_INPUT","Account E2EE key agreement failed.",error);}
  const base=await crypto.subtle.importKey("raw",shared,"HKDF",false,["deriveKey"]);
  const saltContext=encoder.encode(JSON.stringify(["FIDUNIO-DM-HKDF-SALT",ACCOUNT_DM_KDF_VERSION,conversation,pair]));
  const salt=await crypto.subtle.digest("SHA-256",saltContext);
  const info=encoder.encode(JSON.stringify(["FIDUNIO-DM-HKDF-INFO",ACCOUNT_DM_KDF_VERSION,conversation]));
  return crypto.subtle.deriveKey({name:"HKDF",hash:"SHA-256",salt,info},base,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
}
function messageAad({conversationId,messageId,senderUid,recipientUid,senderKeyId,recipientKeyId}){
  return encoder.encode(JSON.stringify([
    "FIDUNIO-DM-MESSAGE",
    ACCOUNT_DM_E2EE_VERSION,
    requiredString(conversationId,"Conversation ID"),
    requiredString(messageId,"Message ID"),
    requiredString(senderUid,"Sender UID"),
    requiredString(recipientUid,"Recipient UID"),
    requiredString(senderKeyId,"Sender keyId"),
    requiredString(recipientKeyId,"Recipient keyId")
  ]));
}
function validateEnvelope(row,{senderKeyId,recipientKeyId}){
  if(!row||typeof row!=="object"||Array.isArray(row))throw codedError("FORMAT_ERROR","Encrypted message envelope is required.");
  const expected=["ciphertext","e2ee","iv","kdfVersion","recipientKeyId","senderKeyId"].sort();
  const keys=Object.keys(row).sort();
  if(keys.length!==expected.length||keys.some((key,index)=>key!==expected[index]))throw codedError("FORMAT_ERROR","Account E2EE message envelope has unexpected fields.");
  if(row.e2ee!==ACCOUNT_DM_E2EE_VERSION||row.kdfVersion!==ACCOUNT_DM_KDF_VERSION)throw codedError("FORMAT_ERROR","Unsupported account E2EE message version.");
  if(row.senderKeyId!==senderKeyId||row.recipientKeyId!==recipientKeyId)throw codedError("FORMAT_ERROR","Account E2EE message key identity does not match the expected accounts.");
  return{ciphertext:base64urlToBytes(row.ciphertext,"Ciphertext"),iv:base64urlToBytes(row.iv,"IV")};
}

export async function encryptAccountDirectMessage({text,conversationId,messageId,senderUid,recipientUid,senderKeyId,recipientKeyId,senderPrivateKey,recipientPublicJwk}){
  const plaintext=String(text??"");
  const key=await deriveDirectMessageKey({localPrivateKey:senderPrivateKey,localUid:senderUid,localKeyId:senderKeyId,peerPublicJwk:recipientPublicJwk,peerUid:recipientUid,peerKeyId:recipientKeyId,conversationId});
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const aad=messageAad({conversationId,messageId,senderUid,recipientUid,senderKeyId,recipientKeyId});
  let ciphertext;
  try{ciphertext=await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:aad,tagLength:128},key,encoder.encode(plaintext));}catch(error){throw codedError("ENCRYPT_FAILED","Account E2EE message encryption failed.",error);}
  return Object.freeze({
    e2ee:ACCOUNT_DM_E2EE_VERSION,
    kdfVersion:ACCOUNT_DM_KDF_VERSION,
    senderKeyId,
    recipientKeyId,
    ciphertext:bytesToBase64url(ciphertext),
    iv:bytesToBase64url(iv)
  });
}

export async function decryptAccountDirectMessage({envelope,conversationId,messageId,senderUid,recipientUid,senderKeyId,recipientKeyId,recipientPrivateKey,senderPublicJwk}){
  const parsed=validateEnvelope(envelope,{senderKeyId,recipientKeyId});
  if(parsed.iv.length!==12)throw codedError("FORMAT_ERROR","Account E2EE message IV must be exactly 12 bytes.");
  const key=await deriveDirectMessageKey({localPrivateKey:recipientPrivateKey,localUid:recipientUid,localKeyId:recipientKeyId,peerPublicJwk:senderPublicJwk,peerUid:senderUid,peerKeyId:senderKeyId,conversationId});
  const aad=messageAad({conversationId,messageId,senderUid,recipientUid,senderKeyId,recipientKeyId});
  try{
    const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:parsed.iv,additionalData:aad,tagLength:128},key,parsed.ciphertext);
    return decoder.decode(plain);
  }catch(error){throw codedError("DECRYPT_FAILED","Account E2EE message authentication failed.",error);}
}
