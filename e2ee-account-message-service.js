import {encryptAccountDirectMessage,decryptAccountDirectMessage} from "./e2ee-account-message-crypto.js";

function codedError(code,message,cause){
  const error=new Error(message);
  error.code=code;
  if(cause!==undefined)error.cause=cause;
  return error;
}
function requireFn(value,name){if(typeof value!=="function")throw new Error(`Missing account message service dependency: ${name}`);return value;}
function required(value,label){const text=String(value??"").trim();if(!text)throw codedError("INVALID_INPUT",`${label} is required.`);return text;}
function exactPublicJwk(jwk){
  if(!jwk||typeof jwk!=="object"||Array.isArray(jwk))throw codedError("PEER_IDENTITY_INVALID","Peer account public key is missing.");
  const keys=Object.keys(jwk).sort(),expected=["crv","kty","x","y"];
  if(keys.length!==expected.length||keys.some((key,index)=>key!==expected[index])||jwk.kty!=="EC"||jwk.crv!=="P-256"||!jwk.x||!jwk.y)throw codedError("PEER_IDENTITY_INVALID","Peer account public key is not the exact ECDH P-256 format.");
  return{kty:"EC",crv:"P-256",x:jwk.x,y:jwk.y};
}
function validatePeerIdentity(record,expectedUid){
  if(!record||typeof record!=="object")throw codedError("PEER_IDENTITY_UNAVAILABLE","Peer account E2EE identity is unavailable.");
  if(record.uid!==expectedUid||record.schemaVersion!==1||record.identityVersion!==1||record.keyAlgorithm!=="ECDH-P256"||record.state!=="ACTIVE")throw codedError("PEER_IDENTITY_INVALID","Peer account E2EE identity metadata is invalid.");
  const keyId=required(record.keyId,"Peer keyId");
  if(keyId.length<16||keyId.length>128)throw codedError("PEER_IDENTITY_INVALID","Peer account keyId is invalid.");
  return{uid:expectedUid,keyId,publicJwk:exactPublicJwk(record.publicJwk)};
}
function validateRuntimeIdentity(identity,uid){
  if(!identity||identity.uid!==uid||!identity.privateKey||!identity.keyId)throw codedError("ACCOUNT_E2EE_NOT_READY","Account E2EE identity is not unlocked for this account.");
  const keyId=required(identity.keyId,"Account keyId");
  if(keyId.length<16||keyId.length>128)throw codedError("ACCOUNT_E2EE_NOT_READY","Account E2EE runtime identity is invalid.");
  return{uid,keyId,privateKey:identity.privateKey};
}
function envelopeFromRow(row){
  return{
    e2ee:row?.e2ee,
    kdfVersion:row?.kdfVersion,
    senderKeyId:row?.senderKeyId,
    recipientKeyId:row?.recipientKeyId,
    ciphertext:row?.ciphertext,
    iv:row?.iv
  };
}

export function createAccountDirectMessageService({getRuntimeIdentity,getPublicIdentity,encrypt=encryptAccountDirectMessage,decrypt=decryptAccountDirectMessage}={}){
  const runtimeReader=requireFn(getRuntimeIdentity,"getRuntimeIdentity");
  const publicReader=requireFn(getPublicIdentity,"getPublicIdentity");
  const encryptFn=requireFn(encrypt,"encrypt");
  const decryptFn=requireFn(decrypt,"decrypt");

  async function resolveContext(uid,peerUid){
    const me=required(uid,"Authenticated UID"),peer=required(peerUid,"Peer UID");
    if(me===peer)throw codedError("INVALID_INPUT","Direct-message peer must be another account.");
    const runtime=validateRuntimeIdentity(runtimeReader(),me);
    let peerRecord;
    try{peerRecord=await publicReader(peer);}catch(error){throw codedError("PEER_IDENTITY_UNAVAILABLE","Peer account E2EE identity could not be loaded.",error);}
    return{runtime,peer:validatePeerIdentity(peerRecord,peer)};
  }

  async function prepareOutgoing({uid,peerUid,conversationId,messageId,text}){
    const {runtime,peer}=await resolveContext(uid,peerUid);
    const envelope=await encryptFn({
      text:String(text??""),
      conversationId:required(conversationId,"Conversation ID"),
      messageId:required(messageId,"Message ID"),
      senderUid:runtime.uid,
      recipientUid:peer.uid,
      senderKeyId:runtime.keyId,
      recipientKeyId:peer.keyId,
      senderPrivateKey:runtime.privateKey,
      recipientPublicJwk:peer.publicJwk
    });
    return Object.freeze({...envelope});
  }

  async function decryptIncoming({uid,peerUid,conversationId,messageId,row}){
    const {runtime,peer}=await resolveContext(uid,peerUid);
    if(row?.e2ee!==3)throw codedError("UNSUPPORTED_MESSAGE_FORMAT","Message is not account-authoritative E2EE v3.");
    return decryptFn({
      envelope:envelopeFromRow(row),
      conversationId:required(conversationId,"Conversation ID"),
      messageId:required(messageId,"Message ID"),
      senderUid:peer.uid,
      recipientUid:runtime.uid,
      senderKeyId:peer.keyId,
      recipientKeyId:runtime.keyId,
      recipientPrivateKey:runtime.privateKey,
      senderPublicJwk:peer.publicJwk
    });
  }

  return Object.freeze({prepareOutgoing,decryptIncoming});
}
