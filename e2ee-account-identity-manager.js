import {
  generateAccountIdentity,
  wrapPrivateKeyNormal,
  unwrapPrivateKeyNormal,
  generateRecoveryUnlockKey,
  wrapPrivateKeyRecovery,
  unwrapPrivateKeyRecovery,
  exportPrivatePkcs8,
  randomKeyId,
  validateSixDigitPin
} from "./e2ee-account-crypto.js";

const STATES = Object.freeze({ EMPTY:"EMPTY", ENROLLING:"ENROLLING", LOCKED:"LOCKED", UNLOCKING:"UNLOCKING", READY:"READY", REWRAPPING:"REWRAPPING", RECOVERING:"RECOVERING", ERROR:"ERROR" });

function requireFn(obj,name){ if(!obj || typeof obj[name]!=="function") throw new Error(`Missing identity adapter method: ${name}`); }
function requireUid(uid){ const value=String(uid||""); if(!value) throw new Error("Authenticated UID is required."); return value; }
function clonePublicJwk(jwk){ return { kty:jwk.kty, crv:jwk.crv, x:jwk.x, y:jwk.y }; }
function privateDoc({keyId,normalWrapper,recoveryWrapper,revision=1}){ return {schemaVersion:1,identityVersion:1,keyId,keyAlgorithm:"ECDH-P256",normalWrapper,recoveryWrapper,state:"ACTIVE",revision}; }
function publicDoc({uid,keyId,publicJwk}){ return {uid,schemaVersion:1,identityVersion:1,keyId,keyAlgorithm:"ECDH-P256",publicJwk:clonePublicJwk(publicJwk),state:"ACTIVE"}; }

export function createAccountE2EEIdentityManager({identityStore,recoveryService,onStateChange}={}){
  ["readIdentity","createIdentity","updateNormalWrapper"].forEach(n=>requireFn(identityStore,n));
  requireFn(recoveryService,"protectRecoveryKey");
  let state=STATES.EMPTY, activeUid=null, runtime=null, tail=Promise.resolve(), generation=0;

  function publishState(next,detail=null){ state=next; onStateChange?.({state,uid:activeUid,keyId:runtime?.keyId||null,revision:runtime?.revision||null,detail}); }
  function serialize(operation){ const run=tail.then(operation,operation); tail=run.catch(()=>{}); return run; }
  function assertAccount(uid){ const clean=requireUid(uid); if(activeUid&&activeUid!==clean) throw new Error("Identity manager is bound to another account. Call resetForSignOut first."); activeUid=clean; return clean; }
  function captureGeneration(){ return generation; }
  function assertGeneration(g){ if(g!==generation) { const e=new Error("E2EE operation was invalidated by sign-out."); e.code="OPERATION_INVALIDATED"; throw e; } }
  function publishFailure(g,next,detail){ if(g===generation){ runtime=null; publishState(next,detail); } }

  async function load(uid){ return serialize(async()=>{ const g=captureGeneration(); const clean=assertAccount(uid); const doc=await identityStore.readIdentity(clean); assertGeneration(g); runtime=null; publishState(doc?STATES.LOCKED:STATES.EMPTY); return doc; }); }

  async function enroll({uid,password,pin}){ return serialize(async()=>{
    const g=captureGeneration(), clean=assertAccount(uid); validateSixDigitPin(pin);
    const existing=await identityStore.readIdentity(clean); assertGeneration(g);
    if(existing){ publishState(STATES.LOCKED); throw new Error("Durable E2EE identity already exists; replacement is forbidden."); }
    publishState(STATES.ENROLLING); let generated=null,ruk=null;
    try{
      generated=await generateAccountIdentity(); assertGeneration(g);
      const keyId=randomKeyId();
      const normalWrapper=await wrapPrivateKeyNormal({privatePkcs8:generated.privatePkcs8,password,pin,uid:clean,keyId}); assertGeneration(g);
      ruk=generateRecoveryUnlockKey();
      const recoveryWrapperLocal=await wrapPrivateKeyRecovery({privatePkcs8:generated.privatePkcs8,recoveryUnlockKey:ruk,uid:clean,keyId}); assertGeneration(g);
      const protectedRecovery=await recoveryService.protectRecoveryKey({uid:clean,keyId,pin,recoveryUnlockKey:ruk}); assertGeneration(g);
      const recoveryWrapper={...recoveryWrapperLocal,...protectedRecovery};
      assertGeneration(g);
      const created=await identityStore.createIdentity({uid:clean,privateIdentity:privateDoc({keyId,normalWrapper,recoveryWrapper}),publicIdentity:publicDoc({uid:clean,keyId,publicJwk:generated.publicJwk})});
      assertGeneration(g);
      const privateKey=await unwrapPrivateKeyNormal({wrapper:normalWrapper,password,pin,uid:clean,keyId}); assertGeneration(g);
      runtime={uid:clean,keyId,revision:created?.revision||1,privateKey}; publishState(STATES.READY);
      return {keyId,revision:runtime.revision,publicJwk:clonePublicJwk(generated.publicJwk)};
    }catch(error){ publishFailure(g,STATES.ERROR,"ENROLL_FAILED"); throw error; }
    finally{ generated=null; ruk=null; }
  }); }

  async function unlock({uid,password,pin}){ return serialize(async()=>{
    const g=captureGeneration(), clean=assertAccount(uid); validateSixDigitPin(pin);
    const doc=await identityStore.readIdentity(clean); assertGeneration(g);
    if(!doc){ publishState(STATES.EMPTY); throw new Error("Durable E2EE identity does not exist."); }
    publishState(STATES.UNLOCKING);
    try{ const privateKey=await unwrapPrivateKeyNormal({wrapper:doc.normalWrapper,password,pin,uid:clean,keyId:doc.keyId}); assertGeneration(g); runtime={uid:clean,keyId:doc.keyId,revision:doc.revision,privateKey}; publishState(STATES.READY); return {...runtime}; }
    catch(error){ publishFailure(g,STATES.LOCKED,"UNLOCK_FAILED"); throw error; }
  }); }

  async function rewrap({uid,oldPassword,oldPin,newPassword,newPin}){ return serialize(async()=>{
    const g=captureGeneration(), clean=assertAccount(uid); validateSixDigitPin(oldPin); validateSixDigitPin(newPin);
    const doc=await identityStore.readIdentity(clean); assertGeneration(g); if(!doc) throw new Error("Durable E2EE identity does not exist."); publishState(STATES.REWRAPPING);
    try{
      const oldKey=await unwrapPrivateKeyNormal({wrapper:doc.normalWrapper,password:oldPassword,pin:oldPin,uid:clean,keyId:doc.keyId,extractable:true}); assertGeneration(g);
      const pkcs8=await exportPrivatePkcs8(oldKey); assertGeneration(g);
      const candidate=await wrapPrivateKeyNormal({privatePkcs8:pkcs8,password:newPassword,pin:newPin,uid:clean,keyId:doc.keyId}); assertGeneration(g);
      const verify=await unwrapPrivateKeyNormal({wrapper:candidate,password:newPassword,pin:newPin,uid:clean,keyId:doc.keyId}); assertGeneration(g);
      const updated=await identityStore.updateNormalWrapper({uid:clean,keyId:doc.keyId,expectedRevision:doc.revision,normalWrapper:candidate}); assertGeneration(g);
      runtime={uid:clean,keyId:doc.keyId,revision:updated?.revision||doc.revision+1,privateKey:verify}; publishState(STATES.READY); return {keyId:doc.keyId,revision:runtime.revision};
    }catch(error){ publishFailure(g,STATES.LOCKED,"REWRAP_FAILED"); throw error; }
  }); }

  async function recover({uid,recoveryUnlockKey,newPassword,pin}){ return serialize(async()=>{
    const g=captureGeneration(), clean=assertAccount(uid); validateSixDigitPin(pin);
    const doc=await identityStore.readIdentity(clean); assertGeneration(g); if(!doc) throw new Error("Durable E2EE identity does not exist."); publishState(STATES.RECOVERING);
    try{
      const recoveredKey=await unwrapPrivateKeyRecovery({wrapper:doc.recoveryWrapper,recoveryUnlockKey,uid:clean,keyId:doc.keyId,extractable:true}); assertGeneration(g);
      const pkcs8=await exportPrivatePkcs8(recoveredKey); assertGeneration(g);
      const candidate=await wrapPrivateKeyNormal({privatePkcs8:pkcs8,password:newPassword,pin,uid:clean,keyId:doc.keyId}); assertGeneration(g);
      const verify=await unwrapPrivateKeyNormal({wrapper:candidate,password:newPassword,pin,uid:clean,keyId:doc.keyId}); assertGeneration(g);
      const updated=await identityStore.updateNormalWrapper({uid:clean,keyId:doc.keyId,expectedRevision:doc.revision,normalWrapper:candidate}); assertGeneration(g);
      runtime={uid:clean,keyId:doc.keyId,revision:updated?.revision||doc.revision+1,privateKey:verify}; publishState(STATES.READY); return {keyId:doc.keyId,revision:runtime.revision};
    }catch(error){ publishFailure(g,STATES.LOCKED,"RECOVERY_FAILED"); throw error; }
  }); }

  function getRuntimeIdentity(){ return runtime?{...runtime}:null; }
  function getState(){ return {state,uid:activeUid,keyId:runtime?.keyId||null,revision:runtime?.revision||null}; }
  function resetForSignOut(){ generation+=1; activeUid=null; runtime=null; publishState(STATES.EMPTY); }
  return Object.freeze({load,enroll,unlock,rewrap,recover,getRuntimeIdentity,getState,resetForSignOut,STATES});
}
