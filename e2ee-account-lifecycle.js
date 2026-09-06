// FIDUNIO account-E2EE auth lifecycle coordinator.
// Owns only auth<->identity-manager binding. It does not mutate UI or initialize Firebase.

function requireManager(manager){
  for(const name of ["load","resetForSignOut","getState"]){
    if(!manager||typeof manager[name]!=="function")throw new Error(`Missing account E2EE manager method: ${name}`);
  }
  return manager;
}
function cleanUid(uid){const value=String(uid||"").trim();if(!value)throw new Error("Authenticated UID is required.");return value;}

export function createAccountE2EEAuthLifecycle({manager}={}){
  const owner=requireManager(manager);
  let epoch=0,boundUid=null,inFlight=null;

  function resetForSignOut(){
    epoch+=1;
    boundUid=null;
    inFlight=null;
    owner.resetForSignOut();
  }

  function bindAuthenticatedUid(uid){
    const clean=cleanUid(uid);
    if(boundUid===clean&&inFlight)return inFlight;
    if(boundUid&&boundUid!==clean)resetForSignOut();
    boundUid=clean;
    const token=++epoch;
    let loadResult;
    try{loadResult=owner.load(clean);}catch(error){loadResult=Promise.reject(error);}
    const promise=Promise.resolve(loadResult).then(doc=>{
      if(token!==epoch||boundUid!==clean)return{uid:clean,stale:true,hasIdentity:false,state:owner.getState()};
      return{uid:clean,stale:false,hasIdentity:!!doc,state:owner.getState()};
    }).catch(error=>{
      if(error?.code==="OPERATION_INVALIDATED"||token!==epoch)return{uid:clean,stale:true,hasIdentity:false,state:owner.getState()};
      throw error;
    }).finally(()=>{if(token===epoch&&inFlight===promise)inFlight=null;});
    inFlight=promise;
    return promise;
  }

  function getLifecycleState(){return{uid:boundUid,epoch,inFlight:!!inFlight,manager:owner.getState()};}
  return Object.freeze({bindAuthenticatedUid,resetForSignOut,getLifecycleState});
}
