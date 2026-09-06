import {initFirebase,getFidunioAccessInfo,signOutFidunio} from "./firebase.js";
let handling=false;
function blocked(profile){
  if(!profile)return false;
  const status=profile.status||((profile.active===false)?"suspended":"active");
  if(profile.active===false||status==="suspended"||status==="deactivated")return true;
  const expires=profile.expiresAt?.toDate?.();
  return !!(expires&&expires.getTime()<=Date.now());
}
export async function startAccountGuard(){
  await initFirebase(async user=>{
    if(!user||handling)return;
    try{
      const info=await getFidunioAccessInfo();
      if(!blocked(info.profile))return;
      handling=true;
      const status=info.profile?.status||"suspended";
      sessionStorage.setItem("fidunioAccessNotice",status==="deactivated"?"This FIDUNIO account is deactivated.":status==="suspended"?"This FIDUNIO account is suspended.":"This FIDUNIO account has expired.");
      await signOutFidunio();
      location.reload();
    }catch(err){console.warn("FIDUNIO account guard could not verify account state",err);}
  });
}
