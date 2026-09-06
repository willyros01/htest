import { createAccountE2EEIdentityManager } from "./e2ee-account-identity-manager.js";
import { createFirebaseAccountE2EEIdentityStore } from "./e2ee-account-firebase-adapter.js";
import { createAccountE2EEAuthLifecycle } from "./e2ee-account-lifecycle.js";
import { createAccountE2EERecoveryClient } from "./e2ee-account-recovery-client.js";
import { enrollCloudE2EERecovery,startCloudE2EERecovery,completeCloudE2EERecovery,changeFidunioPassword } from "./firebase.js";

const recoveryClient=createAccountE2EERecoveryClient({enroll:enrollCloudE2EERecovery,start:startCloudE2EERecovery,complete:completeCloudE2EERecovery});
const identityStore=createFirebaseAccountE2EEIdentityStore();
const manager=createAccountE2EEIdentityManager({identityStore,recoveryService:recoveryClient});
const lifecycle=createAccountE2EEAuthLifecycle({manager});

export function bindAuthenticatedAccountE2EE(uid){return lifecycle.bindAuthenticatedUid(uid);}
export function resetAccountE2EEForSignOut(){lifecycle.resetForSignOut();}
export function getAccountE2EELifecycleState(){return lifecycle.getLifecycleState();}
export function getAccountE2EERuntimeIdentity(){return manager.getRuntimeIdentity();}
export function enrollAccountE2EE({uid,password,pin}){return manager.enroll({uid,password,pin});}
export function unlockAccountE2EE({uid,password,pin}){return manager.unlock({uid,password,pin});}
export async function recoverAccountE2EE({uid,newPassword,pin}){
  const recovered=await recoveryClient.recoverKey({pin});
  try{return await manager.recover({uid,recoveryUnlockKey:recovered.recoveryUnlockKey,newPassword,pin});}
  finally{recovered.recoveryUnlockKey.fill(0);}
}
export async function changeAccountPasswordWithE2EE({uid,currentPassword,newPassword,pin}){
  const state=manager.getState();
  if(state.state==="EMPTY")return changeFidunioPassword(currentPassword,newPassword);
  if(state.state!=="READY")await manager.unlock({uid,password:currentPassword,pin});
  await manager.rewrap({uid,oldPassword:currentPassword,newPassword,pin});
  try{return await changeFidunioPassword(currentPassword,newPassword);}
  catch(error){
    try{await manager.rewrap({uid,oldPassword:newPassword,newPassword:currentPassword,pin});}
    catch(rollbackError){const e=new Error("Firebase password change failed and the E2EE wrapper rollback also failed. Use account recovery before messaging.");e.cause={error,rollbackError};throw e;}
    throw error;
  }
}
