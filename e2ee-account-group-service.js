import {createAccountGroupE2EERuntime} from "./e2ee-account-group-runtime.js";
import {createFirebaseAccountGroupE2EETransport} from "./e2ee-account-group-firebase-adapter.js";
import {getAccountE2EERuntimeIdentity} from "./e2ee-account-runtime.js";

const runtime=createAccountGroupE2EERuntime({
  identityProvider:getAccountE2EERuntimeIdentity,
  transport:createFirebaseAccountGroupE2EETransport()
});

export function ensureAccountGroupEpoch(groupId){return runtime.ensureEpoch(groupId);}
export function rotateAccountGroupEpoch(groupId){return runtime.rotateEpoch(groupId);}
export function sendAccountGroupMessage({groupId,messageId,text}){return runtime.send({groupId,messageId,text});}
export function decryptAccountGroupMessage({groupId,messageId,row}){return runtime.decrypt({groupId,messageId,row});}
export function revalidateQueuedAccountGroupMessage({groupId,queuedEpoch}){return runtime.revalidateQueued({groupId,queuedEpoch});}
export function resetAccountGroupE2EEForSignOut(){runtime.resetForSignOut();}
