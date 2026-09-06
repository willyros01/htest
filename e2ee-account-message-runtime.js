import { createAccountDirectMessageService } from "./e2ee-account-message-service.js";
import { getAccountE2EERuntimeIdentity } from "./e2ee-account-runtime.js";
import { getCloudAccountE2EEPublicKey } from "./firebase.js";
const service=createAccountDirectMessageService({getRuntimeIdentity:getAccountE2EERuntimeIdentity,getPublicIdentity:getCloudAccountE2EEPublicKey});
export function prepareAccountDirectMessage(args){return service.prepareOutgoing(args);}
export function decryptAccountDirectMessage(args){return service.decryptIncoming(args);}
