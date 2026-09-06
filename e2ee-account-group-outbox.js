import {ensureAccountGroupEpoch,sendAccountGroupMessage,revalidateQueuedAccountGroupMessage} from "./e2ee-account-group-service.js";

// Group Outbox orchestration owner. Local persistence stays injected so this
// module never owns IndexedDB or Firebase. A queued plaintext exists only
// inside the caller's encrypted local Outbox record.
let tail=Promise.resolve();
function serial(task){const run=tail.then(task,task);tail=run.catch(()=>{});return run;}

export async function prepareQueuedAccountGroupMessage({groupId,messageId,text}){
  if(!groupId||!messageId)throw new Error("Group and message IDs are required.");
  if(!String(text||"").trim())throw new Error("Group message text is required.");
  const epoch=await ensureAccountGroupEpoch(String(groupId));
  return{kind:"group-e2ee-v1",groupId:String(groupId),messageId:String(messageId),text:String(text),expectedKeyEpoch:Number(epoch.keyEpoch)};
}

export function flushQueuedAccountGroupMessage(payload){
  return serial(async()=>{
    if(payload?.kind!=="group-e2ee-v1")throw new Error("Unsupported group Outbox payload.");
    const check=await revalidateQueuedAccountGroupMessage({groupId:payload.groupId,queuedEpoch:payload.expectedKeyEpoch});
    // Membership/epoch changes invalidate the old expectation. Runtime send
    // always encrypts against the current epoch, so stale queued plaintext is
    // re-encrypted rather than replaying obsolete ciphertext.
    const result=await sendAccountGroupMessage({groupId:payload.groupId,messageId:payload.messageId,text:payload.text});
    return{...result,reEncryptedForCurrentEpoch:!check.current,previousKeyEpoch:payload.expectedKeyEpoch};
  });
}

export function resetAccountGroupOutboxQueue(){tail=Promise.resolve();}
