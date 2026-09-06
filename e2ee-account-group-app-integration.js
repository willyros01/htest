import {prepareGroupSend,flushGroupSend,openGroupConversation,closeGroupConversation,isGroupOutboxPayload,resetGroupMessagingForSignOut} from "./e2ee-account-group-app-controller.js";

// Bounded bridge between the legacy app shell and the account-authoritative
// group messaging owners. This module owns no Firebase, crypto, IndexedDB or
// DOM. app.js supplies only its existing encrypted Outbox/state callbacks.
let activeGroupId=null;

export async function queueGroupTextForApp({groupId,messageId,text,time,persistEncryptedOutbox}){
  if(typeof persistEncryptedOutbox!=="function")throw new Error("Encrypted Outbox persistence callback is required.");
  const queued=await prepareGroupSend({groupId,messageId,text});
  const payload={...queued,time:String(time||"")};
  // The plaintext is persisted only through app.js's AES-GCM encrypted Outbox.
  await persistEncryptedOutbox(payload);
  return payload;
}

export async function flushGroupOutboxForApp(payload,{removeEncryptedOutbox}={}){
  if(!isGroupOutboxPayload(payload))throw new Error("Unsupported group Outbox payload.");
  if(typeof removeEncryptedOutbox!=="function")throw new Error("Outbox removal callback is required.");
  const result=await flushGroupSend(payload);
  // Removal is deliberately after the controller confirms the Firestore write.
  await removeEncryptedOutbox(payload.messageId);
  return result;
}

export function openGroupForApp(groupId,{onRows,onError,isOpen}={}){
  const id=String(groupId||"");
  if(!id)throw new Error("Group ID is required.");
  closeGroupForApp();
  activeGroupId=id;
  return openGroupConversation(id,{onRows,onError,isOpen});
}

export function closeGroupForApp(){
  if(activeGroupId!==null)closeGroupConversation();
  activeGroupId=null;
}

export function resetGroupAppIntegrationForSignOut(){
  closeGroupForApp();
  resetGroupMessagingForSignOut();
}
