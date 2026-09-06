// Deterministic projection of Firestore-authoritative group rows into the
// app's local encrypted history cache. This module owns no Firebase, crypto,
// IndexedDB, DOM, or lifecycle work.

const PENDING_STATES=new Set(["queued","sending","failed"]);

export function mergeAccountGroupRows(existingRows,remoteRows){
  const existing=Array.isArray(existingRows)?existingRows:[];
  const remote=Array.isArray(remoteRows)?remoteRows:[];
  const remoteIds=new Set(remote.map(row=>String(row.id)));
  const pending=existing.filter(row=>
    row?.mine&&PENDING_STATES.has(row.state)&&!remoteIds.has(String(row.id))
  );
  return [...remote,...pending];
}

export function projectAccountGroupConversation(conversation,existingRows,remoteRows){
  if(!conversation?.id)throw new Error("Group conversation identity is required.");
  const messages=mergeAccountGroupRows(existingRows,remoteRows);
  const last=messages.at(-1)||null;
  return{
    messages,
    conversation:{
      ...conversation,
      type:"group",
      cloudGroup:true,
      preview:last?.text??conversation.preview??"Encrypted group",
      time:last?.time??conversation.time??""
    }
  };
}
