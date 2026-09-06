import {getAccountE2EERuntimeIdentity} from "./e2ee-account-runtime.js";
import {decryptAccountGroupMessage} from "./e2ee-account-group-service.js";
import {readCloudGroupAuthority,subscribeCloudGroupMessages,updateCloudGroupReceipt,subscribeCloudGroupReceipts} from "./firebase.js";

// Read-side group messaging owner. app.js supplies a bounded projection callback;
// this module owns Firebase group message/receipt subscriptions and decryption.
const streams=new Map();

function needIdentity(){const id=getAccountE2EERuntimeIdentity();if(!id?.uid||!id?.keyId||!id?.privateKey)throw new Error("Account E2EE identity must be unlocked before group messaging.");return id;}
function aggregateReceipt(row,receipts,myUid,memberUids){
  if(row.senderUid!==myUid)return row.state||"sent";
  const recipients=(memberUids||[]).filter(uid=>uid!==myUid);
  if(!recipients.length)return row.state||"sent";
  const states=new Map((receipts||[]).map(r=>[r.uid,r.state]));
  if(recipients.every(uid=>states.get(uid)==="read"))return "read";
  if(recipients.every(uid=>["delivered","read"].includes(states.get(uid))))return "delivered";
  return "sent";
}

export function subscribeAccountGroupConversation(groupId,{onRows,onError,isOpen=()=>false}={}){
  const id=needIdentity(),key=String(groupId);stopAccountGroupConversation(key);
  const receiptStops=new Map(),receiptRows=new Map();
  let rawRows=[],memberUids=[],closed=false,delivery=Promise.resolve();
  const emit=async()=>{
    const out=[];
    for(const row of rawRows){
      let text="[Encrypted group message — account encryption unavailable]";
      try{text=await decryptAccountGroupMessage({groupId:key,messageId:row.id,row});}catch(err){onError?.(err);}
      out.push({id:row.id,mine:row.senderUid===id.uid,senderUid:row.senderUid,text,time:row.timeLabel||"",state:aggregateReceipt(row,receiptRows.get(row.id),id.uid,memberUids),cloud:true,e2ee:4,keyEpoch:row.keyEpoch});
      if(row.senderUid!==id.uid){
        try{await updateCloudGroupReceipt(key,row.id,isOpen()?"read":"delivered");}catch(err){onError?.(err);}
      }
    }
    if(!closed)onRows?.(out);
  };
  readCloudGroupAuthority(key).then(a=>{memberUids=a.memberUids||[];delivery=delivery.then(emit,emit);}).catch(onError);
  const unsub=subscribeCloudGroupMessages(key,(rows)=>{
    rawRows=rows||[];
    for(const row of rawRows){
      if(row.senderUid===id.uid&&!receiptStops.has(row.id))receiptStops.set(row.id,subscribeCloudGroupReceipts(key,row.id,rs=>{receiptRows.set(row.id,rs||[]);delivery=delivery.then(emit,emit);},onError));
    }
    for(const [messageId,stop] of [...receiptStops])if(!rawRows.some(r=>r.id===messageId)){try{stop();}catch{}receiptStops.delete(messageId);receiptRows.delete(messageId);}
    delivery=delivery.then(emit,emit);
  },onError);
  streams.set(key,()=>{closed=true;try{unsub();}catch{}for(const stop of receiptStops.values())try{stop();}catch{}receiptStops.clear();receiptRows.clear();});
  return()=>stopAccountGroupConversation(key);
}

export function stopAccountGroupConversation(groupId){const key=String(groupId),stop=streams.get(key);if(stop){streams.delete(key);stop();}}
export function resetAccountGroupConversationStreams(){for(const key of [...streams.keys()])stopAccountGroupConversation(key);}
