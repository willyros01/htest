const FORMAT="fidunio-attachment-v1";
const CHUNK_SIZE=256*1024;
const te=new TextEncoder();
function b64u(bytes){let s="";const u=bytes instanceof Uint8Array?bytes:new Uint8Array(bytes);for(let i=0;i<u.length;i+=0x8000)s+=String.fromCharCode(...u.subarray(i,i+0x8000));return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");}
function unb64u(s){const p=String(s).replace(/-/g,"+").replace(/_/g,"/");const raw=atob(p+"=".repeat((4-p.length%4)%4));return Uint8Array.from(raw,c=>c.charCodeAt(0));}
function aad(attachmentId,index,total){return te.encode(`FIDUNIO-ATTACHMENT-V1|${attachmentId}|${index}|${total}`);}
function cleanMeta(meta={}){const name=String(meta.name||"attachment").slice(0,180),type=String(meta.type||"application/octet-stream").slice(0,120);return{name,type};}
export function attachmentChunkSize(){return CHUNK_SIZE;}
export async function encryptAttachmentBytes({attachmentId,bytes,meta={}}){
  if(!attachmentId)throw new Error("Attachment ID is required.");
  const input=bytes instanceof Uint8Array?bytes:new Uint8Array(bytes||0);
  if(!input.byteLength)throw new Error("Attachment is empty.");
  const key=await crypto.subtle.generateKey({name:"AES-GCM",length:256},true,["encrypt","decrypt"]);
  const rawKey=new Uint8Array(await crypto.subtle.exportKey("raw",key));
  const total=Math.ceil(input.byteLength/CHUNK_SIZE),chunks=[];
  for(let index=0;index<total;index++){
    const plain=input.subarray(index*CHUNK_SIZE,Math.min(input.byteLength,(index+1)*CHUNK_SIZE));
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const ciphertext=await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:aad(attachmentId,index,total)},key,plain);
    chunks.push({format:FORMAT,attachmentId:String(attachmentId),index,total,iv:b64u(iv),ciphertext:b64u(new Uint8Array(ciphertext))});
  }
  const digest=b64u(new Uint8Array(await crypto.subtle.digest("SHA-256",input)));
  return{key:b64u(rawKey),manifest:{format:FORMAT,attachmentId:String(attachmentId),...cleanMeta(meta),size:input.byteLength,totalChunks:total,sha256:digest},chunks};
}
export async function decryptAttachmentBytes({manifest,chunks,key}){
  if(manifest?.format!==FORMAT||!manifest.attachmentId||!Number.isInteger(manifest.totalChunks)||manifest.totalChunks<1)throw new Error("Invalid attachment manifest.");
  if(!Array.isArray(chunks)||chunks.length!==manifest.totalChunks)throw new Error("Attachment chunks are incomplete.");
  const cryptoKey=await crypto.subtle.importKey("raw",unb64u(key),{name:"AES-GCM",length:256},false,["decrypt"]),parts=[];
  let size=0;
  for(let index=0;index<manifest.totalChunks;index++){
    const row=chunks.find(x=>x.index===index);
    if(!row||row.format!==FORMAT||row.attachmentId!==manifest.attachmentId||row.total!==manifest.totalChunks)throw new Error("Attachment chunk binding failed.");
    const plain=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64u(row.iv),additionalData:aad(manifest.attachmentId,index,manifest.totalChunks)},cryptoKey,unb64u(row.ciphertext)));
    parts.push(plain);size+=plain.length;
  }
  if(size!==manifest.size)throw new Error("Attachment size check failed.");
  const out=new Uint8Array(size);let offset=0;for(const p of parts){out.set(p,offset);offset+=p.length;}
  const digest=b64u(new Uint8Array(await crypto.subtle.digest("SHA-256",out)));
  if(digest!==manifest.sha256)throw new Error("Attachment integrity check failed.");
  return out;
}
