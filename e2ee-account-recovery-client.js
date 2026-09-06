function bytesToBase64Url(bytes){
  const u8=bytes instanceof Uint8Array?bytes:new Uint8Array(bytes||[]);
  if(u8.length!==32)throw new Error("Recovery key must be exactly 32 bytes.");
  let raw="";for(const b of u8)raw+=String.fromCharCode(b);
  return btoa(raw).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
}
function base64UrlToBytes(value){
  const v=String(value||"");if(!/^[A-Za-z0-9_-]+$/.test(v))throw new Error("Recovery key response is invalid.");
  const padded=v.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-v.length%4)%4);
  const raw=atob(padded),out=new Uint8Array(raw.length);for(let i=0;i<raw.length;i++)out[i]=raw.charCodeAt(i);
  if(out.length!==32)throw new Error("Recovery key response is invalid.");return out;
}
export function createAccountE2EERecoveryClient({enroll,start,complete}={}){
  for(const [name,fn] of Object.entries({enroll,start,complete}))if(typeof fn!=="function")throw new Error(`Missing recovery callable: ${name}`);
  return Object.freeze({
    async protectRecoveryKey({keyId,pin,recoveryUnlockKey}){return enroll({keyId,pin,recoveryUnlockKey:bytesToBase64Url(recoveryUnlockKey)});},
    async recoverKey({pin}){const started=await start();const finished=await complete({sessionId:started.sessionId,pin});return{...finished,recoveryUnlockKey:base64UrlToBytes(finished.recoveryUnlockKey)};}
  });
}
