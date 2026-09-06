import { createAccountE2EEIdentityManager } from "./e2ee-account-identity-manager.js?v=091dffea7642d958979b192b129fbabcd5c99b60";

const out=document.getElementById("results"),rows=[];
function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));}
function render(){out.innerHTML=rows.map(r=>`<div class="test ${r.ok?"pass":"fail"}"><strong>${r.ok?"PASS":"FAIL"}</strong> — ${esc(r.name)}${r.detail?`<div>${esc(r.detail)}</div>`:""}</div>`).join("");}
function row(name,ok,detail=""){rows.push({name,ok,detail});render();}
async function expectFail(name,fn){try{await fn();row(name,false,"unexpected success");}catch(e){row(name,true,e?.code||e?.message||"");}}
function makeStore(){let doc=null,pub=null;return{
 async readIdentity(){return doc?structuredClone(doc):null;},
 async createIdentity({privateIdentity,publicIdentity}){if(doc)throw new Error("exists");doc={...structuredClone(privateIdentity),createdAt:1,updatedAt:1};pub={...structuredClone(publicIdentity),createdAt:1,updatedAt:1};return{revision:1};},
 async updateNormalWrapper({keyId,expectedRevision,normalWrapper}){if(!doc||doc.keyId!==keyId||doc.revision!==expectedRevision)throw new Error("revision conflict");doc={...doc,normalWrapper:structuredClone(normalWrapper),revision:doc.revision+1,updatedAt:doc.updatedAt+1};return{revision:doc.revision};},
 snapshot(){return{doc:doc?structuredClone(doc):null,pub:pub?structuredClone(pub):null};}
};}
function makeRecovery(){let saved=null;return{
 async protectRecoveryKey({uid,keyId,pin,recoveryUnlockKey}){saved={uid,keyId,pin,ruk:new Uint8Array(recoveryUnlockKey)};return{wrappedRecoveryKey:"test-server-wrapped-ruk",recoveryKeyIv:"test-server-iv",recoveryKeyWrappingAlgorithm:"HMAC-SHA256+A256GCM"};},
 get(){return saved;}
};}
function deferred(){let resolve;const promise=new Promise(r=>resolve=r);return{promise,resolve};}

async function run(){
 const uid="identity-manager-test-user",password="Test password 123!",pin="012345";
 const store=makeStore(),recovery=makeRecovery(),states=[];
 const m=createAccountE2EEIdentityManager({identityStore:store,recoveryService:recovery,onStateChange:s=>states.push(s.state)});
 let enrolled;
 try{enrolled=await m.enroll({uid,password,pin});row("enroll creates one durable identity",!!enrolled?.keyId);}catch(e){row("enroll creates one durable identity",false,e.message);return finish();}
 const first=store.snapshot();
 row("public JWK has exact minimal shape",JSON.stringify(Object.keys(first.pub?.publicJwk||{}).sort())===JSON.stringify(["crv","kty","x","y"]));
 row("public record contains no private JWK d",!("d" in (first.pub?.publicJwk||{})));
 row("enrollment runtime private key is non-extractable",m.getRuntimeIdentity()?.privateKey?.extractable===false);
 row("recovery service receives exact six-digit PIN",recovery.get()?.pin===pin);
 await expectFail("second enrollment cannot replace existing identity",()=>m.enroll({uid,password,pin}));
 m.resetForSignOut();
 try{const loaded=await m.load(uid);row("reload finds durable identity and remains locked",!!loaded&&m.getState().state==="LOCKED");}catch(e){row("reload finds durable identity and remains locked",false,e.message);}
 await expectFail("wrong PIN cannot unlock",()=>m.unlock({uid,password,pin:"999999"}));
 let unlocked;
 try{unlocked=await m.unlock({uid,password,pin});row("password plus PIN unlocks same keyId",unlocked.keyId===enrolled.keyId);}catch(e){row("password plus PIN unlocks same keyId",false,e.message);}
 try{const r=await m.rewrap({uid,oldPassword:password,oldPin:pin,newPassword:"New password 456!",newPin:"654321"});row("re-wrap increments revision",r.revision===2);}catch(e){row("re-wrap increments revision",false,e.message);}
 const after=store.snapshot();
 row("re-wrap preserves keyId",after.doc.keyId===first.doc.keyId);
 row("re-wrap preserves public identity",JSON.stringify(after.pub)===JSON.stringify(first.pub));
 row("re-wrap preserves recovery wrapper",JSON.stringify(after.doc.recoveryWrapper)===JSON.stringify(first.doc.recoveryWrapper));
 m.resetForSignOut();await m.load(uid);
 await expectFail("old password and PIN fail after re-wrap",()=>m.unlock({uid,password,pin}));
 try{const u=await m.unlock({uid,password:"New password 456!",pin:"654321"});row("new password and PIN unlock after re-wrap",u.keyId===enrolled.keyId);}catch(e){row("new password and PIN unlock after re-wrap",false,e.message);}

 const beforeRecovery=store.snapshot(), ruk=recovery.get().ruk;
 try{const r=await m.recover({uid,recoveryUnlockKey:ruk,newPassword:"Recovered password 789!",pin});row("recovery increments revision",r.revision===3);}catch(e){row("recovery increments revision",false,e.message);}
 const recovered=store.snapshot();
 row("recovery preserves keyId",recovered.doc.keyId===beforeRecovery.doc.keyId);
 row("recovery preserves public identity",JSON.stringify(recovered.pub)===JSON.stringify(beforeRecovery.pub));
 row("recovery preserves recovery wrapper",JSON.stringify(recovered.doc.recoveryWrapper)===JSON.stringify(beforeRecovery.doc.recoveryWrapper));
 m.resetForSignOut();await m.load(uid);
 try{const u=await m.unlock({uid,password:"Recovered password 789!",pin});row("recovered password plus existing PIN unlock same identity",u.keyId===enrolled.keyId);}catch(e){row("recovered password plus existing PIN unlock same identity",false,e.message);}
 await expectFail("manager refuses cross-account use until sign-out reset",()=>m.load("another-user"));
 row("serialized state path reached READY",states.includes("READY"));

 const gate=deferred(), entered=deferred();
 const slowStore={...makeStore(),async readIdentity(){entered.resolve();await gate.promise;return null;}};
 const slowRecovery=makeRecovery();
 const slow=createAccountE2EEIdentityManager({identityStore:slowStore,recoveryService:slowRecovery});
 const pending=slow.load("signout-race-user");
 await entered.promise;
 slow.resetForSignOut();
 gate.resolve();
 await expectFail("sign-out invalidates an in-flight identity operation",()=>pending);
 row("sign-out race cannot repopulate runtime",slow.getRuntimeIdentity()===null&&slow.getState().state==="EMPTY");
 finish();
}
function finish(){const failed=rows.filter(r=>!r.ok).length;document.getElementById("summary").textContent=failed?`${failed} test(s) failed.`:`All ${rows.length} tests passed.`;}
run().catch(e=>{row("test harness",false,e?.stack||e?.message||String(e));finish();});
