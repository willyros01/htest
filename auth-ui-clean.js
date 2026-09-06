/*
 * FIDUNIO authentication gate only.
 * Settings/Profile/Administration/Invitations are deliberately NOT owned here.
 * See CODING-GUIDELINES.md and settings-lifecycle.js.
 */
import {
  isFirebaseConfigured,
  initFirebase,
  getFirebaseUser,
  getFidunioAccessInfo,
  listCloudUsers,
  getCloudUserDevices,
  validateInvitation,
  redeemFidunioInvitation,
  signInFidunio,
  sendFidunioPasswordReset
} from "./firebase.js";
import {markSuccessfulAuthBypass} from "./local-security.js";
import {
  getAccountStorageStatus,
  inspectLegacyAccountIdentity,
  inspectQuarantinedAccountIdentity,
  recoverQuarantinedE2EEIdentity,
  activateAccountStorage
} from "./account-storage.js";

const VERSION=globalThis.FIDUNIO_RELEASE?.version||"";
let appStarted=false;

function esc(s=""){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function prettyRole(role){return role==="owner"?"Owner":role==="admin"?"Admin":"User";}
function inviteTokenFromUrl(){return new URL(location.href).searchParams.get("invite")||"";}
function clearInviteFromUrl(){const u=new URL(location.href);if(!u.searchParams.has("invite"))return;u.searchParams.delete("invite");history.replaceState(null,"",u.pathname+(u.search||"")+u.hash);}
function authShell(inner){document.querySelector("#app").innerHTML=`<main class="app-shell unlock"><section class="unlock-card" style="max-width:520px"><div class="unlock-brand"><img class="brand-logo" src="fidunio-logo.png" alt="Fidunio logo"></div><h1>FIDUNIO</h1><p>Private Messaging</p>${inner}<div class="small-note">FIDUNIO ${esc(VERSION)} • Invite-only access</div></section></main>`;}

async function sendPasswordReset(email){return sendFidunioPasswordReset(email);}
function canonicalJwk(jwk){return JSON.stringify({kty:jwk?.kty||"",crv:jwk?.crv||"",x:jwk?.x||"",y:jwk?.y||""});}
async function resolveIdentityOwnerUid(identity){
  if(!identity?.publicJwk&&!identity?.deviceId)return null;
  const current=await getFidunioAccessInfo();
  const others=await listCloudUsers();
  const profiles=[current.profile,...others].filter(Boolean);
  const wantedKey=identity.publicJwk?canonicalJwk(identity.publicJwk):null;
  const wantedDevice=String(identity.deviceId||"");
  const matches=new Set();
  for(const profile of profiles){
    if(wantedKey&&canonicalJwk(profile.e2eePublicJwk)===wantedKey)matches.add(profile.uid);
    try{
      const devices=await getCloudUserDevices(profile.uid);
      if(devices.some(d=>
        (wantedDevice&&String(d.deviceId||d.id||"")===wantedDevice)||
        (wantedKey&&canonicalJwk(d.publicJwk)===wantedKey)
      ))matches.add(profile.uid);
    }catch(err){console.warn("Could not inspect device registry for legacy identity ownership",profile.uid,err);}
  }
  return matches.size===1?[...matches][0]:null;
}
async function resolveLegacyOwnerUid(){
  const legacy=await inspectLegacyAccountIdentity();
  if(!legacy.hasLegacyData||(!legacy.publicJwk&&!legacy.deviceId))return null;
  return resolveIdentityOwnerUid(legacy);
}
async function recoverVerifiedQuarantinedIdentity(userUid){
  const legacy=await inspectQuarantinedAccountIdentity();
  if(!legacy.hasIdentity)return{recovered:false,reason:"no-quarantined-identity"};
  const ownerUid=await resolveIdentityOwnerUid(legacy);
  if(ownerUid!==userUid)return{recovered:false,reason:ownerUid?"belongs-to-other-account":"ownership-ambiguous"};
  return recoverQuarantinedE2EEIdentity(userUid,{legacyOwnerUid:ownerUid});
}

async function startApp(){
  if(appStarted)return;
  const user=getFirebaseUser();
  if(!user)throw new Error("Authenticated account is required before FIDUNIO can start.");
  const storageStatus=await getAccountStorageStatus();
  let legacyOwnerUid=null;
  if(!storageStatus.activeUid){
    try{legacyOwnerUid=await resolveLegacyOwnerUid();}
    catch(err){console.warn("FIDUNIO could not uniquely identify legacy local-data ownership; legacy data will be quarantined",err);}
  }
  await activateAccountStorage(user.uid,{legacyOwnerUid});
  // Stable-identity invariant: ordinary startup never overwrites the active E2EE identity from quarantine.
  appStarted=true;
  clearInviteFromUrl();
  await import("./app.js");
}

function renderGate(mode=inviteTokenFromUrl()?"join":"signin",message=""){
  authShell(`<div class="auth-actions" style="margin-bottom:14px"><button class="${mode==="signin"?"primary":"secondary"}" id="signInTab">Sign In</button><button class="${mode==="join"?"primary":"secondary"}" id="joinTab">Join FIDUNIO</button></div><div id="authBody"></div>${message?`<p class="warning-note">${esc(message)}</p>`:""}`);
  document.querySelector("#signInTab").onclick=()=>renderGate("signin");
  document.querySelector("#joinTab").onclick=()=>renderGate("join");
  if(mode==="join")renderJoin(inviteTokenFromUrl());else renderSignIn();
}

function renderSignIn(){
  const body=document.querySelector("#authBody");
  body.innerHTML=`<p class="small-note">Sign in with an existing FIDUNIO account. New accounts require an invitation.</p><label class="form-label" for="loginEmail">Email</label><input class="text-input" id="loginEmail" type="email" autocomplete="username" placeholder="name@example.com"><label class="form-label" for="loginPassword">Password</label><input class="text-input" id="loginPassword" type="password" autocomplete="current-password" placeholder="Password"><button class="primary" id="loginBtn" style="margin-top:14px">Sign In</button><button class="secondary" id="forgotBtn" style="margin-top:10px">Forgot Password</button><div id="loginNote"></div>`;
  document.querySelector("#loginBtn").onclick=async()=>{
    const btn=document.querySelector("#loginBtn");btn.disabled=true;btn.textContent="Signing in…";
    try{await signInFidunio(document.querySelector("#loginEmail").value.trim(),document.querySelector("#loginPassword").value);markSuccessfulAuthBypass();await startApp();}
    catch(err){renderGate("signin",err?.message||String(err));}
  };
  document.querySelector("#forgotBtn").onclick=async()=>{
    const email=document.querySelector("#loginEmail").value.trim(),note=document.querySelector("#loginNote");
    if(!email){note.innerHTML='<p class="warning-note">Enter your email address first.</p>';return;}
    try{await sendPasswordReset(email);note.innerHTML='<p class="small-note">Password reset email sent. Check your inbox.</p>';}
    catch(err){note.innerHTML=`<p class="warning-note">${esc(err?.message||String(err))}</p>`;}
  };
}

async function renderJoin(initialToken=""){
  const body=document.querySelector("#authBody");
  body.innerHTML=`<p class="small-note">A valid single-use invitation is required to create a FIDUNIO account.</p><label class="form-label" for="inviteCode">Invitation code</label><input class="text-input" id="inviteCode" autocomplete="off" placeholder="Invitation code" value="${esc(initialToken)}"><button class="secondary" id="verifyInviteBtn" style="margin-top:12px">Verify Invitation</button><div id="verifiedInvite"></div>`;
  document.querySelector("#verifyInviteBtn").onclick=verifyInvite;
  if(initialToken)await verifyInvite();
}

async function verifyInvite(){
  const token=document.querySelector("#inviteCode")?.value.trim(),btn=document.querySelector("#verifyInviteBtn"),box=document.querySelector("#verifiedInvite");
  if(!token)return;
  if(btn){btn.disabled=true;btn.textContent="Verifying…";}
  try{
    const invite=await validateInvitation(token);
    box.innerHTML=`<div class="card" style="margin-top:14px;text-align:left"><strong>Invitation verified</strong><p class="small-note">Invited by ${esc(invite.invitedByName)} • Role: ${esc(prettyRole(invite.role))}${invite.expiresAt?` • Expires ${esc(invite.expiresAt.toLocaleDateString())}`:""}</p><label class="form-label" for="joinName">Display name</label><input class="text-input" id="joinName" maxlength="80" placeholder="Your display name"><label class="form-label" for="joinEmail">Email</label><input class="text-input" id="joinEmail" type="email" autocomplete="username" placeholder="name@example.com"><label class="form-label" for="joinPassword">Password</label><input class="text-input" id="joinPassword" type="password" autocomplete="new-password" placeholder="At least 6 characters"><button class="primary" id="redeemBtn" style="margin-top:14px">Create FIDUNIO Account</button></div>`;
    document.querySelector("#redeemBtn").onclick=async()=>{
      const createBtn=document.querySelector("#redeemBtn");createBtn.disabled=true;createBtn.textContent="Creating account…";
      try{await redeemFidunioInvitation(token,document.querySelector("#joinEmail").value.trim(),document.querySelector("#joinPassword").value,document.querySelector("#joinName").value.trim());markSuccessfulAuthBypass();await startApp();}
      catch(err){renderGate("join",err?.message||String(err));}
    };
  }catch(err){box.innerHTML=`<p class="warning-note">${esc(err?.message||String(err))}</p>`;}
  finally{if(btn){btn.disabled=false;btn.textContent="Verify Invitation";}}
}

export async function runAuthGate(){
  if(!isFirebaseConfigured()){authShell('<p class="warning-note">FIDUNIO cannot start because Firebase is not configured.</p>');return;}
  // firebase.js owns the complete Firebase startup lifecycle. App Check is
  // initialized there before Auth/Firestore services are exposed.
  await new Promise(resolve=>{
    let first=true;
    initFirebase(user=>{
      if(first){first=false;resolve(user);return;}
      if(appStarted&&!user)location.reload();
    }).catch(err=>{authShell(`<p class="warning-note">${esc(err?.message||String(err))}</p>`);resolve(null);});
  });
  const user=getFirebaseUser();
  if(user){
    try{const info=await getFidunioAccessInfo();if(info.profile)await startApp();else renderGate("join","This login is not enrolled in FIDUNIO. Use a valid invitation.");}
    catch(err){renderGate("signin",err?.message||String(err));}
  }else renderGate();
}
