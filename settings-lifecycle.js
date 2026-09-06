/*
 * FIDUNIO Settings lifecycle owner.
 *
 * MANDATORY OWNERSHIP CONTRACT (CODING-GUIDELINES.md):
 * Resource owner: this module owns Settings structural layout and the late-added
 * Profile, User Administration, and Invitations sections.
 * Scope: only .content.settings, its named section hosts, and Settings-owned modals.
 * Lifecycle trigger: app.js calls mountSettingsLifecycle() after every renderSettings().
 * Serialized write path: all account/admin/invitation mutations pass through
 * serializeSettingsMutation(). Reads are generation-gated so stale async work
 * cannot write into a replaced Settings DOM.
 */
import {
  getFidunioAccessInfo,
  claimLegacyOwner,
  createFidunioInvitation,
  updateFidunioProfile,
  changeFidunioPassword,
  listFidunioUsersForAdmin,
  updateFidunioUserLifecycle,
  listPendingFidunioInvitations,
  revokeFidunioInvitation
} from "./firebase.js";
import { getAccountE2EELifecycleState,enrollAccountE2EE,unlockAccountE2EE,recoverAccountE2EE,changeAccountPasswordWithE2EE } from "./e2ee-account-runtime.js";

let mutationTail=Promise.resolve();
let generation=0;
function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function initials(name){return String(name||"U").trim().split(/\s+/).filter(Boolean).slice(0,2).map(x=>x[0]?.toUpperCase()||"").join("")||"U";}
function prettyRole(role){return role==="owner"?"Owner":role==="admin"?"Administrator":"User";}
function profileStatus(p){if(p?.active===false)return p?.status||"deactivated";return p?.status||"active";}
function dateText(v){const d=v?.toDate?.()||v;if(!d)return"—";try{return new Date(d).toLocaleString();}catch{return String(d);}}
function guideUrl(){return new URL("./quick-start.html",location.href).href;}
function inviteSubject(){return "Your FIDUNIO invitation";}
function inviteMessage(invite){return `You are invited to FIDUNIO as ${prettyRole(invite.role)}.\n\nJoin: ${invite.link}\nQuick Start: ${guideUrl()}\nExpires: ${invite.expiresAt?.toLocaleString?.()||invite.expiresAt||""}`;}

function serializeSettingsMutation(label,work){
  const run=mutationTail.then(()=>work());
  mutationTail=run.catch(err=>{console.warn(`Settings mutation failed: ${label}`,err);});
  return run;
}

const GROUPS=[
  {id:"general",label:"General",icon:"⚙︎",subtitle:"Appearance, text size, and account information.",cards:["Appearance","Text Size","Firebase Account"]},
  {id:"privacy",label:"Privacy & Access",icon:"🔒",subtitle:"Local PIN, device unlock, inactivity lock, and device identity.",cards:["Privacy & Access","Device Identity"]},
  {id:"encryption",label:"Account Encryption",icon:"◇",subtitle:"Unlock or recover the one durable account E2EE identity."},
  {id:"profile",label:"Profile",icon:"●",subtitle:"Your personal information and how you appear to other FIDUNIO users."},
  {id:"users",label:"User Administration",icon:"◉",subtitle:"Manage account status, roles, and expiration."},
  {id:"invites",label:"Invitations",icon:"✉︎",subtitle:"Create and manage FIDUNIO invitations."},
  {id:"data",label:"Data",icon:"▤",subtitle:"Local data and storage controls.",cards:["Data"]},
  {id:"about",label:"About",icon:"ⓘ",subtitle:"FIDUNIO information and version details.",cards:["About"]}
];
const PANEL_ORDER=["profile","general","privacy","encryption","users","invites","data","about"];
let activeGroup="profile";

function directCards(settings){return[...settings.querySelectorAll(":scope > .card")];}
function cardByTitle(settings,title){return directCards(settings).find(card=>card.querySelector("h2")?.textContent?.trim()===title)||null;}
function updateSelection(shell){
  shell.querySelectorAll(".fidunio-settings-nav-btn").forEach(btn=>{
    const active=btn.dataset.group===activeGroup;
    btn.classList.toggle("is-active",active);
    btn.setAttribute("aria-current",active?"page":"false");
  });
  shell.querySelectorAll(".fidunio-settings-panel").forEach(panel=>panel.classList.toggle("is-active",panel.dataset.group===activeGroup));
}
function createShell(settings){
  const shell=document.createElement("div");
  shell.id="fidunioSettingsShell";
  shell.innerHTML='<aside id="fidunioSettingsNav" aria-label="Settings sections"><h2>Settings</h2><div class="fidunio-settings-nav-list"></div></aside><div class="fidunio-settings-panels"></div>';
  const nav=shell.querySelector(".fidunio-settings-nav-list");
  for(const group of GROUPS){
    const btn=document.createElement("button");
    btn.type="button";btn.className="fidunio-settings-nav-btn";btn.dataset.group=group.id;
    btn.innerHTML=`<span class="fidunio-settings-nav-icon" aria-hidden="true">${group.icon}</span><span>${group.label}</span><span class="fidunio-settings-nav-arrow" aria-hidden="true">›</span>`;
    btn.onclick=()=>{activeGroup=group.id;updateSelection(shell);shell.querySelector(`#fidunioSettingsPanel-${group.id}`)?.scrollIntoView({block:"start"});};
    nav.appendChild(btn);
  }
  const panels=shell.querySelector(".fidunio-settings-panels");
  for(const id of PANEL_ORDER){
    const group=GROUPS.find(g=>g.id===id);
    const panel=document.createElement("section");
    panel.id=`fidunioSettingsPanel-${group.id}`;panel.className="fidunio-settings-panel";panel.dataset.group=group.id;
    panel.innerHTML=`<h2 class="fidunio-settings-panel-title">${esc(group.label)}</h2><p class="fidunio-settings-panel-subtitle">${esc(group.subtitle)}</p><div class="fidunio-settings-section-host" id="fidunioSettingsHost-${group.id}" data-settings-owner="${group.id}"></div>`;
    panels.appendChild(panel);
  }
  settings.prepend(shell);
  updateSelection(shell);
  return shell;
}
function collapseTechnicalCard(card,title){
  if(!card||card.dataset.fidunioCollapsed==="1")return;
  const heading=card.querySelector("h2");if(!heading)return;
  card.dataset.fidunioCollapsed="1";
  const details=document.createElement("div");details.className="fidunio-tech-details";details.hidden=true;
  while(heading.nextSibling)details.appendChild(heading.nextSibling);
  const toggle=document.createElement("button");toggle.className="secondary";toggle.type="button";toggle.textContent=`Show ${title}`;toggle.setAttribute("aria-expanded","false");
  const copy=document.createElement("button");copy.className="secondary";copy.type="button";copy.textContent="Copy Details";copy.style.marginTop="10px";copy.hidden=true;
  toggle.onclick=()=>{const open=details.hidden;details.hidden=!open;copy.hidden=!open;toggle.textContent=`${open?"Hide":"Show"} ${title}`;toggle.setAttribute("aria-expanded",String(open));};
  copy.onclick=()=>{const value=details.innerText.trim();if(!value)return;navigator.clipboard?.writeText(value).then(()=>{const old=copy.textContent;copy.textContent="Copied";setTimeout(()=>copy.textContent=old,1200);}).catch(()=>prompt("Copy details:",value));};
  card.append(toggle,details,copy);
}
function placeBaseCards(settings,shell){
  const prototype=cardByTitle(settings,"Prototype connectivity");if(prototype)prototype.remove();
  for(const group of GROUPS){
    const host=shell.querySelector(`#fidunioSettingsHost-${group.id}`);if(!host)continue;
    for(const title of group.cards||[]){const card=cardByTitle(settings,title);if(card)host.appendChild(card);}
  }
  const general=shell.querySelector("#fidunioSettingsHost-general");
  for(const card of directCards(settings))general?.appendChild(card);
  collapseTechnicalCard(shell.querySelector("#fidunioSettingsHost-general .card h2")?.parentElement?.querySelector("h2")?.textContent==="Firebase Account"?shell.querySelector("#fidunioSettingsHost-general .card"):shell.querySelector("#fidunioSettingsHost-general .card:nth-of-type(3)"),"Firebase Account");
  const firebaseCard=[...shell.querySelectorAll("#fidunioSettingsHost-general > .card")].find(c=>c.querySelector("h2")?.textContent?.trim()==="Firebase Account");
  collapseTechnicalCard(firebaseCard,"Firebase Account");
  const deviceCard=[...shell.querySelectorAll("#fidunioSettingsHost-privacy > .card")].find(c=>c.querySelector("h2")?.textContent?.trim()==="Device Identity");
  collapseTechnicalCard(deviceCard,"Device Identity");
  const footer=settings.querySelector(":scope > .version-footer");if(footer){footer.id="fidunioSettingsFooter";settings.appendChild(footer);}
}
function host(shell,id){return shell.querySelector(`#fidunioSettingsHost-${id}`);}
function current(g,shell){return g===generation&&shell?.isConnected&&document.querySelector("#fidunioSettingsShell")===shell;}

async function saveProfile(values){return updateFidunioProfile(values);}
async function changePassword(uid,currentPassword,newPassword,pin){return changeAccountPasswordWithE2EE({uid,currentPassword,newPassword,pin});}
function renderProfile(profileHost,info){
  const p=info.profile;
  profileHost.innerHTML=`<div class="card" id="fidunioProfileCard"><h2>Profile</h2><div style="text-align:center;margin-bottom:12px">${p.photoURL?`<img src="${esc(p.photoURL)}" alt="Profile" style="width:72px;height:72px;border-radius:50%;object-fit:cover">`:`<div class="avatar" style="width:72px;height:72px;margin:auto;font-size:24px">${esc(initials(p.displayName||"U"))}</div>`}<div class="small-note">System role: ${esc(prettyRole(info.role))}</div></div><label class="form-label" for="profileName">Display name</label><input class="text-input" id="profileName" maxlength="80" value="${esc(p.displayName||info.user.displayName||"")}"><label class="form-label" for="profileEmail">Email address</label><input class="text-input" id="profileEmail" type="email" value="${esc(info.user.email||p.email||"")}"><label class="form-label" for="profilePhone">Telephone number</label><input class="text-input" id="profilePhone" type="tel" autocomplete="tel" value="${esc(p.telephone||"")}" placeholder="Optional"><label class="form-label" for="profilePhoto">Profile picture URL</label><input class="text-input" id="profilePhoto" type="url" value="${esc(p.photoURL||"")}" placeholder="https://…"><label class="form-label" for="profileCurrentPassword">Current password</label><input class="text-input" id="profileCurrentPassword" type="password" autocomplete="current-password" placeholder="Required only for email/password changes"><button class="primary" id="saveProfileBtn" style="margin-top:14px">Save Profile</button><div id="profileNote"></div><hr style="margin:22px 0"><h2>Change Password</h2><label class="form-label" for="newPassword">New password</label><input class="text-input" id="newPassword" type="password" autocomplete="new-password" placeholder="At least 6 characters"><label class="form-label" for="newPassword2">Confirm new password</label><input class="text-input" id="newPassword2" type="password" autocomplete="new-password" placeholder="Repeat new password"><label class="form-label" for="passwordE2EEPin">Six-digit account E2EE PIN</label><input class="text-input" id="passwordE2EEPin" type="password" inputmode="numeric" autocomplete="off" maxlength="6" pattern="[0-9]*" placeholder="Required after Account Encryption is created"><button class="secondary" id="changePasswordBtn" style="margin-top:14px">Change Password</button><div id="passwordNote"></div></div>`;
  const card=profileHost.querySelector("#fidunioProfileCard");
  card.querySelector("#saveProfileBtn").onclick=async()=>{
    const btn=card.querySelector("#saveProfileBtn"),note=card.querySelector("#profileNote");btn.disabled=true;btn.textContent="Saving…";
    try{await serializeSettingsMutation("save profile",()=>saveProfile({displayName:card.querySelector("#profileName").value,email:card.querySelector("#profileEmail").value,telephone:card.querySelector("#profilePhone").value,photoURL:card.querySelector("#profilePhoto").value,currentPassword:card.querySelector("#profileCurrentPassword").value}));note.innerHTML='<p class="small-note">Profile updated.</p>';}
    catch(err){note.innerHTML=`<p class="warning-note">${esc(err?.message||String(err))}</p>`;}
    finally{btn.disabled=false;btn.textContent="Save Profile";}
  };
  card.querySelector("#changePasswordBtn").onclick=async()=>{
    const btn=card.querySelector("#changePasswordBtn"),note=card.querySelector("#passwordNote"),currentPassword=card.querySelector("#profileCurrentPassword").value,next=card.querySelector("#newPassword").value,confirm=card.querySelector("#newPassword2").value;
    if(next!==confirm){note.innerHTML='<p class="warning-note">The new passwords do not match.</p>';return;}
    btn.disabled=true;btn.textContent="Changing…";
    try{await serializeSettingsMutation("change password",()=>changePassword(info.user.uid,currentPassword,next,card.querySelector("#passwordE2EEPin").value));card.querySelector("#profileCurrentPassword").value="";card.querySelector("#newPassword").value="";card.querySelector("#newPassword2").value="";note.innerHTML='<p class="small-note">Password changed successfully.</p>';}
    catch(err){note.innerHTML=`<p class="warning-note">${esc(err?.message||String(err))}</p>`;}
    finally{btn.disabled=false;btn.textContent="Change Password";}
  };
}

async function listUsers(){return listFidunioUsersForAdmin();}
async function updateLifecycle(target,status,expiryDays=undefined){return updateFidunioUserLifecycle(target?.uid,status,expiryDays);}
function canManageUser(u,info){const role=info.profile.systemRole,isSelf=u.uid===info.user.uid;return !isSelf&&u.systemRole!=="owner"&&(u.systemRole!=="admin"||role==="owner");}
function userRow(u,info){
  const status=profileStatus(u),manageable=canManageUser(u,info),name=u.displayName||u.email||"FIDUNIO user";
  return `<div class="admin-user-row" data-uid="${esc(u.uid)}"><div class="admin-user-person"><div class="admin-avatar">${esc(initials(name))}</div><div><strong>${esc(name)}</strong><span>${esc(u.email||"")}</span></div></div><div class="admin-role">${esc((u.systemRole||"user").toUpperCase())}</div><div><span class="admin-status admin-status-${esc(status)}">${esc(status.toUpperCase())}</span></div><div class="admin-expiry">${esc(u.expiresAt?dateText(u.expiresAt):"No expiration")}</div><div class="admin-actions-cell">${manageable?`<button class="admin-more" type="button" data-uid="${esc(u.uid)}" aria-label="Actions for ${esc(name)}">•••</button><div class="admin-menu" data-menu-uid="${esc(u.uid)}"><button data-admin-action="${status==="active"?"suspended":"active"}">${status==="active"?"Suspend":"Restore"}</button><button data-admin-action="deactivated">Deactivate</button><div class="admin-menu-sep"></div><span>Expiration</span><button data-expiry="never">Never</button><button data-expiry="7">7 days</button><button data-expiry="30">30 days</button><button data-expiry="90">90 days</button></div>`:`<span class="admin-protected">${u.uid===info.user.uid?"Current":u.systemRole==="owner"?"Protected":"Owner only"}</span>`}</div></div>`;
}
function closeAdminModal(){document.querySelector("#fidunioAdminModal")?.remove();}
async function renderAdminModal(modal,info){
  const users=await listUsers();if(!modal.isConnected)return;
  const body=modal.querySelector(".modal");
  body.innerHTML=`<div class="admin-modal-head"><div><h2>User Administration</h2><p class="small-note">Manage user access, status, and expiration. Invitation management is kept separately under Invitations.</p></div><button class="secondary" id="adminRefreshBtn" style="width:auto">Refresh</button></div><div class="admin-section-label">Users (${users.length})</div><div class="admin-user-table"><div class="admin-user-header"><span>User</span><span>Role</span><span>Status</span><span>Expires</span><span></span></div>${users.map(u=>userRow(u,info)).join("")}</div><p class="small-note" style="margin-top:10px">Suspended, deactivated, or expired users are blocked by Firestore access rules.</p><div class="modal-actions"><button class="modal-cancel" id="adminCloseBtn">Close</button></div>`;
  body.querySelector("#adminCloseBtn").onclick=closeAdminModal;
  body.querySelector("#adminRefreshBtn").onclick=()=>renderAdminModal(modal,info);
  const closeMenus=()=>body.querySelectorAll(".admin-menu.open").forEach(m=>m.classList.remove("open"));
  body.querySelectorAll(".admin-more").forEach(btn=>btn.onclick=e=>{e.stopPropagation();const menu=body.querySelector(`.admin-menu[data-menu-uid="${CSS.escape(btn.dataset.uid)}"]`),open=menu.classList.contains("open");closeMenus();if(!open)menu.classList.add("open");});
  body.querySelectorAll(".admin-menu button[data-admin-action]").forEach(btn=>btn.onclick=async e=>{e.stopPropagation();const menu=btn.closest(".admin-menu"),u=users.find(x=>x.uid===menu.dataset.menuUid),action=btn.dataset.adminAction;if(action==="deactivated"&&!confirm(`Deactivate ${u.displayName||u.email||"this account"}?`))return;btn.disabled=true;try{await serializeSettingsMutation("update user lifecycle",()=>updateLifecycle(u,action));await renderAdminModal(modal,info);}catch(err){alert(err?.message||String(err));btn.disabled=false;}});
  body.querySelectorAll(".admin-menu button[data-expiry]").forEach(btn=>btn.onclick=async e=>{e.stopPropagation();const menu=btn.closest(".admin-menu"),u=users.find(x=>x.uid===menu.dataset.menuUid),days=btn.dataset.expiry==="never"?null:Number(btn.dataset.expiry);btn.disabled=true;try{await serializeSettingsMutation("update user expiration",()=>updateLifecycle(u,profileStatus(u),days));await renderAdminModal(modal,info);}catch(err){alert(err?.message||String(err));btn.disabled=false;}});
  modal.onclick=e=>{if(e.target===modal)closeAdminModal();else if(!e.target.closest(".admin-more,.admin-menu"))closeMenus();};
}
function openAdmin(info){
  closeAdminModal();const modal=document.createElement("div");modal.id="fidunioAdminModal";modal.className="modal-backdrop";modal.innerHTML='<div class="modal fidunio-admin-modal"><h2>User Administration</h2><p class="small-note">Loading users…</p></div>';document.body.appendChild(modal);
  renderAdminModal(modal,info).catch(err=>{if(!modal.isConnected)return;modal.querySelector(".modal").innerHTML=`<h2>User Administration</h2><p class="warning-note">${esc(err?.message||String(err))}</p><button class="secondary" id="adminCloseBtn">Close</button>`;modal.querySelector("#adminCloseBtn").onclick=closeAdminModal;});
}
function renderUserAdmin(usersHost,info){
  if(!["owner","admin"].includes(info.role)){usersHost.innerHTML='<div class="card" id="fidunioUserAdminCard"><h2>User Administration</h2><p class="small-note">Administrator access is required.</p></div>';return;}
  usersHost.innerHTML='<div class="card" id="fidunioUserAdminCard"><h2>User Administration</h2><p class="small-note">Compact user list for access, suspension, restoration, and expiration.</p><button class="primary" type="button" id="manageUsersBtn">Manage Users & Access</button></div>';
  usersHost.querySelector("#manageUsersBtn").onclick=e=>{e.preventDefault();e.stopPropagation();openAdmin(info);};
}

async function pendingInvites(){return listPendingFidunioInvitations();}
async function revokeInvite(id){return revokeFidunioInvitation(id);}
async function refreshPending(card){
  const box=card.querySelector("#pendingInviteList");if(!box)return;box.innerHTML='<p class="small-note">Loading invitations…</p>';
  try{const rows=await pendingInvites();if(!box.isConnected)return;box.innerHTML=rows.length?rows.map(i=>`<div class="admin-invite-row"><div><strong>${esc(prettyRole(i.role))} invitation</strong><span>${esc(i.invitedByName||"Administrator")} • Expires ${esc(dateText(i.expiresAt))}</span></div><button class="row-action invitationRevokeBtn" type="button" data-id="${esc(i.id)}">Revoke</button></div>`).join(""):'<p class="small-note">No pending invitations.</p>';box.querySelectorAll(".invitationRevokeBtn").forEach(btn=>btn.onclick=async e=>{e.preventDefault();e.stopPropagation();btn.disabled=true;btn.textContent="Revoking…";try{await serializeSettingsMutation("revoke invitation",()=>revokeInvite(btn.dataset.id));await refreshPending(card);}catch(err){btn.disabled=false;btn.textContent="Revoke";alert(err?.message||String(err));}});}catch(err){box.innerHTML=`<p class="warning-note">${esc(err?.message||String(err))}</p>`;}
}
function renderInviteResult(card,invite){
  const result=card.querySelector("#inviteResult");if(!result)return;
  result.innerHTML=`<div class="permission-box" style="margin-top:14px"><strong>Single-use ${esc(prettyRole(invite.role))} invitation</strong><div class="uid-box" style="margin-top:8px;word-break:break-all">${esc(invite.link)}</div><p class="small-note" style="margin:10px 0 0">Expires ${esc(invite.expiresAt.toLocaleString())}. The shared message includes FIDUNIO information and the Quick Start Guide.</p><div class="auth-actions" style="margin-top:10px"><button class="secondary" id="copyInviteBtn">Copy Invitation</button><button class="secondary" id="emailInviteBtn">Email Invitation</button>${navigator.share?'<button class="secondary" id="shareInviteBtn">Share…</button>':""}</div><a class="secondary" href="${esc(guideUrl())}" target="_blank" rel="noopener" style="display:flex;text-decoration:none;margin-top:10px;align-items:center;justify-content:center">View Quick Start Guide</a></div>`;
  result.querySelector("#copyInviteBtn").onclick=async e=>{const text=inviteMessage(invite);try{await navigator.clipboard.writeText(text);e.currentTarget.textContent="Copied";}catch{prompt("Copy FIDUNIO invitation:",text);}};
  result.querySelector("#emailInviteBtn").onclick=e=>{e.preventDefault();e.stopPropagation();location.href=`mailto:?subject=${encodeURIComponent(inviteSubject())}&body=${encodeURIComponent(inviteMessage(invite))}`;};
  const share=result.querySelector("#shareInviteBtn");if(share)share.onclick=e=>{e.preventDefault();e.stopPropagation();navigator.share({title:inviteSubject(),text:inviteMessage(invite)}).catch(()=>{});};
  refreshPending(card);
}
function closeInviteModal(){document.querySelector("#fidunioInviteModal")?.remove();}
function openInviteModal(card){
  closeInviteModal();const modal=document.createElement("div");modal.id="fidunioInviteModal";modal.className="modal-backdrop";modal.innerHTML=`<div class="modal" style="max-width:640px"><div style="display:flex;align-items:center;justify-content:space-between;gap:12px"><h2 style="margin:0">Create Invitation</h2><button class="text-btn" id="inviteModalX" aria-label="Close" style="font-size:28px;line-height:1">×</button></div><p class="small-note">Choose the new user's role and how long the invitation should remain valid.</p><label class="form-label" for="modalInviteRole">New user's role</label><select class="text-input" id="modalInviteRole"><option value="user">User</option><option value="admin">Admin</option></select><label class="form-label" for="modalInviteDays">Expires</label><select class="text-input" id="modalInviteDays"><option value="1">1 day</option><option value="7" selected>7 days</option><option value="30">30 days</option></select><div class="permission-box" style="margin-top:14px"><p class="small-note" style="margin:0">ⓘ The recipient gets the Join link plus a public Quick Start Guide link.</p></div><div class="modal-actions"><button class="modal-cancel" id="inviteModalCancel">Cancel</button><button class="modal-confirm" id="inviteModalCreate">Create Invitation</button></div><div id="inviteModalNote"></div></div>`;document.body.appendChild(modal);
  modal.onclick=e=>{if(e.target===modal)closeInviteModal();};modal.querySelector("#inviteModalX").onclick=closeInviteModal;modal.querySelector("#inviteModalCancel").onclick=closeInviteModal;
  modal.querySelector("#inviteModalCreate").onclick=async()=>{const btn=modal.querySelector("#inviteModalCreate"),note=modal.querySelector("#inviteModalNote");btn.disabled=true;btn.textContent="Creating…";try{const invite=await serializeSettingsMutation("create invitation",()=>createFidunioInvitation(modal.querySelector("#modalInviteRole").value,Number(modal.querySelector("#modalInviteDays").value)));renderInviteResult(card,invite);closeInviteModal();}catch(err){note.innerHTML=`<p class="warning-note">${esc(err?.message||String(err))}</p>`;btn.disabled=false;btn.textContent="Create Invitation";}};
}
function renderInvitations(invitesHost,info){
  if(!info.system){
    invitesHost.innerHTML='<div class="card" id="fidunioInvitationAdmin"><h2>FIDUNIO Administration</h2><p class="small-note">Initialize the invite-only access system. The first successful claim becomes the permanent FIDUNIO Owner.</p><button class="primary" id="claimOwnerBtn">Claim FIDUNIO Owner</button><p class="warning-note">Use this only on the Alpha/primary administrative account.</p></div>';
    const card=invitesHost.querySelector("#fidunioInvitationAdmin");card.querySelector("#claimOwnerBtn").onclick=async()=>{const btn=card.querySelector("#claimOwnerBtn");btn.disabled=true;btn.textContent="Claiming…";try{await serializeSettingsMutation("claim owner",()=>claimLegacyOwner());mountSettingsLifecycle();}catch(err){card.querySelector(".warning-note").textContent=err?.message||String(err);btn.disabled=false;btn.textContent="Claim FIDUNIO Owner";}};return;
  }
  if(!["owner","admin"].includes(info.role)){invitesHost.innerHTML='<div class="card" id="fidunioInvitationAdmin"><h2>Invitations</h2><p class="small-note">Administrator access is required.</p></div>';return;}
  invitesHost.innerHTML=`<div class="card" id="fidunioInvitationAdmin"><h2>Invitations</h2><p class="small-note"><strong>${esc(prettyRole(info.role))}</strong> access • Create a single-use invitation and share it directly by Mail, Messages, SMS, or another app.</p><button class="primary" id="createInviteBtn" style="margin-top:14px">Create Invitation</button><div id="inviteResult"></div><div id="pendingInviteList" style="margin-top:14px"></div></div>`;
  const card=invitesHost.querySelector("#fidunioInvitationAdmin");card.querySelector("#createInviteBtn").onclick=e=>{e.preventDefault();e.stopPropagation();openInviteModal(card);};refreshPending(card);
}

function renderAccountEncryption(encryptionHost,info){
  const lifecycle=getAccountE2EELifecycleState(),managerState=lifecycle?.manager?.state||"EMPTY",uid=info.user.uid;
  const ready=managerState==="READY",empty=managerState==="EMPTY";
  encryptionHost.innerHTML=`<div class="card" id="fidunioAccountEncryptionCard"><h2>Account Encryption</h2>
    <p class="small-note"><strong>Status:</strong> ${esc(managerState)}</p>
    ${ready?`<p class="small-note">Your durable account encryption identity is unlocked on this installation. The same keyId is used across legitimate recovery; FIDUNIO never creates a replacement identity after an unlock/recovery failure.</p>`:`
      <label class="form-label" for="accountE2EEPassword">${empty?"Current Firebase password":"Firebase password"}</label>
      <input class="text-input" id="accountE2EEPassword" type="password" autocomplete="current-password" placeholder="Password">
      <label class="form-label" for="accountE2EEPin">Six-digit account E2EE PIN</label>
      <input class="text-input" id="accountE2EEPin" type="password" inputmode="numeric" autocomplete="off" maxlength="6" pattern="[0-9]*" placeholder="Exactly 6 digits">
      ${empty?`<label class="form-label" for="accountE2EEPin2">Confirm E2EE PIN</label><input class="text-input" id="accountE2EEPin2" type="password" inputmode="numeric" autocomplete="off" maxlength="6" pattern="[0-9]*" placeholder="Repeat 6-digit PIN">`:""}
      <button class="primary" id="accountE2EEPrimaryBtn" style="margin-top:14px">${empty?"Create Account Encryption":"Unlock Account Encryption"}</button>
      ${empty?"":'<button class="secondary" id="accountE2EERecoverBtn" style="margin-top:10px">Recover After Password Reset</button>'}
      <div id="accountE2EENote"></div>`}
    <p class="warning-note">This six-digit account E2EE PIN is separate from the installation-local 4–12 digit app-lock PIN.</p></div>`;
  if(ready)return;
  const card=encryptionHost.querySelector("#fidunioAccountEncryptionCard"),note=card.querySelector("#accountE2EENote"),primary=card.querySelector("#accountE2EEPrimaryBtn");
  primary.onclick=async()=>{const password=card.querySelector("#accountE2EEPassword").value,pin=card.querySelector("#accountE2EEPin").value;if(empty&&pin!==card.querySelector("#accountE2EEPin2").value){note.innerHTML='<p class="warning-note">The E2EE PIN entries do not match.</p>';return;}primary.disabled=true;primary.textContent=empty?"Creating…":"Unlocking…";try{if(empty)await enrollAccountE2EE({uid,password,pin});else await unlockAccountE2EE({uid,password,pin});renderAccountEncryption(encryptionHost,info);}catch(err){note.innerHTML=`<p class="warning-note">${esc(err?.message||String(err))}</p>`;primary.disabled=false;primary.textContent=empty?"Create Account Encryption":"Unlock Account Encryption";}};
  const recover=card.querySelector("#accountE2EERecoverBtn");if(recover)recover.onclick=async()=>{const newPassword=card.querySelector("#accountE2EEPassword").value,pin=card.querySelector("#accountE2EEPin").value;if(!confirm("Use recovery only after the Firebase password has been reset. Continue with the existing six-digit account E2EE PIN?"))return;recover.disabled=true;recover.textContent="Recovering…";try{await recoverAccountE2EE({uid,newPassword,pin});renderAccountEncryption(encryptionHost,info);}catch(err){note.innerHTML=`<p class="warning-note">${esc(err?.message||String(err))}</p>`;recover.disabled=false;recover.textContent="Recover After Password Reset";}};
}

async function hydrateAccountPanels(g,shell){
  const profileHost=host(shell,"profile"),usersHost=host(shell,"users"),invitesHost=host(shell,"invites"),encryptionHost=host(shell,"encryption");
  /* Claim the legacy IDs synchronously so old observer-era modules cannot
     become competing writers while this migration build is being validated. */
  profileHost.innerHTML='<div class="card" id="fidunioProfileCard"><h2>Profile</h2><p class="small-note">Loading profile…</p></div>';
  usersHost.innerHTML='<div class="card" id="fidunioUserAdminCard"><h2>User Administration</h2><p class="small-note">Loading access…</p></div>';
  invitesHost.innerHTML='<div class="card" id="fidunioInvitationAdmin"><h2>Invitations</h2><p class="small-note">Loading invitations…</p></div>';
  try{
    const info=await getFidunioAccessInfo();if(!current(g,shell))return;
    if(!info?.user||!info?.profile){profileHost.innerHTML='<div class="card" id="fidunioProfileCard"><h2>Profile</h2><p class="warning-note">Account profile is unavailable.</p></div>';usersHost.innerHTML="";invitesHost.innerHTML="";return;}
    renderProfile(profileHost,info);renderAccountEncryption(encryptionHost,info);renderUserAdmin(usersHost,info);renderInvitations(invitesHost,info);
  }catch(err){if(!current(g,shell))return;profileHost.innerHTML=`<div class="card" id="fidunioProfileCard"><h2>Profile</h2><p class="warning-note">${esc(err?.message||String(err))}</p></div>`;usersHost.innerHTML="";invitesHost.innerHTML="";}
}

export function mountSettingsLifecycle(){
  const settings=document.querySelector(".content.settings");if(!settings)return;
  const g=++generation;
  settings.querySelector(":scope > #fidunioSettingsShell")?.remove();
  /* app.js just rebuilt the base Settings cards. This owner now establishes
     the permanent named areas exactly once for this render generation. */
  const shell=createShell(settings);
  placeBaseCards(settings,shell);
  hydrateAccountPanels(g,shell);
}
