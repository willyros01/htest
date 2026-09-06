/* FIDUNIO New Message recipient owner.
 * Resource: recipient-picker DOM inside the host provided by app.js.
 * Lifecycle: app.js calls mountNewMessageRecipientPicker() after each
 * renderNewConversation(). No observer, global DOM repair, or Firebase init.
 */
import { listCloudUsers } from "./firebase.js";

function displayName(user){return String(user?.displayName||user?.email||"FIDUNIO user").trim();}
function initials(name){
  const parts=String(name||"").trim().split(/\s+/).filter(Boolean);
  return (parts.slice(0,2).map(x=>x[0]?.toUpperCase()||"").join("")||"F").slice(0,2);
}
function renderPeople({list,users,query,uidInput,startButton}){
  const q=String(query||"").trim().toLocaleLowerCase();
  const rows=users.filter(user=>displayName(user).toLocaleLowerCase().includes(q));
  list.innerHTML="";
  if(!rows.length){
    const empty=document.createElement("p");
    empty.className="small-note";
    empty.textContent=q?"No matching FIDUNIO users.":"No other FIDUNIO users are available.";
    list.appendChild(empty);
    return;
  }
  for(const user of rows){
    const name=displayName(user);
    const btn=document.createElement("button");
    btn.type="button";
    btn.className="big-choice fidunio-recipient-choice";
    btn.innerHTML=`<span class="choice-icon" aria-hidden="true">${initials(name)}</span><span><strong></strong><span>FIDUNIO contact</span></span>`;
    btn.querySelector("strong").textContent=name;
    btn.onclick=()=>{
      if(!uidInput.isConnected||!startButton.isConnected)return;
      uidInput.value=user.uid;
      startButton.click();
    };
    list.appendChild(btn);
  }
}

export async function mountNewMessageRecipientPicker({host,uidInput,startButton}){
  if(!host||!uidInput||!startButton)throw new Error("New Message recipient host is incomplete.");
  host.replaceChildren();
  uidInput.hidden=true;
  startButton.hidden=true;
  const label=uidInput.labels?.[0];
  if(label)label.hidden=true;

  const search=document.createElement("input");
  search.type="search";
  search.className="search";
  search.autocomplete="off";
  search.placeholder="Search by display name";
  search.setAttribute("aria-label","Search FIDUNIO users by display name");
  const list=document.createElement("div");
  list.className="choice-list fidunio-recipient-list";
  const loading=document.createElement("p");
  loading.className="small-note";
  loading.textContent="Loading FIDUNIO users…";
  list.appendChild(loading);
  host.append(search,list);

  try{
    const users=await listCloudUsers();
    if(!host.isConnected)return;
    const draw=()=>renderPeople({list,users,query:search.value,uidInput,startButton});
    draw();
    search.oninput=draw;
  }catch(err){
    if(!host.isConnected)return;
    list.innerHTML="";
    const note=document.createElement("p");
    note.className="warning-note";
    note.textContent="Could not load FIDUNIO contacts. Please try again.";
    list.appendChild(note);
    console.warn("FIDUNIO recipient list could not be loaded",err);
  }
}
