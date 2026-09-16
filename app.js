const $ = (id) => document.getElementById(id);
const state = { data:null, view:"browse" };

async function unpack(bytes) {
  if (!("DecompressionStream" in window)) throw new Error("Unsupported browser");
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function openData(password) {
  const raw = new Uint8Array(await fetch("r.dat", {cache:"no-store"}).then(async r => {
    if (!r.ok) throw new Error("Data unavailable");
    return r.arrayBuffer();
  }));
  if (raw.length < 34 || raw[0] !== 2) throw new Error("Unsupported format");
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const rounds = view.getUint32(1, false);
  const salt = raw.slice(5, 21);
  const iv = raw.slice(21, 33);
  const sealed = raw.slice(33);
  const base = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    {name:"PBKDF2", salt, iterations:rounds, hash:"SHA-256"},
    base, {name:"AES-GCM", length:256}, false, ["decrypt"]
  );
  const packed = await crypto.subtle.decrypt(
    {name:"AES-GCM", iv, additionalData:new TextEncoder().encode("r2")},
    key, sealed
  );
  const plain = await unpack(packed);
  return JSON.parse(new TextDecoder().decode(plain));
}

function money(v){ return v == null ? "" : `$${Number(v).toFixed(2)}`; }
function pct(v){ return v == null ? "" : `${Number(v).toFixed(1).replace(".0","")}%`; }
function esc(s=""){ return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
function metricNumber(v){ const m=String(v||"").match(/\d+(?:\.\d+)?/); return m ? Number(m[0]) : -1; }

function itemCard(p){
  const labels=state.data.l||{};
  const old = p.P && p.P > p.p ? `<span class="old">${money(p.P)}</span>` : "";
  const sale = p.d ? `<span class="badge sale">${pct(p.d)} off</span>` : (p.s ? `<span class="badge sale">Offer</span>` : "");
  const meta = [p.c,p.t,p.z,p.h?`${labels.h||"M1"} ${p.h}`:null,p.r?`${labels.r||"M2"} ${p.r}`:null].filter(Boolean).join(" • ");
  return `<article class="card">
    <div class="store">${esc(p.A||"")}</div>
    <div class="brand">${esc(p.b||"")}</div>
    <h3>${esc(p.n||"")}</h3>
    <div class="meta">${esc(meta)}</div>
    ${sale}
    <div class="price">${money(p.p)}${old}</div>
    ${p.g ? `<div class="meta">${money(p.g)}/g</div>` : ""}
    ${p.m ? `<div class="promo">${esc(p.m)}</div>` : ""}
    ${p.v ? `<div class="meta">${esc(p.v)}</div>` : ""}
    ${p.l ? `<a class="source" href="${esc(p.l)}" target="_blank" rel="noopener">Open ↗</a>` : ""}
  </article>`;
}

function filtered(){
  const q=$("search").value.trim().toLowerCase(), source=$("source-filter").value, group=$("group-filter").value;
  let items=[...(state.data.p||[])];
  if(state.view==="offers") items=items.filter(p=>p.s);
  if(q) items=items.filter(p=>[p.n,p.b,p.c,p.t,p.A].some(x=>String(x||"").toLowerCase().includes(q)));
  if(source) items=items.filter(p=>p.a===source);
  if(group) items=items.filter(p=>p.c===group);
  const sort=$("sort").value;
  items.sort((a,b)=>{
    if(sort==="price-asc") return (a.p??Infinity)-(b.p??Infinity);
    if(sort==="price-desc") return (b.p??-1)-(a.p??-1);
    if(sort==="discount") return (b.d??-1)-(a.d??-1);
    if(sort==="metric") return metricNumber(b.h)-metricNumber(a.h);
    if(sort==="ppg") return (a.g??Infinity)-(b.g??Infinity);
    return String(a.n||"").localeCompare(String(b.n||""));
  });
  return items;
}

function renderBrowse(){
  const items=filtered();
  $("summary").textContent=`${items.length} items`;
  $("content").innerHTML=items.map(itemCard).join("") || `<div class="card">No matching items.</div>`;
}
function renderCompare(){
  const groups={};
  for(const p of filtered()) (groups[p.x] ||= []).push(p);
  const matches=Object.values(groups).filter(g=>new Set(g.map(x=>x.a)).size>1);
  $("summary").textContent=`${matches.length} exact cross-source matches`;
  $("content").innerHTML=matches.map(group=>{
    const p=group[0];
    const rows=group.sort((a,b)=>(a.p??Infinity)-(b.p??Infinity)).map(x=>
      `<div class="compare-row"><span>${esc(x.A||"")}</span><strong>${money(x.p)}</strong></div>`
    ).join("");
    return `<article class="card"><div class="brand">${esc(p.b||"")}</div><h3>${esc(p.n||"")}</h3><div class="meta">${esc([p.c,p.z].filter(Boolean).join(" • "))}</div>${rows}</article>`;
  }).join("") || `<div class="card">No exact matches across sources yet.</div>`;
}
function renderSources(){
  const sources=state.data.s||[];
  $("summary").textContent=`${sources.length} sources`;
  $("content").innerHTML=sources.map(s=>`<article class="card">
    <div class="store-status"><span class="dot ${esc(s.s||"")}"></span><h3>${esc(s.n||"")}</h3></div>
    <div class="meta">Status: ${esc(s.s||"unknown")}<br>Last update: ${esc(s.l||"Not yet")}</div>
    ${s.u?`<a class="source" href="${esc(s.u)}" target="_blank" rel="noopener">Open ↗</a>`:""}
  </article>`).join("");
}
function render(){
  document.querySelectorAll("nav button").forEach(b=>b.classList.toggle("active",b.dataset.view===state.view));
  if(state.view==="compare") renderCompare();
  else if(state.view==="sources") renderSources();
  else renderBrowse();
}

function initData(data){
  state.data=data;
  $("freshness").textContent=`Updated ${new Date(data.g).toLocaleString()}`;
  const sources=[...new Map((data.p||[]).map(p=>[p.a,p.A])).entries()].sort((a,b)=>String(a[1]).localeCompare(String(b[1])));
  $("source-filter").innerHTML=`<option value="">All sources</option>`+sources.map(([v,n])=>`<option value="${esc(v)}">${esc(n)}</option>`).join("");
  const groups=[...new Set((data.p||[]).map(p=>p.c).filter(Boolean))].sort();
  $("group-filter").innerHTML=`<option value="">All groups</option>`+groups.map(c=>`<option>${esc(c)}</option>`).join("");
  $("lock").classList.add("hidden"); $("app").classList.remove("hidden");
  render();
}

async function tryUnlock(password, remember){
  $("unlock-error").textContent="Unlocking…";
  try{
    const data=await openData(password);
    if(remember) localStorage.setItem("u-k",password); else localStorage.removeItem("u-k");
    $("unlock-error").textContent="";
    initData(data);
  }catch(err){
    $("unlock-error").textContent="Incorrect password or data unavailable.";
    localStorage.removeItem("u-k");
  }
}

$("unlock-form").addEventListener("submit", e=>{e.preventDefault();tryUnlock($("password").value,$("remember").checked);});
$("lock-button").addEventListener("click",()=>{localStorage.removeItem("u-k");location.reload();});
for(const id of ["search","source-filter","group-filter","sort"]) $(id).addEventListener("input",render);
document.querySelectorAll("nav button").forEach(b=>b.addEventListener("click",()=>{state.view=b.dataset.view;render();}));

const saved=localStorage.getItem("u-k");
if(saved){ $("remember").checked=true; $("password").value=saved; tryUnlock(saved,true); }
