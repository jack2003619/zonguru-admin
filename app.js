const API = "https://zonguru-jack-api.onrender.com";
const token = localStorage.getItem("zonguru_token");

function authHeaders() {
  return { "Authorization": "Bearer " + token, "Content-Type": "application/json" };
}
function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function openModal(id){ document.getElementById(id).classList.add("show"); }
function closeModal(id){ document.getElementById(id).classList.remove("show"); }
document.querySelectorAll("[data-open]").forEach(b=>b.addEventListener("click",()=>openModal(b.dataset.open)));

function logout(){ localStorage.clear(); location.href="login.html"; }
document.getElementById("logoutBtn").onclick=logout;

async function api(path, options={}) {
  const r=await fetch(API+path,{...options,headers:{...authHeaders(),...(options.headers||{})}});
  const d=await r.json().catch(()=>({}));
  if(r.status===401){logout();throw new Error("Session expired");}
  if(!r.ok) throw new Error(d.message||"Request failed");
  return d;
}

async function loadMe(){
  const d=await api("/api/me");
  document.getElementById("welcome").textContent="Welcome, "+d.user.username;
  document.getElementById("balance").textContent=Number(d.user.balance).toFixed(2);
  document.getElementById("profit").textContent=Number(d.user.totalProfit).toFixed(2);
  document.getElementById("roleText").textContent=d.user.role==="admin"?"Administrator":"Active account";
  document.getElementById("profileBox").innerHTML=`
    <div><span>Username</span><b>${esc(d.user.username)}</b></div>
    <div><span>Role</span><b>${esc(d.user.role)}</b></div>
    <div><span>Balance</span><b>${Number(d.user.balance).toFixed(2)} ${d.user.currency}</b></div>
    <div><span>Total Profit</span><b>${Number(d.user.totalProfit).toFixed(2)} ${d.user.currency}</b></div>
    <div><span>Referral Code</span><b>${esc(d.user.referralCode)}</b></div>`;
  localStorage.setItem("zonguru_user",JSON.stringify(d.user));
}

async function loadProducts(){
  const box=document.getElementById("products");
  box.innerHTML="<div class='loading'>Loading products...</div>";
  try{
    const d=await api("/api/products");
    box.innerHTML=d.products.map(p=>`
      <article class="product-card">
        <div class="product-icon">⚡</div>
        <div class="product-info"><h3>${esc(p.name)}</h3><p>${esc(p.category)}</p><b>${Number(p.price).toFixed(2)} USDT</b></div>
        <div class="product-right"><span>Profit ${(p.profitRate*100).toFixed(1)}%</span><button class="small-btn optimize" onclick="optimize('${p._id}','${esc(p.name)}')">Optimize</button></div>
      </article>`).join("");
  }catch(e){box.innerHTML=`<div class="error">${esc(e.message)}</div>`}
}

async function optimize(id,name){
  if(!confirm("Optimize "+name+" now?")) return;
  try{
    const d=await api("/api/products/"+id+"/optimize",{method:"POST"});
    alert(`${d.message}\nProfit: ${Number(d.profit).toFixed(2)} USDT`);
    await loadMe(); await loadProducts();
  }catch(e){alert(e.message)}
}

async function submitDeposit(){
  const amount=Number(document.getElementById("depositAmount").value);
  const note=document.getElementById("depositNote").value;
  const msg=document.getElementById("depositMsg");
  try{const d=await api("/api/deposits",{method:"POST",body:JSON.stringify({amount,note})});msg.textContent=d.message;setTimeout(()=>closeModal("depositModal"),700);showTransactions();}catch(e){msg.textContent=e.message}
}
async function submitWithdraw(){
  const amount=Number(document.getElementById("withdrawAmount").value);
  const note=document.getElementById("withdrawNote").value;
  const msg=document.getElementById("withdrawMsg");
  try{const d=await api("/api/withdrawals",{method:"POST",body:JSON.stringify({amount,note})});msg.textContent=d.message;setTimeout(()=>closeModal("withdrawModal"),700);showTransactions();}catch(e){msg.textContent=e.message}
}
async function showTransactions(){
  const d=await api("/api/transactions");
  document.getElementById("listContent").innerHTML="<h2>Transaction History</h2>"+(d.transactions.length?d.transactions.map(t=>`<div class="history-row"><div><b>${esc(t.type.replaceAll("_"," "))}</b><small>${new Date(t.createdAt).toLocaleString()}</small></div><span>${Number(t.amount).toFixed(2)} USDT<br><small>${esc(t.status)}</small></span></div>`).join(""):"<p class='muted'>No transactions</p>");
  openModal("listModal");
}
async function showMessages(){
  const d=await api("/api/messages");
  document.getElementById("unread").textContent=d.messages.filter(x=>!x.read).length;
  document.getElementById("listContent").innerHTML="<h2>Messages</h2>"+(d.messages.length?d.messages.map(m=>`<div class="message-row"><b>${esc(m.sender)}</b><p>${esc(m.text)}</p><small>${new Date(m.createdAt).toLocaleString()}</small></div>`).join(""):"<p class='muted'>No messages</p>");
  openModal("listModal");
}
async function showTeam(){
  const d=await api("/api/team");
  document.getElementById("memberCount").textContent=d.members.length;
  document.getElementById("listContent").innerHTML=`<h2>Team Report</h2><div class="ref-code">Referral Code: <b>${esc(d.referralCode)}</b></div>`+(d.members.length?d.members.map(m=>`<div class="history-row"><div><b>${esc(m.username)}</b><small>${new Date(m.createdAt).toLocaleDateString()}</small></div><span>${Number(m.balance).toFixed(2)} USDT</span></div>`).join(""):"<p class='muted'>No team members yet.</p>");
  openModal("listModal");
}
async function changePassword(){
  const msg=document.getElementById("passwordMsg");
  try{const d=await api("/api/auth/change-password",{method:"POST",body:JSON.stringify({oldPassword:document.getElementById("oldPassword").value,newPassword:document.getElementById("newPassword").value})});msg.textContent=d.message;}catch(e){msg.textContent=e.message}
}

(async()=>{
  if(!token){location.href="login.html";return}
  try{
    await loadMe();
    await loadProducts();
    const m=await api("/api/messages"); document.getElementById("unread").textContent=m.messages.filter(x=>!x.read).length;
    const t=await api("/api/team"); document.getElementById("memberCount").textContent=t.members.length;
  }catch(e){console.error(e)}
})();
