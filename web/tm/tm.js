import {generateKeypair,encryptPriv,decryptPriv,sign,b64,b64u,b64uDec,utf8,utf8Dec} from './auth-client.js';

const API='/api/v1/tm';
const SS='aether-tm-session';
const DB='aether-tm';
const STORE='keyrings';
const DOMAIN='aether-tm:v1:';

const L={
en:{
 nav_dash:'Dashboard',nav_proj:'Projects',nav_task:'Tasks',nav_user:'Users',btn_logout:'Log out',
 login_title:'Sign in',login_email:'Email',login_pass:'Passphrase',login_btn:'Sign in',
 login_help:'No keys on this device?',reg_link:'Accept an invite',
 reg_title:'Accept invite',reg_token:'Invite token',reg_name:'Your name',reg_pass:'Set passphrase',reg_pass2:'Confirm passphrase',reg_btn:'Generate keys and join',
 reg_help:'Your private key never leaves this device. Lose the passphrase, lose the access.',reg_done:'Account ready. Sign in now.',
 dash_title:'Overview',
 t_open:'Open',t_inp:'In progress',t_blk:'Blocked',t_done:'Done',t_over:'Overdue',
 dash_recent:'Recent tasks',dash_tier:'By tier',dash_create:'Create task',
 proj_title:'Projects',proj_new:'New project',proj_name:'Name',proj_desc:'Description',proj_create:'Create project',
 proj_archive:'Archive',proj_open:'Open',
 task_title:'Tasks',task_new:'New task',task_status:'Status',task_assign:'Assignee',task_due:'Due',task_filter:'Apply filter',task_all:'All',task_overdue:'Overdue only',task_priority:'Priority',task_create:'Create task',task_title_label:'Title',
 user_title:'Users',user_tier:'Tier',user_scope:'Scope',user_delegate:'Apply tier change',user_email:'Email',user_name:'Name',
 sign_title:'Confirm with your passphrase',sign_desc:'This action requires a fresh signature.',sign_pass:'Passphrase',sign_ok:'Sign and submit',sign_cancel:'Cancel',
 err_creds:'Wrong email or passphrase.',err_net:'Network error. Try again.',err_pass:'Could not decrypt key. Wrong passphrase.',err_match:'Passphrases do not match.',err_token:'Invite token is not valid.',err_pwlen:'Passphrase must be 10 characters or more.',err_nokey:'No keys for this email on this device.',
 ok_saved:'Saved.',working:'Working.',
 lbl_unassigned:'Unassigned',lbl_none:'Nothing here yet.',lbl_back:'Back',
 tier_ndma:'NDMA',tier_state:'State',tier_district:'District',tier_resp:'Responder',tier_vol:'Volunteer'
},
hi:{
 nav_dash:'डैशबोर्ड',nav_proj:'परियोजनाएँ',nav_task:'कार्य',nav_user:'सदस्य',btn_logout:'बाहर निकलें',
 login_title:'साइन इन',login_email:'ईमेल',login_pass:'पासफ़्रेज़',login_btn:'साइन इन',
 login_help:'इस फ़ोन पर कुंजी नहीं?',reg_link:'निमंत्रण स्वीकारें',
 reg_title:'निमंत्रण स्वीकारें',reg_token:'निमंत्रण टोकन',reg_name:'आपका नाम',reg_pass:'पासफ़्रेज़ सेट करें',reg_pass2:'पासफ़्रेज़ की पुष्टि',reg_btn:'कुंजी बनाएँ और जुड़ें',
 reg_help:'निजी कुंजी इस फ़ोन से बाहर नहीं जाती. पासफ़्रेज़ खोया तो पहुँच गई.',reg_done:'खाता तैयार. अब साइन इन करें.',
 dash_title:'सिंहावलोकन',
 t_open:'खुले',t_inp:'चल रहे',t_blk:'अटके',t_done:'पूर्ण',t_over:'बीते',
 dash_recent:'हाल के कार्य',dash_tier:'स्तर के अनुसार',dash_create:'कार्य बनाएँ',
 proj_title:'परियोजनाएँ',proj_new:'नई परियोजना',proj_name:'नाम',proj_desc:'विवरण',proj_create:'बनाएँ',
 proj_archive:'पुरालेख',proj_open:'खोलें',
 task_title:'कार्य',task_new:'नया कार्य',task_status:'स्थिति',task_assign:'सौंपा',task_due:'समय',task_filter:'फ़िल्टर लागू करें',task_all:'सभी',task_overdue:'केवल बीते',task_priority:'प्राथमिकता',task_create:'कार्य बनाएँ',task_title_label:'शीर्षक',
 user_title:'सदस्य',user_tier:'स्तर',user_scope:'क्षेत्र',user_delegate:'स्तर बदलें',user_email:'ईमेल',user_name:'नाम',
 sign_title:'पासफ़्रेज़ से पुष्टि करें',sign_desc:'इस कार्य के लिए नया हस्ताक्षर चाहिए.',sign_pass:'पासफ़्रेज़',sign_ok:'हस्ताक्षर और भेजें',sign_cancel:'रद्द',
 err_creds:'गलत ईमेल या पासफ़्रेज़.',err_net:'संजाल त्रुटि. फिर कोशिश करें.',err_pass:'कुंजी नहीं खुली. पासफ़्रेज़ गलत.',err_match:'पासफ़्रेज़ मेल नहीं खाते.',err_token:'निमंत्रण टोकन सही नहीं.',err_pwlen:'पासफ़्रेज़ कम से कम 10 अक्षर.',err_nokey:'इस ईमेल की कुंजी इस फ़ोन पर नहीं.',
 ok_saved:'सहेज लिया.',working:'चल रहा है.',
 lbl_unassigned:'अनिर्दिष्ट',lbl_none:'अभी कुछ नहीं.',lbl_back:'वापस',
 tier_ndma:'NDMA',tier_state:'राज्य',tier_district:'ज़िला',tier_resp:'उत्तरदाता',tier_vol:'स्वयंसेवक'
}};
const lang=(navigator.language||'en').slice(0,2);
const T=L[lang]||L.en;
document.documentElement.lang=L[lang]?lang+'-IN':'en';

const $=s=>document.querySelector(s);
const $$=s=>[...document.querySelectorAll(s)];
const main=$('#main');
const escMap={'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'};
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>escMap[c]);

const TIER_LABEL={100:T.tier_ndma,80:T.tier_state,60:T.tier_district,40:T.tier_resp,20:T.tier_vol};
const STATUS_KEYS=['open','in_progress','blocked','done','cancelled'];
const STATUS_LABEL={open:T.t_open,in_progress:T.t_inp,blocked:T.t_blk,done:T.t_done,cancelled:'Cancelled'};

const session={
 set(token,email){sessionStorage.setItem(SS,JSON.stringify({token,email}))},
 get(){
  try{
   const r=sessionStorage.getItem(SS);if(!r)return null;
   const w=JSON.parse(r);
   const p=JSON.parse(utf8Dec(b64uDec(w.token.split('.')[1])));
   return Object.assign({},w,p);
  }catch{return null}
 },
 clear(){sessionStorage.removeItem(SS)}
};

async function api(path,opts){
 opts=opts||{};
 const s=session.get();
 const h=Object.assign({'Content-Type':'application/json'},opts.headers||{});
 if(s)h.Authorization='Bearer '+s.token;
 const r=await fetch(API+path,{method:opts.method||'GET',headers:h,body:opts.body===undefined?undefined:JSON.stringify(opts.body)});
 if(r.status===401){session.clear();location.hash='#/login';throw new Error(T.err_creds)}
 let j={};try{j=await r.json()}catch{}
 if(!r.ok){const e=new Error((j.error&&j.error.message)||T.err_net);e.code=j.error&&j.error.code;e.status=r.status;throw e}
 return j;
}

function idb(){return new Promise((res,rej)=>{
 if(!('indexedDB' in self))return rej(new Error('no idb'));
 const r=indexedDB.open(DB,1);
 r.onupgradeneeded=()=>r.result.createObjectStore(STORE,{keyPath:'email'});
 r.onsuccess=()=>res(r.result);
 r.onerror=()=>rej(r.error);
});}
async function getKeyring(email){
 const d=await idb();
 return new Promise((res,rej)=>{
  const t=d.transaction(STORE).objectStore(STORE).get(email);
  t.onsuccess=()=>res(t.result||null);
  t.onerror=()=>rej(t.error);
 });
}
async function putKeyring(rec){
 const d=await idb();
 return new Promise((res,rej)=>{
  const t=d.transaction(STORE,'readwrite').objectStore(STORE).put(rec);
  t.onsuccess=()=>res();
  t.onerror=()=>rej(t.error);
 });
}

const wipe=u8=>{if(u8&&u8.fill)u8.fill(0)};

async function login(email,pass){
 const rec=await getKeyring(email);
 if(!rec)throw new Error(T.err_nokey);
 let priv;
 try{priv=await decryptPriv(rec.salt,rec.iv,rec.ct,pass)}catch{throw new Error(T.err_pass)}
 try{
  const c=await api('/auth/challenge',{method:'POST',body:{email}});
  const sig=sign(priv,utf8(DOMAIN+email+':'+c.challenge_b64));
  const v=await api('/auth/verify',{method:'POST',body:{email,ch_id:c.ch_id,signature_b64:sig}});
  session.set(v.token,email);
 }finally{wipe(priv)}
}

function decodeInvite(tok){
 const parts=String(tok).trim().split('.');
 if(parts.length<2)throw new Error(T.err_token);
 try{return JSON.parse(utf8Dec(b64uDec(parts[1])))}catch{throw new Error(T.err_token)}
}
async function register(token,name,pass){
 const inv=decodeInvite(token);
 if(!inv.email)throw new Error(T.err_token);
 const kp=generateKeypair();
 try{
  const e=await encryptPriv(kp.priv,pass);
  const pubkey_b64=b64(kp.pub);
  await api('/auth/register',{method:'POST',body:{invite_token:token,name,pubkey_b64}});
  await putKeyring({email:inv.email,salt:e.saltB64,iv:e.ivB64,ct:e.ctB64,pubkey_b64,created_at:new Date().toISOString()});
  return inv.email;
 }finally{wipe(kp.priv)}
}

function confirmAction(payload,desc){
 return new Promise(res=>{
  const dlg=$('#dlgSign'),form=$('#fSign'),pass=$('#dlgPass'),err=$('#dlgErr'),cancel=$('#dlgCancel'),descEl=$('#dlgSignDesc'),ok=$('#dlgOk');
  let result=null;
  err.textContent='';pass.value='';descEl.textContent=desc||T.sign_desc;ok.disabled=false;
  const finish=v=>{result=v;dlg.close()};
  const onSubmit=async e=>{
   e.preventDefault();err.textContent='';
   const s=session.get();if(!s||!s.email){finish(null);return}
   const rec=await getKeyring(s.email);
   if(!rec){err.textContent=T.err_nokey;return}
   ok.disabled=true;
   let priv;
   try{priv=await decryptPriv(rec.salt,rec.iv,rec.ct,pass.value)}
   catch{err.textContent=T.err_pass;ok.disabled=false;return}
   try{
    const sig=sign(priv,utf8(JSON.stringify(Object.assign({uid:s.uid,ts:Date.now()},payload))));
    finish(sig);
   }finally{wipe(priv);pass.value=''}
  };
  const onCancel=()=>finish(null);
  const onClick=e=>{if(e.target===dlg)finish(null)};
  const onClose=()=>{
   form.removeEventListener('submit',onSubmit);
   cancel.removeEventListener('click',onCancel);
   dlg.removeEventListener('click',onClick);
   pass.value='';
   res(result);
  };
  form.addEventListener('submit',onSubmit);
  cancel.addEventListener('click',onCancel);
  dlg.addEventListener('click',onClick);
  dlg.addEventListener('close',onClose,{once:true});
  dlg.showModal();
  pass.focus();
 });
}

let usersCache=null;
async function getUsers(force){
 if(usersCache&&!force)return usersCache;
 const r=await api('/users');
 usersCache=r.items||[];
 return usersCache;
}
function userOpts(sel){
 return `<option value="">${esc(T.lbl_unassigned)}</option>`+
  (usersCache||[]).map(u=>`<option value="${esc(u.uid)}"${u.uid===sel?' selected':''}>${esc(u.name)} (${esc(TIER_LABEL[u.tier]||u.tier)})</option>`).join('');
}

function flash(node,msg,cls){node.innerHTML=`<p class="${cls||'muted'}" role=status>${esc(msg)}</p>`}

function viewLogin(){
 main.removeAttribute('aria-busy');
 main.innerHTML=`<section class=card aria-labelledby=hLogin>
  <h1 id=hLogin>${esc(T.login_title)}</h1>
  <form id=fLogin novalidate>
   <label for=lEmail>${esc(T.login_email)}<input type=email id=lEmail name=email autocomplete=username required></label>
   <label for=lPass>${esc(T.login_pass)}<input type=password id=lPass name=pass autocomplete=current-password required></label>
   <p id=lErr role=alert class=err></p>
   <button type=submit>${esc(T.login_btn)}</button>
  </form>
  <p class=help>${esc(T.login_help)} <a href="#/register">${esc(T.reg_link)}</a></p>
 </section>`;
 const f=$('#fLogin'),er=$('#lErr');
 f.addEventListener('submit',async e=>{
  e.preventDefault();er.textContent='';
  const btn=f.querySelector('button[type=submit]');btn.disabled=true;btn.textContent=T.working;
  try{
   await login($('#lEmail').value.trim().toLowerCase(),$('#lPass').value);
   $('#lPass').value='';
   location.hash='#/';
  }catch(err){er.textContent=err.message||T.err_creds;btn.disabled=false;btn.textContent=T.login_btn}
 });
 $('#lEmail').focus();
}

function viewRegister(){
 main.removeAttribute('aria-busy');
 main.innerHTML=`<section class=card aria-labelledby=hReg>
  <h1 id=hReg>${esc(T.reg_title)}</h1>
  <form id=fReg novalidate>
   <label for=rTok>${esc(T.reg_token)}<textarea id=rTok name=tok rows=3 required spellcheck=false></textarea></label>
   <label for=rName>${esc(T.reg_name)}<input id=rName name=name required autocomplete=name></label>
   <label for=rPass>${esc(T.reg_pass)}<input type=password id=rPass name=pass minlength=10 required autocomplete=new-password></label>
   <label for=rPass2>${esc(T.reg_pass2)}<input type=password id=rPass2 name=pass2 minlength=10 required autocomplete=new-password></label>
   <p id=rErr role=alert class=err></p>
   <button type=submit>${esc(T.reg_btn)}</button>
  </form>
  <p class=help>${esc(T.reg_help)}</p>
 </section>`;
 const f=$('#fReg'),er=$('#rErr');
 f.addEventListener('submit',async e=>{
  e.preventDefault();er.textContent='';
  const tok=$('#rTok').value.trim(),name=$('#rName').value.trim(),p1=$('#rPass').value,p2=$('#rPass2').value;
  if(p1.length<10){er.textContent=T.err_pwlen;return}
  if(p1!==p2){er.textContent=T.err_match;return}
  const btn=f.querySelector('button[type=submit]');btn.disabled=true;btn.textContent=T.working;
  try{
   await register(tok,name,p1);
   $('#rPass').value='';$('#rPass2').value='';
   flash(main,T.reg_done,'ok');
   setTimeout(()=>{location.hash='#/login'},800);
  }catch(err){er.textContent=err.message||T.err_net;btn.disabled=false;btn.textContent=T.reg_btn}
 });
 $('#rTok').focus();
}

async function viewDash(){
 const me=session.get();
 main.setAttribute('aria-busy','true');
 main.innerHTML=`<section aria-labelledby=hDash>
  <h1 id=hDash>${esc(T.dash_title)}</h1>
  <p class=muted>${esc(me?(me.scope_path||'')+' · '+(TIER_LABEL[me.tier]||''):'')}</p>
  <div id=tiles class=tiles></div>
  <h2>${esc(T.dash_recent)}</h2>
  <div id=recent></div>
  <div id=byTier></div>
  <p class=row><a class=btn href="#/tasks">${esc(T.dash_create)}</a></p>
 </section>`;
 try{
  const d=await api('/dashboard');
  const c=d.counts||{};
  const tiles=[['open','t_open'],['in_progress','t_inp'],['blocked','t_blk'],['done','t_done'],['overdue','t_over']];
  $('#tiles').innerHTML=tiles.map(([k,lk])=>`<dl class="tile${k==='overdue'?' over':''}"><dt>${esc(T[lk])}</dt><dd>${Number(c[k]||0)}</dd></dl>`).join('');
  const rec=d.recent||[];
  $('#recent').innerHTML=rec.length?renderRecent(rec):`<p class=empty>${esc(T.lbl_none)}</p>`;
  if(d.by_tier&&me&&me.tier===100){
   const rows=Object.entries(d.by_tier).map(([k,v])=>`<li><span>${esc(TIER_LABEL[k]||k)}</span><b>${Number(v)}</b></li>`).join('');
   $('#byTier').innerHTML=`<h2>${esc(T.dash_tier)}</h2><ul class=byline>${rows}</ul>`;
  }
 }catch(err){flash($('#tiles'),err.message||T.err_net,'err')}
 main.removeAttribute('aria-busy');
}
function renderRecent(rows){
 return `<div class=tblwrap><table class=tbl><thead><tr><th>${esc(T.task_title_label)}</th><th>${esc(T.task_status)}</th><th>${esc(T.task_due)}</th></tr></thead><tbody>${
  rows.map(x=>{
   const od=x.due_date&&new Date(x.due_date)<new Date()&&x.status!=='done';
   return `<tr${od?' class=over':''}><td>${esc(x.title)}</td><td>${esc(STATUS_LABEL[x.status]||x.status)}</td><td>${x.due_date?esc(String(x.due_date).slice(0,10)):''}</td></tr>`;
  }).join('')
 }</tbody></table></div>`;
}

async function viewProjects(){
 main.setAttribute('aria-busy','true');
 main.innerHTML=`<section aria-labelledby=hProj>
  <h1 id=hProj>${esc(T.proj_title)}</h1>
  <details><summary>${esc(T.proj_new)}</summary>
   <form id=fNewProj class=new>
    <label>${esc(T.proj_name)}<input name=name required></label>
    <label>${esc(T.proj_desc)}<textarea name=description rows=2></textarea></label>
    <button type=submit>${esc(T.proj_create)}</button>
   </form>
  </details>
  <div id=plist></div>
 </section>`;
 $('#fNewProj').addEventListener('submit',async e=>{
  e.preventDefault();
  const f=Object.fromEntries(new FormData(e.target));
  const btn=e.target.querySelector('button[type=submit]');btn.disabled=true;
  try{await api('/projects',{method:'POST',body:f});viewProjects()}
  catch(err){alert(err.message||T.err_net);btn.disabled=false}
 });
 try{
  const r=await api('/projects');
  const items=r.items||[];
  if(!items.length){$('#plist').innerHTML=`<p class=empty>${esc(T.lbl_none)}</p>`}
  else{
   $('#plist').innerHTML=`<div class=tblwrap><table class=tbl><thead><tr><th>${esc(T.proj_name)}</th><th>${esc(T.proj_desc)}</th><th></th></tr></thead><tbody>${
    items.map(p=>`<tr><td><a href="#/projects/${esc(encodeURIComponent(p.id))}">${esc(p.name)}</a></td><td>${esc(p.description||'')}</td><td><button type=button class=arch data-p="${esc(p.id)}">${esc(T.proj_archive)}</button></td></tr>`).join('')
   }</tbody></table></div>`;
   $$('#plist .arch').forEach(b=>b.addEventListener('click',async()=>{
    const pid=b.dataset.p;
    const sig=await confirmAction({action:'project.archive',target:'tm_projects/'+pid});
    if(!sig)return;
    try{await api('/projects/'+encodeURIComponent(pid),{method:'DELETE',body:{action_signature_b64:sig}});viewProjects()}
    catch(err){alert(err.message||T.err_net)}
   }));
  }
 }catch(err){flash($('#plist'),err.message||T.err_net,'err')}
 main.removeAttribute('aria-busy');
}

async function viewProject(id){
 main.setAttribute('aria-busy','true');
 main.innerHTML=`<section><a class=back href="#/projects">${esc(T.lbl_back)}: ${esc(T.proj_title)}</a><h1 id=projTitle></h1><p id=projDesc class=muted></p><h2>${esc(T.task_title)}</h2><details><summary>${esc(T.task_new)}</summary><form id=fNewTask class=new></form></details><div id=ptasks></div></section>`;
 try{
  const p=await api('/projects/'+encodeURIComponent(id));
  $('#projTitle').textContent=p.name||'';
  $('#projDesc').textContent=p.description||'';
  await getUsers();
  $('#fNewTask').innerHTML=newTaskFields(id);
  $('#fNewTask').addEventListener('submit',async e=>{
   e.preventDefault();
   const f=Object.fromEntries(new FormData(e.target));
   try{await api('/tasks',{method:'POST',body:f});viewProject(id)}
   catch(err){alert(err.message||T.err_net)}
  });
  const t=await api('/tasks?project='+encodeURIComponent(id));
  renderTaskTable($('#ptasks'),t.items||[],()=>viewProject(id));
 }catch(err){flash(main,err.message||T.err_net,'err')}
 main.removeAttribute('aria-busy');
}

function newTaskFields(projectId){
 const projOpts=projectId?`<input type=hidden name=project_id value="${esc(projectId)}">`:`<label>${esc(T.proj_title)}<select name=project_id required id=tnProj></select></label>`;
 return `${projOpts}
  <label>${esc(T.task_title_label)}<input name=title required></label>
  <label>${esc(T.proj_desc)}<textarea name=description rows=2></textarea></label>
  <label>${esc(T.task_priority)}<select name=priority><option value=med>med</option><option value=low>low</option><option value=high>high</option><option value=critical>critical</option></select></label>
  <label>${esc(T.task_due)}<input type=date name=due_date></label>
  <button type=submit>${esc(T.task_create)}</button>`;
}

async function viewTasks(){
 main.setAttribute('aria-busy','true');
 const qs=new URLSearchParams((location.hash.split('?')[1])||'');
 const q=Object.fromEntries(qs);
 main.innerHTML=`<section aria-labelledby=hTask>
  <h1 id=hTask>${esc(T.task_title)}</h1>
  <form id=fFilter class=filter>
   <label>${esc(T.task_status)}<select name=status>
    <option value="">${esc(T.task_all)}</option>
    ${STATUS_KEYS.map(s=>`<option value="${s}"${q.status===s?' selected':''}>${esc(STATUS_LABEL[s]||s)}</option>`).join('')}
   </select></label>
   <label class=chk><input type=checkbox name=overdue${q.overdue?' checked':''}>${esc(T.task_overdue)}</label>
   <button type=submit>${esc(T.task_filter)}</button>
  </form>
  <details><summary>${esc(T.task_new)}</summary><form id=fNewTask class=new></form></details>
  <div id=taskList></div>
 </section>`;
 try{
  await getUsers();
  try{
   const p=await api('/projects');
   const projs=p.items||[];
   $('#fNewTask').innerHTML=newTaskFields(null);
   const sel=$('#tnProj');
   if(sel)sel.innerHTML=projs.map(x=>`<option value="${esc(x.id)}">${esc(x.name)}</option>`).join('');
  }catch{}
  $('#fFilter').addEventListener('submit',e=>{
   e.preventDefault();
   const fd=new FormData(e.target);
   const out=new URLSearchParams();
   for(const [k,v] of fd){if(v)out.set(k,v==='on'?'1':v)}
   location.hash='#/tasks'+(out.toString()?'?'+out:'');
  });
  $('#fNewTask').addEventListener('submit',async e=>{
   e.preventDefault();
   const f=Object.fromEntries(new FormData(e.target));
   try{await api('/tasks',{method:'POST',body:f});viewTasks()}
   catch(err){alert(err.message||T.err_net)}
  });
  const tqs=new URLSearchParams();
  if(q.status)tqs.set('status',q.status);
  if(q.overdue)tqs.set('overdue','1');
  const t=await api('/tasks'+(tqs.toString()?'?'+tqs:''));
  renderTaskTable($('#taskList'),t.items||[],()=>viewTasks());
 }catch(err){flash($('#taskList'),err.message||T.err_net,'err')}
 main.removeAttribute('aria-busy');
}

function renderTaskTable(host,items,reload){
 if(!items.length){host.innerHTML=`<p class=empty>${esc(T.lbl_none)}</p>`;return}
 host.innerHTML=`<div class=tblwrap><table class=tbl><thead><tr><th>${esc(T.task_title_label)}</th><th>${esc(T.task_status)}</th><th>${esc(T.task_assign)}</th><th>${esc(T.task_due)}</th></tr></thead><tbody>${
  items.map(x=>{
   const od=x.due_date&&new Date(x.due_date)<new Date()&&x.status!=='done';
   return `<tr${od?' class=over':''}>
    <td>${esc(x.title)}</td>
    <td><select class=sStatus data-t="${esc(x.id)}" aria-label="${esc(T.task_status)}">${STATUS_KEYS.map(s=>`<option value="${s}"${s===x.status?' selected':''}>${esc(STATUS_LABEL[s]||s)}</option>`).join('')}</select></td>
    <td><select class=sAssign data-t="${esc(x.id)}" data-prev="${esc(x.assignee_uid||'')}" aria-label="${esc(T.task_assign)}">${userOpts(x.assignee_uid)}</select></td>
    <td>${x.due_date?esc(String(x.due_date).slice(0,10)):''}</td>
   </tr>`;
  }).join('')
 }</tbody></table></div>`;
 host.querySelectorAll('select.sStatus').forEach(s=>s.addEventListener('change',async()=>{
  try{await api('/tasks/'+encodeURIComponent(s.dataset.t),{method:'PATCH',body:{status:s.value}})}
  catch(err){alert(err.message||T.err_net);if(reload)reload()}
 }));
 host.querySelectorAll('select.sAssign').forEach(s=>s.addEventListener('change',async()=>{
  const tid=s.dataset.t,prev=s.dataset.prev||'',next=s.value;
  if(prev===next)return;
  const sig=await confirmAction({action:'task.assign',target:'tm_tasks/'+tid,assignee_uid:next||null});
  if(!sig){s.value=prev;return}
  try{
   await api('/tasks/'+encodeURIComponent(tid),{method:'PATCH',body:{assignee_uid:next||null,action_signature_b64:sig}});
   s.dataset.prev=next;
  }catch(err){alert(err.message||T.err_net);s.value=prev}
 }));
}

async function viewUsers(){
 main.setAttribute('aria-busy','true');
 main.innerHTML=`<section aria-labelledby=hUsers><h1 id=hUsers>${esc(T.user_title)}</h1><div id=ulist></div></section>`;
 try{
  const items=await getUsers(true);
  const me=session.get();
  const tiers=[100,80,60,40,20].filter(t=>t<=(me?me.tier:0));
  if(!items.length){$('#ulist').innerHTML=`<p class=empty>${esc(T.lbl_none)}</p>`}
  else{
   $('#ulist').innerHTML=`<div class=tblwrap><table class=tbl><thead><tr><th>${esc(T.user_name)}</th><th>${esc(T.user_email)}</th><th>${esc(T.user_tier)}</th><th>${esc(T.user_scope)}</th><th></th></tr></thead><tbody>${
    items.map(u=>`<tr>
     <td>${esc(u.name)}</td>
     <td>${esc(u.email)}</td>
     <td><span class="tag t${esc(u.tier)}">${esc(TIER_LABEL[u.tier]||u.tier)}</span> <select class=uTier data-u="${esc(u.uid)}" data-prev="${esc(u.tier)}" aria-label="${esc(T.user_tier)}">${tiers.map(t=>`<option value="${t}"${t===u.tier?' selected':''}>${esc(TIER_LABEL[t])}</option>`).join('')}</select></td>
     <td>${esc(u.scope_path||'')}</td>
     <td><button type=button class=uApply data-u="${esc(u.uid)}">${esc(T.user_delegate)}</button></td>
    </tr>`).join('')
   }</tbody></table></div>`;
   $$('#ulist .uApply').forEach(b=>b.addEventListener('click',async()=>{
    const uid=b.dataset.u;
    const sel=$('#ulist').querySelector('select.uTier[data-u="'+uid.replace(/"/g,'\\"')+'"]');
    const newTier=Number(sel.value);
    const prev=Number(sel.dataset.prev);
    if(newTier===prev)return;
    const sig=await confirmAction({action:'user.delegate',target:'tm_users/'+uid,tier:newTier});
    if(!sig){sel.value=prev;return}
    try{
     await api('/users/'+encodeURIComponent(uid)+'/delegate',{method:'POST',body:{tier:newTier,action_signature_b64:sig}});
     usersCache=null;
     viewUsers();
    }catch(err){alert(err.message||T.err_net);sel.value=prev}
   }));
  }
 }catch(err){flash($('#ulist'),err.message||T.err_net,'err')}
 main.removeAttribute('aria-busy');
}

function setNavCurrent(path){
 $$('#nav a').forEach(a=>{
  const ar=a.getAttribute('href').replace(/^#/,'');
  if(ar===path)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');
 });
}

function route(){
 const h=location.hash||'#/';
 const path=h.replace(/^#/,'').split('?')[0]||'/';
 const s=session.get();
 const auth=path==='/login'||path==='/register';
 if(!s&&!auth){location.hash='#/login';return}
 if(s&&auth){location.hash='#/';return}
 const r=path==='/'?'dash':path.split('/')[1]||'dash';
 document.body.dataset.route=r;
 setNavCurrent(path);
 if(path==='/login')return viewLogin();
 if(path==='/register')return viewRegister();
 if(path==='/')return viewDash();
 if(path==='/projects')return viewProjects();
 if(path.startsWith('/projects/'))return viewProject(decodeURIComponent(path.slice('/projects/'.length)));
 if(path==='/tasks')return viewTasks();
 if(path==='/users')return viewUsers();
 main.innerHTML=`<p class=empty>${esc(T.lbl_none)}</p>`;
}

$('#btnLogout').addEventListener('click',()=>{session.clear();usersCache=null;location.hash='#/login'});
$$('#nav a').forEach(a=>{
 const k=a.dataset.r;
 if(k&&T['nav_'+k])a.textContent=T['nav_'+k];
});
$('#btnLogout').textContent=T.btn_logout;

window.addEventListener('hashchange',route);
route();
