import {hmacActionSig,canonicalActionMessage,b64,b64Dec,b64u,b64uDec,utf8,utf8Dec} from './auth-client.js';

const API='/api/v1/tm';
const SS='aether-tm-session';
const DB='aether-tm';

const L={
en:{
 nav_dash:'Dashboard',nav_proj:'Projects',nav_task:'Tasks',nav_units:'Resources',nav_disp:'Dispatches',nav_user:'Users',btn_logout:'Log out',
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
 tier_ndma:'NDMA',tier_state:'State',tier_district:'District',tier_resp:'Responder',tier_vol:'Volunteer',
 disp_title:'Dispatches',disp_mine:'Mine',disp_team:'Team',disp_pending:'Pending review',
 disp_time:'Time',disp_caller:'Caller',disp_urgency:'Urgency',disp_summary:'Summary',disp_loc:'Location',disp_status:'Status',disp_actions:'Actions',
 disp_open:'Open',disp_escalate:'Escalate',disp_review:'Mark reviewed',disp_note_label:'Note (optional)',
 status_none:'No review',status_pending:'Pending review',status_escalated:'Escalated',status_auto:'Auto-escalated',status_reviewed:'Reviewed',
 user_pol:'Escalation policy',pol_auto:'Auto-escalate',pol_manual:'Manual review',pol_none:'No review needed',
 demo_banner:'Demo mode. The passphrase below is published on the demo portal. Do not reuse this account in production.',
 unit_title:'Resources',unit_new:'Add unit',unit_create:'Create unit',unit_name:'Name',unit_phone:'Contact phone',unit_type:'Type',unit_capacity:'Capacity',unit_status:'Status',unit_scope:'Home base',unit_archive:'Archive',unit_apply_status:'Update status',
 dss_title:'DSS suggestions',dss_score:'Score',dss_reason:'Reason',dss_dist:'Distance',dss_assign:'Assign',dss_none:'No suitable unit available right now.',
 asn_title:'Active assignments',asn_eta:'ETA minutes',asn_note:'Note',asn_assign_btn:'Assign and sign',asn_manual:'Manual assign',asn_pick:'Pick a unit',asn_mark_enroute:'Mark en route',asn_mark_onscene:'Mark on scene',asn_mark_done:'Mark resolved',asn_cancel:'Cancel',
 disp_pending_count:'Pending in scope',
 ws_received:'Received',ws_under_review:'Under review',ws_resources_assigned:'Resources assigned',ws_en_route:'En route',ws_on_scene:'On scene',ws_resolved:'Resolved',ws_cancelled:'Cancelled'
},
hi:{
 nav_dash:'डैशबोर्ड',nav_proj:'परियोजनाएँ',nav_task:'कार्य',nav_units:'संसाधन',nav_disp:'प्रेषण',nav_user:'सदस्य',btn_logout:'बाहर निकलें',
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
 tier_ndma:'NDMA',tier_state:'राज्य',tier_district:'ज़िला',tier_resp:'उत्तरदाता',tier_vol:'स्वयंसेवक',
 disp_title:'प्रेषण',disp_mine:'मेरे',disp_team:'टीम',disp_pending:'समीक्षा लंबित',
 disp_time:'समय',disp_caller:'कॉलर',disp_urgency:'अति आवश्यकता',disp_summary:'सारांश',disp_loc:'स्थान',disp_status:'स्थिति',disp_actions:'क्रिया',
 disp_open:'खोलें',disp_escalate:'ऊपर भेजें',disp_review:'समीक्षित',disp_note_label:'टिप्पणी (वैकल्पिक)',
 status_none:'समीक्षा नहीं',status_pending:'समीक्षा लंबित',status_escalated:'ऊपर भेजा',status_auto:'स्वत: भेजा',status_reviewed:'समीक्षित',
 user_pol:'एस्केलेशन नीति',pol_auto:'स्वत: ऊपर भेजें',pol_manual:'मैन्युअल समीक्षा',pol_none:'समीक्षा की ज़रूरत नहीं',
 demo_banner:'डेमो मोड. नीचे का पासफ़्रेज़ डेमो पोर्टल पर सार्वजनिक है. इस खाते को असली काम में दोबारा उपयोग न करें.',
 unit_title:'संसाधन',unit_new:'नया संसाधन',unit_create:'जोड़ें',unit_name:'नाम',unit_phone:'फ़ोन',unit_type:'प्रकार',unit_capacity:'क्षमता',unit_status:'स्थिति',unit_scope:'मूल स्थान',unit_archive:'पुरालेख',unit_apply_status:'स्थिति अद्यतन',
 dss_title:'सुझाव',dss_score:'स्कोर',dss_reason:'कारण',dss_dist:'दूरी',dss_assign:'सौंपें',dss_none:'अभी कोई इकाई उपलब्ध नहीं.',
 asn_title:'सक्रिय असाइनमेंट',asn_eta:'ईटीए मिनट',asn_note:'टिप्पणी',asn_assign_btn:'सौंपें और हस्ताक्षर',asn_manual:'मैन्युअल',asn_pick:'इकाई चुनें',asn_mark_enroute:'रवाना',asn_mark_onscene:'पहुँच गया',asn_mark_done:'समाप्त',asn_cancel:'रद्द',
 disp_pending_count:'क्षेत्र में लंबित',
 ws_received:'प्राप्त',ws_under_review:'समीक्षा में',ws_resources_assigned:'संसाधन तय',ws_en_route:'रवाना',ws_on_scene:'पहुँच गया',ws_resolved:'समाप्त',ws_cancelled:'रद्द'
},
ta:{
 nav_dash:'கட்டுப்பாடு',nav_proj:'திட்டங்கள்',nav_task:'பணிகள்',nav_disp:'அனுப்புகைகள்',nav_user:'பயனர்கள்',btn_logout:'வெளியேறு',
 disp_title:'அனுப்புகைகள்',disp_mine:'என்னுடையது',disp_team:'குழு',disp_pending:'மதிப்பாய்வு நிலுவையில்',
 disp_time:'நேரம்',disp_caller:'அழைப்பாளர்',disp_urgency:'அவசரம்',disp_summary:'சுருக்கம்',disp_loc:'இடம்',disp_status:'நிலை',disp_actions:'செயல்கள்',
 disp_open:'திற',disp_escalate:'மேலே அனுப்பு',disp_review:'மதிப்பாய்வு செய்தது',disp_note_label:'குறிப்பு (விருப்பம்)',
 status_none:'மதிப்பாய்வு தேவையில்லை',status_pending:'மதிப்பாய்வு நிலுவையில்',status_escalated:'மேலே அனுப்பப்பட்டது',status_auto:'தானாக மேலே அனுப்பப்பட்டது',status_reviewed:'மதிப்பாய்வு செய்யப்பட்டது',
 user_pol:'எஸ்கலேஷன் கொள்கை',pol_auto:'தானியங்கி',pol_manual:'கைமுறை மதிப்பாய்வு',pol_none:'மதிப்பாய்வு வேண்டாம்'
},
bn:{
 nav_dash:'ড্যাশবোর্ড',nav_proj:'প্রকল্প',nav_task:'কাজ',nav_disp:'প্রেরণ',nav_user:'সদস্য',btn_logout:'বের হন',
 disp_title:'প্রেরণ',disp_mine:'আমার',disp_team:'দল',disp_pending:'পর্যালোচনা বাকি',
 disp_time:'সময়',disp_caller:'কলকারী',disp_urgency:'জরুরি',disp_summary:'সারসংক্ষেপ',disp_loc:'অবস্থান',disp_status:'অবস্থা',disp_actions:'ক্রিয়া',
 disp_open:'খুলুন',disp_escalate:'উপরে পাঠান',disp_review:'পর্যালোচিত',disp_note_label:'মন্তব্য (ঐচ্ছিক)',
 status_none:'পর্যালোচনার দরকার নেই',status_pending:'পর্যালোচনা বাকি',status_escalated:'উপরে পাঠানো',status_auto:'স্বয়ং উপরে পাঠানো',status_reviewed:'পর্যালোচিত',
 user_pol:'এসকেলেশন নীতি',pol_auto:'স্বয়ংক্রিয়',pol_manual:'হাতে পর্যালোচনা',pol_none:'পর্যালোচনা প্রয়োজন নেই'
}};
// 15 locales. en/hi/ta/bn ship inline (above) so first paint never
// blocks; the other 11 lazy-load from /i18n/<code>.json on switch and
// shallow-merge into L[code]. The dispatcher's chosen locale persists
// per-uid in tm_prefs (`locale:<uid>`).
const LANGS=[['en','English'],['hi','हिंदी'],['ta','தமிழ்'],['bn','বাংলা'],['ml','മലയാളം'],['te','తెలుగు'],['mr','मराठी'],['or','ଓଡ଼ିଆ'],['gu','ગુજરાતી'],['pa','ਪੰਜਾਬੀ'],['kn','ಕನ್ನಡ'],['ur','اردو'],['as','অসমীয়া'],['ne','नेपाली'],['mai','मैथिली']];
const LCODES=LANGS.map(x=>x[0]);
let lang=(navigator.language||'en').slice(0,2);
if(!LCODES.includes(lang))lang='en';
let T=L[lang]||L.en;
document.documentElement.lang=lang+'-IN';
document.documentElement.dir=lang==='ur'?'rtl':'ltr';
async function loadDispatcherPack(code){
 if(L[code]&&Object.keys(L[code]).length>20)return L[code];
 try{
  const r=await fetch('/i18n/'+encodeURIComponent(code)+'.json',{cache:'force-cache'});
  if(!r.ok)return null;
  const j=await r.json();
  // SOS shell strings overlap on the dispatcher only weakly. Merge
  // them under their own keys (sos_*) so they do not clobber the
  // dispatcher namespace, while leaving English fallbacks intact.
  const mapped={};for(const k of Object.keys(j))mapped['sos_'+k]=j[k];
  L[code]=Object.assign({},L.en||{},L[code]||{},mapped);
  return L[code];
 }catch{return null}
}
async function setDispatcherLocale(code){
 if(!LCODES.includes(code))code='en';
 if(code!=='en'&&code!=='hi'&&code!=='ta'&&code!=='bn'){await loadDispatcherPack(code)}
 lang=code;T=L[code]||L.en;
 document.documentElement.lang=lang+'-IN';
 document.documentElement.dir=lang==='ur'?'rtl':'ltr';
 const me=session&&session.get&&session.get();
 if(me&&me.uid)await _prefPut('locale:'+me.uid,code);
 const sel=document.querySelector('#langPick');if(sel)sel.value=code;
 // Re-paint nav and route (which re-renders the current view with new T).
 hydrateNav();
 try{route()}catch{}
}

const $=s=>document.querySelector(s);
const $$=s=>[...document.querySelectorAll(s)];
const main=$('#main');
const escMap={'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'};
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>escMap[c]);

const TIER_LABEL={100:T.tier_ndma,80:T.tier_state,60:T.tier_district,40:T.tier_resp,20:T.tier_vol};
const STATUS_KEYS=['open','in_progress','blocked','done','cancelled'];
const STATUS_LABEL={open:T.t_open,in_progress:T.t_inp,blocked:T.t_blk,done:T.t_done,cancelled:'Cancelled'};

// Compact bearer is opaque to the client; uid + tier + scope_path now
// arrive in the verify response body and are stashed alongside the
// token. The 32-byte action_key (returned ONCE at login) signs every
// per-action HMAC. The server rotates it on each verified action and
// returns the next key in X-Next-Action-Key headers.
//
// Storage moved from sessionStorage to IndexedDB store 'tm_session' so
// the service worker can read the bearer during background sync. The
// in-memory cache (_sessCache) is the read-path; writes mirror to IDB
// asynchronously. Encryption-at-rest uses a non-extractable AES-GCM
// CryptoKey held in IDB; same blast radius as today (unprotected once
// the device is unlocked) but accessible from the SW.
const STORE_SESS='tm_session',STORE_SKEY='tm_session_key',STORE_PREFS='tm_prefs',STORE_VOICE='voice_template';
let _sessCache=null,_sessKey=null;
function _idbOpen(){return new Promise((res,rej)=>{
 if(!('indexedDB' in self))return rej(new Error('no idb'));
 // v3 adds tm_prefs (locale per uid) + voice_template; both shared
 // with the SOS PWA which opens the same DB at v3.
 const r=indexedDB.open(DB,3);
 r.onupgradeneeded=()=>{
  const d=r.result;
  // Legacy 'keyrings' store retained on schema so pre-password-auth IDBs upgrade cleanly.
  if(!d.objectStoreNames.contains('keyrings'))d.createObjectStore('keyrings',{keyPath:'email'});
  if(!d.objectStoreNames.contains(STORE_SESS))d.createObjectStore(STORE_SESS);
  if(!d.objectStoreNames.contains(STORE_SKEY))d.createObjectStore(STORE_SKEY);
  if(!d.objectStoreNames.contains(STORE_PREFS))d.createObjectStore(STORE_PREFS);
  if(!d.objectStoreNames.contains(STORE_VOICE))d.createObjectStore(STORE_VOICE);
 };
 r.onsuccess=()=>res(r.result);
 r.onerror=()=>rej(r.error);
});}
async function _prefGet(k){try{const d=await _idbOpen();return await new Promise((r,j)=>{const t=d.transaction(STORE_PREFS,'readonly').objectStore(STORE_PREFS).get(k);t.onsuccess=()=>r(t.result==null?null:t.result);t.onerror=()=>j(t.error)})}catch{return null}}
async function _prefPut(k,v){try{const d=await _idbOpen();await new Promise((r,j)=>{const t=d.transaction(STORE_PREFS,'readwrite').objectStore(STORE_PREFS).put(v,k);t.onsuccess=()=>r();t.onerror=()=>j(t.error)})}catch{}}
async function _sessKeyEnsure(d){
 if(_sessKey)return _sessKey;
 const got=await new Promise((res,rej)=>{const t=d.transaction(STORE_SKEY,'readonly').objectStore(STORE_SKEY).get('k');t.onsuccess=()=>res(t.result||null);t.onerror=()=>rej(t.error)});
 if(got){_sessKey=got;return got}
 _sessKey=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
 await new Promise((res,rej)=>{const t=d.transaction(STORE_SKEY,'readwrite').objectStore(STORE_SKEY).put(_sessKey,'k');t.onsuccess=()=>res();t.onerror=()=>rej(t.error)});
 return _sessKey;
}
async function _sessRead(){
 try{
  const d=await _idbOpen(),k=await _sessKeyEnsure(d);
  const rec=await new Promise((res,rej)=>{const t=d.transaction(STORE_SESS,'readonly').objectStore(STORE_SESS).get('s');t.onsuccess=()=>res(t.result||null);t.onerror=()=>rej(t.error)});
  if(!rec||!rec.iv||!rec.ct)return null;
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:rec.iv},k,rec.ct);
  return JSON.parse(new TextDecoder().decode(pt));
 }catch{return null}
}
async function _sessWrite(rec){
 try{
  const d=await _idbOpen(),k=await _sessKeyEnsure(d);
  if(!rec){
   await new Promise((res,rej)=>{const t=d.transaction(STORE_SESS,'readwrite').objectStore(STORE_SESS).delete('s');t.onsuccess=()=>res();t.onerror=()=>rej(t.error)});
   return;
  }
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},k,new TextEncoder().encode(JSON.stringify(rec)));
  await new Promise((res,rej)=>{const t=d.transaction(STORE_SESS,'readwrite').objectStore(STORE_SESS).put({iv,ct},'s');t.onsuccess=()=>res();t.onerror=()=>rej(t.error)});
 }catch{/* best-effort; cache stays */}
}
const session={
 async init(){_sessCache=await _sessRead();return _sessCache},
 set(rec){_sessCache=rec;_sessWrite(rec)},
 get(){return _sessCache},
 patch(p){_sessCache=Object.assign({},_sessCache||{},p);_sessWrite(_sessCache)},
 clear(){_sessCache=null;_sessWrite(null)}
};

async function api(path,opts){
 opts=opts||{};
 const s=session.get();
 const h=Object.assign({'Content-Type':'application/json'},opts.headers||{});
 if(s&&s.token)h.Authorization='Bearer '+s.token;
 // sigSpec={action,target} → compute HMAC over canonical(uid,action,target,ts,key_id)
 // and attach as X-Action-* headers. Bandwidth: ~50 B vs ~7 KB ML-DSA.
 if(opts.sigSpec&&s&&s.action_key_b64&&s.key_id&&s.uid){
  const ts=Math.floor(Date.now()/1000);
  const keyBytes=b64Dec(s.action_key_b64);
  const sig=await hmacActionSig(keyBytes,{uid:s.uid,action:opts.sigSpec.action,target:opts.sigSpec.target,ts,key_id:s.key_id});
  keyBytes.fill(0);
  h['X-Action-Sig']=sig;
  h['X-Action-Ts']=String(ts);
  h['X-Action-Key-Id']=s.key_id;
 }
 const r=await fetch(API+path,{method:opts.method||'GET',headers:h,body:opts.body===undefined?undefined:JSON.stringify(opts.body)});
 const nextKey=r.headers.get('X-Next-Action-Key');
 const nextKeyId=r.headers.get('X-Next-Action-Key-Id');
 if(nextKey&&nextKeyId&&session.get()){
  session.patch({action_key_b64:nextKey,key_id:nextKeyId});
 }
 if(r.status===401){session.clear();location.hash='#/login';throw new Error(T.err_creds)}
 let j={};try{j=await r.json()}catch{}
 if(!r.ok){const e=new Error((j.error&&j.error.message)||T.err_net);e.code=j.error&&j.error.code;e.status=r.status;throw e}
 return j;
}

// MLP login posture: server-side scrypt over plaintext password.
// Bearer + per-action HMAC unchanged; QR multi-device is retired.
async function login(email,pass){
 const v=await api('/auth/login',{method:'POST',body:{email,password:pass}});
 if(!v||!v.token||!v.user)throw new Error(T.err_creds);
 session.set({
  token:v.token,
  email:v.user.email||email,
  uid:v.user.uid,
  tier:v.user.tier,
  scope_path:v.user.scope_path,
  action_key_b64:v.action_key_b64,
  key_id:v.key_id
 });
}

async function register(token,name,pass){
 const r=await api('/auth/register',{method:'POST',body:{invite_id:token,name,password:pass}});
 return (r&&r.email)||'';
}

// Per-action signing is now an HMAC over a session-bound key, computed
// inline in api(). The old passphrase-prompt modal is gone for the
// fast path. We keep the helper as a thin guard so call sites can
// short-circuit if the session lost its action key (e.g. SW reloaded
// the tab without the live keying material) and bail early with a
// re-login.
function actionReady(){
 const s=session.get();
 return !!(s&&s.token&&s.action_key_b64&&s.key_id&&s.uid);
}
function requireActionKey(){
 if(actionReady())return true;
 session.clear();
 location.hash='#/login';
 return false;
}

let usersCache=null;
async function getUsers(force){
 if(usersCache&&!force)return usersCache;
 const r=await api('/users');
 usersCache=r.users||r.items||[];
 return usersCache;
}
function userOpts(sel){
 return `<option value="">${esc(T.lbl_unassigned)}</option>`+
  (usersCache||[]).map(u=>`<option value="${esc(u.uid)}"${u.uid===sel?' selected':''}>${esc(u.name)} (${esc(TIER_LABEL[u.tier]||u.tier)})</option>`).join('');
}

function flash(node,msg,cls){node.innerHTML=`<p class="${cls||'muted'}" role=status>${esc(msg)}</p>`}

const DEMO_PASS='aether-demo-2026';
// Demo identities are inlined so the login page does not pay an extra
// /demo/credentials.json round trip on 2G. Passwords are server-side
// only; this list is purely a label/email selector for one-click demo.
const DEMO_USERS=[
 {email:'demo.ndma@aether.dmj.one',         tier_name:'NDMA'},
 {email:'demo.state@aether.dmj.one',        tier_name:'SDMA'},
 {email:'demo.district@aether.dmj.one',     tier_name:'DDMA'},
 {email:'demo.responder@aether.dmj.one',    tier_name:'Subdivisional'},
 {email:'demo.volunteer@aether.dmj.one',    tier_name:'Volunteer'}
];
function viewLogin(){
 main.removeAttribute('aria-busy');
 const qs=new URLSearchParams((location.hash.split('?')[1])||'');
 const qEmail=(qs.get('email')||'').trim().toLowerCase();
 const next=qs.get('next')||'';
 const safeNext=/^\/[A-Za-z0-9\/_\-.?#=&%]*$/.test(next)?next:'';
 const isDemo=qs.get('demo')==='1';
 main.innerHTML=`<section class=card aria-labelledby=hLogin>
  <h1 id=hLogin>${esc(T.login_title)}</h1>
  <p id=lBanner></p>
  <details id=demoBox><summary>${esc(T.demo_pick||'Use a demo account (one click)')}</summary>
   <p class=help>${esc(T.demo_pick_help||'Sign in instantly with a published demo identity. The passphrase is auto-filled.')}</p>
   <div id=demoList class=row></div>
   <p id=demoErr role=alert class=err></p>
  </details>
  <form id=fLogin novalidate>
   <label for=lEmail>${esc(T.login_email)}<input type=email id=lEmail name=email autocomplete=username required value="${esc(qEmail)}"></label>
   <label for=lPass>${esc(T.login_pass)}<input type=password id=lPass name=pass autocomplete=current-password required></label>
   <p id=lErr role=alert class=err></p>
   <button type=submit>${esc(T.login_btn)}</button>
  </form>
  <p class=help>${esc(T.login_help)} <a href="#/register">${esc(T.reg_link)}</a></p>
 </section>`;
 const f=$('#fLogin'),er=$('#lErr'),banner=$('#lBanner');
 if(isDemo){
  banner.setAttribute('role','note');
  banner.className='demoBanner';
  const b=document.createElement('b');b.textContent=(T.demo_banner||'Demo mode.').split('.')[0]+'.';
  banner.append(b,' ',(T.demo_banner||'The passphrase below is published. Do not reuse this account in production.').split('.').slice(1).join('.').trim());
  $('#lPass').value=DEMO_PASS;
 }
 const submit=async()=>{er.textContent='';
  const btn=f.querySelector('button[type=submit]');btn.disabled=true;btn.textContent=T.working;
  try{
   await login($('#lEmail').value.trim().toLowerCase(),$('#lPass').value);
   $('#lPass').value='';
   if(safeNext){location.assign(safeNext);return}
   location.hash='#/';
  }catch(err){er.textContent=err.message||T.err_creds;btn.disabled=false;btn.textContent=T.login_btn}
 };
 f.addEventListener('submit',e=>{e.preventDefault();submit()});
 const dList=$('#demoList'),dErr=$('#demoErr');
 for(const c of DEMO_USERS){
  const b=document.createElement('button');b.type='button';b.className='demoChip';
  b.setAttribute('aria-label',c.tier_name+' demo account, '+c.email);
  const t=document.createElement('b');t.textContent=c.tier_name;
  const s=document.createElement('span');s.textContent=c.email;
  b.append(t,s);
  b.addEventListener('click',async()=>{dErr.textContent='';
   const all=dList.querySelectorAll('.demoChip');all.forEach(x=>x.disabled=true);
   $('#lEmail').value=c.email;$('#lPass').value=DEMO_PASS;
   try{await submit()}catch(err){dErr.textContent=(err.message||String(err));all.forEach(x=>x.disabled=false)}
  });
  dList.append(b);
 }
 if(qEmail)$('#lPass').focus();else $('#lEmail').focus();
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
  const [d,recent]=await Promise.all([
   api('/dashboard'),
   api('/tasks?limit=5').catch(()=>({tasks:[]}))
  ]);
  const bs=(d.tasks&&d.tasks.by_status)||{};
  const c={open:bs.open||0,in_progress:bs.in_progress||0,blocked:bs.blocked||0,done:bs.done||0,overdue:(d.tasks&&d.tasks.overdue)||0};
  const tiles=[['open','t_open'],['in_progress','t_inp'],['blocked','t_blk'],['done','t_done'],['overdue','t_over']];
  $('#tiles').innerHTML=tiles.map(([k,lk])=>`<dl class="tile${k==='overdue'?' over':''}"><dt>${esc(T[lk])}</dt><dd>${Number(c[k]||0)}</dd></dl>`).join('');
  const rec=(recent.tasks||recent.items||[]).slice(0,5);
  $('#recent').innerHTML=rec.length?renderRecent(rec):`<p class=empty>${esc(T.lbl_none)}</p>`;
  if(d.by_tier&&me&&me.tier===100){
   const rows=Object.entries(d.by_tier).map(([k,v])=>`<li><span>${esc(TIER_LABEL[k]||k)}</span><b>${Number(v)}</b></li>`).join('');
   $('#byTier').innerHTML=`<h2>${esc(T.dash_tier)}</h2><ul class=byline>${rows}</ul>`;
  }
 }catch(err){flash($('#tiles'),err.message||T.err_net,'err')}
 main.removeAttribute('aria-busy');
}
function renderRecent(rows){
 const lTitle=esc(T.task_title_label),lStatus=esc(T.task_status),lDue=esc(T.task_due);
 return `<div class=tblwrap><table class=tbl><thead><tr><th>${lTitle}</th><th>${lStatus}</th><th>${lDue}</th></tr></thead><tbody>${
  rows.map(x=>{
   const od=x.due_date&&new Date(x.due_date)<new Date()&&x.status!=='done';
   return `<tr${od?' class=over':''}><td data-label="${lTitle}">${esc(x.title)}</td><td data-label="${lStatus}">${esc(STATUS_LABEL[x.status]||x.status)}</td><td data-label="${lDue}">${x.due_date?esc(String(x.due_date).slice(0,10)):''}</td></tr>`;
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
  const items=r.projects||r.items||[];
  if(!items.length){$('#plist').innerHTML=`<p class=empty>${esc(T.lbl_none)}</p>`}
  else{
   const lN=esc(T.proj_name),lD=esc(T.proj_desc);
   $('#plist').innerHTML=`<div class=tblwrap><table class=tbl><thead><tr><th>${lN}</th><th>${lD}</th><th></th></tr></thead><tbody>${
    items.map(p=>`<tr><td data-label="${lN}"><a href="#/projects/${esc(encodeURIComponent(p.pid||p.id))}">${esc(p.name)}</a></td><td data-label="${lD}">${esc(p.description||'')}</td><td><button type=button class=arch data-p="${esc(p.pid||p.id)}">${esc(T.proj_archive)}</button></td></tr>`).join('')
   }</tbody></table></div>`;
   $$('#plist .arch').forEach(b=>b.addEventListener('click',async()=>{
    const pid=b.dataset.p;
    if(!requireActionKey())return;
    try{await api('/projects/'+encodeURIComponent(pid),{method:'DELETE',body:{},sigSpec:{action:'project.archive',target:'project.archive|'+pid}});viewProjects()}
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
  renderTaskTable($('#ptasks'),t.tasks||t.items||[],()=>viewProject(id));
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
  renderTaskTable($('#taskList'),t.tasks||t.items||[],()=>viewTasks());
 }catch(err){flash($('#taskList'),err.message||T.err_net,'err')}
 main.removeAttribute('aria-busy');
}

function renderTaskTable(host,items,reload){
 if(!items.length){host.innerHTML=`<p class=empty>${esc(T.lbl_none)}</p>`;return}
 const lTitle=esc(T.task_title_label),lStatus=esc(T.task_status),lAssign=esc(T.task_assign),lDue=esc(T.task_due);
 host.innerHTML=`<div class=tblwrap><table class=tbl><thead><tr><th>${lTitle}</th><th>${lStatus}</th><th>${lAssign}</th><th>${lDue}</th></tr></thead><tbody>${
  items.map(x=>{
   const od=x.due_date&&new Date(x.due_date)<new Date()&&x.status!=='done';
   return `<tr${od?' class=over':''}>
    <td data-label="${lTitle}">${esc(x.title)}</td>
    <td data-label="${lStatus}"><select class=sStatus data-t="${esc(x.tid||x.id)}" aria-label="${lStatus}">${STATUS_KEYS.map(s=>`<option value="${s}"${s===x.status?' selected':''}>${esc(STATUS_LABEL[s]||s)}</option>`).join('')}</select></td>
    <td data-label="${lAssign}"><select class=sAssign data-t="${esc(x.tid||x.id)}" data-prev="${esc(x.assignee_uid||'')}" aria-label="${lAssign}">${userOpts(x.assignee_uid)}</select></td>
    <td data-label="${lDue}">${x.due_date?esc(String(x.due_date).slice(0,10)):''}</td>
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
  if(!requireActionKey()){s.value=prev;return}
  try{
   await api('/tasks/'+encodeURIComponent(tid),{method:'PATCH',body:{assignee_uid:next||null},sigSpec:{action:'task.assign',target:'task.assign|'+tid+'|'+(next||'')}});
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
   const lN=esc(T.user_name),lE=esc(T.user_email),lT=esc(T.user_tier),lS=esc(T.user_scope),lP=esc(T.user_pol);
   $('#ulist').innerHTML=`<div class=tblwrap><table class=tbl><thead><tr><th>${lN}</th><th>${lE}</th><th>${lT}</th><th>${lS}</th><th>${lP}</th><th></th></tr></thead><tbody>${
    items.map(u=>{
     const canPolicy=me&&me.tier>u.tier;
     const curPol=u.escalation_policy||'manual_review';
     return `<tr>
     <td data-label="${lN}">${esc(u.name)}</td>
     <td data-label="${lE}">${esc(u.email)}</td>
     <td data-label="${lT}"><span class="tag t${esc(u.tier)}">${esc(TIER_LABEL[u.tier]||u.tier)}</span> <select class=uTier data-u="${esc(u.uid)}" data-prev="${esc(u.tier)}" aria-label="${lT}">${tiers.map(t=>`<option value="${t}"${t===u.tier?' selected':''}>${esc(TIER_LABEL[t])}</option>`).join('')}</select></td>
     <td data-label="${lS}">${esc(u.scope_path||'')}</td>
     <td data-label="${lP}">${canPolicy?`<select class=uPol data-u="${esc(u.uid)}" data-prev="${esc(curPol)}" aria-label="${lP}">${POLICY_KEYS.map(p=>`<option value="${p}"${p===curPol?' selected':''}>${esc(T[POLICY_LABEL[p]]||p)}</option>`).join('')}</select>`:`<span class=muted>${esc(T[POLICY_LABEL[curPol]]||curPol)}</span>`}</td>
     <td><button type=button class=uApply data-u="${esc(u.uid)}">${esc(T.user_delegate)}</button></td>
    </tr>`}).join('')
   }</tbody></table></div>`;
   $$('#ulist .uApply').forEach(b=>b.addEventListener('click',async()=>{
    const uid=b.dataset.u;
    const sel=$('#ulist').querySelector('select.uTier[data-u="'+uid.replace(/"/g,'\\"')+'"]');
    const newTier=Number(sel.value);
    const prev=Number(sel.dataset.prev);
    if(newTier===prev)return;
    if(!requireActionKey()){sel.value=prev;return}
    try{
     await api('/users/'+encodeURIComponent(uid)+'/delegate',{method:'POST',body:{new_tier:newTier},sigSpec:{action:'user.delegate',target:'delegate|'+uid+'|'+newTier}});
     usersCache=null;
     viewUsers();
    }catch(err){alert(err.message||T.err_net);sel.value=prev}
   }));
   $$('#ulist .uPol').forEach(s=>s.addEventListener('change',async()=>{
    const uid=s.dataset.u,prev=s.dataset.prev,next=s.value;
    if(prev===next)return;
    s.disabled=true;
    try{
     await api('/users/'+encodeURIComponent(uid)+'/escalation-policy',{method:'POST',body:{policy:next}});
     s.dataset.prev=next;
    }catch(err){alert(err.message||T.err_net);s.value=prev}
    finally{s.disabled=false}
   }));
  }
 }catch(err){flash($('#ulist'),err.message||T.err_net,'err')}
 main.removeAttribute('aria-busy');
}

const STATUS_PILL={none:'status_none',pending_review:'status_pending',escalated:'status_escalated',auto_escalated:'status_auto',reviewed:'status_reviewed'};
const POLICY_KEYS=['auto','manual_review','none'];
const POLICY_LABEL={auto:'pol_auto',manual_review:'pol_manual',none:'pol_none'};

function dispStatusPill(s){
 const k=STATUS_PILL[s]||'status_none';
 return `<span class="pill p-${esc(s||'none')}">${esc(T[k]||s||'')}</span>`;
}
function fmtTime(iso){
 if(!iso)return '';
 try{const d=new Date(iso);if(Number.isNaN(d.getTime()))return esc(String(iso));
  return `<time datetime="${esc(d.toISOString())}" title="${esc(d.toISOString())}">${esc(d.toLocaleString())}</time>`;
 }catch{return esc(String(iso))}
}
function callerCell(d){
 const tier=Number(d.caller_tier);
 const name=d.caller_name||d.caller_email||d.caller_uid||'';
 const tag=Number.isFinite(tier)?` <span class="tag t${tier}">${esc(TIER_LABEL[tier]||tier)}</span>`:'';
 return `${esc(name)}${tag}`;
}
function locCell(loc){
 if(!loc||typeof loc!=='object')return '<span class=muted>—</span>';
 const lat=Number(loc.lat),lng=Number(loc.lng);
 if(!Number.isFinite(lat)||!Number.isFinite(lng))return '<span class=muted>—</span>';
 const acc=Number(loc.accuracy_m);
 const accStr=Number.isFinite(acc)?` ±${Math.round(acc)} m`:'';
 return `<span class=loc>${lat.toFixed(4)}, ${lng.toFixed(4)}${esc(accStr)}</span>`;
}
function summaryCell(d){
 const t=d.triage||{};
 const s=t.summary_for_dispatch||t.transcription_english||'';
 if(!s)return '<span class=muted>—</span>';
 const short=String(s).length>140?String(s).slice(0,137)+'…':String(s);
 return `<span title="${esc(s)}">${esc(short)}</span>`;
}
function urgencyCell(d){
 const u=d?.triage?.urgency||'';
 if(!u)return '<span class=muted>—</span>';
 return `<span class="urg u-${esc(u)}">${esc(u)}</span>`;
}

const ASN_STATUSES=['en_route','on_scene','completed','cancelled'];
const ASN_STATUS_LABEL={assigned:'asn_assign_btn',en_route:'asn_mark_enroute',on_scene:'asn_mark_onscene',completed:'asn_mark_done',cancelled:'asn_cancel'};

async function renderDispDetail(id,d){
 const host=document.getElementById('det-body-'+id);if(!host)return;
 host.innerHTML=`<p class=muted>${esc(T.working)}</p>`;
 try{
  const [sg,uList]=await Promise.all([
   api('/dispatches/'+encodeURIComponent(id)+'/suggestions').catch(()=>({suggestions:[]})),
   api('/units?status=available&limit=200').catch(()=>({units:[]}))
  ]);
  const triageJson=esc(JSON.stringify(d.triage||{},null,2));
  const chainJson=esc(JSON.stringify(d.escalation_chain||[],null,2));
  const ass=Array.isArray(d.assignments)?d.assignments:[];
  const sugs=sg.suggestions||[];
  const us=uList.units||[];
  const wsText=d.worker_summary_text||'';
  const wsLang=(d.worker_summary_lang||(d.triage&&d.triage.language_detected)||'').slice(0,2).toLowerCase();
  const showXlate=wsText&&wsLang&&wsLang!==lang;
  host.innerHTML=`<div class=detList>
   ${wsText?`<h3>${esc(T.ws_summary||'Worker summary')}</h3><p class=workerSum id=wsum-${esc(id)}>${esc(wsText)}${showXlate?` <button type=button class=xlateBtn data-id="${esc(id)}" data-lang="${esc(wsLang)}">${esc(T.xlate||'Translate')}</button>`:''}</p>`:''}
   <h3>${esc(T.dss_title)}</h3>
   ${sugs.length?`<div class=tblwrap><table class="tbl dssTbl"><thead><tr><th>${esc(T.unit_name)}</th><th>${esc(T.unit_type)}</th><th>${esc(T.dss_dist)}</th><th>${esc(T.dss_score)}</th><th>${esc(T.dss_reason)}</th><th></th></tr></thead><tbody>${
    sugs.map(s=>`<tr><td>${esc(s.unit_name)}</td><td>${esc(UNIT_LABEL[s.unit_type]||s.unit_type)}</td><td>${s.distance_km==null?'<span class=muted>—</span>':esc(s.distance_km+' km')}</td><td>${esc(s.score.toFixed(2))}</td><td class=muted>${esc(s.reason||'')}</td><td><button type=button class=dssAsn data-uid="${esc(s.unit_id)}">${esc(T.dss_assign)}</button></td></tr>`).join('')
   }</tbody></table></div>`:`<p class=empty>${esc(T.dss_none)}</p>`}
   <h3>${esc(T.asn_manual)}</h3>
   <form class=manualAsn data-id="${esc(id)}">
    <label>${esc(T.asn_pick)}<select name=unit_id required>${us.map(u=>`<option value="${esc(u.unit_id)}">${esc(u.name)} (${esc(UNIT_LABEL[u.type]||u.type)})</option>`).join('')}</select></label>
    <label>${esc(T.asn_eta)}<input type=number name=eta_minutes min=0 max=600 inputmode=numeric></label>
    <label>${esc(T.asn_note)}<input type=text name=note maxlength=200></label>
    <button type=submit>${esc(T.asn_assign_btn)}</button>
   </form>
   <h3>${esc(T.asn_title)}</h3>
   ${ass.length?`<ul class=asnList>${
    ass.map(a=>`<li class=asnRow><span class=asnName>${esc(UNIT_LABEL[a.unit_type]||a.unit_type)} ${esc(a.unit_name)}</span><span class="pill ws-${esc(a.status)}">${esc(a.status)}</span>${a.contact_phone?`<span class=muted>${esc(a.contact_phone)}</span>`:''}<select class=asnSet data-aid="${esc(a.aid)}" aria-label="${esc(T.asn_title)}">${ASN_STATUSES.map(s=>`<option value="${s}">${esc(T[ASN_STATUS_LABEL[s]]||s)}</option>`).join('')}</select></li>`).join('')
   }</ul>`:`<p class=empty>${esc(T.lbl_none)}</p>`}
   <h3>${esc(T.disp_summary)}</h3>
   <pre class=triagePre>${triageJson}</pre>
   <h3>Chain</h3>
   <pre class=triagePre>${chainJson}</pre>
  </div>`;
  host.querySelectorAll('.xlateBtn').forEach(b=>b.addEventListener('click',async()=>{
   // TODO: surface ?locale at the dispatch route. Today the
   // server's i18n.summaryFor takes a locale arg via the i18n module
   // but the GET /dispatches/<id> route does not yet thread the
   // ?locale query param into that call. The link is wired so the
   // moment the route accepts ?locale, this becomes a one-line
   // server change.
   b.disabled=true;
   try{
    const r=await api('/dispatches/'+encodeURIComponent(id)+'?locale='+encodeURIComponent(lang));
    const txt=r&&r.worker_summary_text;
    if(txt){const p=document.getElementById('wsum-'+id);if(p)p.textContent=txt}
   }catch(err){alert((err&&err.message)||T.err_net);b.disabled=false}
  }));
  host.querySelectorAll('.dssAsn').forEach(b=>b.addEventListener('click',()=>doAssign(id,b.dataset.uid,null,null)));
  const f=host.querySelector('form.manualAsn');
  if(f)f.addEventListener('submit',e=>{
   e.preventDefault();
   const fd=new FormData(f);
   const uid=String(fd.get('unit_id')||'');
   if(!uid)return;
   const eta=fd.get('eta_minutes');const note=String(fd.get('note')||'').trim();
   doAssign(id,uid,eta?Number(eta):null,note||null);
  });
  host.querySelectorAll('.asnSet').forEach(s=>s.addEventListener('change',async()=>{
   const aid=s.dataset.aid,next=s.value;
   if(!requireActionKey())return;
   s.disabled=true;
   try{
    await api('/assignments/'+encodeURIComponent(aid),{method:'PATCH',body:{status:next},sigSpec:{action:'assignment.update',target:'assignment.update|'+aid+'|'+next}});
    viewDispatches();
   }catch(err){alert(err.message||T.err_net)}
   finally{s.disabled=false}
  }));
 }catch(err){host.innerHTML=`<p class=err>${esc(err.message||T.err_net)}</p>`}
}

async function doAssign(dispatchId,unitId,eta,note){
 if(!requireActionKey())return;
 try{
  await api('/dispatches/'+encodeURIComponent(dispatchId)+'/assign',{method:'POST',body:{unit_id:unitId,eta_minutes:eta,note},sigSpec:{action:'dispatch.assign',target:'dispatch.assign|'+dispatchId+'|'+unitId}});
  viewDispatches();
 }catch(err){alert(err.message||T.err_net)}
}

const WS_LABEL={received:'ws_received',under_review:'ws_under_review',resources_assigned:'ws_resources_assigned',en_route:'ws_en_route',on_scene:'ws_on_scene',resolved:'ws_resolved',cancelled:'ws_cancelled'};
const UNIT_LABEL={
 ambulance:'AMB',fire_engine:'FE',police:'POL',sdrf_team:'SDRF',medical_team:'MED',drone:'DRN',helicopter:'HEL',
 ndrf_battalion:'NDRF',army_engineer:'ENGR',army_infantry:'INF',army_signals:'SIG',army_medical:'AMC',
 navy_dive:'DIVE',navy_ship:'SHIP',iaf_helicopter:'IAFH',iaf_transport:'IAFT',
 coast_guard_boat:'CGB',coast_guard_heli:'CGH',
 itbp_mountain:'ITBP',bsf_water:'BSFW',crpf_qrt:'CRPF',cisf_industrial:'CISF',
 hospital_csurge:'AIMS',hospital_dsurge:'DH',hospital_chc_slot:'CHC',hospital_phc_slot:'PHC',blood_unit:'BLD',
 fire_aerial:'FAP',fire_rescue_team:'FRT',power_crew:'PWR',water_tanker:'TKR',ro_unit:'RO',
 comms_cow:'COW',satellite_imagery:'SAT',forecast_cell:'FCAST',
 bus_evac:'BUS',relief_train:'TRN',truck_relief:'TRK',relief_camp:'CAMP',
 ircs_team:'IRC',civil_defence_unit:'CD',ncc_squad:'NCC',nss_squad:'NSS',aapda_mitra_squad:'AM',scouts_team:'BSG'
};
function workerStatusPill(s){
 const k=WS_LABEL[s]||'ws_received';
 return `<span class="pill ws-${esc(s||'received')}">${esc(T[k]||s||'')}</span>`;
}
function pendingCount(items){
 let n=0;for(const d of items){const ws=d.worker_status||'received';if(ws==='received'||ws==='under_review')n++}return n;
}

async function viewDispatches(){
 const me=session.get();
 const qs=new URLSearchParams((location.hash.split('?')[1])||'');
 const tab=qs.get('tab')||'team';
 main.setAttribute('aria-busy','true');
 main.innerHTML=`<section aria-labelledby=hDisp>
  <h1 id=hDisp>${esc(T.disp_title)}</h1>
  <p id=pendBar class=pendBar hidden></p>
  <div class=tabs role=tablist aria-label="${esc(T.disp_title)}">
   ${[['mine',T.disp_mine],['team',T.disp_team],['pending',T.disp_pending]].map(([k,lab])=>
    `<a role=tab href="#/dispatches?tab=${k}" aria-selected="${k===tab?'true':'false'}" class="tabBtn${k===tab?' active':''}">${esc(lab)}</a>`).join('')}
  </div>
  <div id=dlist></div>
 </section>`;
 try{
  let path='/dispatches?limit=100';
  if(tab==='mine')path+='&mine=only';
  else if(tab==='pending')path+='&requires_review=1';
  const r=await api(path);
  const items=r.dispatches||[];
  const pn=pendingCount(items);
  const pBar=$('#pendBar');
  if(pBar){
   if(pn>0){pBar.hidden=false;pBar.textContent=esc(T.disp_pending_count)+': '+pn}
   else{pBar.hidden=true}
  }
  if(!items.length){$('#dlist').innerHTML=`<p class=empty>${esc(T.lbl_none)}</p>`}
  else{
   const lT=esc(T.disp_time),lC=esc(T.disp_caller),lU=esc(T.disp_urgency),lSm=esc(T.disp_summary),lLo=esc(T.disp_loc),lS=esc(T.disp_status),lA=esc(T.disp_actions);
   $('#dlist').innerHTML=`<div class=tblwrap><table class=tbl><thead><tr>
     <th>${lT}</th>
     <th>${lC}</th>
     <th>${lU}</th>
     <th>${lSm}</th>
     <th>${lLo}</th>
     <th>${lS}</th>
     <th>${lA}</th>
    </tr></thead><tbody>${
    items.map(d=>{
     const isMine=me&&d.caller_uid===me.uid;
     const callerTier=Number(d.caller_tier);
     const canAct=!isMine&&me&&Number.isFinite(callerTier)&&callerTier<me.tier;
     const canEsc=canAct&&me.tier<100;
     const canRev=canAct;
     const id=esc(d.id);
     const ws=d.worker_status||'received';
     return `<tr data-id="${id}">
      <td data-label="${lT}">${fmtTime(d.received_at)}</td>
      <td data-label="${lC}">${callerCell(d)}</td>
      <td data-label="${lU}">${urgencyCell(d)}</td>
      <td data-label="${lSm}">${summaryCell(d)}</td>
      <td data-label="${lLo}">${locCell(d.location)}</td>
      <td data-label="${lS}">${dispStatusPill(d.escalation_status)} ${workerStatusPill(ws)}${d.requires_review?' <span class="pill p-pending_review">'+esc(T.status_pending)+'</span>':''}</td>
      <td data-label="${lA}" class=actCell>
       ${canEsc?`<button type=button class=dEsc data-id="${id}">${esc(T.disp_escalate)}</button>`:''}
       ${canRev?`<button type=button class=dRev data-id="${id}">${esc(T.disp_review)}</button>`:''}
       <button type=button class=dOpen aria-expanded=false aria-controls="det-${id}">${esc(T.disp_open)}</button>
      </td>
     </tr>
     <tr class=detRow id="det-${id}" hidden><td colspan=7><div id="det-body-${id}"><p class=muted>${esc(T.working)}</p></div></td></tr>`;
    }).join('')
   }</tbody></table></div>`;
   $$('#dlist .dOpen').forEach(b=>b.addEventListener('click',()=>{
    const tr=b.closest('tr'),id=tr.dataset.id;
    const det=document.getElementById('det-'+id);if(!det)return;
    const open=!det.hidden;det.hidden=open;b.setAttribute('aria-expanded',String(!open));
    if(!open){const d=items.find(x=>x.id===id);if(d)renderDispDetail(id,d)}
   }));
   $$('#dlist .dEsc').forEach(b=>b.addEventListener('click',async()=>{
    const id=b.dataset.id;
    if(!requireActionKey())return;
    b.disabled=true;
    try{await api('/dispatches/'+encodeURIComponent(id)+'/escalate',{method:'POST',body:{},sigSpec:{action:'dispatch.escalate',target:'dispatch.escalate|'+id}});viewDispatches()}
    catch(err){alert(err.message||T.err_net);b.disabled=false}
   }));
   $$('#dlist .dRev').forEach(b=>b.addEventListener('click',async()=>{
    const id=b.dataset.id;
    if(!requireActionKey())return;
    b.disabled=true;
    try{await api('/dispatches/'+encodeURIComponent(id)+'/review',{method:'POST',body:{},sigSpec:{action:'dispatch.review',target:'dispatch.review|'+id}});viewDispatches()}
    catch(err){alert(err.message||T.err_net);b.disabled=false}
   }));
  }
 }catch(err){flash($('#dlist'),err.message||T.err_net,'err')}
 main.removeAttribute('aria-busy');
}

// Mirror of server/tm/taxonomy.js UNIT_TYPES key set. Adding a new
// type means: extend taxonomy.js, extend this list, extend UNIT_LABEL
// above. The server validates type codes against the same taxonomy.
const UNIT_TYPES=[
 'ambulance','fire_engine','police','sdrf_team','medical_team','drone','helicopter',
 'ndrf_battalion','army_engineer','army_infantry','army_signals','army_medical',
 'navy_dive','navy_ship','iaf_helicopter','iaf_transport','coast_guard_boat','coast_guard_heli',
 'itbp_mountain','bsf_water','crpf_qrt','cisf_industrial',
 'hospital_csurge','hospital_dsurge','hospital_chc_slot','hospital_phc_slot','blood_unit',
 'fire_aerial','fire_rescue_team','power_crew','water_tanker','ro_unit',
 'comms_cow','satellite_imagery','forecast_cell',
 'bus_evac','relief_train','truck_relief','relief_camp',
 'ircs_team','civil_defence_unit','ncc_squad','nss_squad','aapda_mitra_squad','scouts_team'
];
const UNIT_STATUSES=['available','en_route','on_scene','returning','busy','offline'];

async function viewUnits(){
 const me=session.get();
 const canCreate=me&&Number(me.tier)>=60;
 main.setAttribute('aria-busy','true');
 main.innerHTML=`<section aria-labelledby=hUnit>
  <h1 id=hUnit>${esc(T.unit_title)}</h1>
  ${canCreate?`<details><summary>${esc(T.unit_new)}</summary>
   <form id=fNewUnit class=new>
    <label>${esc(T.unit_name)}<input name=name required maxlength=40></label>
    <label>${esc(T.unit_type)}<select name=type>${UNIT_TYPES.map(t=>`<option value="${t}">${esc(UNIT_LABEL[t]||t)}</option>`).join('')}</select></label>
    <label>${esc(T.unit_phone)}<input name=contact_phone required></label>
    <label>${esc(T.unit_capacity)}<input name=capacity type=number min=0 max=500 value=4></label>
    <label>${esc(T.unit_scope)}<input name=scope_path value="${esc(me?me.scope_path:'')}" required></label>
    <button type=submit>${esc(T.unit_create)}</button>
   </form>
  </details>`:''}
  <form id=fUnitFilter class=filter>
   <label>${esc(T.unit_status)}<select name=status><option value="">${esc(T.task_all)}</option>${UNIT_STATUSES.map(s=>`<option value="${s}">${esc(s)}</option>`).join('')}</select></label>
   <label>${esc(T.unit_type)}<select name=type><option value="">${esc(T.task_all)}</option>${UNIT_TYPES.map(t=>`<option value="${t}">${esc(UNIT_LABEL[t]||t)}</option>`).join('')}</select></label>
  </form>
  <div id=ulistU></div>
 </section>`;
 const fNew=$('#fNewUnit');
 if(fNew)fNew.addEventListener('submit',async e=>{
  e.preventDefault();
  const f=Object.fromEntries(new FormData(e.target));
  const body={name:String(f.name||'').trim(),type:String(f.type||''),contact_phone:String(f.contact_phone||'').trim(),scope_path:String(f.scope_path||'').trim(),capacity:Number(f.capacity)||4};
  try{await api('/units',{method:'POST',body});viewUnits()}
  catch(err){alert(err.message||T.err_net)}
 });
 const fF=$('#fUnitFilter');
 const reload=async()=>{
  const fd=new FormData(fF);
  const qs=new URLSearchParams();
  for(const[k,v] of fd){if(v)qs.set(k,v)}
  try{
   const r=await api('/units'+(qs.toString()?'?'+qs:''));
   const items=r.units||[];
   if(!items.length){$('#ulistU').innerHTML=`<p class=empty>${esc(T.lbl_none)}</p>`;return}
   const lN=esc(T.unit_name),lT=esc(T.unit_type),lP=esc(T.unit_phone),lC=esc(T.unit_capacity),lS=esc(T.unit_status),lSc=esc(T.unit_scope);
   $('#ulistU').innerHTML=`<div class=tblwrap><table class=tbl><thead><tr><th>${lN}</th><th>${lT}</th><th>${lP}</th><th>${lC}</th><th>${lS}</th><th>${lSc}</th>${canCreate?'<th></th>':''}</tr></thead><tbody>${
    items.map(u=>`<tr><td data-label="${lN}">${esc(u.name)}</td><td data-label="${lT}">${esc(UNIT_LABEL[u.type]||u.type)}</td><td data-label="${lP}">${esc(u.contact_phone||'')}</td><td data-label="${lC}">${u.capacity==null?'':esc(u.capacity)}</td><td data-label="${lS}"><select class=uStatus data-u="${esc(u.unit_id)}" data-prev="${esc(u.status)}">${UNIT_STATUSES.map(s=>`<option value="${s}"${s===u.status?' selected':''}>${esc(s)}</option>`).join('')}</select></td><td data-label="${lSc}">${esc(u.scope_path)}</td>${canCreate?`<td><button type=button class=uArc data-u="${esc(u.unit_id)}">${esc(T.unit_archive)}</button></td>`:''}</tr>`).join('')
   }</tbody></table></div>`;
   $$('#ulistU .uStatus').forEach(s=>s.addEventListener('change',async()=>{
    const uid=s.dataset.u,next=s.value,prev=s.dataset.prev;
    s.disabled=true;
    try{await api('/units/'+encodeURIComponent(uid),{method:'PATCH',body:{status:next}});s.dataset.prev=next}
    catch(err){alert(err.message||T.err_net);s.value=prev}
    finally{s.disabled=false}
   }));
   $$('#ulistU .uArc').forEach(b=>b.addEventListener('click',async()=>{
    const uid=b.dataset.u;
    if(!requireActionKey())return;
    b.disabled=true;
    try{await api('/units/'+encodeURIComponent(uid),{method:'DELETE',body:{},sigSpec:{action:'unit.archive',target:'unit.archive|'+uid}});reload()}
    catch(err){alert(err.message||T.err_net);b.disabled=false}
   }));
  }catch(err){flash($('#ulistU'),err.message||T.err_net,'err')}
 };
 fF.addEventListener('change',reload);
 await reload();
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
 if(path==='/dispatches')return viewDispatches();
 if(path==='/units')return viewUnits();
 if(path==='/users')return viewUsers();
 main.innerHTML=`<p class=empty>${esc(T.lbl_none)}</p>`;
}

// Inject the locale picker into the existing nav. The host page
// (tm/index.html) is otherwise stable; we extend it from JS so a fresh
// deploy ships the new surface without touching that file.
function ensureNavExtras(){
 const nav=document.getElementById('nav');if(!nav)return;
 if(!document.getElementById('langPick')){
  const sel=document.createElement('select');
  sel.id='langPick';sel.className='langPick';sel.setAttribute('aria-label',T.lp_lab||'Language');
  for(const [c,n] of LANGS){const o=document.createElement('option');o.value=c;o.textContent=n;if(c===lang)o.selected=true;sel.append(o)}
  sel.addEventListener('change',()=>setDispatcherLocale(sel.value));
  const logout=document.getElementById('btnLogout');
  if(logout)nav.insertBefore(sel,logout);else nav.append(sel);
 }else{
  document.getElementById('langPick').value=lang;
 }
}
function hydrateNav(){
 ensureNavExtras();
 const map={dash:'nav_dash',projects:'nav_proj',tasks:'nav_task',units:'nav_units',disp:'nav_disp',users:'nav_user'};
 $$('#nav a').forEach(a=>{
  const k=a.dataset.r;
  const tk=map[k]||('nav_'+k);
  if(k&&T[tk])a.textContent=T[tk];
 });
 const lo=$('#btnLogout');if(lo)lo.textContent=T.btn_logout||'Log out';
 const sel=$('#langPick');if(sel)sel.setAttribute('aria-label',T.lp_lab||'Language');
}

$('#btnLogout').addEventListener('click',()=>{session.clear();usersCache=null;location.hash='#/login'});
hydrateNav();

window.addEventListener('hashchange',route);
// Await the IDB-backed session before routing so the first paint sees
// the actual auth state. A legacy sessionStorage record (older builds)
// is migrated into the encrypted store on first boot, then cleared.
(async()=>{
 try{
  const legacy=sessionStorage.getItem(SS);
  if(legacy){try{const obj=JSON.parse(legacy);if(obj&&obj.token)await _sessWrite(obj);_sessCache=obj}catch{}sessionStorage.removeItem(SS)}
  if(!_sessCache)await session.init();
 }catch{}
 // Restore per-uid locale once the session is loaded. Falls back to
 // the navigator-derived first paint locale if nothing was stored.
 try{
  const me=session.get();
  if(me&&me.uid){
   const saved=await _prefGet('locale:'+me.uid);
   if(saved&&LCODES.includes(saved)&&saved!==lang){await setDispatcherLocale(saved);return}
  }
 }catch{}
 route();
})();
