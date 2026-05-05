const V='aether-v1',S=['/','/sw.js','/manifest.webmanifest','/favicon.svg','/icon-192.png','/icon-512.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(V).then(c=>c.addAll(S).catch(()=>{})).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==V).map(k=>caches.delete(k)))).then(()=>self.clients.claim()))});
self.addEventListener('fetch',e=>{
  const r=e.request,u=new URL(r.url);
  if(r.method!=='GET'||u.pathname.startsWith('/api/'))return;
  e.respondWith(caches.match(r).then(c=>c||fetch(r).then(res=>{if(res.ok&&u.origin===location.origin){const cl=res.clone();caches.open(V).then(ca=>ca.put(r,cl))}return res}).catch(()=>caches.match('/'))));
});
const idb=()=>new Promise((r,j)=>{const o=indexedDB.open('a',1);o.onupgradeneeded=e=>e.target.result.createObjectStore('q',{keyPath:'id',autoIncrement:true});o.onsuccess=e=>r(e.target.result);o.onerror=()=>j(o.error)});
const qAll=()=>idb().then(d=>new Promise(r=>{const o=[];d.transaction('q','readonly').objectStore('q').openCursor().onsuccess=e=>{const c=e.target.result;c?(o.push(c.value),c.continue()):r(o)}}));
const qDel=i=>idb().then(d=>new Promise(s=>{const x=d.transaction('q','readwrite');x.objectStore('q').delete(i);x.oncomplete=s}));
const cid=async()=>{const cs=await self.clients.matchAll({includeUncontrolled:true});return cs[0]||null};
const flush=async()=>{
  const items=await qAll();
  for(const it of items){
    const h={'Content-Type':it.mime,'X-Client-Lang':it.lang||'en-IN','X-Client-Timestamp':it.ts};
    if(it.id_)h['X-Client-Id']=it.id_;
    if(it.geo)h['X-Client-Geo']=it.geo;
    if(it.bat!=null)h['X-Client-Battery']=String(it.bat);
    if(it.net)h['X-Client-Network']=it.net;
    try{const r=await fetch('/api/v1/triage',{method:'POST',headers:h,body:it.blob});if(!r.ok)throw 0;await qDel(it.id);const c=await cid();c&&c.postMessage({k:'flushed',id:it.id})}catch(e){throw e}
  }
};
self.addEventListener('sync',e=>{if(e.tag==='flush')e.waitUntil(flush().catch(()=>{}))});
