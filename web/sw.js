const V='aether-v2',S=['/','/sw.js','/manifest.webmanifest','/favicon.svg','/icon-192.png','/icon-512.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(V).then(c=>c.addAll(S).catch(()=>{})).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==V).map(k=>caches.delete(k)))).then(()=>self.clients.claim()))});
self.addEventListener('fetch',e=>{
  const r=e.request,u=new URL(r.url);
  if(r.method!=='GET'||u.pathname.startsWith('/api/'))return;
  e.respondWith(caches.match(r).then(c=>c||fetch(r).then(res=>{if(res.ok&&u.origin===location.origin){const cl=res.clone();caches.open(V).then(ca=>ca.put(r,cl))}return res}).catch(()=>caches.match('/'))));
});
const nudge=async()=>{const cs=await self.clients.matchAll({includeUncontrolled:true,type:'window'});for(const c of cs)c.postMessage({k:'flush'})};
self.addEventListener('sync',e=>{if(e.tag==='flush')e.waitUntil(nudge())});
self.addEventListener('message',e=>{if(e.data&&e.data.k==='nudge')e.waitUntil(nudge())});
