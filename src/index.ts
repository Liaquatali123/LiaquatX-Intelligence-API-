interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  APP_NAME: string;
  APP_ORIGIN: string;
  ADMIN_SECRET: string;
  BINANCE_PAY_ID?: string;
  OPENPAGERANK_API_KEY?: string;
}
const PLAN_LIMITS: Record<string, number> = { free: 100, starter: 5000, pro: 30000, business: 150000 };
const PLANS = ["free", "starter", "pro", "business"];
function corsHeaders(req:Request,env?:Env):Headers {
  const h=new Headers({"access-control-allow-methods":"GET,POST,PATCH,OPTIONS","access-control-allow-headers":"content-type,authorization,x-api-key,x-admin-secret","vary":"Origin"});
  const origin=req.headers.get("Origin");
  const allowed=(env?.APP_ORIGIN||"").split(",").map(x=>x.trim()).filter(Boolean);
  if(origin && allowed.includes(origin))h.set("access-control-allow-origin",origin);
  return h;
}
const json = (data: unknown, status=200, env?: Env, req?:Request) => {
  const headers=corsHeaders(req||new Request("https://worker.invalid"),env);
  headers.set("content-type","application/json; charset=utf-8");
  headers.set("cache-control","no-store");
  headers.set("x-content-type-options","nosniff");
  headers.set("referrer-policy","no-referrer");
  return new Response(JSON.stringify(data,null,2),{status,headers});
};
const uid = () => crypto.randomUUID();
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=/g,"");
async function hash(s:string) { const d=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(s)); return b64(new Uint8Array(d)); }
function token(){ return "lx_live_"+b64(crypto.getRandomValues(new Uint8Array(32))); }
function isBlockedIPv4(host:string):boolean {
  const parts=host.split(".");
  if(parts.length!==4||parts.some(p=>!/^\d{1,3}$/.test(p)||Number(p)>255))return false;
  const [a,b,c]=parts.map(Number);
  return a===0||a===10||a===127||a>=224||
    (a===100&&b>=64&&b<=127)||
    (a===169&&b===254)||
    (a===172&&b>=16&&b<=31)||
    (a===192&&b===168)||
    (a===192&&b===0&&c===0)||
    (a===198&&(b===18||b===19));
}
function safeTarget(raw:string):URL {
  let u:URL;
  try { u=new URL(raw.includes("://")?raw:"https://"+raw); } catch { throw new Error("Invalid URL"); }
  if(!["http:","https:"].includes(u.protocol)||u.username||u.password)throw new Error("Only public HTTP/HTTPS URLs without embedded credentials are allowed");
  if(u.port&& !["80","443"].includes(u.port))throw new Error("Only standard web ports are allowed");
  const h=u.hostname.toLowerCase().replace(/^\[|\]$/g,"").replace(/\.$/,"");
  const metadataHosts=["metadata","metadata.google","metadata.google.internal","metadata.tencentyun.com","metadata.azure.internal","metadata.oraclecloud.com","instance-data"];
  if(!h.includes(".")||h==="localhost"||h.endsWith(".localhost")||h.endsWith(".local")||h.endsWith(".internal")||
     metadataHosts.includes(h)||h.endsWith(".metadata.google.internal")||h.includes(":")||h.startsWith("[")||
     isBlockedIPv4(h)||h==="169.254.169.254"||h==="100.100.100.200") {
    throw new Error("Private, local, metadata, or IP-literal targets are blocked");
  }
  u.hash="";return u;
}
async function safeFetch(input:URL|string,method:"GET"|"HEAD"="GET") {
  let current=safeTarget(input instanceof URL?input.toString():input);
  const chain:Array<{url:string,status:number,location:string|null}>=[];
  for(let hop=0;hop<=3;hop++){
    const response=await fetch(current.toString(),{method,redirect:"manual",signal:AbortSignal.timeout(8000),headers:{"user-agent":"LiaquatX-Intelligence/2.0"}});
    const location=response.headers.get("location");
    chain.push({url:current.toString(),status:response.status,location});
    if(![301,302,303,307,308].includes(response.status)||!location)return {response,finalUrl:current,chain};
    if(hop===3)throw new Error("Too many redirects (maximum 3)");
    current=safeTarget(new URL(location,current).toString());
  }
  throw new Error("Too many redirects");
}
async function limitedText(r:Response,max=500000){
  const len=Number(r.headers.get("content-length")||0); if(len>max) throw new Error("Target response too large");
  if(!r.body) return "";
  const rd=r.body.getReader(), chunks:Uint8Array[]=[]; let total=0;
  while(true){const x=await rd.read(); if(x.done)break; total+=x.value.length;if(total>max){await rd.cancel();throw new Error("Target response too large");}chunks.push(x.value);}
  const all=new Uint8Array(total);let off=0;for(const c of chunks){all.set(c,off);off+=c.length;}return new TextDecoder().decode(all);
}
async function apiUser(req:Request,env:Env){
  const raw=req.headers.get("x-api-key")||req.headers.get("authorization")?.replace(/^Bearer\s+/i,"");
  if(!raw)return null;
  return await env.DB.prepare("SELECT u.id,u.plan,k.id AS key_id FROM api_keys k JOIN users u ON u.id=k.user_id WHERE k.key_hash=? AND k.revoked=0 AND u.status='active'")
    .bind(await hash(raw)).first<any>();
}
async function charge(env:Env,u:any){
  const day=new Date().toISOString().slice(0,10), limit=PLAN_LIMITS[u.plan]||100;
  const r=await env.DB.prepare("INSERT INTO usage_daily(user_id,day,request_count) VALUES(?,?,1) ON CONFLICT(user_id,day) DO UPDATE SET request_count=request_count+1 WHERE request_count<?")
    .bind(u.id,day,limit).run();
  if(!r.meta?.changes)return false;
  await env.DB.prepare("UPDATE api_keys SET last_used_at=CURRENT_TIMESTAMP WHERE id=?").bind(u.key_id).run();
  return true;
}
async function inspect(req:Request,env:Env,kind:string){
  const u=await apiUser(req,env); if(!u)return json({error:"A valid API key is required"},401,env);
  if(!await charge(env,u))return json({error:"Daily quota exceeded"},429,env);
  const raw=new URL(req.url).searchParams.get("url"); if(!raw)return json({error:"Missing url query parameter"},400,env);
  let target:URL;try{target=safeTarget(raw);}catch(e){return json({error:(e as Error).message},400,env);}
  try{
    const {response:r}=await safeFetch(target,kind==="check"?"HEAD":"GET");
    const base:any={url:target.toString(),status_code:r.status,reachable:r.status<500,checked_at:new Date().toISOString()};
    if(kind==="check")return json({ok:true,data:{...base,response_time_ms:0,server:r.headers.get("server")}},200,env);
    if(kind==="headers"){
      const names=["strict-transport-security","content-security-policy","x-content-type-options","x-frame-options","referrer-policy","permissions-policy"];
      const headers:any={};for(const n of names)headers[n]=r.headers.get(n);
      return json({ok:true,data:{...base,headers,missing:names.filter(n=>!headers[n])}},200,env);
    }
    const html=await limitedText(r), title=html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.trim()||null;
    const description=html.match(/<meta\s+name=["']description["']\s+content=["']([^"']*)/i)?.[1]||null;
    if(kind==="seo")return json({ok:true,data:{...base,title,description,html_bytes:new TextEncoder().encode(html).length,has_viewport:/name=["']viewport/i.test(html),has_canonical:/rel=["']canonical/i.test(html)}},200,env);
    const tech:string[]=[];const tests:[RegExp,string][]=[[/wp-content|wp-includes/i,"WordPress"],[/cdn\.shopify\.com/i,"Shopify"],[/__next|_next\//i,"Next.js"],[/react/i,"React"],[/cloudflare/i,"Cloudflare"],[/googletagmanager/i,"Google Tag Manager"]];
    for(const [re,name] of tests)if(re.test(html))tech.push(name);
    return json({ok:true,data:{...base,technologies:[...new Set(tech)],title}},200,env);
  }catch(e){return json({error:"Analysis failed",detail:(e as Error).message},502,env);}
}
async function sha256Bytes(value:string):Promise<Uint8Array>{
  return new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value)));
}
function constantTimeBytesEqual(a:Uint8Array,b:Uint8Array):boolean {
  if(a.length!==b.length)return false;
  let diff=0;for(let i=0;i<a.length;i++)diff|=a[i]^b[i];
  return diff===0;
}
async function adminSecretMatches(provided:string,expected:string):Promise<boolean>{
  const [a,b]=await Promise.all([sha256Bytes(provided),sha256Bytes(expected)]);
  return constantTimeBytesEqual(a,b);
}
async function admin(req:Request,env:Env){
  const ip=req.headers.get("CF-Connecting-IP")||"unknown";
  const rateKey=new Request("https://liaquatx-admin-rate-limit.invalid/"+encodeURIComponent(ip));
  const cache=caches.default;
  const cached=await cache.match(rateKey);
  const state=cached?await cached.json<{count:number}>():{count:0};
  if(state.count>=5)return json({error:"Too many failed admin authentication attempts. Try again in 5 minutes."},429,env,req);
  const supplied=req.headers.get("x-admin-secret")||"";
  const valid=!!env.ADMIN_SECRET&&await adminSecretMatches(supplied,env.ADMIN_SECRET);
  if(!valid){
    await cache.put(rateKey,new Response(JSON.stringify({count:state.count+1}),{headers:{"content-type":"application/json"}}),{expirationTtl:300});
    return json({error:"Unauthorized admin access"},401,env,req);
  }
  await cache.delete(rateKey);
  const url=new URL(req.url), path=url.pathname, day=new Date().toISOString().slice(0,10);
  if(path==="/v1/admin/overview" && req.method==="GET"){
    const row=await env.DB.prepare("SELECT (SELECT COUNT(*) FROM users) AS total_users,(SELECT COUNT(*) FROM api_keys WHERE revoked=0) AS active_keys,(SELECT COALESCE(SUM(request_count),0) FROM usage_daily WHERE day=?) AS requests_today,(SELECT COUNT(*) FROM payment_requests WHERE status='pending') AS pending_payments").bind(day).first<any>();
    return json({ok:true,stats:row},200,env,req);
  }
  if(path==="/v1/admin/users" && req.method==="GET"){
    const rows=await env.DB.prepare("SELECT u.id,u.email,u.plan,u.status,u.created_at,(SELECT COUNT(*) FROM api_keys k WHERE k.user_id=u.id AND k.revoked=0) AS active_keys,(SELECT COALESCE(request_count,0) FROM usage_daily d WHERE d.user_id=u.id AND d.day=?) AS requests_today FROM users u ORDER BY u.created_at DESC LIMIT 200").bind(day).all<any>();
    return json({ok:true,users:rows.results||[]},200,env,req);
  }
  if(path==="/v1/admin/keys" && req.method==="GET"){
    const rows=await env.DB.prepare("SELECT k.id,k.key_prefix,k.label,k.revoked,k.created_at,k.last_used_at,u.email,u.plan FROM api_keys k JOIN users u ON u.id=k.user_id ORDER BY k.created_at DESC LIMIT 200").all<any>();
    return json({ok:true,keys:rows.results||[]},200,env,req);
  }
  if(path==="/v1/admin/keys" && req.method==="POST"){
    const body:any=await req.json().catch(()=>({})), email=String(body.email||"").trim().toLowerCase(), plan=String(body.plan||"free"), label=String(body.label||"Default").slice(0,80);
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!PLANS.includes(plan))return json({error:"Valid email and plan required"},400,env);
    let user=await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first<any>();
    if(!user){const id=uid();await env.DB.prepare("INSERT INTO users(id,email,password_salt,password_hash,plan,status) VALUES(?,?, '', '', ?, 'active')").bind(id,email,plan).run();user={id};}
    else await env.DB.prepare("UPDATE users SET plan=? WHERE id=?").bind(plan,user.id).run();
    const key=token(), id=uid();
    await env.DB.prepare("INSERT INTO api_keys(id,user_id,key_hash,key_prefix,label) VALUES(?,?,?,?,?)").bind(id,user.id,await hash(key),key.slice(0,15),label).run();
    return json({ok:true,email,plan,api_key:key,note:"Copy this key now. It is shown only once."},201,env,req);
  }
  const revoke=path.match(/^\/v1\/admin\/keys\/([a-f0-9-]+)\/revoke$/i);
  if(revoke && req.method==="POST"){
    const r=await env.DB.prepare("UPDATE api_keys SET revoked=1 WHERE id=?").bind(revoke[1]).run();
    if(!r.meta?.changes)return json({error:"API key not found"},404,env);
    return json({ok:true,message:"API key revoked"},200,env,req);
  }
  const userMatch=path.match(/^\/v1\/admin\/users\/([a-f0-9-]+)$/i);
  if(userMatch && req.method==="PATCH"){
    const body:any=await req.json().catch(()=>({})), plan=body.plan===undefined?null:String(body.plan), status=body.status===undefined?null:String(body.status);
    if(plan!==null&&!PLANS.includes(plan))return json({error:"Invalid plan"},400,env);
    if(status!==null&&!["active","suspended"].includes(status))return json({error:"Status must be active or suspended"},400,env);
    if(plan===null&&status===null)return json({error:"No supported changes supplied"},400,env);
    const r=await env.DB.prepare("UPDATE users SET plan=COALESCE(?,plan),status=COALESCE(?,status) WHERE id=?").bind(plan,status,userMatch[1]).run();
    if(!r.meta?.changes)return json({error:"User not found or unchanged"},404,env);
    return json({ok:true,message:"User updated"},200,env,req);
  }
  return json({error:"Admin endpoint not found"},404,env);
}

function validDomain(raw:string):string {
  const d=raw.trim().toLowerCase().replace(/^https?:\/\//,"").split(/[\/?#:]/)[0].replace(/\.$/,"");
  if(d.length>253 || !d.includes(".") || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d)) throw new Error("A valid public domain is required");
  if(d==="localhost" || d.endsWith(".local") || d.endsWith(".internal")) throw new Error("Private domains are not allowed");
  return d;
}
async function toolAuth(req:Request,env:Env){
  const u=await apiUser(req,env);
  if(!u)return {error:json({error:"A valid API key is required"},401,env)};
  if(!await charge(env,u))return {error:json({error:"Daily quota exceeded"},429,env)};
  return {user:u};
}
async function externalJson(url:string,headers:Record<string,string>={}){
  const r=await fetch(url,{headers:{"accept":"application/json","user-agent":"LiaquatX-Intelligence/2.0",...headers},signal:AbortSignal.timeout(25000)});
  const body=await r.text();
  let data:any;try{data=JSON.parse(body)}catch{data={raw:body.slice(0,1500)}}
  if(!r.ok)throw new Error("External provider returned HTTP "+r.status);
  return data;
}
async function domainTool(req:Request,env:Env,kind:string){
  const auth=await toolAuth(req,env);if(auth.error)return auth.error;
  const q=new URL(req.url).searchParams, raw=q.get("domain")||q.get("url")||"";
  let domain:string;try{domain=validDomain(raw)}catch(e){return json({error:(e as Error).message},400,env)}
  try{
    if(kind==="dns"){
      const types=["A","AAAA","MX","NS","TXT","CNAME","SOA"];
      const records:any={};
      for(const type of types){
        const data=await externalJson("https://cloudflare-dns.com/dns-query?name="+encodeURIComponent(domain)+"&type="+type,{"accept":"application/dns-json"});
        records[type]=(data.Answer||[]).map((x:any)=>({name:x.name,type:x.type,ttl:x.TTL,value:x.data}));
      }
      return json({ok:true,domain,records,checked_at:new Date().toISOString()},200,env);
    }
    if(kind==="whois"||kind==="availability"){
      const r=await fetch("https://rdap.org/domain/"+encodeURIComponent(domain),{headers:{"accept":"application/rdap+json","user-agent":"LiaquatX-Intelligence/2.0"},signal:AbortSignal.timeout(15000)});
      if(kind==="availability"){
        if(r.status===404)return json({ok:true,domain,available:true,status:"not_registered",source:"RDAP"},200,env);
        if(r.ok)return json({ok:true,domain,available:false,status:"registered",source:"RDAP"},200,env);
        return json({ok:false,domain,available:null,status:"unknown",provider_status:r.status},502,env);
      }
      const data:any=await r.json().catch(()=>({}));
      if(!r.ok)return json({error:"RDAP lookup failed",provider_status:r.status,detail:data},502,env);
      const events=(data.events||[]).map((e:any)=>({action:e.eventAction,date:e.eventDate}));
      const nameservers=(data.nameservers||[]).map((n:any)=>n.ldhName);
      const entities=(data.entities||[]).map((e:any)=>({roles:e.roles,vcardArray:e.vcardArray}));
      return json({ok:true,domain,registrar:entities,registered_events:events,nameservers,status:data.status||[],handle:data.handle,port43:data.port43,checked_at:new Date().toISOString()},200,env);
    }
    if(kind==="ssl"){
      const data=await externalJson("https://api.ssllabs.com/api/v3/analyze?host="+encodeURIComponent(domain)+"&publish=off&all=done&fromCache=on&maxAge=24");
      return json({ok:true,domain,provider:"Qualys SSL Labs",status:data.status||"UNKNOWN",grade:data.endpoints?.[0]?.grade||null,details:data.endpoints||[],message:data.statusMessage||null,checked_at:new Date().toISOString()},200,env);
    }
    if(kind==="backlinks"){
      if(!env.OPENPAGERANK_API_KEY)return json({error:"Backlink provider is not configured. Add OPENPAGERANK_API_KEY as a Cloudflare Worker secret.",required_secret:"OPENPAGERANK_API_KEY"},503,env);
      const data=await externalJson("https://openpagerank.com/api/v1.0/getPageRank?domains[]="+encodeURIComponent(domain),{"API-OPR":env.OPENPAGERANK_API_KEY});
      return json({ok:true,domain,provider:"Open PageRank",results:data.response||[],checked_at:new Date().toISOString()},200,env);
    }
  }catch(e){return json({error:"Lookup failed",detail:(e as Error).message},502,env)}
  return json({error:"Unknown domain tool"},404,env);
}
async function websiteTool(req:Request,env:Env,kind:string){
  const auth=await toolAuth(req,env);if(auth.error)return auth.error;
  const q=new URL(req.url).searchParams, raw=q.get("url")||"";
  let target:URL;try{target=safeTarget(raw)}catch(e){return json({error:(e as Error).message},400,env)}
  try{
    if(kind==="screenshot"){
      const screenshotUrl="https://image.thum.io/get/width/1200/crop/800/noanimate/"+encodeURIComponent(target.toString());
      return json({ok:true,url:target.toString(),screenshot_url:screenshotUrl,provider:"thum.io",note:"Screenshot is generated by the external screenshot provider."},200,env);
    }
    if(kind==="pagespeed"){
      const strategy=q.get("strategy")==="mobile"?"mobile":"desktop";
      const data=await externalJson("https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url="+encodeURIComponent(target.toString())+"&strategy="+strategy+"&category=performance&category=accessibility&category=best-practices&category=seo");
      const cats=data.lighthouseResult?.categories||{};
      const scores:any={};for(const k of Object.keys(cats))scores[k]=cats[k].score===null?null:Math.round(cats[k].score*100);
      const audits=data.lighthouseResult?.audits||{};
      const metrics:any={};for(const k of ["first-contentful-paint","largest-contentful-paint","speed-index","total-blocking-time","cumulative-layout-shift"])if(audits[k])metrics[k]={displayValue:audits[k].displayValue,score:audits[k].score};
      return json({ok:true,url:target.toString(),strategy,scores,metrics,checked_at:new Date().toISOString()},200,env);
    }
    if(kind==="redirects"){
      let current=target;const chain:any[]=[];
      for(let i=0;i<10;i++){
        const {response:r,chain:redirectChain}=await safeFetch(current,"GET");
        for(const hop of redirectChain)chain.push({url:hop.url,status_code:hop.status,location:hop.location});
        current=new URL(redirectChain[redirectChain.length-1].url);
        break;
      }
      return json({ok:true,start_url:target.toString(),final_url:chain[chain.length-1]?.url,redirect_count:Math.max(0,chain.length-1),chain},200,env);
    }
    if(kind==="broken-links"){
      const {response:r}=await safeFetch(target,"GET"),html=await limitedText(r);
      const found=[...html.matchAll(/(?:href|src)\s*=\s*["']([^"'#]+)["']/gi)].map(m=>m[1]);
      const links=[...new Set(found.map(x=>{try{return new URL(x,target).toString()}catch{return ""}}).filter(x=>x.startsWith("http://")||x.startsWith("https://")))].slice(0,30);
      const results:any[]=[];
      for(const link of links){
        try{const {response:res}=await safeFetch(link,"HEAD");results.push({url:link,status_code:res.status,broken:res.status>=400});}
        catch(e){results.push({url:link,status_code:null,broken:true,error:(e as Error).message});}
      }
      return json({ok:true,url:target.toString(),links_checked:results.length,broken_count:results.filter(x=>x.broken).length,results,limit:30},200,env);
    }
  }catch(e){return json({error:"Website tool failed",detail:(e as Error).message},502,env)}
  return json({error:"Unknown website tool"},404,env);
}

async function handle(req:Request,env:Env){
  const u=new URL(req.url);
  if(req.method==="OPTIONS")return new Response(null,{headers:corsHeaders(req,env)});
  if(u.pathname==="/health")return json({ok:true,name:env.APP_NAME,version:"1.2.0"},200,env,req);
  if(u.pathname.startsWith("/v1/admin/"))return admin(req,env);
  if(u.pathname==="/v1/account/usage"){
    const user=await apiUser(req,env);if(!user)return json({error:"Valid API key required"},401,env);
    const day=new Date().toISOString().slice(0,10), row=await env.DB.prepare("SELECT request_count FROM usage_daily WHERE user_id=? AND day=?").bind(user.id,day).first<any>();
    return json({ok:true,plan:user.plan,used:row?.request_count||0,limit:PLAN_LIMITS[user.plan]||100},200,env);
  }
  const routes:{[key:string]:string}={"/v1/website/check":"check","/v1/website/headers":"headers","/v1/website/seo":"seo","/v1/website/technologies":"tech"};
  if(routes[u.pathname])return inspect(req,env,routes[u.pathname]);
  const domainRoutes:{[key:string]:string}={"/v1/website/dns":"dns","/v1/domain/whois":"whois","/v1/website/ssl":"ssl","/v1/domain/availability":"availability","/v1/domain/backlinks":"backlinks"};
  if(domainRoutes[u.pathname])return domainTool(req,env,domainRoutes[u.pathname]);
  const websiteRoutes:{[key:string]:string}={"/v1/website/redirects":"redirects","/v1/website/screenshot":"screenshot","/v1/website/pagespeed":"pagespeed","/v1/website/broken-links":"broken-links"};
  if(websiteRoutes[u.pathname])return websiteTool(req,env,websiteRoutes[u.pathname]);
  if(env.ASSETS&&req.method==="GET"&&!u.pathname.startsWith("/v1/")){
    const asset=await env.ASSETS.fetch(req);
    const type=asset.headers.get("content-type")||"";
    if(type.includes("text/html")){
      const headers=new Headers(asset.headers);
      headers.delete("content-length");
      headers.delete("content-encoding");
      headers.delete("etag");
      headers.delete("content-md5");
      headers.set("x-content-type-options","nosniff");
      headers.set("x-frame-options","DENY");
      headers.set("referrer-policy","no-referrer");
      const nonce=b64(crypto.getRandomValues(new Uint8Array(18)));
      const html=await asset.text();
      const securedHtml=html.replace(/<script(\s|>)/gi,(_m,tail)=>'<script nonce="'+nonce+'"'+tail)
        .replace(/<style(\s|>)/gi,(_m,tail)=>'<style nonce="'+nonce+'"'+tail);
      headers.set("content-security-policy","default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'nonce-"+nonce+"'; style-src 'self' 'nonce-"+nonce+"'; style-src-attr 'none'; img-src 'self' data: https:; connect-src 'self'; upgrade-insecure-requests");
      headers.set("vary","Origin");
      const origin=req.headers.get("Origin"),allowed=(env.APP_ORIGIN||"").split(",").map(x=>x.trim()).filter(Boolean);
      if(origin&&allowed.includes(origin))headers.set("access-control-allow-origin",origin);
      else headers.delete("access-control-allow-origin");
      return new Response(securedHtml,{status:asset.status,statusText:asset.statusText,headers});
    }
    return asset;
  }
  return json({error:"Not found"},404,env,req);
}
function applyCors(response:Response,req:Request,env:Env):Response {
  const headers=new Headers(response.headers);
  headers.append("vary","Origin");
  const origin=req.headers.get("Origin");
  const allowed=(env.APP_ORIGIN||"").split(",").map(x=>x.trim()).filter(Boolean);
  if(origin&&allowed.includes(origin))headers.set("access-control-allow-origin",origin);
  else headers.delete("access-control-allow-origin");
  return new Response(response.body,{status:response.status,statusText:response.statusText,headers});
}
export default {async fetch(req:Request,env:Env){
  try{return applyCors(await handle(req,env),req,env);}
  catch(e){return applyCors(json({error:"Internal server error"},500,env,req),req,env);}
}};
