interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  APP_NAME: string;
  APP_ORIGIN: string;
  ADMIN_SECRET: string;
  BINANCE_PAY_ID?: string;
}
const PLAN_LIMITS: Record<string, number> = { free: 100, starter: 5000, pro: 30000, business: 150000 };
const json = (data: unknown, status=200, env?: Env) => new Response(JSON.stringify(data,null,2), {
  status, headers: { "content-type":"application/json; charset=utf-8", "cache-control":"no-store",
    "access-control-allow-origin": env?.APP_ORIGIN || "*", "access-control-allow-methods":"GET,POST,OPTIONS",
    "access-control-allow-headers":"content-type,authorization,x-api-key,x-admin-secret",
    "x-content-type-options":"nosniff", "referrer-policy":"strict-origin-when-cross-origin" }
});
const uid = () => crypto.randomUUID();
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=/g,"");
async function hash(s:string) { const d=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(s)); return b64(new Uint8Array(d)); }
function token(){ return "lx_live_"+b64(crypto.getRandomValues(new Uint8Array(32))); }
function safeTarget(raw:string):URL {
  let u:URL; try { u=new URL(raw.includes("://")?raw:"https://"+raw); } catch { throw new Error("Invalid URL"); }
  if (!["http:","https:"].includes(u.protocol) || u.username || u.password) throw new Error("Only public HTTP/HTTPS URLs are allowed");
  if (u.port && !["80","443"].includes(u.port)) throw new Error("Only standard web ports are allowed");
  const h=u.hostname.toLowerCase().replace(/^\[|\]$/g,"");
  if (!h.includes(".") || h==="localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") ||
      /^(127\.|10\.|192\.168\.|169\.254\.|0\.)/.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h) ||
      h==="::1" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80:")) throw new Error("Private or local network targets are blocked");
  u.hash=""; return u;
}
async function fetchTarget(u:URL, method:"GET"|"HEAD"="GET") {
  let current=u;
  for(let i=0;i<4;i++){
    const r=await fetch(current.toString(),{method,redirect:"manual",signal:AbortSignal.timeout(8000),headers:{"user-agent":"LiaquatX-Intelligence/1.1"}});
    if([301,302,303,307,308].includes(r.status)){
      const loc=r.headers.get("location"); if(!loc) return r;
      current=safeTarget(new URL(loc,current).toString()); continue;
    }
    return r;
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
    const r=await fetchTarget(target,kind==="check"?"HEAD":"GET");
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
async function handle(req:Request,env:Env){
  const u=new URL(req.url);
  if(req.method==="OPTIONS")return new Response(null,{headers:{"access-control-allow-origin":env.APP_ORIGIN||"*","access-control-allow-methods":"GET,POST,OPTIONS","access-control-allow-headers":"content-type,authorization,x-api-key,x-admin-secret"}});
  if(u.pathname==="/health")return json({ok:true,name:env.APP_NAME,version:"1.1.0"},200,env);
  if(u.pathname==="/v1/admin/keys"&&req.method==="POST"){
    if(!env.ADMIN_SECRET||req.headers.get("x-admin-secret")!==env.ADMIN_SECRET)return json({error:"Forbidden"},403,env);
    const body:any=await req.json().catch(()=>({})), email=String(body.email||"").trim().toLowerCase(), plan=String(body.plan||"free");
    if(!email.includes("@")||!(plan in PLAN_LIMITS))return json({error:"Valid email and plan required"},400,env);
    let user=await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first<any>();
    if(!user){const id=uid();await env.DB.prepare("INSERT INTO users(id,email,password_salt,password_hash,plan,status) VALUES(?,?, '', '', ?, 'active')").bind(id,email,plan).run();user={id};}
    const key=token(), id=uid();await env.DB.prepare("INSERT INTO api_keys(id,user_id,key_hash,key_prefix,label) VALUES(?,?,?,?,?)").bind(id,user.id,await hash(key),key.slice(0,15),String(body.label||"Default")).run();
    return json({ok:true,email,plan,api_key:key,note:"Copy this key now. It is shown only once."},201,env);
  }
  if(u.pathname==="/v1/account/usage"){
    const user=await apiUser(req,env);if(!user)return json({error:"Valid API key required"},401,env);
    const day=new Date().toISOString().slice(0,10), row=await env.DB.prepare("SELECT request_count FROM usage_daily WHERE user_id=? AND day=?").bind(user.id,day).first<any>();
    return json({ok:true,plan:user.plan,used:row?.request_count||0,limit:PLAN_LIMITS[user.plan]||100},200,env);
  }
  const routes:{[key:string]:string}={"/v1/website/check":"check","/v1/website/headers":"headers","/v1/website/seo":"seo","/v1/website/technologies":"tech"};
  if(routes[u.pathname])return inspect(req,env,routes[u.pathname]);
  if(u.pathname==="/v1/website/dns")return json({error:"DNS endpoint is planned; not enabled in this release"},501,env);
  if(u.pathname==="/v1/domain/whois"||u.pathname==="/v1/website/ssl"||u.pathname==="/v1/website/redirects")return json({error:"Endpoint is not enabled in this release"},501,env);
  if(env.ASSETS&&req.method==="GET"&&!u.pathname.startsWith("/v1/"))return env.ASSETS.fetch(req);
  return json({error:"Not found"},404,env);
}
export default {fetch(req:Request,env:Env){return handle(req,env).catch(e=>json({error:"Internal server error"},500,env));}};
