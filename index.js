const ISSUER = 'https://upsy.ai';
const TOKEN_ENDPOINT = 'https://upsy.ai/api/oauth/token';
const REGISTER_ENDPOINT = 'https://upsy.ai/api/oauth/register';
const MCP_ENDPOINT = 'https://upsy.ai/connect';
const SCOPES = 'memory files browser gmail calendar drive outlook zohomail slack linear atlassian todoist clickup airtable notion miro granola fireflies calendly attio close intercom klaviyo customerio customerioeu stripe paypal webflow wix zapier upstash github context7 sentry supabase neon cloudflare vercel netlify posthog huggingface';
const enc = new TextEncoder();
const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
async function sha256(s) { return crypto.subtle.digest('SHA-256', enc.encode(s)); }
function json(data, status=200, headers={}) { return new Response(JSON.stringify(data,null,2), {status, headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers}}); }
function html(s, status=200) { return new Response(s,{status,headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store'}}); }
async function fetchToken(body) { const r=await fetch(TOKEN_ENDPOINT,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded','accept':'application/json'},body:new URLSearchParams(body)}); const t=await r.text(); let d; try{d=JSON.parse(t)}catch{d={raw:t}} if(!r.ok) throw new Error('Upsy token endpoint '+r.status+': '+JSON.stringify(d)); return d; }
async function kv(env, method, key, value) {
 const stub=env.TOKEN_STORE.get(env.TOKEN_STORE.idFromName('upsy-oauth-tokens'));
 const u='https://token-store.internal/item?key='+encodeURIComponent(key);
 const r=await stub.fetch(u,{method,headers:{'content-type':'application/json'},...(value===undefined?{}:{body:JSON.stringify(value)})});
 if(r.status===404) return null;
 if(!r.ok) throw new Error('Token storage error '+r.status);
 if(method==='GET') return r.json();
 return true;
}
async function handle(req, env) {
 const url=new URL(req.url); const path=url.pathname;
 if(path==='/health') return json({ok:true,service:'upsy-oauth-bridge',upstream:MCP_ENDPOINT,oauthConfigured:!!(await kv(env,'GET','oauth:tokens'))});
 if(path==='/') return html('<!doctype html><meta charset="utf-8"><title>Upsy OAuth Bridge</title><h1>Upsy OAuth Bridge</h1><p><a href="/auth/start">Connect Upsy</a></p><p>After connecting, configure your MCP client to use this Worker’s <code>/mcp</code> endpoint.</p>');
 if(path==='/auth/start') {
   const redirectUri=new URL('/oauth/callback',url.origin).href;
   const verifier=b64url(crypto.getRandomValues(new Uint8Array(32)));
   const challenge=b64url(await sha256(verifier));
   const state=b64url(crypto.getRandomValues(new Uint8Array(24)));
   const reg=await fetch(REGISTER_ENDPOINT,{method:'POST',headers:{'content-type':'application/json','accept':'application/json'},body:JSON.stringify({client_name:'Shade Upsy OAuth Bridge',redirect_uris:[redirectUri],token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code']})});
   const regText=await reg.text(); let client; try{client=JSON.parse(regText)}catch{client={raw:regText}}
   if(!reg.ok || !client.client_id) return json({error:'dynamic_client_registration_failed',status:reg.status,details:client},502);
   await kv(env,'PUT','oauth:state:'+state,{verifier,client_id:client.client_id,redirect_uri:redirectUri,created_at:Date.now()});
   const auth=new URL('/oauth/authorize',ISSUER); auth.searchParams.set('response_type','code'); auth.searchParams.set('client_id',client.client_id); auth.searchParams.set('redirect_uri',redirectUri); auth.searchParams.set('scope',SCOPES); auth.searchParams.set('state',state); auth.searchParams.set('code_challenge',challenge); auth.searchParams.set('code_challenge_method','S256'); auth.searchParams.set('resource',MCP_ENDPOINT);
   return Response.redirect(auth.href,302);
 }
 if(path==='/oauth/callback') {
   const code=url.searchParams.get('code'), state=url.searchParams.get('state'), error=url.searchParams.get('error');
   if(error) return html('<h1>Upsy authorization failed</h1><pre>'+String(error).replace(/[<>&]/g,'')+'</pre>',400);
   if(!code||!state) return json({error:'missing_code_or_state'},400);
   const s=await kv(env,'GET','oauth:state:'+state); if(!s || Date.now()-s.created_at>600000) return json({error:'state_expired_or_invalid'},400);
   await kv(env,'DELETE','oauth:state:'+state);
   try {
     const tokens=await fetchToken({grant_type:'authorization_code',code,redirect_uri:s.redirect_uri,client_id:s.client_id,code_verifier:s.verifier,resource:MCP_ENDPOINT});
     if(!tokens.refresh_token) return json({error:'no_refresh_token_returned',details:tokens},502);
     await kv(env,'PUT','oauth:tokens',{...tokens,client_id:s.client_id,updated_at:Date.now()});
     return html('<!doctype html><meta charset="utf-8"><title>Upsy connected</title><h1>Upsy connected</h1><p>OAuth tokens were stored server-side. You can close this tab and configure your MCP client to use <code>'+url.origin+'/mcp</code>.</p>');
   } catch(e) { return json({error:'token_exchange_failed',details:String(e.message)},502); }
 }
 if(path==='/mcp') {
   if(req.method==='GET') return new Response('MCP endpoint. Use POST with your MCP client.',{status:405,headers:{Allow:'POST, DELETE, OPTIONS'}});
   if(req.method==='OPTIONS') return new Response(null,{status:204,headers:{Allow:'POST, DELETE, OPTIONS'}});
   let t=await kv(env,'GET','oauth:tokens'); if(!t) return json({error:'upsy_not_connected',connect_url:url.origin+'/auth/start'},401);
   if(!t.access_token || (t.expires_in && t.updated_at+Math.max(0,t.expires_in-90)*1000<Date.now())) {
     if(!t.refresh_token) return json({error:'refresh_token_missing',connect_url:url.origin+'/auth/start'},401);
     try { const fresh=await fetchToken({grant_type:'refresh_token',refresh_token:t.refresh_token,client_id:t.client_id,resource:MCP_ENDPOINT}); t={...t,...fresh,refresh_token:fresh.refresh_token||t.refresh_token,client_id:t.client_id,updated_at:Date.now()}; await kv(env,'PUT','oauth:tokens',t); }
     catch(e) { return json({error:'upsy_token_refresh_failed',details:String(e.message),reconnect_url:url.origin+'/auth/start'},502); }
   }
   const headers=new Headers(req.headers); headers.set('authorization','Bearer '+t.access_token); headers.delete('host'); headers.delete('content-length');
   const init={method:req.method,headers,redirect:'manual'}; if(req.method!=='GET'&&req.method!=='HEAD') init.body=req.body;
   const upstream=await fetch(MCP_ENDPOINT,init); const outHeaders=new Headers(upstream.headers); outHeaders.set('cache-control','no-store'); outHeaders.delete('content-encoding'); outHeaders.delete('content-length');
   return new Response(upstream.body,{status:upstream.status,statusText:upstream.statusText,headers:outHeaders});
 }
 return json({error:'not_found'},404);
}
export class TokenStore {
 constructor(state,env){this.state=state;this.env=env;}
 async fetch(req){const u=new URL(req.url);const key=u.searchParams.get('key');if(!key)return new Response('missing key',{status:400});if(req.method==='GET'){const v=await this.state.storage.get(key);return v===undefined?new Response('',{status:404}):Response.json(v);}if(req.method==='PUT'){await this.state.storage.put(key,await req.json());return new Response('ok');}if(req.method==='DELETE'){await this.state.storage.delete(key);return new Response('ok');}return new Response('method not allowed',{status:405});}
}
export default {fetch(req,env){return handle(req,env).catch(e=>json({error:'bridge_error',details:String(e.message)},500));}};
