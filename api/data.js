// Shared cloud client store with per-client sharing.
// One endpoint, multiple ops: pull | save | delete | share | unshare
// Keys:  cl:<id> -> client JSON (incl _owner,_v,_upAt,_upBy)
//        acl:<id> -> SET of emails allowed to access the client (includes owner)
//        uc:<email> -> SET of client ids the user can access
const RURL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const RTOK = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
async function rcmd(cmd){
  const r = await fetch(RURL, { method:"POST", headers:{ Authorization:"Bearer "+RTOK, "Content-Type":"application/json" }, body: JSON.stringify(cmd) });
  const j = await r.json();
  return j.result;
}
const clean = s => String(s||"").replace(/[^a-zA-Z0-9]/g,"");
const lc = s => String(s||"").trim().toLowerCase();
const isEmail = s => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);

// token -> approved user email, or null
async function authEmail(token){
  const t = clean(token);
  if(!t) return null;
  const em = await rcmd(["GET","token:"+t]);
  if(!em) return null;
  const raw = await rcmd(["GET","user:"+em]);
  if(!raw) return null;
  try{ const u = JSON.parse(raw); if(u.status!=="approved") return null; }catch(e){ return null; }
  return em;
}

module.exports = async (req, res) => {
  try {
    if (req.method !== "POST") return res.status(405).json({ ok:false, error:"POST only" });
    const b = req.body || {};
    const email = await authEmail(b.token);
    if (!email) return res.status(401).json({ ok:false, error:"Not signed in." });
    const op = String(b.op || "");

    if (op === "pull") {
      const ids = (await rcmd(["SMEMBERS","uc:"+email])) || [];
      const clients = [];
      for (const id of ids) {
        const raw = await rcmd(["GET","cl:"+id]);
        if (!raw) { await rcmd(["SREM","uc:"+email,id]); continue; }
        let c; try { c = JSON.parse(raw); } catch(e){ continue; }
        const acl = (await rcmd(["SMEMBERS","acl:"+id])) || [];
        c._shared = acl;
        c._isOwner = (c._owner === email);
        clients.push(c);
      }
      return res.json({ ok:true, clients, serverTime: Date.now() });
    }

    if (op === "save") {
      const client = b.client;
      if (!client || !client.id) return res.json({ ok:false, error:"Missing client." });
      const id = clean(client.id) || client.id;
      const existingRaw = await rcmd(["GET","cl:"+id]);
      let hist = [];
      if (existingRaw) {
        let ex; try { ex = JSON.parse(existingRaw); } catch(e){ ex = {}; }
        const allowed = await rcmd(["SISMEMBER","acl:"+id, email]);
        if (!allowed) return res.status(403).json({ ok:false, error:"You don't have access to this client." });
        client._owner = ex._owner || email;
        client._v = (+ex._v || 0) + 1;
        hist = Array.isArray(ex._history) ? ex._history.slice() : [];  // server owns the history
      } else {
        client._owner = email;
        client._v = 1;
        await rcmd(["SADD","acl:"+id, email]);
        await rcmd(["SADD","uc:"+email, id]);
      }
      client._upAt = new Date().toISOString();
      client._upBy = String(b.by || email).slice(0,60);
      // Edit log: collapse one person's continuous edits (within 5 min) into a single session entry.
      const last = hist[hist.length-1];
      if (last && last.by === client._upBy && last.email === email && (Date.parse(client._upAt) - Date.parse(last.at)) < 5*60000) {
        last.at = client._upAt;
      } else {
        hist.push({ by: client._upBy, email, at: client._upAt });
      }
      client._history = hist.slice(-40);
      await rcmd(["SET","cl:"+id, JSON.stringify(client)]);
      return res.json({ ok:true, id, version: client._v, updatedAt: client._upAt, updatedBy: client._upBy });
    }

    if (op === "delete") {
      const id = clean(b.id) || b.id;
      const raw = await rcmd(["GET","cl:"+id]);
      if (!raw) return res.json({ ok:true }); // already gone
      let ex; try { ex = JSON.parse(raw); } catch(e){ ex = {}; }
      if (ex._owner !== email) return res.status(403).json({ ok:false, error:"Only the owner can delete this client." });
      const acl = (await rcmd(["SMEMBERS","acl:"+id])) || [];
      for (const e of acl) await rcmd(["SREM","uc:"+e, id]);
      await rcmd(["DEL","cl:"+id]);
      await rcmd(["DEL","acl:"+id]);
      return res.json({ ok:true });
    }

    if (op === "share" || op === "unshare") {
      const id = clean(b.id) || b.id;
      const target = lc(b.email);
      const raw = await rcmd(["GET","cl:"+id]);
      if (!raw) return res.status(404).json({ ok:false, error:"Client not found." });
      let ex; try { ex = JSON.parse(raw); } catch(e){ ex = {}; }
      if (ex._owner !== email) return res.status(403).json({ ok:false, error:"Only the owner can change sharing." });
      if (!isEmail(target)) return res.json({ ok:false, error:"Enter a valid email." });
      if (op === "share") {
        const tRaw = await rcmd(["GET","user:"+target]);
        if (!tRaw) return res.json({ ok:false, error:"No approved account with that email yet. Ask them to sign up first." });
        try { if (JSON.parse(tRaw).status !== "approved") return res.json({ ok:false, error:"That account isn't approved yet." }); } catch(e){}
        await rcmd(["SADD","acl:"+id, target]);
        await rcmd(["SADD","uc:"+target, id]);
      } else {
        if (target === ex._owner) return res.json({ ok:false, error:"You can't remove the owner." });
        await rcmd(["SREM","acl:"+id, target]);
        await rcmd(["SREM","uc:"+target, id]);
      }
      const shared = (await rcmd(["SMEMBERS","acl:"+id])) || [];
      return res.json({ ok:true, shared });
    }

    return res.json({ ok:false, error:"Unknown op." });
  } catch(e) { res.status(500).json({ ok:false, error:String(e.message || e) }); }
};
