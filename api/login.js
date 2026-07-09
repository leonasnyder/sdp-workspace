const crypto = require("crypto");
const RURL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const RTOK = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
async function rcmd(cmd){ const r = await fetch(RURL, { method:"POST", headers:{ Authorization:"Bearer "+RTOK, "Content-Type":"application/json" }, body: JSON.stringify(cmd) }); const j = await r.json(); return j.result; }
module.exports = async (req, res) => {
  try {
    if (req.method !== "POST") return res.status(405).json({ ok:false });
    const b = req.body || {};
    const em = String(b.email || "").trim().toLowerCase();
    const pw = String(b.password || "");
    if (!em || !pw) return res.status(400).json({ ok:false, error:"Enter your email and password." });
    const raw = await rcmd(["GET", "user:"+em]);
    if (!raw) return res.json({ ok:false, error:"No account found for that email. Create one below." });
    const u = JSON.parse(raw);
    if (!u.salt || !u.hash) return res.json({ ok:false, error:"This account has no password set. Ask your facilitator to reset it." });
    const h = crypto.scryptSync(pw, u.salt, 64).toString("hex");
    const a = Buffer.from(h, "hex"), c = Buffer.from(u.hash, "hex");
    if (a.length !== c.length || !crypto.timingSafeEqual(a, c)) return res.json({ ok:false, error:"Incorrect password." });
    if (u.status === "pending") return res.json({ ok:false, error:"Your account is awaiting approval by your facilitator." });
    if (u.status !== "approved") return res.json({ ok:false, error:"This account is not active. Contact your facilitator." });
    const token = crypto.randomUUID().replace(/-/g, "");
    await rcmd(["SET", "token:"+token, em]);
    u.token = token; u.lastSeen = new Date().toISOString();
    await rcmd(["SET", "user:"+em, JSON.stringify(u)]);
    if (b.device) await rcmd(["SADD", "dev:"+em, String(b.device).slice(0,64)]);
    res.json({ ok:true, token, name:u.name || "" });
  } catch(e) { res.status(500).json({ ok:false, error:String(e.message || e) }); }
};
