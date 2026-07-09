const crypto = require("crypto");
const RURL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const RTOK = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
async function rcmd(cmd){ const r = await fetch(RURL, { method:"POST", headers:{ Authorization:"Bearer "+RTOK, "Content-Type":"application/json" }, body: JSON.stringify(cmd) }); const j = await r.json(); return j.result; }
module.exports = async (req, res) => {
  try {
    if (req.method !== "POST") return res.status(405).json({ ok:false });
    const b = req.body || {};
    const token = String(b.token || "").replace(/[^a-zA-Z0-9]/g, "");
    const oldpw = String(b.oldPassword || "");
    const newpw = String(b.newPassword || "");
    if (!token) return res.json({ ok:false, error:"You must be signed in to change your password." });
    if (newpw.length < 6) return res.json({ ok:false, error:"New password must be at least 6 characters." });
    const em = await rcmd(["GET", "token:"+token]);
    if (!em) return res.json({ ok:false, error:"Your session expired — sign in again." });
    const raw = await rcmd(["GET", "user:"+em]);
    if (!raw) return res.json({ ok:false, error:"Account not found." });
    const u = JSON.parse(raw);
    const h = crypto.scryptSync(oldpw, u.salt, 64).toString("hex");
    const a = Buffer.from(h, "hex"), c = Buffer.from(u.hash, "hex");
    if (a.length !== c.length || !crypto.timingSafeEqual(a, c)) return res.json({ ok:false, error:"Current password is incorrect." });
    u.salt = crypto.randomBytes(16).toString("hex");
    u.hash = crypto.scryptSync(newpw, u.salt, 64).toString("hex");
    await rcmd(["SET", "user:"+em, JSON.stringify(u)]);
    res.json({ ok:true, message:"Password changed." });
  } catch(e) { res.status(500).json({ ok:false, error:String(e.message || e) }); }
};
