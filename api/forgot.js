const crypto = require("crypto");
const RURL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const RTOK = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
async function rcmd(cmd){ const r = await fetch(RURL, { method:"POST", headers:{ Authorization:"Bearer "+RTOK, "Content-Type":"application/json" }, body: JSON.stringify(cmd) }); const j = await r.json(); return j.result; }
function sig(s){ return crypto.createHmac("sha256", process.env.ADMIN_SECRET).update(s).digest("hex").slice(0,32); }
module.exports = async (req, res) => {
  try {
    if (req.method !== "POST") return res.status(405).json({ ok:false });
    const em = String((req.body||{}).email || "").trim().toLowerCase();
    const generic = { ok:true, message:"If that account exists, your facilitator has been notified to reset your password. They'll share a temporary password with you." };
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) return res.json(generic);
    const raw = await rcmd(["GET", "user:"+em]);
    if (!raw) return res.json(generic);
    const u = JSON.parse(raw);
    const host = "https://" + req.headers.host;
    const s = sig(em);
    const html = "<p><strong>" + (u.name || em) + " &lt;" + em + "&gt;</strong> requested a password reset.</p>" +
      "<p><a href=\"" + host + "/api/approve?email=" + encodeURIComponent(em) + "&sig=" + s + "&action=resetpw\">RESET THEIR PASSWORD</a> — this generates a temporary password to share with them.</p>" +
      "<p>Or manage everyone: <a href=\"" + host + "/api/admin?sig=" + sig("admin") + "\">admin panel</a></p>";
    await fetch("https://api.resend.com/emails", { method:"POST", headers:{ Authorization:"Bearer "+process.env.RESEND_API_KEY, "Content-Type":"application/json" }, body: JSON.stringify({ from:"SDP Workspace <onboarding@resend.dev>", to:[process.env.ADMIN_EMAIL], subject:"SDP Workspace password reset request: "+em, html }) });
    res.json(generic);
  } catch(e) { res.status(500).json({ ok:false, error:String(e.message || e) }); }
};
