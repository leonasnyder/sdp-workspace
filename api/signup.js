const crypto = require("crypto");
const RURL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const RTOK = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
async function rcmd(cmd){ const r = await fetch(RURL, { method:"POST", headers:{ Authorization:"Bearer "+RTOK, "Content-Type":"application/json" }, body: JSON.stringify(cmd) }); const j = await r.json(); return j.result; }
function sig(s){ return crypto.createHmac("sha256", process.env.ADMIN_SECRET).update(s).digest("hex").slice(0,32); }
module.exports = async (req, res) => {
  try {
    if (req.method !== "POST") return res.status(405).json({ ok:false });
    const b = req.body || {};
    const em = String(b.email || "").trim().toLowerCase();
    const nm = String(b.name || "").trim().slice(0, 80);
    const pw = String(b.password || "");
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) return res.status(400).json({ ok:false, error:"Please enter a valid email." });
    if (pw.length < 6) return res.status(400).json({ ok:false, error:"Password must be at least 6 characters." });
    const ex = await rcmd(["GET", "user:"+em]);
    if (ex) {
      const u = JSON.parse(ex);
      if (u.status === "approved") return res.json({ ok:true, message:"You already have an account — please sign in." });
      if (u.status === "pending") return res.json({ ok:true, message:"Your account is already awaiting approval." });
    }
    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto.scryptSync(pw, salt, 64).toString("hex");
    await rcmd(["SET", "user:"+em, JSON.stringify({ name:nm, email:em, status:"pending", salt, hash, requestedAt:new Date().toISOString() })]);
    await rcmd(["SADD", "users", em]);
    const host = "https://" + req.headers.host;
    const s = sig(em);
    const html = "<p><strong>" + (nm || "(no name)") + " &lt;" + em + "&gt;</strong> created an account and is awaiting your approval.</p>" +
      "<p><a href=\"" + host + "/api/approve?email=" + encodeURIComponent(em) + "&sig=" + s + "&action=approve\">APPROVE</a> &nbsp;|&nbsp; " +
      "<a href=\"" + host + "/api/approve?email=" + encodeURIComponent(em) + "&sig=" + s + "&action=deny\">DENY</a></p>" +
      "<p>Once approved, they sign in with the email &amp; password they chose. Manage everyone: <a href=\"" + host + "/api/admin?sig=" + sig("admin") + "\">admin panel</a></p>";
    await fetch("https://api.resend.com/emails", { method:"POST", headers:{ Authorization:"Bearer "+process.env.RESEND_API_KEY, "Content-Type":"application/json" }, body: JSON.stringify({ from:"SDP Workspace <onboarding@resend.dev>", to:[process.env.ADMIN_EMAIL], subject:"SDP Workspace new account: "+em, html }) });
    res.json({ ok:true, message:"Account created! You'll be able to sign in once your facilitator approves it." });
  } catch(e) { res.status(500).json({ ok:false, error:String(e.message || e) }); }
};
