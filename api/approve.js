const crypto = require("crypto");
const RURL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const RTOK = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
async function rcmd(cmd){ const r = await fetch(RURL, { method:"POST", headers:{ Authorization:"Bearer "+RTOK, "Content-Type":"application/json" }, body: JSON.stringify(cmd) }); const j = await r.json(); return j.result; }
function sig(s){ return crypto.createHmac("sha256", process.env.ADMIN_SECRET).update(s).digest("hex").slice(0,32); }
function page(t, b){ return "<!DOCTYPE html><html><head><meta charset=utf-8><title>"+t+"</title><style>body{font-family:Arial;max-width:560px;margin:60px auto;padding:0 20px;color:#1f2937}h2{color:#7c2d12}a{color:#ea580c}</style></head><body><h2>"+t+"</h2>"+b+"</body></html>"; }
module.exports = async (req, res) => {
  try {
    const q = req.query || {};
    const em = String(q.email || "").toLowerCase();
    if (!em || q.sig !== sig(em)) return res.status(403).send(page("Not allowed","This link is invalid."));
    const raw = await rcmd(["GET", "user:"+em]);
    if (!raw) return res.status(404).send(page("Not found","No account for "+em+"."));
    const u = JSON.parse(raw);
    const host = "https://" + req.headers.host;
    const adminLink = "<p><a href=\""+host+"/api/admin?sig="+sig("admin")+"\">Back to admin panel</a></p>";
    if (q.action === "resetpw") {
      const temp = crypto.randomBytes(4).toString("hex").toUpperCase();
      u.salt = crypto.randomBytes(16).toString("hex");
      u.hash = crypto.scryptSync(temp, u.salt, 64).toString("hex");
      if (u.status !== "approved") u.status = "approved";
      if (u.token) { await rcmd(["DEL", "token:"+u.token]); u.token = null; }
      await rcmd(["SET", "user:"+em, JSON.stringify(u)]);
      return res.send(page("Temporary password set", "<p>Give <strong>"+(u.name||em)+"</strong> this temporary password:</p><p style=\"font-size:22px;font-weight:700;color:#7c2d12;background:#fff4ec;padding:10px 16px;border-radius:8px;display:inline-block;letter-spacing:2px\">"+temp+"</p><p>They sign in with their email and this password, then can change it under “Account” in the app.</p>"+adminLink));
    }
    if (q.action === "delete") {
      if (u.token) await rcmd(["DEL", "token:"+u.token]);
      await rcmd(["DEL", "user:"+em]);
      await rcmd(["DEL", "dev:"+em]);
      await rcmd(["SREM", "users", em]);
      return res.send(page("Deleted", "<p><strong>"+em+"</strong> has been permanently removed from the list.</p>"+adminLink));
    }
    if (q.action === "deny" || q.action === "revoke") {
      if (u.token) await rcmd(["DEL", "token:"+u.token]);
      u.status = "revoked"; u.token = null;
      await rcmd(["SET", "user:"+em, JSON.stringify(u)]);
      return res.send(page("Access removed", "<p><strong>"+em+"</strong> can no longer sign in. Any active session ends on their next visit.</p>"+adminLink));
    }
    u.status = "approved";
    u.approvedAt = new Date().toISOString();
    await rcmd(["SET", "user:"+em, JSON.stringify(u)]);
    return res.send(page("Approved ✓", "<p><strong>"+(u.name||em)+"</strong> is approved. They can now sign in at <a href=\""+host+"\">"+host.replace("https://","")+"</a> with the email and password they chose — no link needed.</p>"+adminLink));
  } catch(e) { res.status(500).send("Error: " + String(e.message || e)); }
};
