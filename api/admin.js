const crypto = require("crypto");
const RURL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const RTOK = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
async function rcmd(cmd){ const r = await fetch(RURL, { method:"POST", headers:{ Authorization:"Bearer "+RTOK, "Content-Type":"application/json" }, body: JSON.stringify(cmd) }); const j = await r.json(); return j.result; }
function sig(s){ return crypto.createHmac("sha256", process.env.ADMIN_SECRET).update(s).digest("hex").slice(0,32); }
module.exports = async (req, res) => {
  try {
    if ((req.query || {}).sig !== sig("admin")) return res.status(403).send("Not allowed.");
    const host = "https://" + req.headers.host;
    const emails = (await rcmd(["SMEMBERS", "users"])) || [];
    let rows = "";
    for (const em of emails) {
      const raw = await rcmd(["GET", "user:"+em]); if (!raw) continue;
      const u = JSON.parse(raw);
      const devices = (await rcmd(["SCARD", "dev:"+em])) || 0;
      const s = sig(em);
      const del = " · <a href=\""+host+"/api/approve?email="+encodeURIComponent(em)+"&sig="+s+"&action=delete\" style=\"color:#dc2626\">Delete</a>";
      const act = (u.status === "approved"
        ? "<a href=\""+host+"/api/approve?email="+encodeURIComponent(em)+"&sig="+s+"&action=revoke\" style=\"color:#dc2626\">Revoke</a>"
        : "<a href=\""+host+"/api/approve?email="+encodeURIComponent(em)+"&sig="+s+"&action=approve\">Approve</a>" + (u.status==="pending" ? " · <a href=\""+host+"/api/approve?email="+encodeURIComponent(em)+"&sig="+s+"&action=deny\" style=\"color:#dc2626\">Deny</a>" : "")) + del;
      const badge = u.status==="approved" ? "#15803d" : (u.status==="pending" ? "#b45309" : "#dc2626");
      rows += "<tr><td><strong>"+(u.name||"—")+"</strong><br><span style=\"color:#64748b\">"+em+"</span></td><td><span style=\"color:"+badge+";font-weight:700\">"+u.status+"</span></td><td>"+(u.lastSeen ? u.lastSeen.slice(0,16).replace("T"," ") : "never")+"</td><td>"+devices+"</td><td>"+act+"</td></tr>";
    }
    if (!rows) rows = "<tr><td colspan=5 style=\"color:#64748b\">No access requests yet.</td></tr>";
    res.send("<!DOCTYPE html><html><head><meta charset=utf-8><title>SDP Workspace — Admin</title><style>body{font-family:Arial;max-width:860px;margin:40px auto;padding:0 20px;color:#1f2937}h2{color:#7c2d12}table{width:100%;border-collapse:collapse;font-size:14px}td,th{border-bottom:1px solid #e2e8f0;padding:10px 8px;text-align:left;vertical-align:top}th{color:#64748b;font-size:12px;text-transform:uppercase}a{color:#ea580c}</style></head><body><h2>SDP Workspace — People</h2><p style=\"color:#64748b\">Bookmark this page. Approve new sign-ups here; Revoke blocks sign-in but keeps the row; Delete permanently removes it. Devices = how many different browsers that person has signed in from.</p><table><tr><th>Person</th><th>Status</th><th>Last seen</th><th>Devices</th><th>Actions</th></tr>"+rows+"</table></body></html>");
  } catch(e) { res.status(500).send("Error: " + String(e.message || e)); }
};
