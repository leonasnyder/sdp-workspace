module.exports = async (req, res) => {
  try {
    const key = process.env.RESEND_API_KEY || "";
    const admin = process.env.ADMIN_EMAIL || "";
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: "Bearer " + key, "Content-Type": "application/json" },
      body: JSON.stringify({ from: "SDP Workspace <onboarding@resend.dev>", to: [admin], subject: "SDP test", html: "<p>test</p>" })
    });
    const text = await r.text();
    res.status(200).json({ status: r.status, adminEndsWith: admin.slice(-16), keyPrefix: key.slice(0,6), keyLen: key.length, resend: text.slice(0,300) });
  } catch (e) { res.status(200).json({ error: String(e.message || e) }); }
};
