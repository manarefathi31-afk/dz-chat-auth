const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(cors());
app.use(express.json());

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const SENDER_EMAIL = process.env.SENDER_EMAIL;
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});

const pendingEmailRegs = new Map();
const otpDB = new Map();
const tgSessions = new Map();

app.get("/", (req, res) => res.send("DZ_CHAT Auth Server Connected to Supabase!"));

async function sendEmailOTP(toEmail, code) {
  const r = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: { "accept": "application/json", "api-key": BREVO_API_KEY, "content-type": "application/json" },
    body: JSON.stringify({
      sender: { name: "DZ_CHAT", email: SENDER_EMAIL },
      to: [{ email: toEmail }],
      subject: "رمز التحقق الخاص بك - DZ_CHAT",
      htmlContent: `<div dir="rtl" style="font-family:Tahoma;"><h2>رمز التحقق في DZ_CHAT هو: <b>${code}</b></h2><p>هذا الرمز صالح لمدة 5 دقائق.</p></div>`
    })
  });
  if (!r.ok) throw new Error("فشل إرسال رسالة Gmail");
}

async function sendTelegramMessage(chatId, text) {
  const r = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: chatId, text, parse_mode: "HTML" })
  });
  if (!r.ok) throw new Error("فشل إرسال رسالة تيليجرام");
}

async function findSupabaseUser(identifier) {
  const clean = identifier.trim().replace(/^@+/, "");
  if (!clean.includes("@")) {
    const { data: prof } = await supabaseAdmin.from("profiles").select("id").ilike("username", clean).maybeSingle();
    if (prof?.id) {
      const { data: uRes } = await supabaseAdmin.auth.admin.getUserById(prof.id);
      if (uRes?.user) return uRes.user;
    }
  }
  const target = clean.toLowerCase();
  let page = 1;
  while (true) {
    const { data, error } = await supabaseAdmin.auth.admin.listUsers({ page, perPage: 500 });
    if (error || !data?.users?.length) break;
    const found = data.users.find(u =>
      (u.email && u.email.toLowerCase() === target) ||
      (u.user_metadata?.recovery_email && u.user_metadata.recovery_email.toLowerCase() === target) ||
      (u.user_metadata?.username && u.user_metadata.username.toLowerCase() === target)
    );
    if (found) return found;
    if (data.users.length < 500) break;
    page++;
  }
  return null;
}

app.post("/api/telegram-webhook", async (req, res) => {
  try {
    const msg = req.body.message;
    if (msg && msg.text && msg.text.startsWith("/start")) {
      const chatId = msg.chat.id, param = msg.text.split(" ")[1];
      if (param && param.startsWith("reg_")) {
        tgSessions.set(param, chatId);
        await sendTelegramMessage(chatId, "✅ تم التحقق من حساب تيليجرام! عد إلى تطبيق <b>DZ_CHAT</b> وأكمل التسجيل.");
      } else if (param && param.startsWith("link_")) {
        const userId = param.replace("link_", "");
        const { data: uRes } = await supabaseAdmin.auth.admin.getUserById(userId);
        if (uRes?.user) {
          await supabaseAdmin.auth.admin.updateUserById(userId, {
            user_metadata: { ...(uRes.user.user_metadata || {}), telegram_chat_id: chatId }
          });
          await sendTelegramMessage(chatId, "✅ تم ربط حسابك في <b>DZ_CHAT</b> بتيليجرام بنجاح! يمكنك الآن استعادة كلمة المرور من هنا.");
        }
      } else {
        await sendTelegramMessage(chatId, "أهلاً بك في بوت <b>DZ_CHAT</b>! استخدم التطبيق للتسجيل أو ربط حسابك.");
      }
    }
  } catch (e) { console.error(e); }
  res.sendStatus(200);
});

app.post("/api/login-username", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await findSupabaseUser(username);
    if (!user) return res.status(400).json({ message: "بيانات الدخول غير صحيحة" });

    const tempClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false }
    });
    const { data, error } = await tempClient.auth.signInWithPassword({ email: user.email, password });
    if (error || !data?.session) return res.status(400).json({ message: "اسم المستخدم أو كلمة المرور غير صحيحة" });
    res.json({ session: data.session });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.post("/api/register-email", async (req, res) => {
  try {
    const { email, username, password } = req.body;
    const exists = await findSupabaseUser(email);
    if (exists) return res.status(400).json({ message: "هذا البريد مسجل مسبقاً، يمكنك تسجيل الدخول" });

    const uname = username || email.split("@")[0];
    const code = crypto.randomInt(100000, 999999).toString();
    pendingEmailRegs.set(email.toLowerCase(), { username: uname, password, code, expiresAt: Date.now() + 5 * 60 * 1000 });
    await sendEmailOTP(email, code);
    res.json({ message: "تم إرسال الرمز" });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.post("/api/verify-email", async (req, res) => {
  try {
    const email = (req.body.email || "").toLowerCase(), otp = req.body.otp;
    const rec = pendingEmailRegs.get(email);
    if (!rec || rec.code !== otp || Date.now() > rec.expiresAt) {
      return res.status(400).json({ message: "الرمز غير صحيح أو منتهي الصلاحية" });
    }
    const { data, error } = await supabaseAdmin.auth.admin.createUser({
      email, password: rec.password, email_confirm: true,
      user_metadata: { username: rec.username, display_name: rec.username, recovery_email: email }
    });
    if (error) return res.status(400).json({ message: error.message });
    pendingEmailRegs.delete(email);
    res.json({ id: data.user.id, email });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.post("/api/register-telegram", async (req, res) => {
  try {
    const { tgSessionToken, username, authEmail, recoveryEmail, password } = req.body;
    const chatId = tgSessions.get(tgSessionToken);
    if (!chatId) return res.status(400).json({ message: "يرجى فتح بوت تيليجرام والضغط على Start أولاً" });
    if (await findSupabaseUser(username)) return res.status(400).json({ message: "اسم المستخدم محجوز، اختر اسماً آخر" });

    const { data, error } = await supabaseAdmin.auth.admin.createUser({
      email: authEmail, password, email_confirm: true,
      user_metadata: { username, display_name: username, telegram_chat_id: chatId, recovery_email: recoveryEmail || null }
    });
    if (error) return res.status(400).json({ message: error.message });
    tgSessions.delete(tgSessionToken);
    res.json({ id: data.user.id, email: authEmail });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.post("/api/forgot-password", async (req, res) => {
  try {
    const { identifier, method } = req.body;
    const user = await findSupabaseUser(identifier);
    if (!user) return res.status(404).json({ message: "لم يتم العثور على هذا الحساب" });

    const code = crypto.randomInt(100000, 999999).toString();
    if (method === "email") {
      const targetEmail = user.user_metadata?.recovery_email || (user.email && !user.email.endsWith("@dzchat.com") ? user.email : null);
      if (!targetEmail) return res.status(400).json({ message: "هذا الحساب لا يملك بريد Gmail، اختر الاستعادة عبر تيليجرام" });
      await sendEmailOTP(targetEmail, code);
    } else {
      const chatId = user.user_metadata?.telegram_chat_id;
      if (!chatId) return res.status(400).json({ message: "هذا الحساب غير مربوط بتيليجرام، اختر Gmail أو اربط تيليجرام من الإعدادات" });
      await sendTelegramMessage(chatId, `🔐 رمز استعادة كلمة مرورك في <b>DZ_CHAT</b> هو: <b>${code}</b>\nصالح لمدة 5 دقائق.`);
    }

    otpDB.set(identifier.toLowerCase().trim(), { userId: user.id, code, expiresAt: Date.now() + 5 * 60 * 1000 });
    res.json({ message: "تم إرسال الرمز" });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.post("/api/reset-password", async (req, res) => {
  try {
    const { identifier, otp, newPassword } = req.body;
    const key = identifier.toLowerCase().trim();
    const rec = otpDB.get(key);
    if (!rec || rec.code !== otp || Date.now() > rec.expiresAt) {
      return res.status(400).json({ message: "الرمز غير صحيح أو منتهي الصلاحية" });
    }
    const { error } = await supabaseAdmin.auth.admin.updateUserById(rec.userId, { password: newPassword });
    if (error) return res.status(400).json({ message: error.message });
    otpDB.delete(key);
    res.json({ message: "تم تغيير كلمة المرور" });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on " + PORT));
