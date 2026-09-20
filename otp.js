const crypto = require("crypto");
const C = require("./config");
const store = require("./store");
const { sendOtp } = require("./messaging");

const hashCode = (phone, code) =>
  crypto.createHmac("sha256", C.OTP_PEPPER).update(`${phone}:${code}`).digest("hex");

const sixDigit = () => String(crypto.randomInt(100000, 1000000));
const deriveFromPhone = phone => phone.slice(-6);

/** Pool se ek code nikaalta hai aur hamesha ke liye pool se hata deta hai (reuse kabhi nahi). */
async function pullFromPool() {
  const db = store.get();
  const pool = db.config.otpPool.codes;
  if (!pool.length) {
    const err = new Error("OTP codes khatam ho gaye hain — owner ko naye codes upload karne hain.");
    err.status = 503; throw err;
  }
  const i = crypto.randomInt(0, pool.length);
  const [code] = pool.splice(i, 1);
  db.config.otpPool.usedTotal += 1;
  await store.save();
  return code;
}

/** Plain OTP kabhi store nahi hota — sirf HMAC hash. */
async function issue(phone) {
  const db = store.get();
  const now = Date.now();
  const rec = db.otps[phone] || { sentTimes: [] };

  if (rec.lastSentAt && now - rec.lastSentAt < C.OTP_RESEND_MS) {
    const wait = Math.ceil((C.OTP_RESEND_MS - (now - rec.lastSentAt)) / 1000);
    const err = new Error(`Thoda ruko, ${wait}s baad dobara try karo.`);
    err.status = 429; throw err;
  }
  rec.sentTimes = (rec.sentTimes || []).filter(t => now - t < 60 * 60 * 1000);
  // Yahi hai "5 baar se zyada 1 ghante me nahi" wala rule — OTP_MAX_PER_HOUR ke through.
  if (rec.sentTimes.length >= C.OTP_MAX_PER_HOUR) {
    const err = new Error("Is number par bahut zyada OTP bhej diye gaye. 1 ghante baad try karo.");
    err.status = 429; throw err;
  }

  const source = C.OTP_SOURCE;
  const code = source === "pool" ? await pullFromPool()
             : source === "phone" ? deriveFromPhone(phone)
             : sixDigit();

  db.otps[phone] = {
    hash: hashCode(phone, code),
    expiresAt: now + C.OTP_TTL_MS,
    attempts: 0,
    lastSentAt: now,
    sentTimes: [...rec.sentTimes, now]
  };
  await store.save();
  if (source !== "phone") {
    try {
      await sendOtp(phone, code);
    } catch (e) {
      // Code already reserved ho chuka hai (pool se nikal chuka, hash save ho chuka) —
      // isliye verify abhi bhi possible hai agar owner ko code kisi tarah pata chal jaaye.
      // Lekin student ko clear batana zaroori hai ki message nahi gaya.
      const err = new Error("OTP bhejne me dikkat aayi (WhatsApp/SMS provider). Owner se sampark karo ya thodi der baad try karo.");
      err.status = 502; throw err;
    }
  }

  return {
    expiresIn: Math.floor(C.OTP_TTL_MS / 1000),
    derived: source === "phone",     // frontend isse decide karta hai kya honest fallback message dikhana hai
    devCode: C.DEV ? code : undefined
  };
}

/** Timing-safe compare + attempt counting. */
async function verify(phone, code) {
  const db = store.get();
  const rec = db.otps[phone];
  const fail = (m, s = 400) => { const e = new Error(m); e.status = s; return e; };

  if (!rec) throw fail("Pehle OTP request karo.");
  if (Date.now() > rec.expiresAt) { delete db.otps[phone]; await store.save(); throw fail("OTP expire ho gaya."); }
  if (rec.attempts >= C.OTP_MAX_ATTEMPTS) { delete db.otps[phone]; await store.save(); throw fail("Bahut galat try. Naya OTP lo.", 429); }

  const a = Buffer.from(rec.hash, "hex");
  const b = Buffer.from(hashCode(phone, String(code || "")), "hex");
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);

  if (!ok) {
    rec.attempts += 1;
    await store.save();
    throw fail(`Galat OTP. ${C.OTP_MAX_ATTEMPTS - rec.attempts} try bache hain.`);
  }
  delete db.otps[phone];   // one-time use
  await store.save();
  return true;
}

module.exports = { issue, verify };
