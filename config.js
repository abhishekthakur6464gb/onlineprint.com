require("dotenv").config();

const need = (k, fallback) => {
  const v = process.env[k] || fallback;
  if (!v) { console.error(`[config] Missing env var ${k}`); process.exit(1); }
  return v;
};

module.exports = {
  PORT: Number(process.env.PORT || 4000),
  DEV: process.env.NODE_ENV !== "production",
  CORS_ORIGIN: (process.env.CORS_ORIGIN || "*").split(",").map(s => s.trim()),

  JWT_SECRET: need("JWT_SECRET"),
  OTP_PEPPER: need("OTP_PEPPER"),

  OWNER_PASSWORD_HASH: need("OWNER_PASSWORD_HASH"),

  SHOP_PHONE: process.env.SHOP_PHONE || "918318640642",

  // OTP policy
  OTP_TTL_MS: 5 * 60 * 1000,      // 5 minute validity
  OTP_MAX_ATTEMPTS: 5,            // itne galat try ke baad OTP dead
  OTP_RESEND_MS: 60 * 1000,       // resend cooldown
  OTP_MAX_PER_HOUR: 5,            // ek number par per hour limit
  VERIFY_TOKEN_TTL: "20m",        // verify hone ke baad itni der me order banana hoga

  OTP_PROVIDER: process.env.OTP_PROVIDER || "console",
  // OTP_SOURCE: "pool" (owner ke upload kiye codes se) | "phone" (number ke last 6 digit, koi send nahi) | "random"
  OTP_SOURCE: process.env.OTP_SOURCE || "pool",
  MAX_UPLOAD_MB: 25
};
