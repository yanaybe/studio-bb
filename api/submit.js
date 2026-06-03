// Studio BB — Onboarding Form API
// Server-side: rate limiting, validation, sanitization, webhook forwarding
// Deploy to Vercel. Set WEBHOOK_URL in Vercel environment variables.

const rateStore = new Map();
const RATE_WINDOW_MS = 60_000; // 1 minute
const RATE_MAX = 3;            // max 3 submissions per IP per minute

function checkRate(ip) {
  const now = Date.now();
  const r = rateStore.get(ip) || { count: 0, start: now };
  if (now - r.start > RATE_WINDOW_MS) {
    rateStore.set(ip, { count: 1, start: now });
    return true;
  }
  if (r.count >= RATE_MAX) return false;
  r.count++;
  rateStore.set(ip, r);
  return true;
}

// Clean old entries every 5 minutes to prevent memory leak
setInterval(() => {
  const cutoff = Date.now() - RATE_WINDOW_MS * 2;
  for (const [key, val] of rateStore.entries()) {
    if (val.start < cutoff) rateStore.delete(key);
  }
}, 300_000);

function sanitize(value, maxLen = 1000) {
  return String(value || '').trim().slice(0, maxLen);
}

const ALLOWED_GOALS   = ['whatsapp', 'phone', 'lead_form', 'booking', 'purchase', 'signup'];
const ALLOWED_STYLES  = ['dark', 'light', 'warm', 'bold', 'formal'];
const ALLOWED_TIMELINES = ['asap', 'month', 'two_months', 'flexible'];
const EMAIL_RE        = /^[^\s@]{1,64}@[^\s@]{1,253}\.[^\s@]{2,}$/;
const PHONE_RE        = /^[\d\s\-\+\(\)]{7,20}$/;
const URL_RE          = /^https?:\/\/.{1,500}$/;

module.exports = async function handler(req, res) {
  // Only POST allowed
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // IP-based rate limiting
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
             req.headers['x-real-ip'] ||
             req.socket?.remoteAddress ||
             'unknown';

  if (!checkRate(ip)) {
    return res.status(429).json({ error: 'יותר מדי בקשות. המתן דקה ונסה שנית.' });
  }

  const b = req.body || {};

  // Honeypot — bots fill this, humans don't
  if (b._gotcha) {
    return res.status(200).json({ ok: true }); // silent fake success
  }

  // ── Required fields ─────────────────────────────────────
  const required = [
    'business_name', 'contact_name', 'phone', 'email',
    'goal', 'promoted_service', 'business_description', 'page_contact',
  ];
  for (const field of required) {
    if (!b[field] || !String(b[field]).trim()) {
      return res.status(400).json({ error: `שדה חסר: ${field}` });
    }
  }

  // ── Format validation ────────────────────────────────────
  if (!EMAIL_RE.test(b.email)) {
    return res.status(400).json({ error: 'כתובת מייל לא תקינה' });
  }
  if (!PHONE_RE.test(b.phone)) {
    return res.status(400).json({ error: 'מספר טלפון לא תקין' });
  }
  if (!ALLOWED_GOALS.includes(b.goal)) {
    return res.status(400).json({ error: 'ערך לא חוקי עבור שדה מטרה' });
  }
  if (b.design_style && !ALLOWED_STYLES.includes(b.design_style)) {
    return res.status(400).json({ error: 'ערך לא חוקי עבור שדה סגנון' });
  }
  if (b.timeline && !ALLOWED_TIMELINES.includes(b.timeline)) {
    return res.status(400).json({ error: 'ערך לא חוקי עבור שדה לוח זמנים' });
  }
  if (b.booking_link && !URL_RE.test(b.booking_link)) {
    return res.status(400).json({ error: 'קישור הזמנות לא תקין' });
  }
  if (b.video_link && !URL_RE.test(b.video_link)) {
    return res.status(400).json({ error: 'קישור סרטון לא תקין' });
  }

  // ── Sanitize & build payload ─────────────────────────────
  const payload = {
    business_name:        sanitize(b.business_name,        200),
    contact_name:         sanitize(b.contact_name,         100),
    phone:                sanitize(b.phone,                  20),
    email:                sanitize(b.email,                 200),
    goal:                 sanitize(b.goal,                   50),
    promoted_service:     sanitize(b.promoted_service,      300),
    business_description: sanitize(b.business_description,  500),
    page_contact:         sanitize(b.page_contact,          500),
    social_links:         sanitize(b.social_links,          500),
    booking_link:         sanitize(b.booking_link,          200),
    testimonials_text:    sanitize(b.testimonials_text,    2000),
    brand_colors:         sanitize(b.brand_colors,          100),
    design_style:         sanitize(b.design_style,           50),
    example_sites:        sanitize(b.example_sites,         500),
    video_link:           sanitize(b.video_link,            200),
    special_notes:        sanitize(b.special_notes,        1000),
    timeline:             sanitize(b.timeline,               50),
    submitted_at:         new Date().toISOString(),
  };

  // ── Forward to webhook ───────────────────────────────────
  const webhookUrl = process.env.WEBHOOK_URL;

  if (!webhookUrl) {
    // No webhook configured yet — return success (demo mode)
    return res.status(200).json({ ok: true });
  }

  try {
    const webhookRes = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!webhookRes.ok) throw new Error('webhook_error');
    return res.status(200).json({ ok: true });
  } catch {
    // Don't expose internal error details
    return res.status(502).json({ error: 'שגיאת שרת. נסה שנית או פנה אלינו ב-WhatsApp.' });
  }
};
