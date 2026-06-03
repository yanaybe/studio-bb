// Studio BB — Onboarding Form API
// Server-side: rate limiting, full validation, sanitization, webhook forwarding

// ── RATE LIMITER ──────────────────────────────────────────
const rateStore = new Map();
const RATE_WINDOW = 60_000;
const RATE_MAX    = 3;

function checkRate(ip){
  const now = Date.now();
  const r   = rateStore.get(ip) || { count:0, start:now };
  if(now - r.start > RATE_WINDOW){ rateStore.set(ip,{count:1,start:now}); return true; }
  if(r.count >= RATE_MAX) return false;
  r.count++; rateStore.set(ip,r); return true;
}
setInterval(()=>{
  const cutoff = Date.now() - RATE_WINDOW * 2;
  for(const [k,v] of rateStore) if(v.start < cutoff) rateStore.delete(k);
}, 300_000);

// ── VALIDATION LIBRARY (mirrors client-side V) ────────────
const INJECTION_RE = /<script|javascript:|on\w+\s*=|<iframe|<object|<embed|<form|expression\s*\(/i;

const V = {
  hasInjection(v){ return INJECTION_RE.test(String(v||'')); },

  name(val){
    const v = String(val||'').trim();
    if(!v)          return 'שדה חובה';
    if(v.length<2)  return 'מינימום 2 תווים';
    if(v.length>100) return 'מקסימום 100 תווים';
    if(/^\d+$/.test(v)) return 'שם לא יכול להכיל ספרות בלבד';
    if(this.hasInjection(v)) return 'תוכן לא חוקי';
    if(!/^[֐-׿‏‎a-zA-ZÀ-ÿ\s\-'.]+$/.test(v)) return 'תווים לא חוקיים';
    return null;
  },

  email(val){
    const v = String(val||'').trim().toLowerCase();
    if(!v)           return 'שדה חובה';
    if(v.length>254) return 'כתובת מייל ארוכה מדי';
    if(!/^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$/.test(v)) return 'כתובת מייל לא תקינה';
    if((v.match(/@/g)||[]).length !== 1) return 'כתובת מייל לא תקינה';
    return null;
  },

  phone(val){
    const v       = String(val||'').trim();
    if(!v)        return 'שדה חובה';
    const stripped = v.replace(/[\s\-\(\)\.]/g,'');
    const digits   = stripped.startsWith('+') ? stripped.slice(1) : stripped;
    if(!/^\d+$/.test(digits))  return 'ספרות בלבד';
    if(digits.length < 7)      return 'מספר קצר מדי';
    if(digits.length > 15)     return 'מספר ארוך מדי';
    if(/^(.)\1{6,}$/.test(digits)) return 'מספר טלפון לא תקין';
    return null;
  },

  url(val, required = false){
    const v = String(val||'').trim();
    if(!v) return required ? 'שדה חובה' : null;
    if(this.hasInjection(v)) return 'כתובת URL לא תקינה';
    const u = /^https?:\/\//i.test(v) ? v : `https://${v}`;
    try {
      const parsed = new URL(u);
      if(!['http:','https:'].includes(parsed.protocol)) return 'כתובת URL לא תקינה';
      if(!parsed.hostname.includes('.'))               return 'כתובת URL לא תקינה';
      return null;
    } catch { return 'כתובת URL לא תקינה'; }
  },

  text(val, {min=0, max=1000, required=false} = {}){
    const v = String(val||'').trim();
    if(!v) return required ? 'שדה חובה' : null;
    if(v.length < min) return `מינימום ${min} תווים`;
    if(v.length > max) return `מקסימום ${max} תווים`;
    if(this.hasInjection(v)) return 'תוכן לא חוקי';
    return null;
  },

  socialLinks(val){
    if(!val || !String(val).trim()) return null;
    for(const line of String(val).trim().split('\n')){
      const l = line.trim();
      if(!l) continue;
      const err = this.url(l);
      if(err) return `קישור לא תקין: "${l.slice(0,40)}"`;
    }
    return null;
  },
};

const ALLOWED_GOALS     = ['whatsapp','phone','lead_form','booking','purchase','signup'];
const ALLOWED_STYLES    = ['dark','light','warm','bold','formal'];
const ALLOWED_TIMELINES = ['asap','month','two_months','flexible',''];

// ── SANITIZER ─────────────────────────────────────────────
function san(v, max = 1000){
  return String(v||'').trim().slice(0, max);
}

// ── HANDLER ───────────────────────────────────────────────
module.exports = async function handler(req, res){
  if(req.method !== 'POST') return res.status(405).json({error:'Method not allowed'});

  // Rate limit by IP
  const ip = (req.headers['x-forwarded-for']||'').split(',')[0].trim() ||
              req.headers['x-real-ip'] || 'unknown';
  if(!checkRate(ip)) return res.status(429).json({error:'יותר מדי בקשות. המתן דקה ונסה שנית.'});

  const b = req.body || {};

  // Honeypot
  if(b._gotcha) return res.status(200).json({ok:true});

  // ── Required field checks ──────────────────────────────
  const nameErr  = V.name(b.business_name);
  if(nameErr)  return res.status(400).json({error:`שם עסק: ${nameErr}`});

  const cnameErr = V.name(b.contact_name);
  if(cnameErr) return res.status(400).json({error:`שם איש קשר: ${cnameErr}`});

  const phoneErr = V.phone(b.phone);
  if(phoneErr) return res.status(400).json({error:`טלפון: ${phoneErr}`});

  const emailErr = V.email(b.email);
  if(emailErr) return res.status(400).json({error:`מייל: ${emailErr}`});

  if(!b.goal || !ALLOWED_GOALS.includes(b.goal))
    return res.status(400).json({error:'נא לבחור מטרה תקינה'});

  const svcErr = V.text(b.promoted_service, {min:3, max:300, required:true});
  if(svcErr)   return res.status(400).json({error:`שירות: ${svcErr}`});

  const descErr = V.text(b.business_description, {min:20, max:500, required:true});
  if(descErr)   return res.status(400).json({error:`תיאור עסק: ${descErr}`});

  const contactErr = V.text(b.page_contact, {min:5, max:500, required:true});
  if(contactErr)   return res.status(400).json({error:`פרטי קשר: ${contactErr}`});

  const sitesErr = V.text(b.example_sites, {min:10, max:500, required:true});
  if(sitesErr)    return res.status(400).json({error:`אתרים לדוגמה: ${sitesErr}`});

  // ── Optional field checks ──────────────────────────────
  if(b.social_links){
    const slErr = V.socialLinks(b.social_links);
    if(slErr) return res.status(400).json({error:`קישורים: ${slErr}`});
  }

  if(b.booking_link && b.booking_link.trim()){
    const blErr = V.url(b.booking_link);
    if(blErr) return res.status(400).json({error:`קישור הזמנות: ${blErr}`});
  }

  if(b.video_link && b.video_link.trim()){
    const vlErr = V.url(b.video_link);
    if(vlErr) return res.status(400).json({error:`קישור סרטון: ${vlErr}`});
  }

  if(b.design_style && !ALLOWED_STYLES.includes(b.design_style))
    return res.status(400).json({error:'ערך לא חוקי עבור סגנון עיצוב'});

  if(b.timeline && !ALLOWED_TIMELINES.includes(b.timeline))
    return res.status(400).json({error:'ערך לא חוקי עבור לוח זמנים'});

  const notesErr = V.text(b.special_notes, {max:1000});
  if(notesErr) return res.status(400).json({error:`הערות: ${notesErr}`});

  const colorsErr = V.text(b.brand_colors, {max:100});
  if(colorsErr) return res.status(400).json({error:`צבעים: ${colorsErr}`});

  const testimonialsErr = V.text(b.testimonials_text, {max:2000});
  if(testimonialsErr) return res.status(400).json({error:`עדויות: ${testimonialsErr}`});

  // ── Build sanitized payload ────────────────────────────
  const payload = {
    business_name:        san(b.business_name,        200),
    contact_name:         san(b.contact_name,         100),
    phone:                san(b.phone,                 20),
    email:                san(b.email,                200).toLowerCase(),
    goal:                 san(b.goal,                  50),
    promoted_service:     san(b.promoted_service,     300),
    business_description: san(b.business_description, 500),
    page_contact:         san(b.page_contact,          500),
    social_links:         san(b.social_links,          500),
    booking_link:         san(b.booking_link,          200),
    testimonials_text:    san(b.testimonials_text,    2000),
    brand_colors:         san(b.brand_colors,          100),
    design_style:         san(b.design_style,           50),
    example_sites:        san(b.example_sites,         500),
    video_link:           san(b.video_link,            300),
    special_notes:        san(b.special_notes,        1000),
    timeline:             san(b.timeline,               50),
    submitted_at:         new Date().toISOString(),
  };

  // ── Forward to webhook ────────────────────────────────
  const webhookUrl = process.env.WEBHOOK_URL;
  if(!webhookUrl) return res.status(200).json({ok:true}); // demo mode

  try {
    const r = await fetch(webhookUrl,{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload),
    });
    if(!r.ok) throw new Error('webhook');
    return res.status(200).json({ok:true});
  } catch {
    return res.status(502).json({error:'שגיאת שרת. נסה שנית או פנה אלינו ב-WhatsApp.'});
  }
};
