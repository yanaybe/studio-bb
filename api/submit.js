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
    if(/^\d+$/.test(v))  return 'שם לא יכול להכיל ספרות בלבד';
    if(/^[!@#$%^&*]+$/.test(v)) return 'תווים לא חוקיים';
    if(this.hasInjection(v)) return 'תוכן לא חוקי';
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

// ── CLAUDE PROMPT BUILDER ─────────────────────────────────
function buildClaudePrompt(p, GOAL_MAP, STYLE_MAP, TIMELINE_MAP) {
  const GOAL_CTA = {
    whatsapp: 'a floating WhatsApp button + a prominent "Send WhatsApp" CTA button that opens wa.me link',
    phone: 'a click-to-call CTA button and the phone number displayed prominently',
    lead_form: 'a lead capture form with name, phone, and email fields',
    booking: 'a booking CTA button that links to their scheduling system',
    purchase: 'a strong buy/order CTA with urgency elements',
    signup: 'a newsletter/course signup form with email field',
  };

  const STYLE_GUIDE = {
    dark: 'dark background (#0B1120 or similar deep navy/black), gold or blue accents, premium feel, high contrast white text',
    light: 'clean white background, minimal design, soft shadows, professional typography',
    warm: 'warm earthy tones (beige, terracotta, sage green), organic feel, rounded elements',
    bold: 'vibrant gradients, bold typography, energetic color palette, high visual impact',
    formal: 'navy/charcoal professional palette, structured layout, corporate feel, trust signals prominent',
  };

  const lines = [
`Build me a complete, production-ready landing page as a single HTML file.`,
``,
`━━━ CLIENT BRIEF ━━━`,
``,
`Business: ${p.business_name}`,
`Contact: ${p.contact_name} | ${p.phone} | ${p.email}`,
${p.social_links ? `\`Social/Web: ${p.social_links}\`,` : ''}
``,
`━━━ GOAL ━━━`,
``,
`Primary CTA: ${GOAL_MAP[p.goal] || p.goal}`,
`Implementation: Include ${GOAL_CTA[p.goal] || p.goal}. This is the #1 conversion action — make it impossible to miss.`,
`Service/Product being promoted: ${p.promoted_service}`,
``,
`━━━ ABOUT THE BUSINESS ━━━`,
``,
`${p.business_description}`,
``,
`━━━ CONTACT INFO TO DISPLAY ON PAGE ━━━`,
``,
`${p.page_contact}`,
${p.booking_link ? `\`Booking/Scheduling link: ${p.booking_link}\`,` : ''}
``,
`━━━ DESIGN ━━━`,
``,
`Style: ${STYLE_MAP[p.design_style] || p.design_style || 'modern and clean'}`,
`Visual direction: ${STYLE_GUIDE[p.design_style] || 'clean modern design with strong hierarchy'}`,
${p.brand_colors ? `\`Brand colors: ${p.brand_colors}\`,` : ''}
`Reference sites the client likes:`,
`${p.example_sites}`,
``,
`━━━ CONTENT TO INCLUDE ━━━`,
${p.testimonials_text ? `\`\`,\`Testimonials/Social proof:\`,\`${p.testimonials_text}\`,` : ''}
${p.video_link ? `\`\`,\`Video to embed: ${p.video_link}\`,` : ''}
${p.special_notes ? `\`\`,\`⚠️ Special notes from client:\`,\`${p.special_notes}\`,` : ''}
``,
`━━━ TECHNICAL REQUIREMENTS ━━━`,
``,
`- Single HTML file with all CSS and JS inline (no external dependencies except Google Fonts)`,
`- Mobile-first, fully responsive (looks perfect on iPhone)`,
`- RTL layout (Hebrew/Arabic direction)`,
`- Fast loading — no heavy libraries`,
`- WhatsApp float button bottom-left (number: ${p.phone})`,
`- Smooth scroll animations (IntersectionObserver reveal on scroll)`,
`- All CTAs must link to real contact info provided above`,
`- Timeline: ${TIMELINE_MAP[p.timeline] || p.timeline || 'ASAP'}`,
``,
`━━━ PAGE SECTIONS (in order) ━━━`,
``,
`1. Hero — bold headline, subheadline, primary CTA button, trust signals`,
`2. About / What we do — business description, key benefits`,
`3. Services / What you get — 3-4 key service cards with icons`,
`4. Social proof — testimonials${p.testimonials_text ? ' (use the testimonials provided above)' : ' (create 3 believable placeholder testimonials)'}`,
`5. CTA section — strong conversion block with the primary CTA`,
`6. Contact / Footer — all contact details provided above`,
``,
`Make it stunning. Every section should have a clear purpose and push the visitor toward the CTA.`,
`The design should feel like it cost ₪10,000. Use creative layout, micro-animations, and visual hierarchy.`,
`Do not use placeholder text — use the real business information provided above throughout.`,
  ];

  return lines
    .filter(l => l !== undefined && l !== null)
    .join('\n')
    .replace(/`/g, '');
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

  // ── Send email via Resend ─────────────────────────────
  const resendKey = process.env.RESEND_API_KEY;
  if(!resendKey) return res.status(200).json({ok:true}); // no key = demo mode

  const GOAL_MAP = {
    whatsapp:'WhatsApp',phone:'טלפון',lead_form:'טופס ליד',
    booking:'קביעת תור',purchase:'רכישה',signup:'הרשמה',
  };
  const STYLE_MAP = {
    dark:'כהה ומודרני',light:'בהיר ונקי',warm:'חם ואורגני',
    bold:'צבעוני ועז',formal:'פורמלי ומקצועי',
  };
  const TIMELINE_MAP = {
    asap:'בהקדם האפשרי',month:'תוך חודש',
    two_months:'תוך חודשיים',flexible:'אין דחיפות',
  };

  const emailHtml = `
<div dir="rtl" style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#1e293b">
  <div style="background:#2563EB;padding:24px 32px;border-radius:12px 12px 0 0">
    <h1 style="color:#fff;margin:0;font-size:1.3rem">📋 שאלון לקוח חדש — Studio BB</h1>
    <p style="color:rgba(255,255,255,.75);margin:6px 0 0;font-size:.9rem">${new Date().toLocaleString('he-IL')}</p>
  </div>
  <div style="background:#f8fafc;padding:32px;border-radius:0 0 12px 12px;border:1px solid #e2e8f0;border-top:none">

    <h2 style="font-size:1rem;color:#64748b;margin:0 0 16px;text-transform:uppercase;letter-spacing:.05em">פרטי העסק</h2>
    <table style="width:100%;border-collapse:collapse;margin-bottom:28px">
      <tr><td style="padding:8px 0;color:#64748b;width:40%">שם העסק</td><td style="padding:8px 0;font-weight:700">${payload.business_name}</td></tr>
      <tr><td style="padding:8px 0;color:#64748b">איש קשר</td><td style="padding:8px 0;font-weight:700">${payload.contact_name}</td></tr>
      <tr><td style="padding:8px 0;color:#64748b">טלפון</td><td style="padding:8px 0"><a href="tel:${payload.phone}" style="color:#2563EB">${payload.phone}</a></td></tr>
      <tr><td style="padding:8px 0;color:#64748b">מייל</td><td style="padding:8px 0"><a href="mailto:${payload.email}" style="color:#2563EB">${payload.email}</a></td></tr>
      ${payload.social_links ? `<tr><td style="padding:8px 0;color:#64748b">סושיאל</td><td style="padding:8px 0;word-break:break-all">${payload.social_links}</td></tr>` : ''}
    </table>

    <h2 style="font-size:1rem;color:#64748b;margin:0 0 16px;text-transform:uppercase;letter-spacing:.05em">הפרויקט</h2>
    <table style="width:100%;border-collapse:collapse;margin-bottom:28px">
      <tr><td style="padding:8px 0;color:#64748b;width:40%">מטרה</td><td style="padding:8px 0;font-weight:700">${GOAL_MAP[payload.goal]||payload.goal}</td></tr>
      <tr><td style="padding:8px 0;color:#64748b">שירות</td><td style="padding:8px 0">${payload.promoted_service}</td></tr>
      <tr><td style="padding:8px 0;color:#64748b">לוח זמנים</td><td style="padding:8px 0">${TIMELINE_MAP[payload.timeline]||payload.timeline||'לא צוין'}</td></tr>
      <tr><td style="padding:8px 0;color:#64748b">סגנון עיצוב</td><td style="padding:8px 0">${STYLE_MAP[payload.design_style]||payload.design_style||'לא צוין'}</td></tr>
    </table>

    <h2 style="font-size:1rem;color:#64748b;margin:0 0 12px;text-transform:uppercase;letter-spacing:.05em">תיאור העסק</h2>
    <p style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:16px;margin:0 0 28px;line-height:1.7">${payload.business_description}</p>

    <h2 style="font-size:1rem;color:#64748b;margin:0 0 12px;text-transform:uppercase;letter-spacing:.05em">פרטי קשר לדף</h2>
    <p style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:16px;margin:0 0 28px;line-height:1.7;white-space:pre-line">${payload.page_contact}</p>

    ${payload.example_sites ? `<h2 style="font-size:1rem;color:#64748b;margin:0 0 12px;text-transform:uppercase;letter-spacing:.05em">אתרים לדוגמה</h2><p style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:16px;margin:0 0 28px;line-height:1.7;word-break:break-all">${payload.example_sites}</p>` : ''}
    ${payload.testimonials_text ? `<h2 style="font-size:1rem;color:#64748b;margin:0 0 12px;text-transform:uppercase;letter-spacing:.05em">עדויות לקוחות</h2><p style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:16px;margin:0 0 28px;line-height:1.7">${payload.testimonials_text}</p>` : ''}
    ${payload.brand_colors ? `<p style="margin:0 0 8px"><strong>צבעי מותג:</strong> ${payload.brand_colors}</p>` : ''}
    ${payload.booking_link ? `<p style="margin:0 0 8px"><strong>קישור הזמנות:</strong> <a href="${payload.booking_link}" style="color:#2563EB">${payload.booking_link}</a></p>` : ''}
    ${payload.video_link ? `<p style="margin:0 0 8px"><strong>סרטון:</strong> <a href="${payload.video_link}" style="color:#2563EB">${payload.video_link}</a></p>` : ''}
    ${payload.special_notes ? `<h2 style="font-size:1rem;color:#64748b;margin:24px 0 12px;text-transform:uppercase;letter-spacing:.05em">הערות מיוחדות</h2><p style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:16px;margin:0 0 28px;line-height:1.7">${payload.special_notes}</p>` : ''}

    <!-- CLAUDE PROMPT -->
    <div style="margin-top:36px;border-top:2px solid #e2e8f0;padding-top:32px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px">
        <span style="font-size:1.4rem">🤖</span>
        <h2 style="font-size:1.1rem;font-weight:800;color:#1e293b;margin:0">פרומפט מוכן ל-Claude</h2>
      </div>
      <p style="font-size:.85rem;color:#64748b;margin:0 0 12px">העתק את הפרומפט הזה ישירות ל-Claude Code כדי להתחיל לבנות:</p>
      <div style="background:#0f172a;border-radius:10px;padding:24px;direction:ltr;text-align:left">
        <pre style="margin:0;color:#e2e8f0;font-family:'Courier New',monospace;font-size:.78rem;line-height:1.8;white-space:pre-wrap;word-break:break-word">${buildClaudePrompt(payload, GOAL_MAP, STYLE_MAP, TIMELINE_MAP)}</pre>
      </div>
    </div>

  </div>
</div>`;

  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${resendKey}`,
      },
      body: JSON.stringify({
        from: 'Studio BB <onboarding@resend.dev>',
        to: ['yanayberdah@gmail.com'],
        subject: `📋 שאלון חדש — ${payload.business_name}`,
        html: emailHtml,
      }),
    });
    if(!r.ok){ const e = await r.json().catch(()=>{}); throw new Error(e?.message||'resend error'); }
    return res.status(200).json({ok:true});
  } catch(e) {
    console.error('Resend error:', e.message);
    return res.status(502).json({error:'שגיאת שרת. נסה שנית או פנה אלינו ב-WhatsApp.'});
  }
};
