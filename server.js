'use strict';

const express      = require('express');
const { DatabaseSync: Database } = require('node:sqlite');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const Stripe       = require('stripe');
const { OpenAI }   = require('openai');
const cookieParser = require('cookie-parser');
const path         = require('path');
require('dotenv').config();
const crypto     = require('crypto');
const nodemailer = require('nodemailer');

// ─── Init ─────────────────────────────────────────────────────────────────────
const app    = express();

function baseUrl() {
  let u = (process.env.BASE_URL || '').trim().replace(/\/$/, '');
  if (u && !u.startsWith('http://') && !u.startsWith('https://')) u = 'https://' + u;
  return u;
}
const db     = new Database(path.join(__dirname, 'flavory.db'));
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2023-10-16' });
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ─── Database ─────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT    NOT NULL,
    email               TEXT    UNIQUE NOT NULL,
    password            TEXT    NOT NULL,
    stripe_customer_id  TEXT,
    subscription_status TEXT    DEFAULT 'inactive',
    subscription_id     TEXT,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);
// Migration: add free_requests_used and subscription_plan columns for existing DBs
try { db.exec('ALTER TABLE users ADD COLUMN free_requests_used INTEGER DEFAULT 0'); } catch {}
try { db.exec('ALTER TABLE users ADD COLUMN subscription_plan TEXT'); } catch {}

db.exec(`
  CREATE TABLE IF NOT EXISTS password_resets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    token      TEXT    NOT NULL,
    expires_at DATETIME NOT NULL,
    used       INTEGER DEFAULT 0
  )
`);

// ─── Mail helper ──────────────────────────────────────────────────────────────
function sendMail({ to, subject, html }) {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER) {
    console.warn('SMTP not configured — skipping email');
    return Promise.resolve();
  }
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT) || 587,
    secure: false,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
  return transporter.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to, subject, html
  });
}

// ─── Stripe webhook (MUST be before express.json) ────────────────────────────
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), handleWebhook);

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cookieParser());
app.use(express.json({ limit: '20mb' }));

// Static files: frames and logo live at project root, pages in public/
app.use('/frames', express.static(path.join(__dirname, 'frames')));
app.get('/flavory-logo.png', (_, res) =>
  res.sendFile(path.join(__dirname, 'flavory-logo.png'))
);
app.use(express.static(path.join(__dirname, 'public')));

// ─── Auth helpers ─────────────────────────────────────────────────────────────
function cookieOpts() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
  };
}

function issueToken(res, payload) {
  const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.cookie('token', token, cookieOpts());
  return token;
}

// ─── Auth middleware ──────────────────────────────────────────────────────────
function authenticate(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Non autorizzato' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.clearCookie('token');
    res.status(401).json({ error: 'Sessione scaduta, effettua di nuovo il login' });
  }
}

const FREE_LIMIT = 3;

function checkAccess(req, res, next) {
  const user = db
    .prepare('SELECT subscription_status, free_requests_used FROM users WHERE id = ?')
    .get(req.user.id);
  if (!user) return res.status(403).json({ error: 'Utente non trovato' });
  if (user.subscription_status === 'active') return next();
  if ((user.free_requests_used ?? 0) < FREE_LIMIT) return next();
  return res.status(403).json({ error: 'Prova gratuita esaurita', needsSubscription: true });
}

// ─── Auth routes ──────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body ?? {};

  if (!name?.trim() || !email?.trim() || !password)
    return res.status(400).json({ error: 'Compila tutti i campi' });

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Email non valida' });

  if (password.length < 8)
    return res.status(400).json({ error: 'La password deve avere almeno 8 caratteri' });

  try {
    const hashed   = await bcrypt.hash(password, 12);
    const customer = await stripe.customers.create({ email: email.trim(), name: name.trim() });

    const result = db
      .prepare('INSERT INTO users (name, email, password, stripe_customer_id) VALUES (?, ?, ?, ?)')
      .run(name.trim(), email.trim().toLowerCase(), hashed, customer.id);

    issueToken(res, { id: result.lastInsertRowid, email: email.trim().toLowerCase() });
    res.json({ success: true, name: name.trim(), subscription_status: 'inactive' });

  } catch (err) {
    if (err.code === 'ERR_SQLITE_ERROR' && err.message.includes('UNIQUE constraint failed'))
      return res.status(409).json({ error: 'Email già registrata — prova ad accedere' });
    console.error('Register error:', err);
    res.status(500).json({ error: 'Errore del server, riprova' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body ?? {};

  if (!email || !password)
    return res.status(400).json({ error: 'Compila tutti i campi' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.trim().toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'Email o password non corretti' });

  issueToken(res, { id: user.id, email: user.email });
  res.json({ success: true, name: user.name, subscription_status: user.subscription_status });
});

app.post('/api/auth/logout', (_, res) => {
  res.clearCookie('token', cookieOpts());
  res.json({ success: true });
});

app.get('/api/auth/me', authenticate, (req, res) => {
  const user = db
    .prepare('SELECT id, name, email, subscription_status, subscription_plan, free_requests_used FROM users WHERE id = ?')
    .get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Utente non trovato' });
  res.json(user);
});

// ─── Stripe: checkout ─────────────────────────────────────────────────────────
app.post('/api/stripe/create-checkout', authenticate, async (req, res) => {
  const { plan } = req.body ?? {};
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);

  const priceId = plan === 'yearly'
    ? process.env.STRIPE_PRICE_ID_YEARLY
    : process.env.STRIPE_PRICE_ID_MONTHLY;

  if (!priceId)
    return res.status(500).json({ error: 'Prezzo non configurato — controlla il file .env' });

  try {
    const session = await stripe.checkout.sessions.create({
      customer:             user.stripe_customer_id,
      mode:                 'subscription',
      payment_method_types: ['card'],
      line_items:           [{ price: priceId, quantity: 1 }],
      success_url:          `${baseUrl()}/app.html?success=1&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:           `${baseUrl()}/app.html?cancelled=1`,
      metadata:             { user_id: String(user.id), plan },
      allow_promotion_codes: true
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe checkout error:', err);
    res.status(500).json({ error: 'Errore nella creazione del pagamento' });
  }
});

// ─── Stripe: verify checkout session (called on success redirect) ─────────────
app.post('/api/stripe/verify-session', authenticate, async (req, res) => {
  const { sessionId } = req.body ?? {};
  if (!sessionId) return res.status(400).json({ error: 'Session ID mancante' });

  try {
    const session = await stripe.checkout.sessions.retrieve(sessionId);

    // Security: ensure this session belongs to the logged-in user
    if (String(session.metadata?.user_id) !== String(req.user.id))
      return res.status(403).json({ error: 'Non autorizzato' });

    if (session.payment_status !== 'paid')
      return res.json({ verified: false });

    // Activate subscription directly (webhook may not have fired yet)
    db.prepare('UPDATE users SET subscription_status = ?, subscription_id = ?, subscription_plan = ?, free_requests_used = 0 WHERE id = ?')
      .run('active', session.subscription, session.metadata?.plan || 'monthly', req.user.id);

    res.json({ verified: true });
  } catch (err) {
    console.error('Verify session error:', err);
    res.status(500).json({ error: 'Errore verifica pagamento' });
  }
});

// ─── Stripe: customer portal ──────────────────────────────────────────────────
app.get('/api/stripe/portal', authenticate, async (req, res) => {
  const user = db
    .prepare('SELECT stripe_customer_id FROM users WHERE id = ?')
    .get(req.user.id);
  try {
    const session = await stripe.billingPortal.sessions.create({
      customer:   user.stripe_customer_id,
      return_url: `${baseUrl()}/app.html`
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Portal error:', err);
    res.status(500).json({ error: 'Errore nel portale abbonamenti' });
  }
});

// ─── Stripe: upgrade to yearly ────────────────────────────────────────────────
app.post('/api/stripe/upgrade-to-yearly', authenticate, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);

  if (user.subscription_status !== 'active')
    return res.status(400).json({ error: 'Nessun abbonamento attivo' });

  if (user.subscription_plan === 'yearly')
    return res.status(400).json({ error: 'Sei già sul piano annuale' });

  const yearlyPriceId = process.env.STRIPE_PRICE_ID_YEARLY;
  if (!yearlyPriceId)
    return res.status(500).json({ error: 'Prezzo annuale non configurato nel .env' });

  try {
    const subscription = await stripe.subscriptions.retrieve(user.subscription_id);
    const itemId = subscription.items.data[0].id;

    await stripe.subscriptions.update(user.subscription_id, {
      items: [{ id: itemId, price: yearlyPriceId }],
      proration_behavior: 'none',
    });

    db.prepare('UPDATE users SET subscription_plan = ? WHERE id = ?')
      .run('yearly', req.user.id);

    res.json({ success: true });
  } catch (err) {
    console.error('Upgrade error:', err);
    res.status(500).json({ error: "Errore durante l'aggiornamento del piano" });
  }
});

// ─── Stripe: webhook ──────────────────────────────────────────────────────────
async function handleWebhook(req, res) {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const userId  = session.metadata?.user_id;
      if (userId) {
        db.prepare('UPDATE users SET subscription_status = ?, subscription_id = ?, subscription_plan = ?, free_requests_used = 0 WHERE id = ?')
          .run('active', session.subscription, session.metadata?.plan || 'monthly', userId);
      }
      break;
    }
    case 'customer.subscription.updated': {
      const sub    = event.data.object;
      const status = sub.status === 'active' ? 'active' : 'inactive';
      db.prepare('UPDATE users SET subscription_status = ? WHERE subscription_id = ?')
        .run(status, sub.id);
      break;
    }
    case 'customer.subscription.deleted':
    case 'customer.subscription.paused': {
      const sub = event.data.object;
      db.prepare('UPDATE users SET subscription_status = ? WHERE subscription_id = ?')
        .run('inactive', sub.id);
      break;
    }
    case 'invoice.payment_failed': {
      const invoice = event.data.object;
      db.prepare('UPDATE users SET subscription_status = ? WHERE stripe_customer_id = ?')
        .run('past_due', invoice.customer);
      break;
    }
  }

  res.json({ received: true });
}

// ─── Password reset ───────────────────────────────────────────────────────────
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body ?? {};
  if (!email) return res.status(400).json({ error: 'Email richiesta' });

  const user = db.prepare('SELECT id, name FROM users WHERE email = ?').get(email.trim().toLowerCase());
  if (!user) return res.json({ success: true }); // no enumeration

  db.prepare('DELETE FROM password_resets WHERE user_id = ?').run(user.id);

  const token     = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)')
    .run(user.id, token, expiresAt);

  const resetUrl = `${baseUrl()}/reset-password.html?token=${token}`;
  try {
    await sendMail({
      to:      email,
      subject: 'Recupero password — FLAVORY.',
      html:    `<p>Ciao ${user.name},</p>
                <p>Clicca il link per reimpostare la tua password (valido 1 ora):</p>
                <p><a href="${resetUrl}">${resetUrl}</a></p>
                <p>Se non hai richiesto il reset, ignora questa email.</p>`
    });
  } catch (err) { console.error('Email error:', err); }

  res.json({ success: true });
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body ?? {};
  if (!token || !password) return res.status(400).json({ error: 'Dati mancanti' });
  if (password.length < 8) return res.status(400).json({ error: 'La password deve avere almeno 8 caratteri' });

  const record = db.prepare('SELECT * FROM password_resets WHERE token = ? AND used = 0').get(token);
  if (!record || new Date(record.expires_at) < new Date())
    return res.status(400).json({ error: 'Link non valido o scaduto — richiedine uno nuovo' });

  const hashed = await bcrypt.hash(password, 12);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashed, record.user_id);
  db.prepare('UPDATE password_resets SET used = 1 WHERE id = ?').run(record.id);
  res.json({ success: true });
});

// ─── Wine recommendation ──────────────────────────────────────────────────────
app.post('/api/recommend', authenticate, checkAccess, async (req, res) => {
  const { menu, location, budget, menuPhotos, mode } = req.body ?? {};
  // Support both array and legacy single-photo
  const photos = Array.isArray(menuPhotos) ? menuPhotos : (menuPhotos ? [menuPhotos] : []);

  if (!menu || menu.trim().length < 5)
    return res.status(400).json({ error: 'Descrivi il tuo pasto o vino (almeno 5 caratteri)' });

  if (photos.some(p => p.length > 5_000_000))
    return res.status(400).json({ error: 'Una delle immagini è troppo grande. Usa foto più piccole.' });

  const locationNote = location?.trim()
    ? (mode === 'wine-to-food'
        ? `Occasione o tipo di pasto: ${location.trim()}`
        : `Zona del cliente: ${location.trim()}`)
    : (mode === 'wine-to-food'
        ? 'Occasione non specificata'
        : 'Zona non specificata — consiglia vini reperibili a livello nazionale italiano');

  const budgetNote = `Budget massimo per bottiglia: €${budget ?? 30}. Scegli vini in questa fascia di prezzo, che siano reperibili sia in supermercato che in enoteca.`;

  const photoInstruction = photos.length > 0
    ? `\n\nL'utente ha fornito ${photos.length === 1 ? 'una foto' : `${photos.length} foto`} della carta dei vini del ristorante. Consiglia SOLO vini visibili nelle foto.`
    : '';

  const systemPrompt = `Sei un sommelier professionista con specializzazione in vini italiani e internazionali. Hai una conoscenza enciclopedica delle DOC, DOCG, IGT italiane e dei vini disponibili nei supermercati della grande distribuzione italiana. Rispondi sempre in italiano con tono autorevole ma accessibile, come un amico esperto. Usa queste emoji specifiche nei titoli delle sezioni: 🍷 per il nome vino, 🤝 per il perché dell'abbinamento, 📝 per le caratteristiche, 📍 per dove trovarlo, 💰 per il prezzo.${photoInstruction}

REGOLE FONDAMENTALI PER L'ACCURATEZZA:
- Cita solo vini e produttori che esistono realmente e di cui sei certo. Non inventare mai nomi di etichette, cantine o produttori.
- Se non sei sicuro dell'esistenza di un produttore specifico, descrivi il vino in termini generici (es. "un Barolo DOCG di un produttore delle Langhe") senza inventare nomi propri.
- Le denominazioni (DOC, DOCG, IGT) devono essere reali e corrette.
- Le annate consigliate devono essere plausibili per il vino citato; se non sei certo, indica solo il range (es. "annata recente, 2019-2022").
- I prezzi devono essere orientativi e realistici per il mercato italiano attuale.
- Per "Dove trovarlo" cita solo catene della GDO o enoteche effettivamente presenti in Italia; non inventare punti vendita.`;

  let userPrompt;
  if (mode === 'wine-to-food') {
    userPrompt = `Il cliente ha questo vino: ${menu.trim()}\n${locationNote}\n\nSuggerisci 3 abbinamenti gastronomici ideali con questa struttura:\n\n## 🍽️ Abbinamento 1 — [Nome piatto o tipo di cucina]\n\n### 🤝 Perché funziona\nSpiega in 2 frasi il perché del connubio.\n\n### 📝 Come servirlo\nTemperatura del vino, presentazione, consigli pratici.\n\n### 💡 Suggerimento\nUn consiglio in più per valorizzare l'abbinamento.\n\n## 🍽️ Abbinamento 2 — [Nome piatto o tipo di cucina]\n\n### 🤝 Perché funziona\n\n### 📝 Come servirlo\n\n### 💡 Suggerimento\n\n## 🍽️ Abbinamento 3 — [Nome piatto o tipo di cucina]\n\n### 🤝 Perché funziona\n\n### 📝 Come servirlo\n\n### 💡 Suggerimento`;
  } else {
    userPrompt = `Il cliente ha il seguente menu/pasto:\n${menu.trim()}\n\n${locationNote}\n${budgetNote}\n\nFornisci 3 consigli da sommelier con questa struttura per ciascuno:\n\n## 🍷 Vino 1 — [Nome Vino]\nNome specifico, denominazione (DOC/DOCG/IGT), produttore se possibile, annata indicativa.\n\n### 🤝 Perché questo abbinamento\nSpiega in 2 frasi il perché del connubio gusto-vino.\n\n### 📝 Caratteristiche\nGusto, aroma, corpo, temperatura di servizio consigliata.\n\n### 📍 Dove trovarlo\nPunti vendita specifici in base alla zona (nomi di catene GDO, enoteche note).\n\n### 💰 Prezzo\nPrezzo indicativo a bottiglia in base al budget indicato.\n\n## 🍷 Vino 2 — [Nome Vino]\n[stessa struttura]\n\n## 🍷 Vino 3 — [Nome Vino]\n[stessa struttura]`;
  }

  // Check if this is a free-tier request (before OpenAI call)
  const userRow = db
    .prepare('SELECT subscription_status, free_requests_used FROM users WHERE id = ?')
    .get(req.user.id);
  const isFreeRequest = userRow.subscription_status !== 'active';

  try {
    const userMessage = photos.length > 0
      ? { role: 'user', content: [
          { type: 'text', text: userPrompt },
          ...photos.map(p => ({ type: 'image_url', image_url: { url: p, detail: 'high' } }))
        ]}
      : { role: 'user', content: userPrompt };

    const completion = await openai.chat.completions.create({
      model:      'gpt-4o',
      messages:   [
        { role: 'system', content: systemPrompt },
        userMessage
      ],
      max_tokens:  photos.length > 0 ? 1500 : 1200,
      temperature: 0.7
    });

    // Increment counter only on success and only for free-tier users
    let freeRequestsUsed = userRow.free_requests_used ?? 0;
    if (isFreeRequest) {
      freeRequestsUsed++;
      db.prepare('UPDATE users SET free_requests_used = ? WHERE id = ?')
        .run(freeRequestsUsed, req.user.id);
    }

    res.json({
      recommendation:   completion.choices[0].message.content,
      freeRequestsUsed: isFreeRequest ? freeRequestsUsed : null
    });

  } catch (err) {
    console.error('OpenAI error:', err);
    if (err.status === 429)
      return res.status(429).json({ error: 'Troppe richieste simultanee. Riprova tra un momento.' });
    if (err.message?.includes('did not match the expected pattern') || err.message?.includes('invalid_image_url'))
      return res.status(400).json({ error: 'Foto non leggibile da GPT-4o. Riprova con una foto JPEG o PNG.' });
    res.status(500).json({ error: 'Errore nel generare il consiglio. Riprova.' });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🍷  Flavory in esecuzione su http://localhost:${PORT}`);
});
