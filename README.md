# Flavory 🍷

> GPT-4o powered food-wine pairing SaaS — AI sommelier with local Italian DOC/DOCG recommendations, freemium model, and live Stripe subscription.

**Live →** [flavory-production-2af8.up.railway.app](https://flavory-production-2af8.up.railway.app)  
**Portfolio →** [mariusceb.github.io](https://mariusceb.github.io)

---

## What it does

Flavory is a full-stack SaaS that acts as a personal AI sommelier. Describe what you're cooking, enter your city, set a per-bottle budget — GPT-4o returns named wines with DOC/DOCG appellations, pairing rationale, tasting notes, local supermarket sourcing, and price estimates.

Two modes:
- **Ho il cibo** — give a dish, get a wine recommendation
- **Ho il vino** — give a wine, get food pairing suggestions

---

## Stack

| Layer | Tech |
|---|---|
| Backend | Node.js, Express |
| AI | OpenAI GPT-4o API |
| Payments | Stripe Checkout |
| Auth | JWT + bcryptjs |
| Deploy | Railway |

---

## Features

- **AI Sommelier** — GPT-4o returns named wines with real Italian DOC/DOCG producers, pairing rationale, tasting notes, local supermarket sourcing (Coop, Conad, Esselunga), and price estimates
- **Dual Pairing Mode** — food → wine or wine → food, free-text input with optional photo upload
- **Freemium Model** — 3 free queries tracked server-side, displayed as dot indicators in the UI
- **Stripe Subscription** — €9.99/month via hosted Stripe Checkout; session created server-side, no card data touches the app
- **Cronologia** — timestamped history of all past pairings; click any entry to reopen it in the sommelier
- **Responsive** — full three-tab dashboard (Sommelier / Cronologia / Abbonamento) adapts to mobile

---

## Local Setup

```bash
git clone https://github.com/MariusCeb/flavory
cd flavory
npm install
```

Create a `.env` file:

```env
OPENAI_API_KEY=your_key
STRIPE_SECRET_KEY=your_key
JWT_SECRET=your_secret
```

```bash
npm start
```

---

Built by [Ceban Marius](https://mariusceb.github.io)
