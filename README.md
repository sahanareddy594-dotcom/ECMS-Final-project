# AXILEX — Electrician Contractor Management System (ECMS)

A complete enterprise-style web application for managing electricians,
jobs, tasks, materials, payments and reports. Built with **Flask 3**,
**SQLite** (Postgres-ready), **Razorpay** test integration and a
modern responsive UI.

> Final-week deliverable for the AXILEX internship.

---

## ✨ Features

| Module           | Highlights                                                               |
|------------------|--------------------------------------------------------------------------|
| Authentication   | Hashed passwords, role-based access (admin/electrician/client), throttled login, secure session cookies |
| Admin dashboard  | Live stats, revenue & payout charts (Chart.js)                           |
| Electricians     | CRUD, assign to jobs                                                     |
| Jobs             | Image upload, client linking, payment status                             |
| Tasks            | Status flow, comments, PDF report uploads                                |
| Materials        | Inventory + cost tracking                                                |
| Reports          | File uploads + analytics                                                 |
| **Payments**     | **Razorpay test gateway** (real signature verification) + **mock UPI** fallback |
| Transactions     | Role-aware payment history (client / admin / electrician views)          |
| Payouts          | Admin → electrician transfers                                            |
| Security         | CSP / X-Frame / HTTPOnly cookies, file-type & size guards, input validation |
| Hosting          | Render Blueprint, Procfile, runtime.txt, gunicorn ready                  |
| Testing          | Pytest smoke suite (`pytest -q`)                                         |

---

## 🚀 Quick start (local)

```bash
cd week_5_task
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                  # then edit
python app.py
# open http://127.0.0.1:5000
```

### Default users
| Role        | Username | Password   |
|-------------|----------|------------|
| Admin       | `admin`  | `admin123` |
| Electrician | `elec`   | `123`      |
| Client      | `client` | `123`      |

---

## 💳 Payment gateway

The app supports **Razorpay** (test mode) out of the box.

1. Create test API keys at <https://dashboard.razorpay.com/app/keys>.
2. Add to `.env`:
   ```
   RAZORPAY_KEY_ID=rzp_test_xxx
   RAZORPAY_KEY_SECRET=xxxxxxxx
   ```
3. Restart the app. The client payment page now opens the real Razorpay
   checkout, and the server **verifies the HMAC signature** before
   marking the payment as Success.

If keys are not configured the app silently falls back to a **mock UPI
gateway** — perfect for grading without external accounts.

Test cards / UPI handles:
- Card: `4111 1111 1111 1111`, any CVV, any future expiry
- UPI success: `success@razorpay`
- UPI failure: `failure@razorpay`
- Mock failure: any UPI ID starting with `fail` (e.g. `fail@upi`)

---

## ☁️ Deploy online

See **[DEPLOYMENT.md](./DEPLOYMENT.md)** for one-click Render, Railway
and PythonAnywhere instructions. The included `render.yaml` deploys
the app as a Blueprint with auto-generated `SECRET_KEY`.

For a real cloud database (Supabase / Render Postgres / Railway), see
the *Cloud database* section of the deployment guide and the
`migrate_to_postgres.py` helper.

---

## 🧪 Testing

```bash
pip install pytest
pytest -q
```

Smoke tests cover health endpoint, auth gate, admin dashboard, client
portal, registration validation and login throttling.

---

## 🔐 Security checklist

- ✅ Passwords hashed with `werkzeug.security` (PBKDF2-SHA256)
- ✅ Session cookies: HttpOnly, SameSite=Lax, Secure in production
- ✅ Login rate-limit (5 attempts / 5 min / IP+user)
- ✅ All SQL queries use parameterised statements (no concatenation)
- ✅ Role-based access via `@login_required("admin"|"electrician"|"client")`
- ✅ Razorpay HMAC signature verification on every payment
- ✅ Strict file-type & 8 MB upload cap
- ✅ Security headers: CSP, X-Frame, X-Content-Type, Referrer-Policy
- ✅ Input validation (regex) for username / email / phone / UPI / amount

---

## 📁 Project structure

```
week_5_task/
├── app.py                  # Flask application
├── templates/              # Jinja templates (12 pages)
├── static/                 # CSS, JS, uploads
├── tests/test_smoke.py     # Pytest suite
├── migrate_to_postgres.py  # Optional Postgres migration
├── Procfile                # gunicorn entry
├── render.yaml             # Render Blueprint
├── runtime.txt             # Python version pin
├── requirements.txt
├── .env.example
├── README.md
└── DEPLOYMENT.md
```

---

## 📸 Screenshots

See the parent folder (`../*.png`) for dashboard, jobs, tasks,
electricians, materials, reports and login page screenshots.

---

## 📝 Submission checklist

- [x] Working payment gateway (Razorpay test + mock fallback)
- [x] Hosting config for Render / Railway / PythonAnywhere
- [x] Cloud DB migration script (Supabase / Postgres)
- [x] Enterprise UI (responsive, gradient cards, modern tables)
- [x] Full workflow integration (admin ↔ client ↔ electrician)
- [x] Automated tests + input validation
- [x] Security hardening (hashing, headers, rate-limit, CSRF-safe sessions)
- [x] README + DEPLOYMENT documentation

— *AXILEX Internship · Final Week Submission*
