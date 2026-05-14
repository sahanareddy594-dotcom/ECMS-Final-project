"""
AXILEX — ECMS (Electrician Contractor Management System)
Final version with Razorpay payment gateway, security hardening,
input validation, and deployment-ready configuration.
"""
import os, re, sqlite3, uuid, random, hmac, hashlib, time
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, render_template, request, redirect, session,
                   jsonify, flash, url_for, abort)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Optional .env loading for local dev
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# Optional Razorpay
try:
    import razorpay
    _RZP_AVAILABLE = True
except Exception:
    _RZP_AVAILABLE = False

# ---------------- APP ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-secret-change-me")
app.permanent_session_lifetime = timedelta(hours=4)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    MAX_CONTENT_LENGTH=8 * 1024 * 1024,  # 8 MB upload cap
)

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf"}

# Razorpay (test mode if keys provided, otherwise mock)
RZP_KEY_ID = os.environ.get("RAZORPAY_KEY_ID", "").strip()
RZP_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "").strip()
RZP_ENABLED = bool(RZP_KEY_ID and RZP_KEY_SECRET and _RZP_AVAILABLE)
rzp_client = razorpay.Client(auth=(RZP_KEY_ID, RZP_KEY_SECRET)) if RZP_ENABLED else None

# ---------------- DATABASE ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------------- VALIDATION ----------------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
PHONE_RE    = re.compile(r"^[0-9+\-\s]{7,20}$")
EMAIL_RE    = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
UPI_RE      = re.compile(r"^[A-Za-z0-9._-]{2,}@[A-Za-z]{2,}$")
ROLES       = {"admin", "electrician", "client"}

def v_username(s):  return bool(s and USERNAME_RE.match(s))
def v_phone(s):     return not s or bool(PHONE_RE.match(s))
def v_email(s):     return not s or bool(EMAIL_RE.match(s))
def v_upi(s):       return bool(s and UPI_RE.match(s))
def v_amount(x):
    try:
        v = float(x); return v > 0 and v <= 10_00_000
    except Exception:
        return False

# ---------------- SECURITY HEADERS ----------------
@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; "
        "script-src 'self' https://cdn.jsdelivr.net https://checkout.razorpay.com 'unsafe-inline'; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "font-src 'self' data: https://cdn.jsdelivr.net; "
        "frame-src https://api.razorpay.com https://checkout.razorpay.com;"
    )
    return resp

# ---------------- AUTH HELPERS ----------------
def login_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrap(*a, **kw):
            if "user" not in session:
                return redirect("/login")
            if roles and session.get("role") not in roles:
                return abort(403)
            return fn(*a, **kw)
        return wrap
    return deco

# Simple in-memory login throttle
_LOGIN_FAILS = {}
def _throttle_check(key):
    now = time.time()
    fails = [t for t in _LOGIN_FAILS.get(key, []) if now - t < 300]
    _LOGIN_FAILS[key] = fails
    return len(fails) < 5
def _throttle_record(key):
    _LOGIN_FAILS.setdefault(key, []).append(time.time())

# ---------------- TABLES ----------------
def create_tables():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        name TEXT, phone TEXT, email TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS electricians(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, phone TEXT, experience TEXT,
        upi_id TEXT, image TEXT
    );
    CREATE TABLE IF NOT EXISTS jobs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL, location TEXT, deadline TEXT,
        electrician_id INTEGER, image TEXT,
        client_id INTEGER, amount REAL DEFAULT 0,
        payment_status TEXT DEFAULT 'Unpaid'
    );
    CREATE TABLE IF NOT EXISTS tasks(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, job_id INTEGER, electrician_id INTEGER,
        status TEXT, report TEXT
    );
    CREATE TABLE IF NOT EXISTS comments(
        id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER, comment TEXT
    );
    CREATE TABLE IF NOT EXISTS materials(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, quantity INTEGER, cost REAL
    );
    CREATE TABLE IF NOT EXISTS reports(
        id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT
    );
    CREATE TABLE IF NOT EXISTS payments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        txn_id TEXT UNIQUE,
        rzp_order_id TEXT, rzp_payment_id TEXT, rzp_signature TEXT,
        gateway TEXT DEFAULT 'mock',
        job_id INTEGER,
        from_user_id INTEGER, to_user_id INTEGER,
        from_role TEXT, to_role TEXT,
        amount REAL, method TEXT, status TEXT,
        upi_id TEXT, note TEXT, created_at TEXT
    );
    """)
    conn.commit(); conn.close()

def insert_sample():
    """Seed demo data so payment mode works out-of-the-box on first run."""
    conn = get_db()
    if not conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        conn.execute("INSERT INTO users(username,password,role,name,email) VALUES(?,?,?,?,?)",
                     ("admin", generate_password_hash("admin123"), "admin", "Administrator", "admin@axilex.local"))
        conn.execute("INSERT INTO users(username,password,role,name,email) VALUES(?,?,?,?,?)",
                     ("elec", generate_password_hash("123"), "electrician", "Sample Electrician", "elec@axilex.local"))
        conn.execute("INSERT INTO users(username,password,role,name,email) VALUES(?,?,?,?,?)",
                     ("client", generate_password_hash("123"), "client", "Sample Client", "client@axilex.local"))
    # Sample electricians
    if not conn.execute("SELECT 1 FROM electricians LIMIT 1").fetchone():
        sample_electricians = [
            ("Ramesh Kumar", "9876543210", "5 years", "ramesh@okicici"),
            ("Suresh Patil", "9123456780", "3 years", "suresh@okhdfcbank"),
            ("Mahesh Gowda", "7975879257", "6 years", "mahesh@okaxis"),
            ("Prajwal",      "7975879230", "4 years", "prajwal@oksbi"),
        ]
        for n, p, x, u in sample_electricians:
            conn.execute("INSERT INTO electricians(name,phone,experience,upi_id) VALUES(?,?,?,?)",
                         (n, p, x, u))
    # Sample jobs assigned to the demo client so /pay works immediately
    if not conn.execute("SELECT 1 FROM jobs LIMIT 1").fetchone():
        client = conn.execute("SELECT id FROM users WHERE role='client' LIMIT 1").fetchone()
        cid = client["id"] if client else None
        conn.execute("""INSERT INTO jobs(title,location,deadline,electrician_id,
                        client_id,amount,payment_status)
                        VALUES(?,?,?,?,?,?,?)""",
                     ("Office Wiring Setup", "Chennai", "2026-06-01", 1, cid, 4500.0, "Unpaid"))
        conn.execute("""INSERT INTO jobs(title,location,deadline,electrician_id,
                        client_id,amount,payment_status)
                        VALUES(?,?,?,?,?,?,?)""",
                     ("Panel Maintenance", "Bangalore", "2026-06-10", 2, cid, 2750.0, "Unpaid"))
    # Sample materials
    if not conn.execute("SELECT 1 FROM materials LIMIT 1").fetchone():
        conn.execute("INSERT INTO materials(name,quantity,cost) VALUES(?,?,?)",
                     ("Copper Wire (1m)", 200, 25.0))
        conn.execute("INSERT INTO materials(name,quantity,cost) VALUES(?,?,?)",
                     ("MCB Switch", 50, 180.0))
    conn.commit(); conn.close()

# ---------------- AUTH ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        p = request.form.get("password") or ""
        key = (request.remote_addr or "?") + "|" + u.lower()
        if not _throttle_check(key):
            flash("Too many attempts. Try again in 5 minutes.")
            return render_template("login.html"), 429
        if not v_username(u) or not p:
            flash("Invalid username or password.")
            _throttle_record(key)
            return render_template("login.html")
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        conn.close()
        if user and check_password_hash(user["password"], p):
            session.permanent = True
            session["user"] = user["username"]
            session["role"] = user["role"]
            session["uid"]  = user["id"]
            if user["role"] == "admin":  return redirect("/")
            if user["role"] == "client": return redirect("/client")
            return redirect("/tasks")
        _throttle_record(key)
        flash("Invalid username or password.")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        p = request.form.get("password") or ""
        role = request.form.get("role") or ""
        name = (request.form.get("name") or "").strip()[:80]
        phone = (request.form.get("phone") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        if not v_username(u): flash("Username must be 3-32 chars (letters, digits, . _ -)."); return render_template("register.html")
        if len(p) < 6:        flash("Password must be at least 6 characters."); return render_template("register.html")
        if role not in ROLES: flash("Invalid role."); return render_template("register.html")
        if not v_phone(phone):flash("Invalid phone."); return render_template("register.html")
        if not v_email(email):flash("Invalid email."); return render_template("register.html")
        try:
            conn = get_db()
            conn.execute("""INSERT INTO users(username,password,role,name,phone,email)
                            VALUES(?,?,?,?,?,?)""",
                         (u, generate_password_hash(p), role, name, phone, email))
            conn.commit(); conn.close()
            flash("Registration successful. Please login.")
            return redirect("/login")
        except sqlite3.IntegrityError:
            flash("Username already taken.")
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ---------------- DASHBOARD ----------------
@app.route("/")
@login_required()
def dashboard():
    if session["role"] == "client":     return redirect("/client")
    if session["role"] != "admin":      return redirect("/tasks")
    conn = get_db()
    e = conn.execute("SELECT COUNT(*) FROM electricians").fetchone()[0]
    j = conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
    t = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
    completed = conn.execute("SELECT COUNT(*) FROM tasks WHERE status='Completed'").fetchone()[0]
    pending = t - completed
    revenue = conn.execute("SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='Success' AND to_role='admin'").fetchone()[0]
    payouts = conn.execute("SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='Success' AND to_role='electrician'").fetchone()[0]
    conn.close()
    return render_template("dashboard.html", e=e, j=j, t=t, completed=completed,
                           pending=pending, revenue=revenue, payouts=payouts)

@app.route("/api/stats")
@login_required()
def stats():
    conn = get_db()
    completed = conn.execute("SELECT COUNT(*) FROM tasks WHERE status='Completed'").fetchone()[0]
    pending = conn.execute("SELECT COUNT(*) FROM tasks WHERE status!='Completed'").fetchone()[0]
    conn.close()
    return jsonify({"completed": completed, "pending": pending})

# ---------------- ELECTRICIANS ----------------
@app.route("/electricians", methods=["GET", "POST"])
@login_required("admin")
def electricians():
    conn = get_db()
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        exp = (request.form.get("experience") or "").strip()
        upi  = (request.form.get("upi_id") or "").strip()
        file = request.files.get("image")
        filename = None
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(f"elec_{uuid.uuid4().hex[:8]}_{file.filename}")
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        if name and v_phone(phone) and (not upi or v_upi(upi)):
            conn.execute("INSERT INTO electricians(name,phone,experience,upi_id,image) VALUES(?,?,?,?,?)",
                         (name[:80], phone, exp[:80], upi[:80], filename))
            conn.commit()
            flash("Electrician added.")
        else:
            flash("Invalid electrician data (check phone/UPI format like name@bank).")
    data = conn.execute("SELECT * FROM electricians").fetchall()
    conn.close()
    return render_template("electricians.html", data=data)

# ---------------- JOBS ----------------
@app.route("/jobs", methods=["GET", "POST"])
@login_required()
def jobs():
    conn = get_db()
    if request.method == "POST" and session["role"] == "admin":
        file = request.files.get("image")
        filename = None
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        try:
            conn.execute("""INSERT INTO jobs(title,location,deadline,electrician_id,image,client_id,amount)
                            VALUES(?,?,?,?,?,?,?)""",
                         ((request.form.get("title") or "").strip()[:120],
                          (request.form.get("location") or "").strip()[:120],
                          (request.form.get("deadline") or "").strip()[:30],
                          int(request.form.get("electrician") or 0) or None,
                          filename,
                          int(request.form.get("client") or 0) or None,
                          float(request.form.get("amount") or 0)))
            conn.commit()
        except Exception as e:
            flash(f"Could not create job: {e}")
    data = conn.execute("""
        SELECT jobs.*, electricians.name as ename, users.name as cname
        FROM jobs
        LEFT JOIN electricians ON jobs.electrician_id = electricians.id
        LEFT JOIN users ON jobs.client_id = users.id
    """).fetchall()
    electricians = conn.execute("SELECT * FROM electricians").fetchall()
    clients = conn.execute("SELECT id,name,username FROM users WHERE role='client'").fetchall()
    conn.close()
    return render_template("jobs.html", data=data, electricians=electricians, clients=clients)

# ---------------- TASKS ----------------
@app.route("/tasks", methods=["GET", "POST"])
@login_required("admin", "electrician")
def tasks():
    conn = get_db()
    status = request.args.get("status")
    if request.method == "POST":
        if "name" in request.form:
            conn.execute("INSERT INTO tasks(name,job_id,electrician_id,status) VALUES(?,?,?,?)",
                         ((request.form.get("name") or "").strip()[:120],
                          int(request.form.get("job") or 0) or None,
                          int(request.form.get("electrician") or 0) or None,
                          (request.form.get("status") or "Pending")[:30]))
            conn.commit()
        if "report" in request.files:
            f = request.files["report"]
            if f and f.filename and allowed_file(f.filename):
                fname = secure_filename(f.filename)
                f.save(os.path.join(app.config["UPLOAD_FOLDER"], fname))
                conn.execute("UPDATE tasks SET report=? WHERE id=?", (fname, request.form["task_id"]))
                conn.commit()
        if "comment" in request.form and request.form.get("comment"):
            conn.execute("INSERT INTO comments(task_id, comment) VALUES(?,?)",
                         (int(request.form["task_id"]), request.form["comment"][:500]))
            conn.commit()

    if session["role"] == "electrician":
        q = """SELECT tasks.*, jobs.title as jobname FROM tasks
               LEFT JOIN jobs ON tasks.job_id = jobs.id
               WHERE tasks.electrician_id = ?"""
        params = [session["uid"]]
        if status: q += " AND tasks.status = ?"; params.append(status)
        data = conn.execute(q, params).fetchall()
    else:
        q = """SELECT tasks.*, jobs.title as jobname, electricians.name as ename FROM tasks
               LEFT JOIN jobs ON tasks.job_id = jobs.id
               LEFT JOIN electricians ON tasks.electrician_id = electricians.id"""
        params = []
        if status: q += " WHERE tasks.status = ?"; params.append(status)
        data = conn.execute(q, params).fetchall()

    jobs = conn.execute("SELECT * FROM jobs").fetchall()
    electricians = conn.execute("SELECT * FROM electricians").fetchall()
    comments = conn.execute("SELECT * FROM comments").fetchall()
    conn.close()
    return render_template("tasks.html", data=data, jobs=jobs,
                           electricians=electricians, comments=comments)

# ---------------- MATERIALS ----------------
@app.route("/materials", methods=["GET", "POST"])
@login_required("admin")
def materials():
    conn = get_db()
    if request.method == "POST":
        try:
            conn.execute("INSERT INTO materials(name,quantity,cost) VALUES(?,?,?)",
                         ((request.form.get("name") or "").strip()[:80],
                          int(request.form.get("quantity") or 0),
                          float(request.form.get("cost") or 0)))
            conn.commit()
        except Exception as e:
            flash(f"Invalid input: {e}")
    data = conn.execute("SELECT * FROM materials").fetchall()
    conn.close()
    return render_template("materials.html", data=data)

# ---------------- REPORTS ----------------
@app.route("/reports", methods=["GET", "POST"])
@login_required("admin")
def reports():
    conn = get_db()
    if request.method == "POST":
        file = request.files.get("file")
        if file and file.filename and allowed_file(file.filename):
            fname = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], fname))
            conn.execute("INSERT INTO reports(filename) VALUES(?)", (fname,))
            conn.commit()
    total_tasks = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
    completed = conn.execute("SELECT COUNT(*) FROM tasks WHERE status='Completed'").fetchone()[0]
    electricians = conn.execute("SELECT COUNT(*) FROM electricians").fetchone()[0]
    data = conn.execute("SELECT * FROM reports").fetchall()
    conn.close()
    return render_template("reports.html", reports=data, total_tasks=total_tasks,
                           completed=completed, electricians=electricians)

@app.route("/update_task", methods=["POST"])
@login_required()
def update_task():
    conn = get_db()
    conn.execute("UPDATE tasks SET status=? WHERE id=?",
                 ((request.form.get("status") or "Pending")[:30],
                  int(request.form["id"])))
    conn.commit(); conn.close()
    return redirect("/tasks")

# ---------------- CLIENT PORTAL ----------------
@app.route("/client")
@login_required("client")
def client_dashboard():
    conn = get_db()
    jobs = conn.execute("""SELECT jobs.*, electricians.name as ename
                           FROM jobs LEFT JOIN electricians ON jobs.electrician_id = electricians.id
                           WHERE jobs.client_id = ?""", (session["uid"],)).fetchall()
    payments = conn.execute("""SELECT * FROM payments WHERE from_user_id = ?
                               ORDER BY id DESC""", (session["uid"],)).fetchall()
    conn.close()
    return render_template("client.html", jobs=jobs, payments=payments)

# ---------------- PAYMENTS ----------------
def _record_payment(**kw):
    conn = get_db()
    conn.execute("""INSERT INTO payments(txn_id,rzp_order_id,rzp_payment_id,rzp_signature,
                    gateway,job_id,from_user_id,to_user_id,from_role,to_role,
                    amount,method,status,upi_id,note,created_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                 (kw["txn_id"], kw.get("rzp_order_id"), kw.get("rzp_payment_id"),
                  kw.get("rzp_signature"), kw.get("gateway", "mock"),
                  kw.get("job_id"), kw.get("from_user_id"), kw.get("to_user_id"),
                  kw["from_role"], kw["to_role"], kw["amount"], kw.get("method", "UPI"),
                  kw["status"], kw.get("upi_id"), kw.get("note"),
                  datetime.utcnow().isoformat(timespec="seconds")))
    if kw["status"] == "Success" and kw.get("job_id") and kw["to_role"] == "admin":
        conn.execute("UPDATE jobs SET payment_status='Paid' WHERE id=?", (kw["job_id"],))
    conn.commit(); conn.close()

@app.route("/pay/<int:job_id>", methods=["GET", "POST"])
@login_required("client")
def pay_job(job_id):
    conn = get_db()
    job = conn.execute("SELECT * FROM jobs WHERE id=? AND client_id=?",
                       (job_id, session["uid"])).fetchone()
    admin = conn.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()
    conn.close()
    if not job:
        flash("Job not found"); return redirect("/client")
    amount = float(job["amount"] or 0)

    rzp_order = None
    if RZP_ENABLED and amount > 0 and request.method == "GET":
        try:
            rzp_order = rzp_client.order.create(dict(
                amount=int(round(amount * 100)), currency="INR",
                receipt=f"job_{job_id}_{uuid.uuid4().hex[:6]}",
                notes={"job_id": str(job_id), "client_id": str(session["uid"])},
            ))
        except Exception as e:
            flash(f"Razorpay error, falling back to mock: {e}")

    if request.method == "POST":
        gateway = request.form.get("gateway", "mock")
        if gateway == "razorpay" and RZP_ENABLED:
            order_id = request.form.get("razorpay_order_id", "")
            payment_id = request.form.get("razorpay_payment_id", "")
            signature  = request.form.get("razorpay_signature", "")
            try:
                rzp_client.utility.verify_payment_signature({
                    "razorpay_order_id": order_id,
                    "razorpay_payment_id": payment_id,
                    "razorpay_signature": signature,
                })
                status = "Success"
            except Exception:
                status = "Failed"
            txn_id = "RZP" + uuid.uuid4().hex[:10].upper()
            _record_payment(txn_id=txn_id, rzp_order_id=order_id,
                            rzp_payment_id=payment_id, rzp_signature=signature,
                            gateway="razorpay", job_id=job_id,
                            from_user_id=session["uid"], to_user_id=admin["id"] if admin else None,
                            from_role="client", to_role="admin", amount=amount,
                            method="Razorpay", status=status,
                            note=f"Razorpay payment for job: {job['title']}")
            return redirect(url_for("payment_result", txn_id=txn_id))

        # Mock UPI fallback
        upi = (request.form.get("upi_id") or "").strip()
        amt = float(request.form.get("amount") or amount)
        if not v_upi(upi) or not v_amount(amt):
            flash("Please enter a valid UPI ID and amount.")
            return redirect(url_for("pay_job", job_id=job_id))
        ok = not upi.lower().startswith("fail")
        status = "Success" if (ok and random.random() < 0.95) else "Failed"
        txn_id = "TXN" + uuid.uuid4().hex[:12].upper()
        _record_payment(txn_id=txn_id, gateway="mock", job_id=job_id,
                        from_user_id=session["uid"], to_user_id=admin["id"] if admin else None,
                        from_role="client", to_role="admin", amount=amt,
                        method="UPI", status=status, upi_id=upi,
                        note=f"Mock UPI payment for job: {job['title']}")
        return redirect(url_for("payment_result", txn_id=txn_id))

    return render_template("payment.html", job=job, amount=amount,
                           rzp_enabled=RZP_ENABLED, rzp_key=RZP_KEY_ID,
                           rzp_order=rzp_order)

@app.route("/payment/result/<txn_id>")
@login_required()
def payment_result(txn_id):
    conn = get_db()
    p = conn.execute("SELECT * FROM payments WHERE txn_id=?", (txn_id,)).fetchone()
    conn.close()
    if not p: return "Transaction not found", 404
    return render_template("payment_result.html", p=p)

@app.route("/payouts", methods=["GET", "POST"])
@login_required("admin")
def payouts():
    conn = get_db()
    if request.method == "POST":
        try:
            eid = int(request.form["electrician_id"])
            job_id = int(request.form.get("job_id") or 0) or None
            elec = conn.execute("SELECT * FROM electricians WHERE id=?", (eid,)).fetchone()
            # Fall back to electrician's saved UPI / job amount if blanks
            upi = (request.form.get("upi_id") or "").strip() or (elec["upi_id"] if elec else "")
            amt_raw = (request.form.get("amount") or "").strip()
            if not amt_raw and job_id:
                j = conn.execute("SELECT amount FROM jobs WHERE id=?", (job_id,)).fetchone()
                amt_raw = str(j["amount"]) if j else ""
            amount = float(amt_raw or 0)
            elec_user = conn.execute("SELECT id FROM users WHERE role='electrician' LIMIT 1").fetchone()
            if not v_amount(amount):
                flash(f"Invalid payout amount: '{amt_raw}'. Enter a value greater than 0.")
            elif not v_upi(upi):
                flash(f"Invalid UPI ID: '{upi}'. Use format like name@bank.")
            else:
                status = "Success" if random.random() < 0.97 else "Failed"
                txn_id = "PAY" + uuid.uuid4().hex[:12].upper()
                _record_payment(txn_id=txn_id, gateway="mock", job_id=job_id,
                                from_user_id=session["uid"],
                                to_user_id=elec_user["id"] if elec_user else None,
                                from_role="admin", to_role="electrician",
                                amount=amount, method="UPI", status=status, upi_id=upi,
                                note=f"Payout to {elec['name'] if elec else 'electrician'}")
                flash(f"Payout {status}: {txn_id}")
        except Exception as e:
            flash(f"Payout error: {e}")

    electricians = conn.execute("SELECT * FROM electricians").fetchall()
    jobs = conn.execute("SELECT * FROM jobs WHERE payment_status='Paid'").fetchall()
    payouts = conn.execute("""SELECT * FROM payments
                              WHERE from_role='admin' AND to_role='electrician'
                              ORDER BY id DESC""").fetchall()
    conn.close()
    return render_template("payouts.html", electricians=electricians,
                           jobs=jobs, payouts=payouts)

@app.route("/transactions")
@login_required()
def transactions():
    conn = get_db()
    if session["role"] == "admin":
        rows = conn.execute("SELECT * FROM payments ORDER BY id DESC").fetchall()
    else:
        rows = conn.execute("""SELECT * FROM payments
                              WHERE from_user_id=? OR to_user_id=?
                              ORDER BY id DESC""",
                            (session["uid"], session["uid"])).fetchall()
    conn.close()
    return render_template("transactions.html", rows=rows)

# ---------------- ERROR HANDLERS ----------------
@app.errorhandler(403)
def _403(e): return render_template("error.html", code=403, msg="Access denied"), 403
@app.errorhandler(404)
def _404(e): return render_template("error.html", code=404, msg="Page not found"), 404
@app.errorhandler(500)
def _500(e): return render_template("error.html", code=500, msg="Server error"), 500

# ---------------- HEALTH ----------------
@app.route("/healthz")
def healthz():
    return {"status": "ok", "razorpay": RZP_ENABLED}, 200

# ---------------- INIT ----------------
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
create_tables()
insert_sample()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    app.run(host="0.0.0.0", port=port, debug=debug)
