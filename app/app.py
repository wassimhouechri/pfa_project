"""
DevSecOps Demo App — Flask
Compatible avec le pipeline CI/CD (Bandit, Trivy, ZAP, Safety)
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-in-prod")

# ── Utilisateurs en mémoire (demo) ──────────────────
USERS = {
    "admin": generate_password_hash("Admin1234!"),
    "user":  generate_password_hash("User1234!"),
}

# ── Décorateur login requis ──────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ── Routes publiques ─────────────────────────────────

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/health")
def health():
    """
    Health check — utilisé par le pipeline DAST (ZAP attend cette route).
    Retourne 200 JSON quand l'app est prête.
    """
    return jsonify({"status": "healthy", "version": "1.0.0"}), 200


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username in USERS and check_password_hash(USERS[username], password):
            session["username"] = username
            return redirect(url_for("dashboard"))
        error = "Nom d'utilisateur ou mot de passe incorrect."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ── Routes protégées ─────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session["username"])


# ── API REST ─────────────────────────────────────────

@app.route("/api/status")
def api_status():
    return jsonify({"status": "ok", "message": "DevSecOps App running", "version": "1.0.0"})


@app.route("/api/whoami")
@login_required
def api_whoami():
    return jsonify({"username": session["username"], "logged_in": True})


# ── Lancement ────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False) # nosec
