"""
DevSecOps Demo App — Flask
Compatible avec le pipeline CI/CD (Bandit, Trivy, ZAP, Safety)
SOC Dashboard avec vrais appels AWS (boto3) via IAM Role ECS
+ Détection d'attaques en temps réel (before_request / after_request)
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response, stream_with_context
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import re
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import time
import threading
import queue
import json
import urllib.request
import io

# ── PDF (reportlab) — installé via requirements.txt ──
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.units import cm
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-in-prod")
app.config["PERMANENT_SESSION_LIFETIME"] = 86400   # 24h
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# ── Config AWS ───────────────────────────────────────
AWS_REGION    = os.environ.get("AWS_REGION", "us-east-1")
LOG_GROUP     = os.environ.get("CW_LOG_GROUP", "/ecs/devsecops")
ECS_CLUSTER   = os.environ.get("ECS_CLUSTER", "devsecops-cluster")
ECS_SERVICE   = os.environ.get("ECS_SERVICE", "devsecops-service")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN",
                  "arn:aws:sns:us-east-1:792782834628:soc-alerts")
ALARM_NAMES   = [
    "SOC-ECS-Errors",
    "SOC-Unauthorized-Access",
    "SOC-ECS-Task-Stopped",
]
WAF_IP_SET_ID        = os.environ.get("WAF_IP_SET_ID", "")
WAF_IP_SET_NAME      = os.environ.get("WAF_IP_SET_NAME", "SOC-Blocked-IPs")
WAF_SCOPE            = os.environ.get("WAF_SCOPE", "REGIONAL")
SES_FROM_EMAIL       = os.environ.get("SES_FROM_EMAIL", "")
SES_TO_EMAIL         = os.environ.get("SES_TO_EMAIL", "")
AUTO_BLOCK_THRESHOLD = int(os.environ.get("AUTO_BLOCK_THRESHOLD", "10"))

# ── Utilisateurs en mémoire (demo) ──────────────────
USERS = {
    "admin": generate_password_hash("Admin1234!"),
    "user":  generate_password_hash("User1234!"),
}

# ══════════════════════════════════════════════════════
#  MOTEUR DE DÉTECTION D'ATTAQUES
# ══════════════════════════════════════════════════════

# Patterns de détection par type d'attaque
ATTACK_PATTERNS = {
    "SQL Injection": [
        r"union[\s+]select",
        r"drop[\s+]table",
        r"1\s*=\s*1",
        r"or\s+'[^']*'\s*=\s*'[^']*'",
        r"'--",
        r";\s*(drop|delete|insert|update)",
        r"xp_\w+",
        r"exec\s*\(",
        r"sleep\s*\(\d+\)",
        r"benchmark\s*\(",
        r"information_schema",
        r"union\s+all\s+select",
    ],
    "XSS": [
        r"<script[\s>]",
        r"javascript\s*:",
        r"onerror\s*=",
        r"onload\s*=",
        r"onclick\s*=",
        r"alert\s*\(",
        r"document\.cookie",
        r"<iframe[\s>]",
        r"<img[^>]+src\s*=\s*['\"]?\s*x",
        r"expression\s*\(",
        r"vbscript\s*:",
    ],
    "Path Traversal / LFI": [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"/etc/passwd",
        r"/etc/shadow",
        r"/proc/self",
        r"c:\\windows",
        r"boot\.ini",
    ],
    "Command Injection / RCE": [
        r";\s*(ls|cat|id|whoami|uname|ping|curl|wget|nc|bash|sh)\b",
        r"`[^`]+`",
        r"\$\([^)]+\)",
        r"\|\s*(ls|cat|id|whoami|bash|sh)\b",
        r"&&\s*(ls|cat|id|whoami|bash|sh)\b",
        r"/bin/(bash|sh|nc)",
        r"cmd\.exe",
        r"powershell\s+-",
    ],
    "Scanner / Reconnaissance": [
        r"nikto",
        r"sqlmap",
        r"nmap\s+scripting",
        r"dirbuster",
        r"masscan",
        r"zgrab",
        r"gobuster",
        r"wfuzz",
        r"burpsuite",
        r"acunetix",
        r"nessus",
        r"openvas",
    ],
}

# Compteur de tentatives par IP (brute force)
# Structure: { ip: { "count": N, "first_seen": timestamp, "last_seen": timestamp } }
_brute_force_tracker = defaultdict(lambda: {"count": 0, "first_seen": 0, "last_seen": 0})
BRUTE_FORCE_THRESHOLD = 10   # nb de 401/403 en BRUTE_FORCE_WINDOW secondes
BRUTE_FORCE_WINDOW    = 300  # 5 minutes

# Tracker en mémoire de toutes les attaques détectées (tous types)
# Structure: liste de dicts { type, ip, time, detail, severity }
_attack_tracker = []
ATTACK_TRACKER_MAX = 100  # garder les 100 dernières attaques


def _detect_attack_in_request():
    """
    Analyse l'URL, les paramètres GET/POST et les headers
    pour détecter un type d'attaque. Retourne (nom, pattern) ou None.
    """
    # Assemblage de tout le contenu analysable
    parts = [
        request.url,
        str(request.args.to_dict()),
        str(request.form.to_dict()),
        request.headers.get("User-Agent", ""),
        request.headers.get("Referer", ""),
    ]
    # Body JSON si présent
    try:
        if request.is_json:
            parts.append(str(request.get_json(silent=True) or ""))
    except Exception:
        pass

    full_text = " ".join(parts)

    for attack_name, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, full_text, re.IGNORECASE):
                return attack_name, pattern

    return None


def _log_attack(attack_name, detail="", extra=""):
    """Écrit un log WARNING structuré — capté par CloudWatch.
    Stocke aussi l'attaque en mémoire pour l'API /api/soc/attack-stats."""
    global _attack_tracker
    app.logger.warning(
        f"[ATTACK DETECTED] type={attack_name} "
        f"ip={request.remote_addr} "
        f"method={request.method} "
        f"url={request.url[:300]} "
        f"detail={detail} "
        f"{extra}"
    )
    # Stocker en mémoire pour le dashboard
    _attack_tracker.append({
        "type":     attack_name,
        "ip":       request.remote_addr,
        "method":   request.method,
        "url":      request.url[:200],
        "time":     datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "detail":   detail[:100],
        "severity": ATTACK_META.get(attack_name, {}).get("severity", "MEDIUM"),
        "confidence": ATTACK_META.get(attack_name, {}).get("confidence", 75),
    })
    # Garder uniquement les N dernières
    if len(_attack_tracker) > ATTACK_TRACKER_MAX:
        _attack_tracker = _attack_tracker[-ATTACK_TRACKER_MAX:]


def _send_sns_alert(attack_name, severity, confidence, description, recommendation):
    """Publie une alerte SNS de façon non-bloquante (best-effort)."""
    try:
        sns = boto3.client("sns", region_name=AWS_REGION)
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        severity_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        icon = severity_icons.get(severity.upper(), "⚠️")

        message = (
            f"{'='*60}\n"
            f"🚨  ALERTE SOC — ATTAQUE DÉTECTÉE (AUTOMATIQUE)\n"
            f"{'='*60}\n\n"
            f"{icon}  Type d'attaque : {attack_name}\n"
            f"⚡  Sévérité      : {severity.upper()}\n"
            f"🎯  Confiance     : {confidence}%\n"
            f"🌐  IP Source     : {request.remote_addr}\n"
            f"📍  URL ciblée    : {request.url[:200]}\n"
            f"🕐  Horodatage    : {now_str}\n"
            f"🖥️  Cluster       : {ECS_CLUSTER}\n"
            f"⚙️  Service       : {ECS_SERVICE}\n\n"
            f"{'─'*60}\n"
            f"📋  DESCRIPTION\n"
            f"{'─'*60}\n"
            f"{description}\n\n"
            f"{'─'*60}\n"
            f"🛡️  RECOMMANDATION\n"
            f"{'─'*60}\n"
            f"{recommendation}\n\n"
            f"{'='*60}\n"
            f"DevSecOps SOC Dashboard — Action immédiate requise\n"
            f"{'='*60}\n"
        )
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"🚨 SOC ALERT [{severity.upper()}] — {attack_name}",
            Message=message,
        )
    except Exception as e:
        app.logger.error(f"[SOC] Echec envoi SNS: {e}")


# ── Cooldown pour éviter le spam d'alertes SNS ───────
_last_sns_sent = {}          # { attack_name: timestamp }
SNS_COOLDOWN   = 120         # 2 min entre deux alertes du même type


def _maybe_send_sns(attack_name, severity, confidence, description, recommendation):
    """Envoie SNS seulement si le cooldown est écoulé pour ce type."""
    now = time.time()
    last = _last_sns_sent.get(attack_name, 0)
    if now - last > SNS_COOLDOWN:
        _last_sns_sent[attack_name] = now
        _send_sns_alert(attack_name, severity, confidence, description, recommendation)


# Metadata des attaques (sévérité, confiance, textes)
ATTACK_META = {
    "SQL Injection": {
        "severity": "HIGH", "confidence": 88,
        "description": "Tentatives d'injection SQL détectées dans les paramètres de requête.",
        "recommendation": "Utiliser des requêtes paramétrées, activer WAF SQL rules, auditer les entrées."
    },
    "XSS": {
        "severity": "HIGH", "confidence": 85,
        "description": "Injection de scripts malveillants détectée. Risque de vol de session.",
        "recommendation": "Activer Content-Security-Policy, encoder toutes les sorties HTML."
    },
    "Path Traversal / LFI": {
        "severity": "HIGH", "confidence": 87,
        "description": "Tentatives d'accès à des fichiers système sensibles.",
        "recommendation": "Valider les chemins d'accès, restreindre les permissions fichiers."
    },
    "Command Injection / RCE": {
        "severity": "CRITICAL", "confidence": 92,
        "description": "Tentative d'exécution de commandes système à distance.",
        "recommendation": "Désactiver l'exécution de commandes, isoler le conteneur."
    },
    "Scanner / Reconnaissance": {
        "severity": "MEDIUM", "confidence": 75,
        "description": "User-agent de scanner malveillant détecté.",
        "recommendation": "Bloquer les user-agents suspects, activer l'IDS."
    },
    "Brute Force": {
        "severity": "CRITICAL", "confidence": 95,
        "description": "Tentatives répétées de connexion échouées depuis la même IP.",
        "recommendation": "Bloquer l'IP source, activer MFA, renforcer le rate limiting."
    },
}


# ── Middleware : analyse chaque requête ENTRANTE ──────
@app.before_request
def detect_attack_before():
    """Détecte les attaques dans les paramètres/headers de la requête."""
    result = _detect_attack_in_request()
    if result:
        attack_name, matched_pattern = result
        meta = ATTACK_META.get(attack_name, {})
        _log_attack(attack_name, detail=f"pattern={matched_pattern[:60]}")
        _maybe_send_sns(
            attack_name,
            meta.get("severity", "MEDIUM"),
            meta.get("confidence", 75),
            meta.get("description", ""),
            meta.get("recommendation", ""),
        )


# ── Middleware : analyse chaque réponse SORTANTE ──────
@app.after_request
def detect_brute_force(response):
    """Détecte le brute force via les codes 401/403 répétés par IP."""
    if response.status_code in (401, 403):
        ip  = request.remote_addr
        now = time.time()
        tracker = _brute_force_tracker[ip]

        # Réinitialiser si la fenêtre est dépassée
        if now - tracker["first_seen"] > BRUTE_FORCE_WINDOW:
            tracker["count"]      = 0
            tracker["first_seen"] = now

        tracker["count"]    += 1
        tracker["last_seen"] = now

        # Logger chaque accès refusé
        app.logger.warning(
            f"unauthorized ip={ip} "
            f"url={request.url[:200]} "
            f"status={response.status_code} "
            f"count={tracker['count']}"
        )

        # Déclencher l'alerte si seuil dépassé
        if tracker["count"] >= BRUTE_FORCE_THRESHOLD:
            meta = ATTACK_META["Brute Force"]
            _log_attack(
                "Brute Force",
                detail=f"count={tracker['count']} window={BRUTE_FORCE_WINDOW}s"
            )
            _maybe_send_sns(
                "Brute Force",
                meta["severity"],
                meta["confidence"],
                f"{tracker['count']} tentatives échouées depuis {ip} en {BRUTE_FORCE_WINDOW}s.",
                meta["recommendation"],
            )

    return response


# ── Décorateur login requis ──────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            if request.path.startswith("/api/soc/"):
                return jsonify({"ok": False, "error": "session_expired"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════════════
#  ROUTES PUBLIQUES
# ══════════════════════════════════════════════════════

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/health")
def health():
    return jsonify({"status": "healthy", "version": "1.0.0"}), 200


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username in USERS and check_password_hash(USERS[username], password):
            session.permanent = True
            session["username"] = username
            return redirect(url_for("dashboard"))
        error = "Nom d'utilisateur ou mot de passe incorrect."
        # Log tentative échouée (sera compté par after_request via 401 si applicable)
        app.logger.warning(
            f"[LOGIN FAILED] ip={request.remote_addr} username={username}"
        )
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ══════════════════════════════════════════════════════
#  ROUTES PROTÉGÉES
# ══════════════════════════════════════════════════════

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session["username"])


@app.route("/soc")
@login_required
def soc():
    """SOC Dashboard — Security Operations Center."""
    return render_template("soc.html", username=session["username"])


# ══════════════════════════════════════════════════════
#  API REST
# ══════════════════════════════════════════════════════

@app.route("/api/status")
def api_status():
    return jsonify({"status": "ok", "message": "DevSecOps App running", "version": "1.0.0"})


@app.route("/api/whoami")
@login_required
def api_whoami():
    return jsonify({"username": session["username"], "logged_in": True})


# ══════════════════════════════════════════════════════
#  SOC API — vrais appels AWS via IAM Role ECS
# ══════════════════════════════════════════════════════

def _aws(service):
    """Client boto3 — credentials récupérés automatiquement depuis l'IAM Role ECS."""
    return boto3.client(service, region_name=AWS_REGION)


# ── GET /api/soc/logs ─────────────────────────────────
@app.route("/api/soc/logs")
@login_required
def soc_logs():
    """Retourne les 50 derniers événements CloudWatch Logs (fenêtre 3h)."""
    try:
        logs     = _aws("logs")
        start_ms = int((datetime.now(timezone.utc) - timedelta(hours=3)).timestamp() * 1000)
        resp     = logs.filter_log_events(
            logGroupName=LOG_GROUP,
            startTime=start_ms,
            limit=50,
        )
        raw_events = sorted(resp.get("events", []), key=lambda e: e["timestamp"])
        events = []
        for e in raw_events:
            msg = e.get("message", "").strip()
            if "ERROR" in msg or "error" in msg or "Exception" in msg:
                level = "ERROR"
            elif "WARN" in msg or "warn" in msg or "WARNING" in msg or "[ATTACK" in msg:
                level = "WARN"
            else:
                level = "INFO"
            ts = datetime.fromtimestamp(
                e["timestamp"] / 1000, tz=timezone.utc
            ).strftime("%H:%M:%S")
            events.append({"time": ts, "level": level, "msg": msg[:300], "id": e["eventId"]})
        return jsonify({"ok": True, "events": events})
    except NoCredentialsError:
        return jsonify({"ok": False, "error": "Pas de credentials AWS (IAM Role manquant)"}), 403
    except ClientError as ex:
        return jsonify({"ok": False, "error": str(ex)}), 500
    except Exception as ex:
        return jsonify({"ok": False, "error": str(ex)}), 500


# ── GET /api/soc/metrics ──────────────────────────────
@app.route("/api/soc/metrics")
@login_required
def soc_metrics():
    """Retourne CPU%, Mémoire%, erreurs et accès refusés depuis CloudWatch Metrics."""
    try:
        cw      = _aws("cloudwatch")
        now_utc = datetime.now(timezone.utc)
        one_h   = now_utc - timedelta(hours=1)

        def _metric(namespace, metric_name, dimensions, stat="Average"):
            resp = cw.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=dimensions,
                StartTime=one_h,
                EndTime=now_utc,
                Period=300,
                Statistics=[stat],
            )
            pts = resp.get("Datapoints", [])
            if not pts:
                return 0.0
            return round(sorted(pts, key=lambda x: x["Timestamp"])[-1][stat], 1)

        cpu = _metric(
            "AWS/ECS", "CPUUtilization",
            [{"Name": "ClusterName", "Value": ECS_CLUSTER},
             {"Name": "ServiceName", "Value": ECS_SERVICE}],
        )
        mem = _metric(
            "AWS/ECS", "MemoryUtilization",
            [{"Name": "ClusterName", "Value": ECS_CLUSTER},
             {"Name": "ServiceName", "Value": ECS_SERVICE}],
        )
        errors = _metric(
            "SOC/Security", "ErrorCount",
            [{"Name": "LogGroup", "Value": LOG_GROUP}],
            stat="Sum",
        )
        unauth = _metric(
            "SOC/Security", "UnauthorizedAccessCount",
            [{"Name": "LogGroup", "Value": LOG_GROUP}],
            stat="Sum",
        )

        return jsonify({
            "ok": True,
            "cpu":    cpu,
            "mem":    mem,
            "errors": int(errors),
            "unauth": int(unauth),
        })
    except NoCredentialsError:
        return jsonify({"ok": False, "error": "Pas de credentials AWS"}), 403
    except Exception as ex:
        return jsonify({"ok": False, "error": str(ex)}), 500


# ── GET /api/soc/alarms ───────────────────────────────
@app.route("/api/soc/alarms")
@login_required
def soc_alarms():
    """Retourne l'état des alarmes CloudWatch SOC."""
    try:
        cw   = _aws("cloudwatch")
        resp = cw.describe_alarms(AlarmNames=ALARM_NAMES)
        alarms = []
        for a in resp.get("MetricAlarms", []):
            alarms.append({
                "name":   a["AlarmName"],
                "state":  a["StateValue"],
                "desc":   a.get("AlarmDescription", ""),
                "reason": a.get("StateReason", ""),
            })
        return jsonify({"ok": True, "alarms": alarms})
    except NoCredentialsError:
        return jsonify({"ok": False, "error": "Pas de credentials AWS"}), 403
    except Exception as ex:
        return jsonify({"ok": False, "error": str(ex)}), 500


# ── POST /api/soc/test-alert ──────────────────────────
@app.route("/api/soc/test-alert", methods=["POST"])
@login_required
def soc_test_alert():
    """Publie un message de test sur le topic SNS soc-alerts."""
    try:
        sns     = _aws("sns")
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="🚨 SOC ALERT TEST — DevSecOps Dashboard",
            Message=(
                f"Alerte de test envoyée depuis le SOC Dashboard\n"
                f"Cluster   : {ECS_CLUSTER}\n"
                f"Service   : {ECS_SERVICE}\n"
                f"Opérateur : {session.get('username', 'inconnu')}\n"
                f"Horodatage: {now_str}\n\n"
                f"Ceci est un test. Aucune action requise."
            ),
        )
        return jsonify({"ok": True, "message": "Alerte SNS envoyée"})
    except NoCredentialsError:
        return jsonify({"ok": False, "error": "Pas de credentials AWS (IAM Role manquant)"}), 403
    except ClientError as ex:
        code = ex.response["Error"]["Code"]
        return jsonify({"ok": False, "error": f"AWS ClientError: {code}"}), 500
    except Exception as ex:
        return jsonify({"ok": False, "error": str(ex)}), 500


# ── POST /api/soc/attack-alert ────────────────────────
@app.route("/api/soc/attack-alert", methods=["POST"])
@login_required
def soc_attack_alert():
    """
    Envoie une alerte email via SNS lorsqu'une attaque est détectée.
    Appelé par le moteur d'intelligence du SOC Dashboard (JS) ou manuellement.
    """
    try:
        body           = request.get_json(force=True) or {}
        attack_name    = body.get("attack_name", "Attaque Inconnue")
        severity       = body.get("severity", "unknown").upper()
        confidence     = body.get("confidence", 0)
        description    = body.get("description", "Aucune description disponible.")
        recommendation = body.get("recommendation", "Analyser les logs manuellement.")
        operator       = session.get("username", "inconnu")
        now_str        = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        severity_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        icon = severity_icons.get(severity, "⚠️")

        message = (
            f"{'='*60}\n"
            f"🚨  ALERTE SOC — ATTAQUE DÉTECTÉE\n"
            f"{'='*60}\n\n"
            f"{icon}  Type d'attaque : {attack_name}\n"
            f"⚡  Sévérité      : {severity}\n"
            f"🎯  Confiance     : {confidence}%\n"
            f"🕐  Horodatage    : {now_str}\n"
            f"👤  Opérateur     : {operator}\n"
            f"🖥️  Cluster       : {ECS_CLUSTER}\n"
            f"⚙️  Service       : {ECS_SERVICE}\n\n"
            f"{'─'*60}\n"
            f"📋  DESCRIPTION\n"
            f"{'─'*60}\n"
            f"{description}\n\n"
            f"{'─'*60}\n"
            f"🛡️  RECOMMANDATION\n"
            f"{'─'*60}\n"
            f"{recommendation}\n\n"
            f"{'='*60}\n"
            f"DevSecOps SOC Dashboard — Action immédiate requise\n"
            f"{'='*60}\n"
        )

        sns = _aws("sns")
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"🚨 SOC ALERT [{severity}] — {attack_name}",
            Message=message,
        )

        app.logger.warning(
            f"[SOC ATTACK ALERT] type={attack_name} severity={severity} "
            f"confidence={confidence}% operator={operator}"
        )

        return jsonify({
            "ok": True,
            "message": f"Alerte SNS envoyée pour: {attack_name}",
            "severity": severity,
            "attack_name": attack_name,
        })

    except NoCredentialsError:
        return jsonify({"ok": False, "error": "Pas de credentials AWS (IAM Role manquant)"}), 403
    except ClientError as ex:
        code = ex.response["Error"]["Code"]
        return jsonify({"ok": False, "error": f"AWS ClientError: {code}"}), 500
    except Exception as ex:
        return jsonify({"ok": False, "error": str(ex)}), 500


# ── GET /api/soc/attack-stats ─────────────────────────
@app.route("/api/soc/attack-stats")
@login_required
def soc_attack_stats():
    """
    Retourne les statistiques d'attaques détectées par le middleware Flask
    depuis le démarrage du container (en mémoire).
    Retourne : brute_force (IPs ayant dépassé le seuil) + all_attacks (tous types).
    """
    # ── Brute force par IP ─────────────────────────────────
    brute_list = []
    for ip, data in _brute_force_tracker.items():
        if data["count"] >= BRUTE_FORCE_THRESHOLD:
            brute_list.append({
                "type":       "Brute Force",
                "ip":         ip,
                "count":      data["count"],
                "first_seen": datetime.fromtimestamp(
                    data["first_seen"], tz=timezone.utc
                ).strftime("%H:%M:%S") if data["first_seen"] else "--",
                "last_seen": datetime.fromtimestamp(
                    data["last_seen"], tz=timezone.utc
                ).strftime("%H:%M:%S") if data["last_seen"] else "--",
                "severity":  "CRITICAL",
            })

    # ── Résumé par type d'attaque ──────────────────────────
    summary = {}
    for entry in _attack_tracker:
        t = entry["type"]
        if t not in summary:
            summary[t] = {
                "type":       t,
                "count":      0,
                "severity":   entry["severity"],
                "confidence": entry["confidence"],
                "last_ip":    entry["ip"],
                "last_time":  entry["time"],
            }
        summary[t]["count"]    += 1
        summary[t]["last_ip"]   = entry["ip"]
        summary[t]["last_time"] = entry["time"]

    return jsonify({
        "ok":          True,
        "brute_force": brute_list,
        "all_attacks": list(_attack_tracker[-20:]),   # 20 dernières attaques détaillées
        "summary":     list(summary.values()),         # résumé par type
    })



# ══════════════════════════════════════════════════════
#  SSE REALTIME ENGINE — tous les flux en un seul stream
# ══════════════════════════════════════════════════════

class RealtimeBroker:
    """
    Thread de fond unique qui collecte toutes les données AWS
    et les diffuse à tous les clients SSE connectés.
    
    Canaux émis :
      {"chan":"log",     "data": {time, level, msg, id}}
      {"chan":"metrics", "data": {cpu, mem, errors, unauth}}
      {"chan":"alarms",  "data": [{name, state, desc, reason}, ...]}
      {"chan":"attacks", "data": {brute_force, all_attacks, summary}}
      {"chan":"ping",    "data": null}
    """

    LOG_INTERVAL     = 3    # s — nouveaux logs CloudWatch
    METRICS_INTERVAL = 10   # s — CPU/Mem CloudWatch Metrics
    ALARMS_INTERVAL  = 15   # s — CloudWatch Alarms
    ATTACKS_INTERVAL = 5    # s — attack tracker en mémoire Flask
    PING_INTERVAL    = 20   # s — keepalive

    def __init__(self):
        self._clients: list[queue.Queue] = []
        self._lock   = threading.Lock()
        self._started = False
        self._last_log_ts = 0   # ms du dernier event CloudWatch vu

    # ── subscription ──────────────────────────────────────
    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=200)
        with self._lock:
            self._clients.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        with self._lock:
            if q in self._clients:
                self._clients.remove(q)

    # ── broadcast ─────────────────────────────────────────
    def _push(self, chan: str, data):
        payload = "data: " + json.dumps({"chan": chan, "data": data}, ensure_ascii=False) + "\n\n"
        dead = []
        with self._lock:
            for q in self._clients:
                try:
                    q.put_nowait(payload)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self._clients.remove(q)

    # ── collectors ────────────────────────────────────────
    def _collect_logs(self):
        try:
            logs = boto3.client("logs", region_name=AWS_REGION)

            # Premier appel : charger les 3 dernières heures pour avoir
            # un historique visible dès la connexion SSE
            if not self._last_log_ts:
                start_ms = int(
                    (datetime.now(timezone.utc) - timedelta(hours=3)).timestamp() * 1000
                )
            else:
                start_ms = self._last_log_ts + 1

            # Paginer pour récupérer TOUS les events (pas seulement 30)
            all_events = []
            next_token = None
            while True:
                kwargs = dict(
                    logGroupName=LOG_GROUP,
                    startTime=start_ms,
                    limit=50,
                )
                if next_token:
                    kwargs["nextToken"] = next_token
                resp = logs.filter_log_events(**kwargs)
                batch = resp.get("events", [])
                all_events.extend(batch)
                next_token = resp.get("nextToken")
                # Arrêter la pagination après 200 events max pour ne pas bloquer
                if not next_token or len(all_events) >= 200:
                    break

            events = sorted(all_events, key=lambda e: e["timestamp"])

            for e in events:
                msg = e.get("message", "").strip()
                if not msg:
                    continue
                if "ERROR" in msg or "error" in msg or "Exception" in msg:
                    level = "ERROR"
                elif "WARN" in msg or "warn" in msg or "WARNING" in msg or "[ATTACK" in msg:
                    level = "WARN"
                else:
                    level = "INFO"
                ts = datetime.fromtimestamp(
                    e["timestamp"] / 1000, tz=timezone.utc
                ).strftime("%H:%M:%S")
                self._push("log", {
                    "time":  ts,
                    "level": level,
                    "msg":   msg[:300],
                    "id":    e["eventId"],
                })
                self._last_log_ts = max(self._last_log_ts, e["timestamp"])
        except Exception as ex:
            app.logger.error(f"[SSE] _collect_logs error: {ex}")

    def _collect_metrics(self):
        try:
            cw      = boto3.client("cloudwatch", region_name=AWS_REGION)
            now_utc = datetime.now(timezone.utc)
            one_h   = now_utc - timedelta(hours=1)

            def _stat(namespace, metric, dims, stat="Average"):
                r = cw.get_metric_statistics(
                    Namespace=namespace, MetricName=metric,
                    Dimensions=dims,
                    StartTime=one_h, EndTime=now_utc,
                    Period=300, Statistics=[stat],
                )
                pts = r.get("Datapoints", [])
                if not pts: return 0.0
                return round(sorted(pts, key=lambda x: x["Timestamp"])[-1][stat], 1)

            ecs_dims = [
                {"Name": "ClusterName", "Value": ECS_CLUSTER},
                {"Name": "ServiceName", "Value": ECS_SERVICE},
            ]
            log_dims = [{"Name": "LogGroup", "Value": LOG_GROUP}]

            cpu    = _stat("AWS/ECS", "CPUUtilization",          ecs_dims)
            mem    = _stat("AWS/ECS", "MemoryUtilization",       ecs_dims)
            errors = _stat("SOC/Security", "ErrorCount",         log_dims, "Sum")
            unauth = _stat("SOC/Security", "UnauthorizedAccessCount", log_dims, "Sum")

            self._push("metrics", {
                "cpu": cpu, "mem": mem,
                "errors": int(errors), "unauth": int(unauth),
                "ts": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            })
        except Exception:
            pass

    def _collect_alarms(self):
        try:
            cw   = boto3.client("cloudwatch", region_name=AWS_REGION)
            resp = cw.describe_alarms(AlarmNames=ALARM_NAMES)
            alarms = [
                {
                    "name":   a["AlarmName"],
                    "state":  a["StateValue"],
                    "desc":   a.get("AlarmDescription", ""),
                    "reason": a.get("StateReason", ""),
                }
                for a in resp.get("MetricAlarms", [])
            ]
            self._push("alarms", {
                "alarms": alarms,
                "ts": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            })
        except Exception:
            pass

    def _collect_attacks(self):
        try:
            brute_list = []
            for ip, data in _brute_force_tracker.items():
                if data["count"] >= BRUTE_FORCE_THRESHOLD:
                    brute_list.append({
                        "type": "Brute Force", "ip": ip,
                        "count": data["count"],
                        "first_seen": datetime.fromtimestamp(
                            data["first_seen"], tz=timezone.utc
                        ).strftime("%H:%M:%S") if data["first_seen"] else "--",
                        "last_seen": datetime.fromtimestamp(
                            data["last_seen"], tz=timezone.utc
                        ).strftime("%H:%M:%S") if data["last_seen"] else "--",
                        "severity": "CRITICAL",
                    })
            summary = {}
            for entry in _attack_tracker:
                t = entry["type"]
                if t not in summary:
                    summary[t] = {
                        "type": t, "count": 0,
                        "severity": entry["severity"],
                        "confidence": entry["confidence"],
                        "last_ip": entry["ip"], "last_time": entry["time"],
                    }
                summary[t]["count"]    += 1
                summary[t]["last_ip"]   = entry["ip"]
                summary[t]["last_time"] = entry["time"]

            self._push("attacks", {
                "brute_force": brute_list,
                "all_attacks": list(_attack_tracker[-20:]),
                "summary":     list(summary.values()),
                "ts": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            })
        except Exception:
            pass

    # ── main loop ─────────────────────────────────────────
    def _run(self):
        t_metrics = 0
        t_alarms  = 0
        t_attacks = 0
        t_ping    = 0

        while True:
            now = time.time()

            # Logs toutes les LOG_INTERVAL s
            self._collect_logs()

            # Métriques
            if now - t_metrics >= self.METRICS_INTERVAL:
                self._collect_metrics()
                t_metrics = now

            # Alarmes
            if now - t_alarms >= self.ALARMS_INTERVAL:
                self._collect_alarms()
                t_alarms = now

            # Attaques
            if now - t_attacks >= self.ATTACKS_INTERVAL:
                self._collect_attacks()
                t_attacks = now

            # Ping keepalive
            if now - t_ping >= self.PING_INTERVAL:
                self._push("ping", None)
                t_ping = now

            time.sleep(self.LOG_INTERVAL)

    def start(self):
        if not self._started:
            self._started = True
            t = threading.Thread(target=self._run, daemon=True)
            t.start()


_broker = RealtimeBroker()


@app.route("/api/soc/stream")
@login_required
def soc_stream():
    """SSE endpoint — diffuse TOUS les canaux en temps réel."""
    _broker.start()
    q = _broker.subscribe()

    def generate():
        yield "data: " + json.dumps({"chan": "ping", "data": None}) + "\n\n"
        try:
            while True:
                try:
                    yield q.get(timeout=25)
                except queue.Empty:
                    yield "data: " + json.dumps({"chan": "ping", "data": None}) + "\n\n"
        except GeneratorExit:
            pass
        finally:
            _broker.unsubscribe(q)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )

# ══════════════════════════════════════════════════════
#  FEATURE 1 — BLOCAGE AUTOMATIQUE IP DANS AWS WAF
# ══════════════════════════════════════════════════════

# Suivi des IPs bloquées (en mémoire + WAF)
_blocked_ips: dict = {}   # { ip: {"time": str, "reason": str, "count": int} }
_block_lock = threading.Lock()


def _waf_block_ip(ip: str, reason: str = "Auto-blocked by SOC"):
    """Ajoute l'IP dans le WAF IP Set AWS et le tracker local."""
    with _block_lock:
        if ip in _blocked_ips:
            return  # déjà bloquée

    # Appel WAF
    if WAF_IP_SET_ID:
        try:
            waf = boto3.client("wafv2", region_name=AWS_REGION)
            # Récupérer le token courant (obligatoire pour update)
            current = waf.get_ip_set(
                Name=WAF_IP_SET_NAME,
                Scope=WAF_SCOPE,
                Id=WAF_IP_SET_ID,
            )
            existing_addresses = current["IPSet"]["Addresses"]
            cidr = f"{ip}/32"
            if cidr not in existing_addresses:
                existing_addresses.append(cidr)
                waf.update_ip_set(
                    Name=WAF_IP_SET_NAME,
                    Scope=WAF_SCOPE,
                    Id=WAF_IP_SET_ID,
                    LockToken=current["LockToken"],
                    Addresses=existing_addresses,
                )
                app.logger.warning(f"[WAF BLOCK] IP {ip} ajoutée au WAF IP Set — {reason}")
        except Exception as e:
            app.logger.error(f"[WAF BLOCK] Erreur ajout WAF: {e}")

    with _block_lock:
        _blocked_ips[ip] = {
            "ip":     ip,
            "time":   datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "reason": reason,
            "count":  _brute_force_tracker.get(ip, {}).get("count", 0),
        }


def _check_auto_block(ip: str):
    """Vérifie si une IP doit être bloquée automatiquement."""
    attack_count = sum(1 for a in _attack_tracker if a["ip"] == ip)
    brute_count  = _brute_force_tracker.get(ip, {}).get("count", 0)
    total = attack_count + brute_count
    if total >= AUTO_BLOCK_THRESHOLD and ip not in _blocked_ips:
        _waf_block_ip(ip, reason=f"Auto-block: {total} attaques détectées")
        # Notifier via SNS
        try:
            sns = boto3.client("sns", region_name=AWS_REGION)
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f"🚫 SOC AUTO-BLOCK — IP {ip} bloquée",
                Message=(
                    f"IP {ip} automatiquement bloquée par le SOC Dashboard.\n"
                    f"Raison  : {total} attaques détectées\n"
                    f"Heure   : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                    f"Cluster : {ECS_CLUSTER}\n"
                ),
            )
        except Exception:
            pass


# Hooker _check_auto_block dans _log_attack
_orig_log_attack = _log_attack


def _log_attack(attack_name, detail="", extra=""):
    _orig_log_attack(attack_name, detail, extra)
    _check_auto_block(request.remote_addr)


@app.route("/api/soc/blocked-ips")
@login_required
def soc_blocked_ips():
    """Retourne la liste des IPs bloquées automatiquement."""
    with _block_lock:
        return jsonify({"ok": True, "blocked": list(_blocked_ips.values())})


@app.route("/api/soc/block-ip", methods=["POST"])
@login_required
def soc_block_ip_manual():
    """Blocage manuel d'une IP depuis le dashboard."""
    body   = request.get_json(force=True) or {}
    ip     = body.get("ip", "").strip()
    reason = body.get("reason", f"Blocage manuel par {session.get('username','?')}")
    if not ip:
        return jsonify({"ok": False, "error": "IP manquante"}), 400
    _waf_block_ip(ip, reason=reason)
    return jsonify({"ok": True, "message": f"IP {ip} bloquée", "ip": ip})


# ══════════════════════════════════════════════════════
#  FEATURE 2 — GÉOLOCALISATION IP
# ══════════════════════════════════════════════════════

_geo_cache: dict = {}   # { ip: {country, city, org, lat, lon, flag} }
_geo_lock = threading.Lock()


def _geolocate_ip(ip: str) -> dict:
    """Géolocalise une IP via ip-api.com (gratuit, 45 req/min)."""
    with _geo_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]

    result = {"country": "?", "city": "?", "org": "?", "lat": 0, "lon": 0, "flag": "🌐", "isp": "?"}
    try:
        # IPs privées → localhost
        if ip.startswith(("192.168.", "10.", "172.", "127.", "::1")):
            result = {"country": "Local", "city": "Localhost", "org": "LAN",
                      "lat": 0, "lon": 0, "flag": "🏠", "isp": "Local Network"}
        else:
            url  = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,org,isp,lat,lon"
            req  = urllib.request.Request(url, headers={"User-Agent": "SOC-Dashboard/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                cc   = data.get("countryCode", "")
                flag = "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper()) if cc else "🌐"
                result = {
                    "country": data.get("country", "?"),
                    "city":    data.get("city", "?"),
                    "org":     data.get("org", "?"),
                    "isp":     data.get("isp", "?"),
                    "lat":     data.get("lat", 0),
                    "lon":     data.get("lon", 0),
                    "flag":    flag,
                }
    except Exception as e:
        app.logger.debug(f"[GEO] Erreur pour {ip}: {e}")

    with _geo_lock:
        _geo_cache[ip] = result
    return result


@app.route("/api/soc/geolocate")
@login_required
def soc_geolocate():
    """Géolocalise une IP ou toutes les IPs attaquantes connues."""
    ip = request.args.get("ip", "").strip()
    if ip:
        return jsonify({"ok": True, "ip": ip, "geo": _geolocate_ip(ip)})

    # Retourne toutes les IPs avec geo + count pour la carte
    ip_counts: dict = {}
    for entry in _attack_tracker:
        a_ip = entry["ip"]
        if a_ip not in ip_counts:
            ip_counts[a_ip] = {"count": 0, "types": set(), "last_time": entry["time"]}
        ip_counts[a_ip]["count"] += 1
        ip_counts[a_ip]["types"].add(entry["type"])
        ip_counts[a_ip]["last_time"] = entry["time"]

    result = []
    for a_ip, info in ip_counts.items():
        geo = _geolocate_ip(a_ip)
        result.append({
            "ip":        a_ip,
            "count":     info["count"],
            "types":     list(info["types"]),
            "last_time": info["last_time"],
            "blocked":   a_ip in _blocked_ips,
            **geo,
        })
    return jsonify({"ok": True, "attackers": result})


# ══════════════════════════════════════════════════════
#  FEATURE 3 — RAPPORT PDF QUOTIDIEN VIA SES
# ══════════════════════════════════════════════════════

def _build_pdf_report() -> bytes:
    """Génère un rapport PDF des attaques et métriques."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            topMargin=1.5*cm, bottomMargin=1.5*cm,
                            leftMargin=2*cm, rightMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    # ── Couleurs ──
    C_DARK  = colors.HexColor("#030a0e")
    C_CYAN  = colors.HexColor("#00d4ff")
    C_GREEN = colors.HexColor("#00ff88")
    C_RED   = colors.HexColor("#ff3366")
    C_WARN  = colors.HexColor("#ffaa00")
    C_GREY  = colors.HexColor("#4a7a90")

    title_style = ParagraphStyle("title", fontName="Helvetica-Bold",
                                 fontSize=20, textColor=C_CYAN, spaceAfter=4)
    sub_style   = ParagraphStyle("sub",   fontName="Helvetica",
                                 fontSize=10, textColor=C_GREY, spaceAfter=12)
    h2_style    = ParagraphStyle("h2",    fontName="Helvetica-Bold",
                                 fontSize=13, textColor=C_CYAN, spaceBefore=14, spaceAfter=6)
    body_style  = ParagraphStyle("body",  fontName="Helvetica",
                                 fontSize=9,  textColor=colors.HexColor("#b8d4e0"), spaceAfter=4)

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── En-tête ──
    story.append(Paragraph("🛡️  SOC DASHBOARD — RAPPORT DE SÉCURITÉ", title_style))
    story.append(Paragraph(f"Généré le {now_str} · Cluster: {ECS_CLUSTER} · Service: {ECS_SERVICE}", sub_style))
    story.append(HRFlowable(width="100%", thickness=1, color=C_CYAN))
    story.append(Spacer(1, 0.3*cm))

    # ── Résumé exécutif ──
    story.append(Paragraph("📊 RÉSUMÉ EXÉCUTIF", h2_style))
    total_attacks = len(_attack_tracker)
    blocked_count = len(_blocked_ips)
    attack_types  = list({a["type"] for a in _attack_tracker})
    unique_ips    = list({a["ip"] for a in _attack_tracker})

    summary_data = [
        ["Indicateur", "Valeur"],
        ["Total attaques détectées", str(total_attacks)],
        ["IPs sources uniques",      str(len(unique_ips))],
        ["IPs bloquées (WAF)",       str(blocked_count)],
        ["Types d'attaques",         ", ".join(attack_types) or "Aucun"],
        ["Accès refusés (401/403)",  str(sum(d.get("count", 0) for d in _brute_force_tracker.values()))],
    ]
    t = Table(summary_data, colWidths=[9*cm, 8*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0),  C_CYAN),
        ("TEXTCOLOR",   (0, 0), (-1, 0),  C_DARK),
        ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("BACKGROUND",  (0, 1), (-1, -1), colors.HexColor("#0d1f2d")),
        ("TEXTCOLOR",   (0, 1), (-1, -1), colors.HexColor("#b8d4e0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0d1f2d"), colors.HexColor("#060f15")]),
        ("GRID",        (0, 0), (-1, -1), 0.5, C_GREY),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.4*cm))

    # ── Détail des attaques ──
    if _attack_tracker:
        story.append(Paragraph("⚡ DÉTAIL DES ATTAQUES (20 dernières)", h2_style))
        attack_data = [["Heure", "Type", "IP Source", "Sévérité", "Confiance"]]
        for a in list(_attack_tracker)[-20:]:
            sev   = a.get("severity", "MEDIUM")
            color = C_RED if sev == "CRITICAL" else (C_WARN if sev == "HIGH" else C_GREEN)
            attack_data.append([
                a.get("time", "--"),
                a.get("type", "--"),
                a.get("ip",   "--"),
                sev,
                f"{a.get('confidence', 0)}%",
            ])
        t2 = Table(attack_data, colWidths=[2.5*cm, 5*cm, 4*cm, 3*cm, 2.5*cm])
        t2.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_CYAN),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_DARK),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("BACKGROUND",    (0, 1), (-1, -1), colors.HexColor("#0d1f2d")),
            ("TEXTCOLOR",     (0, 1), (-1, -1), colors.HexColor("#b8d4e0")),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#0d1f2d"), colors.HexColor("#060f15")]),
            ("GRID",          (0, 0), (-1, -1), 0.5, C_GREY),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t2)
        story.append(Spacer(1, 0.4*cm))

    # ── IPs bloquées ──
    if _blocked_ips:
        story.append(Paragraph("🚫 IPs BLOQUÉES AUTOMATIQUEMENT", h2_style))
        block_data = [["IP", "Heure blocage", "Raison"]]
        with _block_lock:
            for b in _blocked_ips.values():
                block_data.append([b["ip"], b["time"], b["reason"][:60]])
        t3 = Table(block_data, colWidths=[4*cm, 3*cm, 10*cm])
        t3.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_RED),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("BACKGROUND",    (0, 1), (-1, -1), colors.HexColor("#1a0a0d")),
            ("TEXTCOLOR",     (0, 1), (-1, -1), colors.HexColor("#ffaaaa")),
            ("GRID",          (0, 0), (-1, -1), 0.5, C_GREY),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t3)
        story.append(Spacer(1, 0.4*cm))

    # ── Footer ──
    story.append(HRFlowable(width="100%", thickness=1, color=C_GREY))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        f"DevSecOps SOC Dashboard · {ECS_CLUSTER} · Rapport confidentiel · {now_str}",
        ParagraphStyle("footer", fontName="Helvetica", fontSize=7, textColor=C_GREY)
    ))

    doc.build(story)
    buf.seek(0)
    return buf.read()


@app.route("/api/soc/report/download")
@login_required
def soc_report_download():
    """Télécharge le rapport PDF depuis le navigateur."""
    if not REPORTLAB_OK:
        return jsonify({"ok": False, "error": "reportlab non installé"}), 500
    try:
        pdf_bytes = _build_pdf_report()
        now_str   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=soc_report_{now_str}.pdf"}
        )
    except Exception as ex:
        return jsonify({"ok": False, "error": str(ex)}), 500


@app.route("/api/soc/report/send", methods=["POST"])
@login_required
def soc_report_send():
    """Génère le PDF et l'envoie par email via AWS SES."""
    if not REPORTLAB_OK:
        return jsonify({"ok": False, "error": "reportlab non installé"}), 500
    if not SES_FROM_EMAIL or not SES_TO_EMAIL:
        return jsonify({"ok": False, "error": "SES_FROM_EMAIL / SES_TO_EMAIL non configurés"}), 400
    try:
        import email as email_lib
        from email.mime.multipart import MIMEMultipart
        from email.mime.base import MIMEBase
        from email.mime.text import MIMEText
        import base64

        pdf_bytes = _build_pdf_report()
        now_str   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        filename  = f"soc_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.pdf"

        # Construire email MIME
        msg = MIMEMultipart()
        msg["Subject"] = f"📊 SOC Dashboard — Rapport de sécurité {now_str}"
        msg["From"]    = SES_FROM_EMAIL
        msg["To"]      = SES_TO_EMAIL

        body = MIMEText(
            f"Bonjour,\n\nVeuillez trouver en pièce jointe le rapport de sécurité SOC.\n\n"
            f"Cluster : {ECS_CLUSTER}\nService : {ECS_SERVICE}\nGénéré  : {now_str}\n\n"
            f"Total attaques : {len(_attack_tracker)}\nIPs bloquées   : {len(_blocked_ips)}\n\n"
            f"--\nDevSecOps SOC Dashboard", "plain"
        )
        msg.attach(body)

        attachment = MIMEBase("application", "pdf")
        attachment.set_payload(pdf_bytes)
        from email import encoders
        encoders.encode_base64(attachment)
        attachment.add_header("Content-Disposition", f"attachment; filename={filename}")
        msg.attach(attachment)

        ses = boto3.client("ses", region_name=AWS_REGION)
        ses.send_raw_email(
            Source=SES_FROM_EMAIL,
            Destinations=[SES_TO_EMAIL],
            RawMessage={"Data": msg.as_bytes()},
        )
        app.logger.info(f"[SOC REPORT] PDF envoyé à {SES_TO_EMAIL}")
        return jsonify({"ok": True, "message": f"Rapport PDF envoyé à {SES_TO_EMAIL}"})
    except Exception as ex:
        return jsonify({"ok": False, "error": str(ex)}), 500


# ══════════════════════════════════════════════════════
#  LANCEMENT
# ══════════════════════════════════════════════════════
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)  # nosec