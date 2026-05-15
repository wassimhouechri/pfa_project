"""
DevSecOps Demo App — Flask
Compatible avec le pipeline CI/CD (Bandit, Trivy, ZAP, Safety)
SOC Dashboard avec vrais appels AWS (boto3) via IAM Role ECS
+ Détection d'attaques en temps réel (before_request / after_request)
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import re
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import time

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
    """Écrit un log WARNING structuré — capté par CloudWatch."""
    app.logger.warning(
        f"[ATTACK DETECTED] type={attack_name} "
        f"ip={request.remote_addr} "
        f"method={request.method} "
        f"url={request.url[:300]} "
        f"detail={detail} "
        f"{extra}"
    )


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
    Permet au SOC Dashboard JS d'afficher les attaques en temps réel.
    """
    stats = []
    for ip, data in _brute_force_tracker.items():
        if data["count"] >= BRUTE_FORCE_THRESHOLD:
            stats.append({
                "type": "Brute Force",
                "ip": ip,
                "count": data["count"],
                "first_seen": datetime.fromtimestamp(
                    data["first_seen"], tz=timezone.utc
                ).strftime("%H:%M:%S") if data["first_seen"] else "--",
                "last_seen": datetime.fromtimestamp(
                    data["last_seen"], tz=timezone.utc
                ).strftime("%H:%M:%S") if data["last_seen"] else "--",
                "severity": "CRITICAL",
            })
    return jsonify({"ok": True, "brute_force": stats})


# ══════════════════════════════════════════════════════
#  LANCEMENT
# ══════════════════════════════════════════════════════
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)  # nosec