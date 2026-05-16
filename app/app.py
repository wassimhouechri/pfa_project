"""
DevSecOps Demo App — Flask
Compatible avec le pipeline CI/CD (Bandit, Trivy, ZAP, Safety)
SOC Dashboard avec vrais appels AWS (boto3) via IAM Role ECS
+ Détection d'attaques en temps réel (before_request / after_request)
+ Buffer mémoire pour logs temps réel (0 délai vs CloudWatch)
+ Métriques CPU/RAM avec Period=60 et calcul local des erreurs/unauth
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import re
import logging
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
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
#  BUFFER LOGS EN MÉMOIRE — TEMPS RÉEL (0 délai)
#  Corrige le délai CloudWatch de 15-60 secondes
# ══════════════════════════════════════════════════════

_log_buffer: deque = deque(maxlen=200)


class _BufferHandler(logging.Handler):
    """Handler Python logging qui pousse chaque log dans _log_buffer."""
    def emit(self, record: logging.LogRecord) -> None:
        level_name = record.levelname
        if level_name in ("ERROR", "CRITICAL"):
            level = "ERROR"
        elif level_name == "WARNING":
            level = "WARN"
        else:
            level = "INFO"
        try:
            msg = self.format(record)
        except Exception:
            msg = record.getMessage()
        _log_buffer.appendleft({
            "time":   datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "level":  level,
            "msg":    msg[:300],
            "id":     f"{record.created:.3f}-{record.lineno}",
            "source": "local",
        })


def _setup_logging() -> None:
    """
    Configure app.logger pour :
    1. Ecrire sur stdout (capté par Gunicorn / CloudWatch agent)
    2. Pousser dans _log_buffer (temps réel pour le SOC dashboard)
    """
    gunicorn_logger = logging.getLogger("gunicorn.error")
    if gunicorn_logger.handlers:
        app.logger.handlers = list(gunicorn_logger.handlers)

    if not any(isinstance(h, logging.StreamHandler) for h in app.logger.handlers):
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.DEBUG)
        stream_handler.setFormatter(logging.Formatter(
            "[%(asctime)s] %(levelname)s %(message)s",
            datefmt="%H:%M:%S"
        ))
        app.logger.addHandler(stream_handler)

    buf_handler = _BufferHandler()
    buf_handler.setLevel(logging.DEBUG)
    buf_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    app.logger.addHandler(buf_handler)

    app.logger.setLevel(logging.DEBUG)
    app.logger.propagate = False


_setup_logging()


# ══════════════════════════════════════════════════════
#  MOTEUR DE DÉTECTION D'ATTAQUES
# ══════════════════════════════════════════════════════

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
        r"\.\.\\" ,
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

_brute_force_tracker: defaultdict = defaultdict(
    lambda: {"count": 0, "first_seen": 0, "last_seen": 0}
)
BRUTE_FORCE_THRESHOLD = 10
BRUTE_FORCE_WINDOW    = 300

_attack_tracker: list = []
ATTACK_TRACKER_MAX = 100

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


def _detect_attack_in_request():
    parts = [
        request.url,
        str(request.args.to_dict()),
        str(request.form.to_dict()),
        request.headers.get("User-Agent", ""),
        request.headers.get("Referer", ""),
    ]
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


def _log_attack(attack_name: str, detail: str = "", extra: str = "") -> None:
    """
    Ecrit un log WARNING structuré (stdout → CloudWatch)
    ET stocke l'attaque dans _attack_tracker (buffer mémoire temps réel).
    """
    global _attack_tracker
    app.logger.warning(
        f"[ATTACK DETECTED] type={attack_name} "
        f"ip={request.remote_addr} "
        f"method={request.method} "
        f"url={request.url[:300]} "
        f"detail={detail} "
        f"{extra}"
    )
    entry = {
        "type":       attack_name,
        "ip":         request.remote_addr,
        "method":     request.method,
        "url":        request.url[:200],
        "time":       datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "detail":     detail[:100],
        "severity":   ATTACK_META.get(attack_name, {}).get("severity", "MEDIUM"),
        "confidence": ATTACK_META.get(attack_name, {}).get("confidence", 75),
    }
    _attack_tracker.append(entry)
    if len(_attack_tracker) > ATTACK_TRACKER_MAX:
        _attack_tracker = _attack_tracker[-ATTACK_TRACKER_MAX:]


def _send_sns_alert(
    attack_name: str,
    severity: str,
    confidence: int,
    description: str,
    recommendation: str,
) -> None:
    try:
        sns = boto3.client("sns", region_name=AWS_REGION)
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        icon  = icons.get(severity.upper(), "⚠️")
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
            f"📋  DESCRIPTION\n{'─'*60}\n{description}\n\n"
            f"{'─'*60}\n"
            f"🛡️  RECOMMANDATION\n{'─'*60}\n{recommendation}\n\n"
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


_last_sns_sent: dict = {}
SNS_COOLDOWN = 120


def _maybe_send_sns(
    attack_name: str,
    severity: str,
    confidence: int,
    description: str,
    recommendation: str,
) -> None:
    now = time.time()
    if now - _last_sns_sent.get(attack_name, 0) > SNS_COOLDOWN:
        _last_sns_sent[attack_name] = now
        _send_sns_alert(attack_name, severity, confidence, description, recommendation)


# ── Middleware : analyse chaque requête ENTRANTE ──────
@app.before_request
def detect_attack_before():
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
    if response.status_code in (401, 403):
        ip  = request.remote_addr
        now = time.time()
        tracker = _brute_force_tracker[ip]

        if now - tracker["first_seen"] > BRUTE_FORCE_WINDOW:
            tracker["count"]      = 0
            tracker["first_seen"] = now

        tracker["count"]    += 1
        tracker["last_seen"] = now

        app.logger.warning(
            f"unauthorized ip={ip} "
            f"url={request.url[:200]} "
            f"status={response.status_code} "
            f"count={tracker['count']}"
        )

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
            app.logger.info(f"[LOGIN OK] ip={request.remote_addr} username={username}")
            return redirect(url_for("dashboard"))
        error = "Nom d'utilisateur ou mot de passe incorrect."
        app.logger.warning(
            f"[LOGIN FAILED] ip={request.remote_addr} username={username}"
        )
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    app.logger.info(f"[LOGOUT] username={session.get('username')} ip={request.remote_addr}")
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
#  SOC API
# ══════════════════════════════════════════════════════

def _aws(service: str):
    return boto3.client(service, region_name=AWS_REGION)


# ── GET /api/soc/logs ─────────────────────────────────
@app.route("/api/soc/logs")
@login_required
def soc_logs():
    """
    CORRECTION TEMPS RÉEL :
    Source 1 — Buffer mémoire Flask (_log_buffer) : 0 délai, logs depuis le démarrage du container.
    Source 2 — CloudWatch Logs : historique long terme (fenêtre 3h).
    Les deux sont mergés et dédupliqués. Les logs locaux apparaissent en premier.
    """
    # ── Source 1 : buffer mémoire (temps réel, 0 délai) ──
    local_events = list(_log_buffer)

    # ── Source 2 : CloudWatch (historique) ───────────────
    cw_events: list = []
    try:
        logs     = _aws("logs")
        start_ms = int(
            (datetime.now(timezone.utc) - timedelta(hours=3)).timestamp() * 1000
        )
        resp = logs.filter_log_events(
            logGroupName=LOG_GROUP,
            startTime=start_ms,
            limit=50,
        )
        for e in sorted(resp.get("events", []), key=lambda x: x["timestamp"]):
            msg = e.get("message", "").strip()
            if any(k in msg for k in ("ERROR", "error", "Exception")):
                level = "ERROR"
            elif any(k in msg for k in ("WARN", "warn", "WARNING", "[ATTACK", "unauthorized")):
                level = "WARN"
            else:
                level = "INFO"
            ts = datetime.fromtimestamp(
                e["timestamp"] / 1000, tz=timezone.utc
            ).strftime("%H:%M:%S")
            cw_events.append({
                "time":   ts,
                "level":  level,
                "msg":    msg[:300],
                "id":     e["eventId"],
                "source": "cloudwatch",
            })
    except NoCredentialsError:
        app.logger.warning("[SOC] Pas de credentials AWS — CloudWatch Logs ignoré")
    except Exception as ex:
        app.logger.warning(f"[SOC] CloudWatch Logs fetch failed: {ex}")

    # ── Merge + déduplication ─────────────────────────────
    seen: set = set()
    merged: list = []
    for ev in local_events + cw_events:
        key = f"{ev['time']}-{ev['msg'][:60]}"
        if key not in seen:
            seen.add(key)
            merged.append(ev)

    return jsonify({"ok": True, "events": merged[:100]})


# ── GET /api/soc/metrics ──────────────────────────────
@app.route("/api/soc/metrics")
@login_required
def soc_metrics():
    """
    CORRECTIONS :
    - Period 300→60 : granularité 1 min au lieu de 5 min (réduit le retard de 5 min à ~1 min)
    - Retourne None si pas de datapoints ECS (au lieu de 0 silencieux)
    - errors et unauth calculés depuis _log_buffer (temps réel, namespace SOC/Security inexistant)
    """
    # ── Erreurs / accès refusés depuis le buffer local ────
    errors = sum(1 for e in _log_buffer if e["level"] == "ERROR")
    unauth = sum(
        1 for e in _log_buffer
        if any(k in e["msg"] for k in ("401", "403", "unauthorized", "LOGIN FAILED", "Unauthorized"))
    )

    # ── CPU et RAM depuis CloudWatch ECS ─────────────────
    cpu: float | None = None
    mem: float | None = None

    try:
        cw      = _aws("cloudwatch")
        now_utc = datetime.now(timezone.utc)
        one_h   = now_utc - timedelta(hours=1)

        def _metric(namespace: str, metric_name: str, dimensions: list, stat: str = "Average"):
            resp = cw.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=dimensions,
                StartTime=one_h,
                EndTime=now_utc,
                Period=60,          # ← CORRECTION : était 300 (5 min de retard)
                Statistics=[stat],
            )
            pts = resp.get("Datapoints", [])
            if not pts:
                return None         # ← CORRECTION : None = "pas de données ECS" vs 0 réel
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
    except NoCredentialsError:
        app.logger.warning("[SOC] Pas de credentials AWS — CloudWatch Metrics ignoré")
    except Exception as ex:
        app.logger.warning(f"[SOC] CloudWatch Metrics fetch failed: {ex}")

    return jsonify({
        "ok":            True,
        "cpu":           cpu,            # float ou null
        "mem":           mem,            # float ou null
        "cpu_available": cpu is not None,
        "mem_available": mem is not None,
        "errors":        errors,         # temps réel depuis buffer local
        "unauth":        unauth,         # temps réel depuis buffer local
    })


# ── GET /api/soc/alarms ───────────────────────────────
@app.route("/api/soc/alarms")
@login_required
def soc_alarms():
    try:
        cw   = _aws("cloudwatch")
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
        return jsonify({"ok": True, "alarms": alarms})
    except NoCredentialsError:
        return jsonify({"ok": False, "error": "Pas de credentials AWS"}), 403
    except Exception as ex:
        return jsonify({"ok": False, "error": str(ex)}), 500


# ── POST /api/soc/test-alert ──────────────────────────
@app.route("/api/soc/test-alert", methods=["POST"])
@login_required
def soc_test_alert():
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
        app.logger.info(f"[SOC] Test alert envoyée par {session.get('username')}")
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
    try:
        body           = request.get_json(force=True) or {}
        attack_name    = body.get("attack_name", "Attaque Inconnue")
        severity       = body.get("severity", "unknown").upper()
        confidence     = body.get("confidence", 0)
        description    = body.get("description", "Aucune description disponible.")
        recommendation = body.get("recommendation", "Analyser les logs manuellement.")
        operator       = session.get("username", "inconnu")
        now_str        = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        icon  = icons.get(severity, "⚠️")

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
            f"📋  DESCRIPTION\n{'─'*60}\n{description}\n\n"
            f"{'─'*60}\n"
            f"🛡️  RECOMMANDATION\n{'─'*60}\n{recommendation}\n\n"
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
            "ok":          True,
            "message":     f"Alerte SNS envoyée pour: {attack_name}",
            "severity":    severity,
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
    Retourne depuis le démarrage du container :
    - brute_force : IPs ayant dépassé le seuil de tentatives
    - all_attacks : 20 dernières attaques détaillées (tous types)
    - summary     : résumé par type avec compteur
    """
    brute_list = []
    for ip, data in _brute_force_tracker.items():
        if data["count"] >= BRUTE_FORCE_THRESHOLD:
            brute_list.append({
                "type":       "Brute Force",
                "ip":         ip,
                "count":      data["count"],
                "first_seen": (
                    datetime.fromtimestamp(data["first_seen"], tz=timezone.utc)
                    .strftime("%H:%M:%S") if data["first_seen"] else "--"
                ),
                "last_seen": (
                    datetime.fromtimestamp(data["last_seen"], tz=timezone.utc)
                    .strftime("%H:%M:%S") if data["last_seen"] else "--"
                ),
                "severity": "CRITICAL",
            })

    summary: dict = {}
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
        "all_attacks": list(_attack_tracker[-20:]),
        "summary":     list(summary.values()),
    })


# ── GET /api/soc/buffer-logs ──────────────────────────
@app.route("/api/soc/buffer-logs")
@login_required
def soc_buffer_logs():
    """
    Endpoint de diagnostic : retourne uniquement les logs du buffer mémoire Flask.
    Permet de vérifier que les logs arrivent bien en temps réel,
    indépendamment de CloudWatch.
    """
    return jsonify({
        "ok":     True,
        "count":  len(_log_buffer),
        "events": list(_log_buffer)[:50],
    })


# ══════════════════════════════════════════════════════
#  LANCEMENT
# ══════════════════════════════════════════════════════
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)  # nosec