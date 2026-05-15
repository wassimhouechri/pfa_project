"""
DevSecOps Demo App — Flask
Compatible avec le pipeline CI/CD (Bandit, Trivy, ZAP, Safety)
SOC Dashboard avec vrais appels AWS (boto3) via IAM Role ECS
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timezone, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-in-prod")
app.config["PERMANENT_SESSION_LIFETIME"] = 86400   # 24h — évite les expirations trop rapides
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# ── Config AWS ───────────────────────────────────────
AWS_REGION      = os.environ.get("AWS_REGION", "us-east-1")
LOG_GROUP       = os.environ.get("CW_LOG_GROUP", "/ecs/devsecops")
ECS_CLUSTER     = os.environ.get("ECS_CLUSTER", "devsecops-cluster")
ECS_SERVICE     = os.environ.get("ECS_SERVICE", "devsecops-service")
SNS_TOPIC_ARN   = os.environ.get("SNS_TOPIC_ARN",
                    "arn:aws:sns:us-east-1:792782834628:soc-alerts")
ALARM_NAMES     = [
    "SOC-ECS-Errors",
    "SOC-Unauthorized-Access",
    "SOC-ECS-Task-Stopped",
]

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
            # SOC API routes seulement : retourner JSON 401
            # (le fetch JS vérifie content-type pour éviter que res.json() plante)
            # Les autres routes /api/ (ex: /api/whoami) gardent le redirect 302
            # pour rester compatibles avec les tests existants.
            if request.path.startswith("/api/soc/"):
                return jsonify({"ok": False, "error": "session_expired"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ── Routes publiques ─────────────────────────────────

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


@app.route("/soc")
@login_required
def soc():
    """SOC Dashboard — Security Operations Center."""
    return render_template("soc.html", username=session["username"])


# ── API REST ─────────────────────────────────────────

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
    """Retourne un client boto3 pour le service donné.
    Sur ECS avec IAM Role, boto3 récupère les credentials
    automatiquement depuis les métadonnées du container.
    """
    return boto3.client(service, region_name=AWS_REGION)


# ── GET /api/soc/logs ─────────────────────────────────
@app.route("/api/soc/logs")
@login_required
def soc_logs():
    """
    Retourne les 30 derniers événements du log group ECS.
    Le JS les affiche en temps réel (polling toutes les 10 s).
    """
    try:
        logs = _aws("logs")
        # Fenêtre : 3 dernières heures (1h trop court si le container démarre)
        start_ms = int((datetime.now(timezone.utc) - timedelta(hours=3)).timestamp() * 1000)
        resp = logs.filter_log_events(
            logGroupName=LOG_GROUP,
            startTime=start_ms,
            limit=50,
        )
        raw_events = sorted(resp.get("events", []), key=lambda e: e["timestamp"])
        events = []
        for e in raw_events:
            msg = e.get("message", "").strip()
            # Détection du niveau depuis le message brut
            if "ERROR" in msg or "error" in msg or "Exception" in msg:
                level = "ERROR"
            elif "WARN" in msg or "warn" in msg or "WARNING" in msg:
                level = "WARN"
            else:
                level = "INFO"
            ts = datetime.fromtimestamp(
                e["timestamp"] / 1000, tz=timezone.utc
            ).strftime("%H:%M:%S")
            events.append({"time": ts, "level": level, "msg": msg[:200], "id": e["eventId"]})
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
    """
    Retourne CPU%, Mémoire%, erreurs et accès refusés
    depuis CloudWatch Metrics (ECS) et Logs Insights.
    """
    try:
        cw = _aws("cloudwatch")
        now_utc  = datetime.now(timezone.utc)
        one_hour = now_utc - timedelta(hours=1)

        def _metric(namespace, metric_name, dimensions, stat="Average"):
            resp = cw.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=dimensions,
                StartTime=one_hour,
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

        # Erreurs et accès refusés depuis les métriques SOC custom
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
            "cpu": cpu,
            "mem": mem,
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
    """
    Retourne l'état des alarmes CloudWatch SOC.
    États possibles : OK | ALARM | INSUFFICIENT_DATA
    """
    try:
        cw = _aws("cloudwatch")
        resp = cw.describe_alarms(AlarmNames=ALARM_NAMES)
        alarms = []
        for a in resp.get("MetricAlarms", []):
            alarms.append({
                "name":  a["AlarmName"],
                "state": a["StateValue"],          # OK | ALARM | INSUFFICIENT_DATA
                "desc":  a.get("AlarmDescription", ""),
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
    """
    Publie un message de test sur le topic SNS soc-alerts.
    Les abonnés (emails confirmés) reçoivent l'alerte immédiatement.
    """
    try:
        sns = _aws("sns")
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="🚨 SOC ALERT TEST — DevSecOps Dashboard",
            Message=(
                f"Alerte de test envoyée depuis le SOC Dashboard\n"
                f"Cluster  : {ECS_CLUSTER}\n"
                f"Service  : {ECS_SERVICE}\n"
                f"Opérateur: {session.get('username', 'inconnu')}\n"
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


# ── Lancement ────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)  # nosec
