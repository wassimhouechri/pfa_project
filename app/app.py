from flask import Flask, request, jsonify
import os
import subprocess

app = Flask(__name__)

@app.route("/health")
def health():
    return jsonify({"status": "healthy"}), 200


@app.route("/run", methods=["POST"])
def run_safe():
    """
    SAFE: pas d'exécution directe de commandes utilisateur
    """
    command = request.json.get("command", "")

    allowed_commands = {
        "date": "date",
        "whoami": "whoami"
    }

    if command not in allowed_commands:
        return jsonify({"error": "Command not allowed"}), 403

    result = subprocess.run(
        allowed_commands[command],
        shell=False,
        capture_output=True,
        text=True
    )

    return jsonify({
        "output": result.stdout
    })


@app.route("/")
def home():
    return "Secure DevSecOps App"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)