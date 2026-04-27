import os
import socket
import datetime
from flask import Flask, render_template, jsonify

app = Flask(__name__)

# ── App metadata injected at build time (or defaults for local dev) ──
APP_VERSION   = os.environ.get("APP_VERSION",   "1.0.0")
ENVIRONMENT   = os.environ.get("ENVIRONMENT",   "dev")
DEPLOY_TIME   = os.environ.get("DEPLOY_TIME",   "unknown")
COMMIT_SHA    = os.environ.get("COMMIT_SHA",    "local")
BRANCH        = os.environ.get("BRANCH",        "main")
WORKFLOW      = os.environ.get("WORKFLOW",      "deploy-dev.yml")

@app.route("/")
def index():
    """Main deployment status dashboard."""
    context = {
        "version":    APP_VERSION,
        "env":        ENVIRONMENT,
        "hostname":   socket.gethostname(),
        "deploy_time": DEPLOY_TIME,
        "commit_sha": COMMIT_SHA[:7] if len(COMMIT_SHA) > 7 else COMMIT_SHA,
        "branch":     BRANCH,
        "workflow":   WORKFLOW,
        "port":       "5000",
    }
    return render_template("index.html", **context)


@app.route("/health")
def health():
    """Health check endpoint — used by the pipeline smoke test."""
    return jsonify({
        "status":  "ok",
        "version": APP_VERSION,
        "env":     ENVIRONMENT,
        "host":    socket.gethostname(),
        "time":    datetime.datetime.utcnow().isoformat() + "Z",
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
