from flask import Flask, render_template, jsonify
import json

app = Flask(__name__)

ALERT_FILE = "alerts.json"

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/alerts")
def get_alerts():
    try:
        with open(ALERT_FILE) as f:
            return jsonify(json.load(f))
    except:
        return jsonify([])

@app.route("/api/stats")
def stats():
    try:
        with open(ALERT_FILE) as f:
            data = json.load(f)
    except:
        data = []

    stats = {}
    for alert in data:
        t = alert["type"]
        stats[t] = stats.get(t, 0) + 1

    return jsonify(stats)

if __name__ == "__main__":
    app.run(debug=True)
