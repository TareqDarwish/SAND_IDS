from flask import Flask, render_template, jsonify, request
from pymongo import MongoClient

app = Flask(__name__, static_folder="static")

# ==================== MongoDB ====================

MONGO_URI = "mongodb://127.0.0.1:27017/"
DB_NAME = "ids_llm"

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

alerts_col = db["alerts"]
flow_logs_col = db["flow_logs"]

# ==================== Routes ====================

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/alerts")
def get_alerts():
    query = {}

    # Filters
    if request.args.get("status"):
        query["status"] = request.args["status"]

    if request.args.get("priority"):
        query["priority"] = request.args["priority"]

    if request.args.get("classification"):
        query["classification"] = request.args["classification"]

    if request.args.get("min_confidence"):
        query["confidence"] = {"$gte": int(request.args["min_confidence"])}

    # Sorting
    sort_key = request.args.get("sort", "time")
    if sort_key == "confidence":
        sort = [("confidence", -1)]
    elif sort_key == "priority":
        sort = [("priority", -1)]
    else:
        sort = [("created_at", -1)]

    alerts = []
    for a in alerts_col.find(query).sort(sort).limit(200):
        alerts.append({
            "flow_id": a.get("flow_id"),
            "priority": a.get("priority"),
            "classification": a.get("classification"),
            "attack_name": a.get("attack_name"),
            "confidence": a.get("confidence"),
            "status": a.get("status"),
            "reasoning": a.get("reasoning", "No explanation provided."),
            "created_at": a.get("created_at")
        })

    return jsonify(alerts)


@app.route("/alert/<flow_id>")
def alert_details(flow_id):

    # Mark alert as SEEN
    alerts_col.update_one(
        {"flow_id": flow_id},
        {"$set": {"status": "SEEN"}}
    )

    # Fetch full flow log
    flow = flow_logs_col.find_one(
        {"flow_id": flow_id},
        {"_id": 0}
    )

    # Fetch alert (for reasoning + metadata)
    alert = alerts_col.find_one(
        {"flow_id": flow_id},
        {"_id": 0}
    )

    if not flow:
        return "Flow log not found", 404

    # Attach reasoning from alerts collection
    if alert and alert.get("reasoning"):
        flow["reasoning"] = alert["reasoning"]
    else:
        flow["reasoning"] = (
            "No LLM reasoning is available for this alert. "
            "This may be due to the alert being generated before "
            "reasoning was enabled or due to a fallback classification."
        )

    # Also attach alert-level fields if useful
    if alert:
        flow["alert_status"] = alert.get("status")
        flow["alert_created_at"] = alert.get("created_at")

    return render_template("alert_details.html", flow=flow)

# ==================== Run ====================

if __name__ == "__main__":
    app.run(debug=True)
