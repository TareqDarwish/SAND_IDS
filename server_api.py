#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Central Server API
- Receives prioritized flows from edge devices
- Stores FULL flows in flow_logs
- Pushes flows into priority queues (HIGH / MEDIUM / LOW)
"""

from fastapi import FastAPI, HTTPException
from pymongo import MongoClient
from datetime import datetime

app = FastAPI(title="IDS Central API")

# -------------------- MongoDB --------------------

client = MongoClient("mongodb://127.0.0.1:27017/")
db = client["ids_llm"]

high_q     = db["llm_queue_high"]
medium_q   = db["llm_queue_medium"]
low_q      = db["llm_queue_low"]
flow_logs  = db["flow_logs"]

# -------------------- API Endpoint --------------------

@app.post("/api/flows")
def receive_flow(flow: dict):
    try:
        priority = flow.get("priority")

        if not priority:
            raise HTTPException(status_code=400, detail="Missing priority field")

        # ---------------- Store FULL flow (AS-IS) ----------------
        flow_logs.insert_one({
            **flow,
            "received_at": datetime.utcnow().isoformat()
        })

        # ---------------- Store in Priority Queue ----------------
        if priority == "HIGH":
            high_q.insert_one(flow)
        elif priority == "MEDIUM":
            medium_q.insert_one(flow)
        else:
            low_q.insert_one(flow)

        return {"status": "ok"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
