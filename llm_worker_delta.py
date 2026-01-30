#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LLM Worker
- Pulls flows from MongoDB priority queues (HIGH → MEDIUM → LOW)
- Analyzes using Mistral
- Stores FULL flows in flow_logs (no nesting)
- Stores results
- Generates alerts
"""

import json
import time
import subprocess
from datetime import datetime
from pymongo import MongoClient

# ==================== Configuration ====================

MONGO_URI = "mongodb://127.0.0.1:27017/"
DB_NAME = "ids_llm"

HIGH_QUEUE   = "llm_queue_high"
MEDIUM_QUEUE = "llm_queue_medium"
LOW_QUEUE    = "llm_queue_low"

RESULTS_COL   = "llm_results"
ALERTS_COL    = "alerts"
FLOW_LOGS_COL = "flow_logs"

LLM_MODEL = "mistral"
IDLE_SLEEP = 1

# ==================== MongoDB Setup ====================

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

high_q   = db[HIGH_QUEUE]
medium_q = db[MEDIUM_QUEUE]
low_q    = db[LOW_QUEUE]

results_col   = db[RESULTS_COL]
alerts_col    = db[ALERTS_COL]
flow_logs_col = db[FLOW_LOGS_COL]

attack_knowledge = list(
    db["attack_knowledge"].find({}, {"_id": 0})
)

# ==================== Helper Functions ====================

def fetch_flow():
    flow = high_q.find_one_and_delete({})
    if flow:
        return flow, "HIGH"

    flow = medium_q.find_one_and_delete({})
    if flow:
        return flow, "MEDIUM"

    flow = low_q.find_one_and_delete({})
    if flow:
        return flow, "LOW"

    return None, None


def build_prompt(flow):
    flow.pop("_id", None)

    return f"""
You are a network intrusion detection analyst.

Attack knowledge database:
{json.dumps(attack_knowledge, indent=2)}

Observed network flow:
{json.dumps(flow, indent=2)}

Tasks:
1. Decide if the flow is MALICIOUS, BENIGN, SUSPICIOUS, or UNKNOWN
2. If malicious, identify the most likely attack
3. Give a confidence score (0–100)
4. Explain your reasoning

Respond strictly in JSON:
{{
  "classification": "",
  "attack_name": "",
  "confidence": 0,
  "reasoning": ""
}}
"""


def run_llm(prompt):
    result = subprocess.run(
        ["ollama", "run", LLM_MODEL],
        input=prompt,
        text=True,
        capture_output=True
    )
    return result.stdout.strip()


def parse_llm_response(raw):
    try:
        start = raw.find("{")
        end = raw.rfind("}") + 1
        return json.loads(raw[start:end])
    except Exception:
        return {
            "classification": "UNKNOWN",
            "attack_name": "",
            "confidence": 0,
            "reasoning": "Failed to parse LLM output"
        }


# ==================== Worker Loop ====================

print("[*] LLM Worker started (FULL flow logging enabled)")

while True:
    flow, priority = fetch_flow()

    if not flow:
        time.sleep(IDLE_SLEEP)
        continue

    flow_id = flow.get("flow_id")
    print(f"[+] Processing {flow_id} (priority={priority})")

    prompt = build_prompt(flow)
    raw_response = run_llm(prompt)
    analysis = parse_llm_response(raw_response)

    analyzed_at = datetime.utcnow().isoformat()

    # ---------------- Store FULL Flow Log ----------------

    full_flow_log = {
        **flow,                       # ✅ FULL flow AS-IS
        "classification": analysis.get("classification"),
        "attack_name": analysis.get("attack_name"),
        "confidence": analysis.get("confidence"),
        "reasoning": analysis.get("reasoning"),
        "analyzed_at": analyzed_at
    }

    flow_logs_col.insert_one(full_flow_log)

    # ---------------- Store LLM Result ----------------

    results_col.insert_one({
        "flow_id": flow_id,
        "priority": priority,
        "analysis": analysis,
        "llm_response_raw": raw_response,
        "analyzed_at": analyzed_at
    })

    # ---------------- Generate Alert ----------------

    if analysis.get("classification") in ("MALICIOUS", "SUSPICIOUS"):
        alerts_col.insert_one({
            "flow_id": flow_id,
            "classification": analysis.get("classification"),
            "attack_name": analysis.get("attack_name"),
            "confidence": analysis.get("confidence"),
            "priority": priority,
            "reasoning": analysis.get("reasoning"),
            "created_at": analyzed_at,
            "status": "NEW"
        })

        print(f"[🚨 ALERT] {analysis.get('classification')} detected")

    else:
        print(f"[✓] Classified as {analysis.get('classification')}")

    print()
