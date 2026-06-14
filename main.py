import os
import re
import uuid
import json
import time
import logging
from datetime import datetime, timedelta, timezone

import requests
from flask import Flask, render_template, request, jsonify, make_response
from google.cloud import storage, firestore
import vertexai
from vertexai.generative_models import GenerativeModel, GenerationConfig

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

GCP_PROJECT = os.environ.get("GCP_PROJECT", "")
GCS_BUCKET = os.environ.get("GCS_BUCKET", "exposureiq-configs")

vertexai.init(project=GCP_PROJECT, location="us-central1")

_kev_cache = None

def get_firestore_client():
    return firestore.Client(project=GCP_PROJECT)

def get_storage_client():
    return storage.Client(project=GCP_PROJECT)

def get_kev_catalog():
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache
    try:
        resp = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=10
        )
        resp.raise_for_status()
        _kev_cache = resp.json().get("vulnerabilities", [])
    except Exception as e:
        logger.error(f"Failed to fetch KEV catalog: {e}")
        _kev_cache = []
    return _kev_cache

@app.route("/", methods=["GET"])
def index():
    resp = make_response(render_template("index.html"))
    session_id = request.cookies.get("session_id")
    if not session_id:
        session_id = str(uuid.uuid4())
        expires = datetime.now(timezone.utc) + timedelta(hours=24)
        resp.set_cookie("session_id", session_id, expires=expires, httponly=True)
    return resp

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

@app.route("/upload", methods=["POST"])
def upload():
    session_id = request.cookies.get("session_id")
    if not session_id:
        session_id = str(uuid.uuid4())

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    filename = f.filename
    gcs_path = f"sessions/{session_id}/{filename}"
    config_bytes = f.read()

    try:
        gcs_client = get_storage_client()
        bucket = gcs_client.bucket(GCS_BUCKET)
        blob = bucket.blob(gcs_path)
        blob.upload_from_string(config_bytes, content_type="text/plain")
        logger.info(f"Uploaded {gcs_path} to GCS")
    except Exception as e:
        logger.error(f"GCS upload failed: {e}")
        return jsonify({"error": f"GCS upload failed: {str(e)}"}), 500

    db = get_firestore_client()
    device_doc = db.collection("sessions").document(session_id).collection("assets").document("device")

    deadline = time.time() + 10
    device_data = None
    while time.time() < deadline:
        snap = device_doc.get()
        if snap.exists:
            device_data = snap.to_dict()
            break
        time.sleep(0.5)

    if device_data is None:
        return jsonify({"error": "Cloud Function did not respond in time"}), 504

    return jsonify({
        "hostname": device_data.get("hostname", "Unknown"),
        "platform": device_data.get("platform", "Unknown"),
        "ios_version": device_data.get("ios_version", "Unknown"),
        "role": device_data.get("role", "Unknown"),
        "services": device_data.get("services", []),
        "gcs_path": gcs_path,
        "firestore_status": "written",
        "cloud_function_status": "complete",
    }), 200

@app.route("/analyze", methods=["POST"])
def analyze():
    session_id = request.cookies.get("session_id")
    if not session_id:
        return jsonify({"error": "No session"}), 400

    body = request.get_json(silent=True) or {}
    cve_id = body.get("cve_id", "").strip().upper()

    if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id):
        return jsonify({"error": "Invalid CVE ID format"}), 400

    # Step 2 — Fetch NVD data
    nvd_description = "No description available"
    cvss_score = 0.0
    cvss_severity = "Unknown"
    nvd_affected_products = "Not specified"
    try:
        nvd_resp = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
            timeout=10
        )
        logger.info(f"NVD response for {cve_id}: HTTP {nvd_resp.status_code}")
        nvd_resp.raise_for_status()
        nvd_data = nvd_resp.json()
        logger.info(f"NVD data for {cve_id}: {json.dumps(nvd_data)[:800]}")
        vulns = nvd_data.get("vulnerabilities", [])
        if vulns:
            cve_item = vulns[0].get("cve", {})
            descs = cve_item.get("descriptions", [])
            for d in descs:
                if d.get("lang") == "en":
                    nvd_description = d.get("value", nvd_description)
                    break
            metrics = cve_item.get("metrics", {})
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    m = metrics[key][0].get("cvssData", {})
                    cvss_score = m.get("baseScore", 0.0)
                    cvss_severity = m.get("baseSeverity", "Unknown")
                    break
            configs = cve_item.get("configurations", [])
            products = []
            for config in configs:
                for node in config.get("nodes", []):
                    for cpe in node.get("cpeMatch", []):
                        products.append(cpe.get("criteria", ""))
            nvd_affected_products = "; ".join(products[:5]) if products else "Not specified"
    except Exception as e:
        logger.warning(f"NVD fetch failed for {cve_id}: {e}")

    # Step 3 — Check CISA KEV
    kev_listed = False
    kev_reason = ""
    try:
        kev_list = get_kev_catalog()
        for entry in kev_list:
            if entry.get("cveID", "").upper() == cve_id:
                kev_listed = True
                kev_reason = entry.get("shortDescription", "")
                break
    except Exception as e:
        logger.warning(f"KEV check failed: {e}")

    # Step 4 — Fetch EPSS
    epss_score = None
    epss_percentile = None
    try:
        epss_resp = requests.get(
            f"https://api.first.org/data/1.0/epss?cve={cve_id}",
            timeout=10
        )
        logger.info(f"EPSS response for {cve_id}: HTTP {epss_resp.status_code}")
        if epss_resp.status_code == 404:
            logger.warning(f"EPSS API returned 404 for {cve_id} — endpoint may require authentication")
        else:
            epss_resp.raise_for_status()
            epss_data = epss_resp.json().get("data", [])
            if epss_data:
                epss_score = float(epss_data[0].get("epss", 0.0))
                epss_percentile = float(epss_data[0].get("percentile", 0.0))
    except Exception as e:
        logger.warning(f"EPSS fetch failed for {cve_id}: {e}")

    # Step 5 — Read Firestore device record
    db = get_firestore_client()
    device_doc = db.collection("sessions").document(session_id).collection("assets").document("device")
    device_snap = device_doc.get()
    if not device_snap.exists:
        return jsonify({"error": "No device config found. Please upload a config first."}), 400

    device_data = device_snap.to_dict()
    hostname = device_data.get("hostname", "Unknown")
    platform = device_data.get("platform", "Unknown")
    ios_version = device_data.get("ios_version", "Unknown")
    role = device_data.get("role", "Unknown")
    services = device_data.get("services", [])
    full_config_text = device_data.get("raw_config", "")

    # Step 6 — Build Gemini prompt
    kev_field = f"YES — {kev_reason}" if kev_listed else "NO"
    epss_field = f"{epss_score:.4f} ({epss_percentile:.4f} percentile)" if epss_score is not None else "N/A"
    prompt = f"""You are a cybersecurity analyst. Analyze the following CVE against the provided Cisco router configuration.

CVE ID: {cve_id}
Description: {nvd_description}
CVSS Score: {cvss_score} ({cvss_severity})
Affected Products: {nvd_affected_products}
CISA KEV Listed: {kev_field}
EPSS Score: {epss_field}

DEVICE CONFIGURATION:
{full_config_text}

TASK: Determine if the configuration above exposes this device to the CVE described. Identify any specific configuration lines that match the vulnerability's attack vector.

Respond ONLY with valid JSON in this exact format:
{{
  "overall_verdict": "AFFECTED" or "NOT AFFECTED",
  "vulnerable_config_line": "exact line from config or null",
  "reason": "plain English explanation (2-3 sentences max)",
  "remediation": "exact CLI command(s) to run on the device",
  "patch_type": "config_change" or "ios_upgrade" or "none"
}}"""

    # Step 7 — Call Gemini
    gemini_result = {}
    try:
        model = GenerativeModel("gemini-2.5-flash")
        response = model.generate_content(
            prompt,
            generation_config=GenerationConfig(max_output_tokens=4096)
        )
        raw_text = response.text.strip()
        logger.info(f"Gemini raw response (analyze): {raw_text!r}")
        fence = re.search(r"```(?:json)?\s*\n([\s\S]*?)\n\s*```", raw_text)
        if fence:
            raw_text = fence.group(1).strip()
        else:
            raw_text = re.sub(r"^```(?:json)?\s*\n?", "", raw_text)
            raw_text = re.sub(r"\n?```\s*$", "", raw_text).strip()
            # Final fallback: extract the first {...} JSON object from the text
            json_match = re.search(r'\{[\s\S]*\}', raw_text)
            if json_match:
                raw_text = json_match.group(0)
        gemini_result = json.loads(raw_text)
    except Exception as e:
        logger.exception(f"Gemini call failed for {cve_id}: {e}")
        gemini_result = {
            "overall_verdict": "ERROR",
            "vulnerable_config_line": None,
            "reason": f"Gemini analysis failed: {str(e)}",
            "remediation": None,
            "patch_type": "none"
        }

    # Step 9 — Save to Firestore
    result = {
        "cve_id": cve_id,
        "timestamp": datetime.now(timezone.utc),
        "cvss": cvss_score,
        "severity": cvss_severity,
        "epss": epss_score,
        "kev": kev_listed,
        "overall_verdict": gemini_result.get("overall_verdict", "ERROR"),
        "vulnerable_config_line": gemini_result.get("vulnerable_config_line"),
        "reason": gemini_result.get("reason", ""),
        "remediation": gemini_result.get("remediation"),
        "patch_type": gemini_result.get("patch_type", "none"),
        "nvd_description": nvd_description,
        "epss_percentile": epss_percentile,
    }

    try:
        db.collection("sessions").document(session_id).collection("cve_history").document(cve_id).set(result)
    except Exception as e:
        logger.warning(f"Firestore save failed: {e}")

    # Step 10 — Return
    return jsonify(result), 200

@app.route("/query", methods=["POST"])
def query():
    session_id = request.cookies.get("session_id")
    if not session_id:
        return jsonify({"error": "No session"}), 400

    body = request.get_json(silent=True) or {}
    question = body.get("question", "").strip()
    if not question:
        return jsonify({"error": "No question provided"}), 400

    db = get_firestore_client()

    device_snap = db.collection("sessions").document(session_id).collection("assets").document("device").get()
    device_data = device_snap.to_dict() if device_snap.exists else {}
    hostname = device_data.get("hostname", "Unknown")
    platform = device_data.get("platform", "Unknown")
    ios_version = device_data.get("ios_version", "Unknown")

    history_docs = db.collection("sessions").document(session_id).collection("cve_history").stream()
    history_lines = []
    for doc in history_docs:
        h = doc.to_dict()
        history_lines.append(
            f"CVE: {h.get('cve_id')} | CVSS: {h.get('cvss')} | EPSS: {h.get('epss')} | KEV: {h.get('kev')}\n"
            f"Verdict: {h.get('overall_verdict')}\n"
            f"Vulnerable line: {h.get('vulnerable_config_line')}\n"
            f"Remediation: {h.get('remediation')}"
        )

    history_text = "\n\n".join(history_lines) if history_lines else "No CVE assessments yet."

    prompt = f"""You are a cybersecurity analyst assistant.

DEVICE: {hostname} — {platform} — {ios_version}

CVE ASSESSMENT HISTORY:
{history_text}

USER QUESTION: {question}

Respond in plain language. For remediation plans, rank by:
1. KEV status (actively exploited = highest priority)
2. EPSS score (higher = more urgent)
3. CVSS score (higher = more severe)

Provide exact Cisco CLI commands where relevant."""

    try:
        model = GenerativeModel("gemini-2.5-flash")
        response = model.generate_content(prompt)
        answer = response.text.strip()
        logger.info(f"Gemini raw response (query): {answer!r}")
    except Exception as e:
        logger.error(f"Gemini query failed: {e}")
        answer = f"Query failed: {str(e)}"

    return jsonify({"answer": answer}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
