import re
import logging
from datetime import datetime, timezone

import functions_framework
from google.cloud import storage, firestore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@functions_framework.cloud_event
def parse_config(cloud_event):
    data = cloud_event.data
    bucket_name = data["bucket"]
    file_path = data["name"]

    logger.info(f"Cloud Function triggered: bucket={bucket_name} file={file_path}")

    # Extract session_id from path: sessions/{session_id}/{filename}
    parts = file_path.split("/")
    if len(parts) < 3 or parts[0] != "sessions":
        logger.warning(f"Unexpected file path format: {file_path}")
        return

    session_id = parts[1]

    # Download config file from GCS
    gcs_client = storage.Client()
    bucket = gcs_client.bucket(bucket_name)
    blob = bucket.blob(file_path)
    raw_config = blob.download_as_text()

    # Parse config
    hostname = _extract_hostname(raw_config)
    ios_version = _extract_ios_version(raw_config)
    platform = _extract_platform(raw_config)
    role = _extract_role(raw_config)
    services = _extract_services(raw_config)

    # Write to Firestore
    db = firestore.Client()
    doc_ref = (
        db.collection("sessions")
        .document(session_id)
        .collection("assets")
        .document("device")
    )
    doc_ref.set({
        "hostname": hostname,
        "platform": platform,
        "ios_version": ios_version,
        "role": role,
        "services": services,
        "raw_config": raw_config,
        "timestamp": datetime.now(timezone.utc),
    })

    logger.info(f"Firestore written: sessions/{session_id}/assets/device — hostname={hostname}")

def _extract_hostname(config: str) -> str:
    m = re.search(r"^hostname\s+(\S+)", config, re.MULTILINE)
    return m.group(1) if m else "Unknown"

def _extract_ios_version(config: str) -> str:
    # Look for comment header first: "! IOS XE Version X"
    m = re.search(r"!\s*IOS\s+XE\s+Version\s+([\d.]+)", config, re.IGNORECASE)
    if m:
        return f"IOS XE {m.group(1)}"
    # Fall back to "version X.X" line
    m = re.search(r"^version\s+([\d.]+)", config, re.MULTILINE)
    if m:
        return f"IOS XE {m.group(1)}"
    return "Unknown"

def _extract_platform(config: str) -> str:
    # Look for model in header comment: "! EDGE-RTR-01 — Cisco ISR 4431"
    m = re.search(r"!\s*\S+\s*[—\-]+\s*(Cisco\s+\S+\s+\S+)", config)
    if m:
        return m.group(1).strip()
    if re.search(r"IOS\s*XE", config, re.IGNORECASE):
        return "Cisco IOS XE"
    if re.search(r"IOS", config, re.IGNORECASE):
        return "Cisco IOS"
    return "Cisco Router"

def _extract_role(config: str) -> str:
    m = re.search(r"!\s*Role:\s*(.+)", config)
    if m:
        return m.group(1).strip()
    return "Unknown"

def _extract_services(config: str) -> list:
    services = []
    checks = [
        (r"snmp-server", "SNMP"),
        (r"ip\s+http\s+server", "HTTP Web UI"),
        (r"ip\s+smart-install\s+enable|vstack", "Smart Install"),
        (r"ip\s+ssh", "SSH"),
        (r"router\s+isis", "IS-IS"),
        (r"transport\s+input\s+telnet", "Telnet"),
    ]
    for pattern, label in checks:
        if re.search(pattern, config, re.MULTILINE | re.IGNORECASE):
            services.append(label)
    return services
