# ExposureIQ — CVE Impact Analyzer

**Know your exposure. Before it knows you.**

## What it does

ExposureIQ is a cloud-hosted cybersecurity decision-support tool that analyzes Cisco router configuration files against published CVEs to determine whether a specific network device is exposed. Upload a Cisco IOS/IOS XE config file, enter a CVE ID, and get an AI-powered verdict — including the specific vulnerable configuration line, CVSS score, EPSS probability, CISA KEV status, and exact CLI remediation commands — all in seconds.

## Architecture

**GCP Services**
- Cloud Run — hosts the Flask web application (UI + backend API)
- Cloud Storage — stores uploaded Cisco config files (`exposureiq-configs` bucket)
- Cloud Functions (Gen 2) — GCS-triggered parser that writes structured device data to Firestore
- Cloud Firestore — stores parsed device assets and CVE assessment session history
- Secret Manager — stores the Gemini API key securely
- Artifact Registry — stores the Docker container image

**External APIs (free, no key required)**
- NVD API (NIST) — CVE descriptions and CVSS scores
- CISA KEV Catalog — known exploited vulnerabilities list
- EPSS API (FIRST) — exploit prediction scoring

**AI**
- Google Gemini 1.5 Pro via `google-generativeai` SDK

## Local development

```bash
pip install -r requirements.txt
cp .env.example .env   # fill in your values
python main.py
```

Set the environment variables in `.env`:
- `GCP_PROJECT` — your GCP project ID
- `GCS_BUCKET` — your GCS bucket name (default: `exposureiq-configs`)
- `GEMINI_API_KEY` — your Gemini API key
- `FLASK_SECRET_KEY` — any random string for Flask session signing

## Deployment

**Step 1 — Deploy Cloud Function**
```bash
gcloud functions deploy parse-router-config \
  --gen2 \
  --runtime=python311 \
  --region=us-central1 \
  --source=./cloud_function \
  --entry-point=parse_config \
  --trigger-event-filters="type=google.cloud.storage.object.v1.finalized" \
  --trigger-event-filters="bucket=exposureiq-configs" \
  --set-env-vars GCP_PROJECT=YOUR_PROJECT_ID
```

**Step 2 — Build and push Docker image**
```bash
docker build -t exposureiq .
docker tag exposureiq us-central1-docker.pkg.dev/YOUR_PROJECT_ID/exposureiq/app:latest
docker push us-central1-docker.pkg.dev/YOUR_PROJECT_ID/exposureiq/app:latest
```

**Step 3 — Deploy to Cloud Run**
```bash
gcloud run deploy exposureiq \
  --image=us-central1-docker.pkg.dev/YOUR_PROJECT_ID/exposureiq/app:latest \
  --platform=managed \
  --region=us-central1 \
  --allow-unauthenticated \
  --set-secrets=GEMINI_API_KEY=gemini-api-key:latest \
  --set-env-vars GCS_BUCKET=exposureiq-configs,GCP_PROJECT=YOUR_PROJECT_ID
```

## Demo

1. Upload `EDGE-RTR-01_config.txt` from the repo root using the Section 01 upload panel.
2. Enter `CVE-2023-20198` in the CVE Analysis section and click **ANALYZE →**.
3. Gemini will return an **AFFECTED** verdict with the vulnerable config line and remediation commands.

**Demo CVE IDs to try:**

| CVE ID | Expected Verdict | CVSS |
|---|---|---|
| CVE-2023-20198 | AFFECTED | 10.0 |
| CVE-2018-0171 | AFFECTED | 9.8 |
| CVE-2025-20352 | AFFECTED | 7.7 |
| CVE-2024-20312 | NOT AFFECTED | 7.5 |
| CVE-2025-20138 | NOT AFFECTED | 8.8 |
