import requests
import json
import time
import os
from datetime import datetime, timedelta

def fetch_recent_cves(config, db_path):
    from core.ingestion.database import get_connection

    api_key = os.getenv("NVD_API_KEY", "")
    base_url = config["nvd"]["base_url"]
    days_back = config["nvd"]["days_back"]

    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days_back)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S"),
        "resultsPerPage": 100,
        "startIndex": 0
    }

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    all_cves = []
    total_results = None

    while True:
        response = requests.get(base_url, params=params, headers=headers)
        
        if response.status_code != 200:
            print(f"[NVD] Error: {response.status_code}")
            break

        data = response.json()

        if total_results is None:
            total_results = data.get("totalResults", 0)
            print(f"[NVD] Total CVEs available: {total_results}")

        vulnerabilities = data.get("vulnerabilities", [])
        all_cves.extend(vulnerabilities)

        print(f"[NVD] Fetched {len(all_cves)} / {total_results}")

        if len(all_cves) >= total_results:
            break

        params["startIndex"] += 100
        time.sleep(1)

    saved = save_cves(all_cves, db_path)
    print(f"[NVD] Saved {saved} CVEs to database")
    return saved

def save_cves(vulnerabilities, db_path):
    from core.ingestion.database import get_connection
    conn = get_connection(db_path)
    cursor = conn.cursor()
    saved = 0

    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d["lang"] == "en"), ""
        )

        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_vector = None

        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score = m.get("baseScore")
            cvss_vector = m.get("vectorString")
        elif "cvssMetricV30" in metrics:
            m = metrics["cvssMetricV30"][0]["cvssData"]
            cvss_score = m.get("baseScore")
            cvss_vector = m.get("vectorString")
        elif "cvssMetricV2" in metrics:
            m = metrics["cvssMetricV2"][0]["cvssData"]
            cvss_score = m.get("baseScore")
            cvss_vector = m.get("vectorString")

        weaknesses = cve.get("weaknesses", [])
        cwe = None
        if weaknesses:
            descs = weaknesses[0].get("description", [])
            if descs:
                cwe = descs[0].get("value", None)

        published = cve.get("published", "")
        modified = cve.get("lastModified", "")

        try:
            cursor.execute("""
                INSERT OR REPLACE INTO cves
                (cve_id, description, cvss_score, cvss_vector, cwe, published_date, modified_date, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (cve_id, description, cvss_score, cvss_vector, cwe,
                  published, modified, json.dumps(cve)))
            saved += 1
        except Exception as e:
            print(f"[NVD] Error saving {cve_id}: {e}")

    conn.commit()
    conn.close()
    return saved