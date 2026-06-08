import requests
import time
from core.ingestion.database import get_connection

EPSS_API = "https://api.first.org/data/v1/epss"

def fetch_epss_scores(db_path):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT cve_id FROM cves")
    cve_ids = [row["cve_id"] for row in cursor.fetchall()]
    conn.close()

    print(f"[EPSS] Fetching scores for {len(cve_ids)} CVEs...")

    scores = {}
    batch_size = 100

    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i + batch_size]
        cve_param = ",".join(batch)

        try:
            response = requests.get(EPSS_API, params={"cve": cve_param}, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for item in data.get("data", []):
                    scores[item["cve"]] = float(item.get("epss", 0.0))
            else:
                print(f"[EPSS] Error: {response.status_code}")
        except Exception as e:
            print(f"[EPSS] Request error: {e}")

        print(f"[EPSS] Fetched {min(i + batch_size, len(cve_ids))} / {len(cve_ids)}")
        time.sleep(1)

    print(f"[EPSS] Got scores for {len(scores)} CVEs")
    return scores