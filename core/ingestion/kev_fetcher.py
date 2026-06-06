import requests
from core.ingestion.database import get_connection

def fetch_kev(config, db_path):
    url = config["cisa_kev"]["url"]

    response = requests.get(url)
    if response.status_code != 200:
        print(f"[KEV] Error fetching KEV: {response.status_code}")
        return 0

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])
    print(f"[KEV] Found {len(vulnerabilities)} KEV entries")

    saved = save_kev_entries(vulnerabilities, db_path)
    print(f"[KEV] Saved {saved} KEV entries to database")
    return saved

def save_kev_entries(vulnerabilities, db_path):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    saved = 0

    for v in vulnerabilities:
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO kev_entries
                (cve_id, vendor, product, vulnerability_name, date_added,
                 required_action, due_date, ransomware_use, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                v.get("cveID", ""),
                v.get("vendorProject", ""),
                v.get("product", ""),
                v.get("vulnerabilityName", ""),
                v.get("dateAdded", ""),
                v.get("requiredAction", ""),
                v.get("dueDate", ""),
                v.get("knownRansomwareCampaignUse", ""),
                v.get("notes", "")
            ))
            saved += 1
        except Exception as e:
            print(f"[KEV] Error saving {v.get('cveID')}: {e}")

    conn.commit()
    conn.close()
    return saved

def get_kev_ids(db_path):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT cve_id FROM kev_entries")
    ids = {row["cve_id"] for row in cursor.fetchall()}
    conn.close()
    return ids