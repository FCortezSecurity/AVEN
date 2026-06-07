from core.ingestion.database import get_connection
from core.ingestion.kev_fetcher import get_kev_ids

MATURITY_LEVELS = {
    "ACTIVE": 4,
    "WEAPONIZED": 3,
    "POC": 2,
    "THEORETICAL": 1
}

def classify_maturity(cve_id, db_path, kev_ids):
    # ACTIVE — confirmed in the wild by CISA
    if cve_id in kev_ids:
        return "ACTIVE"

    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT source, stars FROM poc_findings WHERE cve_id = ?
    """, (cve_id,))
    findings = cursor.fetchall()
    conn.close()

    if not findings:
        return "THEORETICAL"

    sources = {f["source"] for f in findings}
    max_stars = max((f["stars"] or 0) for f in findings)

    # WEAPONIZED — multiple sources or high star count
    if len(sources) > 1 or max_stars >= 50:
        return "WEAPONIZED"

    # POC — at least one finding
    return "POC"

def classify_all(db_path):
    kev_ids = get_kev_ids(db_path)

    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT cve_id FROM cves")
    cve_ids = [row["cve_id"] for row in cursor.fetchall()]
    conn.close()

    print(f"[Maturity] Classifying {len(cve_ids)} CVEs...")

    results = {}
    counts = {"ACTIVE": 0, "WEAPONIZED": 0, "POC": 0, "THEORETICAL": 0}

    for cve_id in cve_ids:
        level = classify_maturity(cve_id, db_path, kev_ids)
        results[cve_id] = level
        counts[level] += 1

    print(f"[Maturity] Results — ACTIVE: {counts['ACTIVE']} | "
          f"WEAPONIZED: {counts['WEAPONIZED']} | "
          f"POC: {counts['POC']} | "
          f"THEORETICAL: {counts['THEORETICAL']}")

    return results