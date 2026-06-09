import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from dotenv import load_dotenv
import yaml
import json

load_dotenv()

app = FastAPI(title="AVEN Dashboard")

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def get_db_path():
    return load_config()["database"]["path"]

@app.get("/")
def root():
    return FileResponse("dashboard/static/index.html")

@app.get("/api/stats")
def get_stats():
    from core.ingestion.database import get_connection
    db_path = get_db_path()
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT risk_tier, COUNT(*) as count FROM scores GROUP BY risk_tier")
    tiers = {row["risk_tier"]: row["count"] for row in cursor.fetchall()}

    cursor.execute("SELECT COUNT(*) as count FROM cves")
    total_cves = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM kev_entries")
    total_kev = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM poc_findings")
    total_pocs = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(DISTINCT cve_id) as count FROM asset_matches")
    asset_matched = cursor.fetchone()["count"]

    cursor.execute("""
        SELECT started_at, completed_at, cves_ingested, new_criticals
        FROM runs ORDER BY id DESC LIMIT 1
    """)
    last_run = dict(cursor.fetchone() or {})
    conn.close()

    return {
        "total_cves": total_cves,
        "total_kev": total_kev,
        "total_pocs": total_pocs,
        "asset_matched": asset_matched,
        "tiers": tiers,
        "last_run": last_run
    }

@app.get("/api/cves")
def get_cves(tier: str = None, limit: int = 100):
    from core.ingestion.database import get_connection
    db_path = get_db_path()
    conn = get_connection(db_path)
    cursor = conn.cursor()

    if tier:
        cursor.execute("""
            SELECT s.cve_id, s.risk_score, s.risk_tier, s.maturity_level,
                   s.in_kev, s.asset_match, s.epss_score,
                   c.description, c.cvss_score, c.cwe,
                   k.vendor, k.product
            FROM scores s
            JOIN cves c ON s.cve_id = c.cve_id
            LEFT JOIN kev_entries k ON s.cve_id = k.cve_id
            WHERE s.risk_tier = ?
            ORDER BY s.risk_score DESC
            LIMIT ?
        """, (tier.upper(), limit))
    else:
        cursor.execute("""
            SELECT s.cve_id, s.risk_score, s.risk_tier, s.maturity_level,
                   s.in_kev, s.asset_match, s.epss_score,
                   c.description, c.cvss_score, c.cwe,
                   k.vendor, k.product
            FROM scores s
            JOIN cves c ON s.cve_id = c.cve_id
            LEFT JOIN kev_entries k ON s.cve_id = k.cve_id
            ORDER BY s.risk_score DESC
            LIMIT ?
        """, (limit,))

    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return results

@app.get("/api/cves/{cve_id}")
def get_cve_detail(cve_id: str):
    from core.ingestion.database import get_connection
    db_path = get_db_path()
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT s.*, c.description, c.cvss_score, c.cvss_vector,
               c.cwe, c.published_date,
               k.vendor, k.product, k.vulnerability_name,
               k.required_action, k.ransomware_use
        FROM scores s
        JOIN cves c ON s.cve_id = c.cve_id
        LEFT JOIN kev_entries k ON s.cve_id = k.cve_id
        WHERE s.cve_id = ?
    """, (cve_id,))
    cve = cursor.fetchone()

    if not cve:
        return JSONResponse(status_code=404, content={"error": "CVE not found"})

    cve_dict = dict(cve)

    cursor.execute("""
        SELECT source, url, title, stars FROM poc_findings WHERE cve_id = ?
    """, (cve_id,))
    cve_dict["poc_findings"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute("""
        SELECT asset_id, asset_hostname, match_reason
        FROM asset_matches WHERE cve_id = ?
    """, (cve_id,))
    cve_dict["asset_matches"] = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return cve_dict

@app.get("/api/runs")
def get_runs():
    from core.ingestion.database import get_connection
    db_path = get_db_path()
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM runs ORDER BY id DESC LIMIT 20
    """)
    runs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return runs

@app.get("/api/assets")
def get_assets():
    from core.ingestion.database import get_connection
    import json as jsonlib
    db_path = get_db_path()

    with open("data/mock_assets.json") as f:
        assets = jsonlib.load(f)

    conn = get_connection(db_path)
    cursor = conn.cursor()

    for asset in assets:
        cursor.execute("""
            SELECT COUNT(DISTINCT am.cve_id) as cve_count
            FROM asset_matches am
            JOIN scores s ON am.cve_id = s.cve_id
            WHERE am.asset_id = ?
        """, (asset["asset_id"],))
        asset["cve_count"] = cursor.fetchone()["cve_count"]

    conn.close()
    return assets

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)