import requests
import time
import os
from core.ingestion.database import get_connection

def search_github_for_cve(cve_id, token):
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    results = []

    # Search repositories
    repo_url = "https://api.github.com/search/repositories"
    params = {"q": cve_id, "sort": "stars", "order": "desc", "per_page": 10}

    try:
        response = requests.get(repo_url, headers=headers, params=params)
        if response.status_code == 200:
            items = response.json().get("items", [])
            for item in items:
                results.append({
                    "source": "github_repo",
                    "url": item.get("html_url", ""),
                    "title": item.get("full_name", ""),
                    "stars": item.get("stargazers_count", 0),
                    "description": item.get("description", "") or "",
                    "updated_at": item.get("updated_at", "")
                })
        elif response.status_code == 403:
            print(f"[GitHub] Rate limit hit, sleeping 60s...")
            time.sleep(60)
    except Exception as e:
        print(f"[GitHub] Error searching {cve_id}: {e}")

    time.sleep(2)
    return results

def is_likely_poc(result):
    title = result.get("title", "").lower()
    desc = result.get("description", "").lower()
    stars = result.get("stars", 0)

    poc_keywords = ["exploit", "poc", "proof-of-concept", "rce", "lpe",
                    "vulnerability", "cve", "payload", "bypass"]

    keyword_hit = any(k in title or k in desc for k in poc_keywords)
    high_stars = stars > 10

    return keyword_hit or high_stars

def hunt_github(config, db_path):
    token = os.getenv("GITHUB_TOKEN", "")
    if not token:
        print("[GitHub] No token found, skipping GitHub hunt")
        return 0

    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT cve_id FROM cves")
    cve_ids = [row["cve_id"] for row in cursor.fetchall()]
    conn.close()

    print(f"[GitHub] Hunting PoCs for {len(cve_ids)} CVEs...")
    total_found = 0

    for i, cve_id in enumerate(cve_ids):
        results = search_github_for_cve(cve_id, token)

        poc_results = [r for r in results if is_likely_poc(r)]

        if poc_results:
            save_poc_findings(cve_id, poc_results, db_path)
            total_found += len(poc_results)
            print(f"[GitHub] {cve_id} — {len(poc_results)} PoC(s) found")

        if (i + 1) % 10 == 0:
            print(f"[GitHub] Progress: {i+1}/{len(cve_ids)}")

    print(f"[GitHub] Hunt complete. Total PoCs found: {total_found}")
    return total_found

def save_poc_findings(cve_id, results, db_path):
    conn = get_connection(db_path)
    cursor = conn.cursor()

    for r in results:
        try:
            cursor.execute("""
                INSERT INTO poc_findings (cve_id, source, url, title, stars)
                VALUES (?, ?, ?, ?, ?)
            """, (cve_id, r["source"], r["url"], r["title"], r["stars"]))
        except Exception as e:
            print(f"[GitHub] Error saving PoC for {cve_id}: {e}")

    conn.commit()
    conn.close()