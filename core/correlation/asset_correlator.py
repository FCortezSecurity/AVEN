import json
import re
from core.ingestion.database import get_connection

def load_assets(asset_path="data/mock_assets.json"):
    with open(asset_path, "r") as f:
        return json.load(f)

def extract_keywords(text):
    text = text.lower()
    # Extract meaningful tokens, strip version numbers for broader matching
    tokens = re.findall(r'[a-zA-Z][a-zA-Z0-9]+', text)
    return set(tokens)

def build_asset_keywords(assets):
    asset_keywords = {}
    for asset in assets:
        keywords = set()

        # OS keywords
        keywords.update(extract_keywords(asset["os"]))

        # Software keywords
        for sw in asset["software"]:
            keywords.update(extract_keywords(sw))

        # Add raw software names (first word before version)
        for sw in asset["software"]:
            product = sw.split()[0].lower()
            keywords.add(product)

        asset_keywords[asset["asset_id"]] = {
            "keywords": keywords,
            "hostname": asset["hostname"],
            "criticality": asset["criticality"],
            "environment": asset["environment"]
        }

    return asset_keywords

def correlate_cve_to_assets(cve_id, description, asset_keywords):
    matches = []
    desc_keywords = extract_keywords(description)

    # High value security-relevant terms to match on
    security_terms = {
        "nginx", "apache", "openssl", "php", "python", "node", "java",
        "tomcat", "mssql", "postgresql", "mysql", "windows", "linux",
        "ubuntu", "redhat", "fortios", "fortigate", "chrome", "firefox",
        "office", "powershell", "dotnet", "curl", "git", "log4j",
        "openvpn", "strongswan", "grafana", "prometheus", "npm"
    }

    relevant_desc_keywords = desc_keywords & security_terms

    if not relevant_desc_keywords:
        return matches

    for asset_id, asset_data in asset_keywords.items():
        overlap = relevant_desc_keywords & asset_data["keywords"]
        if overlap:
            matches.append({
                "asset_id": asset_id,
                "hostname": asset_data["hostname"],
                "match_reason": f"Matched keywords: {', '.join(sorted(overlap))}",
                "criticality": asset_data["criticality"],
                "environment": asset_data["environment"]
            })

    return matches

def correlate_all(db_path, asset_path="data/mock_assets.json"):
    assets = load_assets(asset_path)
    asset_keywords = build_asset_keywords(assets)

    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT cve_id, description FROM cves")
    cves = [dict(row) for row in cursor.fetchall()]
    conn.close()

    print(f"[Correlation] Correlating {len(cves)} CVEs against {len(assets)} assets...")

    matched_cve_ids = set()
    total_matches = 0

    conn = get_connection(db_path)
    cursor = conn.cursor()

    # Clear previous matches
    cursor.execute("DELETE FROM asset_matches")

    for cve in cves:
        cve_id = cve["cve_id"]
        description = cve["description"] or ""

        matches = correlate_cve_to_assets(cve_id, description, asset_keywords)

        for match in matches:
            try:
                cursor.execute("""
                    INSERT INTO asset_matches
                    (cve_id, asset_id, asset_hostname, match_reason)
                    VALUES (?, ?, ?, ?)
                """, (cve_id, match["asset_id"], match["hostname"], match["match_reason"]))
                total_matches += 1
            except Exception as e:
                print(f"[Correlation] Error saving match: {e}")

        if matches:
            matched_cve_ids.add(cve_id)

    conn.commit()
    conn.close()

    print(f"[Correlation] Complete — {len(matched_cve_ids)} CVEs matched "
          f"across {total_matches} asset relationships")

    return matched_cve_ids