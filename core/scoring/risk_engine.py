from core.ingestion.database import get_connection
from core.ingestion.kev_fetcher import get_kev_ids
from core.hunting.maturity_classifier import classify_maturity

MATURITY_MAP = {
    "ACTIVE":      1.0,
    "WEAPONIZED":  0.7,
    "POC":         0.4,
    "THEORETICAL": 0.1
}

TIER_MAP = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (0,  "LOW")
]

def get_tier(score):
    for threshold, tier in TIER_MAP:
        if score >= threshold:
            return tier
    return "LOW"

def calculate_score(cve, epss_score, maturity, in_kev, asset_match, weights):
    cvss = cve["cvss_score"] or 0.0
    cvss_component     = (cvss / 10.0) * weights["cvss"]
    epss_component     = epss_score * weights["epss"]
    maturity_component = MATURITY_MAP[maturity] * weights["exploit_maturity"]
    kev_component      = (1.0 if in_kev else 0.0) * weights["kev_bonus"]
    asset_component    = (1.0 if asset_match else 0.0) * weights["asset_exposure"]

    raw = cvss_component + epss_component + maturity_component + kev_component + asset_component
    return round(raw * 100, 2), cvss_component, epss_component, maturity_component, kev_component, asset_component

def score_all_cves(config, db_path, epss_scores, maturity_results, asset_matches):
    weights = config["scoring"]["weights"]
    kev_ids = get_kev_ids(db_path)

    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT cve_id, cvss_score FROM cves")
    cves = [dict(row) for row in cursor.fetchall()]
    conn.close()

    print(f"[Scoring] Scoring {len(cves)} CVEs...")

    conn = get_connection(db_path)
    cursor = conn.cursor()

    tier_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for cve in cves:
        cve_id = cve["cve_id"]

        epss_score    = epss_scores.get(cve_id, 0.0)
        maturity      = maturity_results.get(cve_id, "THEORETICAL")
        in_kev        = cve_id in kev_ids
        asset_match   = cve_id in asset_matches

        score, cvss_c, epss_c, mat_c, kev_c, asset_c = calculate_score(
            cve, epss_score, maturity, in_kev, asset_match, weights
        )

        tier = get_tier(score)
        tier_counts[tier] += 1

        try:
            cursor.execute("""
                INSERT OR REPLACE INTO scores
                (cve_id, risk_score, risk_tier, cvss_component, epss_component,
                 maturity_component, kev_component, asset_component,
                 epss_score, maturity_level, in_kev, asset_match)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (cve_id, score, tier, cvss_c, epss_c, mat_c, kev_c, asset_c,
                  epss_score, maturity, int(in_kev), int(asset_match)))
        except Exception as e:
            print(f"[Scoring] Error saving score for {cve_id}: {e}")

    conn.commit()
    conn.close()

    print(f"[Scoring] Complete — CRITICAL: {tier_counts['CRITICAL']} | "
          f"HIGH: {tier_counts['HIGH']} | "
          f"MEDIUM: {tier_counts['MEDIUM']} | "
          f"LOW: {tier_counts['LOW']}")

    return tier_counts