import os
from datetime import datetime
from core.ingestion.database import get_connection

def generate_executive_report(db_path, output_dir="output"):
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT s.cve_id, s.risk_score, s.risk_tier, s.maturity_level,
               s.in_kev, s.asset_match, s.epss_score,
               c.description, c.cvss_score,
               k.vendor, k.product, k.vulnerability_name, k.ransomware_use
        FROM scores s
        JOIN cves c ON s.cve_id = c.cve_id
        LEFT JOIN kev_entries k ON s.cve_id = k.cve_id
        WHERE s.risk_tier IN ('CRITICAL', 'HIGH', 'MEDIUM')
        ORDER BY s.risk_score DESC
        LIMIT 20
    """)

    results = [dict(row) for row in cursor.fetchall()]

    cursor.execute("""
        SELECT risk_tier, COUNT(*) as count
        FROM scores GROUP BY risk_tier
    """)
    tier_summary = {row["risk_tier"]: row["count"] for row in cursor.fetchall()}
    conn.close()

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    run_date = datetime.utcnow().strftime("%Y-%m-%d_%H%M")

    lines = []
    lines.append("=" * 70)
    lines.append("AVEN — EXECUTIVE VULNERABILITY RISK SUMMARY")
    lines.append(f"Generated: {timestamp}")
    lines.append("=" * 70)
    lines.append("")
    lines.append("OVERVIEW")
    lines.append("-" * 40)
    lines.append(f"Total CVEs analyzed:  {sum(tier_summary.values())}")
    lines.append(f"Critical risk:        {tier_summary.get('CRITICAL', 0)}")
    lines.append(f"High risk:            {tier_summary.get('HIGH', 0)}")
    lines.append(f"Medium risk:          {tier_summary.get('MEDIUM', 0)}")
    lines.append(f"Low risk:             {tier_summary.get('LOW', 0)}")
    lines.append("")

    critical_count = tier_summary.get('CRITICAL', 0)
    high_count = tier_summary.get('HIGH', 0)

    if critical_count > 0:
        lines.append(f"ATTENTION REQUIRED: {critical_count} critical vulnerabilities "
                     f"require immediate remediation.")
    elif high_count > 0:
        lines.append(f"ACTION NEEDED: {high_count} high-severity vulnerabilities "
                     f"identified with known exploit activity.")
    else:
        lines.append("No critical vulnerabilities identified in this reporting period.")

    lines.append("")
    lines.append("TOP VULNERABILITIES REQUIRING ATTENTION")
    lines.append("-" * 40)

    for i, cve in enumerate(results, 1):
        cve_id = cve["cve_id"]
        score = cve["risk_score"]
        tier = cve["risk_tier"]
        maturity = cve["maturity_level"]
        description = cve["description"] or "No description available."
        cvss = cve["cvss_score"] or "N/A"
        in_kev = cve["in_kev"]
        asset_match = cve["asset_match"]
        vendor = cve["vendor"] or ""
        product = cve["product"] or ""
        ransomware = cve["ransomware_use"] or ""

        # Truncate description
        if len(description) > 200:
            description = description[:197] + "..."

        lines.append(f"{i}. {cve_id} — [{tier}] Risk Score: {score}/100")

        if vendor and product:
            lines.append(f"   Affected: {vendor} {product}")

        lines.append(f"   CVSS: {cvss} | Exploit Status: {maturity}")
        lines.append(f"   {description}")

        flags = []
        if in_kev:
            flags.append("Confirmed exploited in the wild (CISA KEV)")
        if asset_match:
            flags.append("Matches assets in your environment")
        if ransomware == "Known":
            flags.append("Associated with ransomware campaigns")

        if flags:
            lines.append(f"   ⚠ {' | '.join(flags)}")

        if maturity == "ACTIVE":
            lines.append("   ACTION: Patch immediately. Active exploitation confirmed.")
        elif maturity == "WEAPONIZED":
            lines.append("   ACTION: Patch within 24-48 hours. Weaponized exploit available.")
        elif maturity == "POC":
            lines.append("   ACTION: Patch within 7 days. Proof-of-concept code is public.")
        else:
            lines.append("   ACTION: Schedule patching in next maintenance window.")

        lines.append("")

    lines.append("=" * 70)
    lines.append("This report was generated automatically by AVEN.")
    lines.append("For technical detection content, see the engineer report.")
    lines.append("=" * 70)

    # Save to file
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, f"{run_date}_executive_summary.txt")
    with open(filepath, "w") as f:
        f.write("\n".join(lines))

    print(f"[Report] Executive summary saved: {filepath}")
    return filepath, "\n".join(lines)