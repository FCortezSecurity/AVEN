import requests
import os
from datetime import datetime
from core.ingestion.database import get_connection

def send_slack_message(webhook_url, message):
    try:
        response = requests.post(webhook_url, json={"text": message}, timeout=10)
        if response.status_code != 200:
            print(f"[Alerts] Slack error: {response.status_code} — {response.text}")
            return False
        return True
    except Exception as e:
        print(f"[Alerts] Failed to send Slack message: {e}")
        return False

def format_cve_alert(cve):
    tier = cve["risk_tier"]
    tier_emoji = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡"}.get(tier, "🟢")
    kev_flag = " | ⚠️ CISA KEV" if cve["in_kev"] else ""
    asset_flag = " | 🎯 Asset Match" if cve["asset_match"] else ""
    vendor = f"{cve['vendor']} {cve['product']}" if cve.get("vendor") else "Unknown"

    return (
        f"{tier_emoji} *{cve['cve_id']}* [{tier}] Score: {cve['risk_score']}/100\n"
        f"> Vendor: {vendor}\n"
        f"> Maturity: {cve['maturity_level']} | CVSS: {cve['cvss_score'] or 'N/A'}{kev_flag}{asset_flag}\n"
        f"> https://nvd.nist.gov/vuln/detail/{cve['cve_id']}"
    )

def check_and_alert(db_path):
    webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
    if not webhook_url:
        print("[Alerts] No Slack webhook configured, skipping alerts")
        return 0

    conn = get_connection(db_path)
    cursor = conn.cursor()

    # Get last run time to find new CVEs
    cursor.execute("""
        SELECT started_at FROM runs
        ORDER BY id DESC LIMIT 1 OFFSET 1
    """)
    last_run = cursor.fetchone()
    last_run_time = last_run["started_at"] if last_run else "2000-01-01"

    # Find CRITICAL and HIGH CVEs scored after last run
    cursor.execute("""
        SELECT s.cve_id, s.risk_score, s.risk_tier, s.maturity_level,
               s.in_kev, s.asset_match, c.cvss_score,
               k.vendor, k.product
        FROM scores s
        JOIN cves c ON s.cve_id = c.cve_id
        LEFT JOIN kev_entries k ON s.cve_id = k.cve_id
        WHERE s.risk_tier IN ('CRITICAL', 'HIGH')
        AND s.scored_at > ?
        ORDER BY s.risk_score DESC
    """, (last_run_time,))

    new_critical = [dict(row) for row in cursor.fetchall()]
    conn.close()

    if not new_critical:
        print("[Alerts] No new CRITICAL/HIGH CVEs to alert on")
        return 0

    print(f"[Alerts] Sending alerts for {len(new_critical)} CRITICAL/HIGH CVEs")

    # Send summary header
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    header = (
        f"*AVEN Alert — {timestamp}*\n"
        f"{len(new_critical)} new high-priority vulnerabilities detected\n"
        f"{'─' * 40}"
    )
    send_slack_message(webhook_url, header)

    # Send individual CVE alerts
    sent = 0
    for cve in new_critical:
        message = format_cve_alert(cve)
        if send_slack_message(webhook_url, message):
            sent += 1

    print(f"[Alerts] Sent {sent} alerts to Slack")
    return sent

def send_pipeline_summary(db_path, tier_counts):
    webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
    if not webhook_url:
        return

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    message = (
        f"*AVEN Pipeline Complete — {timestamp}*\n"
        f"🚨 Critical: {tier_counts.get('CRITICAL', 0)} | "
        f"🔴 High: {tier_counts.get('HIGH', 0)} | "
        f"🟡 Medium: {tier_counts.get('MEDIUM', 0)} | "
        f"🟢 Low: {tier_counts.get('LOW', 0)}"
    )
    send_slack_message(webhook_url, message)