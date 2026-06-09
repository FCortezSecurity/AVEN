import os
import json
import uuid
from datetime import datetime
from core.ingestion.database import get_connection

# CWE to MITRE ATT&CK mapping
CWE_TO_ATTACK = {
    "CWE-78":  {"technique": "T1059", "name": "Command and Scripting Interpreter"},
    "CWE-79":  {"technique": "T1189", "name": "Drive-by Compromise"},
    "CWE-89":  {"technique": "T1190", "name": "Exploit Public-Facing Application"},
    "CWE-22":  {"technique": "T1083",  "name": "File and Directory Discovery"},
    "CWE-94":  {"technique": "T1059",  "name": "Command and Scripting Interpreter"},
    "CWE-119": {"technique": "T1203",  "name": "Exploitation for Client Execution"},
    "CWE-120": {"technique": "T1203",  "name": "Exploitation for Client Execution"},
    "CWE-125": {"technique": "T1005",  "name": "Data from Local System"},
    "CWE-190": {"technique": "T1203",  "name": "Exploitation for Client Execution"},
    "CWE-200": {"technique": "T1082",  "name": "System Information Discovery"},
    "CWE-269": {"technique": "T1068",  "name": "Exploitation for Privilege Escalation"},
    "CWE-276": {"technique": "T1083",  "name": "File and Directory Discovery"},
    "CWE-287": {"technique": "T1078",  "name": "Valid Accounts"},
    "CWE-306": {"technique": "T1078",  "name": "Valid Accounts"},
    "CWE-352": {"technique": "T1185",  "name": "Browser Session Hijacking"},
    "CWE-362": {"technique": "T1203",  "name": "Exploitation for Client Execution"},
    "CWE-400": {"technique": "T1499",  "name": "Endpoint Denial of Service"},
    "CWE-416": {"technique": "T1203",  "name": "Exploitation for Client Execution"},
    "CWE-434": {"technique": "T1105",  "name": "Ingress Tool Transfer"},
    "CWE-476": {"technique": "T1499",  "name": "Endpoint Denial of Service"},
    "CWE-502": {"technique": "T1059",  "name": "Command and Scripting Interpreter"},
    "CWE-611": {"technique": "T1005",  "name": "Data from Local System"},
    "CWE-732": {"technique": "T1083",  "name": "File and Directory Discovery"},
    "CWE-798": {"technique": "T1552",  "name": "Unsecured Credentials"},
    "CWE-918": {"technique": "T1090",  "name": "Proxy"},
}

def get_mitre_mapping(cwe):
    if not cwe:
        return {"technique": "T1190", "name": "Exploit Public-Facing Application"}
    return CWE_TO_ATTACK.get(cwe, {"technique": "T1190", "name": "Exploit Public-Facing Application"})

def generate_sigma_rule(cve_id, description, cwe, cvss_score):
    mitre = get_mitre_mapping(cwe)
    rule_id = str(uuid.uuid4())

    short_desc = description[:100] if description else "No description"

    sigma = f"""title: Detection for {cve_id}
id: {rule_id}
status: experimental
description: >
    Detects potential exploitation of {cve_id}.
    {short_desc}
references:
    - https://nvd.nist.gov/vuln/detail/{cve_id}
author: AVEN
date: {datetime.utcnow().strftime("%Y/%m/%d")}
tags:
    - attack.{mitre['technique'].lower().replace('.', '_')}
    - cve.{cve_id.lower().replace('-', '_')}
logsource:
    category: network
    product: zeek
detection:
    keywords:
        - '{cve_id}'
    condition: keywords
fields:
    - src_ip
    - dst_ip
    - uri
    - user_agent
falsepositives:
    - Security scanners
    - Vulnerability assessment tools
level: {'critical' if cvss_score and cvss_score >= 9.0 else 'high' if cvss_score and cvss_score >= 7.0 else 'medium'}
"""
    return sigma

def generate_splunk_query(cve_id):
    return (f'index=* ("{cve_id}" OR "{cve_id.lower()}") '
            f'| eval cve="{cve_id}" '
            f'| stats count by src_ip, dest_ip, uri, _time '
            f'| sort -count')

def generate_wazuh_rule(cve_id, cvss_score):
    level = 15 if cvss_score and cvss_score >= 9.0 else 12 if cvss_score and cvss_score >= 7.0 else 8
    rule_id = abs(hash(cve_id)) % 90000 + 100000

    return f"""<group name="cve,{cve_id.lower()},">
  <rule id="{rule_id}" level="{level}">
    <decoded_as>json</decoded_as>
    <field name="cve_id">{cve_id}</field>
    <description>Potential exploitation of {cve_id} detected</description>
    <info type="cve">{cve_id}</info>
    <mitre>
      <id>{get_mitre_mapping(None)['technique']}</id>
    </mitre>
  </rule>
</group>"""

def generate_engineer_report(db_path, output_dir="output"):
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT s.cve_id, s.risk_score, s.risk_tier, s.maturity_level,
               s.in_kev, s.asset_match, s.epss_score,
               c.description, c.cvss_score, c.cvss_vector, c.cwe,
               k.vendor, k.product
        FROM scores s
        JOIN cves c ON s.cve_id = c.cve_id
        LEFT JOIN kev_entries k ON s.cve_id = k.cve_id
        WHERE s.risk_tier IN ('CRITICAL', 'HIGH', 'MEDIUM')
        ORDER BY s.risk_score DESC
        LIMIT 20
    """)

    results = [dict(row) for row in cursor.fetchall()]
    conn.close()

    run_date = datetime.utcnow().strftime("%Y-%m-%d_%H%M")
    sigma_dir = os.path.join(output_dir, f"{run_date}_sigma_rules")
    os.makedirs(sigma_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_cves": len(results),
        "vulnerabilities": []
    }

    for cve in results:
        cve_id = cve["cve_id"]
        cwe = cve["cwe"]
        cvss = cve["cvss_score"]
        description = cve["description"] or ""
        mitre = get_mitre_mapping(cwe)

        sigma_rule = generate_sigma_rule(cve_id, description, cwe, cvss)
        splunk_query = generate_splunk_query(cve_id)
        wazuh_rule = generate_wazuh_rule(cve_id, cvss)

        # Save individual Sigma rule file
        sigma_path = os.path.join(sigma_dir, f"{cve_id}.yml")
        with open(sigma_path, "w") as f:
            f.write(sigma_rule)

        report["vulnerabilities"].append({
            "cve_id": cve_id,
            "risk_score": cve["risk_score"],
            "risk_tier": cve["risk_tier"],
            "maturity": cve["maturity_level"],
            "cvss_score": cvss,
            "cvss_vector": cve["cvss_vector"],
            "cwe": cwe,
            "epss_score": cve["epss_score"],
            "in_kev": bool(cve["in_kev"]),
            "asset_match": bool(cve["asset_match"]),
            "vendor": cve["vendor"],
            "product": cve["product"],
            "mitre_technique": mitre["technique"],
            "mitre_name": mitre["name"],
            "sigma_rule": sigma_rule,
            "splunk_query": splunk_query,
            "wazuh_rule": wazuh_rule
        })

    # Save full engineer report JSON
    report_path = os.path.join(output_dir, f"{run_date}_engineer_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[Report] Engineer report saved: {report_path}")
    print(f"[Report] Sigma rules saved: {sigma_dir} ({len(results)} rules)")
    return report_path, report