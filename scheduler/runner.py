import schedule
import time
import os
import sys
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
from rich.console import Console
import yaml

load_dotenv()
console = Console()

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def run_pipeline():
    from core.ingestion.database import init_db
    from core.ingestion.nvd_fetcher import fetch_recent_cves
    from core.ingestion.kev_fetcher import fetch_kev
    from core.hunting.github_hunter import hunt_github
    from core.hunting.exploitdb_hunter import hunt_exploitdb
    from core.hunting.maturity_classifier import classify_all
    from core.scoring.epss_fetcher import fetch_epss_scores
    from core.scoring.risk_engine import score_all_cves
    from core.correlation.asset_correlator import correlate_all
    from core.reporting.executive_report import generate_executive_report
    from core.reporting.engineer_report import generate_engineer_report

    config = load_config()
    db_path = config["database"]["path"]
    start_time = datetime.utcnow()

    console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
    console.print(f"[bold cyan]AVEN Run Started: {start_time.strftime('%Y-%m-%d %H:%M UTC')}[/bold cyan]")
    console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")

    try:
        init_db(db_path)

        console.print("[cyan]Fetching CVEs from NVD...[/cyan]")
        cves_saved = fetch_recent_cves(config, db_path)

        console.print("[cyan]Fetching CISA KEV list...[/cyan]")
        kev_saved = fetch_kev(config, db_path)

        console.print("[cyan]Hunting PoCs on GitHub...[/cyan]")
        github_findings = hunt_github(config, db_path)

        console.print("[cyan]Searching ExploitDB...[/cyan]")
        exploitdb_findings = hunt_exploitdb(config, db_path)

        console.print("[cyan]Classifying exploit maturity...[/cyan]")
        maturity_results = classify_all(db_path)

        console.print("[cyan]Correlating CVEs against assets...[/cyan]")
        asset_matches = correlate_all(db_path)

        console.print("[cyan]Fetching EPSS scores...[/cyan]")
        epss_scores = fetch_epss_scores(db_path)

        console.print("[cyan]Running risk scoring engine...[/cyan]")
        tier_counts = score_all_cves(config, db_path, epss_scores, maturity_results, asset_matches)

        console.print("[cyan]Generating reports...[/cyan]")
        exec_path, _ = generate_executive_report(db_path)
        eng_path, _ = generate_engineer_report(db_path)

        end_time = datetime.utcnow()
        duration = (end_time - start_time).seconds

        log_run(db_path, start_time, end_time, cves_saved, tier_counts)

        console.print(f"\n[bold green]Run Complete in {duration}s[/bold green]")
        console.print(
            f"[bold red]CRITICAL: {tier_counts['CRITICAL']}[/bold red] | "
            f"[red]HIGH: {tier_counts['HIGH']}[/red] | "
            f"[yellow]MEDIUM: {tier_counts['MEDIUM']}[/yellow] | "
            f"[green]LOW: {tier_counts['LOW']}[/green]"
        )
        console.print(f"[cyan]Next run in {load_config()['scheduler']['run_every_hours']} hours[/cyan]\n")

    except Exception as e:
        console.print(f"[bold red]Pipeline error: {e}[/bold red]")
        log_run(db_path, start_time, datetime.utcnow(), 0, {}, error=str(e))

def log_run(db_path, start_time, end_time, cves_ingested, tier_counts, error=None):
    try:
        from core.ingestion.database import get_connection
        conn = get_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO runs
            (started_at, completed_at, cves_ingested, cves_scored, new_criticals, errors)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            start_time.isoformat(),
            end_time.isoformat(),
            cves_ingested,
            sum(tier_counts.values()) if tier_counts else 0,
            tier_counts.get("CRITICAL", 0) if tier_counts else 0,
            error
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        console.print(f"[yellow]Could not log run: {e}[/yellow]")

def start_scheduler():
    config = load_config()
    hours = config["scheduler"]["run_every_hours"]

    console.print("[bold cyan]AVEN — Autonomous Vulnerability & Exploit Notification Engine[/bold cyan]")
    console.print(f"[green]Scheduler started. Running every {hours} hours.[/green]")
    console.print("[green]First run starting now...[/green]\n")

    # Run immediately on startup
    run_pipeline()

    # Then schedule recurring runs
    schedule.every(hours).hours.do(run_pipeline)
    schedule.every().day.at("07:00").do(run_pipeline)

    console.print(f"[green]Scheduler active. Next run in {hours} hours.[/green]")

    while True:
        schedule.run_pending()
        time.sleep(60)

if __name__ == "__main__":
    start_scheduler()