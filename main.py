import yaml
import os
from dotenv import load_dotenv
from rich.console import Console
from core.ingestion.database import init_db
from core.ingestion.nvd_fetcher import fetch_recent_cves
from core.ingestion.kev_fetcher import fetch_kev
from core.hunting.github_hunter import hunt_github
from core.hunting.exploitdb_hunter import hunt_exploitdb
from core.hunting.maturity_classifier import classify_all
from core.scoring.epss_fetcher import fetch_epss_scores
from core.scoring.risk_engine import score_all_cves

load_dotenv()
console = Console()

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def full_pipeline_run(config):
    console.print("[bold green]AVEN Pipeline Starting...[/bold green]")

    db_path = config["database"]["path"]

    console.print("[cyan]Initializing database...[/cyan]")
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

    console.print("[cyan]Fetching EPSS scores...[/cyan]")
    epss_scores = fetch_epss_scores(db_path)

    console.print("[cyan]Running risk scoring engine...[/cyan]")
    # Asset matches will be wired in Phase 5 — empty set for now
    asset_matches = set()
    tier_counts = score_all_cves(config, db_path, epss_scores, maturity_results, asset_matches)

    console.print(f"[bold green]Pipeline Complete.[/bold green]")
    console.print(
        f"CVEs: {cves_saved} | KEV: {kev_saved} | "
        f"GitHub PoCs: {github_findings} | ExploitDB: {exploitdb_findings}"
    )
    console.print(
        f"[bold red]CRITICAL: {tier_counts['CRITICAL']}[/bold red] | "
        f"[red]HIGH: {tier_counts['HIGH']}[/red] | "
        f"[yellow]MEDIUM: {tier_counts['MEDIUM']}[/yellow] | "
        f"[green]LOW: {tier_counts['LOW']}[/green]"
    )

if __name__ == "__main__":
    config = load_config()
    console.print("[bold cyan]AVEN — Autonomous Vulnerability & Exploit Notification Engine[/bold cyan]")
    full_pipeline_run(config)