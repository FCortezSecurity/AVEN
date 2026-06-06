import yaml
import os
from dotenv import load_dotenv
from rich.console import Console
from core.ingestion.database import init_db
from core.ingestion.nvd_fetcher import fetch_recent_cves
from core.ingestion.kev_fetcher import fetch_kev

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

    console.print(f"[bold green]Pipeline Complete. CVEs: {cves_saved} | KEV entries: {kev_saved}[/bold green]")

if __name__ == "__main__":
    config = load_config()
    console.print("[bold cyan]AVEN — Autonomous Vulnerability & Exploit Notification Engine[/bold cyan]")
    full_pipeline_run(config)