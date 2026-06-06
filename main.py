import yaml
from dotenv import load_dotenv
from rich.console import Console

load_dotenv()
console = Console()

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def full_pipeline_run():
    console.print("[bold green]AVEN Pipeline Starting...[/bold green]")
    # Phases will be wired in here as you build them
    console.print("[bold green]AVEN Pipeline Complete.[/bold green]")

if __name__ == "__main__":
    config = load_config()
    console.print("[bold cyan]AVEN — Autonomous Vulnerability & Exploit Notification Engine[/bold cyan]")
    full_pipeline_run()