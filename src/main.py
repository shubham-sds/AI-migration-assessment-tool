# src/main.py

# --- FIX FOR ModuleNotFoundError ---
import sys
import os
from pathlib import Path

# Add the project root directory (the parent of 'src') to the Python path
project_root = Path(__file__).resolve().parents[1]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
# --- END OF FIX ---

import logging
import typer
import yaml
import urllib3
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.logging.logger import setup_logging
from src.agents.agent_data_ingestion import DataIngestionAgent
from src.agents.agent_profiling import ProfilingAgent
from src.agents.status_manager import StatusManager
from src.db.db_manager import DBManager
from src.db.neo4j_manager import Neo4jManager
from src.utils.db_exporter import DBExporter

# Suppress common warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("winrm").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)
console = Console()

app = typer.Typer(
    name="ai-migration-assessment-tool",
    help="An AI-Powered Migration Assessment Tool.",
    no_args_is_help=True,
    rich_markup_mode="rich"
)

def _load_knowledge_base() -> dict:
    """Loads the knowledge base YAML file."""
    try:
        with open("knowledge_base.yaml", 'r') as f:
            return yaml.safe_load(f)
    except (FileNotFoundError, yaml.YAMLError):
        logger.exception("Could not load or parse knowledge_base.yaml")
        return {}

@app.command()
def ingest(
    inventory_file: str = typer.Option("inventory.csv", "--inventory", "-i", help="Path to the inventory CSV file."),
    max_workers: int = typer.Option(20, "--workers", "-w", help="Number of concurrent workers for discovery."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Run discovery without persisting data to the database."),
    db_path: str = typer.Option("data/assessment_history.db", "--db-path", help="Path to the SQLite database file."),
    resume: bool = typer.Option(False, "--resume", "-r", help="Flag to resume all pending and failed hosts.")
):
    """
    Run the data ingestion phase to collect data from hosts.
    """
    setup_logging()
    console.print(Panel(
        "[bold green]🤖 AI-Powered Migration Assessment Tool[/bold green]\n\nStarting the Ingestion Phase...",
        expand=False
    ))

    try:
        db_manager = DBManager(db_path)
        status_manager = StatusManager()
        
        is_resume_mode = resume
        
        if not resume:
            incomplete_hosts = status_manager.get_incomplete_hosts()
            if not incomplete_hosts.empty:
                table = Table(title="[bold yellow]Incomplete Hosts Found[/bold yellow]", show_header=True, header_style="bold magenta")
                table.add_column("Run ID", style="cyan", justify="right")
                table.add_column("IP Address", style="green")
                table.add_column("Status", style="yellow")
                
                for _, host in incomplete_hosts.iterrows():
                    table.add_row(str(host['run_id']), host['ip'], host['status'])
                
                console.print(table)
                
                action = typer.prompt("\nResume all incomplete hosts or start a new run with the inventory file? (resume/new)", default="new")
                if action.lower() == 'resume':
                    is_resume_mode = True
        
        agent = DataIngestionAgent(
            inventory_path=inventory_file,
            db_manager=db_manager,
            status_manager=status_manager,
            max_workers=max_workers
        )
        
        agent.run_discovery(dry_run=dry_run, resume=is_resume_mode)
        console.print("\n[bold green]✅ Ingestion phase complete.[/bold green]")

    except Exception:
        logger.exception("A fatal error occurred in the ingestion pipeline. Aborting.")
        console.print("\n[bold red]❌ A fatal error occurred. Please check the log file `data/assessment.log` for details.[/bold red]")

@app.command()
def profile(
    db_path: str = typer.Option("data/assessment_history.db", "--db-path", help="Path to the SQLite database file."),
    export_to_neo4j: bool = typer.Option(False, "--export-neo4j", help="Export the final graph to Neo4j."),
):
    """
    Analyze the collected data, build a Digital Twin, and identify application clusters.
    """
    setup_logging()
    console.print(Panel(
        "[bold blue]🔎 Starting Analysis & Profiling Phase[/bold blue]",
        expand=False
    ))
    try:
        db_manager = DBManager(db_path)
        profiling_agent = ProfilingAgent(db_manager)
        console.log("Building initial graph from discovered data...")
        profiling_agent.build_initial_graph()
        console.log(
            f"Initial graph built with {profiling_agent.graph.number_of_nodes()} "
            f"nodes and {profiling_agent.graph.number_of_edges()} edges."
        )
        console.log("Correlating and enriching graph to create Digital Twin...")
        profiling_agent.enrich_and_correlate()
        console.log("Digital Twin enrichment complete.")
        console.log("Finding application clusters from enriched graph...")
        profiling_agent.find_and_report_clusters()

        if export_to_neo4j:
            console.rule("[bold blue]Exporting to Neo4j[/bold blue]")
            knowledge_base = _load_knowledge_base()
            neo4j_config = knowledge_base.get('neo4j')
            if not neo4j_config:
                console.print("[bold red]Error: 'neo4j' configuration not found in knowledge_base.yaml.[/bold red]")
                logger.error("'neo4j' configuration not found in knowledge_base.yaml")
            else:
                try:
                    neo4j_manager = Neo4jManager(
                        uri=neo4j_config.get('uri'),
                        user=neo4j_config.get('user'),
                        password=neo4j_config.get('password')
                    )
                    neo4j_manager.export_graph(db_manager)
                    neo4j_manager.close()
                    console.print("[green]Successfully exported graph to Neo4j.[/green]")
                except Exception:
                    logger.exception("Failed to export graph to Neo4j.")
                    console.print("[bold red]Failed to export to Neo4j. Check `data/assessment.log` for details.[/bold red]")

        console.print("\n[bold green]✅ Analysis & Profiling phase complete.[/bold green]")
    except Exception:
        logger.exception("A fatal error occurred in the profiling pipeline. Aborting.")
        console.print("\n[bold red]❌ A fatal error occurred. Please check the log file `data/assessment.log` for details.[/bold red]")

@app.command()
def export(
    db_path: str = typer.Option("data/assessment_history.db", "--db-path", help="Path to the SQLite database file."),
    output_file: str = typer.Option("data/assessment_export.json", "--output", "-o", help="Path for the output JSON file.")
):
    """
    Export the entire assessment database to a single JSON file.
    """
    setup_logging()
    console.print(Panel(
        f"[bold blue]📦 Exporting Database to JSON[/bold blue]\n\nSource: {db_path}\nTarget: {output_file}",
        expand=False
    ))

    try:
        db_manager = DBManager(db_path)
        exporter = DBExporter(db_manager)
        
        success = exporter.export_to_json(output_file)

        if success:
            console.print(f"\n[bold green]✅ Database successfully exported to '{output_file}'.[/bold green]")
        else:
            console.print("\n[bold red]❌ Export failed. Please check the log file `data/assessment.log` for details.[/bold red]")

    except Exception:
        logger.exception("A fatal error occurred during the export process. Aborting.")
        console.print("\n[bold red]❌ A fatal error occurred. Please check the log file `data/assessment.log` for details.[/bold red]")


if __name__ == "__main__":
    app()
