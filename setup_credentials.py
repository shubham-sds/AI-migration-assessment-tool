"""Securely prompts for and stores user credentials.

This script reads the `inventory.csv` file to identify all unique usernames
and then prompts the user to enter a password for each one. The credentials
are stored securely in the system's default keyring (e.g., Windows
Credential Manager, macOS Keychain) for the main application to use.

This should be run once before the main discovery process.
"""

import keyring
import pandas as pd
from keyring.errors import NoKeyringError
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

# Initialize Rich Console for better terminal output
console = Console()

# --- Constants ---
SERVICE_NAME = "ai-migration-tool"
INVENTORY_FILE = "inventory.csv"


def setup_credentials() -> None:
    """Reads inventory, prompts for passwords, and stores them in the keyring.

    This function orchestrates the credential setup process. It performs
    the following steps:
    1. Reads the inventory file to get a list of unique users.
    2. Iterates through each user, prompting for their password.
    3. Stores each username and password securely in the system keyring
       under the defined SERVICE_NAME.

    Handles common errors such as a missing inventory file, incorrect columns,
    or the absence of a system keyring backend.
    """
    console.print(
        Panel(
            f"[bold yellow]Credential Setup for '{SERVICE_NAME}'[/bold yellow]\n\n"
            f"This script will securely store passwords for users found in "
            f"'{INVENTORY_FILE}'.",
            title="[bold cyan]Welcome[/bold cyan]",
            border_style="cyan",
        )
    )

    # 1. Read inventory and find unique users
    try:
        inventory = pd.read_csv(INVENTORY_FILE, dtype=str)
        unique_users = inventory["user"].dropna().unique()
        console.print(
            f"\n[*] Found {len(unique_users)} unique user(s) in "
            f"'{INVENTORY_FILE}': [bold magenta]{', '.join(unique_users)}[/bold magenta]"
        )
    except FileNotFoundError:
        console.print(
            f"\n[bold red]Error: Inventory file not found at '{INVENTORY_FILE}'. "
            "Please create it before running this script.[/bold red]"
        )
        return
    except KeyError:
        console.print(
            f"\n[bold red]Error: The inventory file '{INVENTORY_FILE}' must contain a "
            "'user' column.[/bold red]"
        )
        return
    except Exception as exc:
        console.print(
            f"\n[bold red]An error occurred while reading the inventory file: {exc}[/bold red]"
        )
        return

    if not unique_users.size:
        console.print("[yellow]No users found in the inventory – nothing to do.[/yellow]")
        return

    # 2. Prompt for and store passwords
    console.print("\n[*] Please enter the password for each user when prompted.")
    console.print("[dim]Note: Your input is hidden for security.[/dim]\n")

    for user in unique_users:
        try:
            password = Prompt.ask(
                f"  Enter password for user '[bold yellow]{user}[/bold yellow]'",
                password=True,
                console=console,
            )

            # Prompt again if the password is empty to avoid mistakes
            if not password:
                console.print("[red]Password cannot be empty – try again.[/red]")
                password = Prompt.ask(
                    f"  Enter password for user '[bold yellow]{user}[/bold yellow]'",
                    password=True,
                    console=console,
                )

            keyring.set_password(SERVICE_NAME, user, password)
            console.print(
                f"  [green]✔[/green] Password for '[bold]{user}[/bold]' has been securely stored.\n"
            )
        except NoKeyringError:
            console.print(
                f"\n[bold red]No system keyring backend available on this machine. "
                "Install a backend (e.g. `secretstorage`, `pywin32`, or "
                "`keyrings.alt`) and try again.[/bold red]"
            )
            return
        except Exception as exc:
            console.print(
                f"\n[bold red]Could not store password for '{user}'. Error: {exc}[/bold red]"
            )
            return

    # 3. Final success message
    console.print(
        Panel(
            "[bold green]Credential setup complete! You can now run the main "
            "discovery tool.[/bold green]",
            title="[bold green]Success[/bold green]",
            border_style="green",
        )
    )


if __name__ == "__main__":
    setup_credentials()