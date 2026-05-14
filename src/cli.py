"""Interface en ligne de commande de l'assistant SOC."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


SEVERITY_COLORS = {
    "critical": "red",
    "high": "bright_red",
    "medium": "yellow",
    "low": "green",
}

SEVERITY_LABELS = {
    "critical": "🔴 CRITIQUE",
    "high": "🟠 ÉLEVÉ",
    "medium": "🟡 MOYEN",
    "low": "🟢 FAIBLE",
}


def print_banner() -> None:
    """Affiche le bandeau de l'assistant."""
    console.print(
        Panel.fit(
            "[bold cyan]🛡️  ASSISTANT SOC[/bold cyan]\n"
            "[white]Analyse intelligente de logs basée sur LLM[/white]",
            border_style="cyan",
        )
    )


def print_incident(incident_id: int, data: dict, analysis: dict) -> None:
    """Affiche un incident analysé de manière formatée."""
    severity = analysis.get("severity", "medium")
    color = SEVERITY_COLORS.get(severity, "white")
    label = SEVERITY_LABELS.get(severity, severity.upper())

    header = Text()
    header.append(f"INCIDENT #{incident_id}  ", style="bold")
    header.append(label, style=f"bold {color}")
    if analysis.get("_fallback"):
        header.append("  [mode dégradé]", style="dim italic")

    body = Text()
    body.append(f"Type      : ", style="dim")
    body.append(f"{analysis.get('attack_type', '?')}\n", style="bold")
    body.append(f"IP source : ", style="dim")
    body.append(
        f"{data.get('source_ip', '?')} "
        f"({data.get('country', '?')} — {data.get('reputation', '?')})\n",
        style=color,
    )
    body.append(f"Période   : ", style="dim")
    body.append(f"{data.get('time_start', '?')} → {data.get('time_end', '?')}\n")
    body.append(f"Volume    : ", style="dim")
    body.append(f"{data.get('count', 0)} événement(s)\n")

    body.append("\n")
    body.append("RÉSUMÉ\n", style="bold underline")
    body.append(f"{analysis.get('summary', '')}\n\n")

    body.append("ACTIONS RECOMMANDÉES\n", style="bold underline")
    for i, rec in enumerate(analysis.get("recommendations", []), 1):
        body.append(f"  {i}. ", style="bold cyan")
        body.append(f"{rec}\n")

    console.print(Panel(body, title=header, border_style=color))


def print_incidents_table(incidents: list[dict]) -> None:
    """Affiche un tableau récapitulatif des incidents."""
    if not incidents:
        console.print("[yellow]Aucun incident enregistré.[/yellow]")
        return

    table = Table(title="Incidents enregistrés", show_lines=True)
    table.add_column("#", style="cyan", width=4)
    table.add_column("Sévérité", width=12)
    table.add_column("Type", style="white")
    table.add_column("IP source", style="magenta")
    table.add_column("Date", style="dim")

    for inc in incidents:
        sev = inc.get("severity", "medium")
        color = SEVERITY_COLORS.get(sev, "white")
        label = SEVERITY_LABELS.get(sev, sev)
        table.add_row(
            str(inc["id"]),
            f"[{color}]{label}[/{color}]",
            inc.get("attack_type", "?"),
            inc.get("source_ip", "?"),
            inc.get("timestamp", "")[:19],
        )
    console.print(table)


def print_progress(message: str) -> None:
    console.print(f"[cyan]→[/cyan] {message}")


def print_success(message: str) -> None:
    console.print(f"[green]✓[/green] {message}")


def print_warning(message: str) -> None:
    console.print(f"[yellow]⚠[/yellow]  {message}")


def print_error(message: str) -> None:
    console.print(f"[red]✗[/red] {message}")
