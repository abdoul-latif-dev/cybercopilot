#!/usr/bin/env python3
"""Interface interactive de l'Assistant SOC — pas de commandes à taper."""

import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.text import Text

from src import cache, cli
from src.detector import detect_all
from src.enricher import enrich
from src.llm_client import analyze_incident, chat, get_stats
from src.parser import parse_file
from src.storage import Storage


load_dotenv()
console = Console()


# ════════════════════════════════════════════════════════════════════════
# AFFICHAGE
# ════════════════════════════════════════════════════════════════════════

def print_banner() -> None:
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]🛡️  ASSISTANT SOC INTELLIGENT[/bold cyan]\n"
        "[white]Analyse de logs basée sur les modèles de langage[/white]\n"
        "[dim]CyberCopilot — projet B2[/dim]",
        border_style="cyan",
    ))


def print_menu() -> None:
    """Affiche le menu principal."""
    console.print()
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", width=4)
    table.add_column(style="white")

    table.add_row("1.", "🔍 Détecter des intrusions (brute force SSH)")
    table.add_row("2.", "💉 Détecter des injections SQL")
    table.add_row("3.", "🌐 Détecter un scan de ports")
    table.add_row("4.", "🚀 Détecter une attaque DDoS")
    table.add_row("5.", "🪟 Analyser des logs Windows (Event Log)")
    table.add_row("6.", "🔄 Analyser tous les logs disponibles")
    table.add_row("7.", "📋 Voir la liste des incidents détectés")
    table.add_row("8.", "🔎 Voir le détail d'un incident")
    table.add_row("9.", "💬 Discuter avec l'assistant")
    table.add_row("10.", "📊 Statistiques (tokens, économies)")
    table.add_row("11.", "📤 Exporter un rapport Markdown")
    table.add_row("12.", "🗑️  Supprimer un incident (RGPD)")
    table.add_row("13.", "🧹 Vider toute la base d'incidents")
    table.add_row("14.", "🔐 Activer / désactiver l'anonymisation")
    table.add_row("0.", "🚪 Quitter")

    console.print(Panel(table, title="[bold]Menu principal[/bold]", border_style="blue"))


# ════════════════════════════════════════════════════════════════════════
# ANALYSE D'UN FICHIER DE LOGS
# ════════════════════════════════════════════════════════════════════════

def analyze_log_file(filename: str, anonymize: bool) -> None:
    """Pipeline complet d'analyse pour un fichier."""
    path = Path("data/logs") / filename
    if not path.exists():
        cli.print_error(f"Fichier introuvable : {path}")
        return

    cli.print_progress(f"Lecture du fichier {path.name}...")
    events = parse_file(path)
    cli.print_success(f"{len(events)} événement(s) extrait(s)")

    cli.print_progress("Détection des incidents...")
    incidents = detect_all(events)
    if not incidents:
        cli.print_warning("Aucun incident détecté.")
        return
    cli.print_success(f"{len(incidents)} incident(s) détecté(s)")

    storage = Storage()
    for incident in incidents:
        info = enrich(incident.source_ip)
        data = {
            "source_ip": incident.source_ip,
            "attack_type": incident.attack_type,
            "count": incident.count,
            "users": incident.users,
            "targets": incident.targets,
            "time_start": incident.time_range[0],
            "time_end": incident.time_range[1],
            "sample_logs": incident.sample_logs,
            "country": info["country"],
            "reputation": info["reputation"],
            "tags": info["tags"],
        }
        cli.print_progress(
            f"Analyse de l'incident {incident.attack_type} ({incident.source_ip})..."
        )
        analysis = analyze_incident(data, anonymize=anonymize)
        incident_id = storage.save_incident(
            source_ip=incident.source_ip,
            attack_type=analysis.get("attack_type", incident.attack_type),
            severity=analysis.get("severity", incident.severity),
            summary=analysis.get("summary", ""),
            raw_logs=incident.sample_logs,
            recommendation=analysis.get("recommendations", []),
        )
        cli.print_incident(incident_id, data, analysis)
    storage.close()


# ════════════════════════════════════════════════════════════════════════
# ACTIONS DU MENU
# ════════════════════════════════════════════════════════════════════════

def action_detect_intrusions(anonymize: bool) -> None:
    console.print("\n[bold yellow]🔍 Détection d'intrusions (brute force SSH)[/bold yellow]")
    console.print("[dim]Source : data/logs/auth.log[/dim]\n")
    analyze_log_file("auth.log", anonymize)


def action_detect_sql(anonymize: bool) -> None:
    console.print("\n[bold yellow]💉 Détection d'injections SQL[/bold yellow]")
    console.print("[dim]Source : data/logs/access.log[/dim]\n")
    analyze_log_file("access.log", anonymize)


def action_detect_scan(anonymize: bool) -> None:
    console.print("\n[bold yellow]🌐 Détection de scan de ports[/bold yellow]")
    console.print("[dim]Source : data/logs/firewall.log[/dim]\n")
    analyze_log_file("firewall.log", anonymize)


def action_detect_ddos(anonymize: bool) -> None:
    console.print("\n[bold yellow]🚀 Détection d'attaque DDoS[/bold yellow]")
    console.print("[dim]Source : data/logs/ddos-access.log[/dim]\n")
    analyze_log_file("ddos-access.log", anonymize)


def action_detect_windows(anonymize: bool) -> None:
    console.print("\n[bold yellow]🪟 Analyse de logs Windows Event Log[/bold yellow]")
    console.print("[dim]Source : data/logs/windows-security.evtx.json[/dim]\n")
    analyze_log_file("windows-security.evtx.json", anonymize)


def action_analyze_all(anonymize: bool) -> None:
    console.print("\n[bold yellow]🔄 Analyse de tous les logs[/bold yellow]\n")
    for fname in [
        "auth.log",
        "access.log",
        "firewall.log",
        "ddos-access.log",
        "windows-security.evtx.json",
    ]:
        console.print(f"\n[cyan]── Fichier {fname} ──[/cyan]")
        analyze_log_file(fname, anonymize)


def action_list_incidents() -> None:
    storage = Storage()
    incidents = storage.list_incidents()
    cli.print_incidents_table(incidents)
    storage.close()


def action_show_incident() -> None:
    storage = Storage()
    incidents = storage.list_incidents()
    if not incidents:
        cli.print_warning("Aucun incident enregistré.")
        storage.close()
        return
    cli.print_incidents_table(incidents)
    incident_id = Prompt.ask("\n[cyan]Numéro de l'incident à afficher[/cyan]")
    try:
        incident = storage.get_incident(int(incident_id))
    except ValueError:
        cli.print_error("Numéro invalide.")
        storage.close()
        return
    if not incident:
        cli.print_error(f"Incident #{incident_id} introuvable.")
        storage.close()
        return
    raw_logs = json.loads(incident["raw_logs"]) if incident["raw_logs"] else []
    recos = json.loads(incident["recommendation"]) if incident["recommendation"] else []
    data = {
        "source_ip": incident["source_ip"],
        "country": "—",
        "reputation": "—",
        "count": len(raw_logs),
        "time_start": incident["timestamp"],
        "time_end": incident["timestamp"],
    }
    analysis = {
        "attack_type": incident["attack_type"],
        "severity": incident["severity"],
        "summary": incident["summary"],
        "recommendations": recos,
    }
    cli.print_incident(incident["id"], data, analysis)
    storage.close()


def action_chat() -> None:
    storage = Storage()
    incidents = storage.list_incidents()
    context = "\n".join(
        f"#{inc['id']} [{inc['severity']}] {inc['attack_type']} "
        f"depuis {inc['source_ip']} — {inc['summary']}"
        for inc in incidents[:10]
    ) or "Aucun incident enregistré."

    console.print(
        "\n[bold cyan]💬 Mode conversationnel[/bold cyan]"
    )
    console.print("[dim]Tapez vos questions, 'retour' pour revenir au menu.[/dim]\n")
    while True:
        try:
            question = Prompt.ask("[yellow]?[/yellow]").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not question:
            continue
        if question.lower() in ("retour", "exit", "quit", "q"):
            break
        cli.print_progress("Analyse en cours...")
        answer = chat(question, context=context)
        console.print(f"\n[green]{answer}[/green]\n")
    storage.close()


def action_stats() -> None:
    s = get_stats()
    cache_info = cache.stats()
    console.print("\n[bold cyan]📊 Statistiques de la session[/bold cyan]\n")
    console.print(f"  Appels API LLM         : [bold]{s['calls']}[/bold]")
    console.print(f"  Cache hits             : [green]{s['cache_hits']}[/green]")
    console.print(f"  Tokens entrée          : {s['tokens_in']:,}")
    console.print(f"  Tokens sortie          : {s['tokens_out']:,}")
    console.print(f"  Total tokens utilisés  : [bold]{s['tokens_in'] + s['tokens_out']:,}[/bold]\n")
    saved = s["tokens_saved_compression"] + s["tokens_saved_cache"]
    console.print("[bold yellow]💰 Économies de tokens[/bold yellow]\n")
    console.print(f"  Économisés par compression : [green]{s['tokens_saved_compression']:,}[/green]")
    console.print(f"  Économisés par cache       : [green]{s['tokens_saved_cache']:,}[/green]")
    console.print(f"  Total économisé            : [bold green]{saved:,}[/bold green]\n")
    cost_used = (s["tokens_in"] * 0.15 + s["tokens_out"] * 0.60) / 1_000_000
    cost_saved = saved * 0.30 / 1_000_000
    console.print(f"  Coût estimé utilisé    : ~${cost_used:.4f}")
    console.print(f"  Coût estimé économisé  : [green]~${cost_saved:.4f}[/green]\n")
    console.print(f"[dim]Cache : {cache_info['entries']} entrée(s), {cache_info['size_kb']} Ko[/dim]")


def action_export() -> None:
    storage = Storage()
    incidents = storage.list_incidents()
    if not incidents:
        cli.print_warning("Aucun incident à exporter.")
        storage.close()
        return
    output = Prompt.ask(
        "[cyan]Nom du fichier de sortie[/cyan]",
        default="rapport.md",
    )
    lines = ["# Rapport d'incidents SOC", ""]
    for inc in incidents:
        recos = json.loads(inc["recommendation"]) if inc["recommendation"] else []
        lines.append(f"## Incident #{inc['id']} — {inc['attack_type']}")
        lines.append(f"- **Sévérité :** {inc['severity']}")
        lines.append(f"- **IP source :** {inc['source_ip']}")
        lines.append(f"- **Date :** {inc['timestamp']}")
        lines.append(f"\n**Résumé :** {inc['summary']}\n")
        lines.append("**Actions recommandées :**")
        for r in recos:
            lines.append(f"- {r}")
        lines.append("\n---\n")
    Path(output).write_text("\n".join(lines), encoding="utf-8")
    cli.print_success(f"Rapport exporté : {output}")
    storage.close()


def action_delete_incident() -> None:
    storage = Storage()
    incidents = storage.list_incidents()
    if not incidents:
        cli.print_warning("Aucun incident à supprimer.")
        storage.close()
        return
    cli.print_incidents_table(incidents)
    incident_id = Prompt.ask("\n[cyan]Numéro de l'incident à supprimer[/cyan]")
    try:
        deleted = storage.delete_incident(int(incident_id))
    except ValueError:
        cli.print_error("Numéro invalide.")
        storage.close()
        return
    if deleted:
        cli.print_success(f"Incident #{incident_id} supprimé.")
    else:
        cli.print_error(f"Incident #{incident_id} introuvable.")
    storage.close()


def action_purge() -> None:
    if not Confirm.ask("\n[red]Êtes-vous sûr de vouloir supprimer TOUS les incidents ?[/red]"):
        cli.print_warning("Opération annulée.")
        return
    storage = Storage()
    n = storage.purge_all()
    cli.print_success(f"{n} incident(s) supprimé(s).")
    cache.clear()
    cli.print_success("Cache LLM vidé.")
    storage.close()


def action_toggle_anonymize(state: dict) -> None:
    state["anonymize"] = not state["anonymize"]
    if state["anonymize"]:
        console.print("\n[green]🔐 Anonymisation activée[/green]")
        console.print(
            "[dim]Les IP internes et noms d'utilisateur seront masqués avant envoi au LLM.[/dim]"
        )
    else:
        console.print("\n[yellow]🔓 Anonymisation désactivée[/yellow]")


# ════════════════════════════════════════════════════════════════════════
# BOUCLE PRINCIPALE
# ════════════════════════════════════════════════════════════════════════

def main() -> None:
    state = {"anonymize": False}
    print_banner()

    while True:
        print_menu()
        anon_label = "[green]ON[/green]" if state["anonymize"] else "[dim]OFF[/dim]"
        choice = Prompt.ask(
            f"\n[bold cyan]Votre choix[/bold cyan] [dim](anonymisation: {anon_label})[/dim]",
            default="0",
        ).strip()

        if choice == "0":
            console.print("\n[cyan]À bientôt ![/cyan]\n")
            break
        elif choice == "1":
            action_detect_intrusions(state["anonymize"])
        elif choice == "2":
            action_detect_sql(state["anonymize"])
        elif choice == "3":
            action_detect_scan(state["anonymize"])
        elif choice == "4":
            action_detect_ddos(state["anonymize"])
        elif choice == "5":
            action_detect_windows(state["anonymize"])
        elif choice == "6":
            action_analyze_all(state["anonymize"])
        elif choice == "7":
            action_list_incidents()
        elif choice == "8":
            action_show_incident()
        elif choice == "9":
            action_chat()
        elif choice == "10":
            action_stats()
        elif choice == "11":
            action_export()
        elif choice == "12":
            action_delete_incident()
        elif choice == "13":
            action_purge()
        elif choice == "14":
            action_toggle_anonymize(state)
        else:
            cli.print_error(f"Choix invalide : {choice}")
            continue

        Prompt.ask("\n[dim]Appuyez sur Entrée pour revenir au menu[/dim]", default="")
        print_banner()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[cyan]À bientôt ![/cyan]\n")
        sys.exit(0)
