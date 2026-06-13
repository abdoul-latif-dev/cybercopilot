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
    """Affiche le menu principal réduit."""
    console.print()
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", width=4)
    table.add_column(style="white")

    table.add_row("1.", "🔍 Détecter des menaces")
    table.add_row("2.", "📋 Incidents (liste, détail, export)")
    table.add_row("3.", "🗑️  Supprimer des incidents (RGPD)")
    table.add_row("4.", "💬 Discuter avec l'assistant")
    table.add_row("5.", "📊 Statistiques & Export rapport")
    table.add_row("6.", "🔐 Activer / désactiver l'anonymisation")
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

        status, note = cli.prompt_incident_action(incident_id)
        if status:
            storage.update_incident_status(incident_id, status, note)
            cli.print_success(f"Incident #{incident_id} marqué : {status}")

    storage.close()


# ════════════════════════════════════════════════════════════════════════
# SOUS-MENU DÉTECTION
# ════════════════════════════════════════════════════════════════════════

def action_detect_menu(anonymize: bool) -> None:
    """Sous-menu de détection des menaces (fusion des options 1-6)."""
    while True:
        console.print("\n[bold yellow]🔍 Détection des menaces[/bold yellow]\n")
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column(style="bold cyan", width=4)
        table.add_column(style="white")
        table.add_row("1.", "🔑 Brute force SSH (auth.log)")
        table.add_row("2.", "💉 Injections SQL (access.log)")
        table.add_row("3.", "🌐 Scan de ports (firewall.log)")
        table.add_row("4.", "🚀 Attaque DDoS (ddos-access.log)")
        table.add_row("5.", "🪟 Logs Windows Event Log")
        table.add_row("6.", "🔄 Analyser TOUS les logs")
        table.add_row("0.", "↩️  Retour au menu principal")
        console.print(Panel(table, title="[bold]Choisir le type de détection[/bold]", border_style="yellow"))

        choice = Prompt.ask("[bold cyan]Votre choix[/bold cyan]", default="0").strip()

        if choice == "0":
            break
        elif choice == "1":
            console.print("\n[bold yellow]🔑 Détection brute force SSH[/bold yellow]")
            console.print("[dim]Source : data/logs/auth.log[/dim]\n")
            analyze_log_file("auth.log", anonymize)
        elif choice == "2":
            console.print("\n[bold yellow]💉 Détection injections SQL[/bold yellow]")
            console.print("[dim]Source : data/logs/access.log[/dim]\n")
            analyze_log_file("access.log", anonymize)
        elif choice == "3":
            console.print("\n[bold yellow]🌐 Détection scan de ports[/bold yellow]")
            console.print("[dim]Source : data/logs/firewall.log[/dim]\n")
            analyze_log_file("firewall.log", anonymize)
        elif choice == "4":
            console.print("\n[bold yellow]🚀 Détection attaque DDoS[/bold yellow]")
            console.print("[dim]Source : data/logs/ddos-access.log[/dim]\n")
            analyze_log_file("ddos-access.log", anonymize)
        elif choice == "5":
            console.print("\n[bold yellow]🪟 Analyse logs Windows Event Log[/bold yellow]")
            console.print("[dim]Source : data/logs/windows-security.evtx.json[/dim]\n")
            analyze_log_file("windows-security.evtx.json", anonymize)
        elif choice == "6":
            console.print("\n[bold yellow]🔄 Analyse de tous les logs[/bold yellow]\n")
            for fname in [
                "auth.log", "access.log", "firewall.log",
                "ddos-access.log", "windows-security.evtx.json",
            ]:
                console.print(f"\n[cyan]── Fichier {fname} ──[/cyan]")
                analyze_log_file(fname, anonymize)
        else:
            cli.print_error(f"Choix invalide : {choice}")
            continue

        Prompt.ask("\n[dim]Appuyez sur Entrée pour continuer[/dim]", default="")


# ════════════════════════════════════════════════════════════════════════
# SOUS-MENU INCIDENTS (liste + détail + export fusionnés)
# ════════════════════════════════════════════════════════════════════════

def action_incidents_menu() -> None:
    """Sous-menu incidents : liste, détail, export (fusion 7+8+11)."""
    while True:
        storage = Storage()
        incidents = storage.list_incidents()

        console.print("\n[bold cyan]📋 Gestion des incidents[/bold cyan]\n")
        cli.print_incidents_table(incidents)

        if not incidents:
            storage.close()
            Prompt.ask("\n[dim]Appuyez sur Entrée pour revenir au menu[/dim]", default="")
            break

        console.print()
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column(style="bold cyan", width=4)
        table.add_column(style="white")
        table.add_row("1.", "🔎 Voir le détail d'un incident")
        table.add_row("2.", "📤 Exporter le rapport Markdown")
        table.add_row("0.", "↩️  Retour au menu principal")
        console.print(table)

        choice = Prompt.ask("\n[bold cyan]Votre choix[/bold cyan]", default="0").strip()

        if choice == "0":
            storage.close()
            break
        elif choice == "1":
            incident_id = Prompt.ask("\n[cyan]Numéro de l'incident à afficher[/cyan]")
            try:
                incident = storage.get_incident(int(incident_id))
            except ValueError:
                cli.print_error("Numéro invalide.")
                storage.close()
                continue
            if not incident:
                cli.print_error(f"Incident #{incident_id} introuvable.")
                storage.close()
                continue
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
            Prompt.ask("\n[dim]Appuyez sur Entrée pour continuer[/dim]", default="")
        elif choice == "2":
            output = Prompt.ask(
                "[cyan]Nom du fichier de sortie[/cyan] [dim](Entrée pour 'rapport.md')[/dim]",
                default="rapport.md",
                show_default=False,
            )
            if not output.endswith(".md"):
                output = output + ".md"
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
            Prompt.ask("\n[dim]Appuyez sur Entrée pour continuer[/dim]", default="")
        else:
            cli.print_error(f"Choix invalide : {choice}")
            storage.close()


# ════════════════════════════════════════════════════════════════════════
# SOUS-MENU SUPPRESSION (RGPD) — affiche le tableau après suppression
# ════════════════════════════════════════════════════════════════════════

def action_delete_menu() -> None:
    """Sous-menu suppression RGPD : affiche le tableau mis à jour après chaque suppression."""
    while True:
        storage = Storage()
        incidents = storage.list_incidents()

        console.print("\n[bold red]🗑️  Suppression d'incidents (RGPD)[/bold red]\n")
        cli.print_incidents_table(incidents)

        if not incidents:
            storage.close()
            Prompt.ask("\n[dim]Appuyez sur Entrée pour revenir au menu[/dim]", default="")
            break

        console.print()
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column(style="bold cyan", width=4)
        table.add_column(style="white")
        table.add_row("1.", "🗑️  Supprimer un incident par numéro")
        table.add_row("2.", "🧹 Vider TOUTE la base d'incidents")
        table.add_row("0.", "↩️  Retour au menu principal")
        console.print(table)

        choice = Prompt.ask("\n[bold cyan]Votre choix[/bold cyan]", default="0").strip()

        if choice == "0":
            storage.close()
            break

        elif choice == "1":
            incident_id = Prompt.ask("\n[cyan]Numéro de l'incident à supprimer[/cyan]")
            try:
                deleted = storage.delete_incident(int(incident_id))
            except ValueError:
                cli.print_error("Numéro invalide.")
                storage.close()
                continue
            if deleted:
                cli.print_success(f"✅ Incident #{incident_id} supprimé avec succès.")
            else:
                cli.print_error(f"Incident #{incident_id} introuvable.")
            storage.close()

            # Afficher immédiatement le tableau mis à jour
            storage2 = Storage()
            remaining = storage2.list_incidents()
            console.print("\n[bold cyan]📋 Incidents restants :[/bold cyan]")
            cli.print_incidents_table(remaining)
            storage2.close()
            Prompt.ask("\n[dim]Appuyez sur Entrée pour continuer[/dim]", default="")

        elif choice == "2":
            if not Confirm.ask("\n[red]Êtes-vous sûr de vouloir supprimer TOUS les incidents ?[/red]"):
                cli.print_warning("Opération annulée.")
                storage.close()
                continue
            n = storage.purge_all()
            cli.print_success(f"{n} incident(s) supprimé(s).")
            cache.clear()
            cli.print_success("Cache LLM vidé.")
            storage.close()

            # Afficher le tableau vide pour confirmer
            console.print("\n[bold cyan]📋 Base d'incidents après purge :[/bold cyan]")
            cli.print_incidents_table([])
            Prompt.ask("\n[dim]Appuyez sur Entrée pour continuer[/dim]", default="")

        else:
            cli.print_error(f"Choix invalide : {choice}")
            storage.close()


# ════════════════════════════════════════════════════════════════════════
# ACTIONS SIMPLES
# ════════════════════════════════════════════════════════════════════════

def action_chat() -> None:
    storage = Storage()
    incidents = storage.list_incidents()
    context = "\n".join(
        f"#{inc['id']} [{inc['severity']}] {inc['attack_type']} "
        f"depuis {inc['source_ip']} — {inc['summary']}"
        for inc in incidents[:10]
    ) or "Aucun incident enregistré."

    console.print("\n[bold cyan]💬 Mode conversationnel[/bold cyan]")
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


def action_stats_export() -> None:
    """Statistiques + export rapport fusionnés (fusion 10+11)."""
    while True:
        s = get_stats()
        cache_info = cache.stats()
        console.print("\n[bold cyan]📊 Statistiques & Export[/bold cyan]\n")
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

        console.print()
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column(style="bold cyan", width=4)
        table.add_column(style="white")
        table.add_row("1.", "📤 Exporter un rapport Markdown")
        table.add_row("0.", "↩️  Retour au menu principal")
        console.print(table)

        choice = Prompt.ask("\n[bold cyan]Votre choix[/bold cyan]", default="0").strip()
        if choice == "0":
            break
        elif choice == "1":
            storage = Storage()
            incidents = storage.list_incidents()
            if not incidents:
                cli.print_warning("Aucun incident à exporter.")
                storage.close()
                Prompt.ask("\n[dim]Appuyez sur Entrée pour continuer[/dim]", default="")
                continue
            output = Prompt.ask(
                "[cyan]Nom du fichier de sortie[/cyan] [dim](Entrée pour 'rapport.md')[/dim]",
                default="rapport.md",
                show_default=False,
            )
            if not output.endswith(".md"):
                output = output + ".md"
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
            Prompt.ask("\n[dim]Appuyez sur Entrée pour continuer[/dim]", default="")
        else:
            cli.print_error(f"Choix invalide : {choice}")


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
            action_detect_menu(state["anonymize"])
        elif choice == "2":
            action_incidents_menu()
        elif choice == "3":
            action_delete_menu()
        elif choice == "4":
            action_chat()
        elif choice == "5":
            action_stats_export()
        elif choice == "6":
            action_toggle_anonymize(state)
            Prompt.ask("\n[dim]Appuyez sur Entrée pour revenir au menu[/dim]", default="")
        else:
            cli.print_error(f"Choix invalide : {choice}")
            continue

        print_banner()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[cyan]À bientôt ![/cyan]\n")
        sys.exit(0)
