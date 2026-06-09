#!/usr/bin/env python3
"""Point d'entrée de l'Assistant SOC."""

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv

from src import cache, cli
from src.detector import detect_all
from src.enricher import enrich
from src.llm_client import analyze_incident, chat, get_stats
from src.parser import parse_file
from src.storage import Storage


load_dotenv()


def cmd_analyze(args) -> None:
    """Analyse un fichier de logs."""
    cli.print_banner()
    path = Path(args.file)
    if not path.exists():
        cli.print_error(f"Fichier introuvable : {path}")
        sys.exit(1)

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
        analysis = analyze_incident(data, anonymize=getattr(args, "anonymize", False))

        incident_id = storage.save_incident(
            source_ip=incident.source_ip,
            attack_type=incident.attack_type,   # CVSS — jamais écrasé par le LLM
            severity=incident.severity,          # CVSS — jamais écrasé par le LLM
            summary=analysis.get("summary", ""),
            raw_logs=incident.sample_logs,
            recommendation=analysis.get("recommendations", []),
        )
        cli.print_incident(incident_id, data, analysis)

    storage.close()


def cmd_list(args) -> None:
    """Liste les incidents enregistrés."""
    storage = Storage()
    incidents = storage.list_incidents(severity=args.severity)
    cli.print_incidents_table(incidents)
    storage.close()


def cmd_show(args) -> None:
    """Affiche le détail d'un incident."""
    storage = Storage()
    incident = storage.get_incident(args.id)
    if not incident:
        cli.print_error(f"Incident #{args.id} introuvable.")
        sys.exit(1)

    import json
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


def cmd_chat(args) -> None:
    """Mode conversationnel interactif."""
    cli.print_banner()
    storage = Storage()
    incidents = storage.list_incidents()
    context = "\n".join(
        f"#{inc['id']} [{inc['severity']}] {inc['attack_type']} "
        f"depuis {inc['source_ip']} — {inc['summary']}"
        for inc in incidents[:10]
    ) or "Aucun incident enregistré."

    cli.console.print(
        "[cyan]Mode conversationnel actif.[/cyan] "
        "Tapez vos questions, [bold]exit[/bold] pour quitter.\n"
    )
    while True:
        try:
            question = input("\033[33m? \033[0m").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not question:
            continue
        if question.lower() in ("exit", "quit", "q"):
            break
        cli.print_progress("Analyse en cours...")
        answer = chat(question, context=context)
        cli.console.print(f"\n[green]{answer}[/green]\n")
    storage.close()


def cmd_stats(args) -> None:
    """Affiche les statistiques d'utilisation et d'économie de tokens."""
    s = get_stats()
    cache_info = cache.stats()

    cli.console.print("\n[bold cyan]📊 Statistiques de la session[/bold cyan]\n")
    cli.console.print(f"  Appels API LLM         : [bold]{s['calls']}[/bold]")
    cli.console.print(f"  Cache hits             : [green]{s['cache_hits']}[/green]")
    cli.console.print(f"  Tokens entrée          : {s['tokens_in']:,}")
    cli.console.print(f"  Tokens sortie          : {s['tokens_out']:,}")
    cli.console.print(f"  Total tokens utilisés  : [bold]{s['tokens_in'] + s['tokens_out']:,}[/bold]\n")

    saved = s["tokens_saved_compression"] + s["tokens_saved_cache"]
    cli.console.print("[bold yellow]💰 Économies de tokens[/bold yellow]\n")
    cli.console.print(f"  Économisés par compression : [green]{s['tokens_saved_compression']:,}[/green]")
    cli.console.print(f"  Économisés par cache       : [green]{s['tokens_saved_cache']:,}[/green]")
    cli.console.print(f"  Total économisé            : [bold green]{saved:,}[/bold green]\n")

    # Estimation coût (gpt-4o-mini : ~0.15$/1M input, ~0.60$/1M output)
    cost_used = (s["tokens_in"] * 0.15 + s["tokens_out"] * 0.60) / 1_000_000
    cost_saved = saved * 0.30 / 1_000_000
    cli.console.print(f"  Coût estimé utilisé    : ~${cost_used:.4f}")
    cli.console.print(f"  Coût estimé économisé  : [green]~${cost_saved:.4f}[/green]\n")

    cli.console.print(f"[dim]Cache : {cache_info['entries']} entrée(s), {cache_info['size_kb']} Ko[/dim]\n")


def cmd_clear_cache(args) -> None:
    """Vide le cache LLM."""
    cache.clear()
    cli.print_success("Cache vidé.")


def cmd_delete(args) -> None:
    """Supprime un incident (RGPD — droit à l'effacement)."""
    storage = Storage()
    if storage.delete_incident(args.id):
        cli.print_success(f"Incident #{args.id} supprimé.")
    else:
        cli.print_error(f"Incident #{args.id} introuvable.")
    storage.close()


def cmd_purge(args) -> None:
    """Supprime tous les incidents (RGPD)."""
    if not args.yes:
        cli.print_warning(
            "Confirmation requise. Relancez avec --yes pour effacer tous les incidents."
        )
        return
    storage = Storage()
    n = storage.purge_all()
    cli.print_success(f"{n} incident(s) supprimé(s).")
    storage.close()


def cmd_export(args) -> None:
    """Exporte un rapport au format Markdown."""
    storage = Storage()
    incidents = storage.list_incidents()
    if not incidents:
        cli.print_warning("Aucun incident à exporter.")
        return

    import json
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

    out = Path(args.output)
    out.write_text("\n".join(lines), encoding="utf-8")
    cli.print_success(f"Rapport exporté : {out}")
    storage.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="soc-assistant", description="Assistant SOC LLM")
    sub = p.add_subparsers(dest="command", required=True)

    p_an = sub.add_parser("analyze", help="Analyser un fichier de logs")
    p_an.add_argument("file", help="Chemin du fichier de logs")
    p_an.add_argument(
        "--anonymize",
        action="store_true",
        help="Anonymiser les IP internes et noms d'utilisateur avant envoi au LLM",
    )
    p_an.set_defaults(func=cmd_analyze)

    p_ls = sub.add_parser("list", help="Lister les incidents enregistrés")
    p_ls.add_argument("--severity", help="Filtrer par sévérité", default=None)
    p_ls.set_defaults(func=cmd_list)

    p_sh = sub.add_parser("show", help="Détail d'un incident")
    p_sh.add_argument("id", type=int)
    p_sh.set_defaults(func=cmd_show)

    p_ch = sub.add_parser("chat", help="Mode conversationnel")
    p_ch.set_defaults(func=cmd_chat)

    p_ex = sub.add_parser("export", help="Exporter un rapport Markdown")
    p_ex.add_argument("--output", "-o", default="rapport.md")
    p_ex.set_defaults(func=cmd_export)

    p_st = sub.add_parser("stats", help="Statistiques de tokens et coûts")
    p_st.set_defaults(func=cmd_stats)

    p_cc = sub.add_parser("clear-cache", help="Vider le cache LLM")
    p_cc.set_defaults(func=cmd_clear_cache)

    p_dl = sub.add_parser("delete", help="Supprimer un incident (RGPD)")
    p_dl.add_argument("id", type=int)
    p_dl.set_defaults(func=cmd_delete)

    p_pg = sub.add_parser("purge", help="Supprimer tous les incidents (RGPD)")
    p_pg.add_argument("--yes", action="store_true", help="Confirmer la suppression")
    p_pg.set_defaults(func=cmd_purge)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
