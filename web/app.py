"""Application web FastAPI — Interface graphique CyberCopilot."""

import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

import uvicorn
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.exceptions import StarletteHTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.detector import detect_all
from src.enricher import enrich
from src.llm_client import analyze_incident, chat as llm_chat, get_stats
from src.parser import parse_file

from web import auth, db


load_dotenv()
auth.init_users_table()

BASE_DIR = Path(__file__).resolve().parent

# Secret key — depuis env var en prod, sinon généré (utile pour dev local)
SECRET_KEY = os.getenv("SESSION_SECRET") or secrets.token_urlsafe(32)
IS_PRODUCTION = os.getenv("ENV", "development") == "production"

app = FastAPI(
    title="CyberCopilot",
    description="Assistant SOC intelligent basé sur les LLM",
    version="1.0",
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    https_only=IS_PRODUCTION,
    same_site="lax",
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


def render(request: Request, name: str, **context):
    """Wrapper pour rendre un template avec la bonne signature."""
    return templates.TemplateResponse(request, name, context)


def get_current_user(request: Request) -> dict:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    user = auth.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


# ════════════════════════════════════════════════════════════════════════
# ROUTES PUBLIQUES — AUTH
# ════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    """Landing page publique."""
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard", status_code=303)
    return render(request, "landing.html")


@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    return render(request, "signup.html", error=None)


@app.post("/signup")
def signup(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(""),
):
    if len(password) < 6:
        return render(request, "signup.html", error="Mot de passe trop court (6 caractères minimum)")
    user_id = auth.create_user(email, password, full_name)
    if user_id is None:
        return render(request, "signup.html", error="Cet email est déjà utilisé")
    request.session["user_id"] = user_id
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return render(request, "login.html", error=None)


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    user = auth.authenticate(email, password)
    if not user:
        return render(request, "login.html", error="Email ou mot de passe incorrect")
    request.session["user_id"] = user["id"]
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ════════════════════════════════════════════════════════════════════════
# ROUTES PROTÉGÉES
# ════════════════════════════════════════════════════════════════════════

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    severity: str | None = None,
    status: str | None = None,
    attack: str | None = None,
    user: dict = Depends(get_current_user),
):
    all_incidents = db.list_incidents_for_user(user["id"])
    # Filtres
    incidents = all_incidents
    if severity:
        incidents = [i for i in incidents if i.get("severity") == severity]
    if status:
        incidents = [i for i in incidents if (i.get("status") or "pending") == status]
    if attack:
        incidents = [i for i in incidents if i.get("attack_type") == attack]
    stats = db.stats_for_user(user["id"])
    attack_types = sorted({i.get("attack_type") for i in all_incidents if i.get("attack_type")})
    return render(
        request, "dashboard.html",
        user=user, incidents=incidents, stats=stats,
        attack_types=attack_types,
        current_filters={"severity": severity, "status": status, "attack": attack},
    )


@app.get("/stats", response_class=HTMLResponse)
def stats_page(request: Request, user: dict = Depends(get_current_user)):
    """Page de statistiques avec graphiques."""
    stats = db.stats_for_user(user["id"])
    llm_stats = get_stats()
    incidents = db.list_incidents_for_user(user["id"])
    # Pour le graphique temporel : nb incidents par jour
    timeline = {}
    for inc in incidents:
        date = (inc.get("timestamp") or "")[:10]
        if date:
            timeline[date] = timeline.get(date, 0) + 1
    timeline_sorted = sorted(timeline.items())
    return render(
        request, "stats.html",
        user=user, stats=stats, llm_stats=llm_stats,
        timeline=timeline_sorted,
    )


@app.get("/chat", response_class=HTMLResponse)
def chat_page(request: Request, user: dict = Depends(get_current_user)):
    """Page de chat avec l'assistant."""
    history = request.session.get(f"chat_{user['id']}", [])
    return render(request, "chat.html", user=user, history=history)


@app.post("/chat")
def chat_post(
    request: Request,
    message: str = Form(...),
    user: dict = Depends(get_current_user),
):
    """Envoie un message au LLM et récupère la réponse."""
    history_key = f"chat_{user['id']}"
    history = request.session.get(history_key, [])
    incidents = db.list_incidents_for_user(user["id"])
    context = "\n".join(
        f"#{inc['id']} [{inc['severity']}] {inc['attack_type']} "
        f"depuis {inc['source_ip']} — {inc.get('summary', '')}"
        for inc in incidents[:10]
    ) or "Aucun incident enregistré pour cet utilisateur."
    answer = llm_chat(message, context=context)
    history.append({"user": message, "assistant": answer})
    history = history[-20:]
    request.session[history_key] = history
    return RedirectResponse("/chat", status_code=303)


@app.get("/chat/clear")
def chat_clear(request: Request, user: dict = Depends(get_current_user)):
    request.session.pop(f"chat_{user['id']}", None)
    return RedirectResponse("/chat", status_code=303)


def _build_report_html(user: dict, incidents: list) -> str:
    """Construit le HTML du rapport SOC stylisé."""
    from datetime import datetime
    sev_color = {
        "critical": "#EF4444",
        "high": "#F97316",
        "medium": "#EAB308",
        "low": "#22C55E",
    }
    sev_label = {
        "critical": "🔴 CRITIQUE",
        "high": "🟠 ÉLEVÉ",
        "medium": "🟡 MOYEN",
        "low": "🟢 FAIBLE",
    }
    rows = []
    for inc in incidents:
        recos = json.loads(inc["recommendation"]) if inc.get("recommendation") else []
        recos_html = "".join(f"<li>{r}</li>" for r in recos)
        color = sev_color.get(inc["severity"], "#94A3B8")
        label = sev_label.get(inc["severity"], inc["severity"].upper())
        status = inc.get("status") or "pending"
        status_label = {
            "pending": "⏳ En attente",
            "handled": "✅ Traité",
            "false_positive": "❌ Faux positif",
            "skipped": "⏭️ Passé",
        }.get(status, status)
        rows.append(f"""
<div style="border-left:4px solid {color};padding:18px;margin:16px 0;background:#F8FAFC;border-radius:6px;page-break-inside:avoid">
  <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:8px">
    <h3 style="margin:0;color:#0F1729;font-size:16pt">Incident #{inc['id']} — {inc['attack_type']}</h3>
    <span style="background:{color};color:#fff;padding:3px 10px;border-radius:12px;font-size:9pt;font-weight:bold">{label}</span>
  </div>
  <table style="font-size:10pt;color:#475569;margin-bottom:12px">
    <tr><td style="padding:2px 8px 2px 0"><b>Statut :</b></td><td>{status_label}</td></tr>
    <tr><td style="padding:2px 8px 2px 0"><b>IP source :</b></td><td><code>{inc['source_ip']}</code></td></tr>
    <tr><td style="padding:2px 8px 2px 0"><b>Date :</b></td><td>{inc['timestamp'][:19]}</td></tr>
  </table>
  <div style="background:#fff;padding:12px;border-radius:4px;margin-bottom:12px">
    <div style="font-size:9pt;color:#06B6D4;font-weight:bold;margin-bottom:4px;text-transform:uppercase">Résumé</div>
    <div style="font-size:10pt">{inc['summary']}</div>
  </div>
  <div>
    <div style="font-size:9pt;color:#06B6D4;font-weight:bold;margin-bottom:4px;text-transform:uppercase">Actions recommandées</div>
    <ol style="font-size:10pt;margin:4px 0 0 20px;padding:0">{recos_html}</ol>
  </div>
</div>
""")
    today = datetime.now().strftime("%d/%m/%Y à %H:%M")
    if not incidents:
        synthese = "<p>Aucun incident enregistré.</p>"
    else:
        synthese = (
            f"<p>Le présent rapport présente {len(incidents)} incident(s) "
            "détecté(s) et analysé(s) par l'assistant CyberCopilot. Chaque "
            "incident a été classé selon le standard CVSS 3.1 et accompagné "
            "de recommandations d'action priorisées.</p>"
        )
    detail = "".join(rows) if rows else (
        '<p style="color:#64748B;font-style:italic">Aucun incident à afficher.</p>'
    )
    user_label = user.get("full_name") or user["email"]
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><title>Rapport SOC — CyberCopilot</title>
<style>
@page {{ size: A4; margin: 1.5cm 2cm 2cm 2cm; @bottom-center {{ content: counter(page) " / " counter(pages); font-size: 9pt; color: #64748B; }} }}
body {{ font-family: -apple-system, 'Segoe UI', sans-serif; color: #0F1729; }}
h1 {{ color: #0F1729; border-bottom: 3px solid #06B6D4; padding-bottom: 10px; }}
h2 {{ color: #06B6D4; border-bottom: 1px solid #E2E8F0; padding-bottom: 6px; margin-top: 30px; }}
.meta {{ background: #F1F5F9; padding: 12px 16px; border-radius: 6px; font-size: 10pt; margin-bottom: 24px; }}
.meta b {{ color: #0F1729; }}
.footer-note {{ text-align: center; font-size: 9pt; color: #64748B; margin-top: 40px; }}
</style>
</head>
<body>
<h1>🛡️ Rapport d'incidents SOC — CyberCopilot</h1>
<div class="meta">
  <b>Analyste :</b> {user_label}<br>
  <b>Email :</b> {user['email']}<br>
  <b>Date de génération :</b> {today}<br>
  <b>Nombre d'incidents :</b> {len(incidents)}<br>
  <b>Conformité :</b> Données anonymisées (RGPD) — Permissions chmod 600
</div>

<h2>Synthèse</h2>
{synthese}

<h2>Détail des incidents</h2>
{detail}

<div class="footer-note">
  Document généré par CyberCopilot — Projet B2 2026<br>
  github.com/abdoul-latif-dev/cybercopilot
</div>
</body></html>"""


@app.get("/export")
def export_report(
    request: Request,
    fmt: str = "pdf",
    user: dict = Depends(get_current_user),
):
    """Exporte le rapport au format PDF (par défaut) ou Markdown.

    L'URL /export?fmt=md permet de récupérer la version Markdown.
    """
    from fastapi.responses import Response
    incidents = db.list_incidents_for_user(user["id"])
    username = user["email"].split("@")[0]

    if fmt.lower() in ("md", "markdown"):
        # Version Markdown (fallback)
        lines = [
            f"# Rapport d'incidents SOC — {user.get('full_name') or user['email']}",
            "",
            f"Généré pour : **{user['email']}**",
            f"Nombre d'incidents : **{len(incidents)}**",
            "",
            "---",
            "",
        ]
        for inc in incidents:
            recos = json.loads(inc["recommendation"]) if inc.get("recommendation") else []
            lines.append(f"## Incident #{inc['id']} — {inc['attack_type']}")
            lines.append(f"- **Sévérité :** {inc['severity']}")
            lines.append(f"- **Statut :** {inc.get('status') or 'pending'}")
            lines.append(f"- **IP source :** {inc['source_ip']}")
            lines.append(f"- **Date :** {inc['timestamp']}")
            lines.append("")
            lines.append(f"**Résumé :** {inc['summary']}")
            lines.append("")
            lines.append("**Actions recommandées :**")
            for r in recos:
                lines.append(f"- {r}")
            lines.append("")
            lines.append("---")
            lines.append("")
        return Response(
            content="\n".join(lines),
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="rapport-soc-{username}.md"'},
        )

    # PDF par défaut
    html = _build_report_html(user, incidents)
    try:
        from weasyprint import HTML
        pdf_bytes = HTML(string=html).write_pdf()
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="rapport-soc-{username}.pdf"'},
        )
    except ImportError:
        # Fallback Markdown si weasyprint indisponible
        return Response(
            content=html,
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="rapport-soc-{username}.html"'},
        )


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: dict = Depends(get_current_user)):
    return render(request, "settings.html", user=user, message=None, error=None)


@app.post("/settings/password")
def change_password(
    request: Request,
    current: str = Form(...),
    new_password: str = Form(...),
    user: dict = Depends(get_current_user),
):
    if not auth.verify_password(current, user["password_hash"]):
        return render(request, "settings.html", user=user, message=None, error="Mot de passe actuel incorrect")
    if len(new_password) < 6:
        return render(request, "settings.html", user=user, message=None, error="Nouveau mot de passe trop court (6 caractères minimum)")
    import sqlite3
    conn = sqlite3.connect(auth.DB_PATH)
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                 (auth.hash_password(new_password), user["id"]))
    conn.commit()
    conn.close()
    return render(request, "settings.html", user=auth.get_user_by_id(user["id"]),
                  message="Mot de passe modifié avec succès", error=None)


@app.post("/settings/purge")
def purge_all_incidents(request: Request, user: dict = Depends(get_current_user)):
    """Supprime tous les incidents de l'utilisateur (RGPD — droit à l'oubli)."""
    import sqlite3
    conn = sqlite3.connect(auth.DB_PATH)
    cursor = conn.execute("DELETE FROM incidents WHERE user_id = ?", (user["id"],))
    n = cursor.rowcount
    conn.commit()
    conn.close()
    return render(request, "settings.html", user=user,
                  message=f"{n} incident(s) supprimé(s) (RGPD)", error=None)


@app.get("/upload", response_class=HTMLResponse)
def upload_page(request: Request, user: dict = Depends(get_current_user)):
    return render(request, "upload.html", user=user, result=None, error=None)


@app.post("/upload", response_class=HTMLResponse)
async def upload_analyze(
    request: Request,
    file: UploadFile = File(...),
    user: dict = Depends(get_current_user),
):
    """Upload + analyse simultanée de TOUS les types d'attaque.

    L'anonymisation RGPD est TOUJOURS appliquée (politique permanente).
    """
    content = await file.read()
    if not content:
        return render(request, "upload.html", user=user, error="Fichier vide", result=None)

    suffix = Path(file.filename).suffix or ".log"
    with tempfile.NamedTemporaryFile(
        suffix="_" + (file.filename or f"upload{suffix}"),
        delete=False,
        mode="wb",
    ) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        events = parse_file(tmp_path)
        # detect_all() applique TOUTES les détections (brute force, SQLi, scan, DDoS,
        # admin, horaire) en simultané + calcul de sévérité CVSS avec réputation IP
        incidents = detect_all(events, enricher_fn=enrich)
        anon = True  # RGPD permanent — non négociable

        saved = []
        for incident in incidents:
            info = enrich(incident.source_ip)
            data = {
                "source_ip": incident.source_ip,
                "attack_type": incident.attack_type,
                "severity": incident.severity,
                "severity_score": incident.severity_score,
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
            analysis = analyze_incident(data, anonymize=anon)
            # ⚠️ La sévérité CVSS et le type d'attaque restent ceux du DÉTECTEUR
            # (basés sur le standard CVSS 3.1 et les règles fixes).
            # Le LLM ne fournit que le résumé et les recommandations.
            incident_id = db.save_incident_for_user(
                user_id=user["id"],
                source_ip=incident.source_ip,
                attack_type=incident.attack_type,           # ← jamais écrasé
                severity=incident.severity,                  # ← jamais écrasé
                summary=analysis.get("summary", ""),
                raw_logs=incident.sample_logs,
                recommendation=analysis.get("recommendations", []),
            )
            saved.append({
                "id": incident_id,
                "type": incident.attack_type,
                "ip": incident.source_ip,
                "country": info["country"],
                "severity": incident.severity,
                "summary": analysis.get("summary"),
            })

        return render(
            request, "upload.html",
            user=user,
            result={"filename": file.filename, "events": len(events), "incidents": saved},
            error=None,
        )
    finally:
        tmp_path.unlink(missing_ok=True)


@app.get("/incidents/{incident_id}", response_class=HTMLResponse)
def incident_detail(
    request: Request,
    incident_id: int,
    user: dict = Depends(get_current_user),
):
    incident = db.get_incident_for_user(user["id"], incident_id)
    if not incident:
        return RedirectResponse("/dashboard", status_code=303)
    incident["raw_logs_list"] = (
        json.loads(incident["raw_logs"]) if incident.get("raw_logs") else []
    )
    incident["recommendations_list"] = (
        json.loads(incident["recommendation"]) if incident.get("recommendation") else []
    )
    return render(request, "incident.html", user=user, incident=incident)


@app.post("/incidents/{incident_id}/status")
def update_incident_status(
    request: Request,
    incident_id: int,
    status: str = Form(...),
    note: str = Form(""),
    user: dict = Depends(get_current_user),
):
    db.update_status_for_user(user["id"], incident_id, status, note)
    return RedirectResponse(f"/incidents/{incident_id}", status_code=303)


@app.post("/incidents/{incident_id}/delete")
def delete_incident_route(
    request: Request,
    incident_id: int,
    user: dict = Depends(get_current_user),
):
    db.delete_incident_for_user(user["id"], incident_id)
    return RedirectResponse("/dashboard", status_code=303)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Gestionnaire d'erreurs personnalisé (404, 500, etc.)."""
    if exc.status_code == 303 and "Location" in (exc.headers or {}):
        return RedirectResponse(url=exc.headers["Location"], status_code=303)
    if exc.status_code in (404, 500):
        return render(request, "error.html", code=exc.status_code, detail=str(exc.detail))
    return render(request, "error.html", code=exc.status_code, detail=str(exc.detail))


@app.get("/healthz")
def healthcheck():
    """Endpoint pour le monitoring (Render, Uptime, etc.)."""
    return {"status": "ok", "service": "cybercopilot"}


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    reload = not IS_PRODUCTION
    uvicorn.run("web.app:app", host=host, port=port, reload=reload)
