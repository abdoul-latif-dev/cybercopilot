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


@app.get("/export")
def export_report(
    request: Request,
    fmt: str = "markdown",
    user: dict = Depends(get_current_user),
):
    """Exporte un rapport Markdown de tous les incidents de l'utilisateur."""
    incidents = db.list_incidents_for_user(user["id"])
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

    content = "\n".join(lines)
    from fastapi.responses import Response
    filename = f"rapport-soc-{user['email'].split('@')[0]}.md"
    return Response(
        content=content,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
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
    anonymize: str = Form(""),
    user: dict = Depends(get_current_user),
):
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
        incidents = detect_all(events)
        anon = bool(anonymize)

        saved = []
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
            analysis = analyze_incident(data, anonymize=anon)
            incident_id = db.save_incident_for_user(
                user_id=user["id"],
                source_ip=incident.source_ip,
                attack_type=analysis.get("attack_type", incident.attack_type),
                severity=analysis.get("severity", incident.severity),
                summary=analysis.get("summary", ""),
                raw_logs=incident.sample_logs,
                recommendation=analysis.get("recommendations", []),
            )
            saved.append({
                "id": incident_id,
                "type": incident.attack_type,
                "ip": incident.source_ip,
                "country": info["country"],
                "severity": analysis.get("severity"),
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
