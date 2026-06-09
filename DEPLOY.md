# 🚀 Déploiement de CyberCopilot

Ce guide explique comment déployer CyberCopilot en production sur **Render** (gratuit) ou en local.

---

## 📦 Option 1 — Déploiement sur Render (recommandé)

### Pourquoi Render ?
- ✅ Plan gratuit suffisant pour la démo
- ✅ HTTPS automatique
- ✅ Déploiement depuis GitHub en 2 minutes
- ✅ Domaine fourni (`xxx.onrender.com`)

### Étapes

**1. Créer un compte Render**
- Va sur https://render.com
- Connecte-toi avec ton compte GitHub

**2. Créer un nouveau Web Service**
- Clique **New +** → **Web Service**
- Sélectionne le repo `cybercopilot`
- Render détecte automatiquement le fichier `render.yaml`

**3. Configurer les variables d'environnement**

Dans **Environment** :
- `OPENAI_API_KEY` : ta clé API OpenAI (optionnel, mode dégradé sinon)
- `LLM_MODEL` : `gpt-4o-mini` (déjà préconfiguré)
- `SESSION_SECRET` : généré automatiquement par Render
- `ENV` : `production`

**4. Cliquer Deploy**

Render va :
1. Cloner le repo
2. Installer `requirements.txt`
3. Démarrer l'app avec `uvicorn web.app:app`
4. T'attribuer une URL : `https://cybercopilot.onrender.com`

**5. Tester l'application**
- Va sur ton URL Render
- Crée un compte
- Upload un fichier de logs
- Vérifie que tout marche

### Limitations du plan gratuit
- ⚠️ L'app **s'endort** après 15 min d'inactivité (réveil en ~30 sec au prochain accès)
- ⚠️ La base SQLite est **éphémère** (perte des données entre déploiements)

Pour la démo au prof, c'est suffisant.

---

## 🏠 Option 2 — Lancement en local

### Prérequis
- Python 3.11+
- Git

### Étapes

```bash
# 1. Cloner le projet
git clone https://github.com/abdoul-latif-dev/cybercopilot.git
cd cybercopilot

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Copier la config
cp .env.example .env
# Éditer .env et ajouter OPENAI_API_KEY si tu en as une

# 4. Lancer le serveur
python web/app.py
```

L'app sera accessible sur **http://localhost:8000**

---

## 🐳 Option 3 — Docker (avancé)

Si tu veux containeriser l'app, créer un `Dockerfile` :

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
ENV ENV=production
CMD ["uvicorn", "web.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

Puis :
```bash
docker build -t cybercopilot .
docker run -p 8000:8000 -e OPENAI_API_KEY="..." cybercopilot
```

---

## 🔐 Variables d'environnement

| Variable | Obligatoire | Valeur par défaut | Description |
|---|---|---|---|
| `OPENAI_API_KEY` | Non | — | Clé API OpenAI (fallback si absente) |
| `LLM_MODEL` | Non | `gpt-4o-mini` | Modèle LLM à utiliser |
| `SESSION_SECRET` | Production | aléatoire | Clé pour signer les sessions |
| `ENV` | Non | `development` | `production` pour activer HTTPS-only |
| `PORT` | Non | `8000` | Port d'écoute |
| `HOST` | Non | `0.0.0.0` | Adresse d'écoute |

---

## 🧪 Test après déploiement

Une fois en ligne, vérifie ces endpoints :

```bash
# Health check
curl https://ton-app.onrender.com/healthz
# → {"status": "ok", "service": "cybercopilot"}

# Page d'accueil
curl -I https://ton-app.onrender.com/
# → HTTP/2 200

# Inscription
curl -X POST https://ton-app.onrender.com/signup \
  -d "email=test@test.fr&password=test1234"
```

---

## 🆘 Problèmes fréquents

### L'app ne démarre pas sur Render
- Vérifier les logs : **Logs** dans le dashboard Render
- Vérifier que `requirements.txt` est complet
- Vérifier que `web.app:app` est bien le chemin du module

### Session perdue à chaque visite
- Vérifier que `SESSION_SECRET` est défini en production
- Sans cette variable, une nouvelle clé est générée à chaque redémarrage

### Mode dégradé permanent
- Vérifier `OPENAI_API_KEY` dans les variables d'environnement
- Si la clé est valide, vérifier le crédit du compte OpenAI
