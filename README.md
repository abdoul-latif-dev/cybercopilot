# 🛡️ CyberCopilot

> Assistant SOC intelligent basé sur les modèles de langage (LLM). Transforme des milliers de lignes de logs en résumés clairs et actions concrètes pour les analystes cybersécurité.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-prototype-orange.svg)]()

---

## 📚 Documentation du projet

Le dossier [`docs/`](./docs/) contient tous les livrables académiques :

| N° | Livrable | Description |
|---|---|---|
| 1 | [Cahier des charges](./docs/livrable-1-cahier-des-charges.pdf) | Besoin, périmètre, architecture, sécurité |
| 2 | [Raison d'être](./docs/livrable-2-raison-etre.pdf) | Contexte, problématique, finalité |
| 3 | [État de l'art & marché](./docs/livrable-3-etat-de-lart.pdf) | SIEM, SOAR, LLM + marché français |
| 4 | [Business Plan](./docs/livrable-4-business-plan.pdf) | Modèle SaaS B2B, projections 3 ans |
| 5 | [Brief Figma](./docs/livrable-5-brief-figma.pdf) | Design system + 10 écrans |
| 6 | [Architecture technique](./docs/livrable-6-architecture-technique.pdf) | Modules, flux, performances |
| — | [Répartition équipe](./docs/repartition-equipe.pdf) | Qui fait quoi |

---

## 📖 Présentation

**CyberCopilot** est un assistant SOC (Security Operations Center) qui aide les analystes cybersécurité à traiter le volume massif d'alertes auxquelles ils font face quotidiennement.

Le principe : au lieu de parcourir manuellement des milliers de lignes de logs, l'analyste laisse l'assistant **détecter automatiquement les patterns d'attaque**, **enrichir le contexte** (géolocalisation IP, réputation), puis **générer un résumé clair et des recommandations d'action** grâce à un modèle de langage.

L'objectif n'est pas de remplacer l'analyste, mais de lui fournir un **copilote** qui accélère son travail et améliore la qualité de ses décisions.

---

## ✨ Fonctionnalités

### Détection automatique
- 🔍 **Brute force SSH** — détection par seuil d'échecs de connexion
- 💉 **Injections SQL** — reconnaissance de patterns dans les URL HTTP
- 🌐 **Scans de ports** — analyse de la diversité des ports cibles
- 🔐 **Accès admin suspects** — détection de chemins sensibles
- ⏰ **Connexions horaires anormales** — entre 02h et 05h

### Analyse intelligente
- 🧠 Génération de résumés en **langage naturel** (français) via LLM
- 📊 Classification de **sévérité** (critique / élevé / moyen / faible)
- ✅ **Recommandations d'action** priorisées
- 💬 Mode **conversationnel** pour poser des questions

### Optimisation et sécurité
- 🗜️ **Compression intelligente** des logs (67 % d'économie de tokens mesurée)
- 💾 **Cache des analyses** pour éviter les appels redondants
- 🛡️ **Mode dégradé automatique** si l'API LLM est indisponible
- 🔒 **Anonymisation** activable des IP internes et noms d'utilisateurs (RGPD)
- 🗑️ **Suppression d'incidents** sur demande (droit à l'oubli RGPD)
- 🔐 Permissions **chmod 600** sur la base de données

---

## 🚀 Démarrage rapide

### Prérequis
- Python **3.11** ou plus récent
- Linux ou macOS (testé sur Kali Linux)

### Installation

```bash
git clone https://github.com/VOTRE-USER/cybercopilot.git
cd cybercopilot
pip install -r requirements.txt
cp .env.example .env
```

### Configuration

Éditez le fichier `.env` et ajoutez votre clé API :

```bash
OPENAI_API_KEY=sk-proj-votre-cle-ici
LLM_MODEL=gpt-4o-mini
```

> 💡 **Sans clé API**, le projet fonctionne en **mode dégradé** : les détections sont effectuées par règles statiques, et les résumés sont générés à partir de templates.

### Lancement

**Mode interactif (recommandé) :**
```bash
python app.py
```

Un menu s'affiche, vous naviguez avec les chiffres.

**Mode ligne de commande :**
```bash
python main.py analyze data/logs/auth.log
python main.py list
python main.py show 1
python main.py chat
python main.py export -o rapport.md
python main.py stats
```

---

## 🏗️ Architecture

Le projet est organisé en **6 modules indépendants** articulés en pipeline :

```
   Fichiers de logs
          │
          ▼
   1. Parser              → extrait les événements structurés
          │
          ▼
   2. Détecteur           → applique les règles de détection
          │
          ▼
   3. Enrichisseur        → ajoute le contexte (géoloc, réputation IP)
          │
          ▼
   4. Client LLM          → produit le résumé et les recommandations
          │
          ▼
   5. Stockage            → persiste les incidents (SQLite)
          │
          ▼
   6. Interface CLI       → présente les résultats à l'analyste
```

### Stack technique

| Composant | Technologie | Rôle |
|---|---|---|
| Langage | Python 3.11 | Standard cybersécurité et IA |
| LLM | OpenAI / Anthropic | Analyse sémantique |
| Modèle | gpt-4o-mini | Bon rapport performance/coût |
| Base de données | SQLite | Sans serveur, fichier unique |
| Interface | Rich | Affichage terminal coloré |
| Configuration | python-dotenv | Gestion des secrets |
| Tests | pytest | Tests unitaires |

### Structure du code

```
cybercopilot/
├── app.py                Menu interactif (point d'entrée principal)
├── main.py               Interface en ligne de commande
├── src/
│   ├── parser.py         Parsing des logs (SSH, Apache, firewall)
│   ├── detector.py       Règles de détection des 5 types d'attaques
│   ├── enricher.py       Enrichissement IP (géolocalisation, réputation)
│   ├── llm_client.py     Appels API LLM + mode dégradé
│   ├── prompts.py        Templates de prompts
│   ├── compressor.py     Compression intelligente des logs
│   ├── cache.py          Cache des analyses
│   ├── anonymizer.py     Anonymisation RGPD
│   ├── storage.py        Accès SQLite
│   └── cli.py            Affichage Rich
├── data/
│   ├── logs/             Logs de test (auth, access, firewall)
│   └── threat_intel.json Base IP malveillantes
├── tests/                Tests pytest
├── requirements.txt
├── .env.example
└── .gitignore
```

---

## 📚 Utilisation détaillée

### Le menu interactif

Lancez `python app.py` et choisissez parmi 13 options :

| # | Action |
|---|---|
| 1 | 🔍 Détecter des intrusions (brute force SSH) |
| 2 | 💉 Détecter des injections SQL |
| 3 | 🌐 Détecter un scan de ports |
| 4 | 🔄 Analyser tous les logs disponibles |
| 5 | 📋 Voir la liste des incidents détectés |
| 6 | 🔎 Voir le détail d'un incident |
| 7 | 💬 Discuter avec l'assistant |
| 8 | 📊 Statistiques (tokens, économies) |
| 9 | 📤 Exporter un rapport Markdown |
| 10 | 🗑️ Supprimer un incident (RGPD) |
| 11 | 🧹 Vider toute la base d'incidents |
| 12 | 🔐 Activer / désactiver l'anonymisation |
| 0 | 🚪 Quitter |

### Exemple de sortie

```
╭───── INCIDENT #1  🔴 CRITIQUE ─────────────────────────────────╮
│ Type      : brute_force_ssh                                    │
│ IP source : 203.0.113.50 (Russie — malicious)                  │
│ Période   : 08:30:01 → 08:30:10                                │
│ Volume    : 17 événement(s)                                    │
│                                                                │
│ RÉSUMÉ                                                         │
│ Attaque par force brute SSH détectée depuis 203.0.113.50.      │
│ 17 tentatives échouées sur les comptes root, admin, postgres.  │
│                                                                │
│ ACTIONS RECOMMANDÉES                                           │
│   1. Bloquer l'IP 203.0.113.50 au niveau du firewall           │
│   2. Vérifier qu'aucune connexion n'a réussi                   │
│   3. Activer fail2ban si pas déjà en place                     │
│   4. Désactiver l'authentification SSH par mot de passe        │
╰────────────────────────────────────────────────────────────────╯
```

---

## 🔒 Sécurité

Ce projet intègre plusieurs mécanismes de sécurité dès la conception :

- **Clés API** stockées dans un fichier `.env` exclu de Git
- **Anonymisation optionnelle** des IP internes et noms d'utilisateurs avant envoi au LLM
- **Permissions restreintes** (chmod 600) sur la base SQLite
- **Requêtes SQL paramétrées** (protection contre les injections)
- **Rate limiting** interne sur les appels au LLM
- **Mode dégradé** garantissant la continuité de service
- **Suppression à la demande** (droit à l'oubli RGPD)

⚠️ **Ne jamais commiter le fichier `.env` contenant la vraie clé API.**

---

## 💰 Optimisation des coûts LLM

Le projet économise jusqu'à **70 % de tokens** grâce à trois mécanismes :

1. **Compression intelligente** des logs répétitifs (`[100x] motif` au lieu de 100 lignes)
2. **Cache** des analyses par IP + type + bucket de volume
3. **Choix d'un modèle économique** (gpt-4o-mini par défaut)

La commande `python main.py stats` affiche en temps réel les économies réalisées.

---

## 🧪 Tests

```bash
pytest tests/
```

---

## 📋 Roadmap

- [x] MVP fonctionnel avec 5 types d'attaques
- [x] Mode dégradé et résilience
- [x] Optimisation des tokens (compression + cache)
- [x] Anonymisation RGPD
- [x] Menu interactif
- [ ] Tests unitaires pytest complets
- [ ] Intégration MITRE ATT&CK
- [ ] Connexion à un vrai SIEM (Wazuh, ELK)
- [ ] Interface web (FastAPI + React)
- [ ] LLM local (Mistral) pour la souveraineté
- [ ] Module de réponse automatique (blocage IP)

---

## 📄 Licence

MIT — Ce projet est un projet académique réalisé dans le cadre de la validation B2.

---

## 👤 Auteur

Projet de validation — Année B2 — 2026

---

## 🔗 Liens utiles

- [Documentation Python](https://docs.python.org/3/)
- [API OpenAI](https://platform.openai.com/docs)
- [API Anthropic](https://docs.anthropic.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [ANSSI](https://www.ssi.gouv.fr/)
- [Campus Cyber](https://campuscyber.fr/)
