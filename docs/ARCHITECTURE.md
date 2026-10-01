# Architecture — PhishingAI en production

## État actuel

```
fichier .eml (CLI)
       │
       ▼
  analyzer.py
       │
       ▼
  Ollama local (llama3)
       │
       ▼
  JSON verdict (stdout)
```

Script CLI local, sans exposition réseau, sans authentification. Suffisant pour un POC, pas pour une intégration.

---

## Cible : API HTTP intégrable

```
PhishER / SOAR
       │  POST /analyze (.eml)
       │  Header: X-API-Key: ***
       ▼
  ┌─────────────┐
  │  api.py     │  FastAPI
  │  (HTTP)     │
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │ analyzer.py │  Inchangé
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │ LLM Backend │  abstraction à construire
  └─────────────┘
```

---

## Problème 1 — Exposition et sécurité de l'API

### Ce qu'il faut construire

- `api.py` — serveur FastAPI avec un endpoint `POST /analyze`
- Authentification par API key en header (`X-API-Key`)
- L'endpoint reçoit un fichier `.eml` en multipart et retourne le JSON verdict

### Endpoint cible

```
POST /analyze
Header: X-API-Key: <clé>
Body:   multipart/form-data, champ "file" = fichier .eml

Réponse 200 :
{
  "verdict": "malveillant",
  "score": 85,
  "raisons": [...],
  "tags": [...],
  "recommandation": "..."
}
```

### Options de déploiement

| Option | Description | Complexité |
|--------|-------------|------------|
| Script direct | Lancer `uvicorn api:app` sur la machine | Minimale |
| Docker | Conteneuriser FastAPI + Ollama | Faible |
| Docker Compose | FastAPI + Ollama + reverse proxy Nginx | Moyenne |

---

## Problème 2 — Flexibilité du backend LLM

Aujourd'hui le code appelle Ollama en dur. En production on veut pouvoir choisir le backend sans modifier `analyzer.py`.

### Backends envisageables

| Backend | Avantages | Inconvénients |
|---------|-----------|---------------|
| **Ollama local** | Gratuit, air-gappé, données ne sortent pas | Nécessite du matériel, GPU recommandé |
| **Ollama sur GPU distant** | Modèles plus grands, plus rapide | Infra à gérer, réseau interne |
| **API Anthropic (Claude)** | Pas d'infra, modèles puissants, SLA | Coût à l'usage, données sortent |
| **API OpenAI (GPT-4o)** | Idem | Idem |
| **Azure OpenAI** | Données en région EU, contrat entreprise | Coût, configuration |

### Abstraction à construire

Créer une interface `LLMBackend` dans `analyzer.py` pilotée par variable d'environnement :

```
LLM_BACKEND=ollama      → appel Ollama (comportement actuel)
LLM_BACKEND=anthropic   → appel Claude API
LLM_BACKEND=openai      → appel GPT-4o
```

Le prompt, les règles de décision et le post-processing Python restent identiques quel que soit le backend.

---

## Problème 3 — Accessibilité réseau

La question clé : **où tourne chaque composant ?**

```
┌──────────────────┬──────────────────┬───────────────┬──────────────────────────────────────┐
│ PhishER          │ API PhishingAI   │ LLM           │ Contrainte réseau                    │
├──────────────────┼──────────────────┼───────────────┼──────────────────────────────────────┤
│ SaaS (KnowBe4)   │ On-premise       │ Ollama local  │ API exposée publiquement (TLS requis) │
│ On-premise       │ On-premise       │ Ollama local  │ Réseau local uniquement, aucun risque │
│ On-premise       │ Cloud (VPS)      │ API Claude    │ Simple, tout HTTPS                   │
│ SaaS (KnowBe4)   │ Cloud (VPS)      │ API Claude    │ Simple, tout HTTPS, coût LLM         │
└──────────────────┴──────────────────┴───────────────┴──────────────────────────────────────┘
```

### Scénarios d'exposition

**Tout on-premise** *(recommandé si infrastructure disponible)*
- PhishER on-premise appelle l'API sur le réseau local
- Ollama sur un serveur GPU interne
- Les emails ne sortent jamais du réseau

**API exposée publiquement** *(si PhishER SaaS)*
- Reverse proxy Nginx + certificat TLS (Let's Encrypt)
- API key obligatoire
- Seules les URLs sont envoyées à VirusTotal — le contenu des emails reste sur le serveur

**Full cloud** *(le plus simple à déployer)*
- API déployée sur un VPS (Scaleway, OVH, AWS…)
- Backend LLM = API Anthropic ou OpenAI
- Pas d'infra Ollama à gérer, coût à l'usage selon volume

---

## Questions à trancher avant de coder

| Question | Impact |
|----------|--------|
| PhishER est-il SaaS ou on-premise ? | Détermine si l'API doit être exposée publiquement |
| Les emails peuvent-ils sortir du réseau ? | Détermine si on peut utiliser Claude/OpenAI ou si Ollama est obligatoire |
| Quel volume d'emails par jour ? | Détermine si le coût API est acceptable vs infra GPU |
| GPU disponible en interne ? | Détermine la faisabilité d'Ollama sur serveur dédié |

---

## Prochaines étapes techniques

1. **`api.py`** — FastAPI, endpoint `POST /analyze`, authentification API key
2. **Abstraction LLM** — variable d'environnement `LLM_BACKEND` dans `analyzer.py`
3. **`docker-compose.yml`** — conteneurisation FastAPI + Ollama
4. **Reverse proxy** — Nginx + TLS si exposition publique nécessaire

---

## Stratégie de modèles (référence)

| Modèle | Benchmark F1 | RAM | Usage recommandé |
|--------|-------------|-----|-----------------|
| `llama3` (8B) | **90,8 %** | 8 Go | Production — meilleur équilibre |
| `qwen2.5vl:7b` | 87,1 % | 8 Go | Alternatif, plus de FP |
| `mistral-nemo` (12B) | 67,7 % | 16 Go | Pré-filtrage uniquement (trop de FP en strict) |
| `llama3.1:70b-q3` | non testé | 32 Go | Analyse approfondie des cas ambigus |
| `claude-sonnet-4-6` | non testé | — (API) | Option cloud sans infra Ollama |
