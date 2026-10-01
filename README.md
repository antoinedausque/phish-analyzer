# PhishingAI

Detecteur de phishing local base sur un LLM. Analyse un fichier `.eml` ou `.msg` et retourne un verdict JSON structure avec score de risque, raisons, tags et recommandation.

Fonctionne entierement hors ligne via Ollama — **aucune donnee ne quitte la machine** (sauf URLs vers VirusTotal si configure).

---

## Fonctionnement

```
fichier .eml / .msg
        |
        v
   parse_eml()          extraction headers (SPF, DKIM, DMARC, From, Return-Path...)
        |                + corps (HTML/texte) + URLs
        v
  enrich_urls()         reputation URLs via VirusTotal / URLScan.io
        |                (mock si pas de cle API)
        v
  build_prompt()        construction prompt Chain-of-Thought avec tous les signaux
        |
        v
  Ollama (LLM local)    inference temperature 0.1
        |
        v
  JSON verdict          { verdict, score, raisons, tags, recommandation }
```

### Signaux analyses

| Categorie | Signaux |
|-----------|---------|
| Authentification | SPF, DKIM, DMARC / Auth-Results |
| Coherence expediteur | From <-> Return-Path, Reply-To, domaine typosquatte |
| BEC | Webmail -> domaine corporate, corps vague d'amorce |
| Contenu | Urgence artificielle, demande d'action sensible (IBAN, identifiants) |
| URLs | Votes malveillants VirusTotal, categories dangereuses |

### Regles de verdict

| Priorite | Verdict | Score | Condition |
|----------|---------|-------|-----------|
| 1 | `suspect` BEC | 60-70 | Webmail -> adresse nominative corporate + corps vague |
| 2 | `malveillant` | 70-100 | >= 2 signaux forts (SPF fail, typosquat, URL malveillante...) |
| 3 | `legitime` | 0-35 | auth_score >= 2 + domaines coherents + contenu neutre |
| 4 | `suspect` | 36-69 | Tous les autres cas (signaux mixtes) |

---

## Installation

```bash
# 1. Cloner et creer l'environnement
git clone <repo>
cd phishing
python -m venv .venv
source .venv/bin/activate       # Windows : .venv\Scripts\activate

# 2. Installer les dependances
pip install -r requirements.txt

# 3. Installer Ollama et telecharger un modele
# https://ollama.com
ollama pull llama3

# 4. (Optionnel) Configurer les APIs
cp .env.example .env
# Editer .env : ajouter VIRUSTOTAL_API_KEY et/ou URLSCAN_API_KEY
```

---

## Utilisation

### Analyser un email (CLI)

```bash
python analyzer.py chemin/vers/email.eml
# Avec un modele different :
python analyzer.py chemin/vers/email.eml qwen2.5:7b
# Email de test inclus :
python analyzer.py samples/test_phishing.eml
```

**Exemple de sortie :**
```json
{
  "verdict": "suspect",
  "score": 62,
  "raisons": [
    "Expediteur webmail (gmail.com) ecrit a un domaine corporate (bpex.fr)",
    "Corps tres court/vague demandant un contact sans contexte"
  ],
  "tags": ["bec"],
  "recommandation": "Verifiez l'authenticite de l'expediteur avant de repondre"
}
```

### Interface Streamlit

```bash
streamlit run app.py
# Ouvre http://localhost:8501
# Glisser-deposer un .eml ou .msg, choisir le modele, lancer l'analyse
```

### Exporter un email depuis Outlook

- **Mac / Windows desktop** : glisser-deposer le mail vers le bureau -> genere un `.eml`
- **Outlook Web** : `...` -> *Afficher la source du message* -> copier dans un fichier `.eml`

---

## Benchmark

```bash
# Tous les modeles par defaut (llama3, qwen2.5vl:7b)
python benchmark.py

# Modele specifique
python benchmark.py --models llama3

# Tester le pipeline sans appeler Ollama
python benchmark.py --dry-run

# Consulter les resultats
python report.py                          # dernier run
python report.py results/benchmark_*.json # run specifique
python report.py --history                # historique complet
python report.py --compare f1.json f2.json
```

Les resultats sont sauvegardes dans `results/benchmark_YYYYMMDD_HHMMSS.json`.

---

## Resultats (llama3 + VirusTotal reel, mai 2026)

161 emails, seuil strict (`malveillant` = positif).

| Type | N | Rappel | F1 | Accuracy |
|------|---|--------|----|----------|
| `legitime` | 93 | — | — | 90.3% |
| `nazario` (phishing reels) | 60 | 93.3% | 96.6% | 93.3% |
| `spoofing` | 2 | 100% | 100% | 100% |
| `spear_phishing` | 2 | 100% | 100% | 100% |
| `urgence` | 2 | 100% | 100% | 100% |
| `url_malveillante` | 2 | 100% | 100% | 100% |
| **GLOBAL** | **161** | **94.1%** | **90.8%** | **91.9%** |

**Faux positifs** : 9/93 legitimes (hallucinations LLM : typosquatting, incoh. From/Return-Path sur listes mail)
**Faux negatifs** : 4/68 classes `suspect` au lieu de `malveillant` — tous remontes a l'utilisateur, non manques

En seuil permissif (`suspect` + `malveillant` = positif) : recall **98.5%**, 1 seul phishing rate sur 68.

### Comparaison des modeles

| Modele | F1 | Precision | Rappel | FP legitimes | FN phishing |
|--------|----|-----------|--------|--------------|-------------|
| `llama3` | **90.8%** | **87.7%** | 94.1% | **9** | **4** |
| `qwen2.5vl:7b` | 87.1% | 81.0% | 94.1% | 15 | 4 |
| `mistral-nemo` | 67.7% | 51.5% | **98.5%** | 63 | **1** |

> `mistral-nemo` : excellent rappel phishing mais 63/93 faux positifs — inutilisable sans adaptation du prompt.

### Mock vs VirusTotal reel (llama3)

| Metrique | Mock URL | VirusTotal reel | Gain |
|----------|----------|-----------------|------|
| F1 global | 87.9% | **90.8%** | +2.9 pts |
| FP legitimes | 11 | **9** | -2 |
| FN phishing | 6 | **4** | -2 |
| Rappel nazario | 91.7% | **93.3%** | +1.6 pts |

---

## Dataset

161 emails labelises dans `dataset/labels.json`.

| Type | Quantite | Source |
|------|----------|--------|
| `legitime` | 93 | SpamAssassin easy_ham (2003) |
| `nazario` | 60 | Corpus Nazario (phishing reels) |
| `spoofing` | 2 | Echantillons manuels |
| `urgence` | 2 | Echantillons manuels |
| `spear_phishing` | 2 | Echantillons manuels |
| `url_malveillante` | 2 | Echantillons manuels |

> Les emails SpamAssassin datent de 2003, avant DKIM. Le prompt gere ce cas via une regle heritage pre-DKIM : SPF pass seul suffit si le contenu est neutre.

Pour enrichir le dataset depuis les corpus bruts :
```bash
# Placer les corpus dans corpus/ (cf. .gitignore)
python import_corpus.py --count 20
python import_corpus.py --dry-run --count 5
```

---

## Modeles recommandes

| Modele | F1 | RAM | Usage |
|--------|----|-----|-------|
| `llama3` (8B) | 90.8% | 8 Go | **Recommande** — meilleur equilibre |
| `qwen2.5vl:7b` | 87.1% | 8 Go | Alternatif |
| `mistral-nemo` (12B) | 67.7% | 16 Go | Pre-filtrage uniquement |
| `llama3.1:70b-q3` | — | 32 Go | Analyse approfondie (cas ambigus) |

---

## Configuration

Copier `.env.example` en `.env` :

```env
# VirusTotal — https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=votre_cle

# URLScan.io — https://urlscan.io/user/profile/
URLSCAN_API_KEY=votre_cle
```

Sans cle API, le pipeline fonctionne avec un enrichissement URL mock (signaux headers uniquement).

---

## Structure du projet

```
phishing/
├── analyzer.py          # Core : parsing email + extraction signaux + appel LLM
├── app.py               # Interface Streamlit (drag-and-drop, multilingue)
├── url_enrichment.py    # Enrichissement URLs via VirusTotal / URLScan.io
├── benchmark.py         # Runner de benchmark multi-modeles
├── import_corpus.py     # Construction du dataset depuis les corpus bruts
├── report.py            # Rapports et comparaisons de runs benchmark
│
├── dataset/
│   ├── emails/          # 161 emails labelises
│   └── labels.json      # Metadata + labels ground truth
│
├── samples/
│   └── test_phishing.eml
│
├── docs/
│   ├── ARCHITECTURE.md  # Pipeline cible, integration PhishER, options deploiement
│   ├── IMPROVEMENT.md   # Pistes d'optimisation performances (cache, async, MLX...)
│   └── benchmark_rapport.md
│
├── corpus/              # Corpus bruts (gitignore, trop lourds)
│   ├── easy_ham/        # SpamAssassin ham (2503 fichiers)
│   ├── phishing0.mbox   # Nazario phishing
│   └── phishing1.mbox
│
└── results/             # Resultats benchmark JSON (gitignore)
```

---

## Documentation

- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — pipeline cible avec webhook PhishER, options de deploiement (on-premise / cloud), abstraction backend LLM
- [IMPROVEMENT.md](docs/IMPROVEMENT.md) — analyse detaillee des bottlenecks et 7 options d'optimisation (cache disque, async, VT Premium, MLX, Claude API...)
- [benchmark_rapport.md](docs/benchmark_rapport.md) — rapport complet du benchmark

---

## Limitations connues

- **Vitesse** : 80-270 s/email (bottleneck : rate limit VT free + inference LLM). Voir [IMPROVEMENT.md](docs/IMPROVEMENT.md).
- **Faux positifs** : 9.7% sur emails SpamAssassin 2003 (hallucinations LLM sur emails pre-DKIM).
- **Scope** : POC / usage SOC individuel. Pas prevu pour un volume > 100 emails/j sans optimisations.
