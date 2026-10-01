# PhishingAI — Pistes d'amélioration des performances

## Hardware cible

| Spec | Valeur |
| --- | --- |
| Machine | Mac mini Apple Silicon (M2 / M4) |
| RAM | 16 – 32 GB unifiée (GPU + CPU partagent le même pool) |
| Bande passante mémoire | M2 : 100 GB/s — M4 : 120 GB/s — M2 Pro : 200 GB/s |
| Accélération LLM | Ollama via Metal (GPU intégré) — déjà actif dans les benchmarks |

> **Note** : les benchmarks ci-dessous ont été mesurés sur un M2 Pro 32 GB.
> Sur un M2 base 16 GB, les temps LLM sont ~30–50 % plus longs (bande passante divisée par deux).

---

## Situation actuelle

### Pipeline séquentiel (un email à la fois)

```text
┌─────────────┐   ┌──────────────────────────────┐   ┌──────────────┐
│   Parsing   │ → │     URL enrichment (VT)      │ → │  LLM Ollama  │
│   ~0.1 s    │   │  15 s × N domaines inconnus  │   │   7 – 45 s   │
└─────────────┘   └──────────────────────────────┘   └──────────────┘
```

### Contraintes actuelles

| Contrainte | Source | Impact |
| --- | --- | --- |
| VT free tier : 4 req/min | API externe | 15 s forcés entre chaque domaine |
| Appels VT séquentiels | Code | Pas de parallélisme même si le tier le permettait |
| `_URL_CACHE` en mémoire | Code | Cache perdu à chaque redémarrage |
| Modèle chargé une fois, 1 inférence à la fois | Ollama défaut | Pas de parallélisme LLM |

### Temps observés (benchmarks sur M2 Pro 32 GB)

| Composant | Min | Typique | Max |
| --- | --- | --- | --- |
| Parsing | < 0,1 s | 0,1 s | 0,5 s |
| URL enrichment (5 domaines inconnus) | 75 s | 100 s | 225 s |
| LLM llama3 8B Q4\_0 (Metal) | 6 s | 10 – 15 s | 35 s |
| LLM mistral-nemo 12B (Metal) | — | 45 s | — |
| LLM qwen2.5vl 7B (Metal) | 9 s | 15 – 40 s | 250 s |
| **Total par email** | **~80 s** | **~115 s** | **~270 s** |

### Estimation sur M2 base 16 GB

Le bottleneck LLM est la bande passante mémoire (100 GB/s vs 200 GB/s sur M2 Pro).
llama3 8B Q4\_0 passe à ~15 – 25 s typique ; mistral-nemo devient trop lent (~90 s).

### Débit séquentiel théorique

| Volume | M2 Pro 32 GB | M2 base 16 GB |
| --- | --- | --- |
| 1 email | 80 – 270 s | 90 – 300 s |
| 10 emails | 13 – 45 min | 15 – 50 min |
| 50 emails | 67 – 225 min | 75 – 250 min |

> Hypothèse : 5 domaines inconnus par email, llama3 à 15 s (M2 Pro) / 20 s (M2 base).

---

## Option 1 — Cache disque persistant

**Principe** : sérialiser `_URL_CACHE` dans un fichier JSON entre les sessions.
Un domaine déjà vérifié est servi en < 1 ms sans appel réseau.

**Effort** : faible (< 50 lignes, `url_enrichment.py` uniquement).
**Coût** : zéro.

En pratique, 60 – 80 % des domaines phishing d'une même campagne sont partagés entre les mails.

| Volume | Sans cache | Avec cache (80 % hit) |
| --- | --- | --- |
| 1 email (premier) | ~115 s | ~115 s |
| 1 email (revu) | ~115 s | **~15 s** |
| 10 emails (même campagne) | ~1 150 s | **~165 s** |
| 50 emails (même campagne) | ~5 750 s | **~825 s** |

---

## Option 2 — URLs asynchrones (httpx.AsyncClient)

**Principe** : remplacer la boucle séquentielle dans `enrich_urls` par des coroutines
`asyncio` + un sémaphore respectant le rate limit VT.

**Effort** : moyen (réécriture de `url_enrichment.py`, propagation async dans `analyzer.py`).
**Coût** : zéro.

### Avec VT free tier (4 req/min)

Le rate limit s'applique par clé API, pas par connexion TCP.
L'async ne contourne pas les 15 s entre appels — **gain marginal sur VT free** (~5 – 10 s
économisés sur les domaines whitelist et cache hits qui n'attendent plus en file).

### Avec VT Premium (≥ 500 req/min)

Tous les domaines sont interrogés simultanément.
Le temps d'enrichissement devient la latence réseau d'un seul aller-retour.

| Domaines inconnus | Séquentiel free | Async free | Async Premium |
| --- | --- | --- | --- |
| 5 | 75 s | 70 s | **~3 s** |
| 10 | 150 s | 140 s | **~3 s** |
| 15 (plafond) | 225 s | 210 s | **~3 s** |

---

## Option 3 — VT Premium

**Principe** : passer sur un tier VirusTotal payant pour lever le rate limit.

**Coût** : à partir de ~$300/mois (tier Analyst).

Combiné à l'option 2, l'enrichissement URL passe de la principale source de latence à ~3 s.

| Volume | Aujourd'hui | VT Premium + async |
| --- | --- | --- |
| 1 email | ~115 s | **~15 – 50 s** |
| 10 emails séquentiels | ~1 150 s | **~150 – 500 s** |
| 10 emails parallèles | — | **~15 – 50 s** |

---

## Option 4 — Parallélisme LLM via `OLLAMA_NUM_PARALLEL`

**Principe** : Ollama peut charger plusieurs inférences simultanées si la VRAM (ici : RAM
unifiée) le permet. La variable d'env `OLLAMA_NUM_PARALLEL` contrôle ce degré.

### Capacité par configuration

| Config | RAM dispo LLM | llama3 8B Q4\_0 (~4,7 GB/instance) | Instances simultanées |
| --- | --- | --- | --- |
| M2 base 16 GB | ~10 GB (OS + app ~6 GB) | 4,7 GB/instance | **2** |
| M2/M4 base 16 GB (modèle seul) | ~10 GB | 4,7 GB/instance | **2** |
| M2 Pro / M4 Pro 32 GB | ~24 GB | 4,7 GB/instance | **4 – 5** |

> Chaque inférence parallèle est ~30 – 50 % plus lente individuellement
> (contention mémoire), mais le débit global augmente.

### Impact sur le throughput (32 GB, llama3, URLs déjà en cache)

| `NUM_PARALLEL` | Temps / email | 10 emails | 50 emails |
| --- | --- | --- | --- |
| 1 (actuel) | ~15 s | ~150 s | ~750 s |
| 2 | ~22 s | **~110 s** | **~550 s** |
| 4 | ~35 s | **~90 s** | **~450 s** |

> Avec 16 GB, limiter à `NUM_PARALLEL=2` pour éviter le swap.

---

## Option 5 — MLX au lieu d'Ollama

**Principe** : remplacer Ollama par `mlx-lm` (framework Apple optimisé pour Apple Silicon).
MLX exploite plus efficacement la bande passante mémoire unifiée et le Neural Engine.

**Effort** : moyen (remplacement du client ollama, adaptation du streaming).
**Coût** : zéro.

### Gains typiques (M2 Pro 32 GB, llama3 8B Q4)

| Runtime | Tokens/s | Temps / email (~200 tokens) |
| --- | --- | --- |
| Ollama + Metal (actuel) | ~30 – 50 tok/s | 10 – 15 s |
| mlx-lm | ~55 – 80 tok/s | **5 – 8 s** |

Sur M2 base 16 GB, l'écart est encore plus marqué car MLX gère mieux la pression mémoire.

| Runtime | M2 base 16 GB | M2 Pro 32 GB |
| --- | --- | --- |
| Ollama (actuel) | 15 – 25 s | 10 – 15 s |
| mlx-lm | **8 – 14 s** | **5 – 8 s** |

---

## Option 6 — Remplacer Ollama par l'API Claude (Anthropic)

**Principe** : appeler `claude-haiku-4-5` ou `claude-sonnet-4-6` via l'API Anthropic.
Latence fixe, parallélisme natif, sans contrainte de RAM locale.

**Coût** : ~$0,001 – $0,003 par email (Haiku) / ~$0,015 – $0,05 (Sonnet).
**Avantage** : le Mac mini n'est plus le bottleneck LLM.

| Modèle | Latence / email | 10 emails parallèles | 50 emails parallèles |
| --- | --- | --- | --- |
| Ollama llama3 (actuel) | 10 – 35 s | ~150 – 350 s | ~750 s |
| claude-haiku-4-5 | ~3 – 6 s | **~6 – 10 s** | **~15 – 30 s** |
| claude-sonnet-4-6 | ~8 – 15 s | **~10 – 20 s** | **~20 – 50 s** |

> Hypothèse parallèles : URL enrichment en cache ou VT Premium, 10 workers simultanés.

---

## Option 7 — Pré-filtrage heuristique avant le LLM

**Principe** : court-circuiter Ollama pour les cas évidents détectables par règles Python.
Les règles déterministes existantes (SCL, X-Campaign-ID, SPF fail + urgence) couvrent
déjà ~20 – 30 % des cas. Étendre ce coverage à ~50 % divise les appels LLM par deux.

**Effort** : faible. **Coût** : zéro.

| Taux de court-circuit | 10 emails | 50 emails |
| --- | --- | --- |
| 0 % (actuel) | ~1 150 s | ~5 750 s |
| 30 % | ~800 s | ~4 000 s |
| 50 % | **~575 s** | **~2 875 s** |

---

## Synthèse — gains théoriques cumulés

Hypothèses : llama3, 5 domaines inconnus/email, cache chaud (Option 1 activée),
machine M2 Pro 32 GB sauf mention contraire.

| Configuration | Temps / email | 10 emails | 50 emails |
| --- | --- | --- | --- |
| **Actuel — M2 Pro 32 GB** | 115 s | 1 150 s (~19 min) | 5 750 s (~96 min) |
| **Actuel — M2 base 16 GB** | 125 s | 1 250 s (~21 min) | 6 250 s (~104 min) |
| + Cache disque (opt. 1) | ~15 s* | ~165 s (~3 min)* | ~825 s (~14 min)* |
| + VT Premium + async (opt. 2 + 3) | ~18 s | ~180 s | ~900 s |
| + MLX (opt. 5) — M2 Pro | ~10 s | ~100 s | ~500 s |
| + MLX (opt. 5) — M2 base 16 GB | ~12 s | ~120 s | ~600 s |
| + `NUM_PARALLEL=4` (opt. 4) — 32 GB | ~35 s | **~90 s** | **~450 s** |
| + `NUM_PARALLEL=2` (opt. 4) — 16 GB | ~28 s | **~140 s** | **~700 s** |
| VT Premium + MLX + `NUM_PARALLEL=4` | ~8 s | **~20 s** | **~100 s** |
| Claude Haiku + VT Premium + ×10 parallèles | ~5 s | **~8 s** | **~25 s** |

\* *Sur emails revus / même campagne.*

---

## Recommandation par cas d'usage

| Cas | Config recommandée |
| --- | --- |
| Démo / playground (mails répétés) | Option 1 (cache disque) |
| Analyse SOC temps réel, 1 mail à la fois | Option 1 + Option 5 (MLX) |
| Batch quotidien 50 – 500 mails, budget limité | Option 1 + Option 5 + Option 4 (`NUM_PARALLEL=2/4`) |
| Batch quotidien 50 – 500 mails, budget disponible | Option 1 + Option 3 (VT Premium) + Option 5 |
| Production > 1 000 mails/j | Option 3 + Option 6 (Claude API) + Option 4 |
