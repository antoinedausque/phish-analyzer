# Rapport de benchmark — Détection de phishing par LLM local

**Date :** Mai 2026  
**Outil :** PhishingAI — analyse locale via Ollama + VirusTotal API  
**Dataset :** 161 emails labellisés (93 légitimes + 68 phishing de différents types)  
**Enrichissement URL :** API VirusTotal réelle (vérification réputation des liens)

---

## Résumé exécutif

Trois modèles de langage ont été évalués sur leur capacité à détecter des emails malveillants. Le modèle **llama3** offre le meilleur équilibre précision/rappel avec un F1 de **90,8 %** et seulement **9 faux positifs** sur 93 emails légitimes. Les modèles plus grands (mistral-nemo) favorisent le rappel au détriment de la précision, générant trop de faux positifs pour un usage opérationnel.

---

## Dataset

| Catégorie | Nombre | Description |
|-----------|--------|-------------|
| Légitimes | 93 | Emails ham SpamAssassin (corpus 2003) |
| Nazario | 60 | Phishing réels (corpus Nazario) |
| Spoofing | 2 | Usurpation d'identité |
| Spear phishing | 2 | Ciblage personnalisé |
| Urgence artificielle | 2 | Extorsion / fausse alerte |
| URL malveillante | 2 | Liens vers pages de phishing |
| **Total** | **161** | |

---

## Résultats globaux (seuil strict — `malveillant` uniquement)

| Modèle | F1 | Précision | Rappel | Accuracy | Faux positifs | Faux négatifs | Temps moyen |
|--------|----|-----------|--------|----------|---------------|---------------|-------------|
| **llama3** ✅ | **90,8 %** | **87,7 %** | 94,1 % | **91,9 %** | **9 / 93** | **4 / 68** | 35 s |
| qwen2.5vl:7b | 87,1 % | 81,0 % | 94,1 % | 88,2 % | 15 / 93 | 4 / 68 | 249 s |
| mistral-nemo | 67,7 % | 51,5 % | **98,5 %** | 60,2 % | 63 / 93 | 1 / 68 | 45 s |

> **Faux positif** = email légitime classé malveillant (gêne utilisateur)  
> **Faux négatif** = phishing non détecté (risque sécurité)

---

## Résultats par type de menace

### llama3

| Type de menace | Emails | Détectés | Manqués | Rappel |
|----------------|--------|----------|---------|--------|
| Phishing générique (Nazario) | 60 | 56 | 4 | 93,3 % |
| Spoofing | 2 | 2 | 0 | 100 % |
| Spear phishing | 2 | 2 | 0 | 100 % |
| Urgence artificielle | 2 | 2 | 0 | 100 % |
| URL malveillante | 2 | 2 | 0 | 100 % |
| **Total phishing** | **68** | **64** | **4** | **94,1 %** |

Les 4 phishing non détectés sont classés `suspect` — remontés à l'utilisateur pour vérification, non ignorés.

### qwen2.5vl:7b

| Type de menace | Emails | Détectés | Manqués | Rappel |
|----------------|--------|----------|---------|--------|
| Phishing générique (Nazario) | 60 | 56 | 4 | 93,3 % |
| Spoofing | 2 | 2 | 0 | 100 % |
| Spear phishing | 2 | 2 | 0 | 100 % |
| Urgence artificielle | 2 | 2 | 0 | 100 % |
| URL malveillante | 2 | 2 | 0 | 100 % |
| **Total phishing** | **68** | **64** | **4** | **94,1 %** |

Rappel identique à llama3 sur les phishing, mais 15 faux positifs (vs 9) sur les légitimes.

### mistral-nemo

| Type de menace | Emails | Détectés | Manqués | Rappel |
|----------------|--------|----------|---------|--------|
| Phishing générique (Nazario) | 60 | 59 | 1 | 98,3 % |
| Spoofing | 2 | 2 | 0 | 100 % |
| Spear phishing | 2 | 2 | 0 | 100 % |
| Urgence artificielle | 2 | 2 | 0 | 100 % |
| URL malveillante | 2 | 2 | 0 | 100 % |
| **Total phishing** | **68** | **67** | **1** | **98,5 %** |

Meilleur rappel phishing des trois modèles (1 seul manqué), mais au prix de 63 faux positifs sur les légitimes.

---

## Analyse des faux positifs

### llama3 — 9 faux positifs

Tous des emails de 2003 (corpus SpamAssassin) antérieurs aux standards DKIM/DMARC. Les erreurs proviennent de :

- Incohérence From / Return-Path normale sur les listes de diffusion
- Domaines d'envoi non reconnus (infrastructure 2003)
- Aucune URL malveillante confirmée par VirusTotal dans ces emails

Ces faux positifs seraient rares sur un corpus d'emails modernes avec authentification DKIM/DMARC.

### qwen2.5vl:7b — 15 faux positifs

Même profil que llama3 (emails 2003 sans DKIM/SPF), mais le modèle est plus sensible à l'absence d'authentification et la classe systématiquement comme signal fort de spoofing, même pour des listes de diffusion légitimes.

### mistral-nemo — 63 faux positifs

Le modèle classe comme malveillant la quasi-totalité des emails sans DKIM/SPF, indépendamment du contenu. Il interprète toute absence d'authentification comme une preuve de compromission. Cette approche est inadaptée à un corpus incluant des emails antérieurs à 2007.

---

## Comparaison des stratégies de seuil

| Seuil | Modèle | Faux positifs | Faux négatifs | Rappel phishing | Usage recommandé |
|-------|--------|---------------|---------------|-----------------|-----------------|
| Strict | llama3 | **9** | 4 | 94,1 % | SOC, isolation automatique |
| Strict | qwen2.5vl:7b | 15 | 4 | 94,1 % | — |
| Strict | mistral-nemo | 63 | **1** | **98,5 %** | — |
| Permissif | llama3 | 74 | **1** | **98,5 %** | Pré-filtrage, quarantaine |
| Permissif | qwen2.5vl:7b | 92 | 1 | 98,5 % | — |
| Permissif | mistral-nemo | 90 | 1 | 98,5 % | — |

> En seuil permissif (`malveillant` + `suspect`), les trois modèles atteignent 98,5 % de rappel avec 1 seul phishing manqué. La différence se joue uniquement sur le volume d'alertes à traiter.

---

## Signaux analysés

| Catégorie | Signaux |
|-----------|---------|
| Authentification email | SPF, DKIM, DMARC |
| Cohérence expéditeur | From ↔ Return-Path, Reply-To, domaine typosquatté |
| BEC (Business Email Compromise) | Webmail → domaine corporate, corps vague d'amorce |
| Contenu | Urgence artificielle, demande IBAN / identifiants |
| Réputation des URLs | Votes malveillants VirusTotal (~90 scanners) |
| En-têtes Microsoft | X-MS-Exchange-Organization-SCL, X-Campaign-ID |

---

## Infrastructure & confidentialité

- **Traitement 100 % local** — aucun email ne quitte la machine
- **LLM local** via Ollama (llama3 8B, ~8 Go RAM)
- **Seules les URLs** sont envoyées à l'API VirusTotal pour vérification de réputation
- Compatible Windows / macOS / Linux
- Formats supportés : `.eml` (export Outlook, Apple Mail, Thunderbird)

---

## Conclusion

| Critère | llama3 | qwen2.5vl:7b | mistral-nemo |
|---------|--------|--------------|--------------|
| F1 global | ✅ 90,8 % | 87,1 % | 67,7 % |
| Faux positifs | ✅ 9 | 15 | ❌ 63 |
| Rappel phishing | 94,1 % | 94,1 % | ✅ 98,5 % |
| Vitesse d'analyse | ✅ 35 s | ❌ 249 s | 45 s |
| Usage opérationnel | ✅ Recommandé | Acceptable | ❌ Trop de FP |

**llama3 est le modèle recommandé** pour un déploiement opérationnel. mistral-nemo peut être envisagé dans un rôle de second filtre (pré-quarantaine) où le taux de faux positifs est acceptable.
