"""
PhishingAI - Enrichissement URL
Cascade : VirusTotal → URLScan.io (fallback si VT propre) → mock (si pas de clés)
"""

import base64
import os
import time

import httpx
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY      = os.getenv("VIRUSTOTAL_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")

# Cache en mémoire (durée de vie du processus) — évite de recheck la même URL
_URL_CACHE: dict[str, dict] = {}

VT_URL_BASE      = "https://www.virustotal.com/api/v3/urls"
URLSCAN_SUBMIT   = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT   = "https://urlscan.io/api/v1/result/{uuid}/"

URLSCAN_POLL_INTERVAL = 5    # secondes entre deux polls
URLSCAN_MAX_WAIT      = 30   # timeout total URLScan
VT_RATE_LIMIT_DELAY   = 15   # secondes entre requêtes VT (free tier: 4 req/min)

_vt_last_call: float = 0.0   # timestamp du dernier appel VT

# Domaines dont la réputation est connue — inutile de les envoyer à VT
TRUSTED_DOMAINS = frozenset({
    "google.com", "google.fr", "googleapis.com", "gstatic.com",
    "apple.com", "icloud.com", "itunes.apple.com",
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "youtube.com", "youtu.be",
    "amazon.com", "amazon.fr",
    "microsoft.com", "outlook.com", "office.com", "live.com",
    "github.com", "githubusercontent.com",
    "discord.com", "discord.gg",
    "leboncoin.fr", "vinted.fr", "laposte.fr", "laposte.net",
    "orange.fr", "sfr.fr", "free.fr", "bouyguestelecom.fr",
    "play.google.com", "apps.apple.com",
    "unsubscribe.com",
})


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

def _vt_check(url: str, client: httpx.Client) -> dict | None:
    """
    Interroge VirusTotal pour une URL.
    Retourne un dict normalisé ou None en cas d'erreur.
    """
    global _vt_last_call

    if not VT_API_KEY:
        return None

    # Respect du rate limit (free tier : 4 req/min → 1 req/15s)
    elapsed = time.time() - _vt_last_call
    if elapsed < VT_RATE_LIMIT_DELAY:
        time.sleep(VT_RATE_LIMIT_DELAY - elapsed)
    _vt_last_call = time.time()

    # L'API VT v3 attend l'URL encodée en base64 url-safe sans padding
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()

    try:
        r = client.get(
            f"{VT_URL_BASE}/{url_id}",
            headers={"x-apikey": VT_API_KEY},
            timeout=10,
        )
        if r.status_code == 404:
            # URL inconnue de VT → soumettre pour analyse
            r2 = client.post(
                VT_URL_BASE,
                headers={"x-apikey": VT_API_KEY},
                data={"url": url},
                timeout=10,
            )
            if r2.status_code not in (200, 201):
                return None
            # Attendre que VT analyse (quelques secondes)
            time.sleep(3)
            r = client.get(
                f"{VT_URL_BASE}/{url_id}",
                headers={"x-apikey": VT_API_KEY},
                timeout=10,
            )

        if r.status_code != 200:
            return None

        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values())
        categories = list(
            r.json()["data"]["attributes"].get("categories", {}).values()
        )[:3]

        return {
            "source": "virustotal",
            "malicious_votes": malicious + suspicious,
            "total_scanners": total,
            "categories": categories if categories else ["clean"],
        }

    except Exception:
        return None


# ---------------------------------------------------------------------------
# URLScan.io
# ---------------------------------------------------------------------------

def _urlscan_check(url: str, client: httpx.Client) -> dict | None:
    """
    Soumet une URL à URLScan.io et attend le résultat.
    Retourne un dict normalisé ou None en cas d'erreur / timeout.
    """
    if not URLSCAN_API_KEY:
        return None

    try:
        r = client.post(
            URLSCAN_SUBMIT,
            headers={"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"},
            json={"url": url, "visibility": "private"},
            timeout=10,
        )
        if r.status_code not in (200, 201):
            return None

        uuid = r.json().get("uuid")
        if not uuid:
            return None

        # Polling jusqu'à résultat disponible
        elapsed = 0
        while elapsed < URLSCAN_MAX_WAIT:
            time.sleep(URLSCAN_POLL_INTERVAL)
            elapsed += URLSCAN_POLL_INTERVAL
            res = client.get(URLSCAN_RESULT.format(uuid=uuid), timeout=10)
            if res.status_code == 200:
                data      = res.json()
                verdicts  = data.get("verdicts", {}).get("overall", {})
                malicious = 1 if verdicts.get("malicious", False) else 0
                score     = verdicts.get("score", 0)
                tags      = data.get("verdicts", {}).get("urlscan", {}).get("tags", [])
                return {
                    "source": "urlscan",
                    "malicious_votes": malicious,
                    "total_scanners": 1,
                    "categories": tags if tags else (["phishing"] if malicious else ["clean"]),
                    "urlscan_score": score,
                }

        return None  # timeout

    except Exception:
        return None


# ---------------------------------------------------------------------------
# Mock (fallback si aucune clé disponible)
# ---------------------------------------------------------------------------

def _mock_check(url: str) -> dict:
    suspicious_keywords = [
        "login", "verify", "account", "secure", "update",
        "confirm", "bank", "paypal", "amazon",
    ]
    is_suspicious = any(kw in url.lower() for kw in suspicious_keywords)
    return {
        "source": "mock",
        "malicious_votes": 3 if is_suspicious else 0,
        "total_scanners": 70,
        "categories": ["phishing"] if is_suspicious else ["clean"],
    }


# ---------------------------------------------------------------------------
# Point d'entrée public
# ---------------------------------------------------------------------------

MAX_DOMAINS_TO_CHECK = 15  # plafond d'appels API réels par email


def _extract_hostname(url: str) -> str:
    from urllib.parse import urlparse
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def enrich_urls(urls: list[str], on_progress=None) -> list[dict]:
    """
    Enrichit une liste d'URLs en cascade :
      1. VirusTotal (si clé présente)
      2. URLScan.io en fallback si VT renvoie 0 vote (si clé présente)
      3. Mock si aucune clé

    Optimisations :
    - Déduplication par domaine : un seul appel API par domaine, résultat partagé
      entre toutes les URLs du même domaine.
    - Plafond à MAX_DOMAINS_TO_CHECK domaines inconnus vérifiés par email.

    Retourne une liste de dicts avec les champs attendus par build_prompt().
    """
    if not urls:
        return []

    use_real_api = bool(VT_API_KEY or URLSCAN_API_KEY)

    # Construire un index domaine → première URL représentative
    domain_to_representative: dict[str, str] = {}
    url_to_domain: dict[str, str] = {}
    for url in urls:
        hostname = _extract_hostname(url)
        url_to_domain[url] = hostname
        if hostname not in domain_to_representative:
            domain_to_representative[hostname] = url

    # Cache par domaine (réutilise _URL_CACHE dont les clés sont des URLs)
    domain_result_cache: dict[str, dict] = {}
    api_calls_remaining = MAX_DOMAINS_TO_CHECK
    domains = list(domain_to_representative.items())
    total_domains = len(domains)

    with httpx.Client() as client:
        for idx, (domain, representative_url) in enumerate(domains):

            # Domaine de confiance — directement clean, pas d'appel API
            is_trusted = any(
                domain == d or domain.endswith("." + d)
                for d in TRUSTED_DOMAINS
            )
            if is_trusted:
                domain_result_cache[domain] = {
                    "mock": False, "source": "whitelist",
                    "malicious_votes": 0, "total_scanners": 0,
                    "categories": ["clean"],
                }
            elif representative_url in _URL_CACHE:
                domain_result_cache[domain] = _URL_CACHE[representative_url]
            elif not use_real_api:
                entry = {"mock": True, **_mock_check(representative_url)}
                domain_result_cache[domain] = entry
            elif api_calls_remaining <= 0:
                entry = {"mock": True, **_mock_check(representative_url)}
                domain_result_cache[domain] = entry
            else:
                api_calls_remaining -= 1
                result = None

                if VT_API_KEY:
                    vt = _vt_check(representative_url, client)
                    if vt is not None:
                        result = vt

                if URLSCAN_API_KEY and result is None:
                    us = _urlscan_check(representative_url, client)
                    if us is not None:
                        result = us

                if result is None:
                    result = {"mock": True, **_mock_check(representative_url)}
                else:
                    result["mock"] = False

                _URL_CACHE[representative_url] = result
                domain_result_cache[domain] = result

            if on_progress:
                on_progress(idx + 1, total_domains)

    # Construire la liste finale : chaque URL hérite du résultat de son domaine
    results = []
    for url in urls:
        domain = url_to_domain[url]
        entry = domain_result_cache.get(domain, {"mock": True, **_mock_check(url)})
        results.append({"url": url, **entry})

    return results
