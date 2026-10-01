"""
PhishingAI - Core Analyzer
Input  : fichier .eml (mail brut)
Output : JSON verdict { verdict, score, raisons, tags }
"""

import email
import email.policy
import json
import re
import sys
from email import message_from_string
from email.header import decode_header

import ollama  # pip install ollama
from bs4 import BeautifulSoup
from url_enrichment import enrich_urls

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MODEL = "llama3"  # changer ici si tu veux tester un autre modèle Ollama

WEBMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.fr", "hotmail.com",
    "hotmail.fr", "outlook.com", "live.com", "icloud.com", "protonmail.com",
    "proton.me", "aol.com", "laposte.net", "orange.fr", "free.fr", "sfr.fr",
})

LIST_KEYWORDS = frozenset({
    "list", "lists", "listserv", "announce", "announcements", "discuss",
    "dev", "devel", "users", "user", "support", "help", "info", "contact",
    "noreply", "no-reply", "newsletter", "news", "bounce", "mailer",
    "admin", "postmaster", "abuse", "security", "team", "group", "groups",
    "forum", "forums", "digest", "bugs", "issues", "alerts", "notify",
})

URGENCY_KEYWORDS = [
    "suspendu", "suspension", "expiré", "expire", "échéance", "bloqué",
    "renouvellement", "mise à jour", "mettre à jour", "délai", "immédiatement",
    "urgent", "action requise", "suspended", "expired", "verify now",
]

# ---------------------------------------------------------------------------
# 1. Parsing du mail
# ---------------------------------------------------------------------------

def decode_mime_header(value: str) -> str:
    parts = decode_header(value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(part)
    return " ".join(decoded)


def _html_to_text(html: str) -> str:
    """Convertit du HTML en texte lisible via BeautifulSoup."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["style", "script", "head"]):
        tag.decompose()
    return re.sub(r'\s+', ' ', soup.get_text(separator=" ")).strip()


def extract_text_body(msg: email.message.Message) -> tuple[str, str]:
    """
    Extrait le corps texte et le HTML brut depuis un message (gère multipart).
    Retourne (texte_propre, html_brut).
    """
    body_parts = []
    html_raw = ""

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if ct == "text/plain" and "attachment" not in cd:
                charset = part.get_content_charset() or "utf-8"
                body_parts.append(part.get_payload(decode=True).decode(charset, errors="replace"))
            elif ct == "text/html" and "attachment" not in cd:
                charset = part.get_content_charset() or "utf-8"
                html_raw = part.get_payload(decode=True).decode(charset, errors="replace")
                if not body_parts:
                    body_parts.append(_html_to_text(html_raw))
    else:
        ct = msg.get_content_type()
        charset = msg.get_content_charset() or "utf-8"
        raw = msg.get_payload(decode=True).decode(charset, errors="replace")
        if ct == "text/html":
            html_raw = raw
            body_parts.append(_html_to_text(raw))
        else:
            body_parts.append(raw)

    return "\n".join(body_parts).strip(), html_raw


def extract_urls(text: str, raw_html: str = "") -> list[str]:
    """Extrait les URLs du corps texte ET des attributs href/src du HTML."""
    pattern = r'https?://[^\s\'"<>]+'
    raw_urls = set(re.findall(pattern, text))
    if raw_html:
        raw_urls.update(re.findall(r'href=["\']+(https?://[^\s\'"<>]+)', raw_html))
    # Supprimer la ponctuation traînante souvent capturée depuis le texte brut
    cleaned = set()
    for u in raw_urls:
        cleaned.add(u.rstrip(").,;:!?\"'"))
    return list(cleaned)


def parse_eml(eml_content: str) -> dict:
    msg = message_from_string(eml_content, policy=email.policy.compat32)

    headers = {
        "from":         msg.get("From", ""),
        "reply_to":     msg.get("Reply-To", ""),
        "return_path":  msg.get("Return-Path", ""),
        "to":           msg.get("To", ""),
        "subject":      decode_mime_header(msg.get("Subject", "")),
        "date":         msg.get("Date", ""),
        "message_id":   msg.get("Message-ID", ""),
        "spf":          msg.get("Received-SPF", msg.get("X-SPF-Status", "absent")),
        "dkim":         msg.get("DKIM-Signature", "absent"),
        "dmarc":        msg.get("Authentication-Results", "absent"),
        "x_mailer":      msg.get("X-Mailer", ""),
        "mime_version":  msg.get("MIME-Version", ""),
        "campaign_id":   msg.get("X-Campaign-ID", ""),
        "scl":           msg.get("X-MS-Exchange-Organization-SCL", "absent"),
    }

    body, raw_html = extract_text_body(msg)
    urls = extract_urls(body, raw_html)

    return {"headers": headers, "body": body[:3000], "urls": urls}


# ---------------------------------------------------------------------------
# 2. Mock enrichissement URL
# ---------------------------------------------------------------------------

def mock_url_enrichment(urls: list[str]) -> list[dict]:
    """
    Simule une réponse VirusTotal/URLScan.
    Remplacer par un vrai appel API plus tard.
    """
    results = []
    suspicious_keywords = ["login", "verify", "account", "secure", "update", "confirm", "bank", "paypal", "amazon"]
    for url in urls:
        is_suspicious = any(kw in url.lower() for kw in suspicious_keywords)
        results.append({
            "url": url,
            "mock": True,
            "malicious_votes": 3 if is_suspicious else 0,
            "total_scanners": 70,
            "categories": ["phishing"] if is_suspicious else ["clean"],
        })
    return results


# ---------------------------------------------------------------------------
# 3. Construction du prompt Chain of Thought
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """Tu es un analyste en cybersécurité spécialisé dans la classification d'emails.
Tu évalues objectivement chaque email : il peut être malveillant, suspect OU parfaitement légitime.
Tu raisonnes étape par étape avant de conclure.
Tu réponds UNIQUEMENT avec un objet JSON valide, sans texte avant ou après."""


def _auth_status(h: dict) -> tuple[str, int]:
    """
    Calcule un bilan d'authentification lisible et un score de confiance (0-3).
    Retourne (résumé textuel, nb de signaux positifs).
    """
    signals = []
    score = 0

    spf = h["spf"].lower()
    if "pass" in spf:
        signals.append("SPF : PASS ✓")
        score += 1
    elif "fail" in spf or "softfail" in spf:
        signals.append(f"SPF : FAIL ✗ ({h['spf']})")
    else:
        signals.append(f"SPF : absent/neutre")

    if h["dkim"] != "absent":
        signals.append("DKIM : présent ✓")
        score += 1
    else:
        signals.append("DKIM : absent ✗")

    dmarc = h["dmarc"].lower()
    if "dkim=pass" in dmarc or "spf=pass" in dmarc or "dmarc=pass" in dmarc:
        signals.append("DMARC/Auth-Results : pass ✓")
        score += 1
    elif h["dmarc"] != "absent":
        signals.append(f"DMARC/Auth-Results : {h['dmarc'][:80]}")
    else:
        signals.append("DMARC : absent")

    return "\n  ".join(signals), score


def _domain(addr: str) -> str:
    """Extrait le domaine d'une adresse email."""
    import re
    m = re.search(r'@([\w.\-]+)', addr)
    return m.group(1).lower() if m else addr.lower()


def _is_webmail_to_corporate(h: dict) -> bool:
    """Retourne True si l'expéditeur est un webmail écrivant à une adresse nominative corporate."""
    from_domain = _domain(h["from"])
    if from_domain not in WEBMAIL_DOMAINS:
        return False
    to_raw = h.get("to") or ""
    to_domain = _domain(to_raw) if "@" in to_raw else "absent"
    to_local = to_raw.split("@")[0].lstrip("<").lower()
    return (
        to_domain not in WEBMAIL_DOMAINS
        and to_domain != "absent"
        and not any(kw in to_local for kw in LIST_KEYWORDS)
        and "," not in to_raw
    )


def build_prompt(parsed: dict, url_data: list[dict]) -> str:
    h = parsed["headers"]

    auth_summary, auth_score = _auth_status(h)

    from_domain      = _domain(h["from"])
    return_domain    = _domain(h["return_path"]) if h["return_path"] else "absent"
    reply_to_domain  = _domain(h["reply_to"])   if h["reply_to"]   else "absent"
    domain_coherent  = from_domain == return_domain or return_domain == "absent"

    url_summary = "\n".join(
        f"  - {u['url']} → votes malveillants: {u['malicious_votes']}/{u['total_scanners']}, catégories: {u['categories']}"
        for u in url_data
    ) or "  Aucune URL détectée."

    all_urls_clean = all(u["malicious_votes"] == 0 for u in url_data)
    dkim_absent = h["dkim"] == "absent"
    to_domain = _domain(h["to"]) if h["to"] else "absent"
    webmail_to_corporate = _is_webmail_to_corporate(h)

    return f"""Analyse cet email en trois phases, puis applique les règles de décision.

## Phase 1 — Authentification & cohérence de l'expéditeur
  {auth_summary}
  Bilan : {auth_score}/3 signaux d'authentification positifs

- From         : {h['from']}  (domaine : {from_domain})
- Return-Path  : {h['return_path']}  (domaine : {return_domain})
- Reply-To     : {h['reply_to']}  (domaine : {reply_to_domain})
- Cohérence From ↔ Return-Path : {'OUI ✓' if domain_coherent else 'NON ✗ — domaines différents'}
- Expéditeur webmail vers destinataire nominatif corporate : {'OUI ✗ (' + from_domain + ' → ' + to_domain + ')' if webmail_to_corporate else 'NON ✓'}
- X-Campaign-ID  : {h['campaign_id'] if h['campaign_id'] else 'absent'}{' ✗ — header de campagne de masse' if h['campaign_id'] else ''}
- SCL (spam confidence Microsoft) : {h['scl']}{' ✗ — classé indésirable (≥5)' if h['scl'] not in ('absent', '0', '1', '2', '3', '4') else ' ✓'}
- Sujet        : {h['subject']}

## Phase 2 — Analyse du corps
{parsed['body'][:2000]}

Évalue :
  + Le contenu correspond-il au contexte attendu (info, facture, échange) ? → signal légitime
  - Y a-t-il une menace ou une urgence artificielle (compte suspendu, délai, pénalité) ? → signal malveillant
  - Y a-t-il une demande d'action sensible (saisir identifiants, payer, mettre à jour IBAN) ? → signal malveillant
  - Y a-t-il des incohérences linguistiques ou stylistiques suspectes ?
  - Le message est-il anormalement vague (une seule phrase demandant un contact, sans contexte) ? → signal BEC d'amorce uniquement si le signal webmail corporate ci-dessus est OUI

## Phase 3 — Réputation des URLs
{url_summary}
  Bilan URLs : {'toutes propres ✓' if all_urls_clean else 'au moins une URL suspecte ✗'}

---

## Règles de décision (applique-les DANS L'ORDRE — la première règle qui correspond l'emporte)

**RÈGLE 1 — suspect BEC** : {'⚠ SIGNAL ACTIF — appliquer cette règle en priorité' if webmail_to_corporate else '(signal absent — passer à la règle suivante)'}
  Conditions : signal "Expéditeur webmail vers destinataire nominatif corporate" = {'OUI → règle applicable' if webmail_to_corporate else 'NON → règle non applicable, ignorer'}
  Si applicable ET corps court/vague (demande de contact sans contexte métier) → verdict **suspect**, score 65
  (Les BEC utilisent de vrais comptes webmail avec auth parfaite — ne pas se laisser tromper par auth_score=3)

**RÈGLE 2 — malveillant** si AU MOINS DEUX de ces conditions sont vraies :
  - SPF fail ou Return-Path sur un domaine différent du From
  - Domaine From typosquatté ou non officiel, ou expéditeur usurpant une marque connue (banque, CPAM, impôts, colis…)
  - Demande d'action urgente ET sensible (paiement, identifiants, renouvellement carte, mise à jour compte)
  - URL avec votes malveillants > 0
  - Reply-To sur un domaine différent du From (surtout un webmail)
  - X-Campaign-ID présent + expéditeur qui se présente comme organisme officiel
  - SCL ≥ 5 (Microsoft a classé l'email comme indésirable)
  → score entre 70 et 100

**RÈGLE 3 — légitime** si TOUTES ces conditions sont vraies :
  - Règle 1 non applicable (signal BEC absent)
  - auth_score >= 2 (SPF pass + DKIM présent, ou équivalent)
    **OU** cas héritage pré-DKIM : DKIM absent + SPF pass (auth_score >= 1) + contenu neutre{' — applicable ici car DKIM absent' if dkim_absent else ''}
  - From et Return-Path sur le même domaine (ou Return-Path absent)
  - Aucune URL malveillante
  - Aucune demande d'action urgente/sensible dans le corps
  → score entre 0 et 35

**RÈGLE 4 — suspect** : tous les autres cas (signaux mixtes, doute raisonnable)
  → score 45 (utiliser exactement 45, jamais 65 — ce score est réservé à la règle BEC)

---

Réponds avec ce JSON exact (et seulement ce JSON) :
{{
  "verdict": "malveillant" | "suspect" | "légitime",
  "score": 0-100,
  "raisons": [
    "raison 1",
    "raison 2"
  ],
  "tags": ["phishing", "spoofing", "urgence", "url_suspecte", "bec", "légitime", ...],
  "recommandation": "action suggérée en une phrase"
}}"""


# ---------------------------------------------------------------------------
# 4. Inférence Ollama
# ---------------------------------------------------------------------------

def analyze_with_ollama(parsed: dict, url_data: list[dict], model: str = MODEL,
                        on_token=None) -> dict:
    prompt = build_prompt(parsed, url_data)

    print(f"[*] Envoi à Ollama ({model})...", flush=True)

    if on_token:
        chunks = []
        for chunk in ollama.chat(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            options={"temperature": 0.1},
            stream=True,
        ):
            token = chunk["message"]["content"]
            chunks.append(token)
            on_token(token)
        raw = "".join(chunks).strip()
    else:
        response = ollama.chat(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            options={"temperature": 0.1},
        )
        raw = response["message"]["content"].strip()

    # Extraction robuste du JSON (gère texte parasite et accolade fermante manquante)
    json_match = re.search(r'\{[\s\S]*', raw)
    if not json_match:
        raise ValueError(f"Impossible d'extraire un JSON de la réponse :\n{raw}")

    candidate = json_match.group()
    # Tentative directe
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass
    # Si accolade fermante manquante, on l'ajoute
    try:
        return json.loads(candidate + "\n}")
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON invalide même après correction :\n{candidate}") from e


# ---------------------------------------------------------------------------
# 5. Point d'entrée
# ---------------------------------------------------------------------------

def analyze_eml(eml_content: str, model: str = MODEL,
                on_url_progress=None, on_token=None) -> dict:
    print("[*] Parsing de l'email...")
    parsed = parse_eml(eml_content)

    print(f"[*] Headers extraits : From={parsed['headers']['from']}, Subject={parsed['headers']['subject']}")
    print(f"[*] {len(parsed['urls'])} URL(s) détectée(s) : {parsed['urls']}")

    print("[*] Enrichissement des URLs...")
    url_data = enrich_urls(parsed["urls"], on_progress=on_url_progress)

    verdict = analyze_with_ollama(parsed, url_data, model, on_token=on_token)

    # Post-traitement : corriger le score si le LLM ancre sur 65 sans signal BEC
    h = parsed["headers"]
    from_domain = _domain(h["from"])
    WEBMAIL_DOMAINS = {"gmail.com", "googlemail.com", "yahoo.com", "yahoo.fr", "hotmail.com",
                       "hotmail.fr", "outlook.com", "live.com", "icloud.com", "protonmail.com",
                       "proton.me", "aol.com", "laposte.net", "orange.fr", "free.fr", "sfr.fr"}
    LIST_KEYWORDS = {"list", "lists", "listserv", "announce", "announcements", "discuss",
                     "dev", "devel", "users", "user", "support", "help", "info", "contact",
                     "noreply", "no-reply", "newsletter", "news", "bounce", "mailer",
                     "admin", "postmaster", "abuse", "security", "team", "group", "groups",
                     "forum", "forums", "digest", "bugs", "issues", "alerts", "notify"}
    to_raw = h["to"] or ""
    to_local = to_raw.split("@")[0].lstrip("<").lower() if "@" in to_raw else ""
    to_domain = _domain(h["to"]) if h["to"] else "absent"
    to_is_nominative = (
        to_domain not in WEBMAIL_DOMAINS
        and to_domain != "absent"
        and not any(kw in to_local for kw in LIST_KEYWORDS)
        and "," not in to_raw
    )
    webmail_to_corporate = from_domain in WEBMAIL_DOMAINS and to_is_nominative

    h = parsed["headers"]
    webmail_to_corporate = _is_webmail_to_corporate(h)

    # Correction score BEC : le modèle ancre sur 65 même sans signal BEC
    if (verdict.get("verdict") == "suspect"
            and verdict.get("score", 0) >= 60
            and not webmail_to_corporate):
        verdict["score"] = 45

    # Règles déterministes Python — signaux objectifs que le LLM rate parfois
    scl = h.get("scl", "absent")
    campaign_id = h.get("campaign_id", "")
    body_lower = parsed["body"].lower()
    has_urgency = any(kw in body_lower for kw in URGENCY_KEYWORDS)

    try:
        scl_int = int(scl)
    except (ValueError, TypeError):
        scl_int = 0

    forced_malveillant = (
        (scl_int >= 7)
        or (campaign_id and has_urgency)
        or (scl_int >= 5 and campaign_id)
    )

    if forced_malveillant and verdict.get("verdict") != "malveillant":
        verdict["verdict"] = "malveillant"
        verdict["score"] = max(verdict.get("score", 0), 75)
        reasons = []
        if scl_int >= 5:
            reasons.append(f"SCL={scl_int} — classé indésirable par Microsoft")
        if campaign_id:
            reasons.append(f"X-Campaign-ID détecté : {campaign_id}")
        if has_urgency:
            reasons.append("Urgence artificielle détectée dans le corps")
        verdict["raisons"] = reasons + verdict.get("raisons", [])
        if "phishing" not in verdict.get("tags", []):
            verdict.setdefault("tags", []).append("phishing")

    return verdict


def _msg_to_eml(msg_path: str) -> str:
    """Convertit un fichier .msg Outlook en chaîne au format EML."""
    try:
        import extract_msg
    except ImportError:
        print("Erreur : installez extract-msg  →  pip install extract-msg")
        sys.exit(1)

    msg = extract_msg.Message(msg_path)
    # Reconstruction d'un EML minimal à partir des champs MAPI
    lines = []
    for header, value in [
        ("From",        msg.sender or ""),
        ("To",          msg.to or ""),
        ("Subject",     msg.subject or ""),
        ("Date",        str(msg.date) if msg.date else ""),
        ("Message-ID",  msg.messageId if hasattr(msg, "messageId") else ""),
    ]:
        if value:
            lines.append(f"{header}: {value}")

    lines.append("MIME-Version: 1.0")
    lines.append("Content-Type: text/plain; charset=utf-8")
    lines.append("")
    lines.append(msg.body or "")
    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <fichier.eml|.msg> [modele_ollama]")
        print("Exemple: python analyzer.py test.eml llama3")
        sys.exit(1)

    eml_path = sys.argv[1]
    model = sys.argv[2] if len(sys.argv) > 2 else MODEL

    if eml_path.lower().endswith(".msg"):
        print("[*] Conversion .msg → EML...")
        eml_content = _msg_to_eml(eml_path)
    else:
        with open(eml_path, "r", encoding="utf-8", errors="replace") as f:
            eml_content = f.read()

    result = analyze_eml(eml_content, model=model)

    print("\n" + "="*60)
    print("VERDICT FINAL")
    print("="*60)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
