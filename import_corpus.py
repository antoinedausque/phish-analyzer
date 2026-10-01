"""
PhishingAI - Import corpus
Extrait des emails depuis les corpus Nazario (.mbox) et SpamAssassin (dossier de fichiers)
et les ajoute au dataset avec leurs labels.

Usage:
    # Importer N phishings depuis Nazario + N légitimes depuis SpamAssassin
    .venv/bin/python import_corpus.py --count 20

    # Choisir les sources manuellement
    .venv/bin/python import_corpus.py --phishing corpus/phishing0.mbox --ham corpus/easy_ham --count 15

    # Juste inspecter sans importer
    .venv/bin/python import_corpus.py --dry-run --count 5
"""

import argparse
import email
import email.policy
import hashlib
import json
import mailbox
import random
import re
import shutil
from email import message_from_string
from email.header import decode_header
from pathlib import Path

DATASET_DIR   = Path("dataset/emails")
LABELS_PATH   = Path("dataset/labels.json")
DEFAULT_MBOX  = Path("corpus/phishing0.mbox")
DEFAULT_HAM   = Path("corpus/easy_ham")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def decode_mime_str(value: str) -> str:
    if not value:
        return ""
    parts = decode_header(value)
    out = []
    for part, charset in parts:
        if isinstance(part, bytes):
            safe_charset = charset if charset and charset.lower() not in ("unknown-8bit", "x-unknown") else "latin-1"
            out.append(part.decode(safe_charset, errors="replace"))
        else:
            out.append(part)
    return " ".join(out)


def extract_text(msg: email.message.Message) -> str:
    body = []
    if msg.is_multipart():
        for part in msg.walk():
            ct  = part.get_content_type()
            cd  = str(part.get("Content-Disposition", ""))
            if ct == "text/plain" and "attachment" not in cd:
                try:
                    charset = part.get_content_charset() or "utf-8"
                    body.append(part.get_payload(decode=True).decode(charset, errors="replace"))
                except Exception:
                    pass
    else:
        try:
            charset = msg.get_content_charset() or "utf-8"
            body.append(msg.get_payload(decode=True).decode(charset, errors="replace"))
        except Exception:
            body.append(str(msg.get_payload()))
    return "\n".join(body)[:500]   # extrait court pour l'aperçu


def msg_id(msg: email.message.Message) -> str:
    """Identifiant stable basé sur From + Subject + Date."""
    raw = f"{msg.get('From','')}{msg.get('Subject','')}{msg.get('Date','')}"
    return hashlib.md5(raw.encode()).hexdigest()[:10]


def is_probably_phishing(msg: email.message.Message) -> bool:
    """Filtre grossier : garde les emails avec des signaux de phishing évidents."""
    subject = decode_mime_str(msg.get("Subject", "")).lower()
    body    = extract_text(msg).lower()
    text    = subject + " " + body

    keywords = [
        "account", "verify", "password", "update", "suspend", "click", "confirm",
        "login", "bank", "paypal", "ebay", "amazon", "citibank", "credit", "secure",
        "urgent", "limited", "warning", "expire", "validation",
    ]
    return sum(1 for kw in keywords if kw in text) >= 2


# ---------------------------------------------------------------------------
# Import Nazario (.mbox)
# ---------------------------------------------------------------------------

def import_from_mbox(mbox_path: Path, count: int, existing_ids: set) -> list[dict]:
    print(f"\n[Nazario] Lecture de {mbox_path}...")
    mbox   = mailbox.mbox(str(mbox_path))
    total  = sum(1 for _ in mbox)
    print(f"  {total} emails dans le corpus.")

    candidates = []
    mbox   = mailbox.mbox(str(mbox_path))
    for msg in mbox:
        mid = msg_id(msg)
        if mid in existing_ids:
            continue
        if is_probably_phishing(msg):
            candidates.append((mid, msg))

    print(f"  {len(candidates)} candidats après filtre phishing.")
    random.shuffle(candidates)
    selected = candidates[:count]

    imported = []
    for mid, msg in selected:
        subject = decode_mime_str(msg.get("Subject", "(sans sujet)"))
        sender  = msg.get("From", "")

        # Sauvegarde du .eml
        filename  = f"nazario_phishing_{mid}.eml"
        dest_path = DATASET_DIR / filename
        with open(dest_path, "wb") as f:
            f.write(msg.as_bytes())

        imported.append({
            "file":        f"dataset/emails/{filename}",
            "true_label":  "malveillant",
            "phishing_type": "nazario",
            "description": f"Corpus Nazario — From: {sender[:60]} | Sujet: {subject[:60]}",
        })
        print(f"  ✓ {filename}  [{subject[:50]}]")

    return imported


# ---------------------------------------------------------------------------
# Import SpamAssassin ham (dossier de fichiers)
# ---------------------------------------------------------------------------

def import_from_ham(ham_dir: Path, count: int, existing_ids: set) -> list[dict]:
    print(f"\n[SpamAssassin] Lecture de {ham_dir}...")
    files = [f for f in ham_dir.iterdir() if f.is_file() and not f.name.startswith(".")]
    print(f"  {len(files)} fichiers dans le dossier.")

    candidates = []
    for f in files:
        try:
            raw = f.read_text(encoding="utf-8", errors="replace")
            msg = message_from_string(raw, policy=email.policy.compat32)
            mid = msg_id(msg)
            if mid not in existing_ids:
                candidates.append((mid, msg, f))
        except Exception:
            continue

    print(f"  {len(candidates)} candidats (non-dupliqués).")
    random.shuffle(candidates)
    selected = candidates[:count]

    imported = []
    for mid, msg, src_file in selected:
        subject = decode_mime_str(msg.get("Subject", "(sans sujet)"))
        sender  = msg.get("From", "")

        filename  = f"spamassassin_ham_{mid}.eml"
        dest_path = DATASET_DIR / filename
        shutil.copy(src_file, dest_path)

        imported.append({
            "file":        f"dataset/emails/{filename}",
            "true_label":  "légitime",
            "phishing_type": "légitime",
            "description": f"SpamAssassin easy_ham — From: {sender[:60]} | Sujet: {subject[:60]}",
        })
        print(f"  ✓ {filename}  [{subject[:50]}]")

    return imported


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phishing", default=str(DEFAULT_MBOX))
    parser.add_argument("--ham",      default=str(DEFAULT_HAM))
    parser.add_argument("--count",    type=int, default=10,
                        help="Nombre d'emails à importer par classe (défaut: 10)")
    parser.add_argument("--dry-run",  action="store_true")
    parser.add_argument("--seed",     type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)

    # Chargement du dataset existant
    existing = json.loads(LABELS_PATH.read_text()) if LABELS_PATH.exists() else []
    existing_ids = set()
    for e in existing:
        try:
            raw = Path(e["file"]).read_text(encoding="utf-8", errors="replace")
            msg = message_from_string(raw, policy=email.policy.compat32)
            existing_ids.add(msg_id(msg))
        except Exception:
            pass

    print(f"Dataset existant : {len(existing)} emails.")
    print(f"Import demandé   : {args.count} phishings + {args.count} légitimes")

    if args.dry_run:
        print("\nDRY RUN — aucun fichier ne sera écrit.")
        return

    DATASET_DIR.mkdir(parents=True, exist_ok=True)

    new_phishing = import_from_mbox(Path(args.phishing), args.count, existing_ids)
    new_ham      = import_from_ham(Path(args.ham),      args.count, existing_ids)

    new_entries = new_phishing + new_ham
    updated     = existing + new_entries

    LABELS_PATH.write_text(json.dumps(updated, ensure_ascii=False, indent=2))

    print(f"\nDataset mis à jour : {len(existing)} → {len(updated)} emails")
    print(f"  +{len(new_phishing)} phishings Nazario")
    print(f"  +{len(new_ham)} légitimes SpamAssassin")
    print(f"  Fichier : {LABELS_PATH}")


if __name__ == "__main__":
    main()
