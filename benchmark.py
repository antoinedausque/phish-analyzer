"""
PhishingAI - Benchmark LLM
Compare la précision de détection de phishing entre modèles Ollama.

Usage:
    .venv/bin/python benchmark.py
    .venv/bin/python benchmark.py --models llama3,qwen2.5vl:7b
    .venv/bin/python benchmark.py --models llama3 --dry-run
"""

import argparse
import json
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from analyzer import analyze_eml

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATASET_PATH   = Path("dataset/labels.json")
RESULTS_DIR    = Path("results")
DEFAULT_MODELS = ["llama3", "qwen2.5vl:7b"]

# Mapping verdict LLM → binaire
# "strict"    : seul "malveillant" compte comme détection positive
# "permissif" : "malveillant" OU "suspect" comptent comme détection positive
THRESHOLDS = {
    "strict":    {"malveillant"},
    "permissif": {"malveillant", "suspect"},
}

# ---------------------------------------------------------------------------
# Métriques
# ---------------------------------------------------------------------------

def compute_metrics(results: list[dict], threshold: set[str]) -> dict:
    """
    Calcule precision, recall, F1 pour un ensemble de résultats.
    Positif = email malveillant, Négatif = email légitime.
    """
    tp = fp = fn = tn = 0
    errors = []

    for r in results:
        true_pos  = r["true_label"] == "malveillant"
        pred_pos  = r["predicted_verdict"] in threshold

        if true_pos and pred_pos:
            tp += 1
        elif not true_pos and pred_pos:
            fp += 1
            errors.append(r)
        elif true_pos and not pred_pos:
            fn += 1
            errors.append(r)
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy  = (tp + tn) / len(results) if results else 0.0

    return {
        "precision": precision,
        "recall":    recall,
        "f1":        f1,
        "accuracy":  accuracy,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "n": len(results),
        "errors": errors,
    }


def compute_all_metrics(results: list[dict]) -> dict:
    """Calcule les métriques globales + par type de phishing."""
    out = {}
    for thresh_name, thresh_set in THRESHOLDS.items():
        global_metrics = compute_metrics(results, thresh_set)

        by_type = {}
        types = sorted(set(r["phishing_type"] for r in results))
        for t in types:
            subset = [r for r in results if r["phishing_type"] == t]
            by_type[t] = compute_metrics(subset, thresh_set)

        out[thresh_name] = {"global": global_metrics, "by_type": by_type}
    return out


# ---------------------------------------------------------------------------
# Affichage terminal (sans dépendance externe)
# ---------------------------------------------------------------------------

def pct(v: float) -> str:
    return f"{v*100:5.1f}%"


def print_separator(widths: list[int], char: str = "─"):
    print("─" + char.join(char * w for w in widths) + "─")


def print_table(title: str, headers: list[str], rows: list[list[str]]):
    widths = [max(len(h), max((len(str(r[i])) for r in rows), default=0)) for i, h in enumerate(headers)]
    total  = sum(widths) + 3 * (len(widths) - 1) + 2

    print(f"\n{'─' * total}")
    print(f" {title.center(total - 2)} ")
    print(f"{'─' * total}")

    header_row = " │ ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(f" {header_row} ")
    print("─" + "─┼─".join("─" * w for w in widths) + "─")

    for row in rows:
        line = " │ ".join(str(row[i]).ljust(widths[i]) for i in range(len(headers)))
        print(f" {line} ")

    print(f"{'─' * total}")


def display_model_results(model: str, metrics: dict):
    for thresh_name, data in metrics.items():
        title = f"Modèle : {model}  |  Seuil : {thresh_name}"
        headers = ["Type", "N", "Précision", "Rappel", "F1", "Accuracy", "TP", "FP", "FN", "TN"]
        rows = []

        for t, m in sorted(data["by_type"].items()):
            rows.append([
                t, m["n"],
                pct(m["precision"]), pct(m["recall"]), pct(m["f1"]), pct(m["accuracy"]),
                m["tp"], m["fp"], m["fn"], m["tn"],
            ])

        g = data["global"]
        rows.append([
            "GLOBAL", g["n"],
            pct(g["precision"]), pct(g["recall"]), pct(g["f1"]), pct(g["accuracy"]),
            g["tp"], g["fp"], g["fn"], g["tn"],
        ])
        print_table(title, headers, rows)


def display_comparison(all_model_metrics: dict[str, dict], threshold: str = "strict"):
    headers = ["Modèle", "N", "Précision", "Rappel", "F1", "Accuracy", "Durée moy."]
    rows = []
    for model, data in all_model_metrics.items():
        m = data["metrics"][threshold]["global"]
        avg_time = data["avg_time"]
        rows.append([
            model, m["n"],
            pct(m["precision"]), pct(m["recall"]), pct(m["f1"]), pct(m["accuracy"]),
            f"{avg_time:.1f}s",
        ])
    print_table(f"COMPARAISON MODÈLES (seuil={threshold})", headers, rows)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_benchmark(models: list[str], dataset: list[dict], dry_run: bool = False) -> dict:
    all_model_data = {}

    for model in models:
        print(f"\n{'='*60}")
        print(f"  Modèle : {model}")
        print(f"{'='*60}")

        results   = []
        durations = []

        for i, sample in enumerate(dataset, 1):
            eml_path = Path(sample["file"])
            label    = sample["true_label"]
            ptype    = sample["phishing_type"]
            desc     = sample.get("description", "")

            print(f"\n[{i:02d}/{len(dataset)}] {eml_path.name} ({ptype}) — attendu: {label}")

            if dry_run:
                print("  → DRY RUN, skip.")
                results.append({
                    "file": str(eml_path),
                    "true_label": label,
                    "phishing_type": ptype,
                    "description": desc,
                    "predicted_verdict": "N/A",
                    "predicted_score": 0,
                    "duration": 0,
                    "error": None,
                })
                continue

            if not eml_path.exists():
                print(f"  ⚠ Fichier introuvable : {eml_path}")
                continue

            eml_content = eml_path.read_text(encoding="utf-8", errors="replace")

            t0 = time.time()
            try:
                verdict = analyze_eml(eml_content, model=model)
                duration = time.time() - t0
                predicted = verdict.get("verdict", "inconnu").lower()
                score     = verdict.get("score", 0)

                correct = (
                    (label == "malveillant" and predicted in THRESHOLDS["strict"]) or
                    (label == "légitime"    and predicted == "légitime")
                )
                symbol = "✓" if correct else "✗"
                print(f"  {symbol} verdict={predicted} score={score}  ({duration:.1f}s)")

                results.append({
                    "file": str(eml_path),
                    "true_label": label,
                    "phishing_type": ptype,
                    "description": desc,
                    "predicted_verdict": predicted,
                    "predicted_score": score,
                    "predicted_raisons": verdict.get("raisons", []),
                    "predicted_tags": verdict.get("tags", []),
                    "duration": duration,
                    "error": None,
                })
                durations.append(duration)

            except Exception as e:
                duration = time.time() - t0
                print(f"  ✗ ERREUR : {e}")
                results.append({
                    "file": str(eml_path),
                    "true_label": label,
                    "phishing_type": ptype,
                    "description": desc,
                    "predicted_verdict": "erreur",
                    "predicted_score": 0,
                    "duration": duration,
                    "error": str(e),
                })

        metrics  = compute_all_metrics(results)
        avg_time = sum(durations) / len(durations) if durations else 0

        display_model_results(model, metrics)

        all_model_data[model] = {
            "results":  results,
            "metrics":  metrics,
            "avg_time": avg_time,
        }

    return all_model_data


# ---------------------------------------------------------------------------
# Sauvegarde JSON
# ---------------------------------------------------------------------------

def save_results(all_model_data: dict, output_dir: Path):
    output_dir.mkdir(exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = output_dir / f"benchmark_{ts}.json"

    # Retirer les détails d'erreurs (objets non-sérialisables éventuels)
    clean = {}
    for model, data in all_model_data.items():
        metrics_clean = {}
        for thresh, d in data["metrics"].items():
            metrics_clean[thresh] = {
                "global": {k: v for k, v in d["global"].items() if k != "errors"},
                "by_type": {
                    t: {k: v for k, v in m.items() if k != "errors"}
                    for t, m in d["by_type"].items()
                },
            }
        clean[model] = {
            "results":  data["results"],
            "metrics":  metrics_clean,
            "avg_time": data["avg_time"],
        }

    out_path.write_text(json.dumps(clean, ensure_ascii=False, indent=2))
    print(f"\n Résultats sauvegardés → {out_path}")


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Benchmark LLM phishing detection")
    parser.add_argument("--models",   default=",".join(DEFAULT_MODELS),
                        help="Modèles Ollama séparés par virgule")
    parser.add_argument("--dataset",  default=str(DATASET_PATH),
                        help="Chemin vers labels.json")
    parser.add_argument("--output",   default=str(RESULTS_DIR),
                        help="Dossier de sortie des résultats JSON")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Affiche le plan sans appeler Ollama")
    parser.add_argument("--threshold", default="strict", choices=["strict", "permissif"],
                        help="Seuil pour le tableau comparatif final")
    args = parser.parse_args()

    models  = [m.strip() for m in args.models.split(",")]
    dataset = json.loads(Path(args.dataset).read_text())

    print(f"\nBENCHMARK PHISHING LLM")
    print(f"Modèles  : {', '.join(models)}")
    print(f"Dataset  : {len(dataset)} emails ({Path(args.dataset)})")
    print(f"Dry-run  : {args.dry_run}")

    all_model_data = run_benchmark(models, dataset, dry_run=args.dry_run)

    if len(models) > 1:
        display_comparison(all_model_data, threshold=args.threshold)

    if not args.dry_run:
        save_results(all_model_data, Path(args.output))


if __name__ == "__main__":
    main()
