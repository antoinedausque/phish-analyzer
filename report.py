"""
PhishingAI - Report
Génère un résumé lisible des fichiers de benchmark et compare les runs.

Usage:
    .venv/bin/python report.py                        # dernier run
    .venv/bin/python report.py <fichier.json>         # run spécifique
    .venv/bin/python report.py --history              # historique de tous les runs
    .venv/bin/python report.py --compare f1.json f2.json  # comparaison de deux runs
"""

import argparse
import json
from datetime import datetime
from pathlib import Path

RESULTS_DIR = Path("results")
THRESHOLD   = "strict"  # seuil par défaut pour les rapports


# ---------------------------------------------------------------------------
# Helpers d'affichage
# ---------------------------------------------------------------------------

def pct(v: float) -> str:
    return f"{v * 100:.1f}%"


def delta_str(new: float, old: float) -> str:
    d = (new - old) * 100
    if abs(d) < 0.05:
        return "  —  "
    sign = "+" if d > 0 else ""
    return f"{sign}{d:.1f}%"


def verdict_icon(true_label: str, predicted: str) -> str:
    if predicted == "erreur":
        return "💥"
    if true_label == "malveillant":
        return "✓" if predicted == "malveillant" else ("~" if predicted == "suspect" else "✗")
    else:
        return "✓" if predicted == "légitime" else ("~" if predicted == "suspect" else "✗")


def hr(width: int = 72, char: str = "─"):
    print(char * width)


def section(title: str, width: int = 72):
    print()
    hr(width, "═")
    print(f"  {title}")
    hr(width, "═")


def table(headers: list, rows: list, col_sep: str = " │ "):
    widths = [
        max(len(str(h)), max((len(str(r[i])) for r in rows), default=0))
        for i, h in enumerate(headers)
    ]
    sep = "─┼─".join("─" * w for w in widths)

    print("─" + sep + "─")
    print(col_sep.join(str(h).ljust(widths[i]) for i, h in enumerate(headers)))
    print("─" + sep + "─")
    for row in rows:
        print(col_sep.join(str(row[i]).ljust(widths[i]) for i in range(len(headers))))
    print("─" + sep + "─")


# ---------------------------------------------------------------------------
# Chargement
# ---------------------------------------------------------------------------

def load(path: Path) -> dict:
    return json.loads(path.read_text())


def all_runs() -> list[Path]:
    return sorted(RESULTS_DIR.glob("benchmark_*.json"))


def latest_run() -> Path:
    runs = all_runs()
    if not runs:
        raise FileNotFoundError(f"Aucun fichier de benchmark dans {RESULTS_DIR}/")
    return runs[-1]


def run_timestamp(path: Path) -> str:
    # benchmark_20260507_133349.json → "2026-05-07 13:33:49"
    stem = path.stem.replace("benchmark_", "")
    try:
        dt = datetime.strptime(stem, "%Y%m%d_%H%M%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return stem


# ---------------------------------------------------------------------------
# Vue détaillée d'un run
# ---------------------------------------------------------------------------

def report_single(path: Path, threshold: str = THRESHOLD):
    data = load(path)
    ts   = run_timestamp(path)

    section(f"RAPPORT  {ts}  ({path.name})")

    for model, mdata in data.items():
        metrics = mdata["metrics"][threshold]
        g       = metrics["global"]
        results = mdata["results"]

        print(f"\n  Modèle : {model}  |  seuil : {threshold}  |  durée moy : {mdata['avg_time']:.1f}s")
        print()

        # Métriques globales
        rows = [[
            t,
            m["n"],
            pct(m["precision"]),
            pct(m["recall"]),
            pct(m["f1"]),
            pct(m["accuracy"]),
            m["tp"], m["fp"], m["fn"], m["tn"],
        ] for t, m in sorted(metrics["by_type"].items())]

        rows.append([
            "GLOBAL", g["n"],
            pct(g["precision"]), pct(g["recall"]), pct(g["f1"]), pct(g["accuracy"]),
            g["tp"], g["fp"], g["fn"], g["tn"],
        ])
        table(
            ["Type", "N", "Précision", "Rappel", "F1", "Accuracy", "TP", "FP", "FN", "TN"],
            rows,
        )

        # Détail email par email
        print()
        print(f"  Détail des {len(results)} emails :")
        print()
        detail_rows = []
        for r in results:
            icon  = verdict_icon(r["true_label"], r["predicted_verdict"])
            score = r.get("predicted_score", "—")
            tags  = ", ".join(r.get("predicted_tags", [])) or "—"
            detail_rows.append([
                icon,
                Path(r["file"]).name,
                r["phishing_type"],
                r["true_label"],
                r["predicted_verdict"],
                str(score),
                f"{r['duration']:.1f}s",
                tags[:45] + ("…" if len(tags) > 45 else ""),
            ])
        table(
            ["", "Fichier", "Type", "Attendu", "Prédit", "Score", "Durée", "Tags"],
            detail_rows,
        )

        # Erreurs / ratés
        errors = [r for r in results if r["predicted_verdict"] not in {"malveillant", "suspect", "légitime"}]
        misses = [
            r for r in results
            if verdict_icon(r["true_label"], r["predicted_verdict"]) == "✗"
        ]

        if misses:
            print(f"\n  Ratés ({len(misses)}) :")
            for r in misses:
                print(f"    ✗ {Path(r['file']).name}")
                print(f"      Attendu : {r['true_label']}  |  Prédit : {r['predicted_verdict']} (score {r.get('predicted_score','?')})")
                for reason in r.get("predicted_raisons", []):
                    print(f"      → {reason}")

        if errors:
            print(f"\n  Erreurs ({len(errors)}) :")
            for r in errors:
                print(f"    💥 {Path(r['file']).name} : {r.get('error', '?')}")


# ---------------------------------------------------------------------------
# Historique de tous les runs
# ---------------------------------------------------------------------------

def report_history(threshold: str = THRESHOLD):
    runs = all_runs()
    if not runs:
        print("Aucun run trouvé.")
        return

    section(f"HISTORIQUE  ({len(runs)} runs  |  seuil : {threshold})")

    # Collecte une ligne par run × modèle
    rows = []
    for path in runs:
        data = load(path)
        ts   = run_timestamp(path)
        for model, mdata in data.items():
            g = mdata["metrics"][threshold]["global"]
            rows.append([
                ts,
                model,
                str(g["n"]),
                pct(g["f1"]),
                pct(g["precision"]),
                pct(g["recall"]),
                pct(g["accuracy"]),
                f"{mdata['avg_time']:.1f}s",
                path.name,
            ])

    table(
        ["Date", "Modèle", "N", "F1", "Précision", "Rappel", "Accuracy", "Durée moy.", "Fichier"],
        rows,
    )

    # Évolution F1 entre le premier et le dernier run pour chaque modèle
    if len(runs) >= 2:
        print("\n  Évolution F1 (premier → dernier run) :")
        first = load(runs[0])
        last  = load(runs[-1])
        all_models = set(first) | set(last)
        for model in sorted(all_models):
            if model in first and model in last:
                f1_old = first[model]["metrics"][threshold]["global"]["f1"]
                f1_new = last[model]["metrics"][threshold]["global"]["f1"]
                d = delta_str(f1_new, f1_old)
                print(f"    {model:20s}  {pct(f1_old)} → {pct(f1_new)}  ({d})")


# ---------------------------------------------------------------------------
# Comparaison de deux runs
# ---------------------------------------------------------------------------

def report_compare(path_a: Path, path_b: Path, threshold: str = THRESHOLD):
    data_a = load(path_a)
    data_b = load(path_b)
    ts_a   = run_timestamp(path_a)
    ts_b   = run_timestamp(path_b)

    section(f"COMPARAISON\n  A : {ts_a}\n  B : {ts_b}")

    all_models = sorted(set(data_a) | set(data_b))

    for model in all_models:
        print(f"\n  Modèle : {model}")

        if model not in data_a:
            print("    (absent du run A)")
            continue
        if model not in data_b:
            print("    (absent du run B)")
            continue

        metrics_a = data_a[model]["metrics"][threshold]
        metrics_b = data_b[model]["metrics"][threshold]
        ga, gb    = metrics_a["global"], metrics_b["global"]

        rows = []

        # Global
        rows.append([
            "GLOBAL",
            pct(ga["f1"]),
            pct(gb["f1"]),
            delta_str(gb["f1"], ga["f1"]),
            pct(ga["precision"]),
            pct(gb["precision"]),
            delta_str(gb["precision"], ga["precision"]),
            pct(ga["recall"]),
            pct(gb["recall"]),
            delta_str(gb["recall"], ga["recall"]),
        ])

        # Par type
        all_types = sorted(set(metrics_a["by_type"]) | set(metrics_b["by_type"]))
        for t in all_types:
            ma = metrics_a["by_type"].get(t, {})
            mb = metrics_b["by_type"].get(t, {})
            if not ma or not mb:
                continue
            rows.append([
                t,
                pct(ma["f1"]),
                pct(mb["f1"]),
                delta_str(mb["f1"], ma["f1"]),
                pct(ma["precision"]),
                pct(mb["precision"]),
                delta_str(mb["precision"], ma["precision"]),
                pct(ma["recall"]),
                pct(mb["recall"]),
                delta_str(mb["recall"], ma["recall"]),
            ])

        table(
            ["Type", "F1 A", "F1 B", "ΔF1", "Prec A", "Prec B", "ΔPrec", "Rap A", "Rap B", "ΔRap"],
            rows,
        )

        # Changements de verdict email par email
        results_a = {Path(r["file"]).name: r for r in data_a[model]["results"]}
        results_b = {Path(r["file"]).name: r for r in data_b[model]["results"]}
        changes = []
        for name, ra in results_a.items():
            rb = results_b.get(name)
            if rb and ra["predicted_verdict"] != rb["predicted_verdict"]:
                changes.append((name, ra["predicted_verdict"], rb["predicted_verdict"], ra["true_label"]))

        if changes:
            print(f"\n  Changements de verdict ({len(changes)}) :")
            for name, va, vb, truth in changes:
                icon_a = verdict_icon(truth, va)
                icon_b = verdict_icon(truth, vb)
                print(f"    {name}")
                print(f"      A: {icon_a} {va}  →  B: {icon_b} {vb}  (vérité: {truth})")
        else:
            print("\n  Aucun changement de verdict entre les deux runs.")

        # Temps moyen
        ta = data_a[model]["avg_time"]
        tb = data_b[model]["avg_time"]
        dt = tb - ta
        sign = "+" if dt >= 0 else ""
        print(f"\n  Durée moy. : {ta:.1f}s (A) → {tb:.1f}s (B)  ({sign}{dt:.1f}s)")


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Rapport benchmark phishing LLM")
    parser.add_argument("file", nargs="?", help="Fichier JSON de benchmark (défaut : dernier run)")
    parser.add_argument("--history",  action="store_true", help="Affiche l'historique de tous les runs")
    parser.add_argument("--compare",  nargs=2, metavar=("A", "B"), help="Compare deux fichiers JSON")
    parser.add_argument("--threshold", default=THRESHOLD, choices=["strict", "permissif"])
    args = parser.parse_args()

    if args.history:
        report_history(threshold=args.threshold)

    elif args.compare:
        report_compare(Path(args.compare[0]), Path(args.compare[1]), threshold=args.threshold)

    else:
        path = Path(args.file) if args.file else latest_run()
        report_single(path, threshold=args.threshold)


if __name__ == "__main__":
    main()
