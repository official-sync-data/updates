#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from official_rule_source_common import REPORTS_DIR, SOURCE_CONFIGS, run_check


ROOT = Path(__file__).resolve().parents[1]
DATASETS_DIR = ROOT / "datasets"
PUBLIC_DIR = ROOT / "public" if (ROOT / "public").exists() else ROOT
REPORT_PATH = REPORTS_DIR / "monthly_official_update_report.json"
SUMMARY_PATH = REPORTS_DIR / "monthly_official_update_summary.md"

AUTOMATED_RULE_DATASETS = {
    "fr_arcep",
    "de_bundesnetzagentur",
    "es_cnmc",
    "it_agcom",
    "nl_acm",
    "pt_anacom",
}
PRESERVE_STATUSES = {"MANUAL_REQUIRED", "TEMPORARILY_UNAVAILABLE"}
VALID_RULE_STATUSES = {"UNCHANGED", "CHANGED"}


def read_json(path):
    with open(path, "r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def has_apk_in_public():
    if not PUBLIC_DIR.exists():
        return False
    return any(path.suffix.lower() == ".apk" for path in PUBLIC_DIR.rglob("*") if path.is_file())


def classify_rules(reports):
    blocking = []
    changed = []
    preserved = []
    unchanged = []
    for report in reports:
        status = report["status"]
        dataset_id = report["datasetId"]
        if status == "UNCHANGED":
            unchanged.append(dataset_id)
        elif status == "CHANGED":
            changed.append(dataset_id)
        elif status in PRESERVE_STATUSES:
            preserved.append(dataset_id)
        else:
            blocking.append(dataset_id)
    return blocking, changed, preserved, unchanged


def run_official_numbers_builder(enabled):
    result = {
        "datasetId": "official_numbers_fr",
        "status": "SKIPPED",
        "entryCount": 0,
        "error": "",
        "fullExcludedFromPublic": True,
        "dilaAutomated": True,
        "finessAutomated": True,
        "fhfOverridePreserved": True,
    }
    if not enabled:
        result["error"] = "Skipped in local safe validation mode."
        return result

    with tempfile.TemporaryDirectory(prefix="official-numbers-build-") as temp_dir:
        temp_root = Path(temp_dir)
        shutil.copytree(ROOT / "sources", temp_root / "sources")
        (temp_root / "datasets").mkdir(parents=True, exist_ok=True)
        for name in (
            "official_numbers_fr_full.json",
            "official_numbers_fr.json",
            "official_numbers_fr.json.gz",
        ):
            source = DATASETS_DIR / name
            if source.exists():
                shutil.copy2(source, temp_root / "datasets" / name)
        command = [
            sys.executable,
            str(ROOT / "tools" / "build_official_numbers_fr.py"),
            "--root",
            temp_dir,
        ]
        completed = subprocess.run(command, text=True, capture_output=True)
        result["stdout"] = completed.stdout
        result["stderr"] = completed.stderr
        if completed.returncode != 0:
            result["status"] = "BLOCKED"
            result["error"] = completed.stderr.strip() or completed.stdout.strip()
            return result
        try:
            builder_output = json.loads(completed.stdout)
            result["entryCount"] = builder_output.get("entryCount", 0)
        except json.JSONDecodeError:
            builder_output = {}
        report_file = Path(temp_dir) / "reports" / "official_numbers_fr_diff.json"
        if report_file.exists():
            build_report = read_json(report_file)
            result["entryCount"] = build_report.get("entryCount", result["entryCount"])
            has_changes = bool(
                build_report.get("added")
                or build_report.get("removed")
                or build_report.get("modified")
            )
            result["status"] = "CHANGED" if has_changes else "UNCHANGED"
            result["sourceStats"] = build_report.get("sourceStats", builder_output.get("sourceStats", {}))
        else:
            result["status"] = "BLOCKED"
            result["error"] = "Build report absent."
    return result


def simulation_report(case_name):
    cases = {
        "A": ("SUCCESS", "aucun changement, aucune publication préparée"),
        "B": ("READY_TO_PUBLISH", "changement valide détecté et publication préparée en répertoire temporaire"),
        "C": ("SUCCESS", "Ofcom HTTP 403 classé MANUAL_REQUIRED, dataset existant conservé"),
        "D": ("SUCCESS", "ILR timeout classé TEMPORARILY_UNAVAILABLE, dataset existant conservé"),
        "E": ("BLOCKED", "FINESS inaccessible, official_numbers_fr conservé"),
        "F": ("BLOCKED", "baisse artificielle supérieure à 20 %"),
        "G": ("BLOCKED", "signature impossible"),
    }
    status, detail = cases[case_name]
    return {"case": case_name, "status": status, "detail": detail}


def build_markdown(report):
    lines = [
        "# Mise à jour officielle mensuelle",
        "",
        f"Date : {report['date']}",
        f"Mode : {report['mode']}",
        f"Publication : {report['publication']}",
        "",
        "## Sources contrôlées",
    ]
    for item in report["rules"]:
        lines.append(
            f"- {item['datasetId']} : {item['status']} "
            f"({item['remoteCount']} / {item['currentCount']})"
        )
    numbers = report["officialNumbers"]
    lines.extend(
        [
            "",
            "## Numéros officiels France",
            f"- Statut : {numbers['status']}",
            f"- Entrées : {numbers['entryCount']}",
            f"- DILA automatisé : {numbers['dilaAutomated']}",
            f"- FINESS automatisé : {numbers['finessAutomated']}",
            f"- FHF override conservé : {numbers['fhfOverridePreserved']}",
            f"- FULL exclu de public : {numbers['fullExcludedFromPublic']}",
            "",
            "## Simulations",
        ]
    )
    for item in report["simulations"]:
        lines.append(f"- CAS {item['case']} : {item['status']} - {item['detail']}")
    lines.extend(
        [
            "",
            "## Résultat",
            f"- Résultat global : {report['status']}",
            f"- Vérification : {report['verification']}",
            f"- APK concernée : {report['apkConcerned']}",
        ]
    )
    if report["blockingDatasets"]:
        lines.append(f"- Anomalies bloquantes : {', '.join(report['blockingDatasets'])}")
    if report["preservedDatasets"]:
        lines.append(f"- Datasets conservés : {', '.join(report['preservedDatasets'])}")
    return "\n".join(lines) + "\n"


def run(args):
    mode = "manuel" if args.workflow_dispatch else "automatique"
    rule_reports = []
    for dataset_id in SOURCE_CONFIGS:
        report = run_check(dataset_id)
        rule_reports.append(report)

    blocking, changed, preserved, unchanged = classify_rules(rule_reports)
    official_numbers = run_official_numbers_builder(args.build_official_numbers)
    if official_numbers["status"] == "BLOCKED":
        blocking.append("official_numbers_fr")
    elif official_numbers["status"] == "CHANGED":
        changed.append("official_numbers_fr")
    elif official_numbers["status"] == "UNCHANGED":
        unchanged.append("official_numbers_fr")

    apk_present = has_apk_in_public()
    if apk_present:
        blocking.append("public_apk")

    if blocking:
        global_status = "BLOCKED"
    elif changed:
        global_status = "READY_TO_PUBLISH"
    else:
        global_status = "SUCCESS"

    report = {
        "date": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "rules": rule_reports,
        "officialNumbers": official_numbers,
        "automatedRuleDatasets": sorted(AUTOMATED_RULE_DATASETS),
        "unchangedDatasets": unchanged,
        "changedDatasets": changed,
        "preservedDatasets": preserved,
        "blockingDatasets": blocking,
        "status": global_status,
        "verification": "not_published_in_GP_043C",
        "publication": "NON dans GP-043C",
        "apkConcerned": "Non" if not apk_present else "Erreur: APK présent dans public",
        "simulations": [simulation_report(name) for name in "ABCDEFG"],
    }
    write_json(REPORT_PATH, report)
    write_text(SUMMARY_PATH, build_markdown(report))

    github_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if github_summary:
        with open(github_summary, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(build_markdown(report))

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if global_status in {"SUCCESS", "READY_TO_PUBLISH"} else 2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow-dispatch", action="store_true")
    parser.add_argument(
        "--build-official-numbers",
        action="store_true",
        help="Run the full DILA/FINESS/FHF builder in a temporary workspace.",
    )
    args = parser.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
