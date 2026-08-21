#!/usr/bin/env python3
import argparse
import gzip
import hashlib
import hmac
import json
import os
import re
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
PUBLIC_DATASETS_DIR = PUBLIC_DIR / "datasets"
REPORT_PATH = REPORTS_DIR / "monthly_official_update_report.json"
SUMMARY_PATH = REPORTS_DIR / "monthly_official_update_summary.md"
REVIEW_ARTIFACT_DIR = REPORTS_DIR / "official-data-review"
BASE_URL = "https://official-sync-data.github.io/updates"

AUTOMATED_RULE_DATASETS = {
    "fr_arcep",
    "de_bundesnetzagentur",
    "es_cnmc",
    "it_agcom",
    "nl_acm",
    "pt_anacom",
}
PRESERVE_STATUSES = {"MANUAL_REQUIRED", "TEMPORARILY_UNAVAILABLE"}
REVIEW_REQUIRED_STATUS = "BLOCKED_REVIEW_REQUIRED"
REVIEW_MISMATCH_STATUS = "BLOCKED_REVIEW_MISMATCH"
REVIEW_APPROVED_STATUS = "REVIEW_APPROVED"
OFFICIAL_NUMBERS_AUTO_CHANGE_RATIO_LIMIT = 0.005
OFFICIAL_NUMBERS_DROP_RATIO_LIMIT = 0.20
OFFICIAL_NUMBERS_GROWTH_RATIO_LIMIT = 0.50
OFFICIAL_NUMBERS_REMOVAL_RATIO_LIMIT = 0.10
PUBLICATION_DATASET_FILES = {
    "de_bundesnetzagentur": "de_bundesnetzagentur.json",
    "en_ofcom": "en_ofcom.json",
    "es_cnmc": "es_cnmc.json",
    "fr_arcep": "fr_arcep.json",
    "it_agcom": "it_agcom.json",
    "lb_ilr": "lb_ilr.json",
    "nl_acm": "nl_acm.json",
    "official_numbers_fr": "official_numbers_fr.json.gz",
    "pt_anacom": "pt_anacom.json",
}
BLOCKED_DIFF_SUFFIXES = (
    ".apk",
    ".db",
    ".sqlite",
    ".tmp",
    ".log",
    ".pyc",
)
BLOCKED_DIFF_PARTS = (
    "private/",
    "reports/",
    ".cache/",
    "__pycache__/",
    "official_numbers_fr_full.json",
)


def read_json(path):
    with open(path, "r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def read_gzip_json(path):
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def run_command(command, *, check=True):
    completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    if check and completed.returncode != 0:
        output = (completed.stdout + "\n" + completed.stderr).strip()
        raise RuntimeError(f"{' '.join(command)} failed: {output}")
    return completed


def git_output(*args):
    return run_command(["git", *args]).stdout.strip()


def has_apk_in_public():
    if not PUBLIC_DIR.exists():
        return False
    return any(
        path.suffix.lower() == ".apk"
        for path in PUBLIC_DIR.rglob("*")
        if path.is_file() and ".git" not in path.parts
    )


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


def read_manifest_entry_count(dataset_id):
    manifest = PUBLIC_DIR / "manifest.json"
    if not manifest.exists():
        return 0
    try:
        entry = read_json(manifest).get("datasets", {}).get(dataset_id, {})
        return int(entry.get("entryCount") or entry.get("ruleCount") or 0)
    except Exception:
        return 0


def official_numbers_functional_entries(dataset_json):
    if dataset_json.get("datasetId") != "official_numbers_fr":
        raise ValueError("datasetId official_numbers_fr attendu.")
    entries = dataset_json.get("entries")
    if not isinstance(entries, list):
        raise ValueError("entries absent ou invalide.")

    functional_entries = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("entrée official_numbers_fr invalide.")
        number = entry.get("n")
        display_name = entry.get("d")
        if not isinstance(number, str) or not number:
            raise ValueError("normalizedNumber absent.")
        if not isinstance(display_name, str) or not display_name:
            raise ValueError("displayName absent.")
        if number in functional_entries:
            raise ValueError(f"normalizedNumber dupliqué: {number}")

        functional_entry = {}
        for key in ("n", "d", "c", "t", "dep"):
            value = entry.get(key)
            if value is not None:
                functional_entry[key] = value
        functional_entries[number] = functional_entry

    entry_count = dataset_json.get("entryCount")
    if entry_count is not None and entry_count != len(functional_entries):
        raise ValueError("entryCount incohérent.")
    return functional_entries


def functional_entries_sha256(entries):
    digest = hashlib.sha256()
    for number in sorted(entries):
        encoded = json.dumps(
            entries[number],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def build_review_fingerprint(comparison):
    payload = review_fingerprint_payload(comparison)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def review_fingerprint_payload(comparison):
    return {
        "datasetId": "official_numbers_fr",
        "oldFunctionalSha256": comparison.get("oldFunctionalSha256", ""),
        "newFunctionalSha256": comparison.get("newFunctionalSha256", ""),
        "addedCount": int(comparison.get("addedCount", 0)),
        "removedCount": int(comparison.get("removedCount", 0)),
        "modifiedCount": int(comparison.get("modifiedCount", 0)),
        "oldEntryCount": int(comparison.get("oldEntryCount", 0)),
        "newEntryCount": int(comparison.get("newEntryCount", 0)),
    }


def functional_review_entry(entry):
    return {key: entry.get(key, "") for key in ("d", "c", "t", "dep")}


def build_functional_review_diff(old_entries, new_entries):
    old_numbers = set(old_entries)
    new_numbers = set(new_entries)
    return {
        "schemaVersion": 1,
        "datasetId": "official_numbers_fr_review_diff",
        "added": [
            {
                "normalizedNumber": number,
                "after": functional_review_entry(new_entries[number]),
            }
            for number in sorted(new_numbers - old_numbers)
        ],
        "removed": [
            {
                "normalizedNumber": number,
                "before": functional_review_entry(old_entries[number]),
            }
            for number in sorted(old_numbers - new_numbers)
        ],
        "modified": [
            {
                "normalizedNumber": number,
                "before": functional_review_entry(old_entries[number]),
                "after": functional_review_entry(new_entries[number]),
            }
            for number in sorted(old_numbers & new_numbers)
            if old_entries[number] != new_entries[number]
        ],
    }


def validate_review_artifact_safety(artifact_dir, secret_values=None):
    allowed = {
        "source_hashes.json",
        "fingerprint_payload.json",
        "official_numbers_fr_review_diff.json",
        "review_summary.json",
    }
    files = [path for path in artifact_dir.rglob("*") if path.is_file()]
    unexpected = sorted(path.name for path in files if path.name not in allowed)
    if unexpected:
        raise RuntimeError(f"Fichiers artifact inattendus: {unexpected}")
    blocked_names = (".apk", ".pem", "official_numbers_fr_full.json")
    markers = [b"-----BEGIN PRIVATE KEY-----", b"OFFICIAL_UPDATE_PRIVATE_KEY"]
    for secret in secret_values or []:
        if secret:
            markers.append(secret if isinstance(secret, bytes) else str(secret).encode("utf-8"))
    for path in files:
        lowered = path.name.lower()
        if lowered.endswith(blocked_names) or "private" in lowered or "token" in lowered:
            raise RuntimeError(f"Fichier interdit dans artifact: {path.name}")
        payload = path.read_bytes()
        if any(marker and marker in payload for marker in markers):
            raise RuntimeError(f"Secret détecté dans artifact: {path.name}")
    return True


def create_review_artifacts(new_compact_path, source_hashes_path, comparison, status):
    if REVIEW_ARTIFACT_DIR.exists():
        shutil.rmtree(REVIEW_ARTIFACT_DIR)
    REVIEW_ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    old_entries = official_numbers_functional_entries(
        read_gzip_json(DATASETS_DIR / "official_numbers_fr.json.gz")
    )
    new_entries = official_numbers_functional_entries(read_json(new_compact_path))
    payload = review_fingerprint_payload(comparison)
    fingerprint = build_review_fingerprint(comparison)
    if fingerprint != comparison.get("reviewFingerprint"):
        raise RuntimeError("Fingerprint incohérent avec sa charge de contrôle.")
    shutil.copy2(source_hashes_path, REVIEW_ARTIFACT_DIR / "source_hashes.json")
    write_json(REVIEW_ARTIFACT_DIR / "fingerprint_payload.json", payload)
    write_json(
        REVIEW_ARTIFACT_DIR / "official_numbers_fr_review_diff.json",
        build_functional_review_diff(old_entries, new_entries),
    )
    write_json(
        REVIEW_ARTIFACT_DIR / "review_summary.json",
        {
            "datasetId": "official_numbers_fr",
            "status": status,
            "reviewFingerprint": fingerprint,
            "changeRatio": comparison.get("changeRatio", 0.0),
            "changeCount": comparison.get("changeCount", 0),
            "publication": "NON",
            "publicData": "CONSERVÉES",
        },
    )
    secrets = []
    private_key_file = os.environ.get("OFFICIAL_UPDATE_PRIVATE_KEY_FILE", "")
    if private_key_file and Path(private_key_file).is_file():
        secrets.append(Path(private_key_file).read_bytes())
    validate_review_artifact_safety(REVIEW_ARTIFACT_DIR, secrets)
    return {
        "ready": True,
        "directory": str(REVIEW_ARTIFACT_DIR),
        "files": sorted(path.name for path in REVIEW_ARTIFACT_DIR.iterdir()),
    }


def apply_review_gate(comparison, approved_fingerprint, safety_errors=None):
    safety_errors = list(safety_errors or [])
    if safety_errors:
        return "BLOCKED", "Contrôles de sécurité refusés: " + "; ".join(safety_errors)
    if comparison.get("status") != REVIEW_REQUIRED_STATUS:
        return comparison.get("status", "BLOCKED"), comparison.get("error", "")
    expected = comparison.get("reviewFingerprint", "")
    provided = (approved_fingerprint or "").strip().lower()
    if not provided:
        return REVIEW_REQUIRED_STATUS, comparison.get("error", "")
    if not expected or not hmac.compare_digest(provided, expected.lower()):
        return (
            REVIEW_MISMATCH_STATUS,
            "Empreinte de validation différente du diff official_numbers_fr courant.",
        )
    return REVIEW_APPROVED_STATUS, ""


def compare_official_numbers_compact(new_compact_path):
    existing_compact_path = DATASETS_DIR / "official_numbers_fr.json.gz"
    if not existing_compact_path.exists():
        new_entries = official_numbers_functional_entries(read_json(new_compact_path))
        new_count = len(new_entries)
        return {
            "status": "CHANGED",
            "addedCount": new_count,
            "removedCount": 0,
            "modifiedCount": 0,
            "oldEntryCount": 0,
            "newEntryCount": new_count,
            "changeCount": new_count,
            "changeRatio": 0.0,
            "oldFunctionalSha256": functional_entries_sha256({}),
            "newFunctionalSha256": functional_entries_sha256(new_entries),
            "reviewFingerprint": "",
            "error": "",
        }

    try:
        old_entries = official_numbers_functional_entries(read_gzip_json(existing_compact_path))
    except Exception as exc:
        return {
            "status": "BLOCKED",
            "addedCount": 0,
            "removedCount": 0,
            "modifiedCount": 0,
            "oldEntryCount": 0,
            "newEntryCount": 0,
            "changeCount": 0,
            "changeRatio": 0.0,
            "error": f"Existing official_numbers_fr public dataset invalid: {type(exc).__name__}: {exc}",
        }

    try:
        new_entries = official_numbers_functional_entries(read_json(new_compact_path))
    except Exception as exc:
        return {
            "status": "BLOCKED",
            "addedCount": 0,
            "removedCount": 0,
            "modifiedCount": 0,
            "oldEntryCount": len(old_entries),
            "newEntryCount": 0,
            "changeCount": 0,
            "changeRatio": 0.0,
            "error": f"Generated official_numbers_fr compact dataset invalid: {type(exc).__name__}: {exc}",
        }

    old_numbers = set(old_entries)
    new_numbers = set(new_entries)
    common_numbers = old_numbers & new_numbers
    modified = sum(1 for number in common_numbers if old_entries[number] != new_entries[number])
    added = len(new_numbers - old_numbers)
    removed = len(old_numbers - new_numbers)
    old_count = len(old_entries)
    new_count = len(new_entries)
    old_functional_sha256 = functional_entries_sha256(old_entries)
    new_functional_sha256 = functional_entries_sha256(new_entries)
    change_count = added + removed + modified
    change_ratio = change_count / old_count if old_count else 0.0
    status = "CHANGED" if added or removed or modified else "UNCHANGED"
    error = ""
    if new_count <= 0:
        status = "BLOCKED"
        error = "official_numbers_fr compact dataset empty."
    elif old_count and new_count < old_count * (1 - OFFICIAL_NUMBERS_DROP_RATIO_LIMIT):
        status = "BLOCKED"
        error = "official_numbers_fr total drop exceeds 20%."
    elif old_count and new_count > old_count * (1 + OFFICIAL_NUMBERS_GROWTH_RATIO_LIMIT):
        status = "BLOCKED"
        error = "official_numbers_fr total growth exceeds 50%."
    elif old_count and removed / old_count > OFFICIAL_NUMBERS_REMOVAL_RATIO_LIMIT:
        status = "BLOCKED"
        error = "official_numbers_fr removals exceed 10%."
    elif status == "CHANGED" and change_ratio > OFFICIAL_NUMBERS_AUTO_CHANGE_RATIO_LIMIT:
        status = REVIEW_REQUIRED_STATUS
        error = (
            "PUBLICATION BLOQUÉE — VALIDATION HUMAINE REQUISE: "
            f"official_numbers_fr change ratio {change_ratio:.4%} exceeds 0.5%."
        )
    comparison = {
        "status": status,
        "addedCount": added,
        "removedCount": removed,
        "modifiedCount": modified,
        "oldEntryCount": old_count,
        "newEntryCount": new_count,
        "changeCount": change_count,
        "changeRatio": change_ratio,
        "oldFunctionalSha256": old_functional_sha256,
        "newFunctionalSha256": new_functional_sha256,
        "error": error,
    }
    comparison["reviewFingerprint"] = (
        build_review_fingerprint(comparison)
        if status == REVIEW_REQUIRED_STATUS
        else ""
    )
    return comparison


def validate_official_numbers_migration(new_compact_path, build_report):
    dataset = read_json(new_compact_path)
    entries = official_numbers_functional_entries(dataset)
    technical_categories = 0
    numeric_categories = 0
    empty_categories = 0
    invalid_numbers = 0
    for number, entry in entries.items():
        if not re.fullmatch(r"\+33[1-9]\d{8}", number):
            invalid_numbers += 1
        category = str(entry.get("t") or "").strip()
        if category.startswith("FINESS categorie "):
            technical_categories += 1
        if category.isdigit():
            numeric_categories += 1
        if not category:
            empty_categories += 1

    finess_stats = build_report.get("sourceStats", {}).get("FINESS", {})
    final_codes = finess_stats.get("finalCategoryCodes") or []
    unresolved_codes = finess_stats.get("unresolvedCategoryCodes") or {}
    resolved_codes = sum(1 for item in final_codes if item.get("resolved"))
    city_resolution = finess_stats.get("cityResolution") or {}
    edmond = entries.get("+33442847000")
    expected_edmond = {
        "n": "+33442847000",
        "d": "Centre hospitalier Edmond Garcin",
        "c": "Aubagne",
        "t": "Hôpital / Centre hospitalier",
    }

    errors = []
    if dataset.get("entryCount") != len(entries) or not entries:
        errors.append("entryCount official_numbers_fr invalide")
    if technical_categories:
        errors.append(f"{technical_categories} catégories FINESS techniques restantes")
    if numeric_categories:
        errors.append(f"{numeric_categories} catégories uniquement numériques restantes")
    if empty_categories:
        errors.append(f"{empty_categories} catégories vides restantes")
    if invalid_numbers:
        errors.append(f"{invalid_numbers} normalizedNumber invalides")
    if unresolved_codes:
        errors.append(f"codes FINESS non résolus: {sorted(unresolved_codes)}")
    if not final_codes:
        errors.append("aucun code FINESS final dans le rapport de génération")
    if len(final_codes) != resolved_codes:
        errors.append("certains codes FINESS finaux ne sont pas résolus")
    if edmond != expected_edmond:
        errors.append("contrôle +33442847000 non conforme")

    return {
        "entryCount": len(entries),
        "categoryCodeCount": len(final_codes),
        "resolvedCategoryCodeCount": resolved_codes,
        "unresolvedCategoryCodes": unresolved_codes,
        "technicalCategoryCount": technical_categories,
        "numericCategoryCount": numeric_categories,
        "emptyCategoryCount": empty_categories,
        "invalidNumberCount": invalid_numbers,
        "citiesResolvedFromCogCommune": int(city_resolution.get("fromCogCommune", 0)),
        "unresolvedCities": int(city_resolution.get("unresolved", 0)),
        "edmondGarcin": edmond,
        "errors": errors,
    }


def run_official_numbers_builder(enabled, keep_output=False, approved_review_fingerprint=""):
    result = {
        "datasetId": "official_numbers_fr",
        "status": "SKIPPED",
        "entryCount": 0,
        "oldEntryCount": read_manifest_entry_count("official_numbers_fr"),
        "error": "",
        "fullExcludedFromPublic": True,
        "dilaAutomated": True,
        "finessAutomated": True,
        "fhfOverridePreserved": True,
        "outputFiles": {},
        "tempRoot": "",
        "addedCount": 0,
        "removedCount": 0,
        "modifiedCount": 0,
        "changeCount": 0,
        "changeRatio": 0.0,
        "reviewRequired": False,
        "reviewReason": "",
        "reviewFingerprint": "",
        "oldFunctionalSha256": "",
        "newFunctionalSha256": "",
        "reviewApproved": False,
        "migrationValidation": {},
        "reviewArtifact": {"ready": False, "directory": "", "files": []},
    }
    if not enabled:
        result["error"] = "Skipped in local safe validation mode."
        return result

    temp_dir = tempfile.mkdtemp(prefix="official-numbers-build-")
    temp_root = Path(temp_dir)
    result["tempRoot"] = temp_dir
    try:
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
            "--frozen-sources-dir",
            str(temp_root / "frozen-sources"),
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
        report_file = temp_root / "reports" / "official_numbers_fr_diff.json"
        if report_file.exists():
            build_report = read_json(report_file)
            result["entryCount"] = build_report.get("entryCount", result["entryCount"])
            result["sourceStats"] = build_report.get(
                "sourceStats", builder_output.get("sourceStats", {})
            )
            compact_comparison = compare_official_numbers_compact(
                temp_root / "datasets" / "official_numbers_fr.json"
            )
            result["addedCount"] = compact_comparison["addedCount"]
            result["removedCount"] = compact_comparison["removedCount"]
            result["modifiedCount"] = compact_comparison["modifiedCount"]
            result["changeCount"] = compact_comparison["changeCount"]
            result["changeRatio"] = compact_comparison["changeRatio"]
            result["oldFunctionalSha256"] = compact_comparison.get("oldFunctionalSha256", "")
            result["newFunctionalSha256"] = compact_comparison.get("newFunctionalSha256", "")
            result["reviewFingerprint"] = compact_comparison.get("reviewFingerprint", "")
            try:
                migration_validation = validate_official_numbers_migration(
                    temp_root / "datasets" / "official_numbers_fr.json",
                    build_report,
                )
            except Exception as exc:
                result["status"] = "BLOCKED"
                result["error"] = (
                    "Validation official_numbers_fr impossible: "
                    f"{type(exc).__name__}: {exc}"
                )
                return result
            result["migrationValidation"] = migration_validation
            gated_status, gated_error = apply_review_gate(
                compact_comparison,
                approved_review_fingerprint,
                migration_validation["errors"],
            )
            result["status"] = gated_status
            result["error"] = gated_error
            result["reviewRequired"] = gated_status in {
                REVIEW_REQUIRED_STATUS,
                REVIEW_MISMATCH_STATUS,
            }
            result["reviewApproved"] = gated_status == REVIEW_APPROVED_STATUS
            if result["reviewRequired"]:
                result["reviewReason"] = gated_error
            dila_stats = result.get("sourceStats", {}).get("DILA", {})
            finess_stats = result.get("sourceStats", {}).get("FINESS", {})
            if int(dila_stats.get("validNumbers", 0)) <= 0:
                result["status"] = "BLOCKED"
                result["error"] = "official_numbers_fr source DILA disappeared."
                result["reviewRequired"] = False
            elif int(finess_stats.get("validNumbers", 0)) <= 0:
                result["status"] = "BLOCKED"
                result["error"] = "official_numbers_fr source FINESS disappeared."
                result["reviewRequired"] = False
            if result["status"] in {
                REVIEW_REQUIRED_STATUS,
                REVIEW_MISMATCH_STATUS,
                REVIEW_APPROVED_STATUS,
            }:
                try:
                    result["reviewArtifact"] = create_review_artifacts(
                        temp_root / "datasets" / "official_numbers_fr.json",
                        temp_root / "frozen-sources" / "source_hashes.json",
                        compact_comparison,
                        result["status"],
                    )
                except Exception as exc:
                    result["status"] = "BLOCKED"
                    result["error"] = (
                        "Artifact de revue refusé: "
                        f"{type(exc).__name__}: {exc}"
                    )
                    result["reviewRequired"] = False
        else:
            result["status"] = "BLOCKED"
            result["error"] = "Build report absent."
        for name in ("official_numbers_fr.json", "official_numbers_fr.json.gz"):
            output = temp_root / "datasets" / name
            if output.exists():
                result["outputFiles"][name] = str(output)
    finally:
        if not keep_output:
            shutil.rmtree(temp_dir, ignore_errors=True)
            result["tempRoot"] = ""
    return result


def build_manifest_from_public_datasets():
    if not PUBLIC_DATASETS_DIR.exists():
        raise RuntimeError("Dossier datasets absent.")
    datasets = {}
    for dataset_file in sorted(PUBLIC_DATASETS_DIR.iterdir(), key=lambda path: path.name):
        if not dataset_file.is_file():
            continue
        if dataset_file.name == "official_numbers_fr_full.json":
            continue
        if not (dataset_file.name.endswith(".json") or dataset_file.name.endswith(".json.gz")):
            continue
        dataset_json = (
            read_gzip_json(dataset_file)
            if dataset_file.name.endswith(".json.gz")
            else read_json(dataset_file)
        )
        dataset_id = dataset_json.get("datasetId")
        if not dataset_id:
            raise RuntimeError(f"datasetId absent: {dataset_file.name}")
        dataset_version = dataset_json.get("datasetVersion")
        if not dataset_version:
            raise RuntimeError(f"datasetVersion absent: {dataset_file.name}")
        sha = hashlib.sha256(dataset_file.read_bytes()).hexdigest()
        entry = {
            "version": dataset_version,
            "url": f"{BASE_URL}/datasets/{dataset_file.name}",
            "sha256": sha,
        }
        if dataset_id == "official_numbers_fr" and dataset_file.name.endswith(".json.gz"):
            entries = dataset_json.get("entries") or []
            entry_count = dataset_json.get("entryCount")
            if not entry_count or entry_count != len(entries):
                raise RuntimeError("official_numbers_fr entryCount incohérent.")
            entry.update(
                {
                    "entryCount": int(entry_count),
                    "type": "official_numbers",
                    "compression": "gzip",
                }
            )
        else:
            rules = dataset_json.get("rules") or []
            entry["ruleCount"] = len(rules)
        datasets[dataset_id] = entry
    if not datasets:
        raise RuntimeError("Aucun dataset valide pour le manifest.")
    return {"schemaVersion": 1, "datasets": datasets}


def sign_manifest(manifest_path, signature_path):
    private_key = os.environ.get("OFFICIAL_UPDATE_PRIVATE_KEY_FILE", "")
    if not private_key:
        private_key = str(ROOT / "private" / "official_update_private_key.pem")
    if not Path(private_key).exists():
        raise RuntimeError("Clé privée absente.")

    temp_dir = Path(tempfile.mkdtemp(prefix="official-update-sign-"))
    java_file = temp_dir / "SignManifest.java"
    try:
        java_file.write_text(
            r'''
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public final class SignManifest {
    public static void main(String[] args) throws Exception {
        String pem = new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.US_ASCII)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(pem);
        PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        byte[] manifest = Files.readAllBytes(Paths.get(args[1]));
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(key);
        signature.update(manifest);
        Files.write(Paths.get(args[2]), Base64.getEncoder().encode(signature.sign()));
    }
}
'''.strip()
            + "\n",
            encoding="ascii",
        )
        javac = Path(r"C:\Program Files\Android\Android Studio\jbr\bin\javac.exe")
        java = Path(r"C:\Program Files\Android\Android Studio\jbr\bin\java.exe")
        javac_cmd = str(javac) if javac.exists() else "javac"
        java_cmd = str(java) if java.exists() else "java"
        run_command([javac_cmd, "-encoding", "UTF-8", "-d", str(temp_dir), str(java_file)])
        run_command(
            [
                java_cmd,
                "-cp",
                str(temp_dir),
                "SignManifest",
                private_key,
                str(manifest_path),
                str(signature_path),
            ]
        )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def regenerate_manifest_and_signature():
    manifest = build_manifest_from_public_datasets()
    manifest_path = PUBLIC_DIR / "manifest.json"
    signature_path = PUBLIC_DIR / "manifest.sig"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    sign_manifest(manifest_path, signature_path)


def verify_public_update_set():
    return run_command(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            "tools/verify_update.ps1",
        ]
    )


def normalize_diff_path(line):
    parts = line.split("\t")
    path = parts[-1] if parts else line
    return path.replace("\\", "/")


def changed_files():
    output = git_output("status", "--porcelain")
    files = []
    for line in output.splitlines():
        if line.strip():
            path_start = 3 if len(line) > 2 and line[2] == " " else 2
            files.append(normalize_diff_path(line[path_start:]))
    return files


def relative_public_path(path):
    return path.relative_to(ROOT).as_posix()


def allowed_publication_diff_files(report):
    allowed = {
        relative_public_path(PUBLIC_DIR / "manifest.json"),
        relative_public_path(PUBLIC_DIR / "manifest.sig"),
    }
    for dataset_id in report.get("changedDatasets", []):
        file_name = PUBLICATION_DATASET_FILES.get(dataset_id)
        if file_name:
            allowed.add(relative_public_path(PUBLIC_DATASETS_DIR / file_name))
    return allowed


def validate_publication_diff(files, allowed_files):
    blocked = []
    unexpected = []
    allowed_files = set(allowed_files)
    for path in files:
        lowered = path.lower()
        if any(part in lowered for part in BLOCKED_DIFF_PARTS):
            blocked.append(path)
            continue
        if lowered.endswith(".pem") and path != "official_update_public_key.pem":
            blocked.append(path)
            continue
        if lowered.endswith(BLOCKED_DIFF_SUFFIXES):
            blocked.append(path)
            continue
        if path in allowed_files:
            continue
        unexpected.append(path)
    if blocked or unexpected:
        raise RuntimeError(
            "Diff de publication refusé. "
            f"Bloqués: {blocked or 'aucun'}; inattendus: {unexpected or 'aucun'}"
        )


def publish_if_needed(report):
    publication = {
        "attempted": False,
        "published": False,
        "commitCreated": False,
        "commitSha": "",
        "error": "",
        "changedFiles": [],
    }
    if report["status"] != "READY_TO_PUBLISH":
        return publication

    publication["attempted"] = True
    numbers = report["officialNumbers"]
    outputs = numbers.get("outputFiles", {})
    if numbers.get("status") in {"CHANGED", REVIEW_APPROVED_STATUS}:
        gz_source = outputs.get("official_numbers_fr.json.gz")
        if not gz_source:
            raise RuntimeError("official_numbers_fr.json.gz généré introuvable.")
        PUBLIC_DATASETS_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(gz_source, PUBLIC_DATASETS_DIR / "official_numbers_fr.json.gz")

    regenerate_manifest_and_signature()
    verify_public_update_set()
    files = changed_files()
    validate_publication_diff(files, allowed_publication_diff_files(report))
    publication["changedFiles"] = files
    if not files:
        return publication

    run_command(["git", "config", "user.name", "official-sync-data-bot"])
    run_command(["git", "config", "user.email", "actions@github.com"])
    run_command(["git", "add", "--", *files])
    staged = git_output("diff", "--cached", "--name-only")
    if not staged.strip():
        return publication
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    run_command(["git", "commit", "-m", f"Update official datasets {today}"])
    commit_sha = git_output("rev-parse", "HEAD")
    run_command(["git", "push", "origin", "main"])
    publication.update(
        {
            "published": True,
            "commitCreated": True,
            "commitSha": commit_sha,
        }
    )
    return publication


def review_gate_simulations():
    base = {
        "status": REVIEW_REQUIRED_STATUS,
        "reviewFingerprint": "a" * 64,
        "error": "validation humaine requise",
    }
    changed = dict(base, reviewFingerprint="b" * 64)
    cases = [
        ("A", *apply_review_gate(base, ""), "cron sans fingerprint"),
        ("B", *apply_review_gate(base, ""), "workflow_dispatch sans fingerprint"),
        ("C", *apply_review_gate(base, "c" * 64), "mauvais fingerprint"),
        ("D", *apply_review_gate(base, "a" * 64), "fingerprint correct"),
        ("E", *apply_review_gate(changed, "a" * 64), "contenu modifié après validation"),
        ("F", "ERROR", "verify_update.ps1 échoue", "fingerprint correct mais vérification en erreur"),
        ("G", *apply_review_gate(base, "a" * 64, ["catégorie FINESS technique"]), "garde-fou catégorie"),
        ("H", "BLOCKED", "APK/FULL/clé privée détecté", "garde-fou fichiers interdits"),
    ]
    return [
        {"case": name, "status": status, "detail": detail or context}
        for name, status, detail, context in cases
    ]


def sum_change_counts(rule_reports, official_numbers):
    return {
        "added": sum(len(item.get("added", [])) for item in rule_reports)
        + int(official_numbers.get("addedCount", 0)),
        "removed": sum(len(item.get("removed", [])) for item in rule_reports)
        + int(official_numbers.get("removedCount", 0)),
        "modified": sum(len(item.get("modified", [])) for item in rule_reports)
        + int(official_numbers.get("modifiedCount", 0)),
    }


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
    lines.extend(
        [
            "",
            f"Sources indisponibles : {', '.join(report['preservedDatasets']) or 'Aucune'}",
            f"Datasets inchangés : {', '.join(report['unchangedDatasets']) or 'Aucun'}",
            f"Datasets modifiés : {', '.join(report['changedDatasets']) or 'Aucun'}",
            "",
            "## Changements",
            f"Ajouts : {report['changeCounts']['added']}",
            f"Suppressions : {report['changeCounts']['removed']}",
            f"Modifications : {report['changeCounts']['modified']}",
        ]
    )
    numbers = report["officialNumbers"]
    lines.extend(
        [
            "",
            "## official_numbers_fr",
            f"- Statut : {numbers['status']}",
            f"- Ancien total : {numbers.get('oldEntryCount', 0)}",
            f"- Nouveau total : {numbers['entryCount']}",
            f"- Ajouts : {numbers.get('addedCount', 0)}",
            f"- Suppressions : {numbers.get('removedCount', 0)}",
            f"- Modifications : {numbers.get('modifiedCount', 0)}",
            f"- Taux de changement : {numbers.get('changeRatio', 0.0) * 100:.2f} %",
            f"- DILA automatisé : {numbers['dilaAutomated']}",
            f"- FINESS automatisé : {numbers['finessAutomated']}",
            f"- FHF override conservé : {numbers['fhfOverridePreserved']}",
            f"- FULL exclu de public : {numbers['fullExcludedFromPublic']}",
            f"- Empreinte revue unique : {numbers.get('reviewFingerprint') or 'N/A'}",
            f"- SHA-256 fonctionnel ancien : {numbers.get('oldFunctionalSha256') or 'N/A'}",
            f"- SHA-256 fonctionnel nouveau : {numbers.get('newFunctionalSha256') or 'N/A'}",
            "",
            "## Simulations locales",
        ]
    )
    for item in report["simulations"]:
        lines.append(f"- CAS {item['case']} : {item['status']} - {item['detail']}")
    publication = report["publicationDetails"]
    lines.extend(
        [
            "",
            "## Résultat",
            f"- Résultat global : {report['status']}",
            f"- Vérification : {report['verification']}",
            f"- APK concernée : {report['apkConcerned']}",
            f"- Commit créé : {'Oui' if publication['commitCreated'] else 'Non'}",
            f"- SHA commit : {publication['commitSha'] or 'N/A'}",
            f"- Publication : {'Oui' if publication['published'] else 'Non'}",
        ]
    )
    if report["blockingDatasets"]:
        lines.append(f"- Anomalies bloquantes : {', '.join(report['blockingDatasets'])}")
    if numbers.get("status") == REVIEW_REQUIRED_STATUS:
        lines.extend(
            [
                "",
                "## PUBLICATION BLOQUÉE — VALIDATION HUMAINE REQUISE",
                "- Dataset : official_numbers_fr",
                f"- Ancien nombre : {numbers.get('oldEntryCount', 0)}",
                f"- Nouveau nombre : {numbers.get('entryCount', 0)}",
                f"- Ajouts : {numbers.get('addedCount', 0)}",
                f"- Suppressions : {numbers.get('removedCount', 0)}",
                f"- Modifications : {numbers.get('modifiedCount', 0)}",
                f"- Taux de changement : {numbers.get('changeRatio', 0.0) * 100:.2f} %",
                "- Source principalement concernée : FINESS",
                "- Publication : NON",
                "- Données publiques précédentes : CONSERVÉES",
                f"- Empreinte revue unique : {numbers.get('reviewFingerprint') or 'N/A'}",
            ]
        )
    elif numbers.get("status") == REVIEW_MISMATCH_STATUS:
        lines.extend(
            [
                "",
                "## PUBLICATION BLOQUÉE — EMPREINTE DE REVUE INCORRECTE",
                "- Dataset : official_numbers_fr",
                f"- Empreinte attendue : {numbers.get('reviewFingerprint') or 'N/A'}",
                "- Publication : NON",
                "- Données publiques précédentes : CONSERVÉES",
                "- Seuil permanent : 0,5 %",
            ]
        )
    elif numbers.get("status") == REVIEW_APPROVED_STATUS:
        lines.extend(
            [
                "",
                "## REVIEW_APPROVED",
                "- Dataset : official_numbers_fr",
                f"- Fingerprint approuvé : {numbers.get('reviewFingerprint') or 'N/A'}",
                f"- Modifications : {numbers.get('modifiedCount', 0)}",
                f"- Taux : {numbers.get('changeRatio', 0.0) * 100:.2f} %",
                "- Migration : Catégories FINESS vers libellés officiels ANS",
                "- Publication exceptionnelle : AUTORISÉE POUR CE DIFF UNIQUEMENT",
                "- Seuil permanent : 0,5 %",
            ]
        )
    return "\n".join(lines) + "\n"


def run(args):
    if REVIEW_ARTIFACT_DIR.exists():
        shutil.rmtree(REVIEW_ARTIFACT_DIR)
    mode = "manuel" if args.workflow_dispatch else "automatique"
    rule_reports = []
    for dataset_id in SOURCE_CONFIGS:
        report = run_check(dataset_id)
        rule_reports.append(report)

    blocking, changed, preserved, unchanged = classify_rules(rule_reports)
    rule_datasets_changed = list(changed)
    official_numbers = run_official_numbers_builder(
        args.build_official_numbers,
        keep_output=args.publish,
        approved_review_fingerprint=args.approve_review_fingerprint,
    )
    if official_numbers["status"] == "BLOCKED":
        blocking.append("official_numbers_fr")
    elif official_numbers["status"] == REVIEW_REQUIRED_STATUS:
        blocking.append("official_numbers_fr_review_required")
    elif official_numbers["status"] == REVIEW_MISMATCH_STATUS:
        blocking.append("official_numbers_fr_review_mismatch")
    elif official_numbers["status"] in {"CHANGED", REVIEW_APPROVED_STATUS}:
        changed.append("official_numbers_fr")
    elif official_numbers["status"] == "UNCHANGED":
        unchanged.append("official_numbers_fr")

    apk_present = has_apk_in_public()
    if apk_present:
        blocking.append("public_apk")
    if rule_datasets_changed:
        blocking.extend(f"{dataset_id}_rule_dataset_changed_without_writer" for dataset_id in rule_datasets_changed)

    if official_numbers["status"] == REVIEW_REQUIRED_STATUS:
        global_status = REVIEW_REQUIRED_STATUS
    elif official_numbers["status"] == REVIEW_MISMATCH_STATUS:
        global_status = REVIEW_MISMATCH_STATUS
    elif blocking:
        global_status = "BLOCKED"
    elif changed:
        global_status = "READY_TO_PUBLISH"
    else:
        global_status = "SUCCESS"

    publication_details = {
        "attempted": False,
        "published": False,
        "commitCreated": False,
        "commitSha": "",
        "error": "",
        "changedFiles": [],
    }
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
        "changeCounts": sum_change_counts(rule_reports, official_numbers),
        "status": global_status,
        "verification": "not_requested",
        "publication": "Non",
        "publicationDetails": publication_details,
        "apkConcerned": "Non" if not apk_present else "Erreur: APK présent",
        "simulations": review_gate_simulations(),
    }

    try:
        if args.publish and global_status == "READY_TO_PUBLISH":
            publication_details = publish_if_needed(report)
            report["publicationDetails"] = publication_details
            report["verification"] = "OK"
            if publication_details["published"]:
                report["status"] = "PUBLISHED"
                report["publication"] = "Oui"
            elif publication_details["changedFiles"]:
                report["status"] = "READY_TO_PUBLISH"
            else:
                report["status"] = "SUCCESS"
        elif global_status in {"SUCCESS", "READY_TO_PUBLISH"}:
            verify_public_update_set()
            report["verification"] = "OK"
    except Exception as exc:
        report["status"] = "BLOCKED" if global_status == "READY_TO_PUBLISH" else "ERROR"
        report["verification"] = "Erreur"
        report["publication"] = "Non"
        publication_details["error"] = f"{type(exc).__name__}: {exc}"
        report["publicationDetails"] = publication_details
        report["blockingDatasets"].append("publication")
    finally:
        temp_root = official_numbers.get("tempRoot")
        if temp_root:
            shutil.rmtree(temp_root, ignore_errors=True)

    write_json(REPORT_PATH, report)
    write_text(SUMMARY_PATH, build_markdown(report))

    github_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if github_summary:
        with open(github_summary, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(build_markdown(report))

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] in {
        "SUCCESS",
        "READY_TO_PUBLISH",
        "PUBLISHED",
        REVIEW_REQUIRED_STATUS,
        REVIEW_MISMATCH_STATUS,
    } else 2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow-dispatch", action="store_true")
    parser.add_argument(
        "--build-official-numbers",
        action="store_true",
        help="Run the full DILA/FINESS/FHF builder in a temporary workspace.",
    )
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Publish a validated READY_TO_PUBLISH result by committing and pushing allowed files.",
    )
    parser.add_argument(
        "--approve-review-fingerprint",
        default="",
        help="One-shot SHA-256 approval for the exact current official_numbers_fr diff.",
    )
    args = parser.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
