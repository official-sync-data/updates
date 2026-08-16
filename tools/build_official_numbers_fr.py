#!/usr/bin/env python3
import argparse
import csv
import gzip
import hashlib
import io
import json
import os
import re
import urllib.parse
import urllib.request
from collections import Counter, OrderedDict
from datetime import date

DILA_API = "https://api-lannuaire.service-public.gouv.fr/api/explore/v2.1/catalog/datasets/api-lannuaire-administration/records"
DILA_EXPORT = "https://api-lannuaire.service-public.gouv.fr/api/explore/v2.1/catalog/datasets/api-lannuaire-administration/exports/json"
FINESS_DATASET_API = "https://www.data.gouv.fr/api/1/datasets/finess-structures-1/"
FINESS_CATEGORY_CODE_SYSTEM_URL = "https://smt.esante.gouv.fr/fhir/CodeSystem/tre-r397-categorie-entite-geographique-exercice"
FINESS_CATEGORY_CODE_SYSTEM_CANONICAL = "https://smt.esante.gouv.fr/fhir/CodeSystem/tre-r397-categorie-entite-geographique-exercice"
FINESS_COMMUNE_TABS_URL = "https://mos.esante.gouv.fr/NOS/TRE_R13-CommuneOM/TRE_R13-CommuneOM.tabs"
TODAY = date.today().isoformat()


def normalize_fr_number(value):
    if value is None:
        return None
    text = str(value).strip().replace("(0)", "")
    if not text:
        return None
    if text.startswith("+"):
        normalized = "+" + re.sub(r"\D", "", text[1:])
        return normalized if re.fullmatch(r"\+33\d{9}", normalized) else None
    digits = re.sub(r"\D", "", text)
    if re.fullmatch(r"0\d{9}", digits):
        return "+33" + digits[1:]
    if re.fullmatch(r"33\d{9}", digits):
        return "+" + digits
    if re.fullmatch(r"0033\d{9}", digits):
        return "+33" + digits[4:]
    return None


def department_from_postal_code(postal_code):
    if not postal_code:
        return ""
    text = str(postal_code).strip()
    if text.startswith(("97", "98")) and len(text) >= 3:
        return text[:3]
    return text[:2] if len(text) >= 2 else ""


def read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def write_compact_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    with open(path, "wb") as handle:
        handle.write(payload)
    return payload


def write_gzip(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with gzip.open(path, "wb") as handle:
        handle.write(payload)


def parse_embedded_json(value):
    if not value:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []
    return []


def url_bytes(url, accept="application/octet-stream"):
    request = urllib.request.Request(
        url,
        headers={
            "Accept": accept,
            "User-Agent": "BloqueurAppelsOfficialNumbersBuilder/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def url_json(url, accept="application/json"):
    return json.loads(url_bytes(url, accept).decode("utf-8-sig"))


def download_file(url, target_path):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "BloqueurAppelsOfficialNumbersBuilder/1.0"},
    )
    with urllib.request.urlopen(request, timeout=180) as response:
        with open(target_path, "wb") as handle:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                handle.write(chunk)


def stable_id(normalized_number):
    digest = hashlib.sha256(normalized_number.encode("ascii")).hexdigest()[:16]
    return "official_numbers_fr_" + digest


def clean_text(value):
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def title_city(value):
    value = clean_text(value)
    return value.title() if value else ""


def iter_fhir_concepts(concepts):
    for concept in concepts or []:
        yield concept
        yield from iter_fhir_concepts(concept.get("concept"))


def fhir_concept_status(concept):
    for item in concept.get("property") or []:
        if item.get("code") == "status":
            return clean_text(item.get("valueCode")) or "active"
    return "active"


def valid_business_label(value):
    label = clean_text(value)
    if not label or label.isdigit() or len(label) > 300:
        return False
    lowered = label.lower()
    if lowered.startswith(("http://", "https://", "{", "[")):
        return False
    if re.search(r"</?[a-z][^>]*>", label, flags=re.IGNORECASE):
        return False
    return True


def load_finess_category_nomenclature():
    payload = url_json(FINESS_CATEGORY_CODE_SYSTEM_URL, "application/fhir+json")
    if payload.get("resourceType") != "CodeSystem":
        raise RuntimeError("Nomenclature FINESS invalide: resourceType")
    if payload.get("url") != FINESS_CATEGORY_CODE_SYSTEM_CANONICAL:
        raise RuntimeError("Nomenclature FINESS invalide: URL canonique")
    labels = {}
    statuses = {}
    invalid = []
    for concept in iter_fhir_concepts(payload.get("concept")):
        code = clean_text(concept.get("code"))
        label = clean_text(concept.get("display"))
        if not code:
            continue
        if not valid_business_label(label):
            invalid.append(code)
            continue
        labels[code] = label
        statuses[code] = fhir_concept_status(concept)
    if not labels:
        raise RuntimeError("Nomenclature FINESS vide")
    return labels, statuses, {
        "source": FINESS_CATEGORY_CODE_SYSTEM_URL,
        "canonical": payload.get("url"),
        "version": clean_text(payload.get("version")),
        "date": clean_text(payload.get("date")),
        "conceptCount": len(labels),
        "invalidConceptCodes": sorted(invalid),
    }


def load_finess_commune_nomenclature():
    text = url_bytes(FINESS_COMMUNE_TABS_URL, "text/plain").decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(text), delimiter=";"))
    if len(rows) < 4 or len(rows[1]) < 8:
        raise RuntimeError("Nomenclature des communes FINESS invalide")
    labels = {}
    active = set()
    for row in rows[3:]:
        if len(row) < 8:
            continue
        code = clean_text(row[1])
        label = clean_text(row[4])
        date_end = clean_text(row[6])
        if not code or not valid_business_label(label):
            continue
        if code not in labels or not date_end:
            labels[code] = label
        if not date_end:
            active.add(code)
    if not labels:
        raise RuntimeError("Nomenclature des communes FINESS vide")
    return labels, {
        "source": FINESS_COMMUNE_TABS_URL,
        "version": clean_text(rows[1][7]),
        "date": clean_text(rows[1][7]),
        "conceptCount": len(labels),
        "activeConceptCount": len(active),
    }


def finess_city(address, commune_labels, city_stats):
    city = title_city(address.get("ligneAcheminement"))
    if city:
        city_stats["fromLigneAcheminement"] += 1
        return city
    commune_code = clean_text(address.get("cogCommune"))
    if commune_code and commune_code in commune_labels:
        city_stats["fromCogCommune"] += 1
        return clean_text(commune_labels[commune_code])
    city_stats["unresolved"] += 1
    if commune_code:
        city_stats["unresolvedCodes"][commune_code] += 1
    return ""


def source_rank(source):
    authority = source.get("authority", "")
    entity_type = source.get("entityType", "")
    if authority == "FHF" and source.get("validated") is True:
        return 0
    if authority == "FINESS" and entity_type == "EGE":
        return 1
    if authority == "FINESS" and entity_type == "PMEJ":
        return 2
    if authority == "DILA":
        return 3
    if authority == "FHF":
        return 4
    return 9


def candidate_rank(candidate):
    return min(source_rank(source) for source in candidate["sources"])


def add_candidate(groups, rejected, raw):
    normalized = normalize_fr_number(raw.get("phone"))
    if normalized is None:
        rejected.append({"reason": "invalid_phone", "source": raw.get("authority", ""), "value": raw.get("phone", "")})
        return
    if not clean_text(raw.get("displayName")):
        rejected.append({"reason": "missing_name", "source": raw.get("authority", ""), "value": normalized})
        return
    if raw.get("status") != "ACTIVE":
        rejected.append({"reason": "inactive", "source": raw.get("authority", ""), "value": normalized})
        return
    postal_code = clean_text(raw.get("postalCode"))
    source = OrderedDict(
        authority=raw.get("authority", ""),
        sourceId=clean_text(raw.get("sourceId")),
        entityType=clean_text(raw.get("entityType")),
        url=clean_text(raw.get("url")),
        lastSeenDate=raw.get("lastSeenDate", TODAY),
    )
    if raw.get("validated") is True:
        source["validated"] = True
    if raw.get("finessJuridique"):
        source["finessJuridique"] = clean_text(raw.get("finessJuridique"))
    if raw.get("categoryCode"):
        source["categoryCode"] = clean_text(raw.get("categoryCode"))
        source["categoryCodeSystem"] = clean_text(raw.get("categoryCodeSystem"))
    candidate = {
        "normalizedNumber": normalized,
        "displayName": clean_text(raw.get("displayName")),
        "city": title_city(raw.get("city")),
        "postalCode": postal_code,
        "department": clean_text(raw.get("department")) or department_from_postal_code(postal_code),
        "category": clean_text(raw.get("category")),
        "categoryCode": clean_text(raw.get("categoryCode")),
        "categoryCodeSystem": clean_text(raw.get("categoryCodeSystem")),
        "status": "ACTIVE",
        "sources": [source],
    }
    if normalized not in groups:
        groups[normalized] = candidate
        return
    current = groups[normalized]
    current_rank = candidate_rank(current)
    new_rank = candidate_rank(candidate)
    existing = {(s.get("authority"), s.get("sourceId"), s.get("entityType")) for s in current["sources"]}
    key = (source.get("authority"), source.get("sourceId"), source.get("entityType"))
    if key not in existing:
        current["sources"].append(source)
    if new_rank < current_rank:
        merged_sources = current["sources"]
        groups[normalized] = candidate
        groups[normalized]["sources"] = merged_sources


def new_stats():
    return {
        "examined": 0,
        "withPhone": 0,
        "validNumbers": 0,
        "rejectedNumbers": 0,
        "active": 0,
    }


def fetch_dila(groups, rejected, limit):
    stats = new_stats()
    if limit:
        query = urllib.parse.urlencode({"limit": limit, "where": "telephone is not null"})
        payload = url_json(DILA_API + "?" + query)
        records = payload.get("results", [])
    else:
        query = urllib.parse.urlencode({"where": "telephone is not null", "timezone": "Europe/Paris"})
        records = url_json(DILA_EXPORT + "?" + query)
    for record in records:
        stats["examined"] += 1
        phones = parse_embedded_json(record.get("telephone"))
        if phones:
            stats["withPhone"] += 1
        addresses = parse_embedded_json(record.get("adresse"))
        pivots = parse_embedded_json(record.get("pivot"))
        address = addresses[0] if addresses else {}
        category = ""
        if pivots and isinstance(pivots[0], dict):
            category = clean_text(pivots[0].get("type_service_local"))
        category = category or clean_text(record.get("type_organisme")) or clean_text(record.get("categorie"))
        for phone in phones[:1]:
            value = phone.get("valeur") if isinstance(phone, dict) else phone
            before = len(rejected)
            add_candidate(groups, rejected, {
                "authority": "DILA",
                "sourceId": record.get("id"),
                "entityType": "ADMINISTRATION",
                "url": record.get("url_service_public"),
                "phone": value,
                "displayName": record.get("nom"),
                "city": address.get("nom_commune"),
                "postalCode": address.get("code_postal"),
                "department": department_from_postal_code(address.get("code_postal")),
                "category": category,
                "status": "ACTIVE" if str(record.get("statut_de_diffusion")).lower() in ("true", "1") else "INACTIVE",
                "lastSeenDate": TODAY,
            })
            if len(rejected) == before:
                stats["validNumbers"] += 1
            else:
                stats["rejectedNumbers"] += 1
    return stats


def latest_finess_url():
    metadata = url_json(FINESS_DATASET_API)
    resources = metadata.get("resources", [])
    daily = [r for r in resources if r.get("format") == "json.gz" and "journalier" in r.get("title", "")]
    selected = daily[0] if daily else next((r for r in resources if r.get("format") == "json.gz"), None)
    if not selected:
        raise RuntimeError("FINESS json.gz introuvable")
    return selected.get("url") or selected.get("latest")


def fetch_finess(groups, rejected, limit, cache_dir, required_numbers, category_labels, category_statuses, commune_labels):
    url = latest_finess_url()
    os.makedirs(cache_dir, exist_ok=True)
    file_name = os.path.basename(urllib.parse.urlparse(url).path) or "finess-structures.json.gz"
    archive = os.path.join(cache_dir, file_name)
    if not os.path.exists(archive):
        download_file(url, archive)
    with gzip.open(archive, "rt", encoding="utf-8") as handle:
        payload = json.load(handle)
    added = 0
    stats = new_stats()
    category_codes = Counter()
    unresolved_category_codes = Counter()
    city_stats = {
        "fromLigneAcheminement": 0,
        "fromCogCommune": 0,
        "unresolved": 0,
        "unresolvedCodes": Counter(),
    }
    found_required = set()
    for pmej in payload.get("pmej", []):
        stats["examined"] += 1
        pmej_info = pmej.get("informationsGeneralesPMEJ", {})
        if pmej.get("etatObjet") == "A":
            stats["active"] += 1
            for contact in pmej.get("contact") or []:
                phone = ((contact or {}).get("telecom") or {}).get("telephone")
                normalized = normalize_fr_number(phone)
                if phone:
                    stats["withPhone"] += 1
                if normalized:
                    should_add = (not limit) or added < limit or normalized in required_numbers
                    if not should_add:
                        continue
                    address = (pmej.get("adresse") or [{}])[0]
                    before = len(rejected)
                    add_candidate(groups, rejected, {
                        "authority": "FINESS",
                        "sourceId": pmej_info.get("numFinessPm"),
                        "entityType": "PMEJ",
                        "phone": phone,
                        "displayName": pmej_info.get("denominationPm") or pmej_info.get("denominationLonguePmSmsse"),
                        "city": finess_city(address, commune_labels, city_stats),
                        "postalCode": address.get("codePostal"),
                        "department": department_from_postal_code(address.get("codePostal")),
                        "category": "FINESS PMEJ",
                        "status": "ACTIVE",
                        "lastSeenDate": TODAY,
                    })
                    if normalized in required_numbers:
                        found_required.add(normalized)
                    if len(rejected) == before:
                        stats["validNumbers"] += 1
                    else:
                        stats["rejectedNumbers"] += 1
                    if not limit or added < limit:
                        added += 1
                    break
                elif phone:
                    stats["rejectedNumbers"] += 1
        for ege in pmej.get("ege") or []:
            stats["examined"] += 1
            if ege.get("etatObjet") != "A":
                continue
            stats["active"] += 1
            ege_info = ege.get("informationsGeneralesEGE", {})
            for contact in ege.get("contact") or []:
                phone = ((contact or {}).get("telecom") or {}).get("telephone")
                normalized = normalize_fr_number(phone)
                if phone:
                    stats["withPhone"] += 1
                if normalized:
                    should_add = (not limit) or added < limit or normalized in required_numbers
                    if not should_add:
                        continue
                    address = (ege.get("adresse") or [{}])[0]
                    category_code = clean_text(ege.get("categorieentiteGeographiqueExercice"))
                    category_label = category_labels.get(category_code, "")
                    category_codes[category_code] += 1
                    if not category_label:
                        unresolved_category_codes[category_code or "<empty>"] += 1
                    before = len(rejected)
                    add_candidate(groups, rejected, {
                        "authority": "FINESS",
                        "sourceId": ege_info.get("numFinessEge"),
                        "entityType": "EGE",
                        "phone": phone,
                        "displayName": ege_info.get("nomEgeLong") or ege_info.get("nomEgeCourt"),
                        "city": finess_city(address, commune_labels, city_stats),
                        "postalCode": address.get("codePostal"),
                        "department": department_from_postal_code(address.get("codePostal")),
                        "category": category_label,
                        "categoryCode": category_code,
                        "categoryCodeSystem": FINESS_CATEGORY_CODE_SYSTEM_CANONICAL,
                        "status": "ACTIVE",
                        "lastSeenDate": TODAY,
                    })
                    if normalized in required_numbers:
                        found_required.add(normalized)
                    if len(rejected) == before:
                        stats["validNumbers"] += 1
                    else:
                        stats["rejectedNumbers"] += 1
                    if not limit or added < limit:
                        added += 1
                    break
                elif phone:
                    stats["rejectedNumbers"] += 1
        if limit and added >= limit and found_required == required_numbers:
            break
    stats["categoryCodes"] = [
        {
            "code": code,
            "label": category_labels.get(code, ""),
            "occurrences": count,
            "resolved": bool(category_labels.get(code)),
            "status": category_statuses.get(code, "unknown"),
        }
        for code, count in sorted(category_codes.items())
    ]
    stats["categoryCodeCount"] = len(category_codes)
    stats["unresolvedCategoryCodes"] = dict(sorted(unresolved_category_codes.items()))
    stats["cityResolution"] = {
        "fromLigneAcheminement": city_stats["fromLigneAcheminement"],
        "fromCogCommune": city_stats["fromCogCommune"],
        "unresolved": city_stats["unresolved"],
        "unresolvedCodes": dict(sorted(city_stats["unresolvedCodes"].items())),
    }
    return stats


def apply_fhf_overrides(groups, rejected, overrides_path):
    payload = read_json(overrides_path)
    count = 0
    for item in payload.get("entries", []):
        sources = item.get("sources") or []
        if not sources:
            rejected.append({"reason": "fhf_missing_source", "source": "FHF", "value": item.get("normalizedNumber", "")})
            continue
        source = sources[0]
        add_candidate(groups, rejected, {
            "authority": "FHF",
            "sourceId": source.get("sourceId"),
            "entityType": source.get("entityType") or "HOSPITAL",
            "url": source.get("url"),
            "phone": item.get("normalizedNumber"),
            "displayName": item.get("displayName"),
            "city": item.get("city"),
            "postalCode": item.get("postalCode"),
            "department": item.get("department"),
            "category": item.get("category"),
            "status": item.get("status"),
            "validated": item.get("validated") is True,
            "finessJuridique": source.get("finessJuridique"),
            "lastSeenDate": source.get("lastSeenDate") or TODAY,
        })
        if item.get("validated") is True:
            count += 1
    return count


def build_entries(groups):
    entries = []
    for number in sorted(groups.keys()):
        entry = groups[number]
        entry["id"] = stable_id(number)
        ordered = OrderedDict()
        for key in ("id", "normalizedNumber", "displayName", "city", "postalCode", "department", "category", "categoryCode", "categoryCodeSystem", "status", "sources"):
            ordered[key] = entry.get(key, "" if key != "sources" else [])
        entries.append(ordered)
    return entries


def compare(previous, new):
    prev_entries = {e.get("normalizedNumber"): e for e in previous.get("entries", [])} if previous else {}
    new_entries = {e.get("normalizedNumber"): e for e in new.get("entries", [])}
    added = sorted(set(new_entries) - set(prev_entries))
    removed = sorted(set(prev_entries) - set(new_entries))
    modified = []
    unchanged = 0
    for number in sorted(set(prev_entries) & set(new_entries)):
        changes = {}
        for field in ("displayName", "city", "postalCode", "department", "category", "categoryCode", "categoryCodeSystem", "status", "sources"):
            if prev_entries[number].get(field) != new_entries[number].get(field):
                changes[field] = {"previous": prev_entries[number].get(field), "new": new_entries[number].get(field)}
        if changes:
            modified.append({"normalizedNumber": number, "changes": changes})
        else:
            unchanged += 1
    return {
        "schemaVersion": 1,
        "datasetId": "official_numbers_fr_diff",
        "generatedAt": TODAY,
        "previousEntryCount": len(prev_entries),
        "newEntryCount": len(new_entries),
        "added": added,
        "removed": removed,
        "modified": modified,
        "unchanged": unchanged,
    }


def build_android_dataset(full_dataset):
    compact_entries = []
    for entry in full_dataset.get("entries", []):
        item = OrderedDict()
        item["n"] = entry.get("normalizedNumber", "")
        item["d"] = entry.get("displayName", "")
        if entry.get("city"):
            item["c"] = entry.get("city")
        elif entry.get("department"):
            item["dep"] = entry.get("department")
        if entry.get("category"):
            item["t"] = entry.get("category")
        compact_entries.append(item)
    return OrderedDict(
        schemaVersion=1,
        datasetId="official_numbers_fr",
        datasetVersion=full_dataset.get("datasetVersion"),
        countryId="FR",
        entryCount=len(compact_entries),
        entries=compact_entries,
    )


def guard_android_dataset(dataset):
    errors = []
    for entry in dataset.get("entries", []):
        category = clean_text(entry.get("t"))
        if not category:
            errors.append("empty_android_category")
            break
        if category.startswith("FINESS categorie "):
            errors.append("technical_finess_category")
            break
        if category.isdigit():
            errors.append("numeric_android_category")
            break
        if not valid_business_label(category):
            errors.append("invalid_android_category_label")
            break
    return errors


def guard(dataset, previous, large_change_explanation=""):
    errors = []
    entries = dataset.get("entries", [])
    numbers = [e.get("normalizedNumber") for e in entries]
    ids = [e.get("id") for e in entries]
    if not entries:
        errors.append("dataset_empty")
    if len(numbers) != len(set(numbers)):
        errors.append("duplicate_normalizedNumber")
    if len(ids) != len(set(ids)):
        errors.append("duplicate_id")
    if dataset.get("entryCount") != len(entries):
        errors.append("entryCount_incoherent")
    if any(not e.get("sources") for e in entries):
        errors.append("empty_sources")
    if any(not re.fullmatch(r"\+33\d{9}", e.get("normalizedNumber", "")) for e in entries):
        errors.append("invalid_normalizedNumber")
    if previous and previous.get("entries"):
        previous_count = len(previous.get("entries", []))
        new_count = len(entries)
        if new_count < previous_count * 0.8 and not large_change_explanation:
            errors.append("drop_over_20_percent")
        if new_count > previous_count * 1.5 and not large_change_explanation:
            errors.append("increase_over_50_percent")
    return errors


def main():
    parser = argparse.ArgumentParser()
    root_default = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    parser.add_argument("--root", default=root_default)
    parser.add_argument("--dila-limit", type=int, default=0, help="0 parcourt toute la source DILA")
    parser.add_argument("--finess-limit", type=int, default=0, help="0 parcourt toute la source FINESS")
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    overrides_path = os.path.join(root, "sources", "official_numbers_fr_fhf_overrides.json")
    full_dataset_path = os.path.join(root, "datasets", "official_numbers_fr_full.json")
    android_dataset_path = os.path.join(root, "datasets", "official_numbers_fr.json")
    gzip_dataset_path = os.path.join(root, "datasets", "official_numbers_fr.json.gz")
    report_path = os.path.join(root, "reports", "official_numbers_fr_diff.json")
    cache_dir = os.path.join(root, ".cache")

    if os.path.exists(full_dataset_path):
        previous = read_json(full_dataset_path)
    elif os.path.exists(android_dataset_path):
        previous = read_json(android_dataset_path)
    else:
        previous = None
    overrides = read_json(overrides_path)
    required_numbers = {
        normalize_fr_number(item.get("normalizedNumber"))
        for item in overrides.get("entries", [])
        if item.get("validated") is True
    }
    required_numbers.discard(None)
    groups = OrderedDict()
    rejected = []
    category_labels, category_statuses, category_nomenclature = load_finess_category_nomenclature()
    commune_labels, commune_nomenclature = load_finess_commune_nomenclature()
    dila_stats = fetch_dila(groups, rejected, args.dila_limit)
    finess_stats = fetch_finess(
        groups,
        rejected,
        args.finess_limit,
        cache_dir,
        required_numbers,
        category_labels,
        category_statuses,
        commune_labels,
    )
    fhf_validated = apply_fhf_overrides(groups, rejected, overrides_path)
    entries = build_entries(groups)
    final_category_codes = Counter(
        entry.get("categoryCode")
        for entry in entries
        if entry.get("categoryCode")
    )
    finess_stats["finalCategoryCodes"] = [
        {
            "code": code,
            "label": category_labels.get(code, ""),
            "occurrences": count,
            "resolved": bool(category_labels.get(code)),
            "status": category_statuses.get(code, "unknown"),
        }
        for code, count in sorted(final_category_codes.items())
    ]
    finess_stats["finalCategoryCodeCount"] = len(final_category_codes)
    full_dataset = OrderedDict(
        schemaVersion=1,
        datasetId="official_numbers_fr",
        datasetVersion=TODAY,
        countryId="FR",
        language="fr",
        sourceAuthorities=["DILA", "FINESS", "FHF"],
        lastCheckedDate=TODAY,
        entryCount=len(entries),
        entries=entries,
    )
    android_dataset = build_android_dataset(full_dataset)
    large_change_explanation = ""
    if args.dila_limit == 0 and args.finess_limit == 0:
        large_change_explanation = "Generation complete demandee: limites de test DILA/FINESS supprimees."
    errors = guard(full_dataset, previous, large_change_explanation)
    errors.extend(guard_android_dataset(android_dataset))
    if finess_stats["unresolvedCategoryCodes"]:
        errors.append("unresolved_finess_category_codes")
    diff = compare(previous or {"entries": []}, full_dataset)
    diff["generationBlocked"] = bool(errors)
    diff["guardErrors"] = errors
    diff["largeChangeExplanation"] = large_change_explanation
    diff["rejected"] = rejected
    diff["sourceStats"] = {"DILA": dila_stats, "FINESS": finess_stats, "FHF_validated": fhf_validated}
    diff["finessCategoryNomenclature"] = category_nomenclature
    diff["finessCommuneNomenclature"] = commune_nomenclature
    diff["sourceRawCounts"] = {
        "DILA": dila_stats["validNumbers"],
        "FINESS": finess_stats["validNumbers"],
        "FHF_validated": fhf_validated,
    }
    diff["mergedDuplicates"] = sum(len(e["sources"]) - 1 for e in entries if len(e["sources"]) > 1)
    write_json(report_path, diff)
    if errors:
        raise SystemExit("Generation bloquee: " + ", ".join(errors))
    write_json(full_dataset_path, full_dataset)
    compact_payload = write_compact_json(android_dataset_path, android_dataset)
    write_gzip(gzip_dataset_path, compact_payload)
    print(json.dumps({
        "fullDataset": full_dataset_path,
        "androidDataset": android_dataset_path,
        "gzipDataset": gzip_dataset_path,
        "report": report_path,
        "entryCount": len(entries),
        "sourceStats": diff["sourceStats"],
        "rejected": len(rejected),
        "mergedDuplicates": diff["mergedDuplicates"],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
