import argparse
import json
import re
import sys
import time
import ssl
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


ROOT = Path(__file__).resolve().parents[1]
DATASETS_DIR = ROOT / "datasets"
REPORTS_DIR = ROOT / "reports"


@dataclass(frozen=True)
class SourceConfig:
    dataset_id: str
    authority: str
    country_id: str
    source_url: str
    source_type: str
    method: str
    extra_urls: Tuple[str, ...] = ()


SOURCE_CONFIGS: Dict[str, SourceConfig] = {
    "fr_arcep": SourceConfig(
        "fr_arcep",
        "ARCEP",
        "FR",
        "https://www.arcep.fr/la-regulation/grands-dossiers-thematiques-transverses/la-numerotation.html",
        "HTML",
        "official HTML page; token verification of documented numbering roots",
    ),
    "de_bundesnetzagentur": SourceConfig(
        "de_bundesnetzagentur",
        "Bundesnetzagentur",
        "DE",
        "https://www.bundesnetzagentur.de/DE/Fachthemen/Telekommunikation/Nummerierung/start.html?lang=de",
        "HTML/PDF",
        "official numbering page; token verification, PDF parsing still manual if links change",
    ),
    "en_ofcom": SourceConfig(
        "en_ofcom",
        "Ofcom",
        "GB",
        "https://www.ofcom.org.uk/cy/phones-and-broadband/phone-numbers/numbering-data",
        "CSV/ZIP + HTML",
        "official numbering data page; structured downloads advertised, rule roots verified from page text",
    ),
    "es_cnmc": SourceConfig(
        "es_cnmc",
        "CNMC",
        "ES",
        "https://numeracionyoperadores.cnmc.es/numeracion",
        "HTML/registry",
        "official public CNMC numbering registry plus official numbering-plan references; token verification",
        (
            "https://www.cnmc.es/ambitos-de-actuacion/telecomunicaciones/registros-sgda",
            "https://www.boe.es/buscar/act.php?id=BOE-A-2004-21841",
        ),
    ),
    "it_agcom": SourceConfig(
        "it_agcom",
        "AGCOM",
        "IT",
        "https://www.agcom.it/competenze/comunicazioni-elettroniche/reti/numerazione/piano-di-numerazione",
        "HTML/PDF",
        "official numbering page; token verification, PDF parsing still manual if links change",
    ),
    "lb_ilr": SourceConfig(
        "lb_ilr",
        "ILR",
        "LU",
        "https://www.ilr.lu/secteurs-activites/communications-electroniques/numerotation/plan-national-numerotation/",
        "HTML",
        "official HTML page; token verification of visible numbering ranges",
    ),
    "nl_acm": SourceConfig(
        "nl_acm",
        "ACM",
        "NL",
        "https://www.acm.nl/nl/telefoonnummers/informatienummers/informatienummers-aanvragen",
        "HTML/official plan",
        "official ACM information-number page; token verification of visible numbering ranges",
    ),
    "pt_anacom": SourceConfig(
        "pt_anacom",
        "ANACOM",
        "PT",
        "https://anacom.pt/render.jsp?categoryId=423086",
        "HTML",
        "official numbering plan and related ANACOM pages; token verification",
        (
            "https://anacom.pt/render.jsp?categoryId=2958",
            "https://anacom.pt/render.jsp?categoryId=425984",
            "https://anacom.pt/render.jsp?contentId=1821303",
        ),
    ),
}

SOURCE_TOKEN_ALIASES = {
    "fr_arcep": {
        "+5905987": ["05987", "05987"],
        "+5909475": ["09475", "09475a09479", "0947509479"],
        "+5945988": ["05988"],
        "+5949476": ["09476", "09475a09479", "0947509479"],
        "+5965989": ["05989"],
        "+5969477": ["09477", "09475a09479", "0947509479"],
        "+262688": ["02688"],
        "+2629479": ["09479", "09475a09479", "0947509479"],
        "+262689": ["02689"],
        "+2629478": ["09478", "09475a09479", "0947509479"],
    },
    "nl_acm": {
        "+31906": ["0906", "0900-0909", "0900tot0909", "09000909"],
        "+31909": ["0909", "0900-0909", "0900tot0909", "09000909"],
    },
    "pt_anacom": {
        "+351760": ["760", "760-762", "760a762", "760762"],
        "+351762": ["762", "760-762", "760a762", "760762"],
        "+351808": ["808"],
        "+351884": ["884"],
    },
}


COUNTRY_CODES = {
    "FR": ["+33", "+590", "+594", "+596", "+262"],
    "DE": ["+49"],
    "GB": ["+44"],
    "ES": ["+34"],
    "IT": ["+39"],
    "LU": ["+352"],
    "NL": ["+31"],
    "PT": ["+351"],
}


def load_dataset(dataset_id: str) -> dict:
    path = DATASETS_DIR / f"{dataset_id}.json"
    return json.loads(path.read_text(encoding="utf-8-sig"))


def current_rules(dataset_id: str) -> List[dict]:
    return load_dataset(dataset_id).get("rules", [])


def normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def national_tokens(rule: dict) -> List[str]:
    raw = rule.get("normalizedPrefix") or rule.get("normalizedNumber") or ""
    country_id = rule.get("countryId") or ""
    values = []
    for cc in COUNTRY_CODES.get(country_id, []):
        if raw.startswith(cc):
            national = raw[len(cc) :]
            if country_id == "LU":
                values.append(national)
            else:
                values.append("0" + national)
            values.append(national)
    values.append(raw)
    compacted = []
    for value in values:
        digits = re.sub(r"\D", "", value)
        if digits and digits not in compacted:
            compacted.append(digits)
    return compacted


class ManualRequiredError(Exception):
    pass


class TemporarilyUnavailableError(Exception):
    pass


def fetch_source(url: str, timeout: int = 90, allow_unverified_tls: bool = False) -> Tuple[bytes, int, str, bool]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BloqueurAppelsOfficialRuleChecker/1.0",
            "Accept": "text/html,application/json,text/csv,application/xml,*/*",
            "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read(), int(response.status), response.headers.get("content-type", ""), True
    except urllib.error.URLError as exc:
        if isinstance(exc, urllib.error.HTTPError) and exc.code == 403:
            raise ManualRequiredError(f"HTTP 403 Forbidden: {url}") from exc
        if "CERTIFICATE_VERIFY_FAILED" not in str(exc):
            raise
        if not allow_unverified_tls:
            raise
        context = ssl._create_unverified_context()
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return response.read(), int(response.status), response.headers.get("content-type", ""), False


def fetch_source_with_retries(
    url: str,
    attempts: int = 2,
    timeout: int = 90,
    allow_unverified_tls: bool = False,
) -> Tuple[bytes, int, str, bool]:
    last_error = None
    for _ in range(attempts):
        try:
            return fetch_source(url, timeout=timeout, allow_unverified_tls=allow_unverified_tls)
        except ManualRequiredError:
            raise
        except Exception as exc:
            last_error = exc
            time.sleep(1)
    raise TemporarilyUnavailableError(f"{type(last_error).__name__}: {last_error}")


def decode_source(content: bytes, content_type: str) -> str:
    encoding = "utf-8"
    match = re.search(r"charset=([^;]+)", content_type or "", re.I)
    if match:
        encoding = match.group(1).strip()
    try:
        return content.decode(encoding, errors="replace")
    except LookupError:
        return content.decode("utf-8", errors="replace")


def compact_digits(text: str) -> str:
    return re.sub(r"\D", "", text)


def compact_alnum(text: str) -> str:
    return re.sub(r"[^0-9a-z]+", "", text.lower())


def compare_rules(current: Iterable[dict], extracted: Iterable[dict]) -> Tuple[List[dict], List[dict], List[dict]]:
    def key(rule: dict) -> Tuple[str, str, str]:
        return (
            rule.get("normalizedPrefix") or rule.get("normalizedNumber") or "",
            rule.get("countryId") or "",
            rule.get("territoryId") or "",
        )

    current_by_key = {key(rule): rule for rule in current}
    extracted_by_key = {key(rule): rule for rule in extracted}
    added = [extracted_by_key[k] for k in sorted(extracted_by_key.keys() - current_by_key.keys())]
    removed = [current_by_key[k] for k in sorted(current_by_key.keys() - extracted_by_key.keys())]
    modified = []
    compared_fields = ("category", "status", "enabledByDefault", "userCanDisable")
    for k in sorted(current_by_key.keys() & extracted_by_key.keys()):
        before = current_by_key[k]
        after = extracted_by_key[k]
        changes = {
            field: {"current": before.get(field), "official": after.get(field)}
            for field in compared_fields
            if before.get(field) != after.get(field)
        }
        if changes:
            modified.append({"key": k[0], "changes": changes})
    return added, removed, modified


def validate_extracted(dataset_id: str, current_count: int, extracted: List[dict]) -> List[str]:
    errors = []
    if not extracted:
        errors.append("aucune règle extraite")
    seen = set()
    for rule in extracted:
        prefix = rule.get("normalizedPrefix") or rule.get("normalizedNumber") or ""
        if not prefix.startswith("+") or not re.fullmatch(r"\+\d{1,15}", prefix):
            errors.append(f"préfixe invalide: {prefix}")
        key = (prefix, rule.get("countryId"), rule.get("territoryId", ""))
        if key in seen:
            errors.append(f"doublon: {prefix}")
        seen.add(key)
    if current_count:
        if len(extracted) < current_count * 0.8:
            errors.append("baisse supérieure à 20 %")
        if len(extracted) > current_count * 1.5:
            errors.append("hausse supérieure à 50 %")
    return errors


def run_check(dataset_id: str) -> dict:
    config = SOURCE_CONFIGS[dataset_id]
    started = time.time()
    dataset = load_dataset(dataset_id)
    current = dataset.get("rules", [])
    report = {
        "datasetId": dataset_id,
        "authority": config.authority,
        "sourceAuthority": dataset.get("sourceAuthority"),
        "sourceReference": dataset.get("sourceReference"),
        "sourceUrl": config.source_url,
        "sourceType": config.source_type,
        "method": config.method,
        "publicationDate": dataset.get("publicationDate"),
        "currentCount": len(current),
        "remoteCount": 0,
        "added": [],
        "removed": [],
        "modified": [],
        "status": "FAILED",
        "error": "",
        "sourceAccessible": False,
        "extractionSucceeded": False,
        "durationSeconds": 0,
    }
    try:
        content, http_status, content_type, tls_verified = fetch_source_with_retries(
            config.source_url,
            attempts=2,
            timeout=30 if dataset_id == "lb_ilr" else 90,
            allow_unverified_tls=dataset_id != "lb_ilr",
        )
        report["httpStatus"] = http_status
        report["contentType"] = content_type
        report["tlsVerified"] = tls_verified
        report["sourceAccessible"] = 200 <= http_status < 300
        texts = [decode_source(content, content_type)]
        extra_results = []
        for extra_url in config.extra_urls:
            try:
                extra_content, extra_status, extra_type, extra_tls = fetch_source_with_retries(
                    extra_url,
                    attempts=2,
                    timeout=90,
                    allow_unverified_tls=dataset_id != "lb_ilr",
                )
                extra_results.append(
                    {
                        "url": extra_url,
                        "httpStatus": extra_status,
                        "contentType": extra_type,
                        "tlsVerified": extra_tls,
                        "error": "",
                    }
                )
                if 200 <= extra_status < 300:
                    texts.append(decode_source(extra_content, extra_type))
            except Exception as extra_exc:
                extra_results.append(
                    {
                        "url": extra_url,
                        "httpStatus": 0,
                        "contentType": "",
                        "tlsVerified": False,
                        "error": f"{type(extra_exc).__name__}: {extra_exc}",
                    }
                )
        report["extraSources"] = extra_results
        text = "\n".join(texts)
        source_digits = compact_digits(text)
        source_text_lower = text.lower()
        source_compact_text = compact_alnum(text)
        extracted = []
        missing_tokens = []
        for rule in current:
            prefix = rule.get("normalizedPrefix") or rule.get("normalizedNumber") or ""
            tokens = national_tokens(rule) + SOURCE_TOKEN_ALIASES.get(dataset_id, {}).get(prefix, [])
            if any(
                token in source_digits
                or token.lower() in source_text_lower
                or compact_alnum(token) in source_compact_text
                for token in tokens
            ):
                extracted.append(dict(rule))
            else:
                missing_tokens.append(
                    {
                        "prefix": rule.get("normalizedPrefix") or rule.get("normalizedNumber"),
                        "tokens": tokens,
                    }
                )
        report["missingTokens"] = missing_tokens
        report["remoteCount"] = len(extracted)
        report["extractionSucceeded"] = len(extracted) > 0
        added, removed, modified = compare_rules(current, extracted)
        report["added"] = added
        report["removed"] = removed
        report["modified"] = modified
        guard_errors = validate_extracted(dataset_id, len(current), extracted)
        if missing_tokens:
            guard_errors.append(f"{len(missing_tokens)} règle(s) actuelle(s) non retrouvée(s) dans la source")
        if guard_errors:
            report["status"] = "BLOCKING_ANOMALY"
            report["error"] = "; ".join(guard_errors)
        elif added or removed or modified:
            report["status"] = "CHANGED"
        else:
            report["status"] = "UNCHANGED"
    except Exception as exc:
        if isinstance(exc, ManualRequiredError):
            report["status"] = "MANUAL_REQUIRED"
            report["error"] = str(exc)
        elif isinstance(exc, TemporarilyUnavailableError):
            report["status"] = "TEMPORARILY_UNAVAILABLE"
            report["error"] = str(exc)
        else:
            report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        report["durationSeconds"] = round(time.time() - started, 2)
    return report


def write_report(report: dict) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"{report['datasetId']}_source_check.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset_id", choices=sorted(SOURCE_CONFIGS))
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args(argv)
    report = run_check(args.dataset_id)
    if args.write_report:
        path = write_report(report)
        report["reportPath"] = str(path)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] in {"UNCHANGED", "CHANGED", "MANUAL_REQUIRED", "TEMPORARILY_UNAVAILABLE"} else 2


if __name__ == "__main__":
    sys.exit(main())
