#!/usr/bin/env python3
"""
Install P1 domain integrations via Fleet, ingest pipeline test fixtures, and report counts.

Environment:
  KIBANA_URL              e.g. http://localhost:5601/ftw
  ES_URL                  e.g. http://localhost:9200

  Auth (pick one):
    ELASTIC_API_KEY       Encoded API key (from Elastic Cloud / serverless)
    ELASTIC_API_KEY_ID + ELASTIC_API_KEY_SECRET   Raw id and secret (encoded automatically)
    KIBANA_API_KEY / ES_API_KEY   Per-service overrides (fall back to ELASTIC_API_KEY)
    ELASTIC_USER + ELASTIC_PASSWORD               Basic auth (default: elastic / changeme)

Examples:
  python3 install_and_ingest.py
  ELASTIC_API_KEY=... python3 install_and_ingest.py
  python3 install_and_ingest.py --install-only
  python3 install_and_ingest.py --ingest-only --run-id my-run
  python3 install_and_ingest.py --packages slack,github
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[2]
P1_DIR = ROOT.parent / "p1"
PACKAGES_DIR = REPO / "packages"
OUT_DIR = ROOT / "out"

INGEST_TAG = "p1-domain-fixture-ingest"
PACKAGE_TAG_PREFIX = "p1-ingest-"

SKIP_FIXTURE_SUFFIXES = ("-expected.json", "-config.yml")
SKIP_FIXTURE_NAMES = {"test-common-config.yml"}


@dataclass
class StreamTarget:
    package: str
    stream: str
    data_type: str
    dataset: str

    @property
    def pipeline(self) -> str:
        return f"{self.data_type}-{self.dataset}"

    @property
    def data_stream(self) -> str:
        return f"{self.data_type}-{self.dataset}-default"


@dataclass
class FixtureResult:
    path: str
    stream: str
    submitted: int
    bulk_errors: int
    error: str | None = None


@dataclass
class IntegrationReport:
    package: str
    installed: bool | None = None
    install_error: str | None = None
    fixture_files: int = 0
    events_submitted: int = 0
    bulk_errors: int = 0
    events_saved: int = 0
    events_failed: int = 0
    timestamp_min: str | None = None
    timestamp_max: str | None = None
    datasets: dict[str, int] = field(default_factory=dict)
    failed_datasets: dict[str, int] = field(default_factory=dict)
    fixtures: list[FixtureResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Auth:
    """HTTP Authorization header value (Basic or ApiKey)."""

    scheme: str
    credentials: str

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"{self.scheme} {self.credentials}"}


def strip_url_credentials(url: str) -> tuple[str, Auth | None]:
    parsed = urlparse(url)
    if not parsed.username:
        return url.rstrip("/"), None
    auth_pass = parsed.password or ""
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    clean = f"{parsed.scheme}://{host}{port}{parsed.path or ''}"
    token = base64.b64encode(f"{parsed.username}:{auth_pass}".encode()).decode()
    return clean.rstrip("/"), Auth("Basic", token)


def normalize_api_key(
    encoded: str | None,
    key_id: str | None = None,
    key_secret: str | None = None,
) -> str | None:
    if encoded:
        value = encoded.strip()
        if value.lower().startswith("apikey "):
            value = value[7:].strip()
        if ":" in value and not re.fullmatch(r"[A-Za-z0-9+/=]+", value):
            value = base64.b64encode(value.encode()).decode()
        return value
    if key_id and key_secret:
        return base64.b64encode(f"{key_id}:{key_secret}".encode()).decode()
    return None


def resolve_auth(
    url: str,
    *,
    api_key: str | None,
    api_key_id: str | None,
    api_key_secret: str | None,
    user: str | None,
    password: str | None,
) -> tuple[str, Auth | None]:
    encoded = normalize_api_key(api_key, api_key_id, api_key_secret)
    if encoded:
        return url.rstrip("/"), Auth("ApiKey", encoded)

    clean, url_auth = strip_url_credentials(url)
    if url_auth:
        return clean, url_auth

    if user and password:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        return url.rstrip("/"), Auth("Basic", token)

    return url.rstrip("/"), None


def resolve_service_auth(
    url: str,
    *,
    service_api_key: str | None,
    global_api_key: str | None,
    api_key_id: str | None,
    api_key_secret: str | None,
    user: str | None,
    password: str | None,
) -> tuple[str, Auth | None]:
    key = service_api_key or global_api_key
    return resolve_auth(
        url,
        api_key=key,
        api_key_id=api_key_id if key is None else None,
        api_key_secret=api_key_secret if key is None else None,
        user=user,
        password=password,
    )


def http_json(
    method: str,
    url: str,
    *,
    auth: Auth | None = None,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 120,
    retries: int = 3,
) -> tuple[int, Any]:
    req_headers = {"Accept": "application/json"}
    if body is not None:
        req_headers["Content-Type"] = "application/json"
    if auth:
        req_headers.update(auth.headers())
    if headers:
        req_headers.update(headers)

    last_error: Exception | None = None
    for attempt in range(retries):
        req = Request(url, data=body, headers=req_headers, method=method)
        try:
            with urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                status = resp.status
            last_error = None
            break
        except HTTPError as exc:
            raw = exc.read()
            status = exc.code
            last_error = None
            break
        except (URLError, ConnectionResetError, TimeoutError) as exc:
            last_error = exc
            if attempt + 1 < retries:
                time.sleep(2 ** attempt)
                continue
            raise RuntimeError(f"Request failed after {retries} attempts: {exc}") from exc

    if last_error is not None:
        raise RuntimeError(f"Request failed: {last_error}") from last_error

    if not raw:
        return status, None
    try:
        return status, json.loads(raw.decode())
    except json.JSONDecodeError:
        return status, raw.decode()


def list_p1_packages(selected: list[str] | None) -> list[str]:
    packages = sorted(p.stem for p in P1_DIR.glob("*.md"))
    if selected:
        missing = [p for p in selected if p not in packages]
        if missing:
            raise SystemExit(f"Unknown package(s): {', '.join(missing)}")
        return selected
    return packages


def read_manifest_fields(manifest_path: Path) -> tuple[str, str | None]:
    text = manifest_path.read_text()
    type_match = re.search(r"^type:\s*(\S+)", text, re.MULTILINE)
    dataset_match = re.search(r"^dataset:\s*(\S+)", text, re.MULTILINE)
    data_type = type_match.group(1) if type_match else "logs"
    dataset = dataset_match.group(1) if dataset_match else None
    return data_type, dataset


def stream_target(package: str, stream: str) -> StreamTarget:
    manifest = PACKAGES_DIR / package / "data_stream" / stream / "manifest.yml"
    if not manifest.exists():
        raise FileNotFoundError(f"Missing manifest: {manifest}")
    data_type, dataset = read_manifest_fields(manifest)
    if not dataset:
        dataset = f"{package}.{stream}"
    return StreamTarget(package=package, stream=stream, data_type=data_type, dataset=dataset)


def is_fixture_file(path: Path) -> bool:
    name = path.name
    if name in SKIP_FIXTURE_NAMES:
        return False
    if any(name.endswith(suffix) for suffix in SKIP_FIXTURE_SUFFIXES):
        return False
    return path.suffix in {".log", ".json"}


def discover_fixtures(package: str) -> list[Path]:
    pkg_dir = PACKAGES_DIR / package
    if not pkg_dir.is_dir():
        return []
    fixtures: list[Path] = []
    for path in sorted(pkg_dir.glob("data_stream/*/_dev/test/pipeline/*")):
        if path.is_file() and is_fixture_file(path):
            fixtures.append(path)
    return fixtures


def _dig(doc: dict[str, Any], path: str) -> Any:
    cur: Any = doc
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _to_iso_timestamp(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return text if text else None
    if isinstance(value, (int, float)):
        # Heuristic: epoch ms vs sec
        seconds = value / 1000 if value > 1e11 else value
        return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return None


# Common timestamp locations in pipeline test fixtures (pre-pipeline document shape).
TIMESTAMP_PATHS = (
    "@timestamp",
    "timestamp",
    "event.created",
    "event.start",
    "created",
    "created_at",
    "date_create",
    "time",
    "json.webhook.event_timestamp",
    "webhook.event_timestamp",
    "jamf_pro.events.webhook.event_timestamp",
)


def _timestamp_from_mapping(obj: Any, depth: int = 0) -> str | None:
    if depth > 6:
        return None
    if isinstance(obj, dict):
        for path in TIMESTAMP_PATHS:
            if "." not in path:
                iso = _to_iso_timestamp(obj.get(path))
            else:
                iso = _to_iso_timestamp(_dig(obj, path))
            if iso:
                return iso
        for value in obj.values():
            iso = _timestamp_from_mapping(value, depth + 1)
            if iso:
                return iso
    return None


def ensure_timestamp(doc: dict[str, Any]) -> None:
    """Data streams require @timestamp at index time; agents add it, pipeline tests often omit it."""
    if doc.get("@timestamp"):
        return

    iso = _timestamp_from_mapping(doc)
    if not iso and "message" in doc:
        raw = doc["message"]
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
                iso = _timestamp_from_mapping(parsed) if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                iso = None
        elif isinstance(raw, dict):
            iso = _timestamp_from_mapping(raw)

    if not iso:
        iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    doc["@timestamp"] = iso


def load_documents(fixture: Path, package: str, run_id: str) -> list[dict[str, Any]]:
    text = fixture.read_text()
    docs: list[dict[str, Any]] = []

    if fixture.suffix == ".log":
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            docs.append({"message": line})
    elif fixture.suffix == ".json":
        payload = json.loads(text)
        if isinstance(payload, dict) and isinstance(payload.get("events"), list):
            docs = [dict(item) for item in payload["events"]]
        elif isinstance(payload, list):
            docs = [dict(item) for item in payload]
        elif isinstance(payload, dict):
            docs = [payload]
        else:
            raise ValueError(f"Unsupported JSON fixture shape: {fixture}")
    else:
        raise ValueError(f"Unsupported fixture type: {fixture}")

    tagged: list[dict[str, Any]] = []
    for doc in docs:
        merged = dict(doc)
        existing_tags = merged.get("tags")
        if existing_tags is None:
            tags: list[str] = []
        elif isinstance(existing_tags, str):
            tags = [existing_tags]
        else:
            tags = list(existing_tags)
        for tag in (INGEST_TAG, f"{PACKAGE_TAG_PREFIX}{package}", f"p1-run-{run_id}"):
            if tag not in tags:
                tags.append(tag)
        merged["tags"] = tags
        labels = dict(merged.get("labels") or {})
        labels["p1_ingest_run"] = run_id
        merged["labels"] = labels
        ensure_timestamp(merged)
        tagged.append(merged)
    return tagged


def resolve_ingest_pipeline(es_url: str, auth: Auth | None, base_name: str) -> str | None:
    """Resolve Fleet-installed pipeline name (may include package version suffix)."""
    status, body = http_json("GET", f"{es_url}/_ingest/pipeline/{base_name}", auth=auth)
    if status == 200:
        return base_name

    # Fleet registers versioned pipelines, e.g. logs-slack.audit-1.28.0
    status, body = http_json("GET", f"{es_url}/_ingest/pipeline/{base_name}*", auth=auth)
    if status == 200 and isinstance(body, dict) and body:
        matches = sorted(body.keys(), reverse=True)
        return matches[0]

    return None


def install_package(kibana_url: str, auth: Auth | None, package: str) -> tuple[bool, str | None]:
    status, body = http_json(
        "POST",
        f"{kibana_url}/api/fleet/epm/packages/{package}",
        auth=auth,
        headers={"kbn-xsrf": "true"},
        body=b"{}",
    )
    if status in {200, 201}:
        return True, None
    if status == 409:
        return True, "already installed"
    detail = body if isinstance(body, str) else json.dumps(body)
    return False, f"HTTP {status}: {detail}"


def bulk_ingest(
    es_url: str,
    auth: Auth | None,
    target: StreamTarget,
    pipeline: str,
    documents: list[dict[str, Any]],
    *,
    chunk_size: int = 200,
) -> tuple[int, int]:
    submitted = 0
    errors = 0

    for i in range(0, len(documents), chunk_size):
        chunk = documents[i : i + chunk_size]
        lines: list[str] = []
        for doc in chunk:
            action = {
                "create": {
                    "_index": target.data_stream,
                    "pipeline": pipeline,
                }
            }
            lines.append(json.dumps(action, separators=(",", ":")))
            lines.append(json.dumps(doc, separators=(",", ":")))
        payload = ("\n".join(lines) + "\n").encode()

        req = Request(
            f"{es_url}/_bulk?refresh=wait_for",
            data=payload,
            headers={
                "Content-Type": "application/x-ndjson",
                "Accept": "application/json",
                **(auth.headers() if auth else {}),
            },
            method="POST",
        )
        with urlopen(req, timeout=180) as resp:
            result = json.loads(resp.read().decode())

        submitted += len(chunk)
        if result.get("errors"):
            for item in result.get("items", []):
                action = item.get("create") or {}
                if action.get("error"):
                    errors += 1

    return submitted, errors


def _tagged_count_query(package: str, run_id: str) -> dict[str, Any]:
    return {
        "bool": {
            "filter": [
                {"term": {"tags": INGEST_TAG}},
                {"term": {"tags": f"{PACKAGE_TAG_PREFIX}{package}"}},
                {"term": {"tags": f"p1-run-{run_id}"}},
            ]
        }
    }


def _parse_search_stats(resp: dict[str, Any]) -> dict[str, Any]:
    total = resp.get("hits", {}).get("total", {})
    count = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
    aggs = resp.get("aggregations", {})
    datasets = {
        bucket["key"]: bucket["doc_count"]
        for bucket in aggs.get("by_dataset", {}).get("buckets", [])
    }
    return {
        "total": count,
        "datasets": datasets,
        "timestamp_min": aggs.get("ts_min", {}).get("value_as_string"),
        "timestamp_max": aggs.get("ts_max", {}).get("value_as_string"),
    }


def query_saved_events(
    es_url: str,
    auth: Auth | None,
    package: str,
    run_id: str,
) -> dict[str, Any]:
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": _tagged_count_query(package, run_id),
        "aggs": {
            "by_dataset": {"terms": {"field": "data_stream.dataset", "size": 100}},
            "ts_min": {"min": {"field": "@timestamp"}},
            "ts_max": {"max": {"field": "@timestamp"}},
        },
    }
    payload = json.dumps(body).encode()

    saved = {"total": 0, "datasets": {}, "timestamp_min": None, "timestamp_max": None}
    for index in ("logs-*", "metrics-*"):
        status, resp = http_json("POST", f"{es_url}/{index}/_search", auth=auth, body=payload)
        if status == 200 and isinstance(resp, dict):
            stats = _parse_search_stats(resp)
            saved["total"] += stats["total"]
            for key, value in stats["datasets"].items():
                saved["datasets"][key] = saved["datasets"].get(key, 0) + value
            if stats["timestamp_min"] and (
                not saved["timestamp_min"] or stats["timestamp_min"] < saved["timestamp_min"]
            ):
                saved["timestamp_min"] = stats["timestamp_min"]
            if stats["timestamp_max"] and (
                not saved["timestamp_max"] or stats["timestamp_max"] > saved["timestamp_max"]
            ):
                saved["timestamp_max"] = stats["timestamp_max"]

    failed = {"total": 0, "datasets": {}}
    fail_body = {
        "size": 0,
        "track_total_hits": True,
        "query": _tagged_count_query(package, run_id),
        "aggs": {"by_dataset": {"terms": {"field": "data_stream.dataset", "size": 100}}},
    }
    fail_payload = json.dumps(fail_body).encode()
    for index in ("logs-*::failures", "metrics-*::failures"):
        status, resp = http_json("POST", f"{es_url}/{index}/_search", auth=auth, body=fail_payload)
        if status == 200 and isinstance(resp, dict):
            stats = _parse_search_stats(resp)
            failed["total"] += stats["total"]
            for key, value in stats["datasets"].items():
                failed["datasets"][key] = failed["datasets"].get(key, 0) + value

    return {
        **saved,
        "failed_total": failed["total"],
        "failed_datasets": failed["datasets"],
    }


def fixture_stream(package: str, fixture: Path) -> str:
    # packages/<pkg>/data_stream/<stream>/_dev/test/pipeline/<file>
    parts = fixture.parts
    idx = parts.index("data_stream")
    return parts[idx + 1]


def ingest_package_fixtures(
    es_url: str,
    auth: Auth | None,
    package: str,
    run_id: str,
    *,
    dry_run: bool,
) -> IntegrationReport:
    report = IntegrationReport(package=package)
    fixtures = discover_fixtures(package)
    report.fixture_files = len(fixtures)

    if not fixtures:
        report.notes.append("no pipeline test fixtures found")
        return report

    if not (PACKAGES_DIR / package).is_dir():
        report.notes.append("package directory missing under packages/")
        return report

    for fixture in fixtures:
        stream = fixture_stream(package, fixture)
        try:
            target = stream_target(package, stream)
        except FileNotFoundError as exc:
            report.fixtures.append(
                FixtureResult(str(fixture.relative_to(REPO)), stream, 0, 0, str(exc))
            )
            continue

        try:
            documents = load_documents(fixture, package, run_id)
        except (json.JSONDecodeError, ValueError) as exc:
            report.fixtures.append(
                FixtureResult(str(fixture.relative_to(REPO)), stream, 0, 0, str(exc))
            )
            continue

        if dry_run:
            report.fixtures.append(
                FixtureResult(str(fixture.relative_to(REPO)), stream, len(documents), 0)
            )
            report.events_submitted += len(documents)
            continue

        pipeline = resolve_ingest_pipeline(es_url, auth, target.pipeline)
        if not pipeline:
            msg = f"ingest pipeline not found: {target.pipeline}"
            report.fixtures.append(
                FixtureResult(str(fixture.relative_to(REPO)), stream, 0, 0, msg)
            )
            report.notes.append(msg)
            continue

        try:
            submitted, bulk_errors = bulk_ingest(es_url, auth, target, pipeline, documents)
        except Exception as exc:  # noqa: BLE001
            report.fixtures.append(
                FixtureResult(str(fixture.relative_to(REPO)), stream, 0, 0, str(exc))
            )
            continue

        report.fixtures.append(
            FixtureResult(str(fixture.relative_to(REPO)), stream, submitted, bulk_errors)
        )
        report.events_submitted += submitted
        report.bulk_errors += bulk_errors

    return report


def write_reports(run_id: str, reports: list[IntegrationReport]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    json_path = OUT_DIR / f"ingest_report_{run_id}.json"
    md_path = OUT_DIR / f"ingest_report_{run_id}.md"
    csv_path = OUT_DIR / f"ingest_report_{run_id}.csv"

    serializable = []
    for r in reports:
        serializable.append(
            {
                "package": r.package,
                "installed": r.installed,
                "install_error": r.install_error,
                "fixture_files": r.fixture_files,
                "events_submitted": r.events_submitted,
                "bulk_errors": r.bulk_errors,
                "events_saved": r.events_saved,
                "events_failed": r.events_failed,
                "timestamp_min": r.timestamp_min,
                "timestamp_max": r.timestamp_max,
                "datasets": r.datasets,
                "failed_datasets": r.failed_datasets,
                "notes": r.notes,
                "fixtures": [f.__dict__ for f in r.fixtures],
            }
        )

    json_path.write_text(json.dumps({"run_id": run_id, "generated_at": ts, "integrations": serializable}, indent=2))

    with csv_path.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "package",
                "installed",
                "fixture_files",
                "events_submitted",
                "bulk_errors",
                "events_saved",
                "events_failed",
                "timestamp_min",
                "timestamp_max",
                "datasets",
                "notes",
            ]
        )
        for r in reports:
            writer.writerow(
                [
                    r.package,
                    r.installed,
                    r.fixture_files,
                    r.events_submitted,
                    r.bulk_errors,
                    r.events_saved,
                    r.events_failed,
                    r.timestamp_min or "",
                    r.timestamp_max or "",
                    ";".join(f"{k}:{v}" for k, v in sorted(r.datasets.items())),
                    "; ".join(r.notes),
                ]
            )

    lines = [
        f"# P1 integration ingest report",
        "",
        f"- **Run ID:** `{run_id}`",
        f"- **Generated:** {ts}",
        "",
        "Counts use `logs-*` and `metrics-*` with **no time range** (fixtures may have historical `@timestamp` values).",
        "Failed docs are counted from `::failures` backing indices when present.",
        "",
        "| Package | Installed | Fixtures | Submitted | Bulk errors | Saved | Failed | @timestamp range |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for r in reports:
        ts_range = ""
        if r.timestamp_min or r.timestamp_max:
            ts_range = f"{r.timestamp_min or '?'} → {r.timestamp_max or '?'}"
        installed = "—" if r.installed is None else ("yes" if r.installed else "no")
        lines.append(
            f"| {r.package} | {installed} | {r.fixture_files} | {r.events_submitted} "
            f"| {r.bulk_errors} | {r.events_saved} | {r.events_failed} | {ts_range} |"
        )

    lines.extend(["", "## Per-integration query (no time filter)", ""])
    for r in reports:
        if r.events_saved == 0:
            continue
        lines.append(f"### `{r.package}`")
        lines.append("")
        lines.append("```esql")
        lines.append("FROM logs-*")
        lines.append(f"| WHERE tags == \"{PACKAGE_TAG_PREFIX}{r.package}\"")
        lines.append(f"  AND tags == \"p1-run-{run_id}\"")
        lines.append("| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)")
        lines.append("```")
        lines.append("")

    md_path.write_text("\n".join(lines))
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    print(f"Wrote {csv_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Install P1 integrations and ingest pipeline fixtures")
    parser.add_argument("--packages", help="Comma-separated package list (default: all 47 P1)")
    parser.add_argument("--install-only", action="store_true")
    parser.add_argument("--ingest-only", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="Discover fixtures and count docs only")
    parser.add_argument("--run-id", default=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S"))
    parser.add_argument("--refresh-delay", type=float, default=2.0, help="Seconds to wait before counting")
    args = parser.parse_args()

    do_install = not args.ingest_only
    do_ingest = not args.install_only

    selected = args.packages.split(",") if args.packages else None
    packages = list_p1_packages(selected)

    kibana_raw = os.environ.get("KIBANA_URL", "http://localhost:5601/ftw")
    es_raw = os.environ.get("ES_URL", "http://localhost:9200")
    user = os.environ.get("ELASTIC_USER", "elastic")
    password = os.environ.get("ELASTIC_PASSWORD", "changeme")
    elastic_api_key = os.environ.get("ELASTIC_API_KEY")
    api_key_id = os.environ.get("ELASTIC_API_KEY_ID")
    api_key_secret = os.environ.get("ELASTIC_API_KEY_SECRET")
    kibana_api_key = os.environ.get("KIBANA_API_KEY")
    es_api_key = os.environ.get("ES_API_KEY")

    kibana_url, kibana_auth = resolve_service_auth(
        kibana_raw,
        service_api_key=kibana_api_key,
        global_api_key=elastic_api_key,
        api_key_id=api_key_id,
        api_key_secret=api_key_secret,
        user=user,
        password=password,
    )
    es_url, es_auth = resolve_service_auth(
        es_raw,
        service_api_key=es_api_key,
        global_api_key=elastic_api_key,
        api_key_id=api_key_id,
        api_key_secret=api_key_secret,
        user=user,
        password=password,
    )

    run_id = args.run_id
    reports: list[IntegrationReport] = []

    print(f"Run ID: {run_id}")
    print(f"Kibana: {kibana_url}")
    print(f"Elasticsearch: {es_url}")
    print(f"Auth: kibana={kibana_auth.scheme if kibana_auth else 'none'}, es={es_auth.scheme if es_auth else 'none'}")
    print(f"Packages: {len(packages)}")

    for package in packages:
        report = IntegrationReport(package=package)
        print(f"\n=== {package} ===")

        try:
            if do_install:
                if args.dry_run:
                    report.installed = None
                    print("  [dry-run] skip install")
                else:
                    ok, err = install_package(kibana_url, kibana_auth, package)
                    report.installed = ok
                    report.install_error = err
                    if ok:
                        print(f"  installed{' (' + err + ')' if err else ''}")
                    else:
                        print(f"  install FAILED: {err}")

            if do_ingest:
                ingest_report = ingest_package_fixtures(
                    es_url, es_auth, package, run_id, dry_run=args.dry_run
                )
                report.fixture_files = ingest_report.fixture_files
                report.events_submitted = ingest_report.events_submitted
                report.bulk_errors = ingest_report.bulk_errors
                report.fixtures = ingest_report.fixtures
                report.notes.extend(ingest_report.notes)
                print(
                    f"  fixtures: {report.fixture_files}, submitted: {report.events_submitted}, "
                    f"bulk errors: {report.bulk_errors}"
                )
        except Exception as exc:  # noqa: BLE001
            report.notes.append(f"fatal: {exc}")
            print(f"  ERROR: {exc}")

        reports.append(report)

    if do_ingest and not args.dry_run:
        print(f"\nWaiting {args.refresh_delay}s for indexing...")
        time.sleep(args.refresh_delay)
        for report in reports:
            if report.events_submitted == 0:
                report.events_saved = 0
                continue
            stats = query_saved_events(es_url, es_auth, report.package, run_id)
            report.events_saved = stats["total"]
            report.events_failed = stats.get("failed_total", 0)
            report.datasets = stats["datasets"]
            report.failed_datasets = stats.get("failed_datasets", {})
            report.timestamp_min = stats["timestamp_min"]
            report.timestamp_max = stats["timestamp_max"]
            print(
                f"  {report.package}: saved={report.events_saved}, failed={report.events_failed} "
                f"(@timestamp {report.timestamp_min} .. {report.timestamp_max})"
            )

    write_reports(run_id, reports)
    return 0


if __name__ == "__main__":
    sys.exit(main())
