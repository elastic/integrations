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

  TLS (local dev serverless with self-signed certs):
    ELASTIC_SSL_VERIFY=false    Disable certificate verification
    ELASTIC_SSL_CA_CERT         Path to a custom CA bundle (optional)
    --insecure                  CLI flag equivalent to ELASTIC_SSL_VERIFY=false

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
import ssl
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

# Set by configure_http_ssl() before any HTTP calls.
_HTTP_SSL_CONTEXT: ssl.SSLContext | None = None


def _parse_ssl_verify_env() -> bool | None:
    raw = os.environ.get("ELASTIC_SSL_VERIFY")
    if raw is None:
        return None
    return raw.strip().lower() not in {"0", "false", "no", "off", "none"}


def configure_http_ssl(*, verify: bool, ca_cert: str | None = None) -> None:
    """Configure TLS for urllib. Use verify=False for local dev with self-signed certs."""
    global _HTTP_SSL_CONTEXT
    if not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        _HTTP_SSL_CONTEXT = ctx
        return
    if ca_cert:
        _HTTP_SSL_CONTEXT = ssl.create_default_context(cafile=ca_cert)
        return
    _HTTP_SSL_CONTEXT = None


def _urlopen(req: Request, *, timeout: int):
    if _HTTP_SSL_CONTEXT is not None:
        return urlopen(req, timeout=timeout, context=_HTTP_SSL_CONTEXT)
    return urlopen(req, timeout=timeout)


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
    pipeline: str | None = None
    config_files: list[str] = field(default_factory=list)
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
    unparsed_with_message: int = 0
    parsed_with_event_original: int = 0
    pipeline_errors: int = 0
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
            with _urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                status = resp.status
            last_error = None
            break
        except HTTPError as exc:
            raw = exc.read()
            status = exc.code
            last_error = None
            break
        except (URLError, ConnectionResetError, TimeoutError, ConnectionError) as exc:
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


def _set_nested(doc: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cur: dict[str, Any] = doc
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def _deep_merge_dict(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge_dict(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    text = path.read_text()
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        yaml = None
    if yaml is not None:
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    return _parse_pipeline_config_fallback(text)


def _parse_pipeline_config_fallback(text: str) -> dict[str, Any]:
    """Minimal parser for pipeline test configs when PyYAML is unavailable."""
    fields: dict[str, Any] = {}
    in_fields = False
    fields_indent = 0
    list_key: str | None = None

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip())
        line = raw_line.strip()

        if line == "fields:":
            in_fields = True
            fields_indent = indent
            list_key = None
            continue

        if not in_fields:
            continue

        if indent <= fields_indent and line.endswith(":"):
            break

        if line.startswith("- "):
            if list_key is None:
                continue
            fields.setdefault(list_key, [])
            if isinstance(fields[list_key], list):
                fields[list_key].append(line[2:].strip().strip("'\""))
            continue

        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        list_key = None

        if not value:
            list_key = key
            fields[key] = []
            continue

        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            fields[key] = [item.strip().strip("'\"") for item in inner.split(",") if item.strip()]
        elif value in {"true", "false"}:
            fields[key] = value == "true"
        elif (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            fields[key] = value[1:-1]
        else:
            try:
                if "." in value:
                    fields[key] = float(value)
                else:
                    fields[key] = int(value)
            except ValueError:
                fields[key] = value

    return {"fields": fields}


def fixture_config_paths(fixture: Path) -> list[Path]:
    """Pipeline test configs applied before ingest, same as elastic-package test runner."""
    configs: list[Path] = []
    common = fixture.parent / "test-common-config.yml"
    if common.is_file():
        configs.append(common)
    per_fixture = fixture.parent / f"{fixture.name}-config.yml"
    if per_fixture.is_file():
        configs.append(per_fixture)
    return configs


def load_pipeline_config_fields(config_path: Path) -> dict[str, Any]:
    data = _load_yaml_mapping(config_path)
    fields = data.get("fields")
    return dict(fields) if isinstance(fields, dict) else {}


def apply_pipeline_config_fields(doc: dict[str, Any], fields: dict[str, Any]) -> None:
    """Merge config ``fields`` into a document before bulk ingest (matches pipeline tests)."""
    for key, value in fields.items():
        if key == "tags" and isinstance(value, list):
            existing = doc.get("tags")
            if existing is None:
                doc["tags"] = list(value)
            elif isinstance(existing, str):
                doc["tags"] = [existing, *value]
            else:
                merged = list(existing)
                for tag in value:
                    if tag not in merged:
                        merged.append(tag)
                doc["tags"] = merged
            continue

        if "." in key:
            _set_nested(doc, key, value)
            continue

        if isinstance(value, dict) and isinstance(doc.get(key), dict):
            doc[key] = _deep_merge_dict(doc[key], value)
        else:
            doc[key] = value


def apply_fixture_configs(doc: dict[str, Any], fixture: Path) -> list[str]:
    """Apply test-common-config.yml and per-fixture *-config.yml fields."""
    applied: list[str] = []
    for config_path in fixture_config_paths(fixture):
        fields = load_pipeline_config_fields(config_path)
        if fields:
            apply_pipeline_config_fields(doc, fields)
            applied.append(str(config_path.relative_to(REPO)))
    return applied


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


def default_event_module(package: str) -> str:
    """Beat-style event.module for integrations that omit it in log fixtures."""
    for prefix, module in (
        ("azure_", "azure"),
        ("aws_", "aws"),
        ("google_", "google"),
        ("microsoft_", "microsoft"),
        ("o365_", "o365"),
    ):
        if package.startswith(prefix):
            return module
    return package


def apply_agent_metadata(doc: dict[str, Any], target: StreamTarget, package: str) -> None:
    """Add Fleet/Agent data_stream metadata when fixtures omit it (typical for ``.log`` files)."""
    ds = doc.get("data_stream")
    if not isinstance(ds, dict):
        ds = {}
        doc["data_stream"] = ds
    ds.setdefault("type", target.data_type)
    ds.setdefault("dataset", target.dataset)
    ds.setdefault("namespace", "default")

    event = doc.get("event")
    if not isinstance(event, dict):
        event = {}
        doc["event"] = event
    event.setdefault("dataset", target.dataset)
    event.setdefault("module", default_event_module(package))


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
        apply_fixture_configs(merged, fixture)
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


def pick_fleet_main_pipeline(candidates: list[str], base_name: str) -> str | None:
    """Pick the Fleet default pipeline, not auxiliary sub-pipelines.

    Fleet installs:
      - logs-dataset-1.2.3              (default — runs message parsing)
      - logs-dataset-1.2.3.shared       (sub-pipeline, e.g. azure-shared-pipeline)

    A naive ``sorted(keys, reverse=True)`` picks the sub-pipeline because its name
  is longer, leaving raw ``message`` in the document.
    """
    if not candidates:
        return None

    # logs-<dataset>-<major.minor.patch> with no extra ".segment" after the version
    main = re.compile(rf"^{re.escape(base_name)}-(\d+\.\d+\.\d+)$")
    main_matches = [name for name in candidates if main.match(name)]
    if main_matches:
        return sorted(main_matches, reverse=True)[0]

    # Fallback: versioned name without @custom / @package suffix pipelines
    versioned = [name for name in candidates if name.startswith(f"{base_name}-") and "@" not in name]
    if versioned:
        return sorted(versioned, key=lambda n: (n.count("."), n), reverse=True)[0]

    return None


def list_fleet_pipelines(es_url: str, auth: Auth | None, base_name: str) -> list[str]:
    status, body = http_json("GET", f"{es_url}/_ingest/pipeline/{base_name}-*", auth=auth, timeout=60)
    if status == 200 and isinstance(body, dict):
        return sorted(body.keys())
    return []


def resolve_ingest_pipeline(es_url: str, auth: Auth | None, base_name: str) -> str | None:
    """Resolve Fleet default ingest pipeline (versioned main, not sub-pipelines or stubs).

    Fleet may register an unversioned ``logs-dataset`` stub; always prefer the versioned
    main pipeline ``logs-dataset-1.2.3`` when present.
    """
    candidates = list_fleet_pipelines(es_url, auth, base_name)
    picked = pick_fleet_main_pipeline(candidates, base_name)
    if picked:
        return picked

    status, _ = http_json("GET", f"{es_url}/_ingest/pipeline/{base_name}", auth=auth, timeout=60)
    if status == 200:
        return base_name

    return None


FLEET_INSTALL_PRIVS = "integrations-all AND fleet-agent-policies-all"


def _fleet_headers() -> dict[str, str]:
    return {"kbn-xsrf": "true"}


def ensure_fleet_setup(kibana_url: str, auth: Auth | None) -> None:
    status, body = http_json(
        "POST",
        f"{kibana_url}/api/fleet/setup",
        auth=auth,
        headers=_fleet_headers(),
        body=b"{}",
        timeout=120,
    )
    if status not in {200, 201}:
        detail = body if isinstance(body, str) else json.dumps(body)
        raise RuntimeError(f"Fleet setup failed: HTTP {status}: {detail}")


def get_package_item(kibana_url: str, auth: Auth | None, package: str) -> dict[str, Any] | None:
    status, body = http_json(
        "GET",
        f"{kibana_url}/api/fleet/epm/packages/{package}",
        auth=auth,
        headers=_fleet_headers(),
        timeout=60,
    )
    if status != 200 or not isinstance(body, dict):
        return None
    item = body.get("item")
    return item if isinstance(item, dict) else None


def package_install_state(item: dict[str, Any] | None) -> str | None:
    if not item:
        return None
    state = item.get("status") or item.get("install_status")
    return state if isinstance(state, str) else None


def wait_for_package_install(
    kibana_url: str,
    auth: Auth | None,
    package: str,
    *,
    timeout: float,
    poll_interval: float,
) -> tuple[bool, str | None]:
    deadline = time.time() + timeout
    last_state: str | None = None
    while time.time() < deadline:
        last_state = package_install_state(get_package_item(kibana_url, auth, package))
        if last_state == "installed":
            return True, None
        if last_state == "install_failed":
            return False, "Fleet reported install_failed"
        time.sleep(poll_interval)
    return False, f"timed out waiting for install (last state: {last_state})"


def install_package(
    kibana_url: str,
    auth: Auth | None,
    package: str,
    *,
    install_timeout: int = 600,
    poll_timeout: float = 900,
    poll_interval: float = 5.0,
) -> tuple[bool, str | None]:
    item = get_package_item(kibana_url, auth, package)
    state = package_install_state(item)
    if state == "installed":
        return True, "already installed"

    if state == "installing":
        print("  package already installing, waiting for Fleet...")
        ok, err = wait_for_package_install(
            kibana_url, auth, package, timeout=poll_timeout, poll_interval=poll_interval
        )
        return (True, "installed after wait") if ok else (False, err)

    install_url = f"{kibana_url}/api/fleet/epm/packages/{package}?ignoreMappingUpdateErrors=true"
    post_error: str | None = None
    try:
        status, body = http_json(
            "POST",
            install_url,
            auth=auth,
            headers=_fleet_headers(),
            body=b"{}",
            timeout=install_timeout,
            retries=1,
        )
    except RuntimeError as exc:
        post_error = str(exc)
        status = 0
        body = None

    if status in {200, 201}:
        return True, None
    if status == 409:
        return True, "already installed"
    if status in {401, 403}:
        detail = body if isinstance(body, str) else json.dumps(body)
        return (
            False,
            f"HTTP {status}: Fleet install requires {FLEET_INSTALL_PRIVS}. "
            f"Use the elastic superuser or an API key with those privileges. Detail: {detail}",
        )

    if post_error or status not in {200, 201, 409}:
        if post_error:
            print(f"  install request interrupted ({post_error}), polling Fleet status...")
        elif status:
            detail = body if isinstance(body, str) else json.dumps(body)
            print(f"  install returned HTTP {status}, polling Fleet status... ({detail})")
        ok, poll_err = wait_for_package_install(
            kibana_url, auth, package, timeout=poll_timeout, poll_interval=poll_interval
        )
        if ok:
            note = "installed (recovered after interrupted request)" if post_error else f"installed (recovered after HTTP {status})"
            return True, note
        if post_error:
            return False, f"{post_error}; poll result: {poll_err}"
        detail = body if isinstance(body, str) else json.dumps(body)
        return False, f"HTTP {status}: {detail}; poll result: {poll_err}"

    return True, None


def verify_parsed_events(
    es_url: str,
    auth: Auth | None,
    package: str,
    run_id: str,
) -> dict[str, int]:
    """Count docs that still have raw ``message`` vs properly parsed ``event.original``."""
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": _tagged_count_query(package, run_id),
        "aggs": {
            "with_message": {"filter": {"exists": {"field": "message"}}},
            "with_event_original": {"filter": {"exists": {"field": "event.original"}}},
            "pipeline_errors": {"filter": {"term": {"event.kind": "pipeline_error"}}},
        },
    }
    payload = json.dumps(body).encode()
    total = with_message = with_event_original = pipeline_errors = 0
    for index in ("logs-*", "metrics-*"):
        status, resp = http_json("POST", f"{es_url}/{index}/_search", auth=auth, body=payload)
        if status == 200 and isinstance(resp, dict):
            hits = resp.get("hits", {}).get("total", {})
            total += hits.get("value", 0) if isinstance(hits, dict) else int(hits or 0)
            aggs = resp.get("aggregations", {})
            with_message += aggs.get("with_message", {}).get("doc_count", 0)
            with_event_original += aggs.get("with_event_original", {}).get("doc_count", 0)
            pipeline_errors += aggs.get("pipeline_errors", {}).get("doc_count", 0)
    return {
        "total": total,
        "with_message": with_message,
        "with_event_original": with_event_original,
        "pipeline_errors": pipeline_errors,
    }


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
        with _urlopen(req, timeout=180) as resp:
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
                FixtureResult(str(fixture.relative_to(REPO)), stream, 0, 0, error=str(exc))
            )
            continue

        try:
            documents = load_documents(fixture, package, run_id)
        except (json.JSONDecodeError, ValueError) as exc:
            report.fixtures.append(
                FixtureResult(str(fixture.relative_to(REPO)), stream, 0, 0, error=str(exc))
            )
            continue

        for doc in documents:
            apply_agent_metadata(doc, target, package)

        config_files = [str(p.relative_to(REPO)) for p in fixture_config_paths(fixture)]

        if dry_run:
            report.fixtures.append(
                FixtureResult(
                    str(fixture.relative_to(REPO)), stream, len(documents), 0, config_files=config_files
                )
            )
            report.events_submitted += len(documents)
            continue

        pipeline = resolve_ingest_pipeline(es_url, auth, target.pipeline)
        if not pipeline:
            candidates = list_fleet_pipelines(es_url, auth, target.pipeline)
            msg = f"ingest pipeline not found: {target.pipeline}"
            if candidates:
                msg += f" (found: {', '.join(candidates)})"
            report.fixtures.append(
                FixtureResult(str(fixture.relative_to(REPO)), stream, 0, 0, error=msg)
            )
            report.notes.append(msg)
            continue

        print(f"    pipeline: {pipeline} -> {target.data_stream}")

        try:
            submitted, bulk_errors = bulk_ingest(es_url, auth, target, pipeline, documents)
        except Exception as exc:  # noqa: BLE001
            report.fixtures.append(
                FixtureResult(
                    str(fixture.relative_to(REPO)), stream, 0, 0, pipeline=pipeline, error=str(exc)
                )
            )
            continue

        report.fixtures.append(
            FixtureResult(
                str(fixture.relative_to(REPO)),
                stream,
                submitted,
                bulk_errors,
                pipeline=pipeline,
                config_files=config_files,
            )
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
                "unparsed_with_message": r.unparsed_with_message,
                "parsed_with_event_original": r.parsed_with_event_original,
                "pipeline_errors": r.pipeline_errors,
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
        "| Package | Installed | Fixtures | Submitted | Bulk errors | Saved | Failed | Pipeline errors | Unparsed `message` | @timestamp range |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for r in reports:
        ts_range = ""
        if r.timestamp_min or r.timestamp_max:
            ts_range = f"{r.timestamp_min or '?'} → {r.timestamp_max or '?'}"
        installed = "—" if r.installed is None else ("yes" if r.installed else "no")
        lines.append(
            f"| {r.package} | {installed} | {r.fixture_files} | {r.events_submitted} "
            f"| {r.bulk_errors} | {r.events_saved} | {r.events_failed} | {r.pipeline_errors} "
            f"| {r.unparsed_with_message} | {ts_range} |"
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
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification (local dev with self-signed certs)",
    )
    parser.add_argument(
        "--install-timeout",
        type=int,
        default=int(os.environ.get("FLEET_INSTALL_TIMEOUT", "600")),
        help="Seconds to wait for Fleet install HTTP response (default: 600)",
    )
    parser.add_argument(
        "--install-wait",
        type=float,
        default=float(os.environ.get("FLEET_INSTALL_WAIT", "900")),
        help="Seconds to poll Fleet after an interrupted install (default: 900)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Check saved docs for a run_id (message vs event.original); no install/ingest",
    )
    args = parser.parse_args()

    ssl_verify = _parse_ssl_verify_env()
    if ssl_verify is None:
        ssl_verify = True
    if args.insecure:
        ssl_verify = False
    configure_http_ssl(verify=ssl_verify, ca_cert=os.environ.get("ELASTIC_SSL_CA_CERT"))

    do_install = not args.ingest_only and not args.verify_only
    do_ingest = not args.install_only and not args.verify_only

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
    if not ssl_verify:
        print("TLS: verification disabled (--insecure or ELASTIC_SSL_VERIFY=false)")
    elif os.environ.get("ELASTIC_SSL_CA_CERT"):
        print(f"TLS: custom CA {os.environ['ELASTIC_SSL_CA_CERT']}")
    print(f"Packages: {len(packages)}")

    if args.verify_only:
        run_id = args.run_id
        print(f"\nVerify run `{run_id}` on {es_url}\n")
        exit_code = 0
        for package in packages:
            stats = verify_parsed_events(es_url, es_auth, package, run_id)
            saved = query_saved_events(es_url, es_auth, package, run_id)
            base = f"logs-{package}"  # rough; show resolved pipelines per stream
            print(f"=== {package} ===")
            print(
                f"  saved: {saved['total']}, pipeline_error: {stats['pipeline_errors']}, "
                f"with message: {stats['with_message']}, event.original: {stats['with_event_original']}"
            )
            for fixture in discover_fixtures(package):
                stream = fixture_stream(package, fixture)
                try:
                    target = stream_target(package, stream)
                except FileNotFoundError:
                    continue
                candidates = list_fleet_pipelines(es_url, es_auth, target.pipeline)
                picked = resolve_ingest_pipeline(es_url, es_auth, target.pipeline)
                print(f"  stream {stream}: pipeline={picked or 'NOT FOUND'}")
                if candidates:
                    print(f"    candidates: {', '.join(candidates)}")
            if stats["pipeline_errors"] > 0:
                exit_code = 1
            elif stats["with_message"] and stats["with_message"] == stats["total"] and stats["total"] > 0:
                exit_code = 1
        return exit_code

    if do_install and not args.dry_run:
        print("Running Fleet setup...")
        ensure_fleet_setup(kibana_url, kibana_auth)

    for package in packages:
        report = IntegrationReport(package=package)
        print(f"\n=== {package} ===")

        try:
            if do_install:
                if args.dry_run:
                    report.installed = None
                    print("  [dry-run] skip install")
                else:
                    ok, err = install_package(
                        kibana_url,
                        kibana_auth,
                        package,
                        install_timeout=args.install_timeout,
                        poll_timeout=args.install_wait,
                    )
                    report.installed = ok
                    report.install_error = err
                    if ok:
                        print(f"  installed{' (' + err + ')' if err else ''}")
                    else:
                        print(f"  install FAILED: {err}")
                    delay = float(os.environ.get("FLEET_INSTALL_DELAY", "0"))
                    if delay > 0:
                        time.sleep(delay)

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
            parse_stats = verify_parsed_events(es_url, es_auth, report.package, run_id)
            report.unparsed_with_message = parse_stats["with_message"]
            report.parsed_with_event_original = parse_stats["with_event_original"]
            report.pipeline_errors = parse_stats["pipeline_errors"]
            print(
                f"  {report.package}: saved={report.events_saved}, failed={report.events_failed}, "
                f"pipeline_error={report.pipeline_errors} "
                f"(@timestamp {report.timestamp_min} .. {report.timestamp_max})"
            )
            if parse_stats["pipeline_errors"]:
                print(f"    WARNING: {parse_stats['pipeline_errors']}/{parse_stats['total']} docs have event.kind=pipeline_error")
            elif parse_stats["with_message"]:
                print(
                    f"    WARNING: {parse_stats['with_message']}/{parse_stats['total']} docs still have "
                    f"raw `message` (only {parse_stats['with_event_original']} have event.original)"
                )

    write_reports(run_id, reports)
    return 0


if __name__ == "__main__":
    sys.exit(main())
