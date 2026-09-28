"""Package loading shared by the columnar skill scripts.

Reads package manifests and field definitions, detects mapping features that
columnar rejects or changes, and attributes prebuilt detection rules to data
streams by index pattern.
"""

from __future__ import annotations

import fnmatch
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.exit(
        "error: PyYAML is required. Run with `uv run <script>` "
        "(dependencies are declared inline) or `pip install pyyaml`.",
    )

INDEX_TYPE_PREFIXES = ("logs-", "metrics-", "traces-", "synthetics-")

# format_version major.minor -> first stack whose Fleet accepts it
# (`REGISTRY_SPEC_MAX_VERSION`). 9.0 stops at 3.3, so 3.4 is 8.19 and 9.1+.
SPEC_MIN_STACK = {
    (3, 0): "8.11",
    (3, 1): "8.16",
    (3, 2): "8.16",
    (3, 3): "8.16",
    (3, 4): "8.19",
    (3, 5): "9.2",
    (3, 6): "9.4",
}

# ES|QL source command: FROM <patterns> until METADATA or the next pipe. The
# command starts a line, so prose such as "originates from an external IP" is skipped.
FROM_CLAUSE_RE = re.compile(
    r"""^\s*from\s+(.+?)(?:\s+metadata\b|\s*\||\s*$)""",
    re.IGNORECASE | re.MULTILINE,
)
ESQL_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
RULE_FILE_RE = re.compile(r"^(?P<rule_id>.+)_(?P<version>\d+)\.json$")

# ECS fields defined with `doc_values: false`. elastic-package copies `doc_values`
# from ECS into `external: ecs` fields at build time unless the entry sets it.
ECS_DOC_VALUES_FALSE = frozenset(
    {
        "event.original",
        "file.x509.public_key_exponent",
        "gen_ai.agent.description",
        "threat.enrichments.indicator.file.x509.public_key_exponent",
        "threat.enrichments.indicator.x509.public_key_exponent",
        "threat.indicator.file.x509.public_key_exponent",
        "threat.indicator.x509.public_key_exponent",
        "tls.client.x509.public_key_exponent",
        "tls.server.x509.public_key_exponent",
    },
)


class LineDict(dict):
    """YAML mapping that remembers its own source line and the line of each key."""

    line: int = 1
    key_lines: dict[str, int]

    def line_of(self, key: str) -> int:
        return self.key_lines.get(key, self.line)


class LineLoader(getattr(yaml, "CSafeLoader", yaml.SafeLoader)):  # type: ignore[misc]
    pass


def _construct_line_mapping(loader: LineLoader, node: yaml.MappingNode) -> LineDict:
    mapping = LineDict(loader.construct_mapping(node, deep=True))
    mapping.line = node.start_mark.line + 1
    mapping.key_lines = {str(key.value): key.start_mark.line + 1 for key, _ in node.value}
    return mapping


LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_line_mapping)


def load_yaml(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return yaml.load(path.read_text(errors="replace"), Loader=LineLoader)
    except yaml.YAMLError as exc:
        print(f"warning: cannot parse {display_path(path)}: {exc}", file=sys.stderr)
        return None


def as_line_dict(value: Any) -> LineDict:
    return value if isinstance(value, LineDict) else LineDict()


def is_false(value: Any) -> bool:
    return value is False or (isinstance(value, str) and value.strip().lower() == "false")


def display_path(path: Path) -> str:
    parts = path.parts
    for marker in ("packages", "detection-rules"):
        if marker in parts:
            return str(Path(*parts[parts.index(marker) :]))
    return str(path)


@dataclass
class Finding:
    severity: str  # blocker | data_loss | info
    kind: str
    path: Path
    line: int
    detail: str
    field_path: str | None = None


@dataclass
class Stream:
    name: str
    type: str
    dataset: str
    index_mode: str | None = None
    skip_reason: str | None = None
    findings: list[Finding] = field(default_factory=list)
    declared_fields: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)

    @property
    def in_scope(self) -> bool:
        return self.skip_reason is None


@dataclass
class Package:
    path: Path
    name: str
    type: str | None
    format_version: str | None = None
    kibana_constraint: str | None = None
    skip_reason: str | None = None
    streams: list[Stream] = field(default_factory=list)
    transforms: int = 0
    # policy template name -> data stream directory names it enables
    policy_template_streams: dict[str, list[str]] = field(default_factory=dict)

    @property
    def in_scope_streams(self) -> list[Stream]:
        return [s for s in self.streams if s.in_scope]


def field_yaml_files(root: Path) -> list[Path]:
    fields_dir = root / "fields"
    if not fields_dir.is_dir():
        return []
    return sorted(fields_dir.glob("*.yml")) + sorted(fields_dir.glob("*.yaml"))


def scan_fields(files: list[Path]) -> tuple[list[Finding], set[str]]:
    """Findings and declared field paths across all field files of one stream."""
    findings: list[Finding] = []
    declared: set[str] = set()
    nested: dict[str, tuple[Path, int]] = {}

    def check(entry: LineDict, field_path: str, path: Path) -> None:
        def add(severity: str, kind: str, key: str, detail: str | None = None) -> None:
            if detail is None:
                value = entry[key]
                shown = str(value).lower() if isinstance(value, bool) else value
                detail = f"`{key}: {shown}` on `{field_path}`"
            findings.append(Finding(severity, kind, path, entry.line_of(key), detail, field_path))

        field_type = entry.get("type")
        if field_type == "nested":
            nested.setdefault(field_path, (path, entry.line_of("type")))
        if entry.get("store") is True:
            add("blocker", "store: true", "store")
        integrity = field_path == "event.original" or field_path.endswith(".event.original")
        doc_values_kind = "doc_values: false (event.original)" if integrity else "doc_values: false"
        if is_false(entry.get("doc_values")):
            add("blocker", doc_values_kind, "doc_values")
        elif "doc_values" not in entry and entry.get("external") == "ecs" and field_path in ECS_DOC_VALUES_FALSE:
            add("blocker", doc_values_kind, "external", f"`doc_values: false` on `{field_path}` (ECS, via `external: ecs`)")
        if "copy_to" in entry:
            add("blocker", "copy_to", "copy_to")
        # package-spec: `runtime: true` or a script string.
        if entry.get("runtime") is not None and not is_false(entry.get("runtime")):
            add("blocker", "runtime", "runtime")
        if field_type == "search_as_you_type":
            add("blocker", "type: search_as_you_type", "type")
        if is_false(entry.get("dynamic")):
            add("data_loss", "dynamic: false", "dynamic")
        if is_false(entry.get("enabled")):
            add("data_loss", "enabled: false", "enabled")
        if field_type in {"text", "match_only_text"}:
            add("info", f"type: {field_type}", "type")

    def walk(entries: list[Any], prefix: str, path: Path) -> None:
        for entry in entries:
            if not isinstance(entry, LineDict) or not entry.get("name"):
                continue
            field_path = f"{prefix}.{str(entry['name']).strip()}" if prefix else str(entry["name"]).strip()
            declared.add(field_path)
            check(entry, field_path, path)
            for multi_field in entry.get("multi_fields") or []:
                if isinstance(multi_field, LineDict) and multi_field.get("name"):
                    check(multi_field, f"{field_path}.{multi_field['name']}", path)
            if isinstance(entry.get("fields"), list):
                walk(entry["fields"], field_path, path)

    for path in files:
        entries = load_yaml(path)
        if isinstance(entries, list):
            walk(entries, "", path)

    # Single-level nested is valid; a nested field under another nested field is a blocker.
    for child, (path, line_no) in nested.items():
        parent = max((p for p in nested if child.startswith(p + ".")), key=len, default=None)
        if parent:
            findings.append(
                Finding("blocker", "nested-in-nested", path, line_no, f"`{parent}` → `{child}`", child),
            )
    return findings, declared


def scan_manifest_mappings(elasticsearch: LineDict, manifest_path: Path) -> list[Finding]:
    """`dynamic`/`enabled: false` and a disabled `_source` in `index_template.mappings`."""
    findings: list[Finding] = []

    def walk(node: Any, trail: str) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item, trail)
            return
        if not isinstance(node, LineDict):
            return
        for key, value in node.items():
            key = str(key)
            where = f" at `{trail}`" if trail else ""
            line_no = node.line_of(key)
            if key == "dynamic" and is_false(value):
                findings.append(
                    Finding("data_loss", "manifest/dynamic: false", manifest_path, line_no, f"`dynamic: false`{where}"),
                )
            elif key == "enabled" and is_false(value) and trail.endswith("_source"):
                findings.append(
                    Finding("blocker", "manifest/_source disabled", manifest_path, line_no, "`_source.enabled: false`"),
                )
            elif key == "enabled" and is_false(value):
                findings.append(
                    Finding("data_loss", "manifest/enabled: false", manifest_path, line_no, f"`enabled: false`{where}"),
                )
            else:
                walk(value, f"{trail}.{key}" if trail else key)

    walk(as_line_dict(as_line_dict(elasticsearch.get("index_template")).get("mappings")), "")
    return findings


def build_stream(
    name: str,
    stream_type: str,
    dataset: str,
    index_mode: str | None,
    field_files: list[Path],
    manifest_findings: list[Finding],
) -> Stream:
    if index_mode == "time_series":
        return Stream(name, stream_type, dataset, index_mode, "TSDB (index_mode: time_series)")
    if stream_type == "metrics":
        return Stream(name, stream_type, dataset, index_mode, "metrics (not TSDB; not a logging workload)")
    if stream_type != "logs":
        return Stream(name, stream_type, dataset, index_mode, f"type: {stream_type} (not a logs data stream)")
    findings, declared = scan_fields(field_files)
    return Stream(
        name,
        stream_type,
        dataset,
        index_mode,
        findings=manifest_findings + findings,
        declared_fields=declared,
    )


def load_data_stream(package_name: str, stream_dir: Path) -> Stream:
    manifest_path = stream_dir / "manifest.yml"
    manifest = as_line_dict(load_yaml(manifest_path))
    elasticsearch = as_line_dict(manifest.get("elasticsearch"))
    return build_stream(
        stream_dir.name,
        manifest.get("type") or "logs",
        manifest.get("dataset") or f"{package_name}.{stream_dir.name}",
        elasticsearch.get("index_mode"),
        field_yaml_files(stream_dir),
        scan_manifest_mappings(elasticsearch, manifest_path),
    )


def load_input_streams(package_root: Path, manifest: LineDict) -> list[Stream]:
    """One stream per policy template.

    The dataset is the template's `data_stream.dataset` var default, else Fleet's `<package>.<template>`.
    """
    elasticsearch = as_line_dict(manifest.get("elasticsearch"))
    manifest_findings = scan_manifest_mappings(elasticsearch, package_root / "manifest.yml")
    streams: list[Stream] = []
    for template in manifest.get("policy_templates") or []:
        template = as_line_dict(template)
        if not template.get("name"):
            continue
        name = str(template["name"])
        stream_type = template.get("type") or "logs"
        dataset = next(
            (
                str(var["default"])
                for var in template.get("vars") or []
                if isinstance(var, dict) and var.get("name") == "data_stream.dataset" and var.get("default")
            ),
            f"{package_root.name}.{name}",
        )
        if template.get("input") == "otelcol":
            streams.append(Stream(name, stream_type, dataset, skip_reason="OTel input — the stack OTel template owns storage"))
            continue
        stream = build_stream(
            name,
            stream_type,
            dataset,
            elasticsearch.get("index_mode"),
            field_yaml_files(package_root),
            list(manifest_findings),
        )
        if stream.in_scope:
            stream.notes.append("input package: users can override `data_stream.dataset`; the default is shown")
        streams.append(stream)
    return streams


def load_package(package_root: Path) -> Package:
    package_root = package_root.resolve()
    manifest = as_line_dict(load_yaml(package_root / "manifest.yml"))
    kibana_version = as_line_dict(as_line_dict(manifest.get("conditions")).get("kibana")).get("version")
    pkg = Package(
        path=package_root,
        name=package_root.name,
        type=manifest.get("type"),
        format_version=str(manifest["format_version"]) if manifest.get("format_version") else None,
        kibana_constraint=str(kibana_version) if kibana_version else None,
    )
    if pkg.type == "content":
        pkg.skip_reason = "content package — no data-stream mappings here"
        return pkg
    if pkg.type not in {None, "integration", "input"}:
        pkg.skip_reason = f"package type {pkg.type!r} out of scope"
        return pkg

    if pkg.type == "input":
        pkg.streams.extend(load_input_streams(package_root, manifest))
    streams_root = package_root / "data_stream"
    if streams_root.is_dir():
        for stream_dir in sorted(p for p in streams_root.iterdir() if p.is_dir()):
            pkg.streams.append(load_data_stream(pkg.name, stream_dir))
    if not pkg.streams:
        pkg.skip_reason = "no data streams or policy templates found"

    for template in manifest.get("policy_templates") or []:
        template = as_line_dict(template)
        if template.get("name"):
            enabled = template.get("data_streams")
            pkg.policy_template_streams[str(template["name"])] = (
                [str(s) for s in enabled] if isinstance(enabled, list) else []
            )
    transform_root = package_root / "elasticsearch" / "transform"
    if transform_root.is_dir():
        pkg.transforms = sum(1 for p in transform_root.iterdir() if p.is_dir())
    return pkg


def iter_package_roots(path: Path) -> list[Path]:
    path = path.resolve()
    if path.name == "packages" and path.is_dir():
        return sorted(p for p in path.iterdir() if p.is_dir() and (p / "manifest.yml").is_file())
    if (path / "manifest.yml").is_file():
        return [path]
    if (path / "packages").is_dir():
        return iter_package_roots(path / "packages")
    raise FileNotFoundError(f"not a package or packages/ directory: {path}")


def spec_minor(version: str | None) -> tuple[int, int] | None:
    try:
        major, minor = (version or "").split(".")[:2]
        return int(major), int(minor)
    except ValueError:
        return None


def spec_min_stack(version: str | None) -> str:
    """Minimum stack that can install this format_version. Patch is ignored."""
    parsed = spec_minor(version)
    if parsed is None:
        return "unknown"
    if parsed < (3, 0):
        return "any stateful stack" if parsed >= (2, 3) else "stacks before 9.0"
    return SPEC_MIN_STACK.get(parsed, "above 9.4")


def kibana_allows_8x(constraint: str | None) -> bool:
    """True when any `||` alternative of `conditions.kibana.version` starts below 9.0."""
    if not constraint:
        return True
    for alternative in constraint.split("||"):
        match = re.search(r"(\d+)\.", alternative)
        if match and int(match.group(1)) <= 8:
            return True
    return False


def installs_on_8x(version: str | None, kibana_constraint: str | None = None) -> bool:
    parsed = spec_minor(version)
    return parsed is not None and parsed <= (3, 4) and kibana_allows_8x(kibana_constraint)


def index_patterns_from_query(query: str) -> list[str]:
    """Index patterns of every ES|QL `FROM` in the query."""
    patterns: list[str] = []
    for match in FROM_CLAUSE_RE.finditer(ESQL_LINE_COMMENT_RE.sub("", query)):
        for part in match.group(1).split(","):
            token = part.strip().strip("`\"'")
            if token and not token.startswith("("):
                token = token.split()[0].strip("`\"'")
                if token and token not in patterns:
                    patterns.append(token)
    return patterns


def normalize_pattern(pattern: str) -> str | None:
    """Lowercased local data stream pattern, or None for exclusions and other indices."""
    body = pattern.strip().strip("`\"'").lower().rsplit(":", 1)[-1]
    if not body or body.startswith("-") or not body.startswith(INDEX_TYPE_PREFIXES):
        return None
    return body


def is_broad_pattern(pattern: str) -> bool:
    """`logs-*` names no dataset, so it cannot attribute a query to one integration."""
    body = normalize_pattern(pattern)
    return body is not None and body.split("-", 1)[1].startswith("*")


def pattern_streams(pattern: str, pkg: Package) -> list[str]:
    """Streams whose `<type>-<dataset>-<namespace>` the pattern matches.

    `logs-gcp.audit-*` matches stream `audit`; `logs-gcp*` matches every gcp logs stream.
    `packetbeat-*` and `logs-*` match none.
    """
    body = normalize_pattern(pattern)
    if body is None or is_broad_pattern(pattern):
        return []
    return [
        s.name
        for s in pkg.streams
        if fnmatch.fnmatchcase(f"{s.type}-{s.dataset.lower()}-default", body)
    ]


def names_dataset(text: str, dataset: str) -> bool:
    """True when `text` names the dataset, including as a field prefix (`gcp.audit.method_name`)."""
    return re.search(rf"(?<![\w.]){re.escape(dataset.lower())}(?!\w)", text.lower()) is not None


@dataclass
class Rule:
    """Latest version of a prebuilt rule from `security_detection_engine`."""

    name: str
    language: str
    index_patterns: list[str]
    fields: list[str]
    related_integrations: list[tuple[str, str | None]]  # (package, policy template)
    query: str
    path: Path


def load_prebuilt_rules(sde_root: Path) -> list[Rule]:
    latest: dict[str, tuple[int, Path]] = {}
    for path in (sde_root / "kibana" / "security_rule").glob("*.json"):
        match = RULE_FILE_RE.match(path.name)
        if match and int(match["version"]) > latest.get(match["rule_id"], (-1, path))[0]:
            latest[match["rule_id"]] = (int(match["version"]), path)

    rules: list[Rule] = []
    for rule_id, (_, path) in sorted(latest.items()):
        try:
            attrs = json.loads(path.read_text(errors="replace")).get("attributes") or {}
        except (OSError, json.JSONDecodeError):
            continue
        query = attrs.get("query") or ""
        language = attrs.get("language") or attrs.get("type") or "unknown"
        patterns = [str(p) for p in attrs.get("index") or []]
        if not patterns and language == "esql":
            patterns = index_patterns_from_query(query)
        rules.append(
            Rule(
                name=attrs.get("name") or rule_id,
                language=language,
                index_patterns=patterns,
                fields=[f["name"] for f in attrs.get("required_fields") or [] if isinstance(f, dict) and f.get("name")],
                related_integrations=[
                    (r["package"], r.get("integration"))
                    for r in attrs.get("related_integrations") or []
                    if isinstance(r, dict) and r.get("package")
                ],
                query=query,
                path=path,
            ),
        )
    return rules


def rule_streams(rule: Rule, pkg: Package) -> list[str]:
    """In-scope streams a rule queries.

    Matches index patterns first. A rule on `logs-*` counts only when its
    `related_integrations` names the package. A package-wide match (`logs-aws*`)
    is narrowed to datasets the query names, then to the rule's policy templates.
    """
    in_scope = {s.name: s for s in pkg.in_scope_streams}
    matched = list(dict.fromkeys(n for p in rule.index_patterns for n in pattern_streams(p, pkg) if n in in_scope))
    templates = [t for p, t in rule.related_integrations if p == pkg.name]
    if not matched and templates and any(is_broad_pattern(p) for p in rule.index_patterns):
        matched = [n for n, s in in_scope.items() if s.type == "logs"]
    if len(matched) <= 1:
        return matched

    by_dataset = [n for n in matched if names_dataset(rule.query, in_scope[n].dataset)]
    if by_dataset:
        return by_dataset
    template_streams = {s for t in templates if t for s in pkg.policy_template_streams.get(t) or [t]}
    return [n for n in matched if n in template_streams] or matched


QUERY_TEMPLATE_KINDS = ("alerting_rule_template", "slo_template")


@dataclass
class QueryTemplate:
    """An alerting rule or SLO template shipped by the package."""

    kind: str  # alerting_rule_template | slo_template
    name: str
    index_patterns: list[str]
    query: str
    path: Path


def load_query_templates(pkg: Package) -> list[QueryTemplate]:
    templates: list[QueryTemplate] = []
    for kind in QUERY_TEMPLATE_KINDS:
        for path in sorted((pkg.path / "kibana" / kind).glob("*.json")):
            try:
                attrs = json.loads(path.read_text(errors="replace")).get("attributes") or {}
            except (OSError, json.JSONDecodeError, AttributeError):
                continue
            if kind == "slo_template":
                params = (attrs.get("indicator") or {}).get("params") or {}
            else:
                params = attrs.get("params") or {}
            esql = (params.get("esqlQuery") or {}).get("esql") if isinstance(params.get("esqlQuery"), dict) else None
            if esql:
                patterns = index_patterns_from_query(esql)
            else:
                index = params.get("index")
                patterns = [str(p) for p in index] if isinstance(index, list) else [str(index)] if index else []
                patterns = [p for part in patterns for p in part.split(",")]
            templates.append(
                QueryTemplate(kind, attrs.get("name") or path.stem, patterns, esql or json.dumps(params), path),
            )
    return templates


def template_streams(template: QueryTemplate, pkg: Package) -> list[str]:
    """In-scope streams a package-owned alerting rule or SLO template queries.

    A broad pattern (`logs-*`) counts only for the datasets the query or filter names.
    """
    in_scope = {s.name: s for s in pkg.in_scope_streams}
    matched = list(
        dict.fromkeys(n for p in template.index_patterns for n in pattern_streams(p, pkg) if n in in_scope),
    )
    broad = not matched and any(is_broad_pattern(p) for p in template.index_patterns)
    candidates = list(in_scope) if broad else matched
    named = [n for n in candidates if names_dataset(template.query, in_scope[n].dataset)]
    if broad or (len(matched) > 1 and named):
        return named
    return matched


def sde_root(package_roots: list[Path]) -> Path | None:
    if not package_roots:
        return None
    candidate = package_roots[0].parent / "security_detection_engine"
    return candidate if candidate.is_dir() else None
