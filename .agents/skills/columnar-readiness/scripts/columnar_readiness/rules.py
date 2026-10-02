"""Index patterns and the prebuilt detection rules that query a stream."""

from __future__ import annotations

import fnmatch
import json
import os
import re
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from .common import finding
from .constants import LOOKUP_RISK_FIELDS, LOOKUP_RISK_PREFIXES
from .consumers import source_access_hits
from .ecs import ecs_schema
from .sorting import is_low_cardinality, resolved_type


def strip_cluster(pattern: str) -> str:
    """`remote:logs-*` -> `logs-*` (cross-cluster search prefix)."""
    pattern = pattern.strip().strip("\"'")
    return pattern.split(":", 1)[1] if ":" in pattern else pattern


def index_pattern_matches(pattern: str, index_name: str) -> bool:
    """Whether an index pattern from a rule or a transform covers `index_name`.

    Exclusions (`-logs-foo-*`) never match; everything else is a shell glob, which is
    what Elasticsearch index patterns are.
    """
    pattern = strip_cluster(pattern)
    if not pattern or pattern.startswith("-"):
        return False
    return fnmatch.fnmatchcase(index_name, pattern)


def stream_index_name(ds_type: str, pkg_name: str, ds_name: str,
                      manifest: Dict[str, Any]) -> str:
    """A concrete index name for the stream, for matching patterns against."""
    dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), str) else None
    return f"{ds_type}-{dataset or f'{pkg_name}.{ds_name}'}-default"


# --------------------------------------------------------------------------- #
# Detection rules shipped in this repo (packages/security_detection_engine)
# --------------------------------------------------------------------------- #

# Prebuilt detection rules are generated from `elastic/detection-rules` and ship to
# users inside the `security_detection_engine` package, one saved object per rule
# version (`kibana/security_rule/<rule_id>_<version>.json`). That package is a sibling
# of every other package in this repo, so the rules that query a data stream can be
# read directly. Rules a user writes, or installs from elsewhere, are not covered.
RULES_PACKAGE = "security_detection_engine"
RULES_SUBDIR = os.path.join("kibana", "security_rule")

# `FROM a, b METADATA _source | ...` (or `TS a`), optionally after `SET ...;`
# directives, and each subquery source of `FROM (FROM a | ...), (FROM b | ...)`.
_ESQL_FROM_RE = re.compile(
    r"(?is)(?:^\s*(?:set\b[^;]*;\s*)*|\(\s*)(?:from|ts)\s+([^|()]+?)(?=\s+metadata\b|\||\)|$)")
# A double-quoted string (kept) or a `//` / `/* */` comment (dropped), so comments go
# without touching a `"http://…"` literal.
_ESQL_STRING_OR_COMMENT_RE = re.compile(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/', re.S)
_JSON_EXTRACT_PATH_RE = re.compile(r'(?i)json_extract\s*\(\s*_source\s*,\s*"([^"]+)"')
# Dotted identifiers in a query text. Only names that resolve to a field of the stream
# are kept, so values that happen to contain dots (`"cmd.exe"`) drop out.
_QUERY_FIELD_RE = re.compile(r"(?<![\w.@$'\"])([A-Za-z_@][\w@]*(?:\.[\w@]+)+)")

_RULES_CACHE: Dict[str, Dict[str, Any]] = {}


def default_rules_dir(pkg_dir: str) -> Optional[str]:
    """`packages/security_detection_engine/kibana/security_rule` next to `pkg_dir`."""
    candidate = os.path.join(os.path.dirname(os.path.abspath(pkg_dir)),
                             RULES_PACKAGE, RULES_SUBDIR)
    return candidate if os.path.isdir(candidate) else None


def esql_from_patterns(query: str) -> List[str]:
    """Index patterns of an ES|QL query's source command (`FROM a, b METADATA …`).

    Comments are dropped first: a `// note` between `FROM logs-x-*` and the first pipe
    used to become part of the last pattern, so the rule matched nothing. The list may
    span several lines, and subqueries (`FROM (FROM a | …), (FROM b | …)`) count too.
    """
    text = _ESQL_STRING_OR_COMMENT_RE.sub(
        lambda m: m.group(0) if m.group(0).startswith('"') else " ", query)
    names: List[str] = []
    for match in _ESQL_FROM_RE.finditer(text):
        for part in match.group(1).split(","):
            name = part.strip().strip("`\"'")
            if name and name not in names:
                names.append(name)
    return names


def load_detection_rules(rules_dir: Optional[str]) -> Dict[str, Any]:
    """The latest version of every shipped rule, plus a pattern -> rules index.

    Read once per run and cached: the catalog run matches every logs stream against
    the same ~2,200 rules, so matching goes through the few hundred distinct index
    patterns rather than rule by rule.
    """
    empty: Dict[str, Any] = {"dir": rules_dir, "rules": [], "by_pattern": {}}
    if not rules_dir or not os.path.isdir(rules_dir):
        return empty
    if rules_dir in _RULES_CACHE:
        return _RULES_CACHE[rules_dir]

    latest: Dict[str, Tuple[int, Dict[str, Any]]] = {}
    for fname in os.listdir(rules_dir):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(rules_dir, fname), encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            continue
        attrs = doc.get("attributes", doc) if isinstance(doc, dict) else None
        if not isinstance(attrs, dict) or not attrs.get("rule_id") or not attrs.get("type"):
            continue
        try:
            version = int(attrs.get("version") or 0)
        except (TypeError, ValueError):
            version = 0
        rule_id = str(attrs["rule_id"])
        if rule_id not in latest or version > latest[rule_id][0]:
            latest[rule_id] = (version, attrs)

    rules: List[Dict[str, Any]] = []
    for _, attrs in sorted(latest.values(), key=lambda v: str(v[1].get("name"))):
        query = attrs.get("query") if isinstance(attrs.get("query"), str) else ""
        language = attrs.get("language") or attrs.get("type")
        patterns = [p for p in (attrs.get("index") or []) if isinstance(p, str)]
        if language == "esql" or attrs.get("type") == "esql":
            patterns = esql_from_patterns(query) or patterns
        # Indicator match rules also read the threat intel indices they match against.
        patterns += [p for p in (attrs.get("threat_index") or []) if isinstance(p, str)]
        rules.append({
            "name": attrs.get("name") or attrs["rule_id"],
            "rule_id": attrs["rule_id"],
            "language": language,
            "patterns": patterns,
            "query": query,
            # (package, policy template) pairs from `related_integrations`.
            "related": [(str(r["package"]), r.get("integration"))
                        for r in (attrs.get("related_integrations") or [])
                        if isinstance(r, dict) and r.get("package")],
            "source_hits": source_access_hits(query),
            "extract_paths": sorted(set(_JSON_EXTRACT_PATH_RE.findall(query))),
        })

    by_pattern: Dict[str, List[int]] = {}
    for idx, rule in enumerate(rules):
        for pattern in rule["patterns"]:
            by_pattern.setdefault(pattern, []).append(idx)
    result = {"dir": rules_dir, "rules": rules, "by_pattern": by_pattern}
    _RULES_CACHE[rules_dir] = result
    return result


def names_dataset(text: str, dataset: str) -> bool:
    """True when `text` names the dataset, also as a field prefix (`gcp.audit.method_name`)."""
    return re.search(rf"(?<![\w.]){re.escape(dataset.lower())}(?!\w)", text.lower()) is not None


def attribute_rules(rule_set: Dict[str, Any], streams: List[Tuple[str, str, str, str]],
                    pkg_name: str, template_streams: Dict[str, List[str]]
                    ) -> Dict[str, Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]]:
    """data stream -> (rules about it, rules that only reach it), for one package.

    `streams` holds (name, type, dataset, index name) for the package's logs streams.
    A rule whose patterns match one of them is about this package when
    `related_integrations` names the package, or when a pattern starts with
    `<type>-<package>` (`logs-aws*`, not `logs-*` or `logs-gcp*` for `gcp_vertexai`).
    Among the matched streams it is then about the ones its query names by dataset
    (`event.dataset: gcp.audit`, `gcp.audit.method_name`), else the streams of the
    policy templates `related_integrations` names, else all of them. Every other match
    still reads the stream, so it counts for the `_source` check, but not for the
    workload or the lookup candidates.
    """
    rules = rule_set.get("rules") or []
    by_pattern = rule_set.get("by_pattern") or {}
    datasets = {name: dataset for name, _, dataset, _ in streams}
    matched: Dict[int, List[str]] = {}
    for name, _, _, index_name in streams:
        for pattern, idxs in by_pattern.items():
            if index_pattern_matches(pattern, index_name):
                for idx in idxs:
                    names = matched.setdefault(idx, [])
                    if name not in names:
                        names.append(name)

    about: Dict[int, set] = {}
    for idx, names in matched.items():
        rule = rules[idx]
        named = any(p == pkg_name for p, _ in rule["related"])
        templates = [t for p, t in rule["related"] if p == pkg_name and t]
        ds_type = next(t for n, t, _, _ in streams if n == names[0])
        prefix = f"{ds_type}-{pkg_name}"
        if not named and not any(strip_cluster(pt).startswith(prefix) for pt in rule["patterns"]):
            about[idx] = set()
            continue
        if len(names) == 1:
            about[idx] = set(names)
            continue
        by_dataset = {n for n in names if names_dataset(rule["query"], datasets[n])}
        via_templates = {ds for t in templates for ds in (template_streams.get(t) or [t])}
        about[idx] = by_dataset or (via_templates & set(names)) or set(names)

    out: Dict[str, Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]] = {
        name: ([], []) for name, _, _, _ in streams}
    for idx in sorted(matched):
        for name in matched[idx]:
            out[name][0 if name in about[idx] else 1].append(rules[idx])
    return out


def _source_reader_finding(subject: str, reader: Dict[str, Any], where: str) -> Dict[str, Any]:
    """`source_consumer_detection_rule` for a rule or hunting query that reads `_source`."""
    detail = "; ".join(f"{label} — `{excerpt}`" for label, excerpt in reader["source_hits"][:2])
    paths = reader["extract_paths"]
    return finding(
            "source_consumer_detection_rule", "C", "review",
            f"{subject} reads this stream's `_source`: {detail}"
            + (f". `JSON_EXTRACT` paths: {', '.join(f'`{p}`' for p in paths[:6])}"
               f"{', …' if len(paths) > 6 else ''}" if paths else "")
            + ". Columnar returns `_source` with dotted top-level keys (`{\"a.b\": …}` rather "
              "than `{\"a\": {\"b\": …}}`), so a nested lookup such as "
              "`JSON_EXTRACT(_source, \"a.b\")` returns null and the rule stops matching, with "
              "no error.",
            "Hold this stream back from the tech preview until the query is fixed in "
            "`elastic/detection-rules`. Fixes that work on both `_source` shapes: reference the "
            "mapped fields as columns instead of `_source` (`COALESCE(network_traffic.sip.method, "
            "sip.method)` where the index patterns name the field differently, `TO_STRING` where "
            "they disagree on a type). A value inside a `flattened` field is not a column; read it "
            "with `FIELD_EXTRACT(<flattened field>, \"<sub.key>\")`, e.g. "
            "`FIELD_EXTRACT(gcp.audit.request, \"spec.request\")` (an ES|QL tech-preview "
            "function: check the rule's target stacks have it). A field mapped on some of the "
            "queried indices already returns null on the others; `SET unmapped_fields = "
            "\"nullify\";` is only needed when it is mapped on none. `SET unmapped_fields = "
            "\"load\"` is not a fix: it reads `_source`, which is what columnar changes, and "
            "cannot reach `flattened` subfields. No `JSON_EXTRACT` path matches both shapes "
            "(elasticsearch#160300 asks for one).",
            where)


def detection_rule_findings(specific: List[Dict[str, Any]],
                            broad: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """`source_consumer_detection_rule`: shipped rules that read this stream's `_source`."""
    return [
        _source_reader_finding(
            f"The shipped detection rule \"{rule['name']}\" ({rule['language']})", rule,
            f"packages/{RULES_PACKAGE}/{RULES_SUBDIR.replace(os.sep, '/')}/"
            f"{rule['rule_id']}_<version>.json")
        for rule in specific + broad if rule["source_hits"]]


# --------------------------------------------------------------------------- #
# Alerting rule and SLO templates the package ships
# --------------------------------------------------------------------------- #

QUERY_TEMPLATE_KINDS = ("alerting_rule_template", "slo_template")


def load_query_templates(pkg_dir: str) -> List[Dict[str, Any]]:
    """The package's alerting rule and SLO templates, with the index patterns they query.

    Alerting rule templates are ES|QL (`params.esqlQuery.esql`); SLO templates name an
    index and a KQL filter (`indicator.params.index`, `.filter`).
    """
    out: List[Dict[str, Any]] = []
    for kind in QUERY_TEMPLATE_KINDS:
        root = os.path.join(pkg_dir, "kibana", kind)
        if not os.path.isdir(root):
            continue
        for fname in sorted(f for f in os.listdir(root) if f.endswith(".json")):
            try:
                with open(os.path.join(root, fname), encoding="utf-8") as fh:
                    attrs = (json.load(fh) or {}).get("attributes") or {}
            except (OSError, ValueError, AttributeError):
                continue
            params = ((attrs.get("indicator") or {}).get("params") if kind == "slo_template"
                      else attrs.get("params")) or {}
            esql = (params.get("esqlQuery") or {}).get("esql") if isinstance(
                params.get("esqlQuery"), dict) else None
            if isinstance(esql, str):
                patterns, text = esql_from_patterns(esql), esql
            else:
                index = params.get("index")
                parts = index if isinstance(index, list) else [index] if index else []
                patterns = [p.strip() for part in parts for p in str(part).split(",") if p.strip()]
                text = json.dumps(params)
            out.append({"kind": kind, "name": attrs.get("name") or fname[:-5],
                        "file": f"kibana/{kind}/{fname}", "patterns": patterns, "query": text})
    return out


def attribute_templates(templates: List[Dict[str, Any]],
                        streams: List[Tuple[str, str, str, str]],
                        pkg_name: str) -> Dict[str, List[Dict[str, Any]]]:
    """data stream -> the package's templates that query it.

    A template on a broad pattern (`logs-*`) counts for the streams its query or filter
    names by dataset (`data_stream.dataset: "nginx.access"`); one on the package's own
    patterns counts for the named streams too, or for all it matches when it names none.
    """
    datasets = {name: dataset for name, _, dataset, _ in streams}
    out: Dict[str, List[Dict[str, Any]]] = {name: [] for name, _, _, _ in streams}
    for template in templates:
        matched = [name for name, _, _, index_name in streams
                   if any(index_pattern_matches(p, index_name) for p in template["patterns"])]
        if not matched:
            continue
        own = any(strip_cluster(p).startswith(f"{t}-{pkg_name}")
                  for p in template["patterns"] for _, t, _, _ in streams[:1])
        named = [n for n in matched if names_dataset(template["query"], datasets[n])]
        for name in (named or (matched if own else [])):
            out[name].append(template)
    return out


# --------------------------------------------------------------------------- #
# elastic/detection-rules checkout (hunting queries, unreleased rules)
# --------------------------------------------------------------------------- #

# Hunting queries live only in `elastic/detection-rules` (`hunting/`), not in any
# package, and `rules/` can hold rules the prebuilt snapshot doesn't ship yet. Both are
# scanned when a checkout is at hand, for `_source` readers only: they are run by hand
# or not shipped, so they don't count toward the performance workload. A rule that is
# also in the snapshot is reported once, from the snapshot.
DETECTION_RULES_ENV = "DETECTION_RULES_PATH"
_TOML_QUERY_RE = re.compile(
    r"""^query\s*=\s*(\[.*?^\]|'''.*?'''|\"\"\".*?\"\"\"|"(?:\\.|[^"\\\n])*")""", re.S | re.M)
_TOML_STRING_RE = re.compile(
    r"""'''(.*?)'''|\"\"\"(.*?)\"\"\"|"((?:\\.|[^"\\\n])*)"|'([^'\n]*)'""", re.S)
_TOML_NAME_RE = re.compile(r"""^name\s*=\s*(?:"((?:\\.|[^"\\\n])*)"|'([^'\n]*)')""", re.M)
_REPO_CACHE: Dict[str, Dict[str, Any]] = {}


def find_detection_rules_repo(explicit: Optional[str], packages_root: str
                              ) -> Tuple[Optional[str], List[str]]:
    """(checkout to scan or None, the places looked at): `--detection-rules`, then
    `$DETECTION_RULES_PATH`, then a `detection-rules` checkout next to this repo."""
    root = os.path.abspath(packages_root)
    candidates = [c for c in (explicit, os.environ.get(DETECTION_RULES_ENV),
                              os.path.join(os.path.dirname(os.path.dirname(root)),
                                           "detection-rules")) if c]
    for candidate in candidates:
        if os.path.isdir(os.path.join(candidate, "rules")):
            return os.path.abspath(candidate), candidates
    return None, candidates


def _toml_string(raw: str) -> str:
    try:
        return json.loads(f'"{raw}"')
    except ValueError:
        return raw


def _toml_queries(text: str) -> List[str]:
    """The query (rules) or queries (hunting) of a detection-rules TOML file."""
    match = _TOML_QUERY_RE.search(text)
    if not match:
        return []
    out: List[str] = []
    for literal3, basic3, basic, literal in _TOML_STRING_RE.findall(match.group(1)):
        out.append(literal3 or basic3 or (_toml_string(basic) if basic else literal))
    return [q for q in out if q.strip()]


def load_detection_rules_repo(repo: Optional[str]) -> Dict[str, Any]:
    """The ES|QL rules and hunting queries of a detection-rules checkout that read `_source`."""
    if not repo:
        return {"dir": None, "files": 0, "readers": []}
    if repo in _REPO_CACHE:
        return _REPO_CACHE[repo]
    readers: List[Dict[str, Any]] = []
    files = 0
    for sub in ("rules", "hunting"):
        for dirpath, dirnames, filenames in os.walk(os.path.join(repo, sub)):
            dirnames[:] = sorted(d for d in dirnames if not d.startswith((".", "_")))
            for fname in sorted(f for f in filenames if f.endswith(".toml")):
                files += 1
                path = os.path.join(dirpath, fname)
                try:
                    with open(path, encoding="utf-8") as fh:
                        text = fh.read()
                except OSError:
                    continue
                if "_source" not in text:
                    continue
                name_match = _TOML_NAME_RE.search(text)
                name = (_toml_string(name_match.group(1)) if name_match and name_match.group(1)
                        else name_match.group(2) if name_match else os.path.splitext(fname)[0])
                for query in _toml_queries(text):
                    hits = source_access_hits(query)
                    patterns = esql_from_patterns(query)
                    if hits and patterns:
                        readers.append({
                            "name": name,
                            "kind": "hunting query" if sub == "hunting" else "rule",
                            "file": os.path.relpath(path, repo).replace(os.sep, "/"),
                            "patterns": patterns,
                            "source_hits": hits,
                            "extract_paths": sorted(set(_JSON_EXTRACT_PATH_RE.findall(query))),
                        })
    result = {"dir": repo, "files": files, "readers": readers}
    _REPO_CACHE[repo] = result
    return result


def repo_readers_for(index_name: str, repo: Dict[str, Any],
                     already: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The detection-rules readers whose patterns match this stream, minus the rules
    `already` reported from the prebuilt snapshot (same name)."""
    seen = {r["name"].strip().lower() for r in already}
    out: List[Dict[str, Any]] = []
    for reader in repo.get("readers") or []:
        key = reader["name"].strip().lower()
        if key in seen or not any(index_pattern_matches(p, index_name) for p in reader["patterns"]):
            continue
        seen.add(key)
        out.append(reader)
    return out


def repo_reader_findings(readers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """`source_consumer_detection_rule` for detection-rules readers (`repo_readers_for`)."""
    return [_source_reader_finding(
        f"The `elastic/detection-rules` {r['kind']} \"{r['name']}\" (`{r['file']}`)",
        r, f"elastic/detection-rules/{r['file']}") for r in readers]


def rule_workload(specific: List[Dict[str, Any]], broad: List[Dict[str, Any]],
                  scanned: bool) -> Dict[str, Any]:
    """The rule half of the performance workload for one stream."""
    return {
        "scanned": scanned,
        "specific": len(specific),
        "broad": len(broad),
        "by_language": dict(sorted(Counter(r["language"] for r in specific).items())),
        "reading_source": [r["name"] for r in specific + broad if r["source_hits"]],
        "names": [r["name"] for r in specific][:25],
    }


def lookup_candidates(specific: List[Dict[str, Any]], filter_fields: Counter,
                      field_index: Dict[str, Dict[str, Any]], sort_fields: List[str],
                      limit: int = 10) -> List[Dict[str, Any]]:
    """Fields the stream's rules and dashboards filter on, for the `index: true` review.

    Columnar drops the inverted index of every non-`text` field, so an exact-value
    filter on a field outside the sort key becomes a doc-value scan. This lists the
    `keyword`/`ip` fields the shipped rules (and, when scanned, the dashboard filters)
    reference, most referenced first, with the plan's high-risk lookup fields flagged.
    It is a starting point for a human decision, never a recommendation: "none" is a
    valid answer, and a field in the sort key needs no index.
    """
    rule_refs: Counter = Counter()
    for rule in specific:
        for name in set(_QUERY_FIELD_RE.findall(rule["query"])):
            rule_refs[name] += 1
    names = set(rule_refs) | set(filter_fields or {})
    schema = ecs_schema()
    out: List[Dict[str, Any]] = []
    for name in names:
        if name in sort_fields or name.startswith(("data_stream.", "@")):
            continue
        fdef = field_index.get(name)
        ftype = resolved_type(fdef, name) if fdef else (schema.get(name) or {}).get("type")
        high_risk = name in LOOKUP_RISK_FIELDS or name.startswith(LOOKUP_RISK_PREFIXES)
        if ftype not in ("keyword", "ip") and not (ftype is None and high_risk):
            continue
        # Enum-like fields (`event.type`, `host.os.type`, `http.request.method`) are
        # grouping dimensions that aggregations read from doc values anyway; the plan
        # keeps them doc-values-only, so they are not lookup candidates.
        if not high_risk and is_low_cardinality(name):
            continue
        if fdef is None and name not in schema:
            continue  # not a field of this stream as far as the audit can tell
        out.append({
            "field": name,
            "type": ftype,
            "rules": rule_refs.get(name, 0),
            "dashboard_filters": (filter_fields or {}).get(name, 0),
            "high_risk": high_risk,
        })
    out.sort(key=lambda c: (not c["high_risk"], -c["rules"], -c["dashboard_filters"], c["field"]))
    return out[:limit]
