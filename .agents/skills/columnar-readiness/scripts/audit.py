#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["pyyaml>=6"]
# ///
"""Columnar-readiness audit of one integration package: what the package-spec validator
cannot see.

`elastic-package check` (package-spec >= 3.8.0) reports the mappings and index sort
settings Elasticsearch rejects in `logsdb_columnar`. This script covers the rest, per logs
data stream: scope and effective readiness (Fleet needs every logs stream ready),
`doc_values: false` and `store: true` before readiness is declared (the validator reports
them once it is), `_source` consumers, objects inside `nested` fields, the index sort
proposal, the detection rules and dashboards to benchmark, and the lookup candidates for
`index: true`. See references/columnar.md.

    python3 <skill-dir>/scripts/audit.py packages/<pkg> [--format markdown|json|both]
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from collections import Counter

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: `uv run <skill-dir>/scripts/audit.py <package>`, "
             "or `python3 -m pip install --user pyyaml`.")

LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
STATUS_ORDER = ["OUT_OF_SCOPE", "READY", "NEEDS_REVIEW", "BLOCKED"]
RULES_SUBDIR = os.path.join("security_detection_engine", "kibana", "security_rule")
ECS_CACHE = os.path.expanduser("~/.elastic-package/cache/fields/ecs")


def words(text):
    return set(text.split())


# Index sort vocabulary (references/columnar.md, "Index sort").
HOST_INPUTS = words(
    "logfile filestream log journald winlog unix system/metrics docker containerd "
    "filestream-container event/file etw audit/auditd audit/file_integrity audit/system "
    "auditd-logfile system/auth unifiedlogs osquery packet cloud_defend/control "
    "kubernetes/container_logs")
RECEIVER_INPUTS = words("tcp udp syslog")
COLLECTOR_INPUTS = words(
    "httpjson cel aws-s3 aws-cloudwatch gcp-pubsub gcs azure-eventhub azure-blob-storage "
    "o365audit entity-analytics salesforce http_endpoint streaming websocket lumberjack cometd "
    "netflow azure-monitor benchmark cloudfoundry kafka redis mqtt okta "
    "cloudbeat/asset_inventory_aws cloudbeat/asset_inventory_azure cloudbeat/asset_inventory_gcp "
    "cloudbeat/cis_aws cloudbeat/cis_azure cloudbeat/cis_eks cloudbeat/cis_gcp cloudbeat/cis_k8s "
    "cloudbeat/vuln_mgmt_aws")
# ECS fields only: a proposal on one the stream does not declare comes with its declaration.
RECEIVER_SORT_FIELDS = ["observer.name", "observer.hostname", "observer.serial_number"]
SORT_CANDIDATES = ["cloud.account.id", "organization.id", "cloud.project.id", "observer.name",
                   "observer.serial_number", "service.name", "cloud.instance.id",
                   "orchestrator.namespace", "agent.id"]
TENANT_LEAVES = ("tenantid tenant organizationid orgid accountid customerid subscriptionid "
                 "workspaceid projectid organization instanceid siteid").split()
SORTABLE_STRING, SORTABLE_NUMERIC = {"keyword", "ip"}, words("long integer short byte unsigned_long")
SORT_EXCLUDED = words(
    "@timestamp host.name data_stream.type data_stream.dataset data_stream.namespace "
    "event.dataset event.module event.kind input.type agent.type agent.version ecs.version "
    "message event.original error.message url.full url.original user_agent.original "
    "process.command_line file.path aws.s3.bucket.name aws.s3.object.key log.file.path "
    "log.offset azure.blob_storage.container gcs.storage.bucket.name")
ID_TOKENS = words("id uid identifier")
TENANT_TOKENS = words("account tenant organization organisation org customer project "
                      "subscription workspace site instance")
MEASUREMENT_TOKENS = words(
    "bytes byte bits kb mb gb count total sum avg mean min max seconds second sec ms millis "
    "duration time memory size length progress percent pct ratio rate value latency elapsed "
    "age score usage credits remaining")
HASH_TOKENS = words("hash uuid guid checksum fingerprint digest nonce md5 sha sha1 sha256 "
                    "sha384 sha512 ssdeep tlsh imphash")
FREE_TEXT_TOKENS = words(
    "message description summary comment note reason solution text title body detail "
    "details remediation recommendation command commandline query useragent synopsis")
PER_EVENT_ENTITIES = words(
    "alert event incident item message record request finding detection document doc log "
    "case ticket notification job task scan report trace span run execution invocation batch "
    "transaction upload download")
LOW_CARD_LEAVES = words(
    "severity priority level status state type action outcome category kind result verdict "
    "code reason provider direction evaluation decision disposition enabled flag class "
    "activity role mode protocol input stage phase tier family method health criticality "
    "classification version dataset operation whitelisted blacklisted")
LOW_CARD_EXACT, LOW_CARD_NAMES = words("op verb rc env"), words("name label title display displayname")
LOOKUP_RISK_FIELDS = words(
    "trace.id transaction.id span.id event.id error.id source.ip destination.ip client.ip "
    "server.ip user.name user.id url.path http.request.id host.id")
LOOKUP_RISK_PREFIXES = ("file.hash.", "process.hash.", "process.parent.hash.", "dll.hash.")
# ECS array fields, used when elastic-package's ECS cache is missing.
ECS_ARRAYS = words(
    "tags event.category event.type host.ip host.mac related.ip related.hash related.hosts "
    "related.user dns.answers dns.resolved_ip dns.header_flags process.args "
    "process.thread.capabilities.effective user.roles client.user.roles server.user.roles "
    "source.user.roles destination.user.roles email.to.address email.cc.address "
    "email.bcc.address email.from.address email.reply_to.address email.attachments "
    "container.image.tag threat.tactic.id threat.tactic.name threat.technique.id "
    "threat.technique.name vulnerability.category registry.data.strings rule.author")
# ECS fields with `doc_values: false`, used when elastic-package's ECS cache is missing.
ECS_NO_DOC_VALUES = words(
    "event.original gen_ai.agent.description x509.public_key_exponent "
    "file.x509.public_key_exponent tls.client.x509.public_key_exponent "
    "tls.server.x509.public_key_exponent threat.indicator.x509.public_key_exponent "
    "threat.indicator.file.x509.public_key_exponent "
    "threat.enrichments.indicator.x509.public_key_exponent "
    "threat.enrichments.indicator.file.x509.public_key_exponent")
# ECS types of the sort and lookup candidates (all single-valued, ECS 9.5), used when
# elastic-package's ECS cache is missing: sort proposals and lookup review need them.
ECS_FALLBACK_TYPES = {**dict.fromkeys(SORT_CANDIDATES + RECEIVER_SORT_FIELDS + ["host.name"], "keyword"),
                      **dict.fromkeys(LOOKUP_RISK_FIELDS, "keyword"), "url.path": "wildcard",
                      **dict.fromkeys(words("source.ip destination.ip client.ip server.ip"), "ip")}
TEMP_ROOTS = words("json _temp_ _temp _tmp _conf _ingest")


def read(path, parse, errors=None):
    try:
        with open(path, encoding="utf-8", errors=errors) as fh:
            return parse(fh)
    except Exception:
        return None


def loads(text):
    try:
        return json.loads(text)
    except ValueError:
        return None


def read_yaml(path):
    return read(path, lambda fh: yaml.load(fh, Loader=LOADER))


def read_json(path):
    return read(path, json.load)


def is_false(v):
    return v is False or (isinstance(v, str) and v.strip().lower() == "false")


def is_true(v):
    return v is True or (isinstance(v, str) and v.strip().lower() == "true")


def finding(code, severity, message, where, field=None):
    return {"code": code, "severity": severity, "message": message, "file": where, "field": field}


_ECS, _ECS_SOURCE = {}, []


def ecs():
    """flat name -> {type, array}, from elastic-package's ECS cache, else the fallback."""
    if not _ECS_SOURCE:
        found = os.listdir(ECS_CACHE) if os.path.isdir(ECS_CACHE) else []
        versions = sorted((d for d in found if os.path.isfile(os.path.join(ECS_CACHE, d, "ecs_nested.yml"))),
                          key=lambda n: tuple(int(p) for p in re.findall(r"\d+", n)) or (0,))
        doc = read_yaml(os.path.join(ECS_CACHE, versions[-1], "ecs_nested.yml")) if versions else None
        for group in doc.values() if isinstance(doc, dict) else []:
            for flat, fdef in (group.get("fields") or {}).items() if isinstance(group, dict) else []:
                if isinstance(fdef, dict):
                    _ECS[flat] = {"type": fdef.get("type"),
                                  "array": "array" in (fdef.get("normalize") or []),
                                  "doc_values": fdef.get("doc_values", True)}
        _ECS_SOURCE.append(f"ECS cache {versions[-1]}" if _ECS else "no ECS cache: built-in fallback")
        _ECS.update({} if _ECS else {f: {"type": ECS_FALLBACK_TYPES.get(f), "array": f in ECS_ARRAYS,
                                         "doc_values": f not in ECS_NO_DOC_VALUES}
                                     for f in ECS_ARRAYS | ECS_NO_DOC_VALUES | set(ECS_FALLBACK_TYPES)})
    return _ECS


# --- fields ----------------------------------------------------------------------------- #

def walk_fields(defs, prefix="", in_mf=False):
    for fdef in defs if isinstance(defs, list) else []:
        name = fdef.get("name") if isinstance(fdef, dict) else None
        flat = f"{prefix}.{name}" if prefix and name else (name or prefix)
        if isinstance(fdef, dict) and isinstance(flat, str):
            yield fdef, flat, in_mf
            yield from walk_fields(fdef.get("fields"), flat, in_mf)
            yield from walk_fields(fdef.get("multi_fields"), flat, True)


def read_fields(fields_dir, pkg_dir):
    """[(definition, flat name, in a multi-field, file, file name)] of a `fields/` dir."""
    out = []
    for fname in sorted(os.listdir(fields_dir)) if os.path.isdir(fields_dir) else []:
        if fname.endswith((".yml", ".yaml")):
            path = os.path.join(fields_dir, fname)
            for fdef, flat, in_mf in walk_fields(read_yaml(path)):
                out.append((fdef, flat, in_mf, os.path.relpath(path, pkg_dir), fname))
    return out


def resolved_type(fdef, name):
    if fdef.get("type"):
        return fdef["type"]
    return (ecs().get(name) or {}).get("type") if fdef.get("external") == "ecs" else None


def nested_object_children(entries):
    """Single-level `nested` fields whose elements hold objects (references: script findings)."""
    fields = [(flat, fdef.get("type"), rel) for fdef, flat, in_mf, rel, _ in entries if not in_mf]
    types = {flat: ftype for flat, ftype, _ in fields}
    nested = sorted(p for p, t in types.items() if t == "nested")
    out = []
    for path in (p for p in nested if not any(p.startswith(o + ".") for o in nested)):
        inner = [p for p in nested if p.startswith(path + ".")]
        objects = set()
        for flat in types:
            if flat.startswith(path + ".") and not any(flat == q or flat.startswith(q + ".") for q in inner):
                rel = flat[len(path) + 1:]
                head = rel.split(".", 1)[0]
                if types.get(f"{path}.{head}") != "flattened" and \
                        ("." in rel or types.get(flat) in ("group", "object")):
                    objects.add(head)
        if objects:
            out.append(finding(
                "nested_object_children", "review",
                f"`{path}` is `nested` and its elements hold objects ({', '.join(sorted(objects))}): "
                "columnar indexes an object sent as JSON inside an element apart from it.",
                next(rel for flat, _, rel in fields if flat == path), path))
    return out


def rejected_mappings(entries, itpl, ds_dir, pkg_dir):
    """`doc_values: false` and `store: true`, which Elasticsearch rejects in columnar modes:
    Fleet installs the mappings as they are. package-spec reports them only once the stream
    declares readiness, and only on the built package for ECS imports and `import_mappings`."""
    out = []
    for fdef, flat, in_mf, rel, _ in entries:
        # A multi-field is not rebuilt into `_source`, so it may keep `doc_values: false`.
        from_ecs = fdef.get("external") == "ecs" and "doc_values" not in fdef \
            and (ecs().get(flat) or {}).get("doc_values") is False
        if not in_mf and (is_false(fdef.get("doc_values")) or from_ecs):
            out.append(finding("doc_values_false", "blocker", f"`{flat}` has `doc_values: false`"
                               + (" from its ECS definition" if from_ecs else "")
                               + ": Elasticsearch rejects the mapping in columnar modes.", rel, flat))
        if is_true(fdef.get("store")):
            out.append(finding("store_true", "blocker", f"`{flat}` has `store: true`: Elasticsearch "
                               "rejects the mapping in columnar modes.", rel, flat))
    mappings = itpl.get("mappings") if isinstance(itpl.get("mappings"), dict) else {}
    rel = os.path.relpath(os.path.join(ds_dir, "manifest.yml"), pkg_dir)
    for tpl in mappings.get("dynamic_templates") or []:
        for name, body in tpl.items() if isinstance(tpl, dict) else []:
            mapping = body.get("mapping") if isinstance(body, dict) else None
            mapping = mapping if isinstance(mapping, dict) else {}
            subs = mapping.get("fields") if isinstance(mapping.get("fields"), dict) else {}
            if is_false(mapping.get("doc_values")):
                out.append(finding("doc_values_false", "blocker", f"Dynamic template `{name}` sets "
                                   "`doc_values: false`: in columnar modes, Elasticsearch rejects "
                                   "every event with a matching field.", rel, name))
            if any(is_true(m.get("store")) for m in [mapping, *subs.values()] if isinstance(m, dict)):
                out.append(finding("store_true", "blocker", f"Dynamic template `{name}` sets "
                                   "`store: true`: in columnar modes, Elasticsearch rejects every "
                                   "event with a matching field.", rel, name))
    build = read_yaml(os.path.join(pkg_dir, "_dev", "build", "build.yml"))
    deps = build.get("dependencies") if isinstance(build, dict) else None
    dep = deps.get("ecs") if isinstance(deps, dict) else None
    if isinstance(dep, dict) and is_true(dep.get("import_mappings")):
        out.append(finding("import_mappings", "blocker", "`import_mappings: true` adds ECS dynamic "
                           "templates with `doc_values: false` (`event.original`, "
                           "`*.x509.public_key_exponent`): in columnar modes, Elasticsearch rejects "
                           "every event with one of these fields the stream does not map itself.",
                           os.path.join("_dev", "build", "build.yml")))
    return out


# --- ingest pipelines: written fields and list-valued paths ----------------------------- #

PAINLESS_ARRAY_RES = [re.compile(r'\$\(\s*"([\w.@]+)"\s*,\s*\[\s*\]\s*\)\s*\.stream\(\)')] + [
    re.compile(r"ctx\.?\??\.?([\w.?@]+?)" + tail) for tail in
    (r"\s*\.stream\(\)", r"\s+instanceof\s+List", r"\s*=\s*new\s+ArrayList")] + [
    re.compile(r'for\s*\(\s*def\s+\w+\s*:\s*ctx\.?\??\.?([\w.?@]+?)\s*\)')]
PATTERN_RES = {"grok": re.compile(r'%\{[A-Z0-9_]+:([\w.@]+)(?::\w+)?\}'),
               "dissect": re.compile(r'%\{[+&?*]?([\w.@]+)[^}]*\}')}
NON_PRODUCING = words("remove drop fail pipeline grok dissect script enrich terminate reroute")
OBSERVER_RES = [re.compile(r"(?<!\w)observer\??\.\??(name|hostname|serial_number)\b"), re.compile(
    r"""\[\s*['"]observer['"]\s*\]\s*\[\s*['"](name|hostname|serial_number)['"]\s*\]""")]
# Painless writes are only trusted for these names (a mention is not proof of a write).
SCRIPT_TARGET_RES = [
    (n, re.compile(r"(?<!\w)" + r"\??\.\??".join(map(re.escape, n.split("."))) + r"\b"),
     re.compile(r"\s*".join(r"\[\s*['\"]%s['\"]\s*\]" % re.escape(p) for p in n.split("."))))
    for n in sorted(set(RECEIVER_SORT_FIELDS) | set(SORT_CANDIDATES) - {"agent.id"})]


class Pipelines:
    """What a data stream's ingest pipelines write (unconditionally or not) and iterate."""

    def __init__(self, ds_dir):
        self.arrays, self.array_tails, self.targets, self.unconditional = set(), set(), set(), set()
        pdir = os.path.join(ds_dir, "elasticsearch", "ingest_pipeline")
        texts = [read(os.path.join(pdir, f), lambda fh: fh.read(), "replace")
                 for f in (sorted(os.listdir(pdir)) if os.path.isdir(pdir) else [])
                 if f.endswith((".yml", ".yaml"))]
        for text in filter(None, texts):
            for regex in PAINLESS_ARRAY_RES:
                for m in regex.finditer(text):
                    self.add_array(m.group(1))
            try:
                doc = yaml.load(text, Loader=LOADER)
            except Exception:
                continue
            if isinstance(doc, dict):
                self.walk(doc.get("processors") or [], False)
                self.walk(doc.get("on_failure") or [], True)
        if not self.targets.intersection(RECEIVER_SORT_FIELDS):  # loose: a mention, targets only
            self.targets |= {"observer." + m.group(1) for text in filter(None, texts)
                             for r in OBSERVER_RES for m in r.finditer(text)}

    def add_array(self, raw):
        path = raw.replace("?", "").strip(".")
        if path:
            self.arrays.add(path)
            head, _, tail = path.partition(".")
            if head in TEMP_ROOTS and tail:
                self.array_tails.add(tail)

    def is_array(self, path):
        return path in self.arrays or any(path == t or path.endswith("." + t) for t in self.array_tails)

    def walk(self, procs, conditional):
        for entry in procs if isinstance(procs, list) else []:
            for ptype, body in entry.items() if isinstance(entry, dict) else []:
                if not isinstance(body, dict):
                    continue
                cond = conditional or body.get("if") is not None
                if ptype == "foreach":
                    if isinstance(body.get("field"), str):
                        self.add_array(body["field"])
                    self.walk([body.get("processor")] if body.get("processor") else [], True)
                elif ptype == "script":
                    params = body.get("params")
                    for chunk in filter(None, [body.get("source") or "", None if params is None
                                               else json.dumps(params, default=str)]):
                        self.targets |= {n for n, dotted, bracket in SCRIPT_TARGET_RES
                                         if dotted.search(chunk) or bracket.search(chunk)}
                elif ptype in PATTERN_RES:
                    regex = PATTERN_RES[ptype]
                    for definition in (body.get("pattern_definitions") or {}).values():
                        if isinstance(definition, str):
                            self.targets |= {m.group(1) for m in regex.finditer(definition)}
                    patterns = body.get("patterns") or body.get("pattern") or []
                    patterns = [patterns] if isinstance(patterns, str) else patterns
                    found = [{m.group(1) for m in regex.finditer(p)}
                             for p in (patterns if isinstance(patterns, list) else []) if isinstance(p, str)]
                    self.targets |= set().union(*found)
                    if found and not cond:  # unconditional only when every pattern sets it
                        self.unconditional |= set.intersection(*found)
                elif ptype not in NON_PRODUCING:
                    target = body.get("target_field") or body.get("field")
                    if isinstance(target, str):
                        self.targets.add(target)
                        if not cond:
                            self.unconditional.add(target)
                self.walk(body.get("on_failure") or [], True)


# --- index sort proposal (references/columnar.md, "Index sort") ------------------------ #

def leaf_tokens(name):
    leaf = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name.rsplit(".", 1)[-1])
    return [t.lower() for t in re.split(r"[^a-zA-Z0-9]+", leaf) if t]


def norm_leaf(name, segments=1):
    out = re.sub(r"[^a-z0-9]", "", ".".join(name.split(".")[-segments:]).lower())
    return out[:-3] + "id" if out.endswith("uid") else out


def numeric_is_id(name):
    return bool(set(leaf_tokens(name)) & (ID_TOKENS | TENANT_TOKENS))


def is_low_cardinality(name):
    leaf = norm_leaf(name)
    if leaf in LOW_CARD_EXACT or (leaf in LOW_CARD_NAMES and "." in name
                                  and is_low_cardinality(name.rsplit(".", 2)[-2])):
        return True
    variants = [leaf] + next(([leaf[:-len(s)]] for s in ("uid", "id")
                              if leaf.endswith(s) and len(leaf) > len(s)), [])
    return any(v.endswith(t) for v in variants for t in LOW_CARD_LEAVES)


def weak_leaf(name):
    """Tier 3 (dashboard hints) only: names that cannot be a grouping dimension."""
    tokens, parts, squashed = leaf_tokens(name), name.split("."), norm_leaf(name)
    return bool(
        set(tokens) & (MEASUREMENT_TOKENS | HASH_TOKENS | FREE_TEXT_TOKENS)
        or any(t.endswith("hash") for t in tokens)
        or (len(parts) >= 2 and parts[-1].lower() in ID_TOKENS and parts[-2].lower() in PER_EVENT_ENTITIES)
        or (squashed.endswith("s") and not squashed.endswith(("ss", "us", "is", "as", "os"))
            and not numeric_is_id(name))
        or (tokens and tokens[0] in ("is", "has", "can", "should", "was", "allow"))
        or is_low_cardinality(name))


def multi_valued(fields, name, arrays, pipes):
    """Whether `name`, or any object it lives in, holds a list (sample, mapping, pipeline)."""
    parts = name.split(".")
    for path in (".".join(parts[:i]) for i in range(1, len(parts) + 1)):
        anc = fields.get(path) or {}
        normalize = anc.get("normalize")
        if (path in arrays or pipes.is_array(path) or anc.get("type") == "nested"
                or (isinstance(normalize, list) and "array" in normalize)
                or str(anc.get("normalize_as_array")).strip().lower() == "true"
                or (anc.get("external") == "ecs" and (ecs().get(path) or {}).get("array"))):
            return True
    return False


def sortable(fields, name, arrays, pipes):
    """A declared, single-valued keyword/ip (or identifier-named integer) with doc values."""
    fdef = fields.get(name)
    if fdef is None or name in SORT_EXCLUDED:
        return False
    ftype = resolved_type(fdef, name)
    normalize = fdef.get("normalize")
    if ftype not in SORTABLE_STRING | SORTABLE_NUMERIC or is_false(fdef.get("doc_values")) \
            or (ftype in SORTABLE_NUMERIC and not numeric_is_id(name)) \
            or (normalize and not isinstance(normalize, list)):
        return False
    return not multi_valued(fields, name, arrays, pipes)


def sample_scalar(sample, name):
    parts = name.split(".")
    for split in range(len(parts), 0, -1):
        node = sample
        for key in parts[:split - 1] + [".".join(parts[split - 1:])]:
            node = node[key] if isinstance(node, dict) and key in node else KeyError
            if node is KeyError:
                break
        else:
            return isinstance(node, (str, int, float)) and not isinstance(node, bool) and str(node) != ""
    return False


def sample_arrays(doc, prefix=""):
    out = set()
    for key, value in doc.items():
        flat = f"{prefix}.{key}" if prefix else key
        if isinstance(key, str) and isinstance(value, list):
            out.add(flat)
        elif isinstance(key, str) and isinstance(value, dict):
            out |= sample_arrays(value, flat)
    return out


def pick_candidate(fields, sources, arrays, pipes, sample, allow_agent_id, rejected):
    """Tier 1 (curated ECS grouping fields, with event evidence), then tier 2 (tenant ids)."""
    schema = ecs()
    for name in SORT_CANDIDATES:
        if name == "agent.id" and not allow_agent_id:
            continue
        # An undeclared ECS field populated in the sample event; the proposal declares it.
        ecs_def = schema.get(name) or {}
        undeclared_ok = name not in fields and name != "agent.id" and ecs_def and not ecs_def.get("array") \
            and ecs_def.get("type") in SORTABLE_STRING and sample_scalar(sample, name)
        if not (sortable(fields, name, arrays, pipes) or undeclared_ok):
            continue
        # Event evidence: on a poller, `cloud.*` from agent metadata is the collector's.
        fdef, src = fields.get(name), sources.get(name, "")
        if name == "agent.id":
            return name, "tier 1 (ECS grouping field)"
        if name in pipes.targets:
            return name, "tier 1 (ECS grouping field; the stream's ingest pipeline writes it)"
        if fdef and str(fdef.get("description") or "").strip() and src not in ("agent.yml", "beats.yml"):
            return name, f"tier 1 (ECS grouping field; described in `fields/{src}`)"
        if name not in rejected:
            rejected.append(name)
    for leaf in TENANT_LEAVES:
        hits = []
        for name in (n for n in fields if n not in SORT_CANDIDATES):
            for segments in (1, 2):
                depth = name.count(".") - (segments - 1)
                if name.count(".") + 1 >= segments and norm_leaf(name, segments) == leaf \
                        and depth <= 3 and sortable(fields, name, arrays, pipes):
                    hits.append((depth, len(name), name))
                    break
        if hits:
            return sorted(hits)[0][2], "tier 2 (vendor tenant/account id)"
    return None, ""


def receiver_field_ok(fields, name, arrays, pipes):
    """A receiver's device id: sortable as declared, or an undeclared single-valued ECS keyword
    (the proposal declares it)."""
    if name in fields:
        return sortable(fields, name, arrays, pipes)
    ecs_def = ecs().get(name) or {}
    return ecs_def.get("type") in SORTABLE_STRING and not ecs_def.get("array") \
        and not multi_valued(fields, name, arrays, pipes)


def recommend_sort(inputs, fields, sources, filter_fields, arrays, pipes, sample):
    kinds = {"host-local": HOST_INPUTS, "receiver": RECEIVER_INPUTS, "remote/API": COLLECTOR_INPUTS}
    by_kind = {k: sorted(i for i in inputs if i in v) for k, v in kinds.items()}
    by_kind["unclassified"] = sorted(set(inputs) - HOST_INPUTS - RECEIVER_INPUTS - COLLECTOR_INPUTS)
    host, receiver, api, unknown = by_kind.values()
    reason = [f"{k} input(s): {', '.join(v)}" for k, v in by_kind.items() if v] or ["no inputs declared"]
    rejected = []

    def result(klass, sort_fields, why, explicit=True, hint=None, recommendation=None):
        return {"class": klass, "fields": sort_fields, "orders": ["asc", "desc"][-len(sort_fields):],
                "recommendation": recommendation or "explicit sort proposed: " + (
                    f"{sort_fields[0]} asc, @timestamp desc" if len(sort_fields) == 2 else
                    "@timestamp desc only — no confident candidate; needs human choice"),
                "reason": "; ".join(reason + [why]), "explicit": explicit, "dashboard_hint": hint,
                "undeclared_fields": [f for f in sort_fields if f != "@timestamp" and f not in fields]
                if explicit else [], "rejected_candidates": rejected}

    def default_or_degraded(why):
        fdef = fields.get("host.name")
        ftype = fdef and fdef.get("type")
        if fdef and ftype is None and fdef.get("external") == "ecs":
            ftype = (ecs().get("host.name") or {}).get("type")
        if fdef and ((ftype is not None and ftype not in SORTABLE_STRING | SORTABLE_NUMERIC)
                     or is_false(fdef.get("doc_values"))):
            return result("degraded", ["@timestamp"], "`host.name` is mapped so it cannot be sorted",
                          False, recommendation="default DEGRADED: falls back to `@timestamp` desc only")
        return result("default_ok", ["host.name", "@timestamp"], why, False, recommendation="default OK")

    if host and not receiver and not api and not unknown:
        return default_or_degraded("`host.name` is agent-populated and sort-compatible")
    written = [f for f in RECEIVER_SORT_FIELDS if f in pipes.targets] if receiver else []
    rejected += [f for f in written if not receiver_field_ok(fields, f, arrays, pipes)]
    device = next((f for f in written if f not in rejected), None)
    if receiver and not api:
        if device:
            return result("receiver_proposed", [device, "@timestamp"], f"the pipeline writes `{device}`")
        if "host.name" in pipes.unconditional:
            return default_or_degraded("the pipeline sets `host.name` from the header on every event")
        why = f"the pipeline writes {', '.join(f'`{f}`' for f in written)}, which cannot be sorted on" \
            if written else "no `observer.*` device id in the pipeline"
        return result("receiver_no_candidate", ["@timestamp"], why,
                      recommendation="receiver input — no confident candidate; needs human choice")
    candidate, tier = pick_candidate(fields, sources, arrays, pipes, sample, not api, rejected)
    if candidate:
        return result("explicit", [candidate, "@timestamp"], f"candidate from {tier}")
    if receiver and device:
        return result("receiver_proposed", [device, "@timestamp"], f"mixed inputs; writes `{device}`")
    for name, count in filter_fields.most_common(40):
        if not name.startswith("_") and not weak_leaf(name) and sortable(fields, name, arrays, pipes):
            return result("review_candidate", ["@timestamp"], "a dashboard filter is a lead, not a proposal",
                          False, name, f"no confident candidate — dashboard hint: {name} "
                          f"(filtered {count}×); needs human choice")
    return result("no_candidate", ["@timestamp"], "no single-valued tenant/account/observer field")


def sort_declaration(names, ds_dir, pkg_dir):
    """The `external: ecs` entries a sort on undeclared ECS fields needs: package-spec rejects
    an index.sort field the data stream does not define (only @timestamp is implicit)."""
    path = os.path.join(ds_dir, "fields", "ecs.yml")
    deps = (read_yaml(os.path.join(pkg_dir, "_dev", "build", "build.yml")) or {})
    deps = deps.get("dependencies") if isinstance(deps, dict) else None
    has_ecs = isinstance(deps, dict) and isinstance(deps.get("ecs"), dict) \
        and bool(deps["ecs"].get("reference"))
    return {"file": os.path.relpath(path, pkg_dir), "new_file": not os.path.isfile(path),
            "body": "".join(f"- name: {n}\n  external: ecs\n" for n in names),
            "note": None if has_ecs else "`_dev/build/build.yml` has no ECS dependency: add "
                                          "`dependencies.ecs.reference`, or `external: ecs` cannot resolve."}


def existing_sort(settings):
    """The `index.sort` a manifest already declares (nested or dotted keys), or None."""
    flat = {}

    def walk(node, prefix):
        for key, value in node.items():
            if isinstance(value, dict):
                walk(value, f"{prefix}{key}.")
            else:
                flat[f"{prefix}{key}"] = value
    walk(settings if isinstance(settings, dict) else {}, "")
    if flat.get("index.sort.field") is None:
        return None
    listed = lambda v: [str(x) for x in (v if isinstance(v, list) else [v])]  # noqa: E731
    order = flat.get("index.sort.order")
    return {"field": listed(flat["index.sort.field"]), "order": listed(order) if order is not None else []}


# --- `_source` consumers ---------------------------------------------------------------- #

SOURCE_ACCESS = [
    (re.compile(r"""params\s*\.\s*_source\b|params\s*\[\s*['"]_source['"]\s*\]"""), "params._source"),
    (re.compile(r"""ctx\s*\.\s*_source\b|ctx\s*\[\s*['"]_source['"]\s*\]"""), "ctx._source"),
    (re.compile(r"(?i)json_extract\s*\(\s*_source\b"), "JSON_EXTRACT(_source, ...)"),
    (re.compile(r"(?<![A-Za-z0-9])_source\s*[.\[]"), "_source field access"),
    (re.compile(r"(?i)metadata\s+[^|\n\"]{0,80}?_source\b"), "ES|QL METADATA _source")]
SCRIPTED_FIELD_RE = re.compile(r"""\\?"scriptedFields\\?"|\\?"scripted\\?"\s*:\s*true""")
DASH_FIELD_RE = re.compile(r'\\?"(?:field|key|sourceField)\\?"\s*:\s*\\?"([a-zA-Z][\w.@-]*)\\?"')
KQL_FIELD_RE = re.compile(r'([a-zA-Z][\w.@*-]*)\s*(?::|>=|<=|>|<)')


def source_hits(text):
    """How `text` reads the document `_source` (generic field access only as a fallback)."""
    hits = [label for regex, label in SOURCE_ACCESS if regex.search(text)]
    return ([h for h in hits if h != "_source field access"] or hits)[:3]


def scan_kibana(pkg_dir, count_fields):
    """(referenced fields, filter fields, assets reading `_source`) of `kibana/**/*.json`.
    Filter fields (filter pills, KQL clauses) are sort hints; referenced fields are the
    benchmark workload."""
    referenced, filtered, consumers = Counter(), Counter(), []

    def filters(node, depth=0):
        if depth > 40:
            return
        if isinstance(node, str) and node.strip()[:1] in ("{", "[") and len(node.strip()) > 2:
            filters(loads(node.strip()), depth + 1)
        elif isinstance(node, list):
            for item in node:
                filters(item, depth + 1)
        elif isinstance(node, dict):
            meta = node.get("meta")
            key = meta.get("key") if isinstance(meta, dict) else None
            if isinstance(key, str) and key and not key.startswith("_") and meta.get("type") != "custom":
                filtered[key] += 1
            if node.get("language") in ("kuery", "lucene") and isinstance(node.get("query"), str):
                filtered.update(m.group(1) for m in KQL_FIELD_RE.finditer(node["query"])
                                if m.group(1).lower() not in ("and", "or", "not") and "*" not in m.group(1))
            for value in node.values():
                filters(value, depth + 1)

    for root, _dirs, files in os.walk(os.path.join(pkg_dir, "kibana")):
        for path in (os.path.join(root, n) for n in files if n.endswith(".json")):
            small = os.path.isfile(path) and os.path.getsize(path) <= 4_000_000
            text = read(path, lambda fh: fh.read(), "replace") if small else None
            if text is None:
                continue
            if ("_source" in text or "script" in text) and len(consumers) < 12:
                hits = (source_hits(text) if "_source" in text else []) + \
                    (["scripted field"] if SCRIPTED_FIELD_RE.search(text) else [])
                if hits:
                    consumers.append({"file": os.path.relpath(path, pkg_dir), "hits": hits[:3]})
            if count_fields:
                referenced.update(m.group(1) for m in DASH_FIELD_RE.finditer(text))
                filters(loads(text))
    return referenced, filtered, consumers


def source_transforms(pkg_dir):
    """The package's transforms that read `_source`: every `latest` one (it copies the newest
    `_source` per key), and any other whose scripts read it."""
    out, root = [], os.path.join(pkg_dir, "elasticsearch", "transform")
    for name in sorted(os.listdir(root)) if os.path.isdir(root) else []:
        path = os.path.join(root, name, "transform.yml")
        doc = read_yaml(path)
        if not isinstance(doc, dict):
            continue
        latest = isinstance(doc.get("latest"), dict)
        text = read(path, lambda fh: fh.read(), "replace") or ""
        hits = source_hits(text) if "_source" in text else []
        if not latest and not hits:
            continue
        source = doc.get("source") if isinstance(doc.get("source"), dict) else {}
        indices = source.get("index")
        indices = [indices] if isinstance(indices, str) else (indices if isinstance(indices, list) else [])
        dest = doc.get("dest") if isinstance(doc.get("dest"), dict) else {}
        m = re.search(r'ingestPipelineName\s+"([^"]+)"', str(dest.get("pipeline") or ""))
        out.append({"name": name, "file": f"elasticsearch/transform/{name}/transform.yml",
                    "latest": latest, "hits": hits,
                    "patterns": [p.strip() for e in indices for p in str(e).split(",") if p.strip()],
                    "dest_index": dest.get("index"),
                    "dest_pipeline": m.group(1) if m else dest.get("pipeline")})
    return out


_CATALOG_TRANSFORMS = {}


def foreign_transforms(packages_root, own):
    """Other packages' transforms reading `_source` that could read a logs stream of `own`."""
    if packages_root not in _CATALOG_TRANSFORMS:
        _CATALOG_TRANSFORMS[packages_root] = [
            dict(t, package=p) for p in sorted(os.listdir(packages_root))
            if os.path.isdir(os.path.join(packages_root, p, "elasticsearch", "transform"))
            for t in source_transforms(os.path.join(packages_root, p))]

    def could_match(pattern):
        literal = strip_cluster(pattern).split("*", 1)[0].split("?", 1)[0]
        if not literal or literal.startswith("-"):
            return not literal
        return f"logs-{own}".startswith(literal) or literal.startswith(f"logs-{own}")
    return [t for t in _CATALOG_TRANSFORMS[packages_root]
            if t["package"] != own and any(could_match(p) for p in t["patterns"])]


# --- detection rules -------------------------------------------------------------------- #

ESQL_FROM_RE = re.compile(
    r"(?is)(?:^\s*(?:set\b[^;]*;\s*)*|\(\s*)(?:from|ts)\s+([^|()]+?)(?=\s+metadata\b|\||\)|$)")
ESQL_STRING_OR_COMMENT_RE = re.compile(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/', re.S)
QUERY_FIELD_RE = re.compile(r"(?<![\w.@$'\"])([A-Za-z_@][\w@]*(?:\.[\w@]+)+)")
_RULES = {}


def strip_cluster(pattern):
    pattern = pattern.strip().strip("\"'")
    return pattern.split(":", 1)[1] if ":" in pattern else pattern


def pattern_matches(pattern, index_name):
    pattern = strip_cluster(pattern)
    return bool(pattern) and not pattern.startswith("-") and fnmatch.fnmatchcase(index_name, pattern)


def esql_from_patterns(query):
    text = ESQL_STRING_OR_COMMENT_RE.sub(lambda m: m.group(0) if m.group(0).startswith('"') else " ", query)
    names = []
    for part in (p for m in ESQL_FROM_RE.finditer(text) for p in m.group(1).split(",")):
        name = part.strip().strip("`\"'")
        if name and name not in names:
            names.append(name)
    return names


def load_rules(rules_dir):
    """The latest version of every shipped detection rule in `rules_dir`."""
    if rules_dir and os.path.isdir(rules_dir) and rules_dir not in _RULES:
        latest = {}
        for fname in (f for f in os.listdir(rules_dir) if f.endswith(".json")):
            doc = read_json(os.path.join(rules_dir, fname))
            attrs = doc.get("attributes", doc) if isinstance(doc, dict) else None
            if not isinstance(attrs, dict) or not attrs.get("rule_id") or not attrs.get("type"):
                continue
            try:
                version = int(attrs.get("version") or 0)
            except (TypeError, ValueError):
                version = 0
            if str(attrs["rule_id"]) not in latest or version > latest[str(attrs["rule_id"])][0]:
                latest[str(attrs["rule_id"])] = (version, attrs)
        _RULES[rules_dir] = []
        for _, attrs in sorted(latest.values(), key=lambda v: str(v[1].get("name"))):
            query = attrs.get("query") if isinstance(attrs.get("query"), str) else ""
            language = attrs.get("language") or attrs.get("type")
            patterns = [p for p in (attrs.get("index") or []) if isinstance(p, str)]
            if language == "esql" or attrs.get("type") == "esql":
                patterns = esql_from_patterns(query) or patterns
            related = [(str(r["package"]), r.get("integration")) for r in attrs.get("related_integrations")
                       or [] if isinstance(r, dict) and r.get("package")]
            _RULES[rules_dir].append({
                "name": attrs.get("name") or attrs["rule_id"], "rule_id": attrs["rule_id"],
                "language": language, "query": query, "related": related, "reads_source": source_hits(query),
                "patterns": patterns + [p for p in (attrs.get("threat_index") or []) if isinstance(p, str)]})
    return _RULES.get(rules_dir) or []


def attribute_rules(rules, streams, pkg_name, template_streams):
    """stream -> (rules about it, rules that only match its indices). `streams` holds
    (name, dataset, index name) of the package's logs streams. A rule is about the package
    when `related_integrations` names it or a pattern starts with `logs-<pkg>`; then about
    the streams its query names by dataset, else its policy templates' streams, else all."""
    by_pattern = {}
    for idx, rule in enumerate(rules):
        for pattern in rule["patterns"]:
            by_pattern.setdefault(pattern, []).append(idx)
    matched = {}
    for name, _, index_name in streams:
        for idx in (i for p, idxs in by_pattern.items() if pattern_matches(p, index_name) for i in idxs):
            if name not in matched.setdefault(idx, []):
                matched[idx].append(name)
    datasets, out = {n: d for n, d, _ in streams}, {n: ([], []) for n, _, _ in streams}
    for idx in sorted(matched):
        rule, names = rules[idx], matched[idx]
        if not any(p == pkg_name for p, _ in rule["related"]) and \
                not any(strip_cluster(p).startswith(f"logs-{pkg_name}") for p in rule["patterns"]):
            about = set()
        elif len(names) == 1:
            about = set(names)
        else:
            query = rule["query"].lower()
            by_ds = {n for n in names
                     if re.search(rf"(?<![\w.]){re.escape(datasets[n].lower())}(?!\w)", query)}
            via = {ds for p, t in rule["related"] if p == pkg_name and t
                   for ds in (template_streams.get(t) or [t])}
            about = by_ds or (via & set(names)) or set(names)
        for name in names:
            out[name][0 if name in about else 1].append(rule)
    return out


def lookup_candidates(direct, filter_fields, fields, sort_fields, limit=10):
    """`keyword`/`ip` fields the stream's rules and dashboard filters reference outside the
    sort key: input for the per-stream `index: true` decision, never a recommendation."""
    refs = Counter(n for rule in direct for n in set(QUERY_FIELD_RE.findall(rule["query"])))
    schema, out = ecs(), []
    for name in set(refs) | set(filter_fields):
        fdef = fields.get(name)
        ftype = resolved_type(fdef, name) if fdef else (schema.get(name) or {}).get("type")
        risk = name in LOOKUP_RISK_FIELDS or name.startswith(LOOKUP_RISK_PREFIXES)
        if name in sort_fields or name.startswith(("data_stream.", "@")) or \
                (ftype not in ("keyword", "ip") and not (ftype is None and risk)) or \
                (not risk and is_low_cardinality(name)) or (fdef is None and name not in schema):
            continue
        out.append({"field": name, "type": ftype, "rules": refs.get(name, 0),
                    "dashboard_filters": filter_fields.get(name, 0), "high_risk": risk})
    out.sort(key=lambda c: (not c["high_risk"], -c["rules"], -c["dashboard_filters"], c["field"]))
    return out[:limit]


# --- package and data streams ----------------------------------------------------------- #

def index_name(pkg_name, ds_name, manifest):
    dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), str) else None
    return f"logs-{dataset or f'{pkg_name}.{ds_name}'}-default"


def audit_package(pkg_dir, dashboards=True, rules_dir="auto"):
    pkg_dir = os.path.abspath(pkg_dir.rstrip("/"))
    own_dir, packages_root = os.path.basename(pkg_dir), os.path.dirname(pkg_dir)
    manifest = read_yaml(os.path.join(pkg_dir, "manifest.yml"))
    if not isinstance(manifest, dict):
        return {"package": own_dir, "status": "OUT_OF_SCOPE", "data_streams": [],
                "out_of_scope_reason": "manifest.yml is unreadable"}
    pkg_es = manifest.get("elasticsearch") if isinstance(manifest.get("elasticsearch"), dict) else {}
    result = {"package": manifest.get("name", own_dir), "version": manifest.get("version"),
              "format_version": manifest.get("format_version"), "type": manifest.get("type", "integration"),
              "kibana_condition": ((manifest.get("conditions") or {}).get("kibana") or {}).get("version"),
              "logsdb_columnar": pkg_es.get("logsdb_columnar"), "status": "OUT_OF_SCOPE", "data_streams": []}
    templates = [t for t in manifest.get("policy_templates") or [] if isinstance(t, dict) and t.get("name")]
    ds_root = os.path.join(pkg_dir, "data_stream")
    if result["type"] == "input":
        result["out_of_scope_reason"] = "input package: `logsdb_columnar` is for integration packages"
        result["data_streams"] = [{"data_stream": str(t["name"]), "status": "OUT_OF_SCOPE",
                                   "out_of_scope_reason": "input package policy template"} for t in templates]
    if result["type"] == "input" or not os.path.isdir(ds_root):
        result.setdefault("out_of_scope_reason", "no data_stream directory")
        return result
    pkg_name = result["package"]
    referenced, filtered, kibana = scan_kibana(pkg_dir, dashboards)
    transforms = source_transforms(pkg_dir) + foreign_transforms(packages_root, own_dir)
    result["dashboard_fields"] = [f for f, _ in referenced.most_common(15)]
    result["dashboard_filter_fields"] = [f for f, _ in filtered.most_common(15)]
    rules = load_rules(os.path.join(packages_root, RULES_SUBDIR) if rules_dir == "auto" else rules_dir)
    result["rules_scanned"] = len(rules)
    manifests = {d: read_yaml(os.path.join(ds_root, d, "manifest.yml"))
                 for d in sorted(os.listdir(ds_root)) if os.path.isdir(os.path.join(ds_root, d))}
    manifests = {d: m if isinstance(m, dict) else {} for d, m in manifests.items()}
    logs = [(d, m["dataset"] if isinstance(m.get("dataset"), str) else f"{pkg_name}.{d}",
             index_name(pkg_name, d, m)) for d, m in manifests.items() if m.get("type") == "logs"]
    attribution = attribute_rules(rules, logs, pkg_name, {str(t["name"]): [
        str(ds) for ds in t.get("data_streams") or []] for t in templates})
    for ds_name, ds_manifest in manifests.items():
        context = (pkg_name, own_dir, result["logsdb_columnar"], filtered, kibana, transforms, bool(rules))
        stream = audit_stream(pkg_dir, ds_name, ds_manifest, attribution.get(ds_name, ([], [])), *context)
        result["data_streams"].append(stream)
        result["status"] = max(result["status"], stream["status"], key=STATUS_ORDER.index)
    # Fleet switches an integration only when every logs stream is ready. An `unsupported` stream
    # blocks it, and so does, once readiness is declared, any other logs stream that is not ready;
    # package-spec skips the columnar checks of both.
    ready = ("opt_in", "default")
    # The package value counts even when every logs stream ignores it through `index_mode`.
    declared = result["logsdb_columnar"] in ready \
        or any(s.get("logsdb_columnar_effective") in ready for s in result["data_streams"])
    for s in result["data_streams"]:
        effective = s.get("logsdb_columnar_effective")
        if s.get("type") != "logs" or s["status"] == "OUT_OF_SCOPE" or effective in ready \
                or (effective != "unsupported" and not declared):
            continue
        why = "`logsdb_columnar: unsupported` keeps it on LogsDB" if effective == "unsupported" \
            else f"`index_mode: {s['index_mode']}` keeps it off columnar" if s.get("index_mode") \
            else "neither it nor the package declares `logsdb_columnar`"
        s["findings"].append(finding(
            "stream_not_ready", "blocker", f"Not ready: {why}. Fleet only switches an integration whose "
            "logs streams are all ready.", f"data_stream/{s['data_stream']}/manifest.yml"))
        s["status"] = result["status"] = "BLOCKED"
    # Fleet switches an integration only when every logs stream is ready.
    otel = [s["data_stream"] for s in result["data_streams"]
            if s.get("type") == "logs" and s["status"] == "OUT_OF_SCOPE"]
    if otel:
        result["status"] = "BLOCKED"
        result["blocked_reason"] = (f"OpenTelemetry-input logs stream(s) {', '.join(f'`{d}`' for d in otel)} "
                                    "stay on LogsDB, and Fleet only switches an integration whose logs "
                                    "streams are all ready")
    result["ecs"] = ecs() and _ECS_SOURCE[0]
    return result


def audit_stream(pkg_dir, ds_name, manifest, rules, pkg_name, own_dir, package_value, filtered, kibana,
                 transforms, rules_scanned):
    ds_dir = os.path.join(pkg_dir, "data_stream", ds_name)
    es = manifest.get("elasticsearch") if isinstance(manifest.get("elasticsearch"), dict) else {}
    itpl = es.get("index_template") if isinstance(es.get("index_template"), dict) else {}
    own, mode = es.get("logsdb_columnar"), es.get("index_mode")
    stream = {"data_stream": ds_name, "type": manifest.get("type"), "status": "OUT_OF_SCOPE",
              "index_mode": mode, "logsdb_columnar": own, "findings": []}
    if stream["type"] != "logs":
        stream["out_of_scope_reason"] = f"data stream type is `{stream['type']}` (logs only)"
        return stream
    # The stream's own value wins; a fixed index_mode (time_series) ignores the package value.
    stream["logsdb_columnar_effective"] = effective = own if own in ("opt_in", "default", "unsupported") \
        else package_value if package_value in ("opt_in", "default") and not mode else None
    stream["inputs"] = inputs = sorted({s.get("input") for s in manifest.get("streams") or []
                                        if isinstance(s, dict) and s.get("input")})
    if "otelcol" in inputs:
        stream["out_of_scope_reason"] = "OpenTelemetry input: OTel log streams stay on LogsDB"
        return stream
    findings, fields, sources = stream["findings"], {}, {}
    entries = read_fields(os.path.join(ds_dir, "fields"), pkg_dir)
    for fdef, flat, in_mf, rel, fname in entries:
        if not in_mf:
            fields.setdefault(flat, fdef)
            sources.setdefault(flat, fname)
    findings.extend(rejected_mappings(entries, itpl, ds_dir, pkg_dir))
    findings.extend(nested_object_children(entries))
    findings.extend(finding("source_consumer_kibana", "review", f"Reads `_source`: {', '.join(a['hits'])}.",
                            a["file"]) for a in kibana)
    name = index_name(pkg_name, ds_name, manifest)
    for tr in (t for t in transforms if any(pattern_matches(p, name) for p in t["patterns"])):
        owner = tr.get("package")
        where = f"packages/{owner}/{tr['file']}" if owner and owner != own_dir else tr["file"]
        findings.append(finding(
            "source_consumer_latest_transform", "review", f"`latest` transform `{tr['name']}` copies "
            f"`_source` into `{tr['dest_index']}`" + (f" through the pipeline `{tr['dest_pipeline']}`"
                                                     if tr["dest_pipeline"] else "") + ".", where)
            if tr["latest"] else finding(
                "source_consumer_transform", "review",
                f"Transform `{tr['name']}` reads `_source` in a script: {', '.join(tr['hits'])}.", where))
    direct, other = rules
    findings.extend(finding("source_consumer_detection_rule", "review", f"Detection rule \"{r['name']}\" "
                            f"reads `_source` ({', '.join(r['reads_source'])}).",
                            f"packages/{RULES_SUBDIR}/{r['rule_id']}_<version>.json")
                    for r in direct + other if r["reads_source"])
    sample = read_json(os.path.join(ds_dir, "sample_event.json"))
    sample = sample if isinstance(sample, dict) else {}
    sort = recommend_sort(inputs, fields, sources, filtered, sample_arrays(sample), Pipelines(ds_dir), sample)
    sort["existing"] = existing_sort(itpl.get("settings"))
    sort["declaration"] = sort_declaration(sort["undeclared_fields"], ds_dir, pkg_dir) \
        if sort["undeclared_fields"] and not sort["existing"] else None
    stream["sort"] = sort
    stream["rules"] = {"scanned": rules_scanned, "direct": len(direct), "other": len(other),
                       "by_language": dict(sorted(Counter(r["language"] for r in direct).items())),
                       "names": [r["name"] for r in direct][:25],
                       "reading_source": [r["name"] for r in direct + other if r["reads_source"]]}
    kept = sort["existing"]["field"] if sort["existing"] else sort["fields"]
    stream["lookup_candidates"] = lookup_candidates(direct, filtered, fields, kept)
    severities = {f["severity"] for f in findings}
    stream["status"] = "BLOCKED" if "blocker" in severities else \
        "NEEDS_REVIEW" if "review" in severities else "READY"
    return stream


# --- output ----------------------------------------------------------------------------- #

def markdown(r):
    out = [f"# {r['package']} {r.get('version') or ''} — {r['status']}", "",
           f"- format_version `{r.get('format_version')}`, Kibana `{r.get('kibana_condition')}`, "
           f"package `logsdb_columnar`: `{r.get('logsdb_columnar')}`"
           + (f"; {r['ecs']}" if r.get("ecs") else ""),
           "- Mapping errors and warnings: run `elastic-package check` (package-spec >= 3.8.0)."]
    out += [f"- **No ECS cache** (`{ECS_CACHE}`): fields declared `external: ecs` have no type beyond "
            "the sort and lookup candidates, so proposals can be weaker. Run `elastic-package build` on a "
            "package with an ECS dependency once, then run this again."] \
        if str(r.get("ecs")).startswith("no ECS") else []
    out += [f"- Out of scope: {r['out_of_scope_reason']}"] if r.get("out_of_scope_reason") else []
    out += [f"- Blocked: {r['blocked_reason']}: don't declare readiness."] if r.get("blocked_reason") else []
    out += [f"- Dashboard fields (benchmark): {', '.join(r['dashboard_fields'])}"] \
        if r.get("dashboard_fields") else []
    for s in r["data_streams"]:
        out += ["", f"## `{s['data_stream']}` — {s['status']}"]
        if s["status"] == "OUT_OF_SCOPE":
            out.append(f"- {s.get('out_of_scope_reason', '')}")
            continue
        sort, rules, decl = s["sort"], s["rules"], s["sort"]["declaration"]
        out += [f"- Inputs: {', '.join(s['inputs']) or '(none)'}; "
                f"effective `logsdb_columnar`: `{s['logsdb_columnar_effective']}`",
                f"- Sort: **{sort['recommendation']}** — {sort['reason']}"]
        if sort["existing"]:
            out.append(f"- Existing `index.sort`: {sort['existing']} (keep it unless the data says so)")
        elif sort["explicit"]:
            out += ["", "  ```yaml", "  elasticsearch:   # merge into the manifest's existing key",
                    "    index_template:", "      settings:", "        index:", "          sort:",
                    f"            field: {json.dumps(sort['fields'])}",
                    f"            order: {json.dumps(sort['orders'])}", "  ```"]
        if decl:
            out += [f"- The sort needs this in `{decl['file']}`{' (new file)' if decl['new_file'] else ''}:",
                    "", "  ```yaml", *[f"  {ln}" for ln in decl["body"].rstrip().split("\n")], "  ```"]
            out += [f"  {decl['note']}"] if decl["note"] else []
        out.append(f"- Detection rules: {rules['direct']} query this stream directly "
                   f"({', '.join(f'{k} {v}' for k, v in rules['by_language'].items()) or 'none'}), "
                   f"{rules['other']} more match its indices; {len(rules['reading_source'])} read `_source`"
                   + ("" if rules["scanned"] else " (rules not scanned)"))
        out += ["- Lookup candidates (`index: true` decision; none is valid): " + ", ".join(
            f"`{c['field']}` ({c['rules']} rules, {c['dashboard_filters']} filters)"
            for c in s["lookup_candidates"])] if s["lookup_candidates"] else []
        out += [f"- `{f['code']}` ({f['severity']}): {f['message']} `{f['file']}`" for f in s["findings"]] \
            or ["- No `_source` consumer or other finding."]
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0].replace("\n", " "))
    parser.add_argument("path", help="package directory (packages/<pkg>)")
    parser.add_argument("--format", choices=["markdown", "json", "both"], default="markdown")
    parser.add_argument("--no-dashboards", dest="dashboards", action="store_false",
                        help="skip the dashboard field counts (sort hints, benchmark workload)")
    parser.add_argument("--rules", metavar="DIR", help="detection rules directory (default: "
                        "packages/security_detection_engine/kibana/security_rule)")
    parser.add_argument("--no-rules", action="store_true", help="do not scan detection rules")
    args = parser.parse_args(argv)
    if not os.path.isfile(os.path.join(args.path, "manifest.yml")):
        print(f"error: {args.path}: not a package (no manifest.yml)", file=sys.stderr)
        return 2
    result = audit_package(args.path, args.dashboards, None if args.no_rules else (args.rules or "auto"))
    print("\n\n".join(([markdown(result)] if args.format != "json" else [])
                      + ([json.dumps(result, indent=1)] if args.format != "markdown" else [])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
