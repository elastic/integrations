"""Ingest-pipeline evidence: list-valued paths and the fields a pipeline populates."""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List

import yaml

from .common import YAML_LOADER
from .constants import RECEIVER_SORT_FIELDS, SORT_CANDIDATES, SORT_CANDIDATES_COLLECTOR_ONLY


# --------------------------------------------------------------------------- #
# Ingest-pipeline evidence
#
# Two questions the mapping cannot answer:
#   * which object paths actually hold *lists* (CloudTrail's
#     `aws.cloudtrail.resources` is a plain `group` in `fields.yml`);
#   * which fields a **receiver** pipeline populates, and whether it does so
#     unconditionally (`host.name` set in one grok branch out of twelve is not the
#     same thing as `host.name` parsed from every syslog header).
# --------------------------------------------------------------------------- #

# Painless roots used for the not-yet-renamed source document. A path under one of
# these is matched against a field's ancestors by its tail, because
# `$("json.resources", []).stream()` and `aws.cloudtrail.resources` are the same
# object at two points in the pipeline.
PIPELINE_TEMP_ROOTS = {"json", "_temp_", "_temp", "_tmp", "_conf", "_ingest"}

# Painless array idioms.
_PAINLESS_ARRAY_RES = [
    re.compile(r'\$\(\s*"([\w.@]+)"\s*,\s*\[\s*\]\s*\)\s*\.stream\(\)'),
    re.compile(r'ctx\.?\??\.?([\w.?@]+?)\s*\.stream\(\)'),
    re.compile(r'ctx\.?\??\.?([\w.?@]+?)\s+instanceof\s+List'),
    re.compile(r'for\s*\(\s*def\s+\w+\s*:\s*ctx\.?\??\.?([\w.?@]+?)\s*\)'),
    re.compile(r'ctx\.?\??\.?([\w.?@]+?)\s*=\s*new\s+ArrayList'),
]

# `%{PATTERN:target.field}` / `%{PATTERN:target.field:type}` inside a grok pattern,
# and `%{target.field}` inside a dissect pattern.
_GROK_TARGET_RE = re.compile(r'%\{[A-Z0-9_]+:([\w.@]+)(?::\w+)?\}')
_DISSECT_TARGET_RE = re.compile(r'%\{[+&?*]?([\w.@]+)[^}]*\}')

# Processors that do not produce their `field` as an output.
_NON_PRODUCING_PROCESSORS = {
    "remove", "drop", "fail", "pipeline", "grok", "dissect", "script", "enrich",
    "terminate", "reroute",
}

# `observer.name` / `observer.hostname` / `observer.serial_number` written or read
# anywhere in a pipeline's *text*. `script` is in `_NON_PRODUCING_PROCESSORS` — its
# `field` is not its output — so the structured walk never sees the very common
# "params map -> ECS field" idiom, where the mapping lives in the processor's
# `params` and only Painless writes it:
#
#     - script:
#         params:
#           fw:  [{to: observer.hostname}]
#           id:  [{to: observer.name}]
#           sn:  [{to: observer.serial_number}]
#
# (`sonicwall_firewall/log`). The optional `?` covers Painless null-safe access
# (`ctx?.observer?.hostname`), which is how `cef/log` refers to the CEF header
# fields that the Beats `decode_cef` processor populates before ingest.
_OBSERVER_DEVICE_RE = re.compile(
    r"(?<!\w)observer\??\.\??(name|hostname|serial_number)\b")
# `ctx['observer']['hostname']` — the bracket spelling of the same thing.
_OBSERVER_DEVICE_BRACKET_RE = re.compile(
    r"""\[\s*['"]observer['"]\s*\]\s*\[\s*['"](name|hostname|serial_number)['"]\s*\]""")


def _observer_device_hits(text: str) -> set:
    """Device identifiers named in a chunk of pipeline text."""
    if not text:
        return set()
    hits = {"observer." + m.group(1) for m in _OBSERVER_DEVICE_RE.finditer(text)}
    hits |= {"observer." + m.group(1)
             for m in _OBSERVER_DEVICE_BRACKET_RE.finditer(text)}
    return hits


# The tier-1 ECS grouping fields that need *event* evidence before they can lead an
# index sort — see `_tier1_event_evidence`. `agent.id` is excluded because it already
# has its own, stricter rule (`SORT_CANDIDATES_COLLECTOR_ONLY`).
TIER1_EVENT_EVIDENCE_FIELDS = frozenset(SORT_CANDIDATES) - SORT_CANDIDATES_COLLECTOR_ONLY


def _field_name_res(names):
    """(name, dotted_re, bracket_re) for each dotted field name.

    `cloud.account.id` is matched as `cloud.account.id`, `ctx?.cloud?.account?.id`
    (Painless null-safe access) and `ctx['cloud']['account']['id']`.
    """
    out = []
    for name in names:
        parts = name.split(".")
        dotted = r"(?<!\w)" + r"\??\.\??".join(re.escape(p) for p in parts) + r"\b"
        bracket = r"\s*".join(r"\[\s*['\"]%s['\"]\s*\]" % re.escape(p) for p in parts)
        out.append((name, re.compile(dotted), re.compile(bracket)))
    return out


# Fields a `script` processor is allowed to claim as a write. Kept to an allow-list
# on purpose: a Painless mention is not proof of a write, so this is only trusted for
# the handful of names where the alternative is a *worse* answer (an `observer.*`
# device for a receiver stream, a tenant id for a poller).
_SCRIPT_TARGET_RES = _field_name_res(
    sorted(set(RECEIVER_SORT_FIELDS) | TIER1_EVENT_EVIDENCE_FIELDS))


def _script_field_hits(text: str) -> set:
    """Allow-listed field names a chunk of Painless / processor params refers to."""
    if not text:
        return set()
    return {name for name, dotted, bracket in _SCRIPT_TARGET_RES
            if dotted.search(text) or bracket.search(text)}


class PipelineFacts:
    """What the ingest pipelines of one data stream say about its fields."""

    def __init__(self) -> None:
        self.array_paths: set = set()        # exact dotted paths iterated as lists
        self.array_tails: set = set()        # same, below a temp root: matched by tail
        self.targets: set = set()            # every field the pipelines write
        self.unconditional_targets: set = set()

    def is_array(self, path: str) -> bool:
        if path in self.array_paths:
            return True
        return any(path == tail or path.endswith("." + tail) for tail in self.array_tails)

    def _add_array(self, raw: str) -> None:
        path = raw.replace("?", "").strip(".")
        if not path:
            return
        self.array_paths.add(path)
        head, _, tail = path.partition(".")
        if head in PIPELINE_TEMP_ROOTS and tail:
            self.array_tails.add(tail)


def scan_pipelines(ds_dir: str) -> PipelineFacts:
    facts = PipelineFacts()
    pipeline_dir = os.path.join(ds_dir, "elasticsearch", "ingest_pipeline")
    if not os.path.isdir(pipeline_dir):
        return facts
    texts: List[str] = []
    for fname in sorted(os.listdir(pipeline_dir)):
        if not fname.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(pipeline_dir, fname)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        texts.append(text)
        for regex in _PAINLESS_ARRAY_RES:
            for match in regex.finditer(text):
                facts._add_array(match.group(1))
        try:
            doc = yaml.load(text, Loader=YAML_LOADER)
        except Exception:
            continue
        if isinstance(doc, dict):
            _walk_processors(doc.get("processors") or [], facts, conditional=False)
            _walk_processors(doc.get("on_failure") or [], facts, conditional=True)
    # Last resort for the receiver device pick only: if neither the structured walk
    # nor the `script` scan found an `observer.*` device identifier, look for one in
    # the raw pipeline text. This is deliberately loose — a mention is not a write —
    # but it feeds `targets` ONLY (never `unconditional_targets`), the allow-list it
    # can match is three fields long, and the alternative outcome is "no confident
    # candidate". It never overrides a structured hit, so a precisely detected
    # `observer.hostname` is not displaced by a loosely mentioned `observer.name`.
    if not facts.targets.intersection(RECEIVER_SORT_FIELDS):
        for text in texts:
            facts.targets |= _observer_device_hits(text)
    return facts


def _walk_processors(procs: Any, facts: PipelineFacts, conditional: bool) -> None:
    if not isinstance(procs, list):
        return
    for entry in procs:
        if not isinstance(entry, dict):
            continue
        for ptype, body in entry.items():
            if not isinstance(body, dict):
                continue
            cond = conditional or body.get("if") is not None
            if ptype == "foreach":
                field = body.get("field")
                if isinstance(field, str):
                    facts._add_array(field)
                _walk_processors([body.get("processor")] if body.get("processor") else [],
                                 facts, conditional=True)
            elif ptype == "script":
                # Painless writes are invisible to the structured walk, so the
                # allow-listed names (`observer.*` device identifiers and the tier-1
                # ECS grouping fields) are recovered from the text of `source` and
                # `params` — `aws_bedrock_agentcore/memory_application_logs` sets
                # `ctx.service.name` that way and nowhere else. `targets` only: a
                # Painless write is almost always branch-dependent, so it is never
                # evidence of an unconditional target.
                chunks = [body.get("source") or ""]
                params = body.get("params")
                if params is not None:
                    chunks.append(json.dumps(params, default=str))
                for chunk in chunks:
                    facts.targets |= _script_field_hits(chunk)
            elif ptype in ("grok", "dissect"):
                _add_pattern_targets(ptype, body, facts, cond)
            elif ptype not in _NON_PRODUCING_PROCESSORS:
                target = body.get("target_field") or body.get("field")
                if isinstance(target, str):
                    facts.targets.add(target)
                    if not cond:
                        facts.unconditional_targets.add(target)
            _walk_processors(body.get("on_failure") or [], facts, conditional=True)


def _add_pattern_targets(ptype: str, body: Dict[str, Any], facts: PipelineFacts,
                         conditional: bool) -> None:
    """Grok/dissect targets.

    A target is unconditional only when it appears in **every** pattern of the
    processor: `cisco_asa` sets `host.name` in one branch of a twelve-pattern grok,
    which is not the same as a syslog header parsed the same way every time.
    """
    regex = _GROK_TARGET_RE if ptype == "grok" else _DISSECT_TARGET_RE
    # Named sub-patterns are always a branch of an alternation, never guaranteed.
    for definition in (body.get("pattern_definitions") or {}).values():
        if isinstance(definition, str):
            facts.targets |= {m.group(1) for m in regex.finditer(definition)}
    patterns = body.get("patterns") or body.get("pattern") or []
    if isinstance(patterns, str):
        patterns = [patterns]
    if not isinstance(patterns, list):
        return
    per_pattern = []
    for pattern in patterns:
        if not isinstance(pattern, str):
            continue
        found = {m.group(1) for m in regex.finditer(pattern)}
        per_pattern.append(found)
        facts.targets |= found
    if per_pattern and not conditional:
        facts.unconditional_targets |= set.intersection(*per_pattern)
