"""Index sort recommendation."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from .common import is_false, is_true
from .constants import (
    BOOLEAN_LEAF_PREFIXES,
    COLLECTOR_INPUTS,
    FREE_TEXT_TOKENS,
    HASH_TOKENS,
    HOST_MEANINGFUL_INPUTS,
    ID_TOKENS,
    LOW_CARDINALITY_EXACT,
    LOW_CARDINALITY_LEAVES,
    LOW_CARDINALITY_NAME_LEAVES,
    MEASUREMENT_TOKENS,
    PER_EVENT_ENTITIES,
    RECEIVER_INPUTS,
    RECEIVER_SORT_FIELDS,
    SINGULAR_S_ENDINGS,
    SORTABLE_NUMERIC_TYPES,
    SORTABLE_STRING_TYPES,
    SORTABLE_TYPES,
    SORT_CANDIDATES,
    SORT_CANDIDATES_COLLECTOR_ONLY,
    SORT_CANDIDATE_LEAVES,
    SORT_CANDIDATE_MAX_DEPTH,
    SORT_EXCLUDED_FIELDS,
    TENANT_TOKENS,
)
from .ecs import ecs_schema
from .pipelines import PipelineFacts, TIER1_EVENT_EVIDENCE_FIELDS


# The index sort as the CHILDREN of the stream manifest's `elasticsearch:` key. A
# data stream manifest has exactly one `elasticsearch:` mapping, so the sort and the
# `columnar.supported` flag are siblings inside it — the report therefore emits a
# single merged block (`stream_manifest_block`). Two separate `elasticsearch:`
# snippets are a duplicate key when pasted literally, and YAML keeps only the last.
SORT_YAML_BODY = (
    "  index_template:\n"
    "    settings:\n"
    "      index:\n"
    "        sort:\n"
)
SORT_YAML_HEADER = "elasticsearch:\n" + SORT_YAML_BODY

# Same, for the stream-level readiness flag.
SUPPORTED_YAML_BODY = "  columnar:\n    supported: true\n"


def sort_yaml(fields: List[str], orders: List[str], header: bool = True) -> str:
    return (
        (SORT_YAML_HEADER if header else SORT_YAML_BODY)
        + "          field: [" + ", ".join(f'"{f}"' for f in fields) + "]\n"
        + "          order: [" + ", ".join(f'"{o}"' for o in orders) + "]\n"
    )


def recommend_sort(stream: Dict[str, Any], field_index: Dict[str, Dict[str, Any]],
                   dash_fields: Counter, filter_fields: Counter,
                   array_fields: Optional[set] = None,
                   pipeline_arrays: Optional[PipelineFacts] = None,
                   sample: Optional[Dict[str, Any]] = None,
                   field_sources: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Decide whether the logsdb_columnar default sort is right for this stream.

    The input types pick the **regime**:

      * host-local (`filestream`, `winlog`, …) — the agent runs on the subject, so
        the default `host.name asc, @timestamp desc` is right. Elastic Agent
        populates `host.name` on every event via `add_host_metadata`, and
        Elasticsearch injects the mapping when the template lacks one, so the
        absence of `host.name` from `fields/*.yml` or from `sample_event.json`
        proves nothing. Mapping evidence is used only to downgrade.
      * receiver (`tcp`, `udp`, `syslog`) — a remote device pushes to the agent, and
        what `host.name` holds is whatever the pipeline put there. Evidence comes
        from the pipeline, not from the input.
      * collector / API poller — the agent host is one value, so an explicit sort on
        a tenant-like dimension is needed.
    """
    inputs = stream["inputs"]
    host_inputs = sorted(i for i in inputs if i in HOST_MEANINGFUL_INPUTS)
    receiver_inputs = sorted(i for i in inputs if i in RECEIVER_INPUTS)
    api_inputs = sorted(i for i in inputs if i in COLLECTOR_INPUTS)
    unknown_inputs = sorted(
        set(inputs) - HOST_MEANINGFUL_INPUTS - RECEIVER_INPUTS - COLLECTOR_INPUTS)
    top_dash = [f for f, _ in dash_fields.most_common(10)]
    pipeline_arrays = pipeline_arrays or PipelineFacts()
    sample = sample or {}
    field_sources = field_sources or {}

    reason_bits = []
    if host_inputs:
        reason_bits.append(f"host-local input(s): {', '.join(host_inputs)}")
    if receiver_inputs:
        reason_bits.append(f"receiver input(s): {', '.join(receiver_inputs)} "
                           f"(host = whatever the pipeline sets)")
    if api_inputs:
        reason_bits.append(f"remote/API input(s): {', '.join(api_inputs)} (host = collector)")
    if unknown_inputs:
        reason_bits.append(f"unclassified input(s): {', '.join(unknown_inputs)}")
    if not inputs:
        reason_bits.append("no inputs declared")

    def result(klass: str, recommendation: str, fields: List[str], orders: List[str],
               extra_reason: str = "", explicit: bool = False,
               hint: Optional[str] = None) -> Dict[str, Any]:
        return {
            "class": klass,
            "recommendation": recommendation,
            "sort_fields": fields,
            "sort_orders": orders,
            "reason": "; ".join(reason_bits + ([extra_reason] if extra_reason else [])),
            "explicit_sort_yaml": sort_yaml(fields, orders) if explicit else None,
            "dashboard_top_fields": top_dash,
            # The tier-3 dashboard hint: a field the package's own dashboards filter
            # on. Never a proposal — see `review_candidate` below.
            "dashboard_sort_hint": hint,
            "dashboard_sort_hint_filters": filter_fields.get(hint, 0) if hint else 0,
            # Tier-1 ECS fields that are present but were refused for want of event
            # evidence — see `_tier1_event_evidence`.
            "rejected_candidates": list(rejected),
        }

    rejected: List[str] = []

    def default_or_degraded(extra_reason: str) -> Dict[str, Any]:
        bad_type = _host_name_sort_problem(field_index)
        if bad_type:
            return result("degraded",
                          "default DEGRADED: falls back to `@timestamp` desc only",
                          ["@timestamp"], ["desc"], bad_type)
        return result("default_ok", "default OK", ["host.name", "@timestamp"],
                      ["asc", "desc"], extra_reason)

    host_meaningful = bool(host_inputs) and not receiver_inputs and not api_inputs \
        and not unknown_inputs

    if host_meaningful:
        return default_or_degraded("`host.name` is agent-populated and sort-compatible")

    device = next((f for f in RECEIVER_SORT_FIELDS if f in pipeline_arrays.targets), None)

    # Receiver regime: the pipeline decides. Do not fall through to the tenant tiers —
    # a pure syslog stream has no tenant, and the device identity is the whole
    # question. A stream that *also* offers a collector input is not in this regime:
    # see the mixed-input step below.
    if receiver_inputs and not api_inputs:
        if device:
            return result(
                "receiver_proposed",
                f"explicit sort proposed: {device} asc, @timestamp desc",
                [device, "@timestamp"], ["asc", "desc"],
                f"receiver input: sort on the device identifier the pipeline "
                f"populates (`{device}`)",
                explicit=True)
        if "host.name" in pipeline_arrays.unconditional_targets:
            return default_or_degraded(
                "the pipeline sets `host.name` from the header on every event")
        return result(
            "receiver_no_candidate",
            "receiver input — no confident candidate; needs human choice",
            ["@timestamp"], ["desc"],
            "the pipeline populates no `observer.*` device identifier, and `host.name` "
            "only on some branches — a human has to say which field identifies the "
            "sending device",
            explicit=True)

    candidate, tier = _pick_sort_candidate(
        field_index, filter_fields, array_fields or set(), pipeline_arrays, sample,
        allow_agent_id=not api_inputs, field_sources=field_sources, rejected=rejected)
    if rejected:
        reason_bits.append(
            "rejected tier-1 " + ", ".join(f"`{n}`" for n in rejected)
            + ": populated by agent metadata (collector), not by the event")
    if candidate:
        return result("explicit",
                      f"explicit sort proposed: {candidate} asc, @timestamp desc",
                      [candidate, "@timestamp"], ["asc", "desc"],
                      f"candidate from {tier}", explicit=True)

    # Mixed inputs (`tcp`/`udp` *and* `http_endpoint`, as in `zscaler_zia/firewall`
    # and `gigamon/ami`): tiers 1-2 above already had first refusal, because a tenant
    # id carried in the collector payload beats a syslog device. But receiver
    # evidence — an `observer.*` identifier the pipeline actually populates — is
    # still real evidence, and it outranks the dashboard hint below.
    if receiver_inputs and device:
        return result(
            "receiver_proposed",
            f"explicit sort proposed: {device} asc, @timestamp desc",
            [device, "@timestamp"], ["asc", "desc"],
            f"mixed receiver/collector inputs and no tenant id: sort on the device "
            f"identifier the pipeline populates (`{device}`)",
            explicit=True)

    # Tier 3 is a *hint*, not a proposal. It takes whatever the package's dashboards
    # happen to filter on, and across the catalog two thirds of its picks are junk
    # (`aws.elb.listener`, `domaintools.domain`, `zscaler_zia.web.threat.name`). It
    # is printed for a human to judge and deliberately emits no `index.sort` YAML.
    hint = _dashboard_sort_hint(
        field_index, filter_fields, array_fields or set(), pipeline_arrays)
    if hint:
        return result(
            "review_candidate",
            f"no confident candidate — dashboard hint: {hint} "
            f"(filtered {filter_fields[hint]}\u00d7); needs human choice",
            ["@timestamp"], ["desc"],
            f"no single-valued tenant/account/observer field; the package's own "
            f"dashboards filter on `{hint}` ({filter_fields[hint]}\u00d7), which is a "
            f"lead for a human, not a validated grouping dimension",
            hint=hint)

    return result(
        "no_candidate",
        "explicit sort proposed: @timestamp desc only — no confident candidate; "
        "needs human choice",
        ["@timestamp"], ["desc"],
        "no single-valued tenant/account/observer field and no dashboard filter "
        "field survived validation",
        explicit=True)


def _host_name_sort_problem(field_index: Dict[str, Dict[str, Any]]) -> Optional[str]:
    """Why Elasticsearch would refuse to sort on this package's `host.name` mapping.

    `LogsdbIndexModeSettingsProvider` only keeps `host.name` in the sort when it is a
    keyword or a number **with doc values**; otherwise `IndexSortConfig` resolves to
    `@timestamp` alone.
    """
    fdef = field_index.get("host.name")
    if fdef is None:
        return None  # Elasticsearch injects the mapping itself
    ftype = fdef.get("type")
    if ftype is None and fdef.get("external") == "ecs":
        ftype = (ecs_schema().get("host.name") or {}).get("type")
    if ftype is not None and ftype not in SORTABLE_TYPES:
        return f"`host.name` is mapped as `{ftype}`, which Elasticsearch cannot sort on"
    if is_false(fdef.get("doc_values")):
        return "`host.name` is mapped with `doc_values: false`"
    return None


def _normalise_leaf(name: str, segments: int = 1) -> str:
    """Last `segments` path segments, squashed to lowercase letters/digits.

    `segments=1` turns `o365.audit.OrganizationId` into `organizationid`.
    `segments=2` turns `netbox.tenant.id` into `tenantid`, which is how the
    `<object>.id` spelling of a tenant identifier is recognised. A trailing `uid` is
    folded to `id` so the OCSF spelling (`cloud.account.uid`) matches too.
    """
    tail = ".".join(name.split(".")[-segments:])
    out = re.sub(r"[^a-z0-9]", "", tail.lower())
    if out.endswith("uid"):
        out = out[:-3] + "id"
    return out


_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _leaf_tokens(name: str) -> List[str]:
    """Lowercased words of the last path segment.

    `errorMessage` -> `["error", "message"]`; `response_time_in_seconds` ->
    `["response", "time", "in", "seconds"]`. Token matching (rather than a substring
    test on the squashed name) is what keeps `security_id` out of the `sec` bucket
    and `account_number` out of the `num` one.
    """
    leaf = name.rsplit(".", 1)[-1]
    return [t for t in re.split(r"[^a-zA-Z0-9]+", _CAMEL_RE.sub(" ", leaf)) if t]


def _numeric_leaf_is_id(name: str) -> bool:
    """Whether an integer-typed field's name claims to be an identifier.

    Integers are only admitted as a sort key on the strength of their name: either an
    id token (`id`, `uid`) or a tenant-like entity word. Everything else — `bytes`,
    `count`, `progress`, `seconds_to_triaged`, `observables_count` — is a
    measurement, and sorting a log index by a measurement is worse than not sorting
    it at all.
    """
    tokens = {t.lower() for t in _leaf_tokens(name)}
    return bool(tokens & ID_TOKENS) or bool(tokens & TENANT_TOKENS)


def _is_per_event_id(name: str) -> bool:
    """`<per-event entity>.id` / `.uid`, e.g. `blacklens.alert.id`."""
    parts = name.split(".")
    if len(parts) < 2:
        return False
    if parts[-1].lower() not in ID_TOKENS:
        return False
    return parts[-2].lower() in PER_EVENT_ENTITIES


def _is_plural_leaf(name: str) -> bool:
    squashed = _normalise_leaf(name)
    if not squashed.endswith("s") or squashed.endswith(SINGULAR_S_ENDINGS):
        return False
    return not _numeric_leaf_is_id(name)


def _weak_sort_leaf(name: str) -> Optional[str]:
    """Why this field name disqualifies it as the dashboard-tier sort key, or None.

    Applied to tier 3 only: tiers 1 and 2 match curated field/leaf lists, so their
    names are known good. Tier 3 takes whatever the package's dashboards filter on,
    which is where measurements, hashes, prose and enums get in.
    """
    tokens = {t.lower() for t in _leaf_tokens(name)}
    if tokens & MEASUREMENT_TOKENS:
        return "measurement"
    if (tokens & HASH_TOKENS) or any(t.endswith("hash") for t in tokens):
        return "per-event hash/uuid"
    if tokens & FREE_TEXT_TOKENS:
        return "free text"
    if _is_per_event_id(name):
        return "per-event id"
    if _is_plural_leaf(name):
        return "plural / array-ish"
    leaf_tokens = _leaf_tokens(name)
    if leaf_tokens and leaf_tokens[0].lower() in BOOLEAN_LEAF_PREFIXES:
        return "boolean flag"
    if is_low_cardinality(name):
        return "low-cardinality enum"
    return None


def resolved_type(fdef: Dict[str, Any], name: str) -> Optional[str]:
    """Field type, resolving `external: ecs` references against the ECS schema."""
    ftype = fdef.get("type")
    if ftype:
        return ftype
    if fdef.get("external") == "ecs":
        return (ecs_schema().get(name) or {}).get("type")
    return None


def _declared_multi_valued(field_index: Dict[str, Dict[str, Any]], name: str,
                           array_fields: set, pipeline_arrays: "PipelineFacts") -> bool:
    """Whether `name`, or any object it lives inside, holds a list.

    Index sorting on a multi-valued field is a *correctness* hazard, not a weak pick:
    Lucene picks one value out of the array and every later pruning decision silently
    follows that choice. A member of an array of objects is just as multi-valued as
    the array itself — `aws.cloudtrail.resources.account_id` is one value *per
    resource*, not per event — so every ancestor is checked, from three directions:

      1. the `sample_event.json` shows the ancestor as a list;
      2. the ancestor is declared `type: nested` or `normalize: [array]`;
      3. the ingest pipeline iterates the ancestor (`foreach`, `.stream()`,
         `instanceof List`, a Painless `for (def x : ctx.<path>)` loop).

    (3) is what catches CloudTrail: the sample event has no `resources` at all, and
    `fields.yml` declares it as a plain `group`, but the pipeline builds it with
    `$("json.resources", []).stream()` and `ctx.aws.cloudtrail.resources = new
    ArrayList(...)`.
    """
    parts = name.split(".")
    for i in range(1, len(parts) + 1):
        path = ".".join(parts[:i])
        if path in array_fields:
            return True
        if pipeline_arrays.is_array(path):
            return True
        anc = field_index.get(path)
        if anc is None:
            continue
        if anc.get("type") == "nested":
            return True
        normalize = anc.get("normalize")
        if isinstance(normalize, list) and "array" in normalize:
            return True
        if is_true(anc.get("normalize_as_array")):
            return True
        if anc.get("external") == "ecs" and (ecs_schema().get(path) or {}).get("array"):
            return True
    return False


def _sortable(field_index: Dict[str, Dict[str, Any]], name: str,
              array_fields: set,
              pipeline_arrays: Optional["PipelineFacts"] = None) -> bool:
    """Whether `name` may be used as the leading index-sort field.

    Rejects anything that is not a single-valued identifier-ish type.
    """
    pipeline_arrays = pipeline_arrays or PipelineFacts()
    fdef = field_index.get(name)
    if fdef is None:
        return False
    if name in SORT_EXCLUDED_FIELDS:
        return False
    ftype = resolved_type(fdef, name)
    if ftype not in SORTABLE_TYPES:
        # Also covers `constant_keyword`, `boolean`, all floating-point types,
        # `date`, every type Lucene cannot sort on, and `external: ecs` fields whose
        # ECS type is unknown (the cache is missing) — in which case "no confident
        # candidate" is the right answer anyway.
        return False
    if ftype in SORTABLE_NUMERIC_TYPES and not _numeric_leaf_is_id(name):
        # An integer that is not named like an identifier is a measurement.
        return False
    if is_false(fdef.get("doc_values")):
        return False
    normalize = fdef.get("normalize")
    if normalize and not isinstance(normalize, list):
        return False
    if _declared_multi_valued(field_index, name, array_fields, pipeline_arrays):
        return False
    return True


def _sample_scalar(sample: Dict[str, Any], name: str) -> bool:
    """Whether `sample_event.json` holds a non-empty **scalar** at `name`.

    Handles both the nested (`{"cloud": {"account": {"id": ...}}}`) and the dotted
    (`{"cloud.account.id": ...}`) spellings, and refuses to descend through a list.
    """
    parts = name.split(".")
    for split in range(len(parts), 0, -1):
        node: Any = sample
        ok = True
        for i, part in enumerate(parts[:split]):
            key = part if i < split - 1 else ".".join(parts[split - 1:])
            if not isinstance(node, dict) or key not in node:
                ok = False
                break
            node = node[key]
        if ok:
            return isinstance(node, (str, int, float)) and not isinstance(node, bool) \
                and str(node) != ""
    return False


def _ecs_sample_candidate(name: str, field_index: Dict[str, Dict[str, Any]],
                          sample: Dict[str, Any]) -> bool:
    """Tier 1 acceptance for an ECS field the package never declares.

    ECS fields are installed by the `ecs@mappings` component template, so a package
    that populates `cloud.account.id` in its pipeline has no reason to list it in
    `fields/*.yml` — and most do not (21 streams for `cloud.account.id`, 31 for
    `organization.id`). The sample event is then the only static evidence that the
    field exists at all. Type and array flag still come from the ECS cache, so a
    missing cache falls back to "no confident candidate", the safe direction.
    """
    if name in field_index:
        return False  # declared: the normal `_sortable` path already ruled on it
    if name in SORT_CANDIDATES_COLLECTOR_ONLY:
        return False
    ecs = ecs_schema().get(name)
    if not ecs or ecs.get("array"):
        return False
    if ecs.get("type") not in SORTABLE_STRING_TYPES:
        return False
    return _sample_scalar(sample, name)


# `fields/*.yml` files that describe what **Elastic Agent** adds to every event, not
# what this data stream's events contain. A `cloud.account.id` whose only declaration
# lives here is `add_cloud_metadata` talking about the collector VM.
AGENT_METADATA_FIELD_FILES = {"agent.yml", "beats.yml"}


def _tier1_event_evidence(name: str, field_index: Dict[str, Dict[str, Any]],
                          field_sources: Dict[str, str],
                          pipeline_arrays: PipelineFacts) -> Optional[str]:
    """Why `name` holds the EVENT's tenant rather than the collector's, or None.

    Elastic Agent's `add_cloud_metadata` puts `cloud.account.id`, `cloud.project.id`
    and `cloud.instance.id` on every event it ships, and the generated
    `fields/agent.yml` declares them, so "the field exists" is worth nothing: on a
    poller those are the *collector's* cloud account, one value for the whole data
    stream, which is the worst possible leading sort key. `netflow/log`,
    `kubernetes/audit_logs` and all twelve `elastic_agent/*_logs` streams were being
    proposed `cloud.account.id` on exactly that evidence.

    Two things count as evidence that the *event* carries it:

      * an ingest pipeline of this data stream writes it — a `set` (including
        `copy_from`), `rename`, `append`, grok/dissect target or an allow-listed
        Painless write. `aws/cloudtrail`, `aws/guardduty` and `aws/vpcflow` all set
        `cloud.account.id` from the record, and keep their proposal;
      * the package declares the field itself, with its own description, outside the
        generated agent-metadata files. A bare `external: ecs` stub in `ecs.yml`
        does not count: it asserts nothing about who populates the field.

    A CSPM-style stream where the *input* (not the pipeline) supplies the tenant —
    `cloud_security_posture/findings`, `cloud_asset_inventory/asset_inventory` — is
    rejected here too. That is the intended direction: the audit says "no confident
    candidate; needs human choice" instead of proposing the collector's account id.
    """
    if name in pipeline_arrays.targets:
        return "the data stream's ingest pipeline writes it"
    fdef = field_index.get(name)
    if fdef is not None:
        source_file = field_sources.get(name, "")
        described = str(fdef.get("description") or "").strip()
        if described and source_file not in AGENT_METADATA_FIELD_FILES:
            return f"declared with a package-specific description in `fields/{source_file}`"
    return None


def _tier2_hits(field_index: Dict[str, Dict[str, Any]], leaf: str,
                array_fields: set, pipeline_arrays: PipelineFacts,
                exclude: Optional[set] = None) -> List[str]:
    """Fields whose last one *or two* path segments normalise to `leaf`.

`exclude` keeps tier 1's names out: `cloud.account.id` normalises to `accountid`
    and `organization.id` to `organizationid`, so without it a tier-1 field that was
    just *refused* for want of event evidence would walk straight back in through
    tier 2 (`netflow/log`).

    The two-segment form is how the `<object>.id` spelling of a tenant identifier is
    found: `netbox.tenant.id`, `sentinel_one.*.account.id`,
    `withsecure_elements.security_events.organization.id`, `ocsf.cloud.account.uid`.
    The depth cap is applied to the *effective* depth — the path with the matched
    suffix collapsed to one segment — so those survive it while a tenant id buried in
    a request payload (`...context.http_request.args.client_id`) still does not.
    """
    exclude = exclude or set()
    hits: List[Tuple[int, int, str]] = []
    for name in field_index:
        if name in exclude:
            continue
        for segments in (1, 2):
            if name.count(".") + 1 < segments:
                continue
            if _normalise_leaf(name, segments) != leaf:
                continue
            depth = name.count(".") - (segments - 1)
            if depth > SORT_CANDIDATE_MAX_DEPTH:
                continue
            if not _sortable(field_index, name, array_fields, pipeline_arrays):
                continue
            hits.append((depth, len(name), name))
            break
    return [n for _d, _l, n in sorted(hits)]


def _pick_sort_candidate(field_index: Dict[str, Dict[str, Any]],
                         filter_fields: Counter,
                         array_fields: set,
                         pipeline_arrays: Optional[PipelineFacts] = None,
                         sample: Optional[Dict[str, Any]] = None,
                         allow_agent_id: bool = True,
                         field_sources: Optional[Dict[str, str]] = None,
                         rejected: Optional[List[str]] = None
                         ) -> Tuple[Optional[str], str]:
    """Tiers 1 and 2 — the curated lists, the only tiers that yield a *proposal*.

    Tier 3 (dashboard filter fields) lives in `_dashboard_sort_hint`, because it is
    reported as a human-review hint rather than proposed.
    """
    pipeline_arrays = pipeline_arrays or PipelineFacts()
    sample = sample or {}
    field_sources = field_sources or {}
    # Tier 1: well-known ECS grouping fields, declared or merely populated — but only
    # when the *event* is what populates them (`_tier1_event_evidence`).
    for name in SORT_CANDIDATES:
        if name in SORT_CANDIDATES_COLLECTOR_ONLY and not allow_agent_id:
            continue
        present = (_sortable(field_index, name, array_fields, pipeline_arrays)
                   or _ecs_sample_candidate(name, field_index, sample))
        if not present:
            continue
        if name in TIER1_EVENT_EVIDENCE_FIELDS:
            evidence = _tier1_event_evidence(name, field_index, field_sources,
                                             pipeline_arrays)
            if not evidence:
                if rejected is not None and name not in rejected:
                    rejected.append(name)
                continue
            return name, f"tier 1 (ECS grouping field; {evidence})"
        return name, "tier 1 (ECS grouping field)"
    # Tier 2: vendor tenant/account identifiers, by normalised leaf name. Tier 1's
    # own field names are excluded: tier 1 has already ruled on them, and a name it
    # rejected for want of event evidence must not come back through the leaf match.
    for leaf in SORT_CANDIDATE_LEAVES:
        hits = _tier2_hits(field_index, leaf, array_fields, pipeline_arrays,
                           exclude=set(SORT_CANDIDATES))
        if hits:
            return hits[0], "tier 2 (vendor tenant/account id)"
    return None, ""


def _dashboard_sort_hint(field_index: Dict[str, Dict[str, Any]],
                         filter_fields: Counter,
                         array_fields: set,
                         pipeline_arrays: Optional[PipelineFacts] = None
                         ) -> Optional[str]:
    """Tier 3: a field the package's own dashboards actually FILTER on.

    Being plotted or grouped by is not enough — sorting only pays off for pruning.
    Unlike tiers 1 and 2 this is an uncurated name, so the leaf vocabulary applies
    here. And unlike tiers 1 and 2 the result is only a **hint**: the caller reports
    it as `review_candidate` and writes no `index.sort` YAML, because the vocabulary
    filters out bad *names*, not fields that are merely irrelevant — a dashboard
    filtering on `domaintools.domain` says nothing about whether it is the dataset's
    grouping dimension.
    """
    pipeline_arrays = pipeline_arrays or PipelineFacts()
    for name, _count in filter_fields.most_common(40):
        if name.startswith("_") or _weak_sort_leaf(name):
            continue
        if _sortable(field_index, name, array_fields, pipeline_arrays):
            return name
    return None


def is_low_cardinality(name: str) -> bool:
    """Suffix match on the normalised leaf, and again with a trailing `id`/`uid`.

    Catches `tls_verify_status`, `log_type`, `scanResult`, and the OCSF-style enum
    ids `class_uid`, `severity_id`, `activity_id` — while leaving real identifiers
    (`account_id`, `tenant_id`, `event_id`) alone.
    """
    leaf = _normalise_leaf(name)
    if leaf in LOW_CARDINALITY_EXACT:
        return True
    if leaf in LOW_CARDINALITY_NAME_LEAVES and "." in name:
        # `alert_type.name` is the `alert_type` enum with a nicer spelling.
        parent = name.rsplit(".", 2)[-2] if name.count(".") >= 1 else ""
        if parent and is_low_cardinality(parent):
            return True
    variants = [leaf]
    for suffix in ("uid", "id"):
        if leaf.endswith(suffix) and len(leaf) > len(suffix):
            variants.append(leaf[: -len(suffix)])
            break
    return any(v.endswith(token) for v in variants for token in LOW_CARDINALITY_LEAVES)
