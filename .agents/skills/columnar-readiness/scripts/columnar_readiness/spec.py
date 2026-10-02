"""package-spec 3.7.0 columnar constructs: the override block, the readiness flag, spec and Kibana versions."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# package-spec 3.7.0 columnar constructs
#
# 1. Field-level, mode-scoped override block. Fleet applies it ONLY when the
#    resolved index mode is `logsdb_columnar` or `columnar` — the same way it
#    only emits TSDB's `dimension: true` for `time_series`:
#
#        - name: event.original
#          external: ecs
#          columnar:
#            doc_values: true    # only `true` is valid
#
#    That mode scoping is the point: the same package version installed on a
#    logsdb or standard stack keeps today's mapping byte for byte, so repairing
#    a columnar blocker costs nothing on the installs that are not columnar.
#
#    The block also accepts `index`, for a field whose exact-value lookups the
#    stream's dashboards or detection rules depend on. Whether a stream needs any
#    is a per-stream human decision ("none" is a valid answer): this audit lists
#    lookup candidates from the rules and dashboards, and reports an existing
#    override, but never writes one (rollout rule 2).
#
#    Fleet applies it to STATIC LEAF FIELDS ONLY. It does not apply it to a
#    field it renders as a `dynamic_templates` entry (`type: object`/`group`
#    with `object_type`), nor to anything under `multi_fields:`, and
#    package-spec 3.7.0 rejects the block in both places. A `doc_values: false`
#    there has no scoped fix: `columnar_override_misplaced`.
#
# 2. Stream-level readiness flag in `data_stream/<ds>/manifest.yml`:
#
#        elasticsearch:
#          columnar:
#            supported: true
#
#    The 3.7.0 validator enforces zero columnar blockers when it is set, and
#    Fleet only offers the per-stream opt-in toggle for streams that set it (or
#    that already declare a columnar `index_mode`).
#
# Both require `format_version: "3.7.0"` (`columnar_requires_spec_3_7`) and a
# `conditions.kibana.version` of at least COLUMNAR_KIBANA_CONSTRAINT, because
# both are read by Fleet and a Kibana without that support ignores them.
# --------------------------------------------------------------------------- #


def columnar_block(container: Any) -> Dict[str, Any]:
    """The mode-scoped `columnar:` block of a field definition or of the
    `elasticsearch:` section of a data stream manifest ({} when absent)."""
    if not isinstance(container, dict):
        return {}
    block = container.get("columnar")
    return block if isinstance(block, dict) else {}


def existing_index_sort(es_section: Any) -> Optional[Dict[str, List[str]]]:
    """The `index.sort` a data stream manifest already declares, or None.

    Read so the report can say "already present" instead of proposing a sort the
    package has had for three releases. Package sources write the settings both
    nested (`index: {sort: {field: [...]}}`) and with dotted keys
    (`index.sort.field: [...]`), so both are flattened before the lookup.
    """
    if not isinstance(es_section, dict):
        return None
    itpl = es_section.get("index_template")
    settings = itpl.get("settings") if isinstance(itpl, dict) else None
    if not isinstance(settings, dict):
        return None
    flat: Dict[str, Any] = {}

    def walk(node: Dict[str, Any], prefix: str) -> None:
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict):
                walk(value, path)
            else:
                flat[path] = value

    walk(settings, "")
    fields = flat.get("index.sort.field")
    if fields is None:
        return None
    listed = lambda v: [str(x) for x in (v if isinstance(v, list) else [v])]  # noqa: E731
    orders = flat.get("index.sort.order")
    return {"field": listed(fields), "order": listed(orders) if orders is not None else []}


# The package-spec version that introduced both columnar constructs.
COLUMNAR_SPEC_VERSION = (3, 7)

# `conditions.kibana.version` a migrated package has to declare.
#
# The constraint is NOT about Elasticsearch: 9.5 already has the index mode.
# It is about Fleet. Fleet has to (a) parse `elasticsearch.columnar.supported`
# in order to offer the per-stream opt-in toggle at all, and (b) apply the
# field-level `columnar:` overrides when it builds the mapping — on the install
# path and on the toggle path. A Kibana without those changes silently ignores
# both: the toggle is not offered, and a manual columnar opt-in still ships the
# unpatched `doc_values: false`, so the index template PUT fails. So the
# constraint must be at least the first Kibana minor that ships that Fleet
# support, which is 9.6.
COLUMNAR_KIBANA_CONSTRAINT = "^9.6.0"
COLUMNAR_KIBANA_NOTE = (
    "the Fleet support ships in 9.6; on older Kibana the override and the flag are "
    "silently ignored, so the toggle is unavailable and any `doc_values: false` field "
    "will make a manual columnar opt-in fail"
)

# The constraint is not free, and this is the sentence the package owner has to read
# before declaring readiness. `conditions.kibana.version: "^9.6.0"` (and the
# `format_version: "3.7.0"` bump that goes with it) RAISES THE PACKAGE'S MINIMUM
# STACK VERSION to 9.6: Fleet will not offer the new package version to a stack older
# than that, so every user still on 9.5 or below stops receiving this package's
# updates altogether — not just the columnar ones. Fixing a bug for those users then
# needs a backport: a separate release line off the last pre-9.6 version. That is a
# real, recurring maintenance cost, so readiness is declared deliberately, for the
# packages chosen as tech-preview targets, and not swept across the catalog.
COLUMNAR_MIN_STACK_COST = (
    "**Cost:** declaring `columnar.supported` (and bumping `format_version` to "
    "`\"3.7.0\"`) raises this package's **minimum stack version to 9.6**. Users on an "
    "older stack stop receiving *any* further update to this package, so a bug fix for "
    "them needs a backport branch/release line. That makes it a **breaking change**: "
    "ship it as a **major** version bump with a `type: breaking-change` changelog entry "
    "(\"Raise the minimum required Kibana version to 9.6.0 …\") alongside the "
    "`enhancement` one — the convention elastic/integrations follows for a Kibana floor "
    "raise (`aws` 7.0.0, `aws_bedrock` 2.0.0, `aws_bedrock_agentcore` 1.0.0). Declare "
    "readiness deliberately, for the packages picked as tech-preview targets — not "
    "catalog-wide."
)

# Finding codes that describe the columnar *declaration* itself rather than a
# mapping feature Elasticsearch or the validator would reject on its own merits.
# They are excluded when deciding whether a `columnar.supported: true` stream is
# inconsistent, so the report does not accuse a declaration of blocking itself.
DECLARATION_CODES = {"columnar_requires_spec_3_7", "columnar_supported_with_blockers"}


def spec_version_tuple(raw: Any) -> Optional[Tuple[int, int]]:
    """(major, minor) of a `format_version`, or None if it cannot be parsed.

    Tolerates pre-release suffixes (`3.7.0-next`, `3.7.0-rc1`).
    """
    if raw is None:
        return None
    text = str(raw).strip().strip('"').strip("'")
    if not text:
        return None
    text = re.split(r"[-+]", text, maxsplit=1)[0]
    parts = text.split(".")
    try:
        return (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
    except (ValueError, IndexError):
        return None


def spec_supports_columnar(raw: Any) -> bool:
    """True when `format_version` is >= 3.7.0.

    An unparseable / missing `format_version` returns True: the audit does not
    invent a finding it cannot substantiate.
    """
    parsed = spec_version_tuple(raw)
    if parsed is None:
        return True
    return parsed >= COLUMNAR_SPEC_VERSION


# Severity drives the data stream status:
#   blocker  -> BLOCKED              (Class A, no mechanical fix)
#   auto_fix -> READY_AFTER_AUTO_FIX (Class A, mechanical fix available)
#   review   -> NEEDS_REVIEW         (data loss, or a judgement call)
#   info     -> no status impact     (Class C behaviour change)
