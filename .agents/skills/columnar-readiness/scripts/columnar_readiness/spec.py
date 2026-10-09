"""package-spec 3.7.0 `logsdb_columnar` setting, spec and Kibana versions."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# How a package declares LogsDB columnar readiness (package-spec 3.7.0, as reshaped
# by the elastic/package-spec#1250 review)
#
# One setting, `elasticsearch.logsdb_columnar`, at two levels:
#
#     # manifest.yml (package)
#     elasticsearch:
#       logsdb_columnar: opt_in        # opt_in | default; absent = not ready
#
#     # data_stream/<name>/manifest.yml
#     elasticsearch:
#       logsdb_columnar: unsupported   # opt_in | default | unsupported
#
# * It applies to `type: logs` data streams only: the package value is ignored for
#   metrics and traces streams, and a non-logs stream that sets it is an error.
# * It only applies when `index_mode` is unset. `index_mode` stays for fixed modes the
#   user cannot change (`time_series`); setting both is an error. There is no
#   `index_mode: logsdb_columnar`, and no plain `columnar` mode for integrations.
# * Fleet offers one toggle per integration and stores the user's choice once per
#   installation. `opt_in` offers it; `default` turns it on for new installations
#   only: existing data streams keep their mode, also when a package upgrade changes
#   `opt_in` to `default`.
# * A later version can mark a data stream `unsupported` again. Fleet then moves it
#   back to LogsDB at the next rollover and tells the user why. For the package that is
#   a breaking change: major version bump and a `breaking-change` changelog entry.
# * Mode changes take effect on the next rollover.
# * There is no field-level `columnar:` block. `doc_values: false` (and `store: true`)
#   is for Elasticsearch or Fleet to handle in columnar mode, not for every package;
#   a field that needs an inverted index sets `index: true` itself, which changes
#   nothing on LogsDB.
#
# Using the setting needs `format_version: "3.7.0"` (`logsdb_columnar_requires_spec_3_7`)
# and a `conditions.kibana.version` of at least COLUMNAR_KIBANA_CONSTRAINT, because
# Fleet reads it and a Kibana without that support ignores it.
# --------------------------------------------------------------------------- #

LOGSDB_COLUMNAR_KEY = "logsdb_columnar"
# Values a data stream may set; the package level allows the first two only.
LOGSDB_COLUMNAR_STREAM_VALUES = ("opt_in", "default", "unsupported")
LOGSDB_COLUMNAR_PACKAGE_VALUES = ("opt_in", "default")


def logsdb_columnar_value(es_section: Any) -> Optional[str]:
    """`elasticsearch.logsdb_columnar` of a manifest, or None when unset."""
    if not isinstance(es_section, dict) or es_section.get(LOGSDB_COLUMNAR_KEY) is None:
        return None
    return str(es_section.get(LOGSDB_COLUMNAR_KEY)).strip()


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


# The package-spec version that introduces `elasticsearch.logsdb_columnar`.
COLUMNAR_SPEC_VERSION = (3, 7)

# `conditions.kibana.version` a migrated package has to declare.
#
# The constraint is NOT about Elasticsearch: 9.5 already has the index mode. It is
# about Fleet, which has to parse `elasticsearch.logsdb_columnar` to offer the
# toggle at all. A Kibana without that support silently ignores the setting. So
# the constraint must be at least the first Kibana minor that ships the Fleet
# support, which is 9.6.
COLUMNAR_KIBANA_CONSTRAINT = "^9.6.0"
COLUMNAR_KIBANA_NOTE = (
    "the Fleet support ships in 9.6; older Kibana silently ignores "
    "`elasticsearch.logsdb_columnar`, so the toggle is unavailable"
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
    "**Cost:** declaring `elasticsearch.logsdb_columnar` (and bumping `format_version` to "
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

# Finding codes that describe the `logsdb_columnar` *declaration* itself rather than
# a mapping feature Elasticsearch or the validator would reject on its own merits.
# They are excluded when deciding whether a declared-ready stream is inconsistent,
# so the report does not accuse a declaration of blocking itself.
DECLARATION_CODES = {
    "logsdb_columnar_requires_spec_3_7",
    "logsdb_columnar_with_blockers",
    "logsdb_columnar_with_index_mode",
    "logsdb_columnar_not_logs",
    "index_mode_columnar",
}


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


# The stacks whose Fleet installs a package, by `format_version` major.minor: Kibana's
# `REGISTRY_SPEC_MAX_VERSION` on the 8.11 to 9.5 release branches (the patch number is
# ignored). 9.0 stops at 3.3, so 3.4 skips it. Serverless needs 3.0 or newer.
SPEC_MIN_STACK = {
    (3, 0): "8.11+",
    (3, 1): "8.16+",
    (3, 2): "8.16+",
    (3, 3): "8.16+",
    (3, 4): "8.19 and 9.1+, not 9.0",
    (3, 5): "9.2+",
    (3, 6): "9.4+",
}


def spec_min_stack(raw: Any) -> str:
    """The stacks whose Fleet installs a package with this `format_version`."""
    parsed = spec_version_tuple(raw)
    if parsed is None:
        return "unknown"
    if parsed < (3, 0):
        return "stateful stacks only (serverless needs 3.0+)"
    if parsed in SPEC_MIN_STACK:
        return SPEC_MIN_STACK[parsed]
    return ("no released Kibana yet: the newest accept up to 3.6, and 3.7 needs the 9.6 "
            "Fleet support")


def kibana_allows_8x(condition: Any) -> bool:
    """Whether any `||` branch of `conditions.kibana.version` starts below 9.0."""
    if not condition:
        return True
    for branch in str(condition).split("||"):
        match = re.search(r"(\d+)\.", branch)
        if match and int(match.group(1)) <= 8:
            return True
    return False


def installs_on_8x(format_version: Any, condition: Any) -> bool:
    """Whether 8.x stacks can still install the package (spec 3.4 at most, and a
    `conditions.kibana.version` that admits 8.x); declaring columnar ends that."""
    parsed = spec_version_tuple(format_version)
    return parsed is not None and parsed <= (3, 4) and kibana_allows_8x(condition)


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
