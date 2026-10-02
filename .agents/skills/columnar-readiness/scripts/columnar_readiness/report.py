"""Markdown reporting."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, List, Tuple

from .common import location
from .constants import COLUMNAR_INDEX_MODES, STATUS_ORDER
from .ecs import ecs_source
from .rules import RULES_PACKAGE
from .sorting import SUPPORTED_YAML_BODY, sort_yaml
from .spec import (
    COLUMNAR_KIBANA_CONSTRAINT,
    COLUMNAR_KIBANA_NOTE,
    COLUMNAR_MIN_STACK_COST,
    DECLARATION_CODES,
)


def columnar_optin_label(stream: Dict[str, Any]) -> str:
    """How (and whether) the data stream is already columnar-enabled.

    Two independent declarations, and the difference matters:
      * `elasticsearch.columnar.supported: true` — the stream is *ready*; Fleet
        exposes the per-stream opt-in toggle, but logsdb stays the default.
      * `elasticsearch.index_mode: logsdb_columnar` — columnar is *forced* for every
        install of this package version: Fleet locks the toggle on (the API cannot
        turn it off either), and existing streams switch at the next rollover.
    """
    mode = stream.get("index_mode")
    parts: List[str] = []
    if mode in COLUMNAR_INDEX_MODES:
        parts.append(f"**columnar forced** via `index_mode: {mode}` — every install of this "
                     f"package version is columnar, users cannot opt out, and existing "
                     f"streams switch at the next rollover")
    if stream.get("columnar_supported"):
        parts.append("**declared ready** via `elasticsearch.columnar.supported: true` — "
                     "Fleet offers the per-stream opt-in toggle; users have to turn it on")
    if not parts:
        return ("not declared (`elasticsearch.columnar.supported` unset, no columnar "
                "`index_mode`) — Fleet offers no opt-in for this stream yet")
    label = "; ".join(parts)
    blocking = [f for f in stream.get("findings", [])
                if f["class"] == "A" and f["code"] not in DECLARATION_CODES]
    if blocking:
        code = (" (`columnar_supported_with_blockers`)"
                if stream.get("columnar_supported_with_blockers") else "")
        label += (f". **Inconsistent**{code}: the stream still has {len(blocking)} Class A "
                  "finding(s), which the 3.7.0 columnar validator rejects — fix them or "
                  "drop the declaration")
    # Plumbing pointer only. The 9.6 minimum-stack cost is stated ONCE, in the
    # package header: repeating it per data stream turned a one-stream report into
    # three copies of the same paragraph, which is how a warning stops being read.
    label += (f". Plumbing: `format_version: \"3.7.0\"` + "
              f"`conditions.kibana.version: \"{COLUMNAR_KIBANA_CONSTRAINT}\"` — see the "
              f"package header for the 9.6 minimum-stack cost")
    return label


def kibana_condition_meets_columnar(condition: Any) -> bool:
    """Whether `conditions.kibana.version` already floors the package at 9.6+.

    The condition is a semver range, usually with several `||` branches
    (`"^8.19.0 || ^9.1.0"`). EVERY branch has to be 9.6 or newer: one older branch is
    enough for Fleet to keep offering the package to a stack that ignores both
    columnar constructs, which is exactly the case the constraint exists to prevent.
    That is why the remediation is "replace the whole range", not "add a branch".
    """
    if not condition:
        return False
    branches = [b.strip() for b in str(condition).split("||") if b.strip()]
    if not branches:
        return False
    for branch in branches:
        match = re.search(r"(\d+)\.(\d+)", branch)
        if not match or (int(match.group(1)), int(match.group(2))) < (9, 6):
            return False
    return True


def stream_manifest_block(s: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """(YAML body lines, notes) for the one `elasticsearch:` key of a stream manifest.

    The readiness flag and the index sort live under the same `elasticsearch:`
    mapping, so they are emitted merged — a reader who pastes two snippets gets a
    duplicate key and loses one of them.

    Anything the manifest already declares becomes a note ("already present") instead
    of a proposal: the audit is run again after the migration, and a report that still
    says "add this" about a line that is already there is indistinguishable from a
    migration that did not take.
    """
    body: List[str] = []
    notes: List[str] = []

    if s.get("columnar_supported"):
        notes.append("`elasticsearch.columnar.supported: true` already present")
    elif s["status"] in ("READY", "READY_AFTER_AUTO_FIX"):
        body.extend(SUPPORTED_YAML_BODY.rstrip("\n").split("\n"))
    else:
        notes.append(f"`columnar.supported: true` is not proposed while this stream is "
                     f"{s['status']} — the 3.7.0 validator rejects the flag until the "
                     f"findings below are resolved")

    sort = s["sort"]
    existing = s.get("existing_index_sort")
    if existing:
        shown = _sort_summary(existing["field"], existing["order"])
        note = f"explicit `index.sort` already present ({shown})"
        proposed = _sort_summary(sort["sort_fields"], sort["sort_orders"])
        if sort["explicit_sort_yaml"] and shown != proposed:
            note += (f" — the audit would propose {proposed}; keep the existing sort "
                     f"unless the dataset says otherwise, changing it rewrites the "
                     f"segment layout on the next rollover")
        notes.append(note)
    elif sort["explicit_sort_yaml"]:
        body.extend(sort_yaml(sort["sort_fields"], sort["sort_orders"],
                               header=False).rstrip("\n").split("\n"))
    elif sort["class"] == "default_ok":
        notes.append("no `index.sort` to write — the `logsdb_columnar` logs profile "
                     "already sorts on `host.name asc, @timestamp desc`")
    return body, notes


def stream_manifest_placement(s: Dict[str, Any]) -> str:
    """Where the emitted `elasticsearch:` block goes in this stream's manifest.

    Two different edits, and the reader cannot tell which one they are making from
    the snippet alone: a manifest that already has an `elasticsearch:` key needs the
    children merged into it (a second key is a duplicate and YAML silently keeps one
    of them), while a manifest with no such key needs it added as a brand-new
    top-level key. `has_es_key` is read from the manifest, so the line states which.
    """
    ds = s["data_stream"]
    if s.get("has_es_key"):
        return (f"merge the block below into the existing `elasticsearch:` key of "
                f"`data_stream/{ds}/manifest.yml` — a manifest has a **single** "
                f"`elasticsearch:` key, so add these children to the one already "
                f"there; a second `elasticsearch:` is a duplicate key and the file "
                f"keeps only one of them")
    return (f"add the block below to `data_stream/{ds}/manifest.yml` (there is no "
            f"`elasticsearch:` key yet) — it goes in as a new top-level key, "
            f"conventionally after `streams:` at the end of the file")


def _sort_summary(fields: List[str], orders: List[str]) -> str:
    """`organization.id asc, @timestamp desc`, for prose rather than YAML."""
    pairs = []
    for idx, field in enumerate(fields):
        order = orders[idx] if idx < len(orders) else ""
        pairs.append(f"`{field}`" + (f" {order}" if order else ""))
    return ", ".join(pairs) or "(no fields)"


def source_consumer_line(result: Dict[str, Any], s: Dict[str, Any]) -> str:
    """The `_source` consumer result for one stream, stated in words even when empty.

    A negative result has to be printed: an absent Class C section reads as "not
    checked", and the migration decision depends on knowing which one it was.
    """
    sc = s.get("source_consumers") or {}
    rules_scanned = (s.get("detection_rules") or {}).get("scanned")
    hits: List[str] = []
    if sc.get("transform"):
        hits.append(f"{sc['transform']} transform script(s) (`source_consumer_transform`)")
    if sc.get("latest_transform"):
        hits.append(f"{sc['latest_transform']} `latest` transform(s) "
                    f"(`source_consumer_latest_transform`)")
    if sc.get("kibana"):
        hits.append(f"{sc['kibana']} `kibana/` asset(s) (`source_consumer_kibana`)")
    if sc.get("detection_rule"):
        hits.append(f"{sc['detection_rule']} shipped detection rule(s) "
                    f"(`source_consumer_detection_rule`)")
    if hits:
        head = "**" + ", ".join(hits) + "** — see the Class C findings below"
    else:
        head = ("none found (no transform script reading `_source`, no `latest` transform, "
                "no scripted/runtime fields or ES|QL `METADATA _source` in `kibana/`"
                + (", no shipped detection rule reading `_source`" if rules_scanned else "")
                + ")")
    if sc.get("object_arrays"):
        arrays = "see `object_array_flattening` below"
    else:
        arrays = ("none in the sampled documents (`sample_event.json` and up to four "
                  "`_dev/test/pipeline/*-expected.json`)")
    exempt = sc.get("flattened_exempt") or []
    if exempt:
        arrays += ("; fields of type `flattened` are exempt, they keep their JSON "
                   "verbatim: " + ", ".join(f"`{f}`" for f in exempt))
    tail = ("" if rules_scanned else
            " Detection rules were **not** scanned (no `packages/security_detection_engine` "
            "next to this package, or `--no-rules`), so rules reading `_source` are unknown.")
    return f"`_source` consumers: {head}; object arrays: {arrays}.{tail}"


def detection_rules_repo_line(info: Dict[str, Any]) -> str:
    """Whether an `elastic/detection-rules` checkout was scanned for `_source` readers."""
    if info.get("dir"):
        return (f"`elastic/detection-rules`: scanned `{info['dir']}` (`rules/` and `hunting/`, "
                f"{info.get('files', 0)} files) for `_source` readers")
    looked = ", ".join(f"`{p}`" for p in info.get("looked_at") or [])
    return ("`elastic/detection-rules`: no checkout found"
            + (f" (looked at {looked})" if looked else "")
            + ", so hunting queries were not scanned for `_source` readers. Pass "
              "`--detection-rules DIR` or set `DETECTION_RULES_PATH`")


def detection_rules_line(s: Dict[str, Any]) -> str:
    """Which shipped rules query the stream: the rule half of the performance workload."""
    dr = s.get("detection_rules") or {}
    if not dr.get("scanned"):
        return "Detection rules: not scanned."
    if not dr.get("specific") and not dr.get("broad"):
        return "Detection rules: no shipped rule queries this stream."
    langs = ", ".join(f"{n} {lang}" for lang, n in (dr.get("by_language") or {}).items())
    parts = [f"{dr['specific']} shipped rule(s) query this stream directly"
             + (f" ({langs})" if langs else "")]
    if dr.get("broad"):
        parts.append(f"{dr['broad']} more match its indices without targeting it (`logs-*`, "
                     "or a package-wide pattern whose query names another data stream)")
    readers = len(dr.get("reading_source") or [])
    parts.append(f"{readers} read `_source`" if readers else "none reads `_source`")
    if dr.get("repo_readers"):
        parts.append(f"{len(dr['repo_readers'])} more `_source` reader(s) in "
                     f"`elastic/detection-rules` ({', '.join(dr['repo_readers'][:3])})")
    return ("Detection rules: " + "; ".join(parts) + ". Replay the direct ones (EQL and "
            "KQL are Query DSL underneath) in the performance tests.")


def query_templates_line(s: Dict[str, Any]) -> str:
    """The package's own alerting rule and SLO templates that query the stream."""
    qt = s.get("query_templates") or {}
    rules, slos = qt.get("alerting_rule_template", 0), qt.get("slo_template", 0)
    if not rules and not slos:
        return ""
    counts = ", ".join(part for part in (
        f"{rules} alerting rule template(s)" if rules else "",
        f"{slos} SLO template(s)" if slos else "") if part)
    names = qt.get("names") or []
    return (f"Alerting rule and SLO templates: {counts} shipped by this package query this "
            f"stream ({', '.join(f'“{n}”' for n in names[:4])}{', …' if len(names) > 4 else ''}). "
            "They must return the same results on columnar; add them to the query checks.")


def lookup_candidates_line(s: Dict[str, Any]) -> str:
    """Lookup candidates for the per-stream `index: true` review."""
    cands = s.get("lookup_candidates") or []
    if not cands:
        return ("Lookup candidates for the `index: true` review: none (no shipped rule or "
                "scanned dashboard filter references a `keyword`/`ip` field outside the "
                "sort key).")
    items = []
    for c in cands:
        src = []
        if c.get("rules"):
            src.append(f"{c['rules']} rule{'s' if c['rules'] != 1 else ''}")
        if c.get("dashboard_filters"):
            n = c["dashboard_filters"]
            src.append(f"{n} dashboard filter{'s' if n != 1 else ''}")
        items.append(f"`{c['field']}`" + (" (high-risk lookup)" if c.get("high_risk") else "")
                     + (f": {', '.join(src)}" if src else ""))
    return ("Lookup candidates for the `index: true` review, a starting point and not a "
            "recommendation (\"none\" is a valid decision): " + "; ".join(items) + ".")


def text_subfields_line(s: Dict[str, Any]) -> str:
    subs = s.get("text_subfields") or []
    shown = ", ".join(f"`{t}`" for t in subs[:8]) + (", …" if len(subs) > 8 else "")
    return (f"Text sub-fields (they keep an inverted index in columnar; input for the ECS "
            f"`.text` review): {len(subs)}" + (f", {shown}" if subs else "")
            + ". Sub-fields that `ecs@mappings` adds at index time are not counted.")


# Human-readable gloss for statuses whose name alone overstates what was checked.
STATUS_GLOSS = {
    "READY": "no mapping blocker found; this is not a validation result",
}


def status_label(status: str) -> str:
    gloss = STATUS_GLOSS.get(status)
    return f"**{status}** ({gloss})" if gloss else f"**{status}**"


def md_package(result: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append(f"# Columnar readiness: `{result['package']}`")
    lines.append("")
    lines.append(f"- Status: {status_label(result['status'])}")
    lines.append(f"- Package type: `{result.get('type')}`, version `{result.get('version')}`, "
                 f"format_version `{result.get('format_version')}` (Fleet installs it on "
                 f"{result.get('spec_min_stack', 'unknown')})")
    lines.append(f"- ECS definitions: {ecs_source()}")
    if result.get("detection_rules_scanned"):
        lines.append(f"- Detection rules: {result['detection_rules_scanned']} shipped rules "
                     f"scanned (latest version of each, from `{RULES_PACKAGE}`)")
    else:
        lines.append("- Detection rules: not scanned")
    if result.get("detection_rules_repo"):
        lines.append(f"- {detection_rules_repo_line(result['detection_rules_repo'])}")
    if result.get("kibana_condition"):
        if kibana_condition_meets_columnar(result["kibana_condition"]):
            lines.append(f"- Kibana condition: `{result['kibana_condition']}` — already at "
                         f"the `{COLUMNAR_KIBANA_CONSTRAINT}` floor the columnar constructs "
                         f"need; nothing to change ({COLUMNAR_KIBANA_NOTE})")
        else:
            lines.append(
                f"- Kibana condition: `{result['kibana_condition']}` — declaring readiness "
                f"means **replacing the whole range** with "
                f"`conditions.kibana.version: \"{COLUMNAR_KIBANA_CONSTRAINT}\"`, not adding "
                f"a branch to it: every `||` branch has to be 9.6+, so the older branches "
                f"go away. That is the point of the declaration *and* its cost — if this "
                f"package must keep serving older stacks, do not declare readiness on this "
                f"release line ({COLUMNAR_KIBANA_NOTE})")
        lines.append(f"- {COLUMNAR_MIN_STACK_COST}")
    if result.get("out_of_scope_reason"):
        lines.append(f"- Out of scope: {result['out_of_scope_reason']}")
    for err in result.get("errors", []):
        lines.append(f"- Parse error: {err}")
    lines.append("")

    in_scope = [s for s in result["data_streams"] if s["status"] != "OUT_OF_SCOPE"]
    skipped = [s for s in result["data_streams"] if s["status"] == "OUT_OF_SCOPE"]

    if in_scope:
        lines.append("| Data stream | Status | Findings | Index sort |")
        lines.append("| --- | --- | --- | --- |")
        for s in in_scope:
            lines.append(f"| `{s['data_stream']}` | {s['status']} | {len(s['findings'])} | "
                         f"{s['sort']['recommendation']} |")
        lines.append("")

    for s in in_scope:
        lines.append(f"## `{s['data_stream']}` — {s['status']}")
        lines.append("")
        lines.append(f"- Inputs: {', '.join(f'`{i}`' for i in s['inputs']) or '(none declared)'}")
        lines.append(f"- Current `index_mode`: `{s['index_mode'] or 'unset (logsdb default)'}`")
        lines.append(f"- Columnar opt-in: {columnar_optin_label(s)}")
        lines.append(f"- Sort: **{s['sort']['recommendation']}** — {s['sort']['reason']}")
        lines.append(f"- {source_consumer_line(result, s)}")
        lines.append(f"- {detection_rules_line(s)}")
        templates_line = query_templates_line(s)
        if templates_line:
            lines.append(f"- {templates_line}")
        lines.append(f"- {lookup_candidates_line(s)}")
        lines.append(f"- {text_subfields_line(s)}")
        body, notes = stream_manifest_block(s)
        segments: List[str] = list(notes)
        if body:
            segments.append(stream_manifest_placement(s))
        lines.append("- Stream manifest: "
                     + ("; ".join(segments) if segments else "nothing to add") + ".")
        if body:
            lines.append("")
            lines.append("  ```yaml")
            lines.append("  elasticsearch:")
            for ln in body:
                lines.append(f"  {ln}")
            lines.append("  ```")
        lines.append("")
        if not s["findings"]:
            lines.append("No blocking or lossy mapping features found.")
            lines.append("")
            continue
        for klass, title in (("A", "Class A — rejected by Elasticsearch"),
                             ("B", "Class B — accepted but lossy"),
                             ("C", "Class C — behaviour change")):
            group = [f for f in s["findings"] if f["class"] == klass]
            if not group:
                continue
            lines.append(f"### {title}")
            lines.append("")
            for f in group:
                tag = " (auto-fixable)" if f["auto_fixable"] else ""
                lines.append(f"- `{f['code']}`{tag} — {f['message']}")
                lines.append(f"  - Where: `{location(f)}`")
                for idx, ln in enumerate(f["remediation"].split("\n")):
                    lines.append(f"  - {ln}" if idx == 0 else f"    {ln}")
                p = f.get("patch")
                if p:
                    lines.append(f"  - **Suggested change** in `{p['file']}`, {p['position']}:")
                    lines.append("")
                    lines.append(f"    ```{p.get('lang') or 'yaml'}")
                    for ln in p["body"].rstrip("\n").split("\n"):
                        lines.append(f"    {ln}" if ln else "")
                    lines.append("    ```")
                    if p.get("note"):
                        lines.append("")
                        lines.append(f"    {p['note']}")
            lines.append("")

    if skipped:
        lines.append("## Out of scope")
        lines.append("")
        for s in skipped:
            lines.append(f"- `{s['data_stream']}`: {s.get('out_of_scope_reason', 'skipped')}")
        lines.append("")
    if result.get("dashboard_top_fields"):
        lines.append("## Dashboard fields (benchmark workload)")
        lines.append("")
        lines.append(", ".join(f"`{f}`" for f in result["dashboard_top_fields"]))
        lines.append("")
    if result.get("dashboard_filter_fields"):
        lines.append("## Dashboard filter fields (sort tie-break)")
        lines.append("")
        lines.append("Fields used in a filter pill or KQL query clause — the only "
                     "dashboard evidence the sort heuristic accepts.")
        lines.append("")
        lines.append(", ".join(f"`{f}`" for f in result["dashboard_filter_fields"]))
        lines.append("")
    # `latest` transforms that read none of this package's in-scope streams. Each is
    # flagged on the other packages' logs streams it reads, if any; the rest read
    # metrics streams or indices no package here owns. Listed so none is dropped silently.
    stray = [tr for tr in result.get("latest_transforms") or [] if not tr.get("streams")]
    if stray:
        lines.append("## `latest` transforms that read no stream of this package")
        lines.append("")
        lines.append("None of this package's in-scope logs streams carries a finding for "
                     "them. One that reads another package's logs stream is flagged on that "
                     "stream, and the fix is discussed here, in the package that owns it.")
        lines.append("")
        for tr in stray:
            flagged = tr.get("flagged_on") or []
            where = ("flagged on " + ", ".join(f"`{s}`" for s in flagged) if flagged
                     else "reads no in-scope logs stream of a package in this repo, so no "
                          "columnar opt-in here changes its output")
            lines.append(f"- `{tr['name']}` (`{tr['file']}`): "
                         + ", ".join(f"`{p}`" for p in tr["patterns"]) + f" — {where}")
        lines.append("")
    if in_scope and result.get("detection_rules_scanned"):
        lines.append("## Detection rules in the PR notes")
        lines.append("")
        lines.append("Record the per-stream **Detection rules** lines above in the PR, with "
                     "both numbers: \"N shipped rules query this stream; none read "
                     "`_source`\", or \"no shipped rule queries this stream\". Rules a user "
                     "wrote, or installed from elsewhere, are not covered.")
        lines.append("")
    return "\n".join(lines)


def md_catalog(results: List[Dict[str, Any]]) -> str:
    by_status: Dict[str, List[str]] = {st: [] for st in STATUS_ORDER}
    for r in results:
        by_status[r["status"]].append(r["package"])

    stream_status: Counter = Counter()
    for r in results:
        for s in r["data_streams"]:
            stream_status[s["status"]] += 1

    # code -> {package -> set(data streams)}
    by_code: Dict[str, Dict[str, set]] = {}
    code_class: Dict[str, Tuple[str, str]] = {}
    for r in results:
        for s in r["data_streams"]:
            for f in s["findings"]:
                by_code.setdefault(f["code"], {}).setdefault(r["package"], set()).add(s["data_stream"])
                code_class[f["code"]] = (f["class"], f["severity"])

    def code_rows(codes: List[str]) -> List[str]:
        out: List[str] = []
        for code in codes:
            pkgs = by_code.get(code)
            if not pkgs:
                continue
            nstreams = sum(len(v) for v in pkgs.values())
            klass, sev = code_class[code]
            out.append(f"### `{code}` — class {klass}, {sev}")
            out.append("")
            out.append(f"{len(pkgs)} packages, {nstreams} data streams.")
            out.append("")
            for pkg in sorted(pkgs):
                out.append(f"- `{pkg}`: " + ", ".join(sorted(pkgs[pkg])))
            out.append("")
        return out

    def union(codes: List[str]) -> Tuple[int, int, List[str]]:
        pkgs: Dict[str, set] = {}
        for code in codes:
            for pkg, streams in by_code.get(code, {}).items():
                pkgs.setdefault(pkg, set()).update(streams)
        return len(pkgs), sum(len(v) for v in pkgs.values()), sorted(pkgs)

    lines: List[str] = []
    lines.append("# Columnar readiness — catalog audit")
    lines.append("")
    in_scope_pkgs = sum(1 for r in results
                        if any(s["status"] != "OUT_OF_SCOPE" for s in r["data_streams"]))
    lines.append(f"Packages scanned: {len(results)}")
    lines.append(f"Candidate packages (at least one in-scope `type: logs` data stream): "
                 f"{in_scope_pkgs}")
    on_8x = sum(1 for r in results if r.get("installs_on_8x")
                and any(s["status"] != "OUT_OF_SCOPE" for s in r["data_streams"]))
    lines.append(f"Candidate packages still installable on 8.x: {on_8x} (`format_version` 3.4 "
                 f"or older and a `conditions.kibana.version` that admits 8.x). Declaring "
                 f"columnar moves each of them to 9.6+.")
    lines.append(f"ECS definitions: {ecs_source()}")
    rules_scanned = max((r.get("detection_rules_scanned") or 0) for r in results) if results else 0
    lines.append(f"Detection rules: {rules_scanned} shipped rules scanned (latest version of "
                 f"each, from `{RULES_PACKAGE}`)" if rules_scanned
                 else "Detection rules: not scanned")
    repo_info = next((r["detection_rules_repo"] for r in results if r.get("detection_rules_repo")),
                     None)
    if repo_info:
        lines.append(detection_rules_repo_line(repo_info))
    lines.append("")
    lines.append("| Status | Packages | Logs data streams |")
    lines.append("| --- | --- | --- |")
    for st in ("BLOCKED", "NEEDS_REVIEW", "READY_AFTER_AUTO_FIX", "READY"):
        label = f"{st} ({STATUS_GLOSS[st]})" if st in STATUS_GLOSS else st
        lines.append(f"| {label} | {len(by_status[st])} | {stream_status[st]} |")
    lines.append(f"| OUT_OF_SCOPE (input package / no logs streams / OTel input) | "
                 f"{len(by_status['OUT_OF_SCOPE'])} | {stream_status['OUT_OF_SCOPE']} |")
    lines.append("")
    otel_streams = [(r["package"], s_["data_stream"]) for r in results for s_ in r["data_streams"]
                    if "OpenTelemetry input" in (s_.get("out_of_scope_reason") or "")]
    if otel_streams:
        lines.append(f"OTel log streams out of scope until derived fields land "
                     f"({len(otel_streams)}): "
                     + ", ".join(f"`{p}`/{d}" for p, d in sorted(otel_streams)))
        lines.append("")

    # Streams that already carry one of the package-spec 3.7.0 columnar
    # declarations. Omitted entirely while the count is zero, so the section
    # only appears once the rollout has actually landed somewhere.
    supported = [(r["package"], s_["data_stream"]) for r in results for s_ in r["data_streams"]
                 if s_.get("columnar_supported")]
    default_mode = [(r["package"], s_["data_stream"]) for r in results for s_ in r["data_streams"]
                    if s_.get("index_mode") in COLUMNAR_INDEX_MODES]
    if supported or default_mode:
        lines.append("## Already columnar-enabled")
        lines.append("")
        plural = lambda n: "data stream" if n == 1 else "data streams"  # noqa: E731
        if supported:
            lines.append(f"`elasticsearch.columnar.supported: true` — opt-in toggle offered, "
                         f"logsdb still the default ({len(supported)} {plural(len(supported))}): "
                         + ", ".join(f"`{p}`/{d}" for p, d in sorted(supported)))
            lines.append("")
        if default_mode:
            lines.append(f"Columnar `index_mode` — columnar is forced: every install of the "
                         f"version, the Fleet toggle is locked on, and existing streams switch "
                         f"at the next rollover ({len(default_mode)} {plural(len(default_mode))}): "
                         + ", ".join(f"`{p}`/{d}" for p, d in sorted(default_mode)))
            lines.append("")

    BLOCKER_CODES = ["nested_in_nested", "unsupported_type", "source_mode_stored", "source_disabled"]
    AUTOFIX_SRC_CODES = ["doc_values_false", "store_true", "copy_to", "keyword_normalizer",
                         "dynamic_runtime"]
    LOSS_CODES = ["dynamic_false_manifest", "dynamic_false_field", "dynamic_false_template",
                  "enabled_false"]

    npkg, nds, _ = union(BLOCKER_CODES)
    lines.append(f"## Blockers — Class A, no mechanical fix ({npkg} packages, {nds} data streams)")
    lines.append("")
    lines.extend(code_rows(BLOCKER_CODES) or ["(none)", ""])

    npkg, nds, pkglist = union(BLOCKER_CODES + ["doc_values_false"])
    lines.append("## Hard mapping errors declared in the package source "
                 f"({npkg} packages, {nds} data streams)")
    lines.append("")
    lines.append("Union of `nested_in_nested` and `doc_values_false`. This is the set the "
                 "preliminary catalog analysis called *blocked*; under the status rules in "
                 "`references/report-template.md` the `doc_values_false` ones are "
                 "READY_AFTER_AUTO_FIX because the fix is mechanical: keep the existing "
                 "`doc_values: false` and add a mode-scoped "
                 "`columnar: {doc_values: true}` beside it, so logsdb and standard installs "
                 "of the same package version are unchanged. (On the two placements Fleet "
                 "does not apply overrides to — a `multi_fields:` entry, or an "
                 "`object_type` dynamic-template field — there is no scoped form and the "
                 "`doc_values: false` has to be deleted outright, in every index mode.)")
    lines.append("")
    lines.append(", ".join(f"`{p}`" for p in pkglist) or "(none)")
    lines.append("")

    npkg, nds, _ = union(AUTOFIX_SRC_CODES)
    lines.append("## Class A, mechanically fixable — declared in the package source "
                 f"({npkg} packages, {nds} data streams)")
    lines.append("")
    lines.extend(code_rows(AUTOFIX_SRC_CODES) or ["(none)", ""])

    npkg, nds, _ = union(["doc_values_false_ecs"])
    lines.append("## Class A, mechanically fixable — inherited from ECS "
                 f"({npkg} packages, {nds} data streams)")
    lines.append("")
    lines.append("`external: ecs` imports `doc_values` from the ECS schema into the built "
                 "package, so these never appear in the package source. See "
                 "`references/blockers.md`.")
    lines.append("")
    lines.extend(code_rows(["doc_values_false_ecs"]) or ["(none)", ""])

    npkg, nds, pkglist = union(LOSS_CODES)
    lines.append(f"## Data-loss review — Class B ({npkg} packages, {nds} data streams)")
    lines.append("")
    lines.append(", ".join(f"`{p}`" for p in pkglist) or "(none)")
    lines.append("")
    lines.extend(code_rows(LOSS_CODES))

    REVIEW_CODES = ["nested_single_level", "runtime_field",
                    "source_consumer_transform", "source_consumer_kibana"]
    npkg, nds, _ = union(REVIEW_CODES)
    lines.append(f"## Judgement calls — review ({npkg} packages, {nds} data streams)")
    lines.append("")
    lines.extend(code_rows(REVIEW_CODES) or ["(none)", ""])

    # `_source` readers outside the mappings: shipped detection rules and `latest`
    # transforms. Nothing fails when a stream with one of them goes columnar; the reader
    # silently gets the flat shape, which is why they are called out on their own.
    CONSUMER_CODES = ["source_consumer_detection_rule", "source_consumer_latest_transform"]
    npkg, nds, _ = union(CONSUMER_CODES)
    lines.append(f"## `_source` readers outside the mappings — review "
                 f"({npkg} packages, {nds} data streams)")
    lines.append("")
    lines.append("Shipped detection rules that read `_source` (they silently stop matching on "
                 "columnar), and `latest` transforms, which copy `_source` into their "
                 "destination index (whose documents change shape, and whose destination "
                 "pipeline may stop finding fields). See `references/blockers.md` C6-C10.")
    lines.append("")
    lines.extend(code_rows(CONSUMER_CODES) or ["(none)", ""])
    fix_pipes = sorted({(r["package"], t["dest_pipeline"]) for r in results
                        for t in r.get("latest_transforms") or []
                        if t.get("dest_pipeline") and "/" in t["dest_pipeline"]
                        and not t.get("expands_dotted")})
    if fix_pipes:
        owners = sorted({p for p, _ in fix_pipes})
        lines.append(f"{len(fix_pipes)} `latest` transform destination pipelines need a leading "
                     f"`dot_expander` with `field: \"*\"` ({', '.join(f'`{p}`' for p in owners)}); "
                     f"the per-package report prints the snippet for each file.")
        lines.append("")
    if rules_scanned:
        direct = sum(1 for r in results for s_ in r["data_streams"]
                     if (s_.get("detection_rules") or {}).get("specific"))
        lines.append(f"Shipped rules query {direct} in-scope logs data streams directly; the "
                     "per-package report lists them, as the rule half of each stream's "
                     "performance workload.")
        lines.append("")

    # Problems with the package-spec 3.7.0 columnar declarations themselves.
    # Kept out of the blocker/auto-fix sections above on purpose: those count
    # mapping features, these count mistakes in the opt-in plumbing. Omitted
    # while empty, like "Already columnar-enabled".
    DECLARATION_PROBLEM_CODES = ["columnar_supported_with_blockers",
                                 "columnar_requires_spec_3_7",
                                 "columnar_override_misplaced",
                                 "columnar_doc_values_false"]
    npkg, nds, _ = union(DECLARATION_PROBLEM_CODES)
    if npkg:
        lines.append("## Columnar declaration problems "
                     f"({npkg} packages, {nds} data streams)")
        lines.append("")
        lines.append("Mistakes in the package-spec 3.7.0 opt-in plumbing itself, not in "
                     "the mappings. See `references/blockers.md`.")
        lines.append("")
        lines.extend(code_rows(DECLARATION_PROBLEM_CODES))

    INFO_CODES = ["keyword_normalizer_lowercase", "object_array_flattening"]
    npkg, nds, _ = union(INFO_CODES)
    lines.append("## Informational — Class C "
                 f"({npkg} packages, {nds} data streams)")
    lines.append("")
    lines.append("`object_array_flattening` changes no status: it records that the data "
                 "stream's own example documents contain object arrays, whose columnar "
                 "`_source` shape is flattened into parallel arrays. Queries on the leaf "
                 "fields are unaffected; `_source` readers are not. See "
                 "`references/blockers.md` C8.")
    lines.append("")
    lines.extend(code_rows(INFO_CODES) or ["(none)", ""])

    lines.append("## Packages by status")
    lines.append("")
    for st in ("BLOCKED", "NEEDS_REVIEW", "READY_AFTER_AUTO_FIX", "READY"):
        pkgs = sorted(by_status[st])
        gloss = f" — {STATUS_GLOSS[st]}" if st in STATUS_GLOSS else ""
        lines.append(f"### {st} ({len(pkgs)}){gloss}")
        lines.append("")
        lines.append(", ".join(f"`{p}`" for p in pkgs) or "(none)")
        lines.append("")

    sort_class: Counter = Counter()
    for r in results:
        for s in r["data_streams"]:
            if s["status"] == "OUT_OF_SCOPE":
                continue
            sort_class[s["sort"].get("class", "no_candidate")] += 1
    lines.append("## Index sort")
    lines.append("")
    lines.append(f"- Default `host.name asc, @timestamp desc` looks right: "
                 f"{sort_class['default_ok']} data streams")
    lines.append(f"- Default would degrade to `@timestamp` only (incompatible `host.name` "
                 f"mapping): {sort_class['degraded']} data streams")
    lines.append(f"- Receiver input, explicit sort proposed on the device identifier the "
                 f"pipeline populates: {sort_class['receiver_proposed']} data streams")
    lines.append(f"- Receiver input, no confident candidate — needs a human choice: "
                 f"{sort_class['receiver_no_candidate']} data streams")
    lines.append(f"- Explicit sort proposed on a validated grouping field: "
                 f"{sort_class['explicit']} data streams (run the audit per package to see "
                 "the proposal)")
    lines.append(f"- No confident candidate, but the package's dashboards filter on "
                 f"something — reported as a hint, no sort proposed: "
                 f"{sort_class['review_candidate']} data streams")
    lines.append(f"- No confident candidate — `@timestamp desc` only, needs a human choice: "
                 f"{sort_class['no_candidate']} data streams")
    lines.append("")
    lines.append("Candidate fields are validated: `keyword` and `ip` are accepted, integer "
                 "types only when the leaf name says the field is an identifier rather than "
                 "a measurement, and the field must have doc values. Arrays are rejected — "
                 "ECS `normalize: [array]`, a list in `sample_event.json`, a `nested` or "
                 "list-valued *ancestor*, or an object the ingest pipeline iterates. The "
                 "dashboard tier additionally requires the field to appear in a filter or "
                 "query clause, not merely on an axis, and drops measurement, hash/uuid, "
                 "free-text, plural and enum leaf names — but even then it only yields a "
                 "hint for a human, never an `index.sort` proposal.")
    lines.append("")
    if not any(r.get("dashboard_filter_fields") for r in results):
        lines.append("Kibana assets were not scanned **for sort hints** (`--catalog` "
                     "defaults to `--no-dashboards`), so the dashboard tier never fired "
                     "and the \"no confident candidate\" count is an upper bound. Re-run "
                     "with `--dashboards`, or audit the package on its own, before "
                     "concluding that a data stream has no grouping field. (The "
                     "`source_consumer_kibana` scan runs either way.)")
        lines.append("")
    return "\n".join(lines)
