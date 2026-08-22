#!/usr/bin/env python3
"""Generate copy-paste TS evaluation snippets + one merged enrichment query."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent
P1 = ROOT.parent / "p1"

SECTION_HEADINGS: dict[str, str] = {
    "Detection flags (mandatory — run first)": "detection_flags",
    "Optional classification helpers (when needed)": "optional_classification",
    "Combined ES|QL — actor fields": "actor",
    "Combined ES|QL — event action": "event_action",
    "Combined ES|QL — target fields": "target",
}

SKIP_HEADINGS_PREFIX = (
    "Full pipeline fragment",
    "Streams excluded",
    "Gaps and limitations",
    "Dataset inventory",
    "Field mapping plan",
)

ENRICHMENT_PHASES = ("actor", "event_action", "target", "optional_classification")
SKIP_COLUMNS_SNAPSHOT = frozenset({"host.ip", "host.target.ip"})
PRESERVE_RE = re.compile(r"^\S+\s+IS NOT NULL$")


def export_name(integration: str) -> str:
    return f"{integration}Evaluations"


def extract_esql_section(md: str) -> str | None:
    start = md.find("## ES|QL Entity Extraction")
    if start == -1:
        return None
    rest = md[start + 1 :]
    m = re.search(r"\n## [^#]", rest)
    end = start + 1 + m.start() if m else len(md)
    return md[start:end]


def extract_evaluations(section: str) -> list[dict[str, str]]:
    snippets: list[dict[str, str]] = []
    seen_ids: dict[str, int] = {}

    parts = re.split(r"^### (.+)$", section, flags=re.MULTILINE)
    i = 1
    while i < len(parts):
        heading = parts[i].strip()
        body = parts[i + 1] if i + 1 < len(parts) else ""
        i += 2

        if any(heading.startswith(p) for p in SKIP_HEADINGS_PREFIX):
            continue

        base_id = SECTION_HEADINGS.get(heading)
        if base_id is None:
            continue

        for block in re.findall(r"```esql\n(.*?)```", body, re.DOTALL):
            block = block.strip()
            if block.startswith("FROM ") or not block.startswith("| EVAL"):
                continue

            count = seen_ids.get(base_id, 0)
            seen_ids[base_id] = count + 1
            sid = base_id if count == 0 else f"{base_id}_{count + 1}"
            snippets.append({"id": sid, "section": heading, "esql": block})

    return snippets


def split_top_level(input: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    in_string: str | None = None
    start = 0

    for i, c in enumerate(input):
        if in_string:
            if c == "\\":
                continue
            if c == in_string:
                in_string = None
            continue
        if c in ('"', "'"):
            in_string = c
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(input[start:i].strip())
            start = i + 1

    tail = input[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def find_matching_paren(input: str, open_idx: int) -> int:
    depth = 0
    in_string: str | None = None
    for i in range(open_idx, len(input)):
        c = input[i]
        if in_string:
            if c == "\\":
                continue
            if c == in_string:
                in_string = None
            continue
        if c in ('"', "'"):
            in_string = c
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
    raise ValueError(f"Unbalanced parens: {input[open_idx:open_idx + 40]!r}")


@dataclass
class CaseBranch:
    condition: str
    value: str


@dataclass
class ParsedAssignment:
    column: str
    has_preserve: bool
    branches: list[CaseBranch] = field(default_factory=list)
    default_value: str = "null"


def split_eval_assignments(eval_body: str) -> list[tuple[str, str]]:
    body = re.sub(r"^\|\s*EVAL\s*\n?", "", eval_body).strip()
    assignments: list[tuple[str, str]] = []
    cursor = 0

    while cursor < len(body):
        while cursor < len(body) and body[cursor] in ", \t\n\r":
            cursor += 1
        if cursor >= len(body):
            break

        marker = body.find(" = CASE(", cursor)
        if marker == -1:
            break

        column = body[cursor:marker].strip()
        open_paren = marker + len(" = CASE(") - 1
        close_paren = find_matching_paren(body, open_paren)
        case_expr = body[marker + len(" = ") : close_paren + 1].strip()
        assignments.append((column, case_expr))
        cursor = close_paren + 1

    return assignments


def parse_case_expression(column: str, case_expr: str) -> ParsedAssignment:
    if not (case_expr.startswith("CASE(") and case_expr.endswith(")")):
        raise ValueError(f"Expected CASE(...) for {column}")

    args = split_top_level(case_expr[5:-1])
    index = 0
    has_preserve = False

    if len(args) >= 2 and PRESERVE_RE.match(args[0]) and args[1].strip() == column:
        has_preserve = True
        index = 2

    tail = args[index:]
    default_value = "null"
    branch_args = tail
    if len(tail) % 2 == 1:
        default_value = tail[-1].strip()
        branch_args = tail[:-1]

    branches = [
        CaseBranch(branch_args[i].strip(), branch_args[i + 1].strip())
        for i in range(0, len(branch_args), 2)
    ]
    return ParsedAssignment(column, has_preserve, branches, default_value)


def parse_eval_snippet(esql: str) -> list[ParsedAssignment]:
    return [parse_case_expression(col, expr) for col, expr in split_eval_assignments(esql)]


def merge_assignments(left: ParsedAssignment, right: ParsedAssignment) -> ParsedAssignment:
    seen: set[str] = set()
    branches: list[CaseBranch] = []
    for branch in left.branches + right.branches:
        key = f"{branch.condition}\0{branch.value}"
        if key in seen:
            continue
        seen.add(key)
        branches.append(branch)
    return ParsedAssignment(
        left.column,
        left.has_preserve or right.has_preserve,
        branches,
        left.default_value or right.default_value,
    )


def format_case(assignment: ParsedAssignment) -> str:
    parts: list[str] = []
    if assignment.has_preserve:
        parts.extend([f"{assignment.column} IS NOT NULL", assignment.column])
    for branch in assignment.branches:
        parts.extend([branch.condition, branch.value])
    parts.append(assignment.default_value)

    lines = [f"    {part}{',' if idx < len(parts) - 1 else ''}" for idx, part in enumerate(parts)]
    return f"  {assignment.column} = CASE(\n" + "\n".join(lines) + "\n  )"


def build_merged_query(all_snippets: list[list[dict[str, str]]]) -> str:
    lines: list[str] = []

    for phase in ENRICHMENT_PHASES:
        by_column: dict[str, ParsedAssignment] = {}

        for snippets in all_snippets:
            for snip in snippets:
                if snip["id"] != phase:
                    continue
                for assignment in parse_eval_snippet(snip["esql"]):
                    existing = by_column.get(assignment.column)
                    by_column[assignment.column] = (
                        merge_assignments(existing, assignment)
                        if existing
                        else assignment
                    )

        if not by_column:
            continue

        body = ",\n".join(
            format_case(a)
            for col, a in sorted(by_column.items())
            if col not in SKIP_COLUMNS_SNAPSHOT
        )
        if not body:
            continue
        lines.append(f"| EVAL\n{body}")

    return "\n".join(lines) + "\n"


def emit_integration_ts(integration: str, snippets: list[dict[str, str]]) -> str:
    name = export_name(integration)
    lines = [
        'import type { IntegrationEvaluations } from "./types";',
        "",
        f"export const {name} = {{",
        f'  integration: "{integration}",',
        "  evaluations: [",
    ]
    for snip in snippets:
        lines.append("    {")
        lines.append(f"      id: {json.dumps(snip['id'])},")
        lines.append(f"      section: {json.dumps(snip['section'])},")
        esql_body = snip["esql"].replace("`", "\\`").replace("${", "\\${")
        lines.append(f"      esql: `{esql_body}`,")
        lines.append("    },")
    lines.append("  ],")
    lines.append("} as const satisfies IntegrationEvaluations;")
    lines.append("")
    return "\n".join(lines)


def write_registry(integrations: list[str]) -> None:
    lines = ['import type { IntegrationEvaluations } from "./types";', ""]
    for integration in integrations:
        lines.append(f'import {{ {export_name(integration)} }} from "./{integration}";')
    lines.append("")
    lines.append("/** All integration evaluation snippets keyed by package code. */")
    lines.append("export const allIntegrationEvaluations = {")
    for integration in integrations:
        lines.append(f'  "{integration}": {export_name(integration)},')
    lines.append("} as const satisfies Record<string, IntegrationEvaluations>;")
    lines.append("")
    (ROOT / "registry.ts").write_text("\n".join(lines))


def emit_index(integrations: list[str]) -> str:
    lines = [
        'export type { EvaluationSnippet, IntegrationEvaluations } from "./types";',
        'export { allIntegrationEvaluations } from "./registry";',
        "export {",
        "  buildEnrichmentQuery,",
        "  listIntegrationsWithEvaluations,",
        "  ENRICHMENT_PHASES,",
        '} from "./buildEnrichmentQuery";',
        'export type { BuildEnrichmentQueryOptions, EnrichmentPhase } from "./buildEnrichmentQuery";',
        "",
    ]
    for integration in integrations:
        lines.append(f'export {{ {export_name(integration)} }} from "./{integration}";')
    lines.append("")
    return "\n".join(lines)


def emit_types() -> str:
    return """/** One `| EVAL` step from Pass 4 domain documentation. */
export interface EvaluationSnippet {
  readonly id: string;
  readonly section: string;
  readonly esql: string;
}

export interface IntegrationEvaluations {
  readonly integration: string;
  readonly evaluations: readonly EvaluationSnippet[];
}
"""


def main() -> None:
    integrations: list[str] = []
    all_snippets: list[list[dict[str, str]]] = []

    for md in sorted(P1.glob("*.md")):
        integration = md.stem
        integrations.append(integration)
        section = extract_esql_section(md.read_text())
        snippets = extract_evaluations(section) if section else []
        all_snippets.append(snippets)
        (ROOT / f"{integration}.ts").write_text(emit_integration_ts(integration, snippets))

    query = build_merged_query(all_snippets)
    (ROOT / "enrichmentQuery.esql").write_text(query)
    (ROOT / "types.ts").write_text(emit_types())
    write_registry(integrations)
    (ROOT / "index.ts").write_text(emit_index(integrations))

    print(f"Wrote {len(integrations)} integration files + registry.ts + enrichmentQuery.esql (snapshot)")


if __name__ == "__main__":
    main()
