"""Library behind `scripts/audit.py`, the columnar-readiness audit.

Modules, in dependency order:

- `constants`, `spec`, `common`, `ecs`: shared vocabulary, package-spec 3.7.0
  constructs, YAML loading, the finding record and ECS definitions.
- `fields`, `patches`: the mapping checks and the snippets attached to them.
- `pipelines`, `kibana`, `sorting`: evidence for the index sort proposal.
- `consumers`, `transforms`, `rules`: `_source` consumers, `latest` transforms
  and the prebuilt detection rules that query a stream.
- `packages`: audits one package or data stream from all of the above.
- `report`: renders the markdown reports.
"""

import sys

try:
    import yaml  # noqa: F401  (checked here so a missing PyYAML fails with instructions)
except ImportError:  # pragma: no cover
    sys.exit(
        "PyYAML is required.\n"
        "  python3 -m pip install --user pyyaml\n"
        "or use a venv:\n"
        "  python3 -m venv /tmp/columnar-venv && /tmp/columnar-venv/bin/pip install pyyaml\n"
        "  /tmp/columnar-venv/bin/python3 <skill-dir>/scripts/audit.py <package>"
    )
