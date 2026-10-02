"""Ready-to-paste suggested changes attached to findings."""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# Suggested changes (ready-to-paste snippets attached to findings)
#
# Pipeline snippets follow one convention: they go inline in the pipeline that needs
# them, at the position the change requires, with a `columnar_*` tag and a
# description starting with "columnar:", so `grep columnar_` finds every one. There is
# deliberately no separate "columnar" pipeline file: a pipeline cannot see the index
# mode a document lands in, so these processors run in every mode anyway, and they
# need different positions (a `dot_expander` first, a `copy_to` replacement after the
# processors that set its source).
# --------------------------------------------------------------------------- #

def patch(file: str, position: str, body: str, lang: str = "yaml",
          note: Optional[str] = None) -> Dict[str, Any]:
    """Where a suggested change goes (`file`, `position`) and what to write (`body`)."""
    return {"file": file, "position": position, "lang": lang, "body": body, "note": note}


def _tag_id(name: str) -> str:
    """`crowdstrike.info.host` -> `crowdstrike_info_host`, for processor tags."""
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


DOT_EXPANDER_YAML = (
    "- dot_expander:\n"
    "    tag: columnar_expand_dotted_keys\n"
    "    field: \"*\"\n"
    "    description: >-\n"
    "      columnar: a columnar source returns _source with dotted keys; expand them so\n"
    "      the processors below find their fields. A no-op for nested input.\n"
)

DOT_EXPANDER_JSON = (
    "{\n"
    "  \"dot_expander\": {\n"
    "    \"tag\": \"columnar_expand_dotted_keys\",\n"
    "    \"field\": \"*\",\n"
    "    \"description\": \"columnar: a columnar source returns _source with dotted keys; "
    "expand them so the processors below find their fields. A no-op for nested input.\"\n"
    "  }\n"
    "}\n"
)

# Painless that appends a field's value(s) to one or more targets, creating parent
# objects as needed: `copy_to` semantics (targets gain the values, nothing is
# overwritten, arrays and types are preserved), done at ingest instead of at mapping
# time.
COPY_TO_PAINLESS = """\
def read(def doc, String path) {
  def cur = doc;
  for (String key : path.splitOnToken('.')) {
    if (!(cur instanceof Map)) { return null; }
    cur = cur.get(key);
  }
  return cur;
}
def value = read(ctx, params.field);
if (value == null) { return; }
def values = value instanceof List ? value : [value];
for (String target : params.targets) {
  def parts = target.splitOnToken('.');
  def cur = ctx;
  for (int i = 0; i < parts.length - 1; i++) {
    if (!(cur.get(parts[i]) instanceof Map)) { cur.put(parts[i], new HashMap()); }
    cur = cur.get(parts[i]);
  }
  def last = parts[parts.length - 1];
  def existing = cur.get(last);
  def merged = new ArrayList();
  if (existing instanceof List) { merged.addAll(existing); } else if (existing != null) { merged.add(existing); }
  merged.addAll(values);
  cur.put(last, merged.size() == 1 ? merged.get(0) : merged);
}
"""


def copy_to_snippet(field: str, targets: List[str]) -> str:
    """An ingest `script` processor that replaces `copy_to` on `field`."""
    body = "".join(f"      {ln}\n" if ln else "\n" for ln in COPY_TO_PAINLESS.splitlines())
    return (
        "- script:\n"
        f"    tag: columnar_copy_{_tag_id(field)}\n"
        "    description: >-\n"
        f"      columnar: replaces the copy_to on {field}, which columnar index modes\n"
        "      reject. Runs in every index mode.\n"
        "    lang: painless\n"
        "    params:\n"
        f"      field: {json.dumps(field)}\n"
        f"      targets: [{', '.join(json.dumps(t) for t in targets)}]\n"
        "    source: |-\n"
        + body
    )


# Rewrites each element of a `nested` field so the objects inside it travel as dotted
# keys: `{"Id": "a", "Meta": {"Owner": "u1"}}` becomes `{"Id": "a", "Meta.Owner": "u1"}`,
# and an array of objects becomes one array per leaf. Columnar indexes an object sent as
# JSON inside a nested element as a nested document of its own, detached from the
# element (`nested_object_children`); dotted keys are not affected, and logsdb maps both
# forms the same way. A list holding anything but objects is left as it is.
NESTED_DOTTED_PAINLESS = """\
def read(def doc, String path) {
  def cur = doc;
  for (String key : path.splitOnToken('.')) {
    if (!(cur instanceof Map)) { return null; }
    cur = cur.get(key);
  }
  return cur;
}
void add(Map out, String key, def value) {
  def existing = out.get(key);
  List merged = new ArrayList();
  if (existing instanceof List) { merged.addAll(existing); } else if (existing != null) { merged.add(existing); }
  if (value instanceof List) { merged.addAll(value); } else { merged.add(value); }
  out.put(key, merged);
}
void flatten(Map src, String prefix, Map out) {
  for (def entry : src.entrySet()) {
    String key = prefix + entry.getKey();
    def value = entry.getValue();
    if (value instanceof Map) {
      flatten(value, key + '.', out);
      continue;
    }
    boolean objects = value instanceof List && !value.isEmpty();
    if (objects) {
      for (def item : value) { if (!(item instanceof Map)) { objects = false; } }
    }
    if (!objects) {
      out.put(key, value);
      continue;
    }
    for (def item : value) {
      Map leaves = new HashMap();
      flatten(item, key + '.', leaves);
      for (def leaf : leaves.entrySet()) { add(out, leaf.getKey(), leaf.getValue()); }
    }
  }
}
def elements = read(ctx, params.field);
if (elements == null) { return; }
for (def element : (elements instanceof List ? elements : [elements])) {
  if (!(element instanceof Map)) { continue; }
  Map flat = new HashMap();
  flatten(element, '', flat);
  element.clear();
  element.putAll(flat);
}
"""


def nested_dotted_snippet(field: str) -> str:
    """An ingest `script` processor sending the objects inside `field`'s elements as dotted keys."""
    body = "".join(f"      {ln}\n" if ln else "\n" for ln in NESTED_DOTTED_PAINLESS.splitlines())
    return (
        "- script:\n"
        f"    tag: columnar_nested_dotted_{_tag_id(field)}\n"
        "    description: >-\n"
        f"      columnar: sends the objects inside each {field} element as dotted\n"
        "      keys, so columnar keeps them with their element. Runs in every index mode.\n"
        "    lang: painless\n"
        "    params:\n"
        f"      field: {json.dumps(field)}\n"
        "    source: |-\n"
        + body
    )


def runtime_snippet(field: str, script: str) -> str:
    """A skeleton ingest `script` processor for a mapping-level runtime field."""
    lines = [
        "- script:",
        f"    tag: columnar_compute_{_tag_id(field)}",
        "    description: >-",
        f"      columnar: computes {field} at ingest time; columnar index modes reject",
        "      mapping-level runtime fields. Runs in every index mode.",
        "    lang: painless",
        "    source: |-",
        "      // Port of the runtime script below: read ctx values instead of",
        f"      // doc['...'].value, and assign {field} (creating its parent objects)",
        "      // instead of calling emit().",
    ]
    lines += [f"      // {ln}" for ln in script.splitlines()]
    return "\n".join(lines) + "\n"


def _runtime_script(runtime: Any) -> Optional[str]:
    """The script of a mapping-level runtime field, when it has one."""
    if isinstance(runtime, str) and runtime.strip().lower() not in ("true", "false"):
        return runtime
    if isinstance(runtime, dict):
        script = runtime.get("script")
        if isinstance(script, dict):
            script = script.get("source")
        if isinstance(script, str):
            return script
    return None


def attach_pipeline_patches(findings: List[Dict[str, Any]],
                            field_index: Dict[str, Dict[str, Any]],
                            ds_dir: str, pkg_dir: str) -> None:
    """Attach ingest-pipeline snippets to `copy_to`, `runtime_field` and
    `nested_object_children` findings.

    The fixes move logic from the mapping into the data stream's default pipeline,
    which is resolved here (YAML or JSON; created if the stream has none).
    """
    pipe_dir = os.path.join(ds_dir, "elasticsearch", "ingest_pipeline")
    existing = next((n for n in ("default.yml", "default.yaml", "default.json")
                     if os.path.isfile(os.path.join(pipe_dir, n))), None)
    pipe_file = os.path.relpath(os.path.join(pipe_dir, existing or "default.yml"), pkg_dir)
    extra = ""
    if existing == "default.json":
        extra = " The pipeline is JSON: convert the snippet."
    elif not existing:
        extra = " The data stream has no default pipeline yet: create it with this processor."
    for f in findings:
        if f.get("patch") or not f.get("field"):
            continue
        fdef = field_index.get(f["field"]) or {}
        if f["code"] == "copy_to":
            raw = fdef.get("copy_to")
            targets = [raw] if isinstance(raw, str) else [str(t) for t in (raw or [])]
            if not targets:
                continue
            f["patch"] = patch(
                pipe_file,
                f"near the end of `processors:`, after the processors that set `{f['field']}` "
                f"and before any that read " + ", ".join(f"`{t}`" for t in targets),
                copy_to_snippet(f["field"], targets),
                note="Then delete `copy_to` from the field definition (it applies in every "
                     "index mode) and regenerate the pipeline test expectations with `-g`: "
                     "the targets now appear in the documents." + extra)
        elif f["code"] == "nested_object_children":
            f["patch"] = patch(
                pipe_file,
                f"at the end of `processors:`, after every processor that builds or reads "
                f"`{f['field']}`",
                nested_dotted_snippet(f["field"]),
                note=f"Only the elements of `{f['field']}` change. A `@custom` pipeline runs "
                     "after it and sees dotted keys there. Regenerate the pipeline test "
                     "expectations with `-g` (the elements now carry dotted keys) and diff "
                     "them before accepting." + extra)
        elif f["code"] == "runtime_field":
            script = _runtime_script(fdef.get("runtime"))
            if script:
                f["patch"] = patch(
                    pipe_file,
                    "near the end of `processors:`, after the processors that set the fields "
                    "the script reads",
                    runtime_snippet(f["field"], script),
                    note="A skeleton: port the script by hand, then map the field with a "
                         "concrete type instead of `runtime`." + extra)
            else:
                f["patch"] = patch(
                    f["where"], f"the definition of `{f['field']}`",
                    f"- name: {fdef.get('name', f['field'])}\n"
                    f"  type: {fdef.get('type', 'keyword')}   # keep the type; delete `runtime: true`\n",
                    note="`runtime: true` without a script reads the value from the document, "
                         "so a concrete mapping needs no pipeline change.")
