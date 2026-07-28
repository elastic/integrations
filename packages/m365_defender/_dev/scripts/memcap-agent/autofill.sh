#!/usr/bin/env bash
#
# m365_defender agentless memory harness - one-shot autofill.
#
# Runs ./sweep.sh for every stream, then (from the resulting logs/*.csv) recomputes
# the fit + OOM boundaries, writes them into the README "Result (recorded for the
# ORR)" table + the "Agent build measured" provenance, and emits a ready-to-paste
# ORR snippet (memory-profile table + load-test paragraph) under logs/.
#
# This is the unattended path for the ORR memory numbers. It still needs a Docker
# host that can grant the sweep cgroup (see caveats below).
#
# Usage:
#   ./autofill.sh                      # sweep all three streams, fill README + snippet
#   STREAMS="incident" ./autofill.sh   # only some streams
#   SKIP_SWEEP=1 ./autofill.sh         # reuse existing logs/*.csv, just refill
#   ORR_DOC=/path/to/reviews/m365_defender.md ./autofill.sh   # also inject into the ORR (marker-based)
#
# Caveats (the numbers are only valid if these hold):
#   - Docker daemon must be able to grant SWEEP_CAP (default 6g) as a cgroup limit;
#     on Docker Desktop the VM must be sized > SWEEP_CAP or every big-cap run OOMs
#     and the fit fails.
#   - Network access to pull the agent image (AGENT_IMAGE; SNAPSHOT tags may need a
#     registry login), plus the corpus generator built (see README prerequisites).
#   - Runtime is ~tens of minutes (3 streams x several page sizes).
#   - memory.peak wobbles a few % run-to-run; the linear fit absorbs it. Treat every
#     boundary as an engineering ceiling, not a bit-exact number.
#   - ORR_DOC injection only replaces text between <!-- AUTOFILL:START --> and
#     <!-- AUTOFILL:END --> markers; without them the snippet is only written to logs/.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STREAMS="${STREAMS:-alert incident vulnerability}"
SKIP_SWEEP="${SKIP_SWEEP:-0}"
LOGDIR="$HERE/logs"
README="$HERE/README.md"
mkdir -p "$LOGDIR"

command -v python3 >/dev/null || { echo "python3 required"; exit 1; }

# ------------------------- 1. run the sweeps -------------------------
if [ "$SKIP_SWEEP" != "1" ]; then
  for s in $STREAMS; do
    echo ">>>>>>>>>>>>>>>> sweeping $s <<<<<<<<<<<<<<<<"
    STREAM="$s" "$HERE/sweep.sh" || echo "WARN: sweep for $s exited non-zero (continuing)"
  done
else
  echo ">> SKIP_SWEEP=1: reusing existing logs/*.csv"
fi

# ------------------------- 2. parse + write -------------------------
SNIPPET="$LOGDIR/orr-snippet-$(date +%Y%m%d-%H%M%S).md"

STREAMS="$STREAMS" LOGDIR="$LOGDIR" README="$README" SNIPPET="$SNIPPET" \
ORR_DOC="${ORR_DOC:-}" python3 <<'PY'
import csv, glob, os, re, datetime

streams  = os.environ["STREAMS"].split()
logdir   = os.environ["LOGDIR"]
readme   = os.environ["README"]
snippet  = os.environ["SNIPPET"]
orr_doc  = os.environ.get("ORR_DOC", "")
CAP1, CAP2 = 1073741824, 536870912  # 1Gi, 512Mi
MB = 1048576.0

def newest_csv(stream):
    xs = sorted(glob.glob(os.path.join(logdir, f"sweep-{stream}-*.csv")), key=os.path.getmtime)
    return xs[-1] if xs else None

def fit(stream):
    """Return dict with fit + boundaries, or {'ok':False,'reason':...}."""
    path = newest_csv(stream)
    if not path:
        return {"ok": False, "reason": "no sweep CSV found"}
    pts = []
    with open(path) as f:
        for row in csv.DictReader(f):
            try:
                rec, page, peak, oom = int(row["records"]), int(row["raw_page_bytes"]), int(row["memory_peak_bytes"]), row["oom"]
            except (KeyError, ValueError):
                continue
            if oom != "true" and page > 0 and peak > 0:
                pts.append((rec, page, peak))
    if len(pts) < 2:
        return {"ok": False, "reason": f"<2 non-OOM points in {os.path.basename(path)}"}
    n = len(pts)
    sx = sum(p for _, p, _ in pts); sy = sum(k for *_, k in pts)
    sxx = sum(p*p for _, p, _ in pts); sxy = sum(p*k for _, p, k in pts)
    denom = n*sxx - sx*sx
    if denom == 0:
        return {"ok": False, "reason": "degenerate fit (all pages equal)"}
    k = (n*sxy - sx*sy) / denom
    b = (sy - k*sx) / n
    if k <= 0:
        return {"ok": False, "reason": f"non-positive slope k={k:.3f}"}
    per_rec = sum(page/rec for rec, page, _ in pts) / n  # avg bytes/record
    def boundary(cap):
        pb = (cap - b) / k                # raw page bytes that fit
        return pb, (pb/per_rec if per_rec else 0)
    pb1, rc1 = boundary(CAP1)
    pb2, rc2 = boundary(CAP2)
    return {"ok": True, "csv": os.path.basename(path), "n": n, "b": b, "k": k,
            "per_rec": per_rec, "pb1": pb1, "rc1": rc1, "pb2": pb2, "rc2": rc2}

def agent_build():
    """Best-effort provenance from the newest per-run log."""
    runs = sorted(glob.glob(os.path.join(logdir, "run-*.log")), key=os.path.getmtime)
    ver = img = "_unknown_"
    if runs:
        txt = open(runs[-1], errors="ignore").read()
        m = re.search(r"agent version\s*:\s*(\S+)", txt);  ver = m.group(1) if m else ver
        m = re.search(r"agent image\s*:\s*(\S+)", txt);    img = m.group(1) if m else img
    return ver, img, datetime.date.today().isoformat()

results = {s: fit(s) for s in streams}
ver, img, today = agent_build()

def cell_fit(r):   return f"≈{r['b']/MB:.0f} MB + {r['k']:.2f}·page" if r["ok"] else "n/a"
def cell_b1(r):    return f"~{r['pb1']/MB:.0f} MB / ~{r['rc1']:,.0f} recs" if r["ok"] else f"_pending: {r['reason']}_"
def cell_b2(r):    return f"~{r['pb2']/MB:.0f} MB / ~{r['rc2']:,.0f} recs" if r["ok"] else f"_pending: {r['reason']}_"

# ---- update README ----
# Only rewrite stream rows inside the "## Result (recorded for the ORR)" section,
# so the overview table (which also has backticked stream rows) is left untouched.
lines = open(readme).read().splitlines(keepends=False)
out = []
in_result = False
for ln in lines:
    if ln.startswith("## "):
        in_result = ln.strip().lower().startswith("## result")
    m = re.match(r"^\|\s*`(\w+)`\s*\|", ln)
    if in_result and m and m.group(1) in results:
        r = results[m.group(1)]
        out.append(f"| `{m.group(1)}`{' '*(13-len(m.group(1)))}| {cell_fit(r):<24} | {cell_b1(r):<12} | {cell_b2(r):<14} |")
        continue
    ln = re.sub(r"(- version string:\s*)_TODO_", rf"\g<1>`{ver}`", ln)
    ln = re.sub(r"(- image / commit:\s*)_TODO_", rf"\g<1>`{img}`", ln)
    ln = re.sub(r"(- date measured:\s*)_TODO_", rf"\g<1>{today}", ln)
    ln = re.sub(r"^\*\*Agent build measured:\*\* _TODO_", f"**Agent build measured:** {ver}", ln)
    out.append(ln)
open(readme, "w").write("\n".join(out) + "\n")
print(f">> README updated: {readme}")

# ---- ORR snippet ----
def snip():
    L = []
    L.append("## Memory profile (harness-derived) — paste into the ORR\n")
    L.append(f"_Agent build measured: {ver} / {img} / {today}. Steady-state RSS is from "
             "telemetry (fill separately); the columns below are the synthetic worst-case ceiling._\n")
    L.append("| stream | fit (base + k·page) | 1Gi OOM boundary | 512Mi OOM boundary | source CSV |")
    L.append("|---|---|---|---|---|")
    for s in streams:
        r = results[s]
        L.append(f"| `{s}` | {cell_fit(r)} | {cell_b1(r)} | {cell_b2(r)} | {r.get('csv','-')} |")
    L.append("\n**Load test (methodology):** bespoke docker+cgroup harness "
             "(`_dev/scripts/memcap-agent/`); real elastic-agent, agentless env, output held, "
             "`memory.peak` swept across page sizes at a non-OOM cap and fitted to "
             "`base + k·raw_page`. Boundaries are the raw page (and record count) at which "
             "peak reaches the cap. Compare each against the realistic max page the stream can "
             "return; the combined pod footprint is the sum across streams (all run in one pod).")
    return "\n".join(L) + "\n"

body = snip()
open(snippet, "w").write(body)
print(f">> ORR snippet written: {snippet}")

# ---- optional ORR injection (marker-based, non-destructive) ----
if orr_doc and os.path.exists(orr_doc):
    doc = open(orr_doc).read()
    if "<!-- AUTOFILL:START -->" in doc and "<!-- AUTOFILL:END -->" in doc:
        doc = re.sub(r"<!-- AUTOFILL:START -->.*?<!-- AUTOFILL:END -->",
                     "<!-- AUTOFILL:START -->\n" + body + "<!-- AUTOFILL:END -->",
                     doc, flags=re.S)
        open(orr_doc, "w").write(doc)
        print(f">> ORR doc injected between markers: {orr_doc}")
    else:
        print(f">> ORR_DOC has no <!-- AUTOFILL:START/END --> markers; snippet not injected. "
              f"Paste {snippet} manually.")

for s in streams:
    r = results[s]
    print(f"   {s}: " + ("OK "+r['csv'] if r["ok"] else "PENDING - "+r["reason"]))
PY

echo
echo "Done. README result table + ORR snippet updated."
echo "Snippet: $SNIPPET"