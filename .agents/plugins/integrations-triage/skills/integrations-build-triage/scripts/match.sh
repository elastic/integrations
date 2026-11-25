#!/usr/bin/env bash
# Classify every failed package of a build against what is already known.
# Usage: match.sh <failures.tsv> <known.tsv> [signatures.tsv]
#   failures.tsv  from collect.sh (pkg, tests, link, detail)
#   known.tsv     workspace memory: pkg, tests, detail, cause_id, cause, tracked (comma-separated owner/repo#n)
#   signatures    generic families (default: ../references/signatures.tsv)
# Output (TSV): pkg, status, cause_id, cause, tracked, link
#   KNOWN    same package, same failing tests, same detail as a known cause  -> no reasoning needed
#   CHANGED  package known, but tests or detail differ (new failure, or an earlier test type now hides/reveals one)
#   SIG:<id> new package matching a generic family                          -> needs a quick verification
#   UNKNOWN  nothing matches                                                 -> investigate
# Also prints known packages that no longer fail (DROPPED).
set -euo pipefail
F=${1:?failures.tsv}; K=${2:?known.tsv}
SIG=${3:-$(dirname "$0")/../references/signatures.tsv}
[ -f "$K" ] || printf 'pkg\ttests\tdetail\tcause_id\tcause\ttracked\n' > "$K"

awk -F'\t' -v OFS='\t' '
  FILENAME==ARGV[1] { if (FNR>1) { kt[$1]=$2; kd[$1]=$3; kc[$1]=$4; kn[$1]=$5; kr[$1]=$6 } next }
  FILENAME==ARGV[2] { if (FNR>1) { n++; sid[n]=$1; st[n]=$2; sre[n]=$3; spk[n]=$4; sfam[n]=$5 } next }
  FNR==1 { print "pkg","status","cause_id","cause","tracked","link"; next }
  {
    pkg=$1; tests=$2; link=$3; detail=$4; seen[pkg]=1
    if (pkg in kc) {
      if (kt[pkg]==tests && kd[pkg]==detail) print pkg,"KNOWN",kc[pkg],kn[pkg],kr[pkg],link
      else print pkg,"CHANGED",kc[pkg],"was: " kn[pkg] " | now: " tests " :: " detail,kr[pkg],link
      next
    }
    type="any"; if (match(tests, /\((pipeline|policy|system|script|static|asset)\)/)) type=substr(tests,RSTART+1,RLENGTH-2)
    hit=""
    for (i=1;i<=n;i++) if ((st[i]=="any" || st[i]==type) && detail ~ sre[i] && pkg ~ spk[i]) { hit=i; break }
    if (hit!="") print pkg,"SIG:" sid[hit],sid[hit],sfam[hit] " :: " detail,"",link
    else print pkg,"UNKNOWN","",tests " :: " detail,"",link
  }
  END { for (p in kc) if (!(p in seen)) print p,"DROPPED",kc[p],kn[p],kr[p],"" }
' "$K" "$SIG" "$F" | { IFS= read -r h; echo "$h"; sort -t$'\t' -k2,2 -k3,3 -k1,1; }
