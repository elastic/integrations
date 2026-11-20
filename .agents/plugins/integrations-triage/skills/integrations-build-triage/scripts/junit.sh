#!/usr/bin/env bash
# Download the JUnit XML artifacts of one Buildkite job into a directory (the want/got diff of pipeline tests is there).
# Usage: junit.sh [-p <pipeline>] [-k <pkg>] <build-number> <job-id> <out-dir>
#   -k: only files named <pkg>-*.xml. Prints the path of each downloaded file.
# bk artifacts download writes to the current directory; this script does the cd so callers don't have to
# (unattended runs deny "cd <dir> && <command>").
set -euo pipefail
while getopts hp:k: o; do case $o in p) P=$OPTARG ;; k) PKG=$OPTARG ;; h) sed -n "2,6p" "$0"; exit 0 ;; *) exit 2 ;; esac; done; shift $((OPTIND-1))
B=${1:?build number}; JOB=${2:?job id}; OUT=${3:?out dir}
P=${P:-elastic/integrations}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

bk artifacts list "$B" -p "$P" --job "$JOB" -o json |
  jq -r --arg k "${PKG:-}" '.[] | select(.filename | endswith(".xml")) | select($k == "" or (.filename | startswith($k + "-"))) | [.id, .filename] | @tsv' |
  while IFS=$'\t' read -r id name; do
    [ -s "$OUT/$name" ] || (cd "$OUT" && bk artifacts download "$id" -q >/dev/null && mv "artifact-$id/$name" "$name" && rmdir "artifact-$id")
    echo "$OUT/$name"
  done
