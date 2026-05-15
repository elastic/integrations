#!/usr/bin/env bash
# Scans TLS certificates used by test mock servers under packages/_dev/ directories.
#
# Many integrations use a local HTTPS mock server (via docker.elastic.co/observability/stream)
# to simulate vendor APIs during system tests. Each mock server is configured with a
# self-signed TLS certificate checked into the repo under:
#   packages/<integration>/_dev/deploy/docker/files/*.crt
#
# The CEL input in Elastic Agent validates the mock server's certificate against the CA
# embedded in the test config (test-*-config.yml). When the cert expires, TLS handshakes
# fail silently and tests report a generic "could not find expected hits" error with no
# indication that certificate expiry is the root cause.
#
# This script catches expiry proactively before tests run.
#
# Usage:
#   check_certificates.sh [package_path]
#
#   package_path  Optional path to a single package (e.g. packages/cybereason).
#                 When omitted, all packages under packages/ are scanned.
#
# Thresholds:
#   ERROR   — certificate is expired or expires within 6 months (180 days)
#   WARNING — certificate expires within 1 year (365 days)
#
# Exits non-zero if any ERROR is found. Warnings are printed but do not fail the build.
# Called from test_one_package.sh (per-package, scoped) so that a cert problem fails
# only the affected package's test step.

set -euo pipefail

# Threshold constants in seconds, used with `openssl x509 -checkend <secs>` which
# returns exit code 1 if the certificate expires within the given number of seconds.
readonly SECS_6_MONTHS=$((180 * 86400))
readonly SECS_1_YEAR=$((365 * 86400))

search_root="${1:-.}"

error_count=0
warning_count=0
junit_errors=()  # accumulates (cert_path, message) pairs passed to write_junit_cert_report.py

echo "--- Checking TLS certificate expiry under ${search_root}"
echo ""

# Converts an openssl enddate string (e.g. "May  6 06:27:43 2026 GMT") to a day count
# relative to now. Returns "?" if the date cannot be parsed (GNU date required).
_days_remaining() {
    local expiry="$1"
    local expiry_epoch now_epoch
    expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null) || { echo "?"; return; }
    now_epoch=$(date +%s)
    echo $(( (expiry_epoch - now_epoch) / 86400 ))
}

# We exclude *.key files because some packages store private keys with a .pem extension and
# openssl would fail to parse them as X.509 certificates.
find_output=$(find "$search_root" \( -name "*.crt" -o -name "*.pem" \) -not -name "*.key" | sort)

# readarray -> stores lines from a stream into an array; -t to strip trailing newlines
# Using printf '%s' to avoid cert_files=("") instead of an empty array when find returns no results.
readarray -t cert_files < <(printf '%s' "$find_output")

if [ ${#cert_files[@]} -eq 0 ]; then
    echo "No certificate files found under ${search_root} — nothing to check."
    exit 0
fi

for cert_file in "${cert_files[@]}"; do
    # Some .pem files are combined cert+key bundles or contain only a private key.
    # Attempt to parse as X.509 and skip silently if it fails — we only care about certs.
    if ! openssl x509 -in "$cert_file" -noout 2>/dev/null; then
        continue
    fi

    # Extract the human-readable fields we need for display and threshold evaluation.
    # -enddate returns "notAfter=<date string>"; cut strips the field name prefix.
    expiry=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
    subject=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed 's/^subject=//')
    days=$(_days_remaining "$expiry")

    # Strip the leading "./" that find produces so paths read cleanly in CI output.
    short="${cert_file#./}"

    # Evaluate in order from most severe to least. `openssl x509 -checkend <secs>`
    # exits 1 if the certificate will have expired within the given seconds window,
    # making it the cleanest way to test thresholds without manual date arithmetic.
    if ! openssl x509 -in "$cert_file" -noout -checkend 0 >/dev/null 2>&1; then
        # checkend 0 means "has it already expired?" — a negative days value confirms it.
        printf "ERROR   [EXPIRED %s days ago] %s\n" "${days#-}" "$short"
        printf "        subject: %s\n\n" "$subject"
        error_count=$((error_count + 1))
        junit_errors+=("$short" "expired certificate (${days#-} day(s) ago): ${short}")
    elif ! openssl x509 -in "$cert_file" -noout -checkend "$SECS_6_MONTHS" >/dev/null 2>&1; then
        printf "ERROR   [expires in %s days — within 6 months] %s\n" "$days" "$short"
        printf "        subject: %s  |  expiry: %s\n\n" "$subject" "$expiry"
        error_count=$((error_count + 1))
        junit_errors+=("$short" "certificate expires in ${days} day(s) — renew now: ${short}")
    elif ! openssl x509 -in "$cert_file" -noout -checkend "$SECS_1_YEAR" >/dev/null 2>&1; then
        printf "WARNING [expires in %s days — within 1 year] %s\n" "$days" "$short"
        printf "        subject: %s  |  expiry: %s\n\n" "$subject" "$expiry"
        warning_count=$((warning_count + 1))
    else
        printf "OK      [expires in %s days] %s\n\n" "$days" "$short"
    fi
done

echo "Summary: ${error_count} error(s), ${warning_count} warning(s)"

if [ "$error_count" -gt 0 ]; then
    echo ""
    echo "To fix, renew each certificate and propagate the new PEM to the test config files:"
    echo ""
    echo "  1. Regenerate the certificate:"
    echo "       openssl req -x509 -newkey rsa:2048 -keyout <key> -out <cert> \\"
    echo "         -subj '<subject>' [-addext 'subjectAltName=DNS:<hostname>'] -days 3650 -noenc"
    echo ""
    echo "  2. Find the test config files in the package that embed the old PEM:"
    echo "       find ${search_root} -name 'test-*-config.yml' | xargs grep -l 'certificate_authorities'"
    echo ""
    echo "  3. In each file, replace the PEM block under 'certificate_authorities' with"
    echo "     the contents of the new .crt file."

    junit_dir="build/test-results"
    mkdir -p "$junit_dir"
    timestamp=$(date +%s%N 2>/dev/null || date +%s)
    package_name="$(basename "$search_root")"

    export _CERT_CHECK_CALLER="check_certificates.sh"
    python3 "$(dirname "$0")/write_junit_cert_report.py" \
        "$package_name" \
        "${junit_dir}/${package_name}-certcheck-${timestamp}.xml" \
        "${junit_errors[@]}"

    exit 1
fi
