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
mapfile -t cert_files < <(find "$search_root" \( -name "*.crt" -o -name "*.pem" \) -not -name "*.key" | sort)

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
    if ! openssl x509 -in "$cert_file" -noout -checkend 0 2>/dev/null; then
        # checkend 0 means "has it already expired?" — a negative days value confirms it.
        printf "ERROR   [EXPIRED %s days ago] %s\n" "${days#-}" "$short"
        printf "        subject: %s\n\n" "$subject"
        error_count=$((error_count + 1))
    elif ! openssl x509 -in "$cert_file" -noout -checkend "$SECS_6_MONTHS" 2>/dev/null; then
        printf "ERROR   [expires in %s days — within 6 months] %s\n" "$days" "$short"
        printf "        subject: %s  |  expiry: %s\n\n" "$subject" "$expiry"
        error_count=$((error_count + 1))
    elif ! openssl x509 -in "$cert_file" -noout -checkend "$SECS_1_YEAR" 2>/dev/null; then
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
    echo "Renew the certificates above, then sync test configs:"
    echo "  openssl req -x509 -newkey rsa:2048 -keyout <key> -out <cert> \\"
    echo "    -subj '<subject>' [-addext 'subjectAltName=DNS:<hostname>'] -days 3650 -noenc"
    echo "  .buildkite/scripts/update-test-cert.sh <cert>"
    exit 1
fi
