#!/usr/bin/env bash
# Shared assert helpers for shell unit tests.
# Source this file — do not execute it directly.

assert_equals() {
    local description="$1"
    local expected="$2"
    local actual="$3"
    if [[ "${actual}" == "${expected}" ]]; then
        echo "PASS: ${description}"
        (( pass++ )) || true
    else
        echo "FAIL: ${description} — expected '${expected}', got '${actual}'"
        (( fail++ )) || true
    fi
}

assert_exit_code() {
    local description="$1"
    local expected="$2"
    local actual="$3"
    if [[ "${actual}" == "${expected}" ]]; then
        echo "PASS: ${description}"
        (( pass++ )) || true
    else
        echo "FAIL: ${description} — expected exit code '${expected}', got '${actual}'"
        (( fail++ )) || true
    fi
}
