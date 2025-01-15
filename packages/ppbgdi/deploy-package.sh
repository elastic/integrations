#!/bin/bash
set -e
set -u


# Function to display help
display_help() {
    echo "Usage: $0 PACKAGE_NAME PACKAGE_VERSION"
    echo
    echo Build and deploy package to codebuild artifacts bucket
    echo
    echo "   PACKAGE_NAME      Package name, e.g. PPBGDI"
    echo "   PACKAGE_VERSION   Package version, e.g. 0.9.1"
    echo
    echo "Options:"
    echo "   -h, --help   Display this help message."
}

# Check for help option
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    display_help
    exit 0
fi

# Check for correct number of arguments
if [[ "$#" -ne 2 ]]; then
    >&2 echo "ERROR: Invalid number of arguments."
    display_help
    exit 1
fi

PACKAGE_NAME="$1"
PACKAGE_VERSION="$2"
PACKAGE_FULL="${PACKAGE_NAME}-${PACKAGE_VERSION}"
PACKAGE_ZIP="${PACKAGE_FULL}.zip"

BUILD_DIR="../../build/packages"
AWS_PROFILE="swisstopo-bgdi-builder"
S3_BUCKET="build-artifacts-swisstopo"
S3_PREFIX="elastic-integrations"

echo "Build package ${PACKAGE_FULL}"
elastic-package check

echo "Deploy package ${PACKAGE_FULL} to s3://${S3_BUCKET}/${S3_PREFIX}/${PACKAGE_ZIP}"
aws s3api put-object --profile "${AWS_PROFILE}" --bucket "${S3_BUCKET}" --body "${BUILD_DIR}/${PACKAGE_ZIP}" --key "${S3_PREFIX}/${PACKAGE_ZIP}"
