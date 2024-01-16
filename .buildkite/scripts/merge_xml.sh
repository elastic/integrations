#!/bin/bash

set -euo pipefail

sourceFolder="build/test-coverage"
mergedCoverageFileName="coverage_merged.xml"

pushd "${sourceFolder}" > /dev/null
echo "Generating ${mergedCoverageFileName} into ${sourceFolder}..."
echo '<?xml version="1.0" encoding="UTF-8"?>' > "${mergedCoverageFileName}"
echo '<coverage version="1">' >> "${mergedCoverageFileName}"

# for file in coverage-nginx-*.xml coverage-elastic_package_registry-*.xml; do
for file in coverage-*.xml; do
  [[ "$file" == "${mergedCoverageFileName}" ]] && continue
  echo " - Adding ${file}"
  # generic coverage
  sed '1d;$d' "$file" | awk '/<file/,/<\/file>/' >> "${mergedCoverageFileName}"
done

echo '</coverage>' >> "${mergedCoverageFileName}"
echo 'Done'

popd > /dev/null

