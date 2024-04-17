#!/bin/bash

set -euo pipefail

# Script to merge all the coverage XML files into just one file.
# It supports XML files using generic test coverage report format:
# https://docs.sonarsource.com/sonarqube/9.8/analyzing-source-code/test-coverage/generic-test-data/#generic-test-coverage

sourceFolder="build/test-coverage"
mergedCoverageFileName="coverage_merged.xml"

pushd "${sourceFolder}" > /dev/null
echo "Generating ${mergedCoverageFileName} into ${sourceFolder}..."
echo '<?xml version="1.0" encoding="UTF-8"?>' > "${mergedCoverageFileName}"
echo '<coverage version="1">' >> "${mergedCoverageFileName}"

for file in coverage-*.xml; do
  if [[ "$file" == "${mergedCoverageFileName}" ]]; then
      continue
  fi
  echo " - Adding ${file}"
  sed '1d;$d' "$file" | awk '/<file/,/<\/file>/' >> "${mergedCoverageFileName}"
done

echo '</coverage>' >> "${mergedCoverageFileName}"
echo 'Done'

popd > /dev/null

