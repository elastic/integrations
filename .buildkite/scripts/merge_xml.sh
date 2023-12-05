#!/bin/bash

set -euox pipefail

sourceFolder="build/test-coverage"
mergedCoverageFileName="coverage_merged.xml"

pushd "${sourceFolder}" > /dev/null
echo '<coverage>' > "${mergedCoverageFileName}"

for file in *.xml; do
  [ "$file" = "${mergedCoverageFileName}" ] && continue
  sed '1d;$d' "$file" | awk '/<package /,/<\/package>/' >> "${mergedCoverageFileName}"
done

echo '</coverage>' >> "${mergedCoverageFileName}"

mkdir -p coverage-report
cp "$(find . -name 'coverage-*.xml' | head -n 1)" coverage-report/

popd > /dev/null

ls -la $sourceFolder
ls -la $sourceFolder/coverage-report
