#!/bin/bash

set -euo pipefail

sourceFolder="build/test-coverage"
mergedCoverageFileName="${sourceFolder}/coverage_merged.xml"
echo '<coverage>' > "${mergedCoverageFileName}"

for file in "${sourceFolder}/*.xml"; do
  [ "$file" = "${mergedCoverageFileName}" ] && continue
  sed '1d;$d' "$file" | awk '/<package /,/<\/package>/' >> "${mergedCoverageFileName}"
done

echo '</coverage>' >> "${mergedCoverageFileName}"
