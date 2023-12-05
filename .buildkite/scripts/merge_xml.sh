#!/bin/bash

set -euox pipefail

sourceFolder="build/test-coverage"
mergedCoverageFileName="${sourceFolder}/coverage_merged.xml"
echo '<coverage>' > "${mergedCoverageFileName}"

for file in ${sourceFolder}/*.xml; do
  [ "$file" = "${mergedCoverageFileName}" ] && continue
  sed '1d;$d' "$file" | awk '/<package /,/<\/package>/' >> "${mergedCoverageFileName}"
done

echo '</coverage>' >> "${mergedCoverageFileName}"

file_to_copy=$(find ${sourceFolder}/ -maxdepth 1 -type f -name "coverage-.xml" | head -n 1 | xargs basename)
echo "Copy file ${file_to_copy} to the 'coverage-reports' folder"
cp ${file_to_copy} coverage-reports/

ls ${sourceFolder}
ls coverage-reports
