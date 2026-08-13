# dev/scripts

Developer and maintenance scripts that are **not** involved in package testing.

Because none of these scripts affect package behaviour, the entire `dev/scripts/`
directory is listed as a `non_package_pattern` in
`.buildkite/scripts/common.sh`. This means changes here do not trigger the
package test matrix in CI.

If a script is ever added here that does affect package testing, the
`non_package_patterns` entry for `dev/scripts/` must be narrowed or removed
accordingly so that the relevant packages are still tested.
