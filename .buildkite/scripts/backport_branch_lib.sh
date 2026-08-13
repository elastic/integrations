#!/usr/bin/env bash
# Pure helper functions for backport_branch.sh.
# Source this file; do not execute it directly.

# get_package_path returns the path of the package with the given name as
# defined in the manifest.yml `name` field. Returns 1 if not found.
get_package_path() {
  local package_name="${1}"
  local package_path=""

  while IFS= read -r package_path; do
    local name
    name=$(yq -r '.name' "${package_path}/manifest.yml")
    if [[ "${name}" == "${package_name}" ]]; then
      echo "${package_path}"
      return 0
    fi
  done < <(list_all_directories)

  return 1
}

# get_required_package_names returns (one per line) the names of all packages
# listed under requires.input and requires.content in the manifest.yml of the
# given package path. Outputs nothing if the section is absent.
get_required_package_names() {
  local package_path="${1}"
  local manifest="${package_path}/manifest.yml"

  if [[ ! -f "${manifest}" ]]; then
    return 0
  fi

  yq -r '.requires.input[].package' "${manifest}" 2>/dev/null || true
  yq -r '.requires.content[].package' "${manifest}" 2>/dev/null || true
}

remove_other_packages() {
  local -a packages_to_keep=("$@")
  local package_path
  local package_paths=""
  package_paths=$(list_all_directories)
  for package_path in ${package_paths}; do
    local should_keep=false
    for keep_path in "${packages_to_keep[@]}"; do
      if [[ "${package_path}" == "${keep_path}" ]]; then
        should_keep=true
        break
      fi
    done
    if [[ -d "$package_path" ]] && [[ "${should_keep}" == "false" ]]; then
      echo "Removing directory: ${package_path}"
      rm -rf "$package_path"

      echo "Removing ${package_path} from .github/CODEOWNERS"
      sed -i "\|^/${package_path}/|d" .github/CODEOWNERS
      sed -i "\|^/${package_path} |d" .github/CODEOWNERS
    fi
  done
}
