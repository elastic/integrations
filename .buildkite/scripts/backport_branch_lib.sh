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
# Note: transitive chaining is not possible here — input and content packages
# are not allowed to declare their own requires.* dependencies.
get_required_package_names() {
  local package_path="${1}"
  local manifest="${package_path}/manifest.yml"

  if [[ ! -f "${manifest}" ]]; then
    return 0
  fi

  yq -r '.requires.input[].package' "${manifest}" 2>/dev/null || true
  yq -r '.requires.content[].package' "${manifest}" 2>/dev/null || true
}

# get_linked_source_package_names returns (one per line) the paths of packages
# that own the source files of any *.link files found under the given package
# path. The target package itself is excluded from the output. If a resolved
# source path does not belong to any known package a warning is printed to
# stderr and that file is skipped.
get_linked_source_package_names() {
  local package_path="${1}"
  local target_abs
  target_abs=$(realpath "${package_path}")

  # Build the package list and their absolute paths once so we don't re-invoke
  # list_all_directories (and realpath) for every .link file.
  local -a pkg_paths=()
  local -a pkg_abss=()
  local pkg_path pkg_abs_tmp
  while IFS= read -r pkg_path; do
    if pkg_abs_tmp=$(realpath "${pkg_path}" 2>/dev/null); then
      pkg_paths+=("${pkg_path}")
      pkg_abss+=("${pkg_abs_tmp}")
    else
      echo "Warning: cannot resolve package path '${pkg_path}', skipping" >&2
    fi
  done < <(list_all_directories)

  local -A emitted=()
  local link_file relative_src resolved_src
  while IFS= read -r link_file; do
    relative_src=$(awk '{print $1; exit}' "${link_file}")
    if [[ -z "${relative_src}" ]]; then
      continue
    fi
    resolved_src=$(realpath -m "$(dirname "${link_file}")/${relative_src}")

    # Self-link: source is within the target package — skip silently.
    if [[ "${resolved_src}" == "${target_abs}"/* || "${resolved_src}" == "${target_abs}" ]]; then
      continue
    fi

    local matched=false
    local i pkg_abs
    for (( i=0; i<${#pkg_paths[@]}; i++ )); do
      pkg_abs="${pkg_abss[$i]}"
      if [[ "${pkg_abs}" == "${target_abs}" ]]; then
        continue
      fi
      if [[ "${resolved_src}" == "${pkg_abs}"/* || "${resolved_src}" == "${pkg_abs}" ]]; then
        matched=true
        pkg_path="${pkg_paths[$i]}"
        if [[ -z "${emitted[${pkg_path}]+x}" ]]; then
          echo "${pkg_path}"
          emitted["${pkg_path}"]=1
        fi
        break
      fi
    done

    if [[ "${matched}" == "false" ]]; then
      echo "Warning: source '${resolved_src}' (from ${link_file}) does not belong to any known package, skipping" >&2
    fi
  done < <(find "${package_path}" -type f -name "*.link")
}

# collect_linked_package_paths returns (one per line) all packages reachable
# from the given package via .link files, transitively. The starting package is
# excluded. Each package is emitted at most once, in BFS discovery order.
collect_linked_package_paths() {
  local target_path="${1}"
  local -A seen=()
  seen["${target_path}"]=1
  local -a queue=("${target_path}")

  while [[ ${#queue[@]} -gt 0 ]]; do
    local current="${queue[0]}"
    queue=("${queue[@]:1}")

    local linked_path
    while IFS= read -r linked_path; do
      if [[ -z "${seen[${linked_path}]+x}" ]]; then
        seen["${linked_path}"]=1
        echo "${linked_path}"
        queue+=("${linked_path}")
      fi
    done < <(get_linked_source_package_names "${current}")
  done
}

# collect_linked_packages_from_roots accepts any number of root package paths
# and returns (one per line) all packages reachable via .link files from any
# of those roots, transitively. The roots themselves are excluded. Output is
# deduplicated across all roots so each package appears at most once.
collect_linked_packages_from_roots() {
  local -A seen=()
  local root
  for root in "$@"; do seen["${root}"]=1; done

  for root in "$@"; do
    local linked_path
    while IFS= read -r linked_path; do
      if [[ -z "${seen[${linked_path}]+x}" ]]; then
        seen["${linked_path}"]=1
        echo "${linked_path}"
      fi
    done < <(collect_linked_package_paths "${root}")
  done
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
