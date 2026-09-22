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


# collect_linked_packages_from_roots accepts any number of root package paths
# and returns (one per line) all packages reachable via .link files from any
# of those roots, transitively. The roots themselves are excluded. Output is
# deduplicated across all roots so each package appears at most once.
# list_all_directories is called exactly once per invocation of this function,
# regardless of the number of roots or BFS hops. collect_packages_to_keep calls
# this function once per outer iteration (see its known-limitation comment).
collect_linked_packages_from_roots() {
  # Build the package cache once upfront.
  local -a pkg_paths=() pkg_abss=()
  local pkg_path pkg_abs_tmp
  while IFS= read -r pkg_path; do
    if pkg_abs_tmp=$(realpath "${pkg_path}" 2>/dev/null); then
      pkg_paths+=("${pkg_path}")
      pkg_abss+=("${pkg_abs_tmp}")
    else
      echo "Warning: cannot resolve package path '${pkg_path}', skipping" >&2
    fi
  done < <(list_all_directories)

  # BFS over .link reachability. The queue is needed because a discovered
  # package may itself contain .link files pointing into further packages
  # (transitive chain: A links B, B links C → C must also be kept).
  # Roots are pre-seeded into seen so they are never emitted as output.
  local -A seen=()
  local root
  for root in "$@"; do seen["${root}"]=1; done
  local -a queue=("$@")
  local queue_idx=0

  while [[ ${queue_idx} -lt ${#queue[@]} ]]; do
    local current="${queue[${queue_idx}]}"
    queue_idx=$(( queue_idx + 1 ))
    local current_abs
    if ! current_abs=$(realpath "${current}" 2>/dev/null); then
      echo "Warning: cannot resolve path '${current}', skipping" >&2
      continue
    fi

    local link_file relative_src resolved_src matched i pkg_abs
    while IFS= read -r link_file; do
      # package-spec parses .link files the same way (strings.Fields → fields[0]),
      # so paths with spaces are structurally unsupported by the spec.
      relative_src=$(awk '{print $1; exit}' "${link_file}")
      [[ -z "${relative_src}" ]] && continue
      resolved_src=$(realpath -m "$(dirname "${link_file}")/${relative_src}")

      # Self-link: source is within the current package — skip silently.
      if [[ "${resolved_src#"${current_abs}/"}" != "${resolved_src}" || \
            "${resolved_src}" == "${current_abs}" ]]; then
        continue
      fi

      matched=false
      for (( i=0; i<${#pkg_paths[@]}; i++ )); do
        pkg_abs="${pkg_abss[$i]}"
        [[ "${pkg_abs}" == "${current_abs}" ]] && continue
        if [[ "${resolved_src#"${pkg_abs}/"}" != "${resolved_src}" || \
              "${resolved_src}" == "${pkg_abs}" ]]; then
          matched=true
          pkg_path="${pkg_paths[$i]}"
          if [[ -z "${seen[${pkg_path}]+x}" ]]; then
            seen["${pkg_path}"]=1
            echo "${pkg_path}"
            queue+=("${pkg_path}")
          fi
          break
        fi
      done

      if [[ "${matched}" == "false" ]]; then
        echo "Warning: source '${resolved_src}' (from ${link_file}) does not belong to any known package, skipping" >&2
      fi
    done < <(find "${current}" -type f -name "*.link")
  done
}

# collect_packages_to_keep returns (one per line) all packages that must be
# retained for the given target package: the target itself, its requires.*
# dependencies, packages reachable via .link files, and any requires.*
# dependencies of those packages. Expanded iteratively until stable so that
# any cross-type chaining (link → requires, requires → link) is fully covered.
# Package paths are emitted on stdout; informational and warning messages go
# to stderr.
collect_packages_to_keep() {
  local target_path="${1}"
  echo "${target_path}"

  local -a packages_to_keep=("${target_path}")
  local -A seen_pkgs=()
  seen_pkgs["${target_path}"]=1
  local -A requires_expanded=()
  local expanded=true

  while [[ "${expanded}" == "true" ]]; do
    expanded=false

    # Expand via requires.* for each package not yet checked.
    local pkg req_name req_path
    for pkg in "${packages_to_keep[@]}"; do
      [[ -n "${requires_expanded[${pkg}]+x}" ]] && continue
      requires_expanded["${pkg}"]=1
      while IFS= read -r req_name; do
        req_path=$(get_package_path "${req_name}" || true)
        if [[ -n "${req_path}" ]]; then
          if [[ -z "${seen_pkgs[${req_path}]+x}" ]]; then
            echo "Keeping required package: ${req_path} (required by ${pkg})" >&2
            echo "${req_path}"
            packages_to_keep+=("${req_path}")
            seen_pkgs["${req_path}"]=1
            expanded=true
          fi
        else
          echo "Warning: required package '${req_name}' not found in packages folder" >&2
        fi
      done < <(get_required_package_names "${pkg}")
    done

    # Expand via .link files for all current packages.
    # Known limitation: collect_linked_packages_from_roots rebuilds the package
    # list from list_all_directories on each call. The outer loop runs at most a
    # handful of iterations in practice (typically 1, rarely more than 3), so the
    # extra find traversal per iteration is negligible.
    local linked_path
    while IFS= read -r linked_path; do
      if [[ -z "${seen_pkgs[${linked_path}]+x}" ]]; then
        echo "Keeping linked source package: ${linked_path} (linked transitively)" >&2
        echo "${linked_path}"
        packages_to_keep+=("${linked_path}")
        seen_pkgs["${linked_path}"]=1
        expanded=true
      fi
    done < <(collect_linked_packages_from_roots "${packages_to_keep[@]}")
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
