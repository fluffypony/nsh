#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"

DEFAULT_TARGETS=(
  "aarch64-apple-darwin"
  "x86_64-apple-darwin"
  "i686-unknown-freebsd"
  "x86_64-unknown-freebsd"
  "i686-unknown-linux-gnu"
  "aarch64-unknown-linux-gnu"
  "riscv64gc-unknown-linux-gnu"
  "x86_64-unknown-linux-gnu"
)

TARGETS=()
BACKEND="auto"
VERSION=""
HOST_ONLY=0
NO_PACKAGE=0

usage() {
  cat <<'USAGE'
Build release binaries and package GitHub artifacts.

Usage:
  scripts/release-builds.sh [options]

Options:
  --target <triple>        Build one target (repeatable)
  --targets <csv>          Build comma-separated targets
  --host-only              Build only the current host target
  --backend <mode>         Build backend: auto|cargo|cross|zigbuild
  --version <semver>       Version for manifest lines (default: Cargo.toml)
  --dist-dir <path>        Output directory (default: ./dist)
  --no-package             Build only, skip tar.gz packaging
  -h, --help               Show this help

Environment:
  NSH_BUILD_BACKEND        Same as --backend

Artifacts (default packaging):
  dist/nsh-<target>.tar.gz
  dist/nsh-<target>.tar.gz.sha256
  dist/update-records.txt  # lines: <version>:<target>:<binary_sha256>
USAGE
}

error() {
  echo "release-builds: $*" >&2
  exit 1
}

have() {
  command -v "$1" >/dev/null 2>&1
}

parse_version_from_cargo() {
  awk -F'"' '/^version[[:space:]]*=[[:space:]]*"/{print $2; exit}' "${ROOT_DIR}/Cargo.toml"
}

host_triple() {
  local rustc_info
  rustc_info="$(rustc -vV)"
  awk '/^host: /{print $2; exit}' <<< "${rustc_info}"
}

target_env_key() {
  # x86_64-unknown-linux-gnu -> X86_64_UNKNOWN_LINUX_GNU
  local t="$1"
  echo "${t}" | tr '[:lower:]-' '[:upper:]_'
}

cc_for_target() {
  case "$1" in
    i686-unknown-linux-gnu) echo "i686-linux-gnu-gcc" ;;
    x86_64-unknown-linux-gnu) echo "x86_64-linux-gnu-gcc" ;;
    aarch64-unknown-linux-gnu) echo "aarch64-linux-gnu-gcc" ;;
    riscv64gc-unknown-linux-gnu) echo "riscv64-linux-gnu-gcc" ;;
    x86_64-unknown-linux-musl) echo "x86_64-linux-musl-gcc" ;;
    aarch64-unknown-linux-musl) echo "aarch64-linux-musl-gcc" ;;
    *) echo "" ;;
  esac
}

choose_backend() {
  local target="$1"
  if [[ "${BACKEND}" != "auto" ]]; then
    echo "${BACKEND}"
    return
  fi

  # Native macOS cross-arch builds are straightforward with cargo.
  if [[ "${target}" == *"apple-darwin" ]]; then
    echo "cargo"
    return
  fi

  if have cargo-zigbuild; then
    echo "zigbuild"
    return
  fi

  if have cross; then
    echo "cross"
    return
  fi

  echo "cargo"
}

ensure_target_installed() {
  local target="$1"
  if ! have rustup; then
    error "rustup is required to manage targets"
  fi
  local installed
  installed="$(rustup target list --installed)"
  if ! grep -Fxq "${target}" <<< "${installed}"; then
    echo "==> Installing Rust target ${target}"
    rustup target add "${target}"
  fi
}

sha256_file() {
  local path="$1"
  if have shasum; then
    shasum -a 256 "${path}" | awk '{print $1}'
  elif have sha256sum; then
    sha256sum "${path}" | awk '{print $1}'
  else
    error "need shasum or sha256sum"
  fi
}

build_with_cargo() {
  local target="$1"
  local host="$2"

  local cc
  cc="$(cc_for_target "${target}")"

  # On macOS, Linux targets need a cross C toolchain for crates like ring.
  if [[ "${host}" == *"apple-darwin" && "${target}" == *"unknown-linux"* ]]; then
    if [[ -z "${cc}" ]] || ! have "${cc}"; then
      cat >&2 <<EOF_ERR
release-builds: missing linker/compiler for ${target}.

Install one of these approaches:
  1) cross (Docker/Podman backend):
     cargo install cross --locked

  2) zigbuild:
     brew install zig
     cargo install cargo-zigbuild --locked

  3) native GNU cross toolchains (for plain cargo):
     brew tap messense/macos-cross-toolchains
     brew install ${target}
EOF_ERR
      exit 1
    fi

    local env_key
    env_key="$(target_env_key "${target}")"
    echo "==> cargo build --release --target ${target} (CC=${cc})"
    env \
      "CC_${target}=${cc}" \
      "CARGO_TARGET_${env_key}_LINKER=${cc}" \
      cargo build --release --target "${target}"
    return
  fi

  echo "==> cargo build --release --target ${target}"
  cargo build --release --target "${target}"
}

build_target() {
  local target="$1"
  local host="$2"

  ensure_target_installed "${target}"

  local chosen
  chosen="$(choose_backend "${target}")"

  case "${chosen}" in
    cargo)
      build_with_cargo "${target}" "${host}"
      ;;
    cross)
      have cross || error "backend 'cross' selected but 'cross' is not installed"
      echo "==> cross build --release --target ${target}"
      cross build --release --target "${target}"
      ;;
    zigbuild)
      have cargo-zigbuild || error "backend 'zigbuild' selected but 'cargo-zigbuild' is not installed"
      echo "==> cargo zigbuild --release --target ${target}"
      cargo zigbuild --release --target "${target}"
      ;;
    *)
      error "unknown backend: ${chosen}"
      ;;
  esac
}

package_target() {
  local target="$1"
  local version="$2"
  local out_dir="$3"
  local manifest="$4"

  local bin="${ROOT_DIR}/target/${target}/release/nsh"
  [[ -x "${bin}" ]] || error "binary not found for ${target}: ${bin}"

  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' RETURN
  cp "${bin}" "${tmp}/nsh"

  local archive="${out_dir}/nsh-${target}.tar.gz"
  tar -C "${tmp}" -czf "${archive}" nsh

  local archive_sha
  archive_sha="$(sha256_file "${archive}")"
  printf '%s  %s\n' "${archive_sha}" "$(basename "${archive}")" > "${archive}.sha256"

  local binary_sha
  binary_sha="$(sha256_file "${bin}")"
  printf '%s:%s:%s\n' "${version}" "${target}" "${binary_sha}" >> "${manifest}"

  echo "    packaged: $(basename "${archive}")"
  echo "    archive_sha256: ${archive_sha}"
  echo "    binary_sha256:  ${binary_sha}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      [[ $# -ge 2 ]] || error "--target requires a value"
      TARGETS+=("$2")
      shift 2
      ;;
    --targets)
      [[ $# -ge 2 ]] || error "--targets requires a value"
      IFS=',' read -r -a csv_targets <<< "$2"
      TARGETS+=("${csv_targets[@]}")
      shift 2
      ;;
    --host-only)
      HOST_ONLY=1
      shift
      ;;
    --backend)
      [[ $# -ge 2 ]] || error "--backend requires a value"
      BACKEND="$2"
      shift 2
      ;;
    --version)
      [[ $# -ge 2 ]] || error "--version requires a value"
      VERSION="$2"
      shift 2
      ;;
    --dist-dir)
      [[ $# -ge 2 ]] || error "--dist-dir requires a value"
      DIST_DIR="$2"
      shift 2
      ;;
    --no-package)
      NO_PACKAGE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      error "unknown option: $1"
      ;;
  esac
done

case "${BACKEND}" in
  auto|cargo|cross|zigbuild) ;;
  *) error "--backend must be one of: auto, cargo, cross, zigbuild" ;;
esac

if [[ -z "${VERSION}" ]]; then
  VERSION="$(parse_version_from_cargo)"
fi
[[ -n "${VERSION}" ]] || error "could not determine version"
VERSION="${VERSION#v}"

HOST="$(host_triple)"
[[ -n "${HOST}" ]] || error "could not determine host target"

if (( HOST_ONLY )); then
  TARGETS=("${HOST}")
elif [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=("${DEFAULT_TARGETS[@]}")
fi

# De-duplicate while preserving order.
uniq_targets=()
for t in "${TARGETS[@]}"; do
  skip=0
  for u in "${uniq_targets[@]}"; do
    if [[ "${u}" == "${t}" ]]; then
      skip=1
      break
    fi
  done
  (( skip )) || uniq_targets+=("${t}")
done
TARGETS=("${uniq_targets[@]}")

mkdir -p "${DIST_DIR}"
MANIFEST="${DIST_DIR}/update-records.txt"
: > "${MANIFEST}"

echo "nsh release build"
echo "  version: ${VERSION}"
echo "  host:    ${HOST}"
echo "  backend: ${BACKEND}"
echo "  targets: ${TARGETS[*]}"
echo ""

for target in "${TARGETS[@]}"; do
  build_target "${target}" "${HOST}"
  if (( ! NO_PACKAGE )); then
    package_target "${target}" "${VERSION}" "${DIST_DIR}" "${MANIFEST}"
  fi
  echo ""
done

if (( NO_PACKAGE )); then
  rm -f "${MANIFEST}"
  echo "Done. Binaries are in target/<triple>/release/nsh"
else
  echo "Done. Artifacts in ${DIST_DIR}:"
  ls -1 "${DIST_DIR}" | sed 's/^/  - /'
  echo ""
  echo "Use ${MANIFEST} entries for update.nsh.tools DNS TXT records."
fi
