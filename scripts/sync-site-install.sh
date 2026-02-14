#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_SH="${ROOT_DIR}/install.sh"
SOURCE_PS1="${ROOT_DIR}/install.ps1"
SITE_DIR="${NSH_SITE_DIR:-${ROOT_DIR}/../nsh-site}"
WATCH_MODE=0

usage() {
  cat <<'USAGE'
Sync installer scripts into the nsh-site repo.

Usage:
  scripts/sync-site-install.sh [options]

Options:
  --site-dir <path>   Destination site repo path (default: ../nsh-site)
  --watch             Watch install.sh and sync on changes
  -h, --help          Show this help
USAGE
}

have() {
  command -v "$1" >/dev/null 2>&1
}

sync_once() {
  if [[ ! -f "${SOURCE_SH}" ]]; then
    echo "sync-site-install: source file not found: ${SOURCE_SH}" >&2
    exit 1
  fi
  if [[ ! -f "${SOURCE_PS1}" ]]; then
    echo "sync-site-install: source file not found: ${SOURCE_PS1}" >&2
    exit 1
  fi
  if [[ ! -d "${SITE_DIR}" ]]; then
    echo "sync-site-install: site dir not found: ${SITE_DIR}" >&2
    exit 1
  fi

  cp "${SOURCE_SH}" "${SITE_DIR}/install.sh"
  cp "${SOURCE_PS1}" "${SITE_DIR}/install.ps1"
  chmod 755 "${SITE_DIR}/install.sh"
  echo "synced: ${SOURCE_SH} -> ${SITE_DIR}/install.sh"
  echo "synced: ${SOURCE_PS1} -> ${SITE_DIR}/install.ps1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --site-dir)
      [[ $# -ge 2 ]] || { echo "sync-site-install: --site-dir requires a value" >&2; exit 1; }
      SITE_DIR="$2"
      shift 2
      ;;
    --watch)
      WATCH_MODE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "sync-site-install: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

sync_once

if (( WATCH_MODE )); then
  if have fswatch; then
    echo "watching: ${SOURCE_SH} ${SOURCE_PS1}"
    fswatch -0 "${SOURCE_SH}" "${SOURCE_PS1}" | while IFS= read -r -d '' _; do
      sync_once
    done
    exit 0
  fi

  if have entr; then
    echo "watching with entr: ${SOURCE_SH} ${SOURCE_PS1}"
    while true; do
      printf '%s\n%s\n' "${SOURCE_SH}" "${SOURCE_PS1}" | entr -n bash -lc 'cp "$0" "$2/install.sh" && cp "$1" "$2/install.ps1" && chmod 755 "$2/install.sh"' "${SOURCE_SH}" "${SOURCE_PS1}" "${SITE_DIR}"
      echo "synced: ${SOURCE_SH} -> ${SITE_DIR}/install.sh"
      echo "synced: ${SOURCE_PS1} -> ${SITE_DIR}/install.ps1"
    done
  fi

  echo "sync-site-install: watch mode requires fswatch or entr" >&2
  exit 1
fi
