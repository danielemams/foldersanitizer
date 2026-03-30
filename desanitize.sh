#!/usr/bin/env bash
#
# Copyright 2026 Daniele Mammarella
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# desanitize.sh — Reverse sanitization on deliverable files.
#
# Reads the sanitizer mapping JSON and replaces masked values with originals
# in the target files. Intended for preparing customer-facing deliverables
# after Claude has generated them with masked data.
#
# Author: Daniele Mammarella <dmammare@redhat.com>
set -euo pipefail

# ---- resolve script location (symlink-safe) --------------------------------
_self="${BASH_SOURCE[0]}"
while [ -L "$_self" ]; do
  _dir="$(cd "$(dirname "$_self")" && pwd)"
  _self="$(readlink "$_self")"
  [[ "$_self" != /* ]] && _self="$_dir/$_self"
done
SCRIPT_DIR="$(cd "$(dirname "$_self")" && pwd)"
SCRIPT_NAME="$(basename "$0")"

# ---- defaults ---------------------------------------------------------------
# DESANITIZE_MAPPING  — path to mapping_*.json (required, or auto-detected)
# DESANITIZE_INPUT    — file or directory to de-sanitize (required)
# DESANITIZE_OUTPUT   — output path; if empty, modifies in-place
# DESANITIZE_AGENT_DIR — agent data dir, used for auto-detecting mapping

# ---- usage ------------------------------------------------------------------
usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS] <input-path>

Reverse sanitization: replace masked values with originals using the
sanitizer mapping file.

Arguments:
  input-path            File or directory to de-sanitize.

Options:
  -m, --mapping FILE    Path to mapping_*.json file.
                        Default: auto-detect from --agent-dir or \$DESANITIZE_MAPPING.
  -a, --agent-dir DIR   Agent data directory (to auto-detect mapping).
                        Default: \$DESANITIZE_AGENT_DIR or current directory.
  -o, --output PATH     Output file/directory. If omitted, modifies in-place.
  -n, --dry-run         Show what would be replaced without modifying files.
  -v, --verbose         Print each replacement.
  -h, --help            Show this help.

Environment variables:
  DESANITIZE_MAPPING    Default mapping file path.
  DESANITIZE_AGENT_DIR  Default agent data directory for auto-detection.
  DESANITIZE_OUTPUT     Default output path.

Examples:
  # De-sanitize a single file using explicit mapping
  $SCRIPT_NAME -m sanitize-data/mapping_20260318.json solution/internal/step2.sh

  # De-sanitize a directory, output to a separate folder
  $SCRIPT_NAME -a /path/to/agent-data -o desanitized/ solution/

  # Dry-run: see what would change
  $SCRIPT_NAME -n -m mapping.json solution/customer-deliverable/proposed-public-comment.txt
EOF
  exit 1
}

# ---- argument parsing -------------------------------------------------------
MAPPING="${DESANITIZE_MAPPING:-}"
AGENT_DIR="${DESANITIZE_AGENT_DIR:-}"
OUTPUT="${DESANITIZE_OUTPUT:-}"
DRY_RUN=false
VERBOSE=false
INPUT=""

while [ $# -gt 0 ]; do
  case "$1" in
    -m|--mapping)   shift; MAPPING="$1" ;;
    -a|--agent-dir) shift; AGENT_DIR="$1" ;;
    -o|--output)    shift; OUTPUT="$1" ;;
    -n|--dry-run)   DRY_RUN=true ;;
    -v|--verbose)   VERBOSE=true ;;
    -h|--help)      usage ;;
    -*)             echo "Error: unknown option: $1" >&2; usage ;;
    *)              INPUT="$1" ;;
  esac
  shift
done

if [ -z "$INPUT" ]; then
  echo "Error: input path is required." >&2
  usage
fi

if [ ! -e "$INPUT" ]; then
  echo "Error: input path does not exist: $INPUT" >&2
  exit 1
fi

# ---- auto-detect mapping ----------------------------------------------------
_find_latest_mapping() {
  local dir="$1"
  # Look in sanitize-data/ first, then directly in dir
  local search_dirs=("$dir/sanitize-data" "$dir")
  for d in "${search_dirs[@]}"; do
    if [ -d "$d" ]; then
      local latest
      latest=$(find "$d" -maxdepth 1 -name 'mapping_*.json' -type f 2>/dev/null \
               | sort -r | head -1)
      if [ -n "$latest" ]; then
        echo "$latest"
        return 0
      fi
    fi
  done
  return 1
}

if [ -z "$MAPPING" ]; then
  search_dir="${AGENT_DIR:-.}"
  MAPPING=$(_find_latest_mapping "$search_dir") || {
    echo "Error: no mapping_*.json found in $search_dir/sanitize-data/ or $search_dir/" >&2
    echo "       Use -m to specify the mapping file, or -a to specify the agent data dir." >&2
    exit 1
  }
  echo "[*] Auto-detected mapping: $MAPPING"
fi

if [ ! -f "$MAPPING" ]; then
  echo "Error: mapping file not found: $MAPPING" >&2
  exit 1
fi

# ---- parse mapping with pure bash + python one-liner ------------------------
# Mapping format: { "CATEGORY": { "masked_value": "original_value", ... }, ... }
# We flatten it into a list of masked→original pairs, sorted longest-first
# to avoid partial replacements.

declare -a MASKED_VALS=()
declare -a ORIGINAL_VALS=()

_parse_mapping() {
  # Use python to flatten and sort by length (longest first).
  # Output: one line per pair, tab-separated (masked<TAB>original).
  local pairs
  pairs=$(python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
pairs = []
for cat, entries in data.items():
    for masked, original in entries.items():
        pairs.append((masked, original))
# Sort by masked length descending to avoid partial replacements
pairs.sort(key=lambda p: -len(p[0]))
for m, o in pairs:
    print(m + '\t' + o)
" "$MAPPING") || {
    echo "Error: failed to parse mapping file: $MAPPING" >&2
    exit 1
  }

  while IFS=$'\t' read -r masked original; do
    [ -z "$masked" ] && continue
    MASKED_VALS+=("$masked")
    ORIGINAL_VALS+=("$original")
  done <<< "$pairs"
}

_parse_mapping

if [ ${#MASKED_VALS[@]} -eq 0 ]; then
  echo "[*] Mapping is empty — nothing to de-sanitize."
  exit 0
fi

echo "[*] Loaded ${#MASKED_VALS[@]} masked→original mappings from: $MAPPING"

# ---- de-sanitize a single file ----------------------------------------------
_desanitize_file() {
  local src="$1"
  local dst="$2"

  # Skip binary files
  if file -b --mime-type "$src" 2>/dev/null | grep -qv '^text/'; then
    [ "$VERBOSE" = true ] && echo "  SKIP (binary): $src"
    return
  fi

  local content
  content=$(<"$src")
  local original_content="$content"
  local count=0

  for i in "${!MASKED_VALS[@]}"; do
    local masked="${MASKED_VALS[$i]}"
    local original="${ORIGINAL_VALS[$i]}"

    if [[ "$content" == *"$masked"* ]]; then
      content="${content//"$masked"/"$original"}"
      count=$((count + 1))
      if [ "$VERBOSE" = true ]; then
        echo "  REPLACE: '$masked' → '$original'"
      fi
    fi
  done

  if [ "$content" != "$original_content" ]; then
    if [ "$DRY_RUN" = true ]; then
      echo "  WOULD MODIFY ($count replacements): $src"
    else
      echo "$content" > "$dst"
      echo "  MODIFIED ($count replacements): $dst"
    fi
  else
    if [ "$DRY_RUN" = false ] && [ "$src" != "$dst" ]; then
      cp "$src" "$dst"
    fi
    [ "$VERBOSE" = true ] && echo "  UNCHANGED: $src"
  fi
}

# ---- process input ----------------------------------------------------------
_process() {
  local input="$1"
  local output="$2"

  if [ -f "$input" ]; then
    # Single file
    local dst="$output"
    if [ -z "$dst" ]; then
      dst="$input"  # in-place
    elif [ -d "$dst" ]; then
      dst="$dst/$(basename "$input")"
    fi
    _desanitize_file "$input" "$dst"

  elif [ -d "$input" ]; then
    # Directory: process all text files recursively
    local dst_dir="$output"
    if [ -z "$dst_dir" ]; then
      dst_dir="$input"  # in-place
    else
      mkdir -p "$dst_dir"
    fi

    local file_count=0
    while IFS= read -r -d '' src_file; do
      local rel="${src_file#"${input%/}/"}"
      local dst_file="$dst_dir/$rel"
      mkdir -p "$(dirname "$dst_file")"
      _desanitize_file "$src_file" "$dst_file"
      file_count=$((file_count + 1))
    done < <(find "$input" -type f -print0 2>/dev/null | sort -z)

    echo "[*] Processed $file_count files in: $input"
  fi
}

echo
if [ "$DRY_RUN" = true ]; then
  echo "[*] DRY-RUN mode — no files will be modified."
fi

_process "$INPUT" "$OUTPUT"

echo
echo "[*] De-sanitization complete."
if [ "$DRY_RUN" = false ] && [ -n "$OUTPUT" ]; then
  echo "[*] Output: $OUTPUT"
fi
