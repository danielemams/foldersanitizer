# desanitize.sh

Reverse sanitization tool. Reads the sanitizer mapping JSON and replaces
masked values with their originals in deliverable files.

## Purpose

After Claude generates solution files using masked data, this script
prepares customer-facing deliverables by restoring original values
(hostnames, IPs, emails, resource names, etc.).

## Interface

```
desanitize.sh [OPTIONS] <input-path>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `input-path` | File or directory to de-sanitize |

### Options

| Option | Description |
|--------|-------------|
| `-m, --mapping FILE` | Path to `mapping_*.json`. Auto-detected if omitted. |
| `-a, --agent-dir DIR` | Agent data dir for auto-detecting mapping. |
| `-o, --output PATH` | Output path. If omitted, modifies in-place. |
| `-n, --dry-run` | Show what would change without modifying. |
| `-v, --verbose` | Print each replacement. |
| `-h, --help` | Show usage. |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DESANITIZE_MAPPING` | (none) | Default mapping file path |
| `DESANITIZE_AGENT_DIR` | (none) | Default agent data dir for auto-detection |
| `DESANITIZE_OUTPUT` | (none) | Default output path |

## Mapping auto-detection

When no `-m` is provided, the script searches for the latest `mapping_*.json` in:
1. `<agent-dir>/sanitize-data/` (standard agent layout)
2. `<agent-dir>/` (fallback)

The most recent mapping file (by filename sort) is used.

## Replacement order

Masked values are sorted by length (longest first) to prevent partial
replacements. For example, `host-001.domain-001.com` is replaced before
`domain-001.com`.

## Examples

```bash
# De-sanitize solution deliverables using auto-detected mapping
desanitize.sh -a ~/cases/04393780/initcaseenv-agent-data \
  -o desanitized/ runs/20260318120000000/solution/

# De-sanitize a single file in-place
desanitize.sh -m sanitize-data/mapping_20260318_120000.json \
  solution/step2.sh

# Dry-run with verbose output
desanitize.sh -n -v -m mapping.json solution/

# Via symlink
ln -s /path/to/lib/sanitizer/desanitize.sh ~/bin/desanitize
desanitize -a /path/to/agent-data solution/customer-deliverable-proposed-public-comment.txt
```

## Integration with agent workflow

Typical flow:
1. Sanitizer masks customer data → produces `mapping_*.json`
2. Claude analyzes masked data → generates `solution/` files
3. Engineer reviews solution files
4. `desanitize.sh` restores original values in deliverables
   (`customer-deliverable-fix.sh`, `customer-deliverable-proposed-public-comment.txt`,
   `analysis.txt`)
5. Engineer reviews restored files before sending to customer

## Safety

- Binary files are automatically skipped.
- Always use `--dry-run` first to review changes.
- The mapping file contains original sensitive data — keep it secure.
- In-place mode overwrites files directly; use `-o` to preserve originals.

## Dependencies

- bash 4+
- python3 (for JSON parsing)
- `file` command (for binary detection)

## Author

Daniele Mammarella <dmammare@redhat.com>
