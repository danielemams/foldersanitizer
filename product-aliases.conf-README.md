# product-aliases.conf

Shared product alias map — single source of truth for product name resolution.

## Purpose

Maps alternative product names (slugs derived from SFDC product names) to canonical resolver types. Used by both bash scripts and `sanitizer.py`.

## Format

```
# Comment
alias=canonical_type
```

The canonical type must match a resolver file: `lib/case/env/lib/resolve-<type>.sh`

## Used by

- `_resolve_product_alias()` in `initcaseenv-agent-common.sh` — resolves detected product slug to canonical type
- `sanitizer.py` — resolves `--product` CLI flag to sanitizer context key

## How to add an alias

Add a line to this file:

```
new-alias=existing-type
```

No code changes needed. Both bash and python will pick it up.

## Author

Daniele Mammarella <dmammare@redhat.com>
