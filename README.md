# FolderSanitizer

Sensitive data masking tool for enterprise product diagnostics.

Masks hostnames, IPs, usernames, passwords, tokens, certificates, and other sensitive data across JBoss EAP, WildFly, RHBK, Keycloak, OpenShift inspect, and must-gather files. Produces sanitized output with a correlation-friendly mapping file (no secrets stored).

## Quick start

```bash
python3 sanitizer.py -i ./input-folder -o ./sanitized-output
```

See [sanitizer.py-README.md](sanitizer.py-README.md) for full usage and options.

## Integration

This tool is used by the [initcaseenv-agent](../initcaseenv-agent-ok/) project to sanitize customer data before feeding it to Claude Code for analysis. The `sanitizer.py` file is copied into the agent's `lib/` directory.

## Files

| File | Description |
|------|-------------|
| `sanitizer.py` | Main sanitizer script |
| `product-aliases.conf` | Shared product alias map (single source of truth) |
| `notcommit/` | Alternative implementations (Claude Code, Gemini Pro, Gemini) for comparison |

## Author

Daniele Mammarella <dmammare@redhat.com>
