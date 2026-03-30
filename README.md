# FolderSanitizer

Sensitive data masking tool for enterprise product diagnostics.

Masks hostnames, IPs, usernames, passwords, tokens, certificates, and other sensitive data across JBoss EAP, WildFly, RHBK, Keycloak, OpenShift inspect, and must-gather files. Produces sanitized output with a correlation-friendly mapping file (no secrets stored).

## Quick start

```bash
python3 sanitizer.py -i ./input-folder -o ./sanitized-output
```

### Environment variables

| ENV variable | Default | Description |
|-------------|---------|-------------|
| `SANITIZER_INPUT_DIR` | `/opt/foldersanitizer/data/input` | Default input path (overridden by `-i`) |
| `SANITIZER_OUTPUT_DIR` | `/opt/foldersanitizer/data/output` | Default output path (overridden by `-o`) |

## Integration

This tool is used by the [initcaseenv-agent](https://github.com/danielemams/initcaseenv-agent) project. The agent includes a pure Java reimplementation of the sanitizer for runtime use; this Python version serves as the reference implementation and standalone tool.

## Files

| File | Description |
|------|-------------|
| `sanitizer.py` | Main sanitizer script (Python reference implementation) |
| `product-aliases.conf` | Shared product alias map (single source of truth) |

## License

Apache License 2.0

## Author

Daniele Mammarella <dmammare@redhat.com>
