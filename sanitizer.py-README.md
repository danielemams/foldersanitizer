# sanitizer.py

Sensitive data masking tool for enterprise product diagnostics.

Consistently masks hostnames, IPs, usernames, passwords, tokens, certificates, and other sensitive data across JBoss EAP, WildFly, RHBK, Keycloak, OpenShift inspect, and must-gather files.

## Usage

```bash
python3 sanitizer.py -i <input-dir> -o <output-dir>
python3 sanitizer.py -i <input-dir> -o <output-dir> -p keycloak,jboss
python3 sanitizer.py -i <input-dir> -o <output-dir> -d          # dry-run
python3 sanitizer.py -i <input-dir> -o <output-dir> -m REDACTED  # custom mask
```

### Options

| Flag | Description |
|------|-------------|
| `-i` | Input: file, folder, or compressed archive |
| `-o` | Output folder for sanitized results |
| `-d` | Dry-run: scan and report only, no files written |
| `-m` | Custom mask string (default: `****`) |
| `-p` | Force product profiles (comma-separated, see below) |
| `--aggressive` | Enable aggressive mode (broader FQDN/JDBC/JNDI masking) |

## Output

- Sanitized copies of all input files in the output directory
- `mapping_<timestamp>.json` — correlation-friendly mapping file (no secrets stored)
- `sanitization_audit_<timestamp>.csv` — audit log of all replacements

## Pattern architecture

The sanitizer applies patterns in 4 phases:

1. **Multiline** — private keys (static mask)
2. **K8s Secrets** — `data:`/`stringData:` values in Secret manifests
3. **Line-by-line generic** — passwords, hostnames, IPs, emails, usernames
4. **Product-specific** — additional patterns activated by context or `--product`

### Generic patterns (always active)

| Category | Type | What it catches |
|----------|------|-----------------|
| `credential_kv` | static | password=, secret=, api_key=, etc. |
| `xml_secret` | static | `<password>...</password>` XML elements |
| `jwt` | static | JWT tokens (eyJ...) |
| `bearer_token` | static | Bearer tokens |
| `private_key` | static | PEM private keys |
| `jdbc_cred` | static | user/password in JDBC URLs |
| `hostname_in_url` | consistent | hostnames in http(s) URLs |
| `hostname_in_config` | consistent | host=, server=, address=, etc. |
| `ipv4` / `ipv6` | consistent | IP addresses (127.0.0.1, ::1 preserved) |
| `email` | consistent | email addresses |
| `username` | consistent | user=, login=, owner=, etc. |

### Aggressive mode patterns (`--aggressive`)

Activated by `--aggressive` flag. These run after generic patterns and before product-specific ones.

| Pattern | Type | What it catches |
|---------|------|-----------------|
| `fqdn` | consistent | Any FQDN with 2+ dots (e.g. `db.corp.local`, `app.customer.net`) |
| `jdbc_url` | consistent | Host in JDBC URLs (`jdbc:postgresql://db.corp:5432`) |
| `jndi_any` | consistent | JNDI names anywhere, not just in `jndi-name=` attributes |

Safe domains are preserved (`.redhat.com`, `.github.com`, `.apache.org`, etc.).
Java qualified names are detected and preserved (e.g. `org.apache.commons.lang.StringUtils`).

### Product-specific patterns (`PRODUCT_PATTERNS` dictionary)

Located in `sanitizer.py` at the top of the file, in the `PRODUCT_PATTERNS` dict.

**KEYCLOAK** (auto-detected from path containing `keycloak`, `rhbk`, `sso`):

| Pattern | Type | Category | What it catches |
|---------|------|----------|-----------------|
| `kc_realm_json` | consistent | `REALM` | `"realm": "customer-realm"` in JSON |
| `kc_client_id` | consistent | `CLIENT` | `"clientId": "my-app"` in JSON |
| `kc_realm_url` | consistent | `REALM` | `/realms/customer-realm/` in URLs |
| `kc_client_secret` | static | — | `"secret": "..."` in JSON |

**JBOSS_CONFIG** (auto-detected from path containing `standalone`, `jboss`, `wildfly`):

| Pattern | Type | Category | What it catches |
|---------|------|----------|-----------------|
| `jboss_jndi` | consistent | `JNDI` | `jndi-name="java:jboss/.../CustomerDS"` |
| `jboss_deployment` | consistent | `DEPLOY` | `customer-app.war`, `.ear`, `.jar` |
| `jboss_security_domain` | consistent | `SECDOMAIN` | `security-domain name="..."` |
| `jboss_vault` | static | — | `${VAULT::...}` expressions |

**OPENSHIFT** (auto-detected from path containing `namespaces/`, `must-gather`, `inspect`):

| Pattern | Type | Category | What it catches |
|---------|------|----------|-----------------|
| `oc_namespace_path` | consistent | `NAMESPACE` | `namespaces/customer-ns/` in paths |
| `oc_namespace_yaml` | consistent | `NAMESPACE` | `namespace: customer-ns` in YAML |
| `oc_serviceaccount` | consistent | `SA` | `serviceAccountName: customer-sa` |

### Preserved values (never masked)

| Category | Preserved values |
|----------|-----------------|
| IP | `127.0.0.1`, `0.0.0.0`, `255.255.255.255`, `::1` |
| HOST | `localhost`, `localhost.localdomain` |
| REALM | `master` |
| JNDI | `ExampleDS`, `DefaultDS` |
| DEPLOY | `ROOT.war`, `jboss-web.jar` |
| NAMESPACE | `default`, `kube-system`, `openshift-*`, etc. |
| SA | `default`, `builder`, `deployer` |

### Context auto-detection (`_detect_context()`)

Product patterns activate automatically based on file path keywords:

| Context | Path keywords |
|---------|--------------|
| `JBOSS_CONFIG` | `standalone`, `domain.xml`, `host.xml`, `jboss`, `wildfly` |
| `KEYCLOAK` | `keycloak`, `rhbk`, `sso` |
| `OPENSHIFT` | `namespaces/`, `cluster-scoped-resources/`, `must-gather`, `inspect` |
| `K8S_MANIFEST` | `.yaml`, `.yml`, `.json` files |
| `GENERIC` | everything else |

### Forcing product profiles (`--product`)

Use `-p` to force product patterns on ALL files, regardless of auto-detection:

```bash
# Force Keycloak patterns on every file
python3 sanitizer.py -i ./case-data -o ./out -p keycloak

# Force both Keycloak and JBoss patterns
python3 sanitizer.py -i ./case-data -o ./out -p keycloak,jboss
```

CLI names: `keycloak`/`rhbk`, `jboss`/`eap`/`wildfly`, `openshift`/`k8s`

### How to add new patterns

Edit the `PRODUCT_PATTERNS` dict in `sanitizer.py`:

```python
PRODUCT_PATTERNS = {
    'KEYCLOAK': [
        ('pattern_name', re.compile(r'...'), 'consistent', 'CATEGORY'),
        # ...
    ],
}
```

Each tuple: `(name, compiled_regex, masking_type, category)`
- `masking_type`: `'consistent'` (mapped to stable ID) or `'static'` (replaced with mask)
- `category`: ID prefix for consistent masking (e.g. `REALM_1`, `JNDI_2`)
- Add preserved values to `PRODUCT_PRESERVED` if needed

To add a new product context: add a key to `PRODUCT_PATTERNS` and update `_detect_context()`.

## Integration

Called by the agent scripts via `_sanitize_sfdc_data()` in `initcaseenv-agent-common.sh`:

```
rm old sanitized/ → sanitize to temp dir → move mapping/audit to sanitize-data/ → mv temp to sanitized/
```

## Supported file types

- Text files (XML, JSON, YAML, properties, logs, shell scripts, etc.)
- Archives (ZIP, TAR, GZ) — extracted, sanitized, re-packaged
- Binary files above 200 MB copied as-is

## Source

Maintained in `~/workspace/foldersanitizer/` and copied into the agent's `lib/` directory.

## Dependencies

- Python 3
- No external packages (stdlib only)

## Author

Daniele Mammarella <dmammare@redhat.com>
