#!/usr/bin/env python3
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
"""
FolderSanitizer - Sensitive data masking tool for enterprise product diagnostics.

Consistently masks sensitive data across JBoss EAP, WildFly, RHBK, Keycloak,
OpenShift inspect and must-gather files. Produces sanitized output with a
correlation-friendly mapping file (no secrets stored).

Author: Daniele Mammarella <dmammare@redhat.com>
"""

import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
import json
import csv
import gzip
import zipfile
import tarfile
import shutil
import tempfile
import argparse
from datetime import datetime
from collections import defaultdict

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

MAX_FILE_SIZE = 200 * 1024 * 1024  # 200 MB - files above this are copied as-is

TEXT_EXTENSIONS = (
    '.xml', '.properties', '.json', '.txt', '.yaml', '.yml',
    '.log', '.conf', '.sh', '.cfg', '.env', '.ini', '.toml',
    '.html', '.htm', '.csv', '.md',
    '.service', '.timer', '.socket',
)

PRESERVED_IPS = frozenset({
    '127.0.0.1', '0.0.0.0', '255.255.255.255', '::1', 'localhost',
})

PRESERVED_HOSTS = frozenset({
    'localhost', 'localhost.localdomain',
})

# Domains safe from aggressive FQDN masking (public/infrastructure)
PRESERVED_FQDNS_SUFFIXES = (
    '.redhat.com', '.redhat.io', '.jboss.org', '.wildfly.org',
    '.keycloak.org', '.quarkus.io', '.hibernate.org',
    '.apache.org', '.eclipse.org', '.java.net', '.oracle.com',
    '.github.com', '.github.io', '.googleapis.com',
    '.docker.io', '.docker.com', '.k8s.io', '.kubernetes.io',
    '.openshift.io', '.openshift.com', '.fedoraproject.org',
    '.centos.org', '.example.com', '.example.org',
    '.w3.org', '.xml.org', '.schema.org',
)

# ---------------------------------------------------------------------------
# Product-specific patterns
#
# Each context maps to a list of (name, regex, masking_type, category) tuples.
#   masking_type: 'consistent' → value mapped to stable ID (stored in mapping)
#                 'static'     → value replaced with mask (no mapping)
#   category:     ID category for consistent masking (e.g. 'REALM', 'JNDI')
#
# Contexts: KEYCLOAK, JBOSS_CONFIG, OPENSHIFT, K8S_MANIFEST, GENERIC
# A pattern is applied when the file's detected context matches its key,
# OR when '--product' forces a profile regardless of context.
#
# To add patterns: append tuples to the relevant context list below.
# To add a new context: add a new key and update _detect_context().
# ---------------------------------------------------------------------------

PRODUCT_PATTERNS = {
    'KEYCLOAK': [
        # Realm name in JSON exports: "realm": "customer-realm"
        ('kc_realm_json', re.compile(
            r'("realm"\s*:\s*")'
            r'([^"]{2,})'
            r'(")'
        ), 'consistent', 'REALM'),
        # Client ID in JSON: "clientId": "my-app"
        ('kc_client_id', re.compile(
            r'("clientId"\s*:\s*")'
            r'([^"]{2,})'
            r'(")'
        ), 'consistent', 'CLIENT'),
        # Realm name in URL paths: /realms/customer-realm/ or /auth/realms/...
        ('kc_realm_url', re.compile(
            r'(/(?:auth/)?realms/)'
            r'([a-zA-Z0-9][a-zA-Z0-9._-]{1,})'
            r'([/?\s"\'&]|$)'
        ), 'consistent', 'REALM'),
        # Redirect URIs in JSON: "redirectUris": ["https://..."]
        # (hostnames already caught by generic hostname_in_url pattern)
        # Client secret in JSON: "secret": "..." (static mask)
        ('kc_client_secret', re.compile(
            r'("secret"\s*:\s*")'
            r'([^"]+)'
            r'(")'
        ), 'static', None),
    ],

    'JBOSS_CONFIG': [
        # JNDI names: java:jboss/datasources/CustomerDS, java:/CustomerQueue
        # Captures the last path segment (the actual datasource/queue name)
        ('jboss_jndi', re.compile(
            r'((?:jndi-name|pool-name)\s*=\s*["\']?(?:java:[a-zA-Z0-9:/]*/)?)'
            r'([a-zA-Z][a-zA-Z0-9_-]{2,})'
            r'(["\s<\'/>]|$)'
        ), 'consistent', 'JNDI'),
        # Deployment names: customer-app.war, myapp.ear
        ('jboss_deployment', re.compile(
            r'(?<![a-zA-Z0-9_/.-])'
            r'([a-zA-Z][a-zA-Z0-9_.-]{2,}\.(?:war|ear|jar))'
            r'(?![a-zA-Z0-9_.-])'
        ), 'consistent', 'DEPLOY'),
        # Security domain name: <security-domain name="my-domain">
        ('jboss_security_domain', re.compile(
            r'(security-domain\s+name\s*=\s*["\'])'
            r'([^"\']+)'
            r'(["\'])'
        ), 'consistent', 'SECDOMAIN'),
        # Vault expressions: ${VAULT::keystore::password::...}
        ('jboss_vault', re.compile(
            r'(\$\{VAULT::)'
            r'([^}]+)'
            r'(\})'
        ), 'static', None),
    ],

    'OPENSHIFT': [
        # Namespace/project in paths: namespaces/customer-project/
        ('oc_namespace_path', re.compile(
            r'(namespaces?/)'
            r'([a-zA-Z][a-zA-Z0-9._-]{1,})'
            r'(/)'
        ), 'consistent', 'NAMESPACE'),
        # Namespace in YAML: namespace: customer-project
        ('oc_namespace_yaml', re.compile(
            r'((?:namespace|project)\s*:\s*)'
            r'([a-zA-Z][a-zA-Z0-9._-]{1,})'
            r'(\s|$)'
        ), 'consistent', 'NAMESPACE'),
        # Route host: host: app.customer.example.com
        # (hostnames already caught by generic patterns, this adds route-specific)
        # ServiceAccount names
        ('oc_serviceaccount', re.compile(
            r'(serviceAccountName\s*:\s*)'
            r'([a-zA-Z][a-zA-Z0-9._-]{1,})'
            r'(\s|$)'
        ), 'consistent', 'SA'),
    ],
}

# Preserved values that should NOT be masked by product patterns
PRESERVED_REALMS = frozenset({'master'})
PRESERVED_JNDI = frozenset({
    'ExampleDS', 'DefaultDS', 'java:jboss/datasources/ExampleDS',
})
PRESERVED_DEPLOYS = frozenset({
    'ROOT.war', 'jboss-web.jar',
})
PRESERVED_NAMESPACES = frozenset({
    'default', 'kube-system', 'kube-public', 'kube-node-lease',
    'openshift', 'openshift-infra', 'openshift-node',
    'openshift-monitoring', 'openshift-operators',
})

PRESERVED_SA = frozenset({
    'default', 'builder', 'deployer',
})

PRODUCT_PRESERVED = {
    'REALM': PRESERVED_REALMS,
    'JNDI': PRESERVED_JNDI,
    'DEPLOY': PRESERVED_DEPLOYS,
    'NAMESPACE': PRESERVED_NAMESPACES,
    'SA': PRESERVED_SA,
}

# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class FolderSanitizer:

    def __init__(self, input_path, output_root, dry_run=False, mask='****',
                 product_contexts=None, aggressive=False):
        self.input_path = os.path.abspath(input_path)
        self.output_root = os.path.abspath(output_root)
        self.dry_run = dry_run
        self.mask = mask
        self.aggressive = aggressive

        # Product contexts forced via --product (applied to ALL files)
        self._forced_contexts = set(product_contexts or [])

        # Consistent-masking state  (category, original) -> ID
        self._id_map = {}
        self._counters = defaultdict(int)

        # Statistics
        self._file_count = 0
        self._sanitized_count = 0
        self._stats = defaultdict(int)

        # Output paths
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        self._audit_path = os.path.join(output_root, f'sanitization_audit_{ts}.csv')
        self._mapping_path = os.path.join(output_root, f'mapping_{ts}.json')

        self._compile_patterns()

    # ---- pattern compilation ------------------------------------------------

    def _compile_patterns(self):
        """All regex patterns, split by masking strategy."""

        # STATIC masking - value is destroyed, never stored
        self.static_patterns = {
            'credential_kv': re.compile(
                r'(?i)'
                r'((?:password|passwd|passphrase|secret|credential|'
                r'auth[_-]?key|bind[_-]?credential|bind[_-]?password|'
                r'keystore[_-]?password|truststore[_-]?password|'
                r'key[_-]?password|storepass|keypass|'
                r'client[_-]?secret|api[_-]?key|api[_-]?secret|'
                r'access[_-]?token|refresh[_-]?token|'
                r'secret[_-]?key|adminPassword|sslPassword|'
                r'connectionPassword|managementPassword)'
                r'\s*[:=]\s*["\']?)'          # group 1 - label + separator
                r'([^"\'\s,<>\n\r}{]+)'       # group 2 - the secret value
                r'(["\']?)'                   # group 3 - optional closing quote
            ),
            'xml_secret': re.compile(
                r'(<[^>]*?(?:password|secret|credential|keystore|'
                r'truststore|key-password|storepass|ssl-password|'
                r'connection-password|management-password)[^>]*?>)'
                r'([^<]+)'
                r'(</[^>]*?>)',
                re.IGNORECASE,
            ),
            'jwt': re.compile(
                r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}'
                r'\.[A-Za-z0-9_.+/=-]*'
            ),
            'bearer_token': re.compile(
                r'(?i)(Bearer\s+)([A-Za-z0-9_\-.~+/]{8,}=*)'
            ),
            'private_key': re.compile(
                r'-----BEGIN\s+(?:[\w\s]+)?PRIVATE\s+KEY-----'
                r'[\s\S]*?'
                r'-----END\s+(?:[\w\s]+)?PRIVATE\s+KEY-----'
            ),
            'jdbc_cred': re.compile(
                r'(?i)(jdbc:[a-z0-9+:]+//[^?]*\?[^"\'<>\s]*?'
                r'(?:user|password)\s*=\s*)([^&\s"\'>]+)'
            ),
        }

        # CONSISTENT masking - values mapped to stable IDs, stored in mapping
        self.consistent_patterns = {
            'hostname_in_url': re.compile(
                r'(https?://)'
                r'([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
                r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*'
                r'\.[a-zA-Z]{2,})'
                r'([:/?#]|$)'
            ),
            'hostname_in_config': re.compile(
                r'(?i)((?:host|hostname|server|node[_-]?name|address|'
                r'endpoint|broker|jboss\.bind\.address|'
                r'jboss\.default\.multicast\.address)\s*[:=]\s*["\']?)'
                r'([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
                r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)'
                r'(["\']?)'
            ),
            'ipv4': re.compile(
                r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
                r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b'
            ),
            'ipv6': re.compile(
                r'(?<![:\w])'
                r'((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}'
                r'|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
                r'|fe80::[0-9a-fA-F:]+%[a-zA-Z0-9]+)'
                r'(?![:\w])'
            ),
            'email': re.compile(
                r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b'
            ),
            'username': re.compile(
                r'(?i)((?:user|username|login|uid|run[_-]?as[_-]?user|'
                r'owner|admin[_-]?user|principal)\s*[:=]\s*["\']?)'
                r'([a-zA-Z][a-zA-Z0-9._@-]{1,})'
                r'(["\']?)'
            ),
            # Comment author / case owner lines (e.g. "Author: John Smith", "Owner: Jane Doe")
            'comment_author': re.compile(
                r'^((?:Author|Owner):\s*)'
                r'(.+?)'
                r'(\s*$)',
                re.MULTILINE
            ),
        }

        # AGGRESSIVE patterns - broader hostname/FQDN detection
        # Only active when --aggressive is passed
        self.aggressive_patterns = {
            # Any FQDN with 2+ dots (e.g. db.corp.local, keycloak.internal.company.com)
            # Excludes common safe domains (redhat.com, github.com, etc.)
            'fqdn': re.compile(
                r'(?<![a-zA-Z0-9@/.-])'
                r'([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
                r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?){2,})'
                r'(?![a-zA-Z0-9.-])'
            ),
            # JDBC connection URLs (mask the host part)
            'jdbc_url': re.compile(
                r'(jdbc:[a-z0-9+:]+//)'
                r'([a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?)'
                r'(:\d+)'
            ),
            # JNDI names anywhere (not just in jndi-name= attributes)
            'jndi_any': re.compile(
                r'(java:(?:jboss|comp|global|app|module)/[a-zA-Z0-9/]*?)'
                r'([a-zA-Z][a-zA-Z0-9_-]{2,})'
                r'(["\s<\'/>,;]|$)'
            ),
        }

        # K8s Secret-specific patterns
        self._re_kind_secret = re.compile(r'^\s*kind:\s*Secret\s*$', re.MULTILINE)
        self._re_metadata_name = re.compile(
            r'^(\s+name:\s*)(\S+)\s*$', re.MULTILINE
        )

    # ---- consistent ID management ------------------------------------------

    def _get_id(self, original, category):
        """Return a stable replacement ID for *original* within *category*."""
        if category in ('IP', 'IPV6') and original in PRESERVED_IPS:
            return original
        if category == 'HOST' and original.lower() in PRESERVED_HOSTS:
            return original
        key = (category, original)
        if key not in self._id_map:
            self._counters[category] += 1
            self._id_map[key] = f'{category}_{self._counters[category]}'
        return self._id_map[key]

    # ---- context detection --------------------------------------------------

    @staticmethod
    def _detect_context(path):
        p = path.lower()
        if any(k in p for k in ('standalone', 'domain.xml', 'host.xml',
                                 'jboss', 'wildfly')):
            return 'JBOSS_CONFIG'
        if any(k in p for k in ('keycloak', 'rhbk', 'sso')):
            return 'KEYCLOAK'
        if any(k in p for k in ('namespaces/', 'cluster-scoped-resources/',
                                 'must-gather', 'inspect')):
            return 'OPENSHIFT'
        if p.endswith(('.yaml', '.yml', '.json')):
            return 'K8S_MANIFEST'
        return 'GENERIC'

    # ---- K8s Secret handling ------------------------------------------------

    def _sanitize_k8s_secret_blocks(self, content, stats):
        """Mask data/stringData values and resource names in Secret manifests."""
        docs = re.split(r'^---\s*$', content, flags=re.MULTILINE)
        out_docs = []

        for doc in docs:
            if not self._re_kind_secret.search(doc):
                out_docs.append(doc)
                continue

            # -- consistent-mask the metadata name
            def _replace_name(m):
                stats['k8s_resource_name'] += 1
                return m.group(1) + self._get_id(m.group(2), 'RESOURCE')
            doc = self._re_metadata_name.sub(_replace_name, doc)

            # -- static-mask values under data: / stringData:
            lines = doc.split('\n')
            new_lines = []
            in_data = False
            data_indent = 0

            for line in lines:
                stripped = line.lstrip()
                indent = len(line) - len(stripped)

                if re.match(r'^(data|stringData)\s*:\s*$', stripped):
                    in_data = True
                    data_indent = indent
                    new_lines.append(line)
                    continue

                if in_data:
                    if stripped and not stripped.startswith('#') and indent <= data_indent:
                        in_data = False
                    elif stripped and not stripped.startswith('#'):
                        kv = re.match(r'^(\s*\S+:\s+)(.+)$', line)
                        if kv:
                            stats['k8s_secret_data'] += 1
                            line = kv.group(1) + self.mask

                new_lines.append(line)

            doc = '\n'.join(new_lines)
            out_docs.append(doc)

        return '---'.join(out_docs)

    # ---- core sanitization --------------------------------------------------

    def _sanitize_content(self, content, file_path):
        """Apply every pattern to *content*.  Returns (sanitized, stats)."""
        stats = defaultdict(int)
        ctx = self._detect_context(file_path)

        # Phase 1 - multiline (private keys)
        def _mask_pk(m):
            stats['private_key'] += 1
            return f'-----PRIVATE KEY {self.mask}-----'
        content = self.static_patterns['private_key'].sub(_mask_pk, content)

        # Phase 2 - K8s Secret blocks
        if ctx in ('OPENSHIFT', 'K8S_MANIFEST') and self._re_kind_secret.search(content):
            content = self._sanitize_k8s_secret_blocks(content, stats)

        # Phase 3 - line-by-line patterns
        mask = self.mask  # local ref for speed
        lines = content.split('\n')
        result = []

        for line in lines:
            # -- static patterns --
            for name, pat in self.static_patterns.items():
                if name == 'private_key':
                    continue
                found = pat.findall(line)
                if not found:
                    continue
                stats[name] += len(found)
                if name == 'credential_kv':
                    line = pat.sub(rf'\g<1>{mask}\3', line)
                elif name == 'xml_secret':
                    line = pat.sub(rf'\g<1>{mask}\3', line)
                elif name == 'jwt':
                    line = pat.sub(f'JWT_{mask}', line)
                elif name == 'bearer_token':
                    line = pat.sub(rf'\g<1>{mask}', line)
                elif name == 'jdbc_cred':
                    line = pat.sub(rf'\g<1>{mask}', line)

            # -- consistent patterns (order: URLs > config hosts > IPs > email > user) --

            def _url_host(m):
                stats['hostname'] += 1
                return m.group(1) + self._get_id(m.group(2), 'HOST') + m.group(3)
            line = self.consistent_patterns['hostname_in_url'].sub(_url_host, line)

            def _cfg_host(m):
                stats['hostname'] += 1
                return m.group(1) + self._get_id(m.group(2), 'HOST') + m.group(3)
            line = self.consistent_patterns['hostname_in_config'].sub(_cfg_host, line)

            def _ipv4(m):
                ip = m.group(1)
                if ip in PRESERVED_IPS:
                    return ip
                stats['ipv4'] += 1
                return self._get_id(ip, 'IP')
            line = self.consistent_patterns['ipv4'].sub(_ipv4, line)

            def _ipv6(m):
                ip = m.group(1)
                if ip in PRESERVED_IPS:
                    return ip
                stats['ipv6'] += 1
                return self._get_id(ip, 'IPV6')
            line = self.consistent_patterns['ipv6'].sub(_ipv6, line)

            def _email(m):
                stats['email'] += 1
                return self._get_id(m.group(1), 'EMAIL')
            line = self.consistent_patterns['email'].sub(_email, line)

            def _user(m):
                stats['username'] += 1
                return m.group(1) + self._get_id(m.group(2), 'USER') + m.group(3)
            line = self.consistent_patterns['username'].sub(_user, line)

            def _comment_author(m):
                stats['comment_author'] += 1
                return m.group(1) + self._get_id(m.group(2).strip(), 'PERSON') + m.group(3)
            line = self.consistent_patterns['comment_author'].sub(_comment_author, line)

            # -- aggressive patterns (broad FQDN, JDBC host, JNDI anywhere) --
            if self.aggressive:
                def _fqdn(m):
                    fqdn = m.group(1)
                    low = fqdn.lower()
                    if low in PRESERVED_HOSTS:
                        return m.group(0)
                    if any(low.endswith(s) for s in PRESERVED_FQDNS_SUFFIXES):
                        return m.group(0)
                    # Skip Java qualified names: lowercase segments + optional PascalCase
                    # class, but NOT if ending in a common TLD (.com,.net,.org,.io,.local)
                    if (re.match(r'^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*){2,}(\.[A-Z][a-zA-Z0-9]*)?$', fqdn)
                            and not re.search(r'\.(com|net|org|io|dev|local|internal|corp|lan)$', fqdn)):
                        return m.group(0)
                    stats['fqdn'] += 1
                    return self._get_id(fqdn, 'HOST')
                line = self.aggressive_patterns['fqdn'].sub(_fqdn, line)

                def _jdbc_url(m):
                    host = m.group(2)
                    if host.lower() in PRESERVED_HOSTS:
                        return m.group(0)
                    stats['jdbc_url'] += 1
                    return m.group(1) + self._get_id(host, 'HOST') + m.group(3)
                line = self.aggressive_patterns['jdbc_url'].sub(_jdbc_url, line)

                def _jndi_any(m):
                    name = m.group(2)
                    if name in PRESERVED_JNDI:
                        return m.group(0)
                    stats['jndi_any'] += 1
                    return m.group(1) + self._get_id(name, 'JNDI') + m.group(3)
                line = self.aggressive_patterns['jndi_any'].sub(_jndi_any, line)

            result.append(line)

        content = '\n'.join(result)

        # Phase 4 - product-specific patterns
        active_contexts = self._forced_contexts | {ctx}
        for pctx in active_contexts:
            for name, pat, mtype, category in PRODUCT_PATTERNS.get(pctx, []):
                preserved = PRODUCT_PRESERVED.get(category, frozenset())

                if mtype == 'static':
                    def _pp_static(m, _n=name):
                        stats[_n] += 1
                        return m.group(1) + self.mask + m.group(3)
                    content = pat.sub(_pp_static, content)
                else:  # consistent
                    def _pp_consistent(m, _n=name, _c=category, _p=preserved):
                        val = m.group(2) if m.lastindex >= 2 else m.group(1)
                        if val in _p:
                            return m.group(0)
                        stats[_n] += 1
                        repl = self._get_id(val, _c)
                        if m.lastindex >= 3:
                            return m.group(1) + repl + m.group(3)
                        elif m.lastindex >= 2:
                            return m.group(1) + repl
                        return repl
                    content = pat.sub(_pp_consistent, content)

        # Phase 5 - mask known PERSON/USER names in free text
        # After all patterns have run, names collected from Author:/Owner: lines
        # may still appear elsewhere (e.g. signatures, greetings). Replace them.
        person_names = {}
        for (cat, orig), replacement in self._id_map.items():
            if cat == 'PERSON':
                person_names[orig] = replacement
                # Also mask individual name parts (e.g. "Abbate, Stefano" → "Abbate", "Stefano")
                for part in re.split(r'[,\s]+', orig):
                    part = part.strip()
                    if len(part) >= 3:  # skip short fragments
                        person_names[part] = replacement

        # Sort by length descending to avoid partial replacements
        for name in sorted(person_names, key=len, reverse=True):
            replacement = person_names[name]
            pattern = re.compile(re.escape(name), re.IGNORECASE)
            new_content = pattern.sub(replacement, content)
            if new_content != content:
                stats['person_in_text'] += new_content.count(replacement) - content.count(replacement)
                content = new_content

        # aggregate into global stats
        for k, v in stats.items():
            self._stats[k] += v

        return content, stats

    # ---- audit log ----------------------------------------------------------

    def _init_audit(self):
        os.makedirs(self.output_root, exist_ok=True)
        with open(self._audit_path, 'w', newline='', encoding='utf-8') as f:
            csv.writer(f).writerow(
                ['Timestamp', 'File', 'Context', 'Pattern', 'Matches', 'Status']
            )

    def _log_audit(self, rel_path, context, stats):
        status = 'DRY-RUN' if self.dry_run else 'SANITIZED'
        with open(self._audit_path, 'a', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            for pat, count in stats.items():
                if count > 0:
                    w.writerow([datetime.now().isoformat(), rel_path,
                                context, pat, count, status])

    # ---- mapping export -----------------------------------------------------

    def _export_mapping(self):
        """Write the identity map to JSON.  Contains ONLY correlatable IDs
        (IP, HOST, EMAIL, USER, RESOURCE).  NEVER secrets or passwords."""
        out = {}
        for (cat, orig), replacement in sorted(self._id_map.items()):
            out.setdefault(cat, {})[replacement] = orig

        with open(self._mapping_path, 'w', encoding='utf-8') as f:
            json.dump(out, f, indent=2, ensure_ascii=False)

        print(f'[*] Mapping file: {self._mapping_path}')
        print('    (contains original values - keep it secure!)')

    # ---- safe extraction ----------------------------------------------------

    @staticmethod
    def _safe_zip_extract(zf, dest):
        dest = os.path.abspath(dest)
        for info in zf.infolist():
            target = os.path.abspath(os.path.join(dest, info.filename))
            if not target.startswith(dest + os.sep) and target != dest:
                raise RuntimeError(f'ZipSlip blocked: {info.filename}')
        zf.extractall(dest)

    @staticmethod
    def _safe_tar_extract(tf, dest):
        dest = os.path.abspath(dest)
        for member in tf.getmembers():
            target = os.path.abspath(os.path.join(dest, member.name))
            if not target.startswith(dest + os.sep) and target != dest:
                raise RuntimeError(f'Path traversal blocked: {member.name}')
        tf.extractall(dest)

    # ---- file processors ----------------------------------------------------

    def _sanitize_and_write(self, content, in_path, out_path, rel_path,
                            writer=None):
        """Sanitize content and write output. writer(path, data) handles format."""
        ctx = self._detect_context(rel_path)
        sanitized, stats = self._sanitize_content(content, rel_path)
        touched = any(v > 0 for v in stats.values())

        if touched:
            self._sanitized_count += 1

        if not self.dry_run:
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            if touched:
                writer(out_path, sanitized)
            elif in_path != out_path:
                shutil.copy2(in_path, out_path)

        if touched:
            self._log_audit(rel_path, ctx, stats)

    def _process_text(self, in_path, out_path, rel_path):
        self._file_count += 1

        if os.path.getsize(in_path) > MAX_FILE_SIZE:
            print(f'  [!] Skipped (too large): {rel_path}')
            if not self.dry_run and in_path != out_path:
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                shutil.copy2(in_path, out_path)
            return

        try:
            with open(in_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            def _write(path, data):
                with open(path, 'w', encoding='utf-8') as fh:
                    fh.write(data)

            self._sanitize_and_write(content, in_path, out_path, rel_path,
                                     _write)
        except Exception as exc:
            print(f'  [!] Error: {rel_path} -> {exc}')

    def _process_gzip(self, in_path, out_path, rel_path):
        self._file_count += 1
        try:
            with gzip.open(in_path, 'rt', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            def _write(path, data):
                with gzip.open(path, 'wt', encoding='utf-8') as fh:
                    fh.write(data)

            self._sanitize_and_write(content, in_path, out_path, rel_path,
                                     _write)
        except Exception as exc:
            print(f'  [!] gzip error: {rel_path} -> {exc}')

    @staticmethod
    def _extract_archive(path, dest):
        """Extract an archive (zip/jar/war/ear/tar.gz/tgz/tar.bz2/tar.xz) into dest."""
        low = path.lower()
        if low.endswith(('.zip', '.jar', '.war', '.ear')):
            with zipfile.ZipFile(path, 'r') as zf:
                FolderSanitizer._safe_zip_extract(zf, dest)
        elif low.endswith(('.tar.gz', '.tgz')):
            with tarfile.open(path, 'r:gz') as tf:
                FolderSanitizer._safe_tar_extract(tf, dest)
        elif low.endswith('.tar.bz2'):
            with tarfile.open(path, 'r:bz2') as tf:
                FolderSanitizer._safe_tar_extract(tf, dest)
        elif low.endswith('.tar.xz'):
            with tarfile.open(path, 'r:xz') as tf:
                FolderSanitizer._safe_tar_extract(tf, dest)
        else:
            return False
        return True

    @staticmethod
    def _repack_archive(src_dir, out_path, original_path):
        """Repack a directory into the same archive format as original_path."""
        low = original_path.lower()
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        if low.endswith(('.zip', '.jar', '.war', '.ear')):
            with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for r, _, fs in os.walk(src_dir):
                    for fn in fs:
                        fp = os.path.join(r, fn)
                        zf.write(fp, os.path.relpath(fp, src_dir))
        else:
            mode = 'w:gz'
            if low.endswith('.tar.bz2'):
                mode = 'w:bz2'
            elif low.endswith('.tar.xz'):
                mode = 'w:xz'
            with tarfile.open(out_path, mode) as tf:
                for r, _, fs in os.walk(src_dir):
                    for fn in fs:
                        fp = os.path.join(r, fn)
                        tf.add(fp, os.path.relpath(fp, src_dir))

    def _process_archive(self, in_path, out_path, rel_path):
        with tempfile.TemporaryDirectory() as tmp_in:
            try:
                if not self._extract_archive(in_path, tmp_in):
                    return

                with tempfile.TemporaryDirectory() as tmp_out:
                    self._scan_dir(tmp_in, tmp_out, prefix=rel_path)

                    if not self.dry_run:
                        self._repack_archive(tmp_out, out_path, in_path)

            except Exception as exc:
                print(f'  [!] Archive error: {rel_path} -> {exc}')

    # ---- directory scanner --------------------------------------------------

    def _sanitize_filename(self, fname):
        """Sanitize a filename by applying consistent patterns to it.
        Preserves the file extension. Returns (sanitized_name, was_changed)."""
        # Split extension(s) — handle .tar.gz, .tar.bz2 etc.
        base = fname
        ext = ''
        for multi_ext in ('.tar.gz', '.tar.bz2', '.tar.xz'):
            if fname.lower().endswith(multi_ext):
                base = fname[:-len(multi_ext)]
                ext = fname[-len(multi_ext):]
                break
        if not ext:
            base, ext = (os.path.splitext(fname)[0], os.path.splitext(fname)[1])

        sanitized = base
        changed = False

        # Apply hostname, IP, email patterns to filename
        for pat_name in ('hostname_in_url', 'hostname_in_config', 'ipv4', 'email'):
            pat = self.consistent_patterns.get(pat_name)
            if pat and pat.search(sanitized):
                if pat_name in ('hostname_in_url', 'hostname_in_config'):
                    def _repl(m):
                        return m.group(1) + self._get_id(m.group(2), 'HOST') + m.group(3)
                elif pat_name == 'ipv4':
                    def _repl(m):
                        ip = m.group(1)
                        return ip if ip in PRESERVED_IPS else self._get_id(ip, 'IP')
                elif pat_name == 'email':
                    def _repl(m):
                        return self._get_id(m.group(1), 'EMAIL')
                new = pat.sub(_repl, sanitized)
                if new != sanitized:
                    sanitized = new
                    changed = True

        # Apply aggressive FQDN to filename if enabled
        if self.aggressive and 'fqdn' in self.aggressive_patterns:
            pat = self.aggressive_patterns['fqdn']
            def _fqdn_repl(m):
                fqdn = m.group(1)
                if fqdn.lower() in PRESERVED_HOSTS:
                    return m.group(0)
                if any(fqdn.lower().endswith(s) for s in PRESERVED_FQDNS_SUFFIXES):
                    return m.group(0)
                return self._get_id(fqdn, 'HOST')
            new = pat.sub(_fqdn_repl, sanitized)
            if new != sanitized:
                sanitized = new
                changed = True

        return sanitized + ext, changed

    def _scan_dir(self, input_dir, output_dir, prefix=''):
        # Process comment files first so PERSON names are in the mapping
        # before other files (e.g. case-description.txt) are sanitized.
        all_entries = []
        for root, dirs, files in os.walk(input_dir):
            for fname in sorted(files):
                in_f = os.path.join(root, fname)
                rel = os.path.relpath(in_f, input_dir)
                is_comment = '/comments/' in ('/' + rel.replace(os.sep, '/') + '/')
                all_entries.append((root, fname, is_comment))
        # Comments first, then everything else
        all_entries.sort(key=lambda e: (0 if e[2] else 1, e[0], e[1]))

        for root, fname, _ in all_entries:
                in_f = os.path.join(root, fname)
                rel = os.path.relpath(in_f, input_dir)
                audit_rel = os.path.join(prefix, rel) if prefix else rel

                # Sanitize the filename itself
                san_fname, fname_changed = self._sanitize_filename(fname)
                san_rel = os.path.join(os.path.dirname(rel), san_fname) if os.path.dirname(rel) else san_fname
                out_f = os.path.join(output_dir, san_rel)

                lower = fname.lower()
                full_lower = in_f.lower()

                if full_lower.endswith(('.tar.gz', '.tgz', '.tar.bz2', '.tar.xz')):
                    self._process_archive(in_f, out_f, audit_rel)
                elif lower.endswith(('.zip', '.jar', '.war', '.ear')):
                    self._process_archive(in_f, out_f, audit_rel)
                elif lower.endswith('.gz'):
                    self._process_gzip(in_f, out_f, audit_rel)
                elif lower.endswith(TEXT_EXTENSIONS):
                    self._process_text(in_f, out_f, audit_rel)
                else:
                    if not self.dry_run and in_f != out_f:
                        os.makedirs(os.path.dirname(out_f), exist_ok=True)
                        shutil.copy2(in_f, out_f)

    # ---- post-processing: cross-file PERSON masking -------------------------

    def _postprocess_person_names(self):
        """Re-scan output files to mask PERSON names found across all files."""
        # Build replacement map from all PERSON entries
        replacements = {}
        for (cat, orig), replacement in self._id_map.items():
            if cat != 'PERSON':
                continue
            replacements[orig] = replacement
            # Individual name parts (>= 3 chars)
            for part in re.split(r'[,\s]+', orig):
                part = part.strip()
                if len(part) >= 3:
                    replacements[part] = replacement

        if not replacements:
            return

        # Sort by length descending to avoid partial replacements
        sorted_names = sorted(replacements, key=len, reverse=True)

        for root, _, files in os.walk(self.output_root):
            for fname in files:
                fpath = os.path.join(root, fname)
                if not fname.lower().endswith(TEXT_EXTENSIONS):
                    continue
                # Skip mapping/audit files
                if fname.startswith('mapping_') or fname.startswith('sanitization_audit_'):
                    continue
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                except Exception:
                    continue

                new_content = content
                for name in sorted_names:
                    pattern = re.compile(re.escape(name), re.IGNORECASE)
                    new_content = pattern.sub(replacements[name], new_content)

                if new_content != content:
                    with open(fpath, 'w', encoding='utf-8') as f:
                        f.write(new_content)

    # ---- entry point --------------------------------------------------------

    def run(self):
        self._init_audit()

        mode = 'DRY-RUN' if self.dry_run else 'LIVE'
        print(f'[*] Mode:   {mode}')
        print(f'[*] Input:  {self.input_path}')
        print(f'[*] Output: {self.output_root}')
        print(f'[*] Mask:   {self.mask}')
        if self.aggressive:
            print('[*] Mode:   AGGRESSIVE')
        if self._forced_contexts:
            print(f'[*] Forced: {", ".join(sorted(self._forced_contexts))}')
        print()

        low = self.input_path.lower()

        if os.path.isfile(self.input_path):
            if low.endswith(('.tar.gz', '.tgz', '.tar.bz2', '.tar.xz', '.zip')):
                # top-level archive -> extract into output as flat directory
                with tempfile.TemporaryDirectory() as tmp:
                    try:
                        self._extract_archive(self.input_path, tmp)
                        self._scan_dir(tmp, self.output_root)
                    except Exception as exc:
                        print(f'[!] Fatal: {exc}')
                        return

            elif low.endswith('.gz'):
                fn = os.path.basename(self.input_path)
                self._process_gzip(self.input_path,
                                   os.path.join(self.output_root, fn), fn)
            else:
                fn = os.path.basename(self.input_path)
                out = os.path.join(self.output_root, fn)
                if fn.lower().endswith(TEXT_EXTENSIONS):
                    self._process_text(self.input_path, out, fn)
                else:
                    if not self.dry_run:
                        os.makedirs(self.output_root, exist_ok=True)
                        shutil.copy2(self.input_path, out)

        elif os.path.isdir(self.input_path):
            self._scan_dir(self.input_path, self.output_root)
        else:
            print(f"[!] '{self.input_path}' does not exist.")
            return

        # Post-processing: mask PERSON names discovered cross-file
        if not self.dry_run:
            self._postprocess_person_names()

        # Export mapping (always, even dry-run - useful for review)
        if self._id_map:
            self._export_mapping()

        # Summary
        print()
        print('=' * 60)
        print('  SANITIZATION SUMMARY')
        print('=' * 60)
        print(f'  Files scanned:     {self._file_count}')
        print(f'  Files sanitized:   {self._sanitized_count}')
        print(f'  Audit log:         {self._audit_path}')
        if self._id_map:
            print(f'  Mapping file:      {self._mapping_path}')
        print()
        if self._stats:
            print('  Detections by pattern:')
            for name, count in sorted(self._stats.items(), key=lambda x: -x[1]):
                print(f'    {name:30s} {count:>6d}')
        else:
            print('  No sensitive data detected.')
        print('=' * 60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Sanitize sensitive data in JBoss/WildFly, Keycloak/RHBK, '
                    'and OpenShift diagnostic files.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''\
examples:
  %(prog)s -i ./must-gather.tar.gz -o ./sanitized
  %(prog)s -i ./standalone.xml    -o ./out
  %(prog)s -i ./inspect_folder    -o ./out -d        (dry-run)
  %(prog)s -i ./jboss_logs        -o ./out -m REDACTED
''',
    )
    parser.add_argument('-i', '--input',
                        default=os.environ.get('SANITIZER_INPUT_DIR', '/opt/foldersanitizer/data/input'),
                        help='Input: file, folder, or compressed archive '
                             '(env: SANITIZER_INPUT_DIR, default: /opt/foldersanitizer/data/input)')
    parser.add_argument('-o', '--output',
                        default=os.environ.get('SANITIZER_OUTPUT_DIR', '/opt/foldersanitizer/data/output'),
                        help='Output folder for sanitized results '
                             '(env: SANITIZER_OUTPUT_DIR, default: /opt/foldersanitizer/data/output)')
    parser.add_argument('-d', '--dry-run', action='store_true',
                        help='Scan and report only, do not write sanitized files')
    parser.add_argument('-m', '--mask', default='****',
                        help='Replacement string for secrets (default: ****)')
    parser.add_argument('-p', '--product', default='',
                        help='Force product profiles (comma-separated: '
                             'keycloak,jboss,openshift). Applied to ALL files '
                             'regardless of auto-detection.')
    parser.add_argument('--aggressive', action='store_true',
                        help='Aggressive mode: also mask FQDNs, JDBC hosts, '
                             'and JNDI names found anywhere in text. '
                             'Safe domains (redhat.com, github.com, etc.) '
                             'are preserved.')

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: '{args.input}' not found.")
        sys.exit(1)

    if os.path.abspath(args.input) == os.path.abspath(args.output):
        print('Error: input and output paths must differ.')
        sys.exit(1)

    # Resolve product names to sanitizer context keys.
    # 1. Load alias map from product-aliases.conf (shared with bash scripts)
    # 2. Resolve alias to canonical type
    # 3. Map canonical type to sanitizer context key
    aliases_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'product-aliases.conf')
    alias_map = {}
    if os.path.isfile(aliases_file):
        with open(aliases_file, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    alias, canonical = line.split('=', 1)
                    alias_map[alias.strip()] = canonical.strip()

    # Canonical type → sanitizer context key
    type_to_context = {
        'rhbk': 'KEYCLOAK',
        'sso': 'KEYCLOAK',
        'eap': 'JBOSS_CONFIG',
        'openshift': 'OPENSHIFT',
    }

    product_contexts = []
    if args.product:
        for p in args.product.split(','):
            p = p.strip().lower()
            # Resolve alias first (keycloak→rhbk, sso→rhbk, etc.)
            canonical = alias_map.get(p, p)
            ctx = type_to_context.get(canonical)
            if ctx is None:
                available = sorted(set(list(alias_map.keys()) +
                                       list(type_to_context.keys())))
                print(f"Error: unknown product '{p}'. "
                      f"Available: {', '.join(available)}")
                sys.exit(1)
            product_contexts.append(ctx)

    FolderSanitizer(
        input_path=args.input,
        output_root=args.output,
        dry_run=args.dry_run,
        mask=args.mask,
        product_contexts=product_contexts,
        aggressive=args.aggressive,
    ).run()


if __name__ == '__main__':
    main()
