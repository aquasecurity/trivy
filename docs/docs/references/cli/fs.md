# Filesystem

```bash
Scan local filesystem

Usage:
  trivy filesystem [flags] PATH

Aliases:
  filesystem, fs

Examples:
  # Scan a local project including language-specific files
  $ trivy fs /path/to/your_project

  # Scan a single file
  $ trivy fs ./trivy-ci-test/Pipfile.lock

Scan Flags
      --offline-scan             do not issue API requests to identify dependencies
      --security-checks string   comma-separated list of what security issues to detect (vuln,config,secret) (default "vuln,secret")
      --skip-dirs strings        specify the directories where the traversal is skipped
      --skip-files strings       specify the file paths to skip traversal

Report Flags
      --dependency-tree        show dependency origin tree (EXPERIMENTAL)
      --exit-code int          specify exit code when any security issues are found
  -f, --format string          format (table, json, sarif, template, cyclonedx, spdx, spdx-json, github, cosign-vuln) (default "table")
      --ignore-policy string   specify the Rego file path to evaluate each vulnerability
      --ignorefile string      specify .trivyignore file (default ".trivyignore")
      --list-all-pkgs          enabling the option will output all packages regardless of vulnerability
  -o, --output string          output file name
  -s, --severity string        severities of security issues to be displayed (comma separated) (default "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
  -t, --template string        output template

Cache Flags
      --cache-backend string   cache backend (e.g. redis://localhost:6379) (default "fs")
      --cache-ttl duration     cache TTL when using redis as cache backend
      --clear-cache            clear image caches without scanning
      --redis-ca string        redis ca file location, if using redis as cache backend
      --redis-cert string      redis certificate file location, if using redis as cache backend
      --redis-key string       redis key file location, if using redis as cache backend

DB Flags
      --db-repository string   OCI repository to retrieve trivy-db from (default "ghcr.io/aquasecurity/trivy-db")
      --download-db-only       download/update vulnerability database but don't run a scan
      --no-progress            suppress progress bar
      --reset                  remove all caches and database
      --skip-db-update         skip updating vulnerability database

Vulnerability Flags
      --ignore-unfixed     display only fixed vulnerabilities
      --vuln-type string   comma-separated list of vulnerability types (os,library) (default "os,library")

Misconfiguration Flags
      --config-data strings         specify paths from which data for the Rego policies will be recursively loaded
      --config-policy strings       specify paths to the Rego policy files directory, applying config files
      --file-patterns strings       specify config file patterns, available with '--security-checks config'
      --include-non-failures        include successes and exceptions, available with '--security-checks config'
      --policy-namespaces strings   Rego namespaces
      --trace                       enable more verbose trace output for custom queries

Secret Flags
      --secret-config string   specify a path to config file for secret scanning (default "trivy-secret.yaml")

License Flags
      --ignored-licenses strings   specify a list of license to ignore
      --license-full               eagerly look for licenses in source code headers and license files

Client/Server Flags
      --custom-headers strings   custom headers in client mode
      --server string            server address in client mode
      --token string             for authentication in client/server mode
      --token-header string      specify a header name for token in client/server mode (default "Trivy-Token")

Global Flags:
      --cache-dir string          cache directory (default "/Users/teppei/Library/Caches/trivy")
  -c, --config string             config path (default "trivy.yaml")
  -d, --debug                     debug mode
      --generate-default-config   write the default config to trivy-default.yaml
      --insecure                  allow insecure server connections when using TLS
  -q, --quiet                     suppress progress bar and log output
      --timeout duration          timeout (default 5m0s)
  -v, --version                   show version
```