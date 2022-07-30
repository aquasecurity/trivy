# Config

``` bash
Scan config files for misconfigurations

Usage:
  trivy config [flags] DIR

Aliases:
  config, conf

Scan Flags
      --skip-dirs strings    specify the directories where the traversal is skipped
      --skip-files strings   specify the file paths to skip traversal

Report Flags
      --exit-code int       specify exit code when any security issues are found
  -f, --format string       format (table, json, sarif, template, cyclonedx, spdx, spdx-json, github, cosign-vuln) (default "table")
      --ignorefile string   specify .trivyignore file (default ".trivyignore")
  -o, --output string       output file name
  -s, --severity string     severities of security issues to be displayed (comma separated) (default "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
  -t, --template string     output template

Cache Flags
      --cache-backend string   cache backend (e.g. redis://localhost:6379) (default "fs")
      --cache-ttl duration     cache TTL when using redis as cache backend
      --clear-cache            clear image caches without scanning
      --redis-ca string        redis ca file location, if using redis as cache backend
      --redis-cert string      redis certificate file location, if using redis as cache backend
      --redis-key string       redis key file location, if using redis as cache backend

Misconfiguration Flags
      --config-data strings         specify paths from which data for the Rego policies will be recursively loaded
      --config-policy strings       specify paths to the Rego policy files directory, applying config files
      --file-patterns strings       specify config file patterns, available with '--security-checks config'
      --include-non-failures        include successes and exceptions, available with '--security-checks config'
      --policy-namespaces strings   Rego namespaces
      --trace                       enable more verbose trace output for custom queries

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
