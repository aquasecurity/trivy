# Rootfs

```bash
Scan rootfs

Usage:
  trivy rootfs [flags] ROOTDIR

Examples:
  # Scan unpacked filesystem
  $ docker export $(docker create alpine:3.10.2) | tar -C /tmp/rootfs -xvf -
  $ trivy rootfs /tmp/rootfs

  # Scan from inside a container
  $ docker run --rm -it alpine:3.11
  / # curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
  / # trivy rootfs /

Scan Flags
      --file-patterns strings     specify config file patterns
      --offline-scan              do not issue API requests to identify dependencies
      --rekor-url string          [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --sbom-sources strings      [EXPERIMENTAL] try to retrieve SBOM from the specified sources (rekor)
      --security-checks strings   comma-separated list of what security issues to detect (vuln,config,secret,license) (default [vuln,secret])
      --skip-dirs strings         specify the directories where the traversal is skipped
      --skip-files strings        specify the file paths to skip traversal

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
      --helm-set strings          specify Helm values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
      --helm-set-file strings     specify Helm values from respective files specified via the command line (can specify multiple or separate values with commas: key1=path1,key2=path2)
      --helm-set-string strings   specify Helm string values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
      --helm-values strings       specify paths to override the Helm values.yaml files
      --include-non-failures      include successes and exceptions, available with '--security-checks config'
      --tf-vars strings           specify paths to override the Terraform tfvars files

Secret Flags
      --secret-config string   specify a path to config file for secret scanning (default "trivy-secret.yaml")

License Flags
      --ignored-licenses strings   specify a list of license to ignore
      --license-full               eagerly look for licenses in source code headers and license files

Rego Flags
      --config-data strings         specify paths from which data for the Rego policies will be recursively loaded
      --config-policy strings       specify paths to the Rego policy files directory, applying config files
      --policy-namespaces strings   Rego namespaces
      --trace                       enable more verbose trace output for custom queries

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
