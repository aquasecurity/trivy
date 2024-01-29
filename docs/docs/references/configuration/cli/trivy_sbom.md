## trivy sbom

Scan SBOM for vulnerabilities

```
trivy sbom [flags] SBOM_PATH
```

### Examples

```
  # Scan CycloneDX and show the result in tables
  $ trivy sbom /path/to/report.cdx

  # Scan CycloneDX-type attestation and show the result in tables
  $ trivy sbom /path/to/report.cdx.intoto.jsonl

```

### Options

```
      --cache-backend string        cache backend (e.g. redis://localhost:6379) (default "fs")
      --cache-ttl duration          cache TTL when using redis as cache backend
      --clear-cache                 clear image caches without scanning
      --compliance string           compliance report to generate
      --custom-headers strings      custom headers in client mode
      --db-repository string        OCI repository to retrieve trivy-db from (default "ghcr.io/aquasecurity/trivy-db")
      --download-db-only            download/update vulnerability database but don't run a scan
      --download-java-db-only       download/update Java index database but don't run a scan
      --exit-code int               specify exit code when any security issues are found
      --exit-on-eol int             exit with the specified code when the OS reaches end of service/life
      --file-patterns strings       specify config file patterns
  -f, --format string               format (table,json,template,sarif,cyclonedx,spdx,spdx-json,github,cosign-vuln) (default "table")
  -h, --help                        help for sbom
      --ignore-policy string        specify the Rego file path to evaluate each vulnerability
      --ignore-status strings       comma-separated list of vulnerability status to ignore (unknown,not_affected,affected,fixed,under_investigation,will_not_fix,fix_deferred,end_of_life)
      --ignore-unfixed              display only fixed vulnerabilities
      --ignorefile string           specify .trivyignore file (default ".trivyignore")
      --java-db-repository string   OCI repository to retrieve trivy-java-db from (default "ghcr.io/aquasecurity/trivy-java-db")
      --list-all-pkgs               enabling the option will output all packages regardless of vulnerability
      --no-progress                 suppress progress bar
      --offline-scan                do not issue API requests to identify dependencies
      --only-dirs strings           specify the directories where the traversal is allowed
  -o, --output string               output file name
      --output-plugin-arg string    [EXPERIMENTAL] output plugin arguments
      --redis-ca string             redis ca file location, if using redis as cache backend
      --redis-cert string           redis certificate file location, if using redis as cache backend
      --redis-key string            redis key file location, if using redis as cache backend
      --redis-tls                   enable redis TLS with public certificates, if using redis as cache backend
      --rekor-url string            [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --reset                       remove all caches and database
      --sbom-sources strings        [EXPERIMENTAL] try to retrieve SBOM from the specified sources (oci,rekor)
      --server string               server address in client mode
  -s, --severity strings            severities of security issues to be displayed (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL) (default [UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL])
      --skip-db-update              skip updating vulnerability database
      --skip-dirs strings           specify the directories or glob patterns to skip
      --skip-files strings          specify the files or glob patterns to skip
      --skip-java-db-update         skip updating Java index database
  -t, --template string             output template
      --token string                for authentication in client/server mode
      --token-header string         specify a header name for token in client/server mode (default "Trivy-Token")
      --vex string                  [EXPERIMENTAL] file path to VEX
      --vuln-type strings           comma-separated list of vulnerability types (os,library) (default [os,library])
```

### Options inherited from parent commands

```
      --cache-dir string          cache directory (default "/path/to/cache")
  -c, --config string             config path (default "trivy.yaml")
  -d, --debug                     debug mode
      --generate-default-config   write the default config to trivy-default.yaml
      --insecure                  allow insecure server connections
  -q, --quiet                     suppress progress bar and log output
      --timeout duration          timeout (default 5m0s)
  -v, --version                   show version
```

### SEE ALSO

* [trivy](trivy.md)	 - Unified security scanner

