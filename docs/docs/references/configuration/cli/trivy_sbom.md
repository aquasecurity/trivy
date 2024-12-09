## trivy sbom

Scan SBOM for vulnerabilities and licenses

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
      --cache-backend string         [EXPERIMENTAL] cache backend (e.g. redis://localhost:6379) (default "memory")
      --cache-ttl duration           cache TTL when using redis as cache backend
      --compliance string            compliance report to generate
      --custom-headers strings       custom headers in client mode
      --db-repository strings        OCI repository(ies) to retrieve trivy-db in order of priority (default [mirror.gcr.io/aquasec/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2])
      --detection-priority string    specify the detection priority:
                                       - "precise": Prioritizes precise by minimizing false positives.
                                       - "comprehensive": Aims to detect more security findings at the cost of potential false positives.
                                      (precise,comprehensive) (default "precise")
      --distro string                [EXPERIMENTAL] specify a distribution, <family>/<version>
      --download-db-only             download/update vulnerability database but don't run a scan
      --download-java-db-only        download/update Java index database but don't run a scan
      --exit-code int                specify exit code when any security issues are found
      --exit-on-eol int              exit with the specified code when the OS reaches end of service/life
      --file-patterns strings        specify config file patterns
  -f, --format string                format (table,json,template,sarif,cyclonedx,spdx,spdx-json,github,cosign-vuln) (default "table")
  -h, --help                         help for sbom
      --ignore-policy string         specify the Rego file path to evaluate each vulnerability
      --ignore-status strings        comma-separated list of vulnerability status to ignore (unknown,not_affected,affected,fixed,under_investigation,will_not_fix,fix_deferred,end_of_life)
      --ignore-unfixed               display only fixed vulnerabilities
      --ignored-licenses strings     specify a list of license to ignore
      --ignorefile string            specify .trivyignore file (default ".trivyignore")
      --java-db-repository strings   OCI repository(ies) to retrieve trivy-java-db in order of priority (default [mirror.gcr.io/aquasec/trivy-java-db:1,ghcr.io/aquasecurity/trivy-java-db:1])
      --list-all-pkgs                output all packages in the JSON report regardless of vulnerability
      --no-progress                  suppress progress bar
      --offline-scan                 do not issue API requests to identify dependencies
  -o, --output string                output file name
      --output-plugin-arg string     [EXPERIMENTAL] output plugin arguments
      --password strings             password. Comma-separated passwords allowed. TRIVY_PASSWORD should be used for security reasons.
      --password-stdin               password from stdin. Comma-separated passwords are not supported.
      --pkg-relationships strings    list of package relationships (unknown,root,workspace,direct,indirect) (default [unknown,root,workspace,direct,indirect])
      --pkg-types strings            list of package types (os,library) (default [os,library])
      --redis-ca string              redis ca file location, if using redis as cache backend
      --redis-cert string            redis certificate file location, if using redis as cache backend
      --redis-key string             redis key file location, if using redis as cache backend
      --redis-tls                    enable redis TLS with public certificates, if using redis as cache backend
      --registry-token string        registry token
      --rekor-url string             [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --sbom-sources strings         [EXPERIMENTAL] try to retrieve SBOM from the specified sources (oci,rekor)
      --scanners strings             comma-separated list of what security issues to detect (vuln,license) (default [vuln])
      --server string                server address in client mode
  -s, --severity strings             severities of security issues to be displayed (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL) (default [UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL])
      --show-suppressed              [EXPERIMENTAL] show suppressed vulnerabilities
      --skip-db-update               skip updating vulnerability database
      --skip-dirs strings            specify the directories or glob patterns to skip
      --skip-files strings           specify the files or glob patterns to skip
      --skip-java-db-update          skip updating Java index database
      --skip-vex-repo-update         [EXPERIMENTAL] Skip VEX Repository update
  -t, --template string              output template
      --token string                 for authentication in client/server mode
      --token-header string          specify a header name for token in client/server mode (default "Trivy-Token")
      --username strings             username. Comma-separated usernames allowed.
      --vex strings                  [EXPERIMENTAL] VEX sources ("repo", "oci" or file path)
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

