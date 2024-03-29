## trivy filesystem

Scan local filesystem

```
trivy filesystem [flags] PATH
```

### Examples

```
  # Scan a local project including language-specific files
  $ trivy fs /path/to/your_project

  # Scan a single file
  $ trivy fs ./trivy-ci-test/Pipfile.lock
```

### Options

```
      --cache-backend string              cache backend (e.g. redis://localhost:6379) (default "fs")
      --cache-ttl duration                cache TTL when using redis as cache backend
      --cf-params strings                 specify paths to override the CloudFormation parameters files
      --clear-cache                       clear image caches without scanning
      --compliance string                 compliance report to generate
      --config-data strings               specify paths from which data for the Rego policies will be recursively loaded
      --config-policy strings             specify the paths to the Rego policy files or to the directories containing them, applying config files
      --custom-headers strings            custom headers in client mode
      --db-repository string              OCI repository to retrieve trivy-db from (default "ghcr.io/aquasecurity/trivy-db:2")
      --dependency-tree                   [EXPERIMENTAL] show dependency origin tree of vulnerable packages
      --download-db-only                  download/update vulnerability database but don't run a scan
      --download-java-db-only             download/update Java index database but don't run a scan
      --enable-modules strings            [EXPERIMENTAL] module names to enable
      --exit-code int                     specify exit code when any security issues are found
      --file-patterns strings             specify config file patterns
  -f, --format string                     format (table,json,template,sarif,cyclonedx,spdx,spdx-json,github,cosign-vuln) (default "table")
      --helm-set strings                  specify Helm values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
      --helm-set-file strings             specify Helm values from respective files specified via the command line (can specify multiple or separate values with commas: key1=path1,key2=path2)
      --helm-set-string strings           specify Helm string values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
      --helm-values strings               specify paths to override the Helm values.yaml files
  -h, --help                              help for filesystem
      --ignore-policy string              specify the Rego file path to evaluate each vulnerability
      --ignore-status strings             comma-separated list of vulnerability status to ignore (unknown,not_affected,affected,fixed,under_investigation,will_not_fix,fix_deferred,end_of_life)
      --ignore-unfixed                    display only fixed vulnerabilities
      --ignored-licenses strings          specify a list of license to ignore
      --ignorefile string                 specify .trivyignore file (default ".trivyignore")
      --include-dev-deps                  include development dependencies in the report (supported: npm, yarn)
      --include-non-failures              include successes and exceptions, available with '--scanners misconfig'
      --java-db-repository string         OCI repository to retrieve trivy-java-db from (default "ghcr.io/aquasecurity/trivy-java-db:1")
      --license-confidence-level float    specify license classifier's confidence level (default 0.9)
      --license-full                      eagerly look for licenses in source code headers and license files
      --list-all-pkgs                     enabling the option will output all packages regardless of vulnerability
      --misconfig-scanners strings        comma-separated list of misconfig scanners to use for misconfiguration scanning (default [azure-arm,cloudformation,dockerfile,helm,kubernetes,terraform,terraformplan-json,terraformplan-snapshot])
      --module-dir string                 specify directory to the wasm modules that will be loaded (default "$HOME/.trivy/modules")
      --no-progress                       suppress progress bar
      --offline-scan                      do not issue API requests to identify dependencies
  -o, --output string                     output file name
      --output-plugin-arg string          [EXPERIMENTAL] output plugin arguments
      --parallel int                      number of goroutines enabled for parallel scanning, set 0 to auto-detect parallelism (default 5)
      --password strings                  password. Comma-separated passwords allowed. TRIVY_PASSWORD should be used for security reasons.
      --policy-bundle-repository string   OCI registry URL to retrieve policy bundle from (default "ghcr.io/aquasecurity/trivy-policies:0")
      --policy-namespaces strings         Rego namespaces
      --redis-ca string                   redis ca file location, if using redis as cache backend
      --redis-cert string                 redis certificate file location, if using redis as cache backend
      --redis-key string                  redis key file location, if using redis as cache backend
      --redis-tls                         enable redis TLS with public certificates, if using redis as cache backend
      --registry-token string             registry token
      --rekor-url string                  [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --report string                     specify a compliance report format for the output (all,summary) (default "all")
      --reset                             remove all caches and database
      --reset-policy-bundle               remove policy bundle
      --sbom-sources strings              [EXPERIMENTAL] try to retrieve SBOM from the specified sources (oci,rekor)
      --scanners strings                  comma-separated list of what security issues to detect (vuln,misconfig,secret,license) (default [vuln,secret])
      --secret-config string              specify a path to config file for secret scanning (default "trivy-secret.yaml")
      --server string                     server address in client mode
  -s, --severity strings                  severities of security issues to be displayed (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL) (default [UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL])
      --show-suppressed                   [EXPERIMENTAL] show suppressed vulnerabilities
      --skip-db-update                    skip updating vulnerability database
      --skip-dirs strings                 specify the directories or glob patterns to skip
      --skip-files strings                specify the files or glob patterns to skip
      --skip-java-db-update               skip updating Java index database
      --skip-policy-update                skip fetching rego policy updates
  -t, --template string                   output template
      --tf-exclude-downloaded-modules     exclude misconfigurations for downloaded terraform modules
      --tf-vars strings                   specify paths to override the Terraform tfvars files
      --token string                      for authentication in client/server mode
      --token-header string               specify a header name for token in client/server mode (default "Trivy-Token")
      --trace                             enable more verbose trace output for custom queries
      --username strings                  username. Comma-separated usernames allowed.
      --vex string                        [EXPERIMENTAL] file path to VEX
      --vuln-type strings                 comma-separated list of vulnerability types (os,library) (default [os,library])
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

