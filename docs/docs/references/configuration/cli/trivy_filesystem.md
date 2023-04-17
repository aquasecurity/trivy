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
      --cache-backend string        cache backend (e.g. redis://localhost:6379) (default "fs")
      --cache-ttl duration          cache TTL when using redis as cache backend
      --clear-cache                 clear image caches without scanning
      --config-data strings         specify paths from which data for the Rego policies will be recursively loaded
      --config-policy strings       specify paths to the Rego policy files directory, applying config files
      --custom-headers strings      custom headers in client mode
      --db-repository string        OCI repository to retrieve trivy-db from (default "ghcr.io/aquasecurity/trivy-db")
      --dependency-tree             [EXPERIMENTAL] show dependency origin tree of vulnerable packages
      --download-db-only            download/update vulnerability database but don't run a scan
      --download-java-db-only       download/update Java index database but don't run a scan
      --enable-modules strings      [EXPERIMENTAL] module names to enable
      --exit-code int               specify exit code when any security issues are found
      --file-patterns strings       specify config file patterns
  -f, --format string               format (table, json, template, sarif, cyclonedx, spdx, spdx-json, github, cosign-vuln) (default "table")
      --helm-set strings            specify Helm values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
      --helm-set-file strings       specify Helm values from respective files specified via the command line (can specify multiple or separate values with commas: key1=path1,key2=path2)
      --helm-set-string strings     specify Helm string values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
      --helm-values strings         specify paths to override the Helm values.yaml files
  -h, --help                        help for filesystem
      --ignore-policy string        specify the Rego file path to evaluate each vulnerability
      --ignore-unfixed              display only fixed vulnerabilities
      --ignored-licenses strings    specify a list of license to ignore
      --ignorefile string           specify .trivyignore file (default ".trivyignore")
      --include-non-failures        include successes and exceptions, available with '--scanners config'
      --java-db-repository string   OCI repository to retrieve trivy-java-db from (default "ghcr.io/aquasecurity/trivy-java-db")
      --license-full                eagerly look for licenses in source code headers and license files
      --list-all-pkgs               enabling the option will output all packages regardless of vulnerability
      --module-dir string           specify directory to the wasm modules that will be loaded (default "$HOME/.trivy/modules")
      --no-progress                 suppress progress bar
      --offline-scan                do not issue API requests to identify dependencies
  -o, --output string               output file name
      --password strings            password. Comma-separated passwords allowed. TRIVY_PASSWORD should be used for security reasons.
      --policy-namespaces strings   Rego namespaces
      --redis-ca string             redis ca file location, if using redis as cache backend
      --redis-cert string           redis certificate file location, if using redis as cache backend
      --redis-key string            redis key file location, if using redis as cache backend
      --redis-tls                   enable redis TLS with public certificates, if using redis as cache backend
      --registry-token string       registry token
      --rekor-url string            [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --reset                       remove all caches and database
      --sbom-sources strings        [EXPERIMENTAL] try to retrieve SBOM from the specified sources (oci,rekor)
      --scanners strings            comma-separated list of what security issues to detect (vuln,config,secret,license) (default [vuln,secret])
      --secret-config string        specify a path to config file for secret scanning (default "trivy-secret.yaml")
      --server string               server address in client mode
  -s, --severity string             severities of security issues to be displayed (comma separated) (default "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
      --skip-db-update              skip updating vulnerability database
      --skip-dirs strings           specify the directories where the traversal is skipped
      --skip-files strings          specify the file paths to skip traversal
      --skip-java-db-update         skip updating Java index database
      --skip-policy-update          skip fetching rego policy updates
      --slow                        scan over time with lower CPU and memory utilization
  -t, --template string             output template
      --tf-vars strings             specify paths to override the Terraform tfvars files
      --token string                for authentication in client/server mode
      --token-header string         specify a header name for token in client/server mode (default "Trivy-Token")
      --trace                       enable more verbose trace output for custom queries
      --username strings            username. Comma-separated usernames allowed.
      --vuln-type string            comma-separated list of vulnerability types (os,library) (default "os,library")
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

