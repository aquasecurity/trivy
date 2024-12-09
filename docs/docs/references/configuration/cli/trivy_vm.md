## trivy vm

[EXPERIMENTAL] Scan a virtual machine image

```
trivy vm [flags] VM_IMAGE
```

### Examples

```
  # Scan your AWS AMI
  $ trivy vm --scanners vuln ami:${your_ami_id}

  # Scan your AWS EBS snapshot
  $ trivy vm ebs:${your_ebs_snapshot_id}

```

### Options

```
      --aws-region string                 AWS region to scan
      --cache-backend string              [EXPERIMENTAL] cache backend (e.g. redis://localhost:6379) (default "fs")
      --cache-ttl duration                cache TTL when using redis as cache backend
      --checks-bundle-repository string   OCI registry URL to retrieve checks bundle from (default "mirror.gcr.io/aquasec/trivy-checks:1")
      --compliance string                 compliance report to generate
      --config-file-schemas strings       specify paths to JSON configuration file schemas to determine that a file matches some configuration and pass the schema to Rego checks for type checking
      --custom-headers strings            custom headers in client mode
      --db-repository strings             OCI repository(ies) to retrieve trivy-db in order of priority (default [mirror.gcr.io/aquasec/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2])
      --dependency-tree                   [EXPERIMENTAL] show dependency origin tree of vulnerable packages
      --detection-priority string         specify the detection priority:
                                            - "precise": Prioritizes precise by minimizing false positives.
                                            - "comprehensive": Aims to detect more security findings at the cost of potential false positives.
                                           (precise,comprehensive) (default "precise")
      --distro string                     [EXPERIMENTAL] specify a distribution, <family>/<version>
      --download-db-only                  download/update vulnerability database but don't run a scan
      --download-java-db-only             download/update Java index database but don't run a scan
      --enable-modules strings            [EXPERIMENTAL] module names to enable
      --exit-code int                     specify exit code when any security issues are found
      --exit-on-eol int                   exit with the specified code when the OS reaches end of service/life
      --file-patterns strings             specify config file patterns
  -f, --format string                     format (table,json,template,sarif,cyclonedx,spdx,spdx-json,github,cosign-vuln) (default "table")
      --helm-api-versions strings         Available API versions used for Capabilities.APIVersions. This flag is the same as the api-versions flag of the helm template command. (can specify multiple or separate values with commas: policy/v1/PodDisruptionBudget,apps/v1/Deployment)
      --helm-kube-version string          Kubernetes version used for Capabilities.KubeVersion. This flag is the same as the kube-version flag of the helm template command.
      --helm-set strings                  specify Helm values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
      --helm-set-file strings             specify Helm values from respective files specified via the command line (can specify multiple or separate values with commas: key1=path1,key2=path2)
      --helm-set-string strings           specify Helm string values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
      --helm-values strings               specify paths to override the Helm values.yaml files
  -h, --help                              help for vm
      --ignore-policy string              specify the Rego file path to evaluate each vulnerability
      --ignore-status strings             comma-separated list of vulnerability status to ignore (unknown,not_affected,affected,fixed,under_investigation,will_not_fix,fix_deferred,end_of_life)
      --ignore-unfixed                    display only fixed vulnerabilities
      --ignorefile string                 specify .trivyignore file (default ".trivyignore")
      --include-non-failures              include successes, available with '--scanners misconfig'
      --java-db-repository strings        OCI repository(ies) to retrieve trivy-java-db in order of priority (default [mirror.gcr.io/aquasec/trivy-java-db:1,ghcr.io/aquasecurity/trivy-java-db:1])
      --list-all-pkgs                     output all packages in the JSON report regardless of vulnerability
      --misconfig-scanners strings        comma-separated list of misconfig scanners to use for misconfiguration scanning (default [azure-arm,cloudformation,dockerfile,helm,kubernetes,terraform,terraformplan-json,terraformplan-snapshot])
      --module-dir string                 specify directory to the wasm modules that will be loaded (default "$HOME/.trivy/modules")
      --no-progress                       suppress progress bar
      --offline-scan                      do not issue API requests to identify dependencies
  -o, --output string                     output file name
      --output-plugin-arg string          [EXPERIMENTAL] output plugin arguments
      --parallel int                      number of goroutines enabled for parallel scanning, set 0 to auto-detect parallelism (default 5)
      --pkg-relationships strings         list of package relationships (unknown,root,workspace,direct,indirect) (default [unknown,root,workspace,direct,indirect])
      --pkg-types strings                 list of package types (os,library) (default [os,library])
      --redis-ca string                   redis ca file location, if using redis as cache backend
      --redis-cert string                 redis certificate file location, if using redis as cache backend
      --redis-key string                  redis key file location, if using redis as cache backend
      --redis-tls                         enable redis TLS with public certificates, if using redis as cache backend
      --rekor-url string                  [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
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
      --skip-vex-repo-update              [EXPERIMENTAL] Skip VEX Repository update
  -t, --template string                   output template
      --tf-exclude-downloaded-modules     exclude misconfigurations for downloaded terraform modules
      --token string                      for authentication in client/server mode
      --token-header string               specify a header name for token in client/server mode (default "Trivy-Token")
      --vex strings                       [EXPERIMENTAL] VEX sources ("repo", "oci" or file path)
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

