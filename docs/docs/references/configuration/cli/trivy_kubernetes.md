## trivy kubernetes

[EXPERIMENTAL] Scan kubernetes cluster

```
trivy kubernetes [flags] { cluster | all | specific resources like kubectl. eg: pods, pod/NAME }
```

### Examples

```
  # cluster scanning
  $ trivy k8s --report summary cluster

  # namespace scanning:
  $ trivy k8s -n kube-system --report summary all

  # resources scanning:
  $ trivy k8s --report=summary deploy
  $ trivy k8s --namespace=kube-system --report=summary deploy,configmaps

  # resource scanning:
  $ trivy k8s deployment/orion

```

### Options

```
  -A, --all-namespaces                    fetch resources from all cluster namespaces
      --burst int                         specify the maximum burst for throttle (default 10)
      --cache-backend string              cache backend (e.g. redis://localhost:6379) (default "fs")
      --cache-ttl duration                cache TTL when using redis as cache backend
      --clear-cache                       clear image caches without scanning
      --compliance string                 compliance report to generate (k8s-nsa,k8s-cis,k8s-pss-baseline,k8s-pss-restricted)
      --components strings                specify which components to scan (workload,infra) (default [workload,infra])
      --config-data strings               specify paths from which data for the Rego policies will be recursively loaded
      --config-policy strings             specify the paths to the Rego policy files or to the directories containing them, applying config files
      --context string                    specify a context to scan
      --db-repository string              OCI repository to retrieve trivy-db from (default "ghcr.io/aquasecurity/trivy-db:2")
      --dependency-tree                   [EXPERIMENTAL] show dependency origin tree of vulnerable packages
      --download-db-only                  download/update vulnerability database but don't run a scan
      --download-java-db-only             download/update Java index database but don't run a scan
      --exclude-nodes strings             indicate the node labels that the node-collector job should exclude from scanning (example: kubernetes.io/arch:arm64,team:dev)
      --exclude-owned                     exclude resources that have an owner reference
      --exit-code int                     specify exit code when any security issues are found
      --file-patterns strings             specify config file patterns
  -f, --format string                     format (table,json,cyclonedx) (default "table")
      --helm-set strings                  specify Helm values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
      --helm-set-file strings             specify Helm values from respective files specified via the command line (can specify multiple or separate values with commas: key1=path1,key2=path2)
      --helm-set-string strings           specify Helm string values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
      --helm-values strings               specify paths to override the Helm values.yaml files
  -h, --help                              help for kubernetes
      --ignore-policy string              specify the Rego file path to evaluate each vulnerability
      --ignore-status strings             comma-separated list of vulnerability status to ignore (unknown,not_affected,affected,fixed,under_investigation,will_not_fix,fix_deferred,end_of_life)
      --ignore-unfixed                    display only fixed vulnerabilities
      --ignorefile string                 specify .trivyignore file (default ".trivyignore")
      --image-src strings                 image source(s) to use, in priority order (docker,containerd,podman,remote) (default [docker,containerd,podman,remote])
      --include-non-failures              include successes and exceptions, available with '--scanners misconfig'
      --java-db-repository string         OCI repository to retrieve trivy-java-db from (default "ghcr.io/aquasecurity/trivy-java-db:1")
      --k8s-version string                specify k8s version to validate outdated api by it (example: 1.21.0)
      --kubeconfig string                 specify the kubeconfig file path to use
      --list-all-pkgs                     enabling the option will output all packages regardless of vulnerability
      --misconfig-scanners strings        comma-separated list of misconfig scanners to use for misconfiguration scanning (default [azure-arm,cloudformation,dockerfile,helm,kubernetes,terraform,terraformplan-json,terraformplan-snapshot])
  -n, --namespace string                  specify a namespace to scan
      --no-progress                       suppress progress bar
      --node-collector-imageref string    indicate the image reference for the node-collector scan job (default "ghcr.io/aquasecurity/node-collector:0.0.9")
      --node-collector-namespace string   specify the namespace in which the node-collector job should be deployed (default "trivy-temp")
      --offline-scan                      do not issue API requests to identify dependencies
  -o, --output string                     output file name
      --output-plugin-arg string          [EXPERIMENTAL] output plugin arguments
      --parallel int                      number of goroutines enabled for parallel scanning, set 0 to auto-detect parallelism (default 5)
      --password strings                  password. Comma-separated passwords allowed. TRIVY_PASSWORD should be used for security reasons.
      --policy-bundle-repository string   OCI registry URL to retrieve policy bundle from (default "ghcr.io/aquasecurity/trivy-policies:0")
      --policy-namespaces strings         Rego namespaces
      --qps float                         specify the maximum QPS to the master from this client (default 5)
      --redis-ca string                   redis ca file location, if using redis as cache backend
      --redis-cert string                 redis certificate file location, if using redis as cache backend
      --redis-key string                  redis key file location, if using redis as cache backend
      --redis-tls                         enable redis TLS with public certificates, if using redis as cache backend
      --registry-token string             registry token
      --rekor-url string                  [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --report string                     specify a report format for the output (all,summary) (default "all")
      --reset                             remove all caches and database
      --reset-policy-bundle               remove policy bundle
      --sbom-sources strings              [EXPERIMENTAL] try to retrieve SBOM from the specified sources (oci,rekor)
      --scanners strings                  comma-separated list of what security issues to detect (vuln,misconfig,secret,rbac) (default [vuln,misconfig,secret,rbac])
      --secret-config string              specify a path to config file for secret scanning (default "trivy-secret.yaml")
  -s, --severity strings                  severities of security issues to be displayed (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL) (default [UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL])
      --show-suppressed                   [EXPERIMENTAL] show suppressed vulnerabilities
      --skip-db-update                    skip updating vulnerability database
      --skip-dirs strings                 specify the directories or glob patterns to skip
      --skip-files strings                specify the files or glob patterns to skip
      --skip-java-db-update               skip updating Java index database
      --skip-policy-update                skip fetching rego policy updates
  -t, --template string                   output template
      --tf-exclude-downloaded-modules     exclude misconfigurations for downloaded terraform modules
      --tolerations strings               specify node-collector job tolerations (example: key1=value1:NoExecute,key2=value2:NoSchedule)
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

