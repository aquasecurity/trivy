## trivy kubernetes

[EXPERIMENTAL] Scan kubernetes cluster

### Synopsis

Default context in kube configuration will be used unless specified

```
trivy kubernetes [flags] [CONTEXT]
```

### Examples

```
  # cluster scanning
  $ trivy k8s --report summary

  # cluster scanning with specific namespace:
  $ trivy k8s --include-namespaces kube-system --report summary 

  # cluster with specific context:
  $ trivy k8s kind-kind --report summary 
  
  

```

### Options

```
      --burst int                         specify the maximum burst for throttle (default 10)
      --cache-backend string              [EXPERIMENTAL] cache backend (e.g. redis://localhost:6379) (default "fs")
      --cache-ttl duration                cache TTL when using redis as cache backend
      --check-namespaces strings          Rego namespaces
      --checks-bundle-repository string   OCI registry URL to retrieve checks bundle from (default "mirror.gcr.io/aquasec/trivy-checks:1")
      --compliance string                 compliance report to generate (k8s-nsa-1.0,k8s-cis-1.23,eks-cis-1.4,rke2-cis-1.24,k8s-pss-baseline-0.1,k8s-pss-restricted-0.1)
      --config-check strings              specify the paths to the Rego check files or to the directories containing them, applying config files
      --config-data strings               specify paths from which data for the Rego checks will be recursively loaded
      --config-file-schemas strings       specify paths to JSON configuration file schemas to determine that a file matches some configuration and pass the schema to Rego checks for type checking
      --db-repository strings             OCI repository(ies) to retrieve trivy-db in order of priority (default [mirror.gcr.io/aquasec/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2])
      --dependency-tree                   [EXPERIMENTAL] show dependency origin tree of vulnerable packages
      --detection-priority string         specify the detection priority:
                                            - "precise": Prioritizes precise by minimizing false positives.
                                            - "comprehensive": Aims to detect more security findings at the cost of potential false positives.
                                           (precise,comprehensive) (default "precise")
      --disable-node-collector            When the flag is activated, the node-collector job will not be executed, thus skipping misconfiguration findings on the node.
      --distro string                     [EXPERIMENTAL] specify a distribution, <family>/<version>
      --download-db-only                  download/update vulnerability database but don't run a scan
      --download-java-db-only             download/update Java index database but don't run a scan
      --exclude-kinds strings             indicate the kinds exclude from scanning (example: node)
      --exclude-namespaces strings        indicate the namespaces excluded from scanning (example: kube-system)
      --exclude-nodes strings             indicate the node labels that the node-collector job should exclude from scanning (example: kubernetes.io/arch:arm64,team:dev)
      --exclude-owned                     exclude resources that have an owner reference
      --exit-code int                     specify exit code when any security issues are found
      --file-patterns strings             specify config file patterns
  -f, --format string                     format (table,json,cyclonedx) (default "table")
      --helm-api-versions strings         Available API versions used for Capabilities.APIVersions. This flag is the same as the api-versions flag of the helm template command. (can specify multiple or separate values with commas: policy/v1/PodDisruptionBudget,apps/v1/Deployment)
      --helm-kube-version string          Kubernetes version used for Capabilities.KubeVersion. This flag is the same as the kube-version flag of the helm template command.
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
      --include-deprecated-checks         include deprecated checks
      --include-kinds strings             indicate the kinds included in scanning (example: node)
      --include-namespaces strings        indicate the namespaces included in scanning (example: kube-system)
      --include-non-failures              include successes, available with '--scanners misconfig'
      --java-db-repository strings        OCI repository(ies) to retrieve trivy-java-db in order of priority (default [mirror.gcr.io/aquasec/trivy-java-db:1,ghcr.io/aquasecurity/trivy-java-db:1])
      --k8s-version string                specify k8s version to validate outdated api by it (example: 1.21.0)
      --kubeconfig string                 specify the kubeconfig file path to use
      --list-all-pkgs                     output all packages in the JSON report regardless of vulnerability
      --misconfig-scanners strings        comma-separated list of misconfig scanners to use for misconfiguration scanning (default [azure-arm,cloudformation,dockerfile,helm,kubernetes,terraform,terraformplan-json,terraformplan-snapshot])
      --no-progress                       suppress progress bar
      --node-collector-imageref string    indicate the image reference for the node-collector scan job (default "ghcr.io/aquasecurity/node-collector:0.3.1")
      --node-collector-namespace string   specify the namespace in which the node-collector job should be deployed (default "trivy-temp")
      --offline-scan                      do not issue API requests to identify dependencies
  -o, --output string                     output file name
      --output-plugin-arg string          [EXPERIMENTAL] output plugin arguments
      --parallel int                      number of goroutines enabled for parallel scanning, set 0 to auto-detect parallelism (default 5)
      --password strings                  password. Comma-separated passwords allowed. TRIVY_PASSWORD should be used for security reasons.
      --password-stdin                    password from stdin. Comma-separated passwords are not supported.
      --pkg-relationships strings         list of package relationships (unknown,root,workspace,direct,indirect) (default [unknown,root,workspace,direct,indirect])
      --pkg-types strings                 list of package types (os,library) (default [os,library])
      --qps float                         specify the maximum QPS to the master from this client (default 5)
      --redis-ca string                   redis ca file location, if using redis as cache backend
      --redis-cert string                 redis certificate file location, if using redis as cache backend
      --redis-key string                  redis key file location, if using redis as cache backend
      --redis-tls                         enable redis TLS with public certificates, if using redis as cache backend
      --registry-token string             registry token
      --rekor-url string                  [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --report string                     specify a report format for the output (all,summary) (default "all")
      --sbom-sources strings              [EXPERIMENTAL] try to retrieve SBOM from the specified sources (oci,rekor)
      --scanners strings                  comma-separated list of what security issues to detect (vuln,misconfig,secret,rbac) (default [vuln,misconfig,secret,rbac])
      --secret-config string              specify a path to config file for secret scanning (default "trivy-secret.yaml")
  -s, --severity strings                  severities of security issues to be displayed (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL) (default [UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL])
      --show-suppressed                   [EXPERIMENTAL] show suppressed vulnerabilities
      --skip-check-update                 skip fetching rego check updates
      --skip-db-update                    skip updating vulnerability database
      --skip-dirs strings                 specify the directories or glob patterns to skip
      --skip-files strings                specify the files or glob patterns to skip
      --skip-images                       skip the downloading and scanning of images (vulnerabilities and secrets) in the cluster resources
      --skip-java-db-update               skip updating Java index database
      --skip-vex-repo-update              [EXPERIMENTAL] Skip VEX Repository update
  -t, --template string                   output template
      --tf-exclude-downloaded-modules     exclude misconfigurations for downloaded terraform modules
      --tolerations strings               specify node-collector job tolerations (example: key1=value1:NoExecute,key2=value2:NoSchedule)
      --trace                             enable more verbose trace output for custom queries
      --username strings                  username. Comma-separated usernames allowed.
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

