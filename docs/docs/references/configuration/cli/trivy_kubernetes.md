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
      --cache-backend string        cache backend (e.g. redis://localhost:6379) (default "fs")
      --cache-ttl duration          cache TTL when using redis as cache backend
      --clear-cache                 clear image caches without scanning
      --compliance string           compliance report to generate (k8s-nsa,k8s-cis, k8s-pss-baseline, k8s-pss-restricted)
      --components strings          specify which components to scan (default [workload,infra])
      --config-data strings         specify paths from which data for the Rego policies will be recursively loaded
      --config-policy strings       specify paths to the Rego policy files directory, applying config files
      --context string              specify a context to scan
      --db-repository string        OCI repository to retrieve trivy-db from (default "ghcr.io/aquasecurity/trivy-db")
      --dependency-tree             [EXPERIMENTAL] show dependency origin tree of vulnerable packages
      --download-db-only            download/update vulnerability database but don't run a scan
      --download-java-db-only       download/update Java index database but don't run a scan
      --exit-code int               specify exit code when any security issues are found
      --file-patterns strings       specify config file patterns
  -f, --format string               format (table, json, template, sarif, cyclonedx, spdx, spdx-json, github, cosign-vuln) (default "table")
      --helm-set strings            specify Helm values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
      --helm-set-file strings       specify Helm values from respective files specified via the command line (can specify multiple or separate values with commas: key1=path1,key2=path2)
      --helm-set-string strings     specify Helm string values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
      --helm-values strings         specify paths to override the Helm values.yaml files
  -h, --help                        help for kubernetes
      --ignore-policy string        specify the Rego file path to evaluate each vulnerability
      --ignore-unfixed              display only fixed vulnerabilities
      --ignored-licenses strings    specify a list of license to ignore
      --ignorefile string           specify .trivyignore file (default ".trivyignore")
      --include-non-failures        include successes and exceptions, available with '--scanners config'
      --java-db-repository string   OCI repository to retrieve trivy-java-db from (default "ghcr.io/aquasecurity/trivy-java-db")
      --k8s-version string          specify k8s version to validate outdated api by it (example: 1.21.0)
      --kubeconfig string           specify the kubeconfig file path to use
      --license-full                eagerly look for licenses in source code headers and license files
      --list-all-pkgs               enabling the option will output all packages regardless of vulnerability
  -n, --namespace string            specify a namespace to scan
      --no-progress                 suppress progress bar
      --offline-scan                do not issue API requests to identify dependencies
  -o, --output string               output file name
      --parallel int                number (between 1-20) of goroutines enabled for parallel scanning (default 5)
      --policy-namespaces strings   Rego namespaces
      --redis-ca string             redis ca file location, if using redis as cache backend
      --redis-cert string           redis certificate file location, if using redis as cache backend
      --redis-key string            redis key file location, if using redis as cache backend
      --redis-tls                   enable redis TLS with public certificates, if using redis as cache backend
      --rekor-url string            [EXPERIMENTAL] address of rekor STL server (default "https://rekor.sigstore.dev")
      --report string               specify a report format for the output. (all,summary) (default "all")
      --reset                       remove all caches and database
      --sbom-sources strings        [EXPERIMENTAL] try to retrieve SBOM from the specified sources (oci,rekor)
      --scanners string             comma-separated list of what security issues to detect (vuln,config,secret,license) (default "vuln,config,secret,rbac")
      --secret-config string        specify a path to config file for secret scanning (default "trivy-secret.yaml")
  -s, --severity string             severities of security issues to be displayed (comma separated) (default "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
      --skip-db-update              skip updating vulnerability database
      --skip-dirs strings           specify the directories where the traversal is skipped
      --skip-files strings          specify the file paths to skip traversal
      --skip-java-db-update         skip updating Java index database
      --skip-policy-update          skip fetching rego policy updates
      --slow                        scan over time with lower CPU and memory utilization
  -t, --template string             output template
      --tf-vars strings             specify paths to override the Terraform tfvars files
      --tolerations strings         specify node-collector job tolerations (example: key1=value1:NoExecute,key2=value2:NoSchedule)
      --trace                       enable more verbose trace output for custom queries
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

