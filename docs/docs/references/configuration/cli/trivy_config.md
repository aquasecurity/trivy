## trivy config

Scan config files for misconfigurations

```
trivy config [flags] DIR
```

### Options

```
      --cache-backend string              [EXPERIMENTAL] cache backend (e.g. redis://localhost:6379) (default "memory")
      --cache-ttl duration                cache TTL when using redis as cache backend
      --cf-params strings                 specify paths to override the CloudFormation parameters files
      --check-namespaces strings          Rego namespaces
      --checks-bundle-repository string   OCI registry URL to retrieve checks bundle from (default "mirror.gcr.io/aquasec/trivy-checks:1")
      --compliance string                 compliance report to generate
      --config-check strings              specify the paths to the Rego check files or to the directories containing them, applying config files
      --config-data strings               specify paths from which data for the Rego checks will be recursively loaded
      --config-file-schemas strings       specify paths to JSON configuration file schemas to determine that a file matches some configuration and pass the schema to Rego checks for type checking
      --enable-modules strings            [EXPERIMENTAL] module names to enable
      --exit-code int                     specify exit code when any security issues are found
      --file-patterns strings             specify config file patterns
  -f, --format string                     format
                                          Allowed values:
                                            - table
                                            - json
                                            - template
                                            - sarif
                                            - cyclonedx
                                            - spdx
                                            - spdx-json
                                            - github
                                            - cosign-vuln
                                           (default "table")
      --helm-api-versions strings         Available API versions used for Capabilities.APIVersions. This flag is the same as the api-versions flag of the helm template command. (can specify multiple or separate values with commas: policy/v1/PodDisruptionBudget,apps/v1/Deployment)
      --helm-kube-version string          Kubernetes version used for Capabilities.KubeVersion. This flag is the same as the kube-version flag of the helm template command.
      --helm-set strings                  specify Helm values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
      --helm-set-file strings             specify Helm values from respective files specified via the command line (can specify multiple or separate values with commas: key1=path1,key2=path2)
      --helm-set-string strings           specify Helm string values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
      --helm-values strings               specify paths to override the Helm values.yaml files
  -h, --help                              help for config
      --ignore-policy string              specify the Rego file path to evaluate each vulnerability
      --ignorefile string                 specify .trivyignore file (default ".trivyignore")
      --include-deprecated-checks         include deprecated checks
      --include-non-failures              include successes, available with '--scanners misconfig'
      --k8s-version string                specify k8s version to validate outdated api by it (example: 1.21.0)
      --misconfig-scanners strings        comma-separated list of misconfig scanners to use for misconfiguration scanning (default [azure-arm,cloudformation,dockerfile,helm,kubernetes,terraform,terraformplan-json,terraformplan-snapshot])
      --module-dir string                 specify directory to the wasm modules that will be loaded (default "$HOME/.trivy/modules")
  -o, --output string                     output file name
      --output-plugin-arg string          [EXPERIMENTAL] output plugin arguments
      --password strings                  password. Comma-separated passwords allowed. TRIVY_PASSWORD should be used for security reasons.
      --password-stdin                    password from stdin. Comma-separated passwords are not supported.
      --redis-ca string                   redis ca file location, if using redis as cache backend
      --redis-cert string                 redis certificate file location, if using redis as cache backend
      --redis-key string                  redis key file location, if using redis as cache backend
      --redis-tls                         enable redis TLS with public certificates, if using redis as cache backend
      --registry-token string             registry token
      --render-cause strings              specify configuration types for which the rendered causes will be shown in the table report (allowed values: terraform)
      --report string                     specify a compliance report format for the output (allowed values: all,summary) (default "all")
  -s, --severity strings                  severities of security issues to be displayed
                                          Allowed values:
                                            - UNKNOWN
                                            - LOW
                                            - MEDIUM
                                            - HIGH
                                            - CRITICAL
                                           (default [UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL])
      --skip-check-update                 skip fetching rego check updates
      --skip-dirs strings                 specify the directories or glob patterns to skip
      --skip-files strings                specify the files or glob patterns to skip
      --table-mode strings                [EXPERIMENTAL] tables that will be displayed in 'table' format (allowed values: summary,detailed) (default [summary,detailed])
  -t, --template string                   output template
      --tf-exclude-downloaded-modules     exclude misconfigurations for downloaded terraform modules
      --tf-vars strings                   specify paths to override the Terraform tfvars files
      --trace                             enable more verbose trace output for custom queries
      --username strings                  username. Comma-separated usernames allowed.
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

