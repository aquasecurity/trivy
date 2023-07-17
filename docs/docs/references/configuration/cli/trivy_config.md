## trivy config

Scan config files for misconfigurations

```
trivy config [flags] DIR
```

### Options

```
      --cache-backend string            cache backend (e.g. redis://localhost:6379) (default "fs")
      --cache-ttl duration              cache TTL when using redis as cache backend
      --clear-cache                     clear image caches without scanning
      --compliance string               compliance report to generate
      --config-data strings             specify paths from which data for the Rego policies will be recursively loaded
      --config-policy strings           specify the paths to the Rego policy files or to the directories containing them, applying config files
      --enable-modules strings          [EXPERIMENTAL] module names to enable
      --exit-code int                   specify exit code when any security issues are found
      --file-patterns strings           specify config file patterns
  -f, --format string                   format (table,json,template,sarif,cyclonedx,spdx,spdx-json,github,cosign-vuln) (default "table")
      --helm-set strings                specify Helm values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
      --helm-set-file strings           specify Helm values from respective files specified via the command line (can specify multiple or separate values with commas: key1=path1,key2=path2)
      --helm-set-string strings         specify Helm string values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
      --helm-values strings             specify paths to override the Helm values.yaml files
  -h, --help                            help for config
      --ignorefile string               specify .trivyignore file (default ".trivyignore")
      --include-non-failures            include successes and exceptions, available with '--scanners config'
      --k8s-version string              specify k8s version to validate outdated api by it (example: 1.21.0)
      --module-dir string               specify directory to the wasm modules that will be loaded (default "$HOME/.trivy/modules")
  -o, --output string                   output file name
      --password strings                password. Comma-separated passwords allowed. TRIVY_PASSWORD should be used for security reasons.
      --policy-namespaces strings       Rego namespaces
      --redis-ca string                 redis ca file location, if using redis as cache backend
      --redis-cert string               redis certificate file location, if using redis as cache backend
      --redis-key string                redis key file location, if using redis as cache backend
      --redis-tls                       enable redis TLS with public certificates, if using redis as cache backend
      --registry-token string           registry token
      --report string                   specify a compliance report format for the output (all,summary) (default "all")
      --reset-policy-bundle             remove policy bundle
  -s, --severity strings                severities of security issues to be displayed (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL) (default [UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL])
      --skip-dirs strings               specify the directories where the traversal is skipped
      --skip-files strings              specify the file paths to skip traversal
      --skip-policy-update              skip fetching rego policy updates
  -t, --template string                 output template
      --tf-exclude-downloaded-modules   remove results for downloaded modules in .terraform folder
      --tf-vars strings                 specify paths to override the Terraform tfvars files
      --trace                           enable more verbose trace output for custom queries
      --username strings                username. Comma-separated usernames allowed.
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

