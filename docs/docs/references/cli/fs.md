# Filesystem

```bash
NAME:
   trivy filesystem - scan local filesystem for language-specific dependencies and config files

USAGE:
   trivy filesystem [command options] path

OPTIONS:
   --template value, -t value                     output template [$TRIVY_TEMPLATE]
   --format value, -f value                       format (table, json, sarif, template) (default: "table") [$TRIVY_FORMAT]
   --severity value, -s value                     severities of vulnerabilities to be displayed (comma separated) (default: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL") [$TRIVY_SEVERITY]
   --output value, -o value                       output file name [$TRIVY_OUTPUT]
   --exit-code value                              Exit code when vulnerabilities were found (default: 0) [$TRIVY_EXIT_CODE]
   --skip-db-update, --skip-update                skip updating vulnerability database (default: false) [$TRIVY_SKIP_UPDATE, $TRIVY_SKIP_DB_UPDATE]
   --skip-policy-update                           skip updating built-in policies (default: false) [$TRIVY_SKIP_POLICY_UPDATE]
   --clear-cache, -c                              clear image caches without scanning (default: false) [$TRIVY_CLEAR_CACHE]
   --ignore-unfixed                               display only fixed vulnerabilities (default: false) [$TRIVY_IGNORE_UNFIXED]
   --vuln-type value                              comma-separated list of vulnerability types (os,library) (default: "os,library") [$TRIVY_VULN_TYPE]
   --security-checks value                        comma-separated list of what security issues to detect (vuln,config) (default: "vuln") [$TRIVY_SECURITY_CHECKS]
   --ignorefile value                             specify .trivyignore file (default: ".trivyignore") [$TRIVY_IGNOREFILE]
   --cache-backend value                          cache backend (e.g. redis://localhost:6379) (default: "fs") [$TRIVY_CACHE_BACKEND]
   --cache-ttl value                              cache TTL when using redis as cache backend (default: 0s) [$TRIVY_CACHE_TTL]
   --timeout value                                timeout (default: 5m0s) [$TRIVY_TIMEOUT]
   --no-progress                                  suppress progress bar (default: false) [$TRIVY_NO_PROGRESS]
   --ignore-policy value                          specify the Rego file to evaluate each vulnerability [$TRIVY_IGNORE_POLICY]
   --list-all-pkgs                                enabling the option will output all packages regardless of vulnerability (default: false) [$TRIVY_LIST_ALL_PKGS]
   --offline-scan                                 do not issue API requests to identify dependencies (default: false) [$TRIVY_OFFLINE_SCAN]
   --db-repository value                          OCI repository to retrieve trivy-db from (default: "ghcr.io/aquasecurity/trivy-db") [$TRIVY_DB_REPOSITORY]
   --skip-files value                             specify the file paths to skip traversal                                        (accepts multiple inputs) [$TRIVY_SKIP_FILES]
   --skip-dirs value                              specify the directories where the traversal is skipped                          (accepts multiple inputs) [$TRIVY_SKIP_DIRS]
   --config-policy value                          specify paths to the Rego policy files directory, applying config files         (accepts multiple inputs) [$TRIVY_CONFIG_POLICY]
   --config-data value                            specify paths from which data for the Rego policies will be recursively loaded  (accepts multiple inputs) [$TRIVY_CONFIG_DATA]
   --policy-namespaces value, --namespaces value  Rego namespaces (default: "users")                                              (accepts multiple inputs) [$TRIVY_POLICY_NAMESPACES]
   --server value                                 server address [$TRIVY_SERVER]
   --token value                                  for authentication in client/server mode [$TRIVY_TOKEN]
   --token-header value                           specify a header name for token in client/server mode (default: "Trivy-Token") [$TRIVY_TOKEN_HEADER]
   --custom-headers value                         custom headers in client/server mode  (accepts multiple inputs) [$TRIVY_CUSTOM_HEADERS]
   --help, -h                                     show help (default: false)
```