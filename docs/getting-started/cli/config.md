# Config

``` bash
NAME:
   trivy config - scan config files

USAGE:
   trivy config [command options] dir

OPTIONS:
   --template value, -t value                     output template [$TRIVY_TEMPLATE]
   --format value, -f value                       format (table, json, template) (default: "table") [$TRIVY_FORMAT]
   --severity value, -s value                     severities of vulnerabilities to be displayed (comma separated) (default: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL") [$TRIVY_SEVERITY]
   --output value, -o value                       output file name [$TRIVY_OUTPUT]
   --exit-code value                              Exit code when vulnerabilities were found (default: 0) [$TRIVY_EXIT_CODE]
   --skip-policy-update                           skip updating builtin policies (default: false) [$TRIVY_SKIP_POLICY_UPDATE]
   --clear-cache, -c                              clear image caches without scanning (default: false) [$TRIVY_CLEAR_CACHE]
   --ignore-unfixed                               display only fixed vulnerabilities (default: false) [$TRIVY_IGNORE_UNFIXED]
   --ignorefile value                             specify .trivyignore file (default: ".trivyignore") [$TRIVY_IGNOREFILE]
   --cache-backend value                          cache backend (e.g. redis://localhost:6379) (default: "fs") [$TRIVY_CACHE_BACKEND]
   --timeout value                                timeout (default: 5m0s) [$TRIVY_TIMEOUT]
   --no-progress                                  suppress progress bar (default: false) [$TRIVY_NO_PROGRESS]
   --ignore-policy value                          specify the Rego file to evaluate each vulnerability [$TRIVY_IGNORE_POLICY]
   --skip-files value                             specify the file paths to skip traversal [$TRIVY_SKIP_FILES]
   --skip-dirs value                              specify the directories where the traversal is skipped [$TRIVY_SKIP_DIRS]
   --policy value, --config-policy value          specify paths to the Rego policy files directory, applying config files [$TRIVY_POLICY]
   --file-patterns value                          specify file patterns [$TRIVY_FILE_PATTERNS]
   --policy-namespaces value, --namespaces value  Rego namespaces (default: "users") [$TRIVY_POLICY_NAMESPACES]
   --include-successes                            include successes of misconfigurations (default: false) [$TRIVY_INCLUDE_SUCCESSES]
   --help, -h                                     show help (default: false)
```
