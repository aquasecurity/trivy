# Image

```bash
NAME:
   trivy image - scan an image

USAGE:
   trivy image [command options] image_name

OPTIONS:
   --template value, -t value       output template [$TRIVY_TEMPLATE]
   --format value, -f value         format (table, json, sarif, template) (default: "table") [$TRIVY_FORMAT]
   --input value, -i value          input file path instead of image name [$TRIVY_INPUT]
   --severity value, -s value       severities of vulnerabilities to be displayed (comma separated) (default: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL") [$TRIVY_SEVERITY]
   --output value, -o value         output file name [$TRIVY_OUTPUT]
   --exit-code value                Exit code when vulnerabilities were found (default: 0) [$TRIVY_EXIT_CODE]
   --skip-db-update, --skip-update  skip updating vulnerability database (default: false) [$TRIVY_SKIP_UPDATE, $TRIVY_SKIP_DB_UPDATE]
   --download-db-only               download/update vulnerability database but don't run a scan (default: false) [$TRIVY_DOWNLOAD_DB_ONLY]
   --reset                          remove all caches and database (default: false) [$TRIVY_RESET]
   --clear-cache, -c                clear image caches without scanning (default: false) [$TRIVY_CLEAR_CACHE]
   --no-progress                    suppress progress bar (default: false) [$TRIVY_NO_PROGRESS]
   --ignore-unfixed                 display only fixed vulnerabilities (default: false) [$TRIVY_IGNORE_UNFIXED]
   --removed-pkgs                   detect vulnerabilities of removed packages (only for Alpine) (default: false) [$TRIVY_REMOVED_PKGS]
   --vuln-type value                comma-separated list of vulnerability types (os,library) (default: "os,library") [$TRIVY_VULN_TYPE]
   --security-checks value          comma-separated list of what security issues to detect (vuln,config) (default: "vuln") [$TRIVY_SECURITY_CHECKS]
   --ignorefile value               specify .trivyignore file (default: ".trivyignore") [$TRIVY_IGNOREFILE]
   --timeout value                  timeout (default: 5m0s) [$TRIVY_TIMEOUT]
   --light                          deprecated (default: false) [$TRIVY_LIGHT]
   --ignore-policy value            specify the Rego file to evaluate each vulnerability [$TRIVY_IGNORE_POLICY]
   --list-all-pkgs                  enabling the option will output all packages regardless of vulnerability (default: false) [$TRIVY_LIST_ALL_PKGS]
   --cache-backend value            cache backend (e.g. redis://localhost:6379) (default: "fs") [$TRIVY_CACHE_BACKEND]
   --cache-ttl value                cache TTL when using redis as cache backend (default: 0s) [$TRIVY_CACHE_TTL]
   --offline-scan                   do not issue API requests to identify dependencies (default: false) [$TRIVY_OFFLINE_SCAN]
   --insecure                       allow insecure server connections when using SSL (default: false) [$TRIVY_INSECURE]
   --db-repository value            OCI repository to retrieve trivy-db from (default: "ghcr.io/aquasecurity/trivy-db") [$TRIVY_DB_REPOSITORY]
   --skip-files value               specify the file paths to skip traversal                (accepts multiple inputs) [$TRIVY_SKIP_FILES]
   --skip-dirs value                specify the directories where the traversal is skipped  (accepts multiple inputs) [$TRIVY_SKIP_DIRS]
   --server value                   server address [$TRIVY_SERVER]
   --token value                    for authentication in client/server mode [$TRIVY_TOKEN]
   --token-header value             specify a header name for token in client/server mode (default: "Trivy-Token") [$TRIVY_TOKEN_HEADER]
   --custom-headers value           custom headers in client/server mode  (accepts multiple inputs) [$TRIVY_CUSTOM_HEADERS]
   --help, -h                       show help (default: false)
```
