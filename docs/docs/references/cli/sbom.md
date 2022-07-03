# SBOM

```bash
NAME:
   trivy sbom - scan SBOM for vulnerabilities

USAGE:
   trivy sbom [command options] SBOM

OPTIONS:
   --cache-backend value            cache backend (e.g. redis://localhost:6379) (default: "fs") [$TRIVY_CACHE_BACKEND]
   --cache-ttl value                cache TTL when using redis as cache backend (default: 0s) [$TRIVY_CACHE_TTL]
   --clear-cache, -c                clear image caches without scanning (default: false) [$TRIVY_CLEAR_CACHE]
   --custom-headers value           custom headers in client/server mode  (accepts multiple inputs) [$TRIVY_CUSTOM_HEADERS]
   --db-repository value            OCI repository to retrieve trivy-db from (default: "ghcr.io/aquasecurity/trivy-db") [$TRIVY_DB_REPOSITORY]
   --download-db-only               download/update vulnerability database but don't run a scan (default: false) [$TRIVY_DOWNLOAD_DB_ONLY]
   --exit-code value                Exit code when vulnerabilities were found (default: 0) [$TRIVY_EXIT_CODE]
   --format value, -f value         format (table, json, sarif, template, cyclonedx, spdx, spdx-json, github) (default: "table") [$TRIVY_FORMAT]
   --ignore-policy value            specify the Rego file to evaluate each vulnerability [$TRIVY_IGNORE_POLICY]
   --ignore-unfixed                 display only fixed vulnerabilities (default: false) [$TRIVY_IGNORE_UNFIXED]
   --ignorefile value               specify .trivyignore file (default: ".trivyignore") [$TRIVY_IGNOREFILE]
   --input value, -i value          input file path instead of image name [$TRIVY_INPUT]
   --insecure                       allow insecure server connections when using SSL (default: false) [$TRIVY_INSECURE]
   --list-all-pkgs                  enabling the option will output all packages regardless of vulnerability (default: false) [$TRIVY_LIST_ALL_PKGS]
   --no-progress                    suppress progress bar (default: false) [$TRIVY_NO_PROGRESS]
   --offline-scan                   do not issue API requests to identify dependencies (default: false) [$TRIVY_OFFLINE_SCAN]
   --output value, -o value         output file name [$TRIVY_OUTPUT]
   --reset                          remove all caches and database (default: false) [$TRIVY_RESET]
   --security-checks value          comma-separated list of what security issues to detect (vuln,config,secret) (default: "vuln") [$TRIVY_SECURITY_CHECKS]
   --server value                   server address [$TRIVY_SERVER]
   --severity value, -s value       severities of vulnerabilities to be displayed (comma separated) (default: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL") [$TRIVY_SEVERITY]
   --skip-db-update, --skip-update  skip updating vulnerability database (default: false) [$TRIVY_SKIP_UPDATE, $TRIVY_SKIP_DB_UPDATE]
   --skip-dirs value                specify the directories where the traversal is skipped  (accepts multiple inputs) [$TRIVY_SKIP_DIRS]
   --skip-files value               specify the file paths to skip traversal                (accepts multiple inputs) [$TRIVY_SKIP_FILES]
   --template value, -t value       output template [$TRIVY_TEMPLATE]
   --timeout value                  timeout (default: 5m0s) [$TRIVY_TIMEOUT]
   --token value                    for authentication in client/server mode [$TRIVY_TOKEN]
   --token-header value             specify a header name for token in client/server mode (default: "Trivy-Token") [$TRIVY_TOKEN_HEADER]

EXAMPLES:
  - Scan CycloneDX and show the result in tables:
      $ trivy sbom /path/to/report.cdx

  - Scan CycloneDX and generate a CycloneDX report:
      $ trivy sbom --format cyclonedx /path/to/report.cdx
```
