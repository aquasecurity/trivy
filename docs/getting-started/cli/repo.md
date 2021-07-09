# Repository

```bash
NAME:
   trivy repository - scan remote repository

USAGE:
   trivy repository [command options] repo_url

OPTIONS:
   --template value, -t value  output template [$TRIVY_TEMPLATE]
   --format value, -f value    format (table, json, template) (default: "table") [$TRIVY_FORMAT]
   --input value, -i value     input file path instead of image name [$TRIVY_INPUT]
   --severity value, -s value  severities of vulnerabilities to be displayed (comma separated) (default: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL") [$TRIVY_SEVERITY]
   --output value, -o value    output file name [$TRIVY_OUTPUT]
   --exit-code value           Exit code when vulnerabilities were found (default: 0) [$TRIVY_EXIT_CODE]
   --skip-update               skip db update (default: false) [$TRIVY_SKIP_UPDATE]
   --clear-cache, -c           clear image caches without scanning (default: false) [$TRIVY_CLEAR_CACHE]
   --ignore-unfixed            display only fixed vulnerabilities (default: false) [$TRIVY_IGNORE_UNFIXED]
   --removed-pkgs              detect vulnerabilities of removed packages (only for Alpine) (default: false) [$TRIVY_REMOVED_PKGS]
   --vuln-type value           comma-separated list of vulnerability types (os,library) (default: "os,library") [$TRIVY_VULN_TYPE]
   --ignorefile value          specify .trivyignore file (default: ".trivyignore") [$TRIVY_IGNOREFILE]
   --cache-backend value       cache backend (e.g. redis://localhost:6379) (default: "fs") [$TRIVY_CACHE_BACKEND]
   --timeout value             timeout (default: 5m0s) [$TRIVY_TIMEOUT]
   --no-progress               suppress progress bar (default: false) [$TRIVY_NO_PROGRESS]
   --ignore-policy value       specify the Rego file to evaluate each vulnerability [$TRIVY_IGNORE_POLICY]
   --list-all-pkgs             enabling the option will output all packages regardless of vulnerability (default: false) [$TRIVY_LIST_ALL_PKGS]
   --skip-files value          specify the file path to skip traversal [$TRIVY_SKIP_FILES]
   --skip-dirs value           specify the directory where the traversal is skipped [$TRIVY_SKIP_DIRS]
   --help, -h                  show help (default: false)
```