# Client

```bash
NAME:
   trivy client - client mode

USAGE:
   trivy client [command options] image_name

OPTIONS:
   --template value, -t value  output template [$TRIVY_TEMPLATE]
   --format value, -f value    format (table, json, template) (default: "table") [$TRIVY_FORMAT]
   --input value, -i value     input file path instead of image name [$TRIVY_INPUT]
   --severity value, -s value  severities of vulnerabilities to be displayed (comma separated) (default: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL") [$TRIVY_SEVERITY]
   --output value, -o value    output file name [$TRIVY_OUTPUT]
   --exit-code value           Exit code when vulnerabilities were found (default: 0) [$TRIVY_EXIT_CODE]
   --clear-cache, -c           clear image caches without scanning (default: false) [$TRIVY_CLEAR_CACHE]
   --ignore-unfixed            display only fixed vulnerabilities (default: false) [$TRIVY_IGNORE_UNFIXED]
   --removed-pkgs              detect vulnerabilities of removed packages (only for Alpine) (default: false) [$TRIVY_REMOVED_PKGS]
   --vuln-type value           comma-separated list of vulnerability types (os,library) (default: "os,library") [$TRIVY_VULN_TYPE]
   --ignorefile value          specify .trivyignore file (default: ".trivyignore") [$TRIVY_IGNOREFILE]
   --timeout value             timeout (default: 5m0s) [$TRIVY_TIMEOUT]
   --ignore-policy value       specify the Rego file to evaluate each vulnerability [$TRIVY_IGNORE_POLICY]
   --list-all-pkgs             enabling the option will output all packages regardless of vulnerability (default: false) [$TRIVY_LIST_ALL_PKGS]
   --token value               for authentication [$TRIVY_TOKEN]
   --token-header value        specify a header name for token (default: "Trivy-Token") [$TRIVY_TOKEN_HEADER]
   --remote value              server address (default: "http://localhost:4954") [$TRIVY_REMOTE]
   --custom-headers value      custom headers [$TRIVY_CUSTOM_HEADERS]
   --help, -h                  show help (default: false)
```
