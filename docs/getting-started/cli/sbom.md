# Sbom

```bash
NAME:
   trivy sbom - generate sbom for an artifact

USAGE:
   trivy sbom [command options] ARTIFACT

DESCRIPTION:
   "ARTIFACT" is the artifact path, trivy will determine the artifact type.
       To tell trivy the artifact type you can use use the "type":"details" format.
       Supported types: [image dir archive]

OPTIONS:
   --format value, -f value  format (table, json, sarif, template) (default: "table") [$TRIVY_FORMAT]
   --output value, -o value  output file name [$TRIVY_OUTPUT]
   --clear-cache, -c         clear image caches without scanning (default: false) [$TRIVY_CLEAR_CACHE]
   --ignorefile value        specify .trivyignore file (default: ".trivyignore") [$TRIVY_IGNOREFILE]
   --timeout value           timeout (default: 5m0s) [$TRIVY_TIMEOUT]
   --help, -h                show help (default: false)
```
