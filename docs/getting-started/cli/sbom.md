# Sbom

```bash
NAME:
   trivy sbom - generate sbom for an artifact

USAGE:
   trivy sbom [command options] ARTIFACT

DESCRIPTION:
   "ARTIFACT" uses the "type":"path" format.
       Supported types: [image dir archive]

OPTIONS:
   --format value, -f value  format (cyclonedx) (default: "cyclonedx") [$TRIVY_SBOM_FORMAT]
   --output value, -o value  output file name [$TRIVY_OUTPUT]
   --clear-cache, -c         clear image caches without scanning (default: false) [$TRIVY_CLEAR_CACHE]
   --ignorefile value        specify .trivyignore file (default: ".trivyignore") [$TRIVY_IGNOREFILE]
   --timeout value           timeout (default: 5m0s) [$TRIVY_TIMEOUT]
   --help, -h                show help (default: false)
```
