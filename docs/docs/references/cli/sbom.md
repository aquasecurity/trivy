# SBOM

```bash
NAME:
   trivy sbom - generate SBOM for an artifact

USAGE:
   trivy sbom [command options] ARTIFACT

OPTIONS:
   --output value, -o value             output file name [$TRIVY_OUTPUT]
   --clear-cache, -c                    clear image caches without scanning (default: false) [$TRIVY_CLEAR_CACHE]
   --ignorefile value                   specify .trivyignore file (default: ".trivyignore") [$TRIVY_IGNOREFILE]
   --timeout value                      timeout (default: 5m0s) [$TRIVY_TIMEOUT]
   --severity value, -s value           severities of vulnerabilities to be displayed (comma separated) (default: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL") [$TRIVY_SEVERITY]
   --artifact-type value, --type value  input artifact type (image, fs, repo, archive) (default: "image") [$TRIVY_ARTIFACT_TYPE]
   --sbom-format value, --format value  SBOM format (cyclonedx) (default: "cyclonedx") [$TRIVY_SBOM_FORMAT]
   --help, -h                           show help (default: false)
```
