# SBOM

```bash
NAME:
   trivy sbom - generate SBOM for an artifact

USAGE:
   trivy sbom [command options] ARTIFACT

DESCRIPTION:
   ARTIFACT can be a container image, file path/directory, git repository or container image archive. See examples.

OPTIONS:
   --output value, -o value             output file name [$TRIVY_OUTPUT]
   --clear-cache, -c                    clear image caches without scanning (default: false) [$TRIVY_CLEAR_CACHE]
   --ignorefile value                   specify .trivyignore file (default: ".trivyignore") [$TRIVY_IGNOREFILE]
   --timeout value                      timeout (default: 5m0s) [$TRIVY_TIMEOUT]
   --severity value, -s value           severities of vulnerabilities to be displayed (comma separated) (default: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL") [$TRIVY_SEVERITY]
   --offline-scan                       do not issue API requests to identify dependencies (default: false) [$TRIVY_OFFLINE_SCAN]
   --db-repository value                OCI repository to retrieve trivy-db from (default: "ghcr.io/aquasecurity/trivy-db") [$TRIVY_DB_REPOSITORY]
   --insecure                           allow insecure server connections when using SSL (default: false) [$TRIVY_INSECURE]
   --skip-files value                   specify the file paths to skip traversal                (accepts multiple inputs) [$TRIVY_SKIP_FILES]
   --skip-dirs value                    specify the directories where the traversal is skipped  (accepts multiple inputs) [$TRIVY_SKIP_DIRS]
   --artifact-type value, --type value  input artifact type (image, fs, repo, archive) (default: "image") [$TRIVY_ARTIFACT_TYPE]
   --sbom-format value, --format value  SBOM format (cyclonedx, spdx, spdx-json) (default: "cyclonedx") [$TRIVY_SBOM_FORMAT]
   --help, -h                           show help (default: false)
```
