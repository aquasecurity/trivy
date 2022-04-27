# Server

```bash
NAME:
   trivy server - server mode

USAGE:
   trivy server [command options] [arguments...]

OPTIONS:
   --skip-db-update, --skip-update  skip updating vulnerability database (default: false) [$TRIVY_SKIP_UPDATE, $TRIVY_SKIP_DB_UPDATE]
   --download-db-only               download/update vulnerability database but don't run a scan (default: false) [$TRIVY_DOWNLOAD_DB_ONLY]
   --reset                          remove all caches and database (default: false) [$TRIVY_RESET]
   --cache-backend value            cache backend (e.g. redis://localhost:6379) (default: "fs") [$TRIVY_CACHE_BACKEND]
   --cache-ttl value                cache TTL when using redis as cache backend (default: 0s) [$TRIVY_CACHE_TTL]
   --db-repository value            OCI repository to retrieve trivy-db from (default: "ghcr.io/aquasecurity/trivy-db") [$TRIVY_DB_REPOSITORY]
   --token value                    for authentication in client/server mode [$TRIVY_TOKEN]
   --token-header value             specify a header name for token in client/server mode (default: "Trivy-Token") [$TRIVY_TOKEN_HEADER]
   --listen value                   listen address (default: "localhost:4954") [$TRIVY_LISTEN]
   --help, -h                       show help (default: false)
```
