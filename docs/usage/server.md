# Server

```bash
NAME:
   trivy server - server mode

USAGE:
   trivy server [command options] [arguments...]

OPTIONS:
   --skip-update          skip db update (default: false) [$TRIVY_SKIP_UPDATE]
   --download-db-only     download/update vulnerability database but don't run a scan (default: false) [$TRIVY_DOWNLOAD_DB_ONLY]
   --reset                remove all caches and database (default: false) [$TRIVY_RESET]
   --cache-backend value  cache backend (e.g. redis://localhost:6379) (default: "fs") [$TRIVY_CACHE_BACKEND]
   --token value          for authentication [$TRIVY_TOKEN]
   --token-header value   specify a header name for token (default: "Trivy-Token") [$TRIVY_TOKEN_HEADER]
   --listen value         listen address (default: "localhost:4954") [$TRIVY_LISTEN]
   --help, -h             show help (default: false)
```
