# Server

```bash
Server mode

Usage:
  trivy server [flags]

Aliases:
  server, s

Examples:
  # Run a server
  $ trivy server

  # Listen on 0.0.0.0:10000
  $ trivy server --listen 0.0.0.0:10000


Cache Flags
      --cache-backend string   cache backend (e.g. redis://localhost:6379) (default "fs")
      --cache-ttl duration     cache TTL when using redis as cache backend
      --clear-cache            clear image caches without scanning
      --redis-ca string        redis ca file location, if using redis as cache backend
      --redis-cert string      redis certificate file location, if using redis as cache backend
      --redis-key string       redis key file location, if using redis as cache backend

DB Flags
      --db-repository string   OCI repository to retrieve trivy-db from (default "ghcr.io/aquasecurity/trivy-db")
      --download-db-only       download/update vulnerability database but don't run a scan
      --no-progress            suppress progress bar
      --reset                  remove all caches and database
      --skip-db-update         skip updating vulnerability database

Client/Server Flags
      --listen string         listen address in server mode (default "localhost:4954")
      --token string          for authentication in client/server mode
      --token-header string   specify a header name for token in client/server mode (default "Trivy-Token")

Global Flags:
      --cache-dir string          cache directory (default "/Users/teppei/Library/Caches/trivy")
  -c, --config string             config path (default "trivy.yaml")
  -d, --debug                     debug mode
      --generate-default-config   write the default config to trivy-default.yaml
      --insecure                  allow insecure server connections when using TLS
  -q, --quiet                     suppress progress bar and log output
      --timeout duration          timeout (default 5m0s)
  -v, --version                   show version
```
