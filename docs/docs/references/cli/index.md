Trivy has several sub commands, image, fs, repo, client and server.

``` bash
Scanner for vulnerabilities in container images, file systems, and Git repositories, as well as for configuration issues and hard-coded secrets

Usage:
  trivy [global flags] command [flags] target
  trivy [command]

Examples:
  # Scan a container image
  $ trivy image python:3.4-alpine

  # Scan a container image from a tar archive
  $ trivy image --input ruby-3.1.tar

  # Scan local filesystem
  $ trivy fs .

  # Run in server mode
  $ trivy server

Available Commands:
  config      Scan config files for misconfigurations
  filesystem  Scan local filesystem
  help        Help about any command
  image       Scan a container image
  kubernetes  scan kubernetes cluster
  module      Manage modules
  plugin      Manage plugins
  repository  Scan a remote repository
  rootfs      Scan rootfs
  sbom        Scan SBOM for vulnerabilities
  server      Server mode
  version     Print the version

Flags:
      --cache-dir string          cache directory (default "/Users/teppei/Library/Caches/trivy")
  -c, --config string             config path (default "trivy.yaml")
  -d, --debug                     debug mode
  -f, --format string             version format (json)
      --generate-default-config   write the default config to trivy-default.yaml
  -h, --help                      help for trivy
      --insecure                  allow insecure server connections when using TLS
  -q, --quiet                     suppress progress bar and log output
      --timeout duration          timeout (default 5m0s)
  -v, --version                   show version

Use "trivy [command] --help" for more information about a command.
```
