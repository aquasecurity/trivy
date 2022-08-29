# Module

```bash
Manage modules

Usage:
  trivy module [command]

Aliases:
  module, m

Available Commands:
  install     Install a module
  uninstall   Uninstall a module

Flags:
  -h, --help   help for module

Global Flags:
      --cache-dir string          cache directory (default "/Users/teppei/Library/Caches/trivy")
  -c, --config string             config path (default "trivy.yaml")
  -d, --debug                     debug mode
      --generate-default-config   write the default config to trivy-default.yaml
      --insecure                  allow insecure server connections when using TLS
  -q, --quiet                     suppress progress bar and log output
      --timeout duration          timeout (default 5m0s)
  -v, --version                   show version

Use "trivy module [command] --help" for more information about a command.
```