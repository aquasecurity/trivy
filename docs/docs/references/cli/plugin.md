# Plugin

```bash
Manage plugins

Usage:
  trivy plugin [command]

Aliases:
  plugin, p

Available Commands:
  Uninstall   uninstall a plugin
  info        Show information about the specified plugin
  install     Install a plugin
  list        List installed plugin
  run         Run a plugin on the fly
  update      Update an existing plugin

Flags:
  -h, --help   help for plugin

Global Flags:
      --cache-dir string   cache directory (default "/Users/teppei/Library/Caches/trivy")
  -c, --config string      config path (default "trivy.yaml")
  -d, --debug              debug mode
      --insecure           allow insecure server connections when using TLS
  -q, --quiet              suppress progress bar and log output
      --timeout duration   timeout (default 5m0s)
  -v, --version            show version
```