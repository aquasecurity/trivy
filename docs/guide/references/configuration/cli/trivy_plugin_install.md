## trivy plugin install

Install a plugin

```
trivy plugin install NAME | URL | FILE_PATH
```

### Examples

```
  # Install a plugin from the plugin index
  $ trivy plugin install referrer

  # Specify the version of the plugin to install
  $ trivy plugin install referrer@v0.3.0

  # Install a plugin from a URL
  $ trivy plugin install github.com/aquasecurity/trivy-plugin-referrer
```

### Options

```
  -h, --help[=true|false]   help for install
```

### Options inherited from parent commands

```
      --cacert string                          Path to PEM-encoded CA certificate file
      --cache-dir string                       cache directory (default "/path/to/cache")
  -c, --config string                          config path (empty string disables loading) (default "trivy.yaml")
  -d, --debug[=true|false]                     debug mode
      --generate-default-config[=true|false]   write the default config to trivy-default.yaml
      --insecure[=true|false]                  allow insecure server connections
  -q, --quiet[=true|false]                     suppress progress bar and log output
      --timeout duration                       timeout (default 5m0s)
  -v, --version[=true|false]                   show version
```

### SEE ALSO

* [trivy plugin](trivy_plugin.md)	 - Manage plugins

