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
  -h, --help   help for install
```

### Options inherited from parent commands

```
      --cache-dir string          cache directory (default "/path/to/cache")
  -c, --config string             config path (default "trivy.yaml")
  -d, --debug                     debug mode
      --generate-default-config   write the default config to trivy-default.yaml
      --insecure                  allow insecure server connections
  -q, --quiet                     suppress progress bar and log output
      --timeout duration          timeout (default 5m0s)
  -v, --version                   show version
```

### SEE ALSO

* [trivy plugin](trivy_plugin.md)	 - Manage plugins

