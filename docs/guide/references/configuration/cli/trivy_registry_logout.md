## trivy registry logout

Log out of a registry

```
trivy registry logout SERVER [flags]
```

### Examples

```
  # Log out of reg.example.com
  trivy registry logout reg.example.com
```

### Options

```
  -h, --help[=true|false]   help for logout
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

* [trivy registry](trivy_registry.md)	 - Manage registry authentication

