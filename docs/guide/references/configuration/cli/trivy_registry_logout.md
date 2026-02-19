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
  -h, --help   help for logout
```

### Options inherited from parent commands

```
      --cacert string             Path to PEM-encoded CA certificate file
      --cache-dir string          cache directory (default "/path/to/cache")
  -c, --config string             config path (default "trivy.yaml")
  -d, --debug                     debug mode
      --generate-default-config   write the default config to trivy-default.yaml
      --insecure                  allow insecure server connections
      --no-color                  Remove color from output
  -q, --quiet                     suppress progress bar and log output
      --timeout duration          timeout (default 5m0s)
  -v, --version                   show version
```

### SEE ALSO

* [trivy registry](trivy_registry.md)	 - Manage registry authentication

