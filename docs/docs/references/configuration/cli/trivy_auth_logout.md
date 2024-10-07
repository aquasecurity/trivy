## trivy auth logout

Log out of a registry

```
trivy auth logout SERVER [flags]
```

### Examples

```
  # Log out of reg.example.com
  trivy auth logout reg.example.com
```

### Options

```
  -h, --help   help for logout
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

* [trivy auth](trivy_auth.md)	 - Authentication

