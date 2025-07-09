## trivy registry login

Log in to a registry

```
trivy registry login SERVER [flags]
```

### Examples

```
  # Log in to reg.example.com
  cat ~/my_password.txt | trivy registry login --username foo --password-stdin reg.example.com
```

### Options

```
  -h, --help               help for login
      --password strings   password. Comma-separated passwords allowed. TRIVY_PASSWORD should be used for security reasons.
      --password-stdin     password from stdin. Comma-separated passwords are not supported.
      --username strings   username. Comma-separated usernames allowed.
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

* [trivy registry](trivy_registry.md)	 - Manage registry authentication

