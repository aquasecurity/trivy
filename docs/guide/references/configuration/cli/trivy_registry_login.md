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
  -h, --help[=true|false]             help for login
      --password strings              password. Comma-separated passwords allowed. TRIVY_PASSWORD should be used for security reasons.
      --password-stdin[=true|false]   password from stdin. Comma-separated passwords are not supported.
      --username strings              username. Comma-separated usernames allowed.
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

