## trivy login

Log in to the Trivy Cloud platform

### Synopsis

Log in to the Trivy Cloud platform to enable scanning of images and repositories in the cloud using the token retrieved from the Trivy Cloud platform

```
trivy login [flags]
```

### Examples

```
  # Log in to the Trivy Cloud platform
  $ trivy login --token <token>
```

### Options

```
      --api-url string            API URL for Trivy Cloud platform (default "https://app.trivy.dev")
  -h, --help                      help for login
      --token string              Token used to athenticate with Trivy Cloud platform
      --trivy-server-url string   Trivy Server URL for Trivy Cloud platform (default "https://scan.trivy.dev")
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

* [trivy](trivy.md)	 - Unified security scanner

