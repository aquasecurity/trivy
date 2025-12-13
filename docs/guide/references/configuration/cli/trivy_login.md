## trivy login

Log in to Trivy Pro

```
trivy login [flags]
```

### Options

```
  -h, --help                          help for login
      --pro-api-url string            API URL for Trivy Pro platform, requires the token to be provided to have an effect (default "https://api.trivy.dev")
      --pro-app-url string            App URL for Trivy Pro platform, requires the token to be provided to have an effect (default "https://app.trivy.dev")
      --pro-server-scanning           Use server-side image scanning in Trivy Pro platform, requires the token to be provided to have an effect (default true)
      --pro-token string              Token used to athenticate with Trivy Pro platform
      --pro-trivy-server-url string   Trivy Server URL for Trivy Pro platform, requires the token to be provided to have an effect (default "https://scan.trivy.dev")
      --pro-upload-results            Upload results to Trivy Pro platform, requires the token to be provided to have an effect
      --pro-use-secret-config         Use secret configurations from Trivy Pro platform, requires the token to be provided to have an effect (default true)
```

### Options inherited from parent commands

```
      --cacert string             Path to PEM-encoded CA certificate file
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
* [trivy login status](trivy_login_status.md)	 - Check the login status of Trivy Pro

