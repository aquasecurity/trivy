## trivy cloud config edit

Edit Trivy Cloud configuration

### Synopsis

Edit Trivy Cloud platform configuration in the default editor specified in the EDITOR environment variable

```
trivy cloud config edit [flags]
```

### Options

```
  -h, --help   help for edit
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

* [trivy cloud config](trivy_cloud_config.md)	 - Control Trivy Cloud configuration

