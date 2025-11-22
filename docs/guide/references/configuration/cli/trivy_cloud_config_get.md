## trivy cloud config get

Get Trivy Cloud configuration

### Synopsis

Get a Trivy Cloud platform configuration
			
Available config settings can be viewed by using the `trivy cloud config list` command

```
trivy cloud config get [setting] [flags]
```

### Examples

```
  $ trivy cloud config get server.scanning.enabled
  $ trivy cloud config get server.scanning.upload-results
```

### Options

```
  -h, --help   help for get
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

