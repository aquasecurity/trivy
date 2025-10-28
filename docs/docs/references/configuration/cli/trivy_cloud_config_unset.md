## trivy cloud config unset

Unset Trivy Cloud configuration

### Synopsis

Unset a Trivy Cloud platform configuration and return it to the default setting
			
Available config settings can be viewed by using the `trivy cloud config list` command

```
trivy cloud config unset [setting] [flags]
```

### Examples

```
  $ trivy cloud config unset server.scanning.enabled
  $ trivy cloud config unset server.scanning.upload-results
```

### Options

```
  -h, --help   help for unset
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

* [trivy cloud config](trivy_cloud_config.md)	 - Control Trivy Cloud configuration

