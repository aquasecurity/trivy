## trivy cloud edit-config

Edit Trivy Cloud configuration

### Synopsis

Edit the Trivy Cloud platform configuration in the default editor specified in the EDITOR environment variable

```
trivy cloud edit-config [flags]
```

### Options

```
  -h, --help   help for edit-config
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

* [trivy cloud](trivy_cloud.md)	 - Control Trivy Cloud platform integration settings

