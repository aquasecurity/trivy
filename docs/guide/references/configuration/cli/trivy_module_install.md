## trivy module install

Install a module

```
trivy module install [flags] REPOSITORY
```

### Options

```
  -h, --help[=true|false]   help for install
```

### Options inherited from parent commands

```
      --cacert string                          Path to PEM-encoded CA certificate file
      --cache-dir string                       cache directory (default "/path/to/cache")
  -c, --config string                          config path (empty string disables loading) (default "trivy.yaml")
  -d, --debug[=true|false]                     debug mode
      --enable-modules strings                 [EXPERIMENTAL] module names to enable
      --generate-default-config[=true|false]   write the default config to trivy-default.yaml
      --insecure[=true|false]                  allow insecure server connections
      --module-dir string                      specify the directory of the WASM modules to load (default "$HOME/.trivy/modules")
  -q, --quiet[=true|false]                     suppress progress bar and log output
      --timeout duration                       timeout (default 5m0s)
  -v, --version[=true|false]                   show version
```

### SEE ALSO

* [trivy module](trivy_module.md)	 - Manage modules

