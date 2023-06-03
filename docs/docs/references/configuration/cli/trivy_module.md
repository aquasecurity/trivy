## trivy module

Manage modules

### Options

```
      --enable-modules strings   [EXPERIMENTAL] module names to enable
  -h, --help                     help for module
      --module-dir string        specify directory to the wasm modules that will be loaded (default "$HOME/.trivy/modules")
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
* [trivy module install](trivy_module_install.md)	 - Install a module
* [trivy module uninstall](trivy_module_uninstall.md)	 - Uninstall a module

