## trivy plugin

Manage plugins

### Options

```
  -h, --help[=true|false]   help for plugin
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

* [trivy](trivy.md)	 - Unified security scanner
* [trivy plugin info](trivy_plugin_info.md)	 - Show information about the specified plugin
* [trivy plugin install](trivy_plugin_install.md)	 - Install a plugin
* [trivy plugin list](trivy_plugin_list.md)	 - List installed plugin
* [trivy plugin run](trivy_plugin_run.md)	 - Run a plugin on the fly
* [trivy plugin search](trivy_plugin_search.md)	 - List Trivy plugins available on the plugin index and search among them
* [trivy plugin uninstall](trivy_plugin_uninstall.md)	 - Uninstall a plugin
* [trivy plugin update](trivy_plugin_update.md)	 - Update the local copy of the plugin index
* [trivy plugin upgrade](trivy_plugin_upgrade.md)	 - Upgrade installed plugins to newer versions

