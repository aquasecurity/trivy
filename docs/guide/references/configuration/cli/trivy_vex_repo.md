## trivy vex repo

Manage VEX repositories

### Examples

```
  # Initialize the configuration file
  $ trivy vex repo init

  # List VEX repositories
  $ trivy vex repo list

  # Download the VEX repositories
  $ trivy vex repo download

```

### Options

```
  -h, --help[=true|false]   help for repo
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

* [trivy vex](trivy_vex.md)	 - [EXPERIMENTAL] VEX utilities
* [trivy vex repo download](trivy_vex_repo_download.md)	 - Download the VEX repositories
* [trivy vex repo init](trivy_vex_repo_init.md)	 - Initialize a configuration file
* [trivy vex repo list](trivy_vex_repo_list.md)	 - List VEX repositories

