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
  -h, --help   help for repo
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

* [trivy vex](trivy_vex.md)	 - [EXPERIMENTAL] VEX utilities
* [trivy vex repo download](trivy_vex_repo_download.md)	 - Download the VEX repositories
* [trivy vex repo init](trivy_vex_repo_init.md)	 - Initialize a configuration file
* [trivy vex repo list](trivy_vex_repo_list.md)	 - List VEX repositories

