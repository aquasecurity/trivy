## trivy vex repo download

Download the VEX repositories

### Synopsis

Downloads enabled VEX repositories. If specific repository names are provided as arguments, only those repositories will be downloaded. Otherwise, all enabled repositories are downloaded.

```
trivy vex repo download [REPO_NAMES] [flags]
```

### Options

```
  -h, --help   help for download
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

* [trivy vex repo](trivy_vex_repo.md)	 - Manage VEX repositories

