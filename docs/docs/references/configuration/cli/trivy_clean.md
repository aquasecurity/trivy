## trivy clean

Remove cached files

```
trivy clean [flags]
```

### Examples

```
  # Remove all caches
  $ trivy clean --all

  # Remove scan cache
  $ trivy clean --scan-cache

  # Remove vulnerability database
  $ trivy clean --vuln-db

```

### Options

```
  -a, --all             remove all caches
      --checks-bundle   remove checks bundle
  -h, --help            help for clean
      --java-db         remove Java database
      --scan-cache      remove scan cache (container and VM image analysis results)
      --vex-repo        remove VEX repositories
      --vuln-db         remove vulnerability database
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

