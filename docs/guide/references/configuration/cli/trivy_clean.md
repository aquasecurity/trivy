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
  -a, --all[=true|false]             remove all caches
      --checks-bundle[=true|false]   remove checks bundle
  -h, --help[=true|false]            help for clean
      --java-db[=true|false]         remove Java database
      --scan-cache[=true|false]      remove scan cache (container and VM image analysis results)
      --vex-repo[=true|false]        remove VEX repositories
      --vuln-db[=true|false]         remove vulnerability database
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

