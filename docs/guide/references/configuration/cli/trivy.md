## trivy

Unified security scanner

### Synopsis

Scanner for vulnerabilities in container images, file systems, and Git repositories, as well as for configuration issues and hard-coded secrets

```
trivy [global flags] command [flags] target
```

### Examples

```
  # Scan a container image
  $ trivy image python:3.4-alpine

  # Scan a container image from a tar archive
  $ trivy image --input ruby-3.1.tar

  # Scan local filesystem
  $ trivy fs .

  # Run in server mode
  $ trivy server
```

### Options

```
      --cacert string             Path to PEM-encoded CA certificate file
      --cache-dir string          cache directory (default "/path/to/cache")
  -c, --config string             config path (default "trivy.yaml")
  -d, --debug                     debug mode
  -f, --format string             version format (json)
      --generate-default-config   write the default config to trivy-default.yaml
  -h, --help                      help for trivy
      --insecure                  allow insecure server connections
      --no-color                  Remove color from output
  -q, --quiet                     suppress progress bar and log output
      --timeout duration          timeout (default 5m0s)
  -v, --version                   show version
```

### SEE ALSO

* [trivy clean](trivy_clean.md)	 - Remove cached files
* [trivy cloud](trivy_cloud.md)	 - Control Trivy Cloud platform integration settings
* [trivy config](trivy_config.md)	 - Scan config files for misconfigurations
* [trivy convert](trivy_convert.md)	 - Convert Trivy JSON report into a different format
* [trivy filesystem](trivy_filesystem.md)	 - Scan local filesystem
* [trivy image](trivy_image.md)	 - Scan a container image
* [trivy kubernetes](trivy_kubernetes.md)	 - [EXPERIMENTAL] Scan kubernetes cluster
* [trivy login](trivy_login.md)	 - Log in to the Trivy Cloud platform
* [trivy logout](trivy_logout.md)	 - Log out of Trivy Cloud platform
* [trivy module](trivy_module.md)	 - Manage modules
* [trivy plugin](trivy_plugin.md)	 - Manage plugins
* [trivy registry](trivy_registry.md)	 - Manage registry authentication
* [trivy repository](trivy_repository.md)	 - Scan a repository
* [trivy rootfs](trivy_rootfs.md)	 - Scan rootfs
* [trivy sbom](trivy_sbom.md)	 - Scan SBOM for vulnerabilities and licenses
* [trivy server](trivy_server.md)	 - Server mode
* [trivy version](trivy_version.md)	 - Print the version
* [trivy vex](trivy_vex.md)	 - [EXPERIMENTAL] VEX utilities
* [trivy vm](trivy_vm.md)	 - [EXPERIMENTAL] Scan a virtual machine image

