Trivy has several sub commands, image, fs, repo, client and server.

``` bash
NAME:
   trivy - Scanner for vulnerabilities in container images, file systems, and Git repositories, as well as for configuration issues and hard-coded secrets

USAGE:
   trivy [global options] command [command options] target

VERSION:
   dev

COMMANDS:
   image, i          scan an image
   filesystem, fs    scan local filesystem for language-specific dependencies and config files
   rootfs            scan rootfs
   repository, repo  scan remote repository
   server, s         server mode
   config, conf      scan config files
   plugin, p         manage plugins
   kubernetes, k8s   scan kubernetes vulnerabilities and misconfigurations
   sbom              generate SBOM for an artifact
   version           print the version
   help, h           Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --quiet, -q        suppress progress bar and log output (default: false) [$TRIVY_QUIET]
   --debug, -d        debug mode (default: false) [$TRIVY_DEBUG]
   --cache-dir value  cache directory (default: "/Users/teppei/Library/Caches/trivy") [$TRIVY_CACHE_DIR]
   --help, -h         show help (default: false)
   --version, -v      print the version (default: false)
```
