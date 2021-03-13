Trivy has several sub commands, image, fs, repo, client and server.

```
NAME:
   trivy - A simple and comprehensive vulnerability scanner for containers

USAGE:
   trivy [global options] command [command options] target

VERSION:
   v0.15.0

COMMANDS:
   image, i          scan an image
   filesystem, fs    scan local filesystem
   repository, repo  scan remote repository
   client, c         client mode
   server, s         server mode
   help, h           Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --quiet, -q        suppress progress bar and log output (default: false) [$TRIVY_QUIET]
   --debug, -d        debug mode (default: false) [$TRIVY_DEBUG]
   --cache-dir value  cache directory (default: "/Users/teppei/Library/Caches/trivy") [$TRIVY_CACHE_DIR]
   --help, -h         show help (default: false)
   --version, -v      print the version (default: false)
```
