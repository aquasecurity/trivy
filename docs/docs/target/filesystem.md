# Filesystem

Scan a code project in a directory, or a specific file. This is typically used for scanning code projects. 

`fs` is a pre-build target type, which means it scans package manager lock files. For more information, see [Target types](../coverage/language/index.md#target-types).

Usage:

```shell
trivy fs /path/to/directory
trivy fs /path/to/file
```

## Scanners

Supported scanners:

- Vulnerabilities
- Misconfigurations
- Secrets
- Licenses
 
By default, only vulnerability and secret scanning are enabled. You can configure which scanners are used with the [`--scanners` flag](https://trivy.dev/latest/docs/configuration/others/#enabledisable-scanners).

## Scan Cache
When scanning local projects, it doesn't use the cache by default.
However, when the local project is a git repository with clean status and the cache backend other than the memory one is enabled, it stores analysis results, using the latest commit hash as the key.

```shell
$ trivy fs --cache-backend fs /path/to/git/repo
```

More details are available in the [cache documentation](../configuration/cache.md#scan-cache-backend).