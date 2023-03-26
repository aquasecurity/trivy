# Troubleshooting

## Scan
### Timeout

!!! error
    ``` bash
    $ trivy image ...
    ...
    analyze error: timeout: context deadline exceeded
    ```

Your scan may time out. Java takes a particularly long time to scan. Try increasing the value of the ---timeout option such as `--timeout 15m`.

### Certification

!!! error
    Error: x509: certificate signed by unknown authority

`TRIVY_INSECURE` can be used to allow insecure connections to a container registry when using SSL.

```
$ TRIVY_INSECURE=true trivy image [YOUR_IMAGE]
```

### GitHub Rate limiting

!!! error
    ``` bash
    $ trivy image ...
    ...
    API rate limit exceeded for xxx.xxx.xxx.xxx.
    ```

Specify GITHUB_TOKEN for authentication
https://developer.github.com/v3/#rate-limiting

```
$ GITHUB_TOKEN=XXXXXXXXXX trivy alpine:3.10
```

### Unable to open JAR files

!!! error
    ``` bash
    $ trivy image ...
    ...
    failed to analyze file: failed to analyze usr/lib/jvm/java-1.8-openjdk/lib/tools.jar: unable to open usr/lib/jvm/java-1.8-openjdk/lib/tools.jar: failed to open: unable to read the file: stream error: stream ID 9; PROTOCOL_ERROR; received from peer
    ```

Currently, we're investigating this issue. As a temporary mitigation, you may be able to avoid this issue by downloading the Java DB in advance.

```shell
$ trivy image --download-java-db-only
2023-02-01T16:57:04.322+0900    INFO    Downloading the Java DB...
$ trivy image [YOUR_JAVA_IMAGE]
```

### Running in parallel takes same time as series run
When running trivy on multiple images simultaneously, it will take same time as running trivy in series.
This is because of a limitation of boltdb.
> Bolt obtains a file lock on the data file so multiple processes cannot open the same database at the same time. Opening an already open Bolt database will cause it to hang until the other process closes it.

Reference : [boltdb: Opening a database][boltdb].

[boltdb]: https://github.com/boltdb/bolt#opening-a-database

### Multiple Trivy servers

!!! error
    ```
    $ trivy image --server http://xxx.com:xxxx test-image
    ...
    - twirp error internal: failed scan, test-image: failed to apply layers: layer cache missing: sha256:*****
    ```
To run multiple Trivy servers, you need to use Redis as the cache backend so that those servers can share the cache. 
Follow [this instruction][redis-cache] to do so.


### Problems with `/tmp` on remote Git repository scans

!!! error
    FATAL repository scan error: scan error: unable to initialize a scanner: unable to initialize a filesystem scanner: git clone error: write /tmp/fanal-remote...

Trivy clones remote Git repositories under the `/tmp` directory before scanning them. If `/tmp` doesn't work for you, you can change it by setting the `TMPDIR` environment variable.

Try:

```
$ TMPDIR=/my/custom/path trivy repo ...
```

### Running out of space during image scans

!!! error
    ``` bash
    image scan failed:
    failed to copy the image:
    write /tmp/fanal-3323732142: no space left on device
    ```

Trivy uses the `/tmp` directory during image scan, if the image is large or `/tmp` is of insufficient size then the scan fails You can set the `TMPDIR` environment variable to use redirect trivy to use a directory with adequate storage.

Try:

```
$ TMPDIR=/my/custom/path trivy image ...
```

## DB
### Old DB schema

!!! error
    --skip-update cannot be specified with the old DB schema.

Trivy v0.23.0 or later requires Trivy DB v2. Please update your local database or follow [the instruction of air-gapped environment][air-gapped].

### Error downloading vulnerability DB

!!! error
    FATAL failed to download vulnerability DB

If trivy is running behind corporate firewall, you have to add the following urls to your allowlist.

- ghcr.io
- pkg-containers.githubusercontent.com

### Denied

!!! error
    GET https://ghcr.io/token?scope=repository%3Aaquasecurity%2Ftrivy-db%3Apull&service=ghcr.io: DENIED: denied

Your local GHCR (GitHub Container Registry) token might be expired.
Please remove the token and try downloading the DB again.

```shell
docker logout ghcr.io
```


## Homebrew
### Scope error
!!! error
    Error: Your macOS keychain GitHub credentials do not have sufficient scope!

```
$ brew tap aquasecurity/trivy
Error: Your macOS keychain GitHub credentials do not have sufficient scope!
Scopes they need: none
Scopes they have:
Create a personal access token:
https://github.com/settings/tokens/new?scopes=gist,public_repo&description=Homebrew
echo 'export HOMEBREW_GITHUB_API_TOKEN=your_token_here' >> ~/.zshrc
```

Try:

```
$ printf "protocol=https\nhost=github.com\n" | git credential-osxkeychain erase
```

### Already installed
!!! error
    Error: aquasecurity/trivy/trivy 64 already installed

```
$ brew upgrade
...
Error: aquasecurity/trivy/trivy 64 already installed
```

Try:

```
$ brew unlink trivy && brew uninstall trivy
($ rm -rf /usr/local/Cellar/trivy/64)
$ brew install aquasecurity/trivy/trivy
```


## Others
### Unknown error

Try again with `--reset` option:

```
$ trivy image --reset
```

[air-gapped]: ../advanced/air-gap.md
[redis-cache]: ../../vulnerability/examples/cache/#cache-backend
