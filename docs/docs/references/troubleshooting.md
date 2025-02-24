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

### Unable to initialize an image scanner

!!! error
    ```bash
    $ trivy image ...
    ...
    2024-01-19T08:15:33.288Z	FATAL	image scan error: scan error: unable to initialize a scanner: unable to initialize an image scanner: 4 errors occurred:
	* docker error: unable to inspect the image (ContainerImageName): Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
	* containerd error: containerd socket not found: /run/containerd/containerd.sock
	* podman error: unable to initialize Podman client: no podman socket found: stat podman/podman.sock: no such file or directory
	* remote error: GET https://index.docker.io/v2/ContainerImageName: MANIFEST_UNKNOWN: manifest unknown; unknown tag=0.1
    ```
    
It means Trivy is unable to find the container image in the following places:

* Docker Engine
* containerd
* Podman
* A remote registry

Please see error messages for details of each error.

Common mistakes include the following, depending on where you are pulling images from:

#### Common
- Typos in the image name
    - Common mistake :)
- Forgetting to specify the registry
    - By default, it is considered to be Docker Hub ( `index.docker.io` ).

#### Docker Engine
- Incorrect Docker host
    - If the Docker daemon's socket path is not `/var/run/docker.sock`, you need to specify the `--docker-host` flag or the `DOCKER_HOST` environment variable.
      The same applies when using TCP; you must specify the correct host address.

#### containerd
- Incorrect containerd address
    - If you are using a non-default path, you need to specify the `CONTAINERD_ADDRESS` environment variable.
      Please refer to [this documentation](../target/container_image.md#containerd).
- Incorrect namespace
    - If you are using a non-default namespace, you need to specify the `CONTAINERD_NAMESPACE` environment variable.
      Please refer to [this documentation](../target/container_image.md#containerd).
    - 
#### Podman
- Podman socket configuration
    - You need to enable the Podman socket. Please refer to [this documentation](../target/container_image.md#podman).

#### Container Registry
- Unauthenticated
    - If you are using a private container registry, you need to authenticate. Please refer to [this documentation](../advanced/private-registries/index.md).
- Using a proxy
    - If you are using a proxy within your network, you need to correctly set the `HTTP_PROXY`, `HTTPS_PROXY`, etc., environment variables.
- Use of a self-signed certificate in the registry
    - Because certificate verification will fail, you need to either trust that certificate or use the `--insecure` flag (not recommended in production).

### Certification

!!! error
    Error: x509: certificate signed by unknown authority

`TRIVY_INSECURE` can be used to allow insecure connections to a container registry when using SSL.

```
$ TRIVY_INSECURE=true trivy image [YOUR_IMAGE]
```

### GitHub Rate limiting
Trivy uses GitHub API for [VEX repositories](../supply-chain/vex/repo.md).

!!! error
    ``` bash
    $ trivy image --vex repo ...
    ...
    API rate limit exceeded for xxx.xxx.xxx.xxx.
    ```

Specify GITHUB_TOKEN for [authentication](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28)

```
$ GITHUB_TOKEN=XXXXXXXXXX trivy image --vex repo [YOUR_IMAGE]
```

!!! note
    `GITHUB_TOKEN` doesn't help with the rate limit for the vulnerability database and other assets.
    See https://github.com/aquasecurity/trivy/discussions/8009

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

Trivy uses a temporary directory during image scans.
The directory path would be determined as follows:

- On Unix systems: Use `$TMPDIR` if non-empty, else `/tmp`.
- On Windows: Uses GetTempPath, returning the first non-empty value from `%TMP%`, `%TEMP%`, `%USERPROFILE%`, or the Windows directory.

See [this documentation](https://golang.org/pkg/os/#TempDir) for more details.

If the image is large or the temporary directory has insufficient space, the scan will fail.
You can configure the directory path to redirect Trivy to a directory with adequate storage.
On Unix systems, you can set the `$TMPDIR` environment variable.

```
$ TMPDIR=/my/custom/path trivy image ...
```

When scanning images from a container registry, Trivy processes each layer by streaming, loading only the necessary files for the scan into memory and discarding unnecessary files.
If a layer contains large files that are necessary for the scan (such as JAR files or binary files), Trivy saves them to a temporary directory (e.g. $TMPDIR) on local storage to avoid increased memory consumption.
Although these files are deleted after the scan is complete, they can temporarily increase disk consumption and potentially exhaust storage.
In such cases, there are currently three workarounds:

1. Use a temporary directory with sufficient capacity
 
    This is the same as explained above.
 
2. Specify a small value for `--parallel`
 
    By default, multiple layers are processed in parallel.
    If each layer contains large files, disk space may be consumed rapidly.
    By specifying a small value such as `--parallel 1`, parallelism is reduced, which can mitigate the issue.

3. Specify `--skip-files` or `--skip-dirs`
 
    If the container image contains large files that do not need to be scanned, you can skip their processing by specifying --skip-files or --skip-dirs. 
    For more details, please refer to [this documentation](../configuration/skipping.md).

## DB
### Old DB schema

!!! error
    --skip-update cannot be specified with the old DB schema.

Trivy v0.23.0 or later requires Trivy DB v2. Please update your local database or follow [the instruction of air-gapped environment][air-gapped].

### Error downloading vulnerability DB

!!! error
    FATAL failed to download vulnerability DB

If Trivy is running behind corporate firewall, refer to the necessary connectivity requirements as described [here][network].

### Denied

!!! error
    GET https://ghcr.io/token?scope=repository%3Aaquasecurity%2Ftrivy-db%3Apull&service=ghcr.io: DENIED: denied

Your local GHCR (GitHub Container Registry) token might be expired.
Please remove the token and try downloading the DB again.

```shell
docker logout ghcr.io
```

or

```shell
unset GITHUB_TOKEN
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

Try again after running `trivy clean --all`:

```
$ trivy clean --all
```

[air-gapped]: ../advanced/air-gap.md
[network]: ../advanced/air-gap.md#network-requirements
[redis-cache]: ../configuration/cache.md#redis
