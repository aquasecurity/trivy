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

### Maven rate limiting / inconsistent jar vulnerability reporting

!!! error
    ``` bash
    $ trivy image ...
    ...
    status 403 Forbidden from http://search.maven.org/solrsearch/select
    ```

Trivy calls Maven API for better detection of JAR files, but many requests may exceed rate limiting.
This can easily happen if you are running more than one instance of Trivy which is concurrently scanning multiple images.
Once this starts happening Trivy's vulnerability reporting on jar files may become inconsistent.
There are two options to resolve this issue:

The first is to enable offline scanning using the `--offline-scan` option to stop Trivy from making API requests.
This option affects only vulnerability scanning. The vulnerability database and builtin policies are downloaded as usual.
If you want to skip them as well, you can try `--skip-update` and `--skip-policy-update`.
**Note that a number of vulnerabilities might be fewer than without the `--offline-scan` option.**

The second, more scalable, option is to place Trivy behind a rate-limiting forward-proxy to the Maven Central API.
One way to achieve this is to use nginx. You can use the following nginx config to enable both rate-limiting and caching (the caching greatly reduces the number of calls to the Maven Central API, especially if you are scanning a lot of similar images):

```nginx
limit_req_zone global zone=maven:1m rate=10r/s;
proxy_cache_path /tmp/cache keys_zone=mavencache:10m;

server {
  listen 80;
  proxy_cache mavencache;

  location / {
    limit_req zone=maven burst=1000;
    proxy_cache_valid any 1h;
    proxy_pass https://search.maven.org:443;
  }
}
```

This config file will allow a maximum of 10 requests per second to the Maven API, this number was determined experimentally so you might want to use something else if it doesn't fit your needs.

Once nginx is up and running, you need to tell all your Trivy deployments to proxy their Maven API calls through nginx. You can do this by setting the `MAVEN_CENTRAL_URL` environment variable. For example, if your nginx proxy is running at `127.0.0.1`, you can set `MAVEN_CENTRAL_URL=http://127.0.0.1/solrsearch/select`.


### Running in parallel takes same time as series run
When running trivy on multiple images simultaneously, it will take same time as running trivy in series.
This is because of a limitation of boltdb.
> Bolt obtains a file lock on the data file so multiple processes cannot open the same database at the same time. Opening an already open Bolt database will cause it to hang until the other process closes it.

Reference : [boltdb: Opening a database][boltdb].

[boltdb]: https://github.com/boltdb/bolt#opening-a-database

### Error downloading vulnerability DB

!!! error
    FATAL failed to download vulnerability DB

If trivy is running behind corporate firewall, you have to add the following urls to your allowlist.

- ghcr.io
- pkg-containers.githubusercontent.com

### Old DB schema

!!! error
    --skip-update cannot be specified with the old DB schema.

Trivy v0.23.0 or later requires Trivy DB v2. Please update your local database or follow [the instruction of air-gapped environment][air-gapped].

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
