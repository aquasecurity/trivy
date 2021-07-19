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

### Running in parallel takes same time as series run
When running trivy on multiple images simultaneously, it will take same time as running trivy in series.  
This is because of a limitation of boltdb.
> Bolt obtains a file lock on the data file so multiple processes cannot open the same database at the same time. Opening an already open Bolt database will cause it to hang until the other process closes it.

Reference : [boltdb: Opening a database][boltdb].

[boltdb]: https://github.com/boltdb/bolt#opening-a-database

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
