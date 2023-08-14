# Air-Gapped Environment

Trivy can be used in air-gapped environments. Note that an allowlist is [here][allowlist].

## Air-Gapped Environment for vulnerabilities

### Download the vulnerability database
At first, you need to download the vulnerability database for use in air-gapped environments.

=== "Trivy"

    ```
    TRIVY_TEMP_DIR=$(mktemp -d)
    trivy --cache-dir $TRIVY_TEMP_DIR image --download-db-only
    tar -cf ./db.tar.gz -C $TRIVY_TEMP_DIR/db metadata.json trivy.db
    rm -rf $TRIVY_TEMP_DIR
    ```

=== "oras >= v0.13.0"
    Please follow [oras installation instruction][oras].

    Download `db.tar.gz`:

    ```
    $ oras pull ghcr.io/aquasecurity/trivy-db:2
    ```

=== "oras < v0.13.0"
    Please follow [oras installation instruction][oras].

    Download `db.tar.gz`:

    ```
    $ oras pull -a ghcr.io/aquasecurity/trivy-db:2
    ```

### Download the Java index database[^1]
Java users also need to download the Java index database for use in air-gapped environments.

!!! note
    You container image may contain JAR files even though you don't use Java directly.
    In that case, you also need to download the Java index database.

=== "Trivy"

    ```
    TRIVY_TEMP_DIR=$(mktemp -d)
    trivy --cache-dir $TRIVY_TEMP_DIR image --download-java-db-only
    tar -cf ./javadb.tar.gz -C $TRIVY_TEMP_DIR/java-db metadata.json trivy-java.db
    rm -rf $TRIVY_TEMP_DIR
    ```
=== "oras >= v0.13.0"
    Please follow [oras installation instruction][oras].

    Download `javadb.tar.gz`:

    ```
    $ oras pull ghcr.io/aquasecurity/trivy-java-db:1
    ```

=== "oras < v0.13.0"
    Please follow [oras installation instruction][oras].

    Download `javadb.tar.gz`:

    ```
    $ oras pull -a ghcr.io/aquasecurity/trivy-java-db:1
    ```


### Transfer the DB files into the air-gapped environment
The way of transfer depends on the environment.

=== "Vulnerability db"
    ```
    $ rsync -av -e ssh /path/to/db.tar.gz [user]@[host]:dst
    ```

=== "Java index db[^1]"
    ```
    $ rsync -av -e ssh /path/to/javadb.tar.gz [user]@[host]:dst
    ```

### Put the DB files in Trivy's cache directory
You have to know where to put the DB files. The following command shows the default cache directory.

```
$ ssh user@host
$ trivy -h | grep cache
   --cache-dir value  cache directory (default: "/home/myuser/.cache/trivy") [$TRIVY_CACHE_DIR]
```
=== "Vulnerability db"
    Put the DB file in the cache directory + `/db`.
    
    ```
    $ mkdir -p /home/myuser/.cache/trivy/db
    $ cd /home/myuser/.cache/trivy/db
    $ tar xvf /path/to/db.tar.gz -C /home/myuser/.cache/trivy/db
    x trivy.db
    x metadata.json
    $ rm /path/to/db.tar.gz
    ```

=== "Java index db[^1]"
    Put the DB file in the cache directory + `/java-db`.

    ```
    $ mkdir -p /home/myuser/.cache/trivy/java-db
    $ cd /home/myuser/.cache/trivy/java-db
    $ tar xvf /path/to/javadb.tar.gz -C /home/myuser/.cache/trivy/java-db
    x trivy-java.db
    x metadata.json
    $ rm /path/to/javadb.tar.gz
    ```



In an air-gapped environment it is your responsibility to update the Trivy databases on a regular basis, so that the scanner can detect recently-identified vulnerabilities. 

### Run Trivy with the specific flags.
In an air-gapped environment, you have to specify `--skip-db-update` and `--skip-java-db-update`[^1] so that Trivy doesn't attempt to download the latest database files.
In addition, if you want to scan `pom.xml` dependencies, you need to specify `--offline-scan` since Trivy tries to issue API requests for scanning Java applications by default.

```
$ trivy image --skip-db-update --skip-java-db-update --offline-scan alpine:3.12
```

## Air-Gapped Environment for misconfigurations

No special measures are required to detect misconfigurations in an air-gapped environment.

### Run Trivy with `--skip-policy-update` option
In an air-gapped environment, specify `--skip-policy-update` so that Trivy doesn't attempt to download the latest misconfiguration policies.

```
$ trivy conf --skip-policy-update /path/to/conf
```

[allowlist]: ../references/troubleshooting.md
[oras]: https://oras.land/cli/

[^1]: This is only required to scan `jar` files. More information about `Java index db` [here](../coverage/language/java.md)
