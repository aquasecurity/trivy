# Air-Gapped Environment

Trivy can be used in air-gapped environments. Note that an allowlist is [here][allowlist].

## Air-Gapped Environment for vulnerabilities

### Download the vulnerability database
At first, you need to download the vulnerability database for use in air-gapped environments.
Please follow [oras installation instruction][oras].

Download `db.tar.gz`:

```
$ oras pull ghcr.io/aquasecurity/trivy-db:2 -a
```

### Transfer the DB file into the air-gapped environment
The way of transfer depends on the environment.

```
$ rsync -av -e ssh /path/to/db.tar.gz [user]@[host]:dst
```

### Put the DB file in Trivy's cache directory
You have to know where to put the DB file. The following command shows the default cache directory.

```
$ ssh user@host
$ trivy -h | grep cache
   --cache-dir value  cache directory (default: "/home/myuser/.cache/trivy") [$TRIVY_CACHE_DIR]
```

Put the DB file in the cache directory + `/db`.

```
$ mkdir -p /home/myuser/.cache/trivy/db
$ cd /home/myuser/.cache/trivy/db
$ tar xvf /path/to/db.tar.gz -C /home/myuser/.cache/trivy/db
x trivy.db
x metadata.json
$ rm /path/to/db.tar.gz
```

In an air-gapped environment it is your responsibility to update the Trivy database on a regular basis, so that the scanner can detect recently-identified vulnerabilities. 

### Run Trivy with --skip-update and --offline-scan option
In an air-gapped environment, specify `--skip-update` so that Trivy doesn't attempt to download the latest database file.
In addition, if you want to scan Java dependencies such as JAR and pom.xml, you need to specify `--offline-scan` since Trivy tries to issue API requests for scanning Java applications by default.

```
$ trivy image --skip-update --offline-scan alpine:3.12
```

## Air-Gapped Environment for misconfigurations

### Download misconfiguration policies
At first, you need to download misconfiguration policies for use in air-gapped environments.
Please follow [oras installation instruction][oras].

Download `bundle.tar.gz`:

```
$ oras pull ghcr.io/aquasecurity/appshield:latest -a
```

### Transfer misconfiguration policies into the air-gapped environment
The way of transfer depends on the environment.

```
$ rsync -av -e ssh /path/to/bundle.tar.gz [user]@[host]:dst
```

### Put the misconfiguration policies in Trivy's cache directory
You have to know where to put the misconfiguration policies file. The following command shows the default cache directory.

```
$ ssh user@host
$ trivy -h | grep cache
   --cache-dir value  cache directory (default: "/home/myuser/.cache/trivy") [$TRIVY_CACHE_DIR]
```

Put the misconfiguration policies file in the cache directory + `/policy/content`.

```
$ mkdir -p /home/myuser/.cache/trivy/policy/content
$ cd /home/myuser/.cache/trivy/policy/content
$ mv /path/to/bundle.tar.gz .
```

Then, decompress it.
`bundle.tar.gz ` file includes two folders: `docker`, `kubernetes` and file: `.manifest`.

```
$ tar xvf bundle.tar.gz 
x ./docker/
...
x ./kubernetes/
...
x ./.manifest
$ rm bundle.tar.gz
```

In an air-gapped environment it is your responsibility to update policies on a regular basis, so that the scanner can detect recently-identified misconfigurations. 

### Run Trivy with --skip-policy-update option
In an air-gapped environment, specify `--skip-policy-update` so that Trivy doesn't attempt to download the latest misconfiguration policies.

```
$ trivy conf --skip-policy-update /path/to/conf
```

[allowlist]: ../getting-started/troubleshooting.md
[oras]: https://oras.land/cli/
