# Air-Gapped Environment

Trivy can be used in air-gapped environments.

## Download the vulnerability database
At first, you need to download the vulnerability database for use in air-gapped environments.
Go to [trivy-db][trivy-db] and download `trivy-offline.db.tgz` in the latest release.
If you download `trivy-light-offline.db.tgz`, you have to run Trivy with `--light` option.

```
$ wget https://github.com/aquasecurity/trivy-db/releases/latest/download/trivy-offline.db.tgz
```

## Transfer the DB file into the air-gapped environment
The way of transfer depends on the environment.

```
$ rsync -av -e ssh /path/to/trivy-offline.db.tgz [user]@[host]:dst
```

## Put the DB file in Trivy's cache directory
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
$ mv /path/to/trivy-offline.db.tgz .
```

Then, decompress it.
`trivy-offline.db.tgz` file includes two files, `trivy.db` and `metadata.json`.

```
$ tar xvf trivy-offline.db.tgz
x trivy.db
x metadata.json
$ rm trivy-offline.db.tgz
```

In an air-gapped environment it is your responsibility to update the Trivy database on a regular basis, so that the scanner can detect recently-identified vulnerabilities. 

## Run Trivy with --skip-update option
In an air-gapped environment, specify `--skip-update` so that Trivy doesn't attempt to download the latest database file.

```
$ trivy image --skip-update alpine:3.12
```

[trivy-db]: https://github.com/aquasecurity/trivy-db/releases
