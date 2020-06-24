# Air-gapped environment
Trivy can be used under air-gapped environment.

## Download the vulnerability database
At first, you need to download the vulnerability database for air-gapped environment.
Go to [trivy-db](https://github.com/aquasecurity/trivy-db/releases) and download `trivy-offline.db.tgz` in the latest release.
If you download `trivy-light-offline.db.tgz`, you have to run Trivy with `--light` option.

```
$ wget https://github.com/aquasecurity/trivy-db/releases/latest/download/trivy-offline.db.tgz
```


## Transfer the DB file into the air-gapped environment
The way of transfer depends on the environment.

```
$ rsync -av -e ssh /path/to/trivy-offline.db.tgz [user]@[host]:dst
```

## Put the DB file to Trivy's cache directory
You have to know where to put the DB file. The following command shows the default cache directory.

```
$ ssh user@host
$ trivy -h | grep cache
   --cache-dir value  cache directory (default: "/home/myuser/.cache/trivy") [$TRIVY_CACHE_DIR]
```

Put the DB file to the cache directory + `/db`.

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

## Run Trivy with --skip-update option
Trivy automatically downloads the latest database file if you don't specify `--skip-update`.

```
$ trivy image --skip-update alpine:3.12
```
