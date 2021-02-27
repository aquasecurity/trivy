Replace [YOUR_CACHE_DIR] with the cache directory on your machine.

```
$ docker run --rm -v [YOUR_CACHE_DIR]:/root/.cache/ aquasec/trivy [YOUR_IMAGE_NAME]
```

Example for macOS:

```
$ docker run --rm -v $HOME/Library/Caches:/root/.cache/ aquasec/trivy python:3.4-alpine
```

If you would like to scan the image on your host machine, you need to mount `docker.sock`.

```
$ docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    -v $HOME/Library/Caches:/root/.cache/ aquasec/trivy python:3.4-alpine
```

Please re-pull latest `aquasec/trivy` if an error occurred.

<details>
<summary>Result</summary>

```
2019-05-16T01:20:43.180+0900    INFO    Updating vulnerability database...
2019-05-16T01:20:53.029+0900    INFO    Detecting Alpine vulnerabilities...

python:3.4-alpine3.9 (alpine 3.9.2)
===================================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

+---------+------------------+----------+-------------------+---------------+--------------------------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |             TITLE              |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
| openssl | CVE-2019-1543    | MEDIUM   | 1.1.1a-r1         | 1.1.1b-r1     | openssl: ChaCha20-Poly1305     |
|         |                  |          |                   |               | with long nonces               |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
```

</details>
