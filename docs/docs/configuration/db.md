# DB

|     Scanner      | Supported |
|:----------------:|:---------:|
|  Vulnerability   |     ✓     |
| Misconfiguration |           |
|      Secret      |           |
|     License      |           |

The vulnerability database and the Java index database are needed only for vulnerability scanning.
See [here](../scanner/vulnerability.md) for the detail.

## Vulnerability Database

### Skip update of vulnerability DB
If you want to skip downloading the vulnerability database, use the `--skip-db-update` option.

```
$ trivy image --skip-db-update python:3.4-alpine3.9
```

<details>
<summary>Result</summary>

```
2019-05-16T12:48:08.703+0900    INFO    Detecting Alpine vulnerabilities...

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

### Only download vulnerability database
You can also ask `Trivy` to simply retrieve the vulnerability database.
This is useful to initialize workers in Continuous Integration systems.

```
$ trivy image --download-db-only
```

### DB Repository
`Trivy` could also download the vulnerability database from an external OCI registry by using `--db-repository` option.

```
$ trivy image --db-repository registry.gitlab.com/gitlab-org/security-products/dependencies/trivy-db
```

## Java Index Database
The same options are also available for the Java index DB, which is used for scanning Java applications.
Skipping an update can be done by using the `--skip-java-db-update` option, while `--download-java-db-only` can be used to only download the Java index DB.

Downloading the Java index DB from an external OCI registry can be done by using the `--java-db-repository` option.

```
$ trivy image --java-db-repository registry.gitlab.com/gitlab-org/security-products/dependencies/trivy-java-db --download-java-db-only
```

!!! Note
    In [Client/Server](../references/modes/client-server.md) mode, `Java index DB` is currently only used on the `client` side.

## Remove DBs
The `--reset` flag removes all caches and databases.

```
$ trivy image --reset
```