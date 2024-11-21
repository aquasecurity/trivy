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

The media type of the OCI layer must be `application/vnd.aquasec.trivy.db.layer.v1.tar+gzip`.
You can reference the OCI manifest of [trivy-db].

<details>
<summary>Manifest</summary>

```shell
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.aquasec.trivy.config.v1+json",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2
  },
  "layers": [
    {
      "mediaType": "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip",
      "digest": "sha256:29ad6505b8957c7cd4c367e7c705c641a9020d2be256812c5f4cc2fc099f4f02",
      "size": 55474933,
      "annotations": {
        "org.opencontainers.image.title": "db.tar.gz"
      }
    }
  ],
  "annotations": {
    "org.opencontainers.image.created": "2024-09-11T06:14:51Z"
  }
}
```
</details>

!!!note
    Trivy automatically adds the `trivy-db` schema version as a tag if the tag is not used:

    `trivy-db-registry:latest` => `trivy-db-registry:latest`, but `trivy-db-registry` => `trivy-db-registry:2`.


### Rate limits
Trivy hosts its databases on public OCI registries that are subject to their respective rate limits. While we strive to make the databases available to every
Trivy user, there are certain recommendations that one can make in order to ensure rate limits are not hit.

#### Authenticated use of Registries
By authenticating with the registries that Trivy hosts its DBs on can significantly increase the limit for users. For Amazon ECR, the details for rate limits can be found [ecr-limits].

Please see more info on how to authenticate with ECR [auth-ecr].

#### Caching DBs
Trivy DB and Trivy Java DB are published every 6 hours and 24 hours, respectively. If you are running Trivy scans more often than this, you can significantly benefit from caching the DBs on each run and updating them as needed.
One example of this can be seen in Trivy Action, where with caching multiple CI invocations can be performed with a single download of the DBs. More on info Trivy Action caching can be found [trivy-action-cache].

## Java Index Database
The same options are also available for the Java index DB, which is used for scanning Java applications.
Skipping an update can be done by using the `--skip-java-db-update` option, while `--download-java-db-only` can be used to only download the Java index DB.

!!! Note
    In [Client/Server](../references/modes/client-server.md) mode, `Java index DB` is currently only used on the `client` side.

Downloading the Java index DB from an external OCI registry can be done by using the `--java-db-repository` option.

```
$ trivy image --java-db-repository registry.gitlab.com/gitlab-org/security-products/dependencies/trivy-java-db --download-java-db-only
```

The media type of the OCI layer must be `application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip`.
You can reference the OCI manifest of [trivy-java-db].

!!!note
    Trivy automatically adds the `trivy-java-db` schema version as a tag if the tag is not used:

    `java-db-registry:latest` => `java-db-registry:latest`, but `java-db-registry` => `java-db-registry:1`.

## Remove DBs
"trivy clean" command removes caches and databases.

```
$ trivy clean --vuln-db --java-db
2024-06-24T11:42:31+06:00       INFO    Removing vulnerability database...
2024-06-24T11:42:31+06:00       INFO    Removing Java database...
```

[trivy-db]: https://github.com/aquasecurity/trivy-db/pkgs/container/trivy-db
[trivy-java-db]: https://github.com/aquasecurity/trivy-java-db/pkgs/container/trivy-java-db
[ecr-limits]: https://docs.aws.amazon.com/AmazonECR/latest/public/public-service-quotas.html
[auth-ecr]: https://aws.amazon.com/blogs/compute/authenticating-amazon-ecr-repositories-for-docker-cli-with-credential-helper/
[trivy-action-cache]: https://github.com/aquasecurity/trivy-action?tab=readme-ov-file#cache