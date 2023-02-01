# Filesystem

Scan your local projects for

- Vulnerabilities
- Misconfigurations
- Secrets
- Licenses
 
By default, vulnerability and secret scanning are enabled, and you can configure that with `--scanners`.

```bash
$ trivy fs /path/to/project
```

It's also possible to scan a single file.

```
$ trivy fs ~/src/github.com/aquasecurity/trivy-ci-test/Pipfile.lock
```

## Scanners
### Vulnerabilities
It is enabled by default.
Trivy will look for vulnerabilities based on lock files such as Gemfile.lock and package-lock.json.
See [here](../vulnerability/scanning.md) for the detail.

```
$ trivy fs ~/src/github.com/aquasecurity/trivy-ci-test
```

<details>
<summary>Result</summary>

```
2020-06-01T17:06:58.652+0300    WARN    OS is not detected and vulnerabilities in OS packages are not detected.
2020-06-01T17:06:58.652+0300    INFO    Detecting pipenv vulnerabilities...
2020-06-01T17:06:58.691+0300    INFO    Detecting cargo vulnerabilities...

Pipfile.lock
============
Total: 10 (UNKNOWN: 2, LOW: 0, MEDIUM: 6, HIGH: 2, CRITICAL: 0)

+---------------------+------------------+----------+-------------------+------------------------+------------------------------------+
|       LIBRARY       | VULNERABILITY ID | SEVERITY | INSTALLED VERSION |     FIXED VERSION      |               TITLE                |
+---------------------+------------------+----------+-------------------+------------------------+------------------------------------+
| django              | CVE-2020-7471    | HIGH     | 2.0.9             | 3.0.3, 2.2.10, 1.11.28 | django: potential                  |
|                     |                  |          |                   |                        | SQL injection via                  |
|                     |                  |          |                   |                        | StringAgg(delimiter)               |
+                     +------------------+----------+                   +------------------------+------------------------------------+
|                     | CVE-2019-19844   | MEDIUM   |                   | 3.0.1, 2.2.9, 1.11.27  | Django: crafted email address      |
|                     |                  |          |                   |                        | allows account takeover            |
+                     +------------------+          +                   +------------------------+------------------------------------+
|                     | CVE-2019-3498    |          |                   | 2.1.5, 2.0.10, 1.11.18 | python-django: Content             |
|                     |                  |          |                   |                        | spoofing via URL path in           |
|                     |                  |          |                   |                        | default 404 page                   |
+                     +------------------+          +                   +------------------------+------------------------------------+
|                     | CVE-2019-6975    |          |                   | 2.1.6, 2.0.11, 1.11.19 | python-django:                     |
|                     |                  |          |                   |                        | memory exhaustion in               |
|                     |                  |          |                   |                        | django.utils.numberformat.format() |
+---------------------+------------------+----------+-------------------+------------------------+------------------------------------+
...
```

</details>

### Misconfigurations
It is disabled by default and can be enabled with `--scanners config`.
See [here](../misconfiguration/scanning.md) for the detail.

```shell
$ trivy fs --scanners config /path/to/project
```

### Secrets
It is enabled by default.
See [here](../secret/scanning.md) for the detail.

```shell
$ trivy fs /path/to/project
```

### Licenses
It is disabled by default.
See [here](../licenses/scanning.md) for the detail.

```shell
$ trivy fs --scanners license /path/to/project
```

## SBOM generation
Trivy can generate SBOM for local projects.
See [here](../sbom/index.md) for the detail.
