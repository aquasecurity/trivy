# Code Repository

Scan your local or remote code repositories for

- Vulnerabilities
- Misconfigurations
- Secrets
- Licenses

By default, vulnerability and secret scanning are enabled, and you can configure that with `--scanners`.

```bash
$ trivy repo (REPO_PATH | REPO_URL)
```

For example, you can scan a local repository as below.

```bash
$ trivy repo ./
```

It's also possible to scan a single file.

```
$ trivy repo ./trivy-ci-test/Pipfile.lock
```

To scan remote code repositories, you need to specify the URL.

```bash
$ trivy repo https://github.com/aquasecurity/trivy-ci-test
```

## Rationale
`trivy repo` is  designed to scan code repositories, and it is intended to be used for scanning local/remote repositories in your machine or in your CI environment.
Therefore, unlike container/VM image scanning, it targets lock files such as package-lock.json and does not target artifacts like JAR files, binary files, etc.
See [here](../scanner/vulnerability.md#language-specific-packages) for the detail.

## Scanners
### Vulnerabilities
It is enabled by default.
Trivy will look for vulnerabilities based on lock files such as Gemfile.lock and package-lock.json.
See [here](../scanner/vulnerability.md) for the detail.

```
$ trivy repo ~/src/github.com/aquasecurity/trivy-ci-test
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
See [here](../scanner/misconfiguration/index.md) for the detail.

```shell
$ trivy repo --scanners config (REPO_PATH | REPO_URL)
```

### Secrets
It is enabled by default.
See [here](../scanner/secret.md) for the detail.

```shell
$ trivy repo (REPO_PATH | REPO_URL)
```

### Licenses
It is disabled by default.
See [here](../scanner/license.md) for the detail.

```shell
$ trivy repo --scanners license (REPO_PATH | REPO_URL)
```

## SBOM generation
Trivy can generate SBOM for code repositories.
See [here](../supply-chain/sbom.md) for the detail.

## References
The following flags and environmental variables are available for remote git repositories.

### Scanning a Branch

Pass a `--branch` argument with a valid branch name on the remote repository provided:

```
$ trivy repo --branch <branch-name> <repo-name>
```

### Scanning upto a Commit

Pass a `--commit` argument with a valid commit hash on the remote repository provided:

```
$ trivy repo --commit <commit-hash> <repo-name>
```

### Scanning a Tag

Pass a `--tag` argument with a valid tag on the remote repository provided:

```
$ trivy repo --tag <tag-name> <repo-name>
```

### Scanning Private Repositories
In order to scan private GitHub or GitLab repositories, the environment variable `GITHUB_TOKEN` or `GITLAB_TOKEN` must be set, respectively, with a valid token that has access to the private repository being scanned.

The `GITHUB_TOKEN` environment variable will take precedence over `GITLAB_TOKEN`, so if a private GitLab repository will be scanned, then `GITHUB_TOKEN` must be unset.

You can find how to generate your GitHub Token in the following [GitHub documentation.](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)

For example:

```
$ export GITHUB_TOKEN="your_private_github_token"
$ trivy repo <your private GitHub repo URL>

# or
$ export GITLAB_TOKEN="your_private_gitlab_token"
$ trivy repo <your private GitLab repo URL>
```
