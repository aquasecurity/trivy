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
It is disabled by default and can be enabled with `--scanners misconfig`.
See [here](../scanner/misconfiguration/index.md) for the detail.

```shell
$ trivy repo --scanners misconfig (REPO_PATH | REPO_URL)
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

## Git Metadata
When scanning git repositories (both local and remote), Trivy automatically extracts and includes git metadata in the scan results.
This metadata provides context about the scanned repository.

The metadata includes information such as:

- Repository URL
- Branch name
- Tags
- Commit details (hash, message, committer)
- Author information

This feature works automatically for any git repository.
When using JSON format output, the git metadata will be included in the `Metadata` field.
For detailed information about the available fields, please refer to the JSON output of your scan results.

```bash
$ trivy repo --format json <repo-name>
```

## Scan Cache
When scanning git repositories, it stores analysis results in the cache, using the latest commit hash as the key.
Note that the cache is not used when the repository is dirty, otherwise Trivy will miss the files that are not committed.

More details are available in the [cache documentation](../configuration/cache.md#scan-cache-backend).

## References
The following flags and environmental variables are available for remote git repositories.

### Scanning a Branch

Pass a `--branch` argument with a valid branch name on the remote repository provided:

```
$ trivy repo --branch <branch-name> <repo-name>
```

### Scanning up to a Commit

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
In order to scan private repositories, set the environment variable matching the hosting platform with a valid token that has access to the private repository being scanned:

| Platform | Environment variable | Notes |
|---|---|---|
| GitHub (`github.com`) | `GITHUB_TOKEN` | Personal access token (classic or fine-grained) |
| GitLab (`gitlab.com` or self-hosted, host contains `gitlab`) | `GITLAB_TOKEN` | Personal access token |
| Bitbucket (`bitbucket.org` or self-hosted Bitbucket Server, host contains `bitbucket`) | `BITBUCKET_TOKEN` | Repository/workspace access token (default username `x-token-auth`) or app password (set `BITBUCKET_USERNAME` to your account username) |

The token is selected based on the repository host, so a private Bitbucket repository can be scanned by setting only `BITBUCKET_TOKEN`, even when `GITHUB_TOKEN`/`GITLAB_TOKEN` are also set. For any other (e.g. self-hosted) host, the tokens are tried in the order `GITHUB_TOKEN`, `GITLAB_TOKEN`, `BITBUCKET_TOKEN`.

You can find how to generate your GitHub token in the following [GitHub documentation](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token), your GitLab token in the [GitLab documentation](https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html), and your Bitbucket app password or repository access token in the [Bitbucket documentation](https://support.atlassian.com/bitbucket-cloud/docs/app-passwords/).

For example:

```
$ export GITHUB_TOKEN="your_private_github_token"
$ trivy repo <your private GitHub repo URL>

# or
$ export GITLAB_TOKEN="your_private_gitlab_token"
$ trivy repo <your private GitLab repo URL>

# or
$ export BITBUCKET_TOKEN="your_private_bitbucket_token"
$ trivy repo <your private Bitbucket repo URL>

# Bitbucket app password instead of an access token:
$ export BITBUCKET_USERNAME="your_bitbucket_username"
$ export BITBUCKET_TOKEN="your_bitbucket_app_password"
$ trivy repo <your private Bitbucket repo URL>
```
