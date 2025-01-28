# Code Repository

Scan local or remote code repositories which are managed by git.

`repo` is a pre-build target type, which means it scans package manager lock files. For more information, see [Target types](../coverage/language/index.md#target-types).

Usage:

```shell
trivy repo ~/dev/myapp
trivy repo ~/dev/myapp/Pipfile.lock
trivy repo https://github.com/aquasecurity/trivy
```

## Scanners

- Vulnerabilities
- Misconfigurations
- Secrets
- Licenses

By default, only vulnerability and secret scanning are enabled. You can configure which scanners are used with the [`--scanners` flag](https://trivy.dev/latest/docs/configuration/others/#enabledisable-scanners).

## Scan Cache
When scanning git repositories, it stores analysis results in the cache, using the latest commit hash as the key.
Note that the cache is not used when the repository is dirty, otherwise Trivy will miss the files that are not committed.

More details are available in the [cache documentation](../configuration/cache.md#scan-cache-backend).

## Scanning a Branch

Pass a `--branch` argument with a valid branch name on the remote repository provided:

```shell
trivy repo --branch <branch-name> <repo-name>
```

## Scanning upto a Commit

Pass a `--commit` argument with a valid commit hash on the remote repository provided:

```shell
trivy repo --commit <commit-hash> <repo-name>
```

## Scanning a Tag

Pass a `--tag` argument with a valid tag on the remote repository provided:

```shell
trivy repo --tag <tag-name> <repo-name>
```

## Scanning Private Repositories
In order to scan private GitHub or GitLab repositories, the environment variable `GITHUB_TOKEN` or `GITLAB_TOKEN` must be set, respectively, with a valid token that has access to the private repository being scanned.

The `GITHUB_TOKEN` environment variable will take precedence over `GITLAB_TOKEN`, so if a private GitLab repository will be scanned, then `GITHUB_TOKEN` must be unset.

You can find how to generate your GitHub Token in the following [GitHub documentation.](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)

For example:

```bash
$ export GITHUB_TOKEN="your_private_github_token"
$ trivy repo <your private GitHub repo URL>

# or
$ export GITLAB_TOKEN="your_private_gitlab_token"
$ trivy repo <your private GitLab repo URL>
```
