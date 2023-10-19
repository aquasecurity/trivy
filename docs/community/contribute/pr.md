Thank you for taking interest in contributing to Trivy!

1. Every Pull Request should have an associated bug or feature issue unless you are fixing a trivial documentation issue.
1. Please add the associated Issue link in the PR description.
1. Your PR is more likely to be accepted if it focuses on just one change.
1. There's no need to add or tag reviewers.
1. If a reviewer commented on your code or asked for changes, please remember to respond with comment. Do not mark discussion as resolved. It's up to reviewer to mark it resolved (in case if suggested fix addresses problem properly). PRs with unresolved issues should not be merged (even if the comment is unclear or requires no action from your side).
1. Please include a comment with the results before and after your change.
1. Your PR is more likely to be accepted if it includes tests (We have not historically been very strict about tests, but we would like to improve this!).
1. If your PR affects the user experience in some way, please update the README.md and the CLI help accordingly.

## Development
Install the necessary tools for development by following their respective installation instructions.

- [Go](https://go.dev/doc/install)
- [Mage](https://magefile.org/)

### Build
After making changes to the Go source code, build the project with the following command:

```shell
$ mage build
$ ./trivy -h
```

### Lint
You must pass the linter checks:

```shell
$ mage lint:run
```

Additionally, you need to have run `go mod tidy`, so execute the following command as well:

```shell
$ mage tidy
```

To autofix linters use the following command:
```shell
$ mage lint:fix
```

### Unit tests
Your PR must pass all the unit tests. You can test it as below.

```
$ mage test:unit
```

### Integration tests
Your PR must pass all the integration tests. You can test it as below.

```
$ mage test:integration
```

### Documentation
If you update CLI flags, you need to generate the CLI references.
The test will fail if they are not up-to-date.

```shell
$ mage docs:generate
```

You can build the documents as below and view it at http://localhost:8000.

```
$ mage docs:serve
```

## Title
It is not that strict, but we use the title conventions in this repository.
Each commit message doesn't have to follow the conventions as long as it is clear and descriptive since it will be squashed and merged.

### Format of the title

```
<type>(<scope>): <subject>
```

The `type` and `scope` should always be lowercase as shown below.

**Allowed `<type>` values:**

- **feat** for a new feature for the user, not a new feature for build script. Such commit will trigger a release bumping a MINOR version.
- **fix** for a bug fix for the user, not a fix to a build script. Such commit will trigger a release bumping a PATCH version.
- **perf** for performance improvements. Such commit will trigger a release bumping a PATCH version.
- **docs** for changes to the documentation.
- **style** for formatting changes, missing semicolons, etc.
- **refactor** for refactoring production code, e.g. renaming a variable.
- **test** for adding missing tests, refactoring tests; no production code change.
- **build** for updating build configuration, development tools or other changes irrelevant to the user.
- **chore** for updates that do not apply to the above, such as dependency updates.
- **ci** for changes to CI configuration files and scripts
- **revert** for revert to a previous commit

**Allowed `<scope>` values:**

checks:

- vuln
- misconf
- secret
- license

mode:

- image
- fs
- repo
- sbom
- k8s
- server
- aws
- vm

os:

- alpine
- redhat
- alma
- rocky
- mariner
- oracle
- debian
- ubuntu
- amazon
- suse
- photon
- distroless

language:

- ruby
- php
- python
- nodejs
- rust
- dotnet
- java
- go
- elixir
- dart

vuln:

- os
- lang

config:

- kubernetes
- dockerfile
- terraform
- cloudformation

container

- docker
- podman
- containerd
- oci

cli:

- cli
- flag

SBOM:

- cyclonedx
- spdx
- purl

others:

- helm
- report
- db
- deps

The `<scope>` can be empty (e.g. if the change is a global or difficult to assign to a single component), in which case the parentheses are omitted.

### Example titles

```
feat(alma): add support for AlmaLinux
```

```
fix(oracle): handle advisories with ksplice versions
```

```
docs(misconf): add comparison with Conftest and TFsec
```

```
chore(deps): bump go.uber.org/zap from 1.19.1 to 1.20.0
```

**NOTE**: please do not use `chore(deps): update fanal` and something like that if you add new features or fix bugs in Trivy-related projects.
The PR title should describe what the PR adds or fixes even though it just updates the dependency in Trivy.

## Commits


## Understand where your pull request belongs

Trivy is composed of several repositories that work together:

- [Trivy](https://github.com/aquasecurity/trivy) is the client-side, user-facing, command line tool.
- [vuln-list](https://github.com/aquasecurity/vuln-list) is a vulnerability database, aggregated from different sources, and normalized for easy consumption. Think of this as the "server" side of the trivy command line tool. **There should be no pull requests to this repo**
- [vuln-list-update](https://github.com/aquasecurity/vuln-list-update) is the code that maintains the vuln-list database.
- [trivy-db](https://github.com/aquasecurity/trivy-db) maintains the vulnerability database pulled by Trivy CLI.
- [go-dep-parser](https://github.com/aquasecurity/go-dep-parser) is a library for parsing lock files such as package-lock.json and Gemfile.lock.
