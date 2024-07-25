# VEX Repository

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

## Using VEX Repository

Trivy can download and utilize VEX documents from repositories that comply with [the VEX Repository Specification][vex-repo].
While it's planned to be enabled by default in the future, currently it can be activated by explicitly specifying `--vex repo`.

```
$ trivy image ghcr.io/aquasecurity/trivy:0.52.0 --vex repo
2024-07-20T11:22:58+04:00       INFO    [vex] The default repository config has been created    
file_path="/Users/teppei/.trivy/vex/repository.yaml"
2024-07-20T11:23:23+04:00       INFO    [vex] Updating repository...    repo="default" url="https://github.com/aquasecurity/vexhub"
```

During scanning, Trivy generates PURLs for discovered packages and searches for matching PURLs in the VEX Repository.
If a match is found, the corresponding VEX is utilized.

### Configuration File

#### Default Configuration

When `--vex repo` is specified for the first time, a default configuration file is created at `$HOME/.trivy/vex/repository.yaml`.
The home directory can be configured through environment variable `$XDG_DATA_HOME`.

You can also create the configuration file in advance using the `trivy vex repo init` command and edit it.

The default configuration file looks like this:

```yaml
repositories:
  - name: default
    url: https://github.com/aquasecurity/vexhub
    enabled: true
    username: ""
    password: ""
    token: ""
```

By default, [VEX Hub][vexhub] managed by Aqua Security is used.
VEX Hub primarily trusts VEX documents published by the package maintainers.

#### Show Configuration
You can see the config file path and the configured repositories with `trivy vex repo list`:

```bash
$ trivy vex repo list
VEX Repositories (config: /home/username/.trivy/vex/repository.yaml)

- Name: default
  URL: https://github.com/aquasecurity/vexhub
  Status: Enabled
```

#### Custom Repositories

If you want to trust VEX documents published by other organizations or use your own VEX repository, you can specify a custom repository that complies with [the VEX Repository Specification][vex-repo].
You can add a custom repository as below:

```yaml
- name: custom
  url: https://example.com/custom-repo
  enabled: true
```


#### Authentication

For private repositories:

- `username`/`password` can be used for Basic authentication
- `token` can be used for Bearer authentication

```yaml
- name: custom
  url: https://example.com/custom-repo
  enabled: true
  token: "my-token"
```

#### Repository Priority

The priority of VEX repositories is determined by their order in the configuration file.
You can add repositories with higher priority than the default or even remove the default VEX Hub.

```yaml
- name: repo1
  url: https://example.com/repo1
- name: repo2
  url: https://example.com/repo2
```

In this configuration, when Trivy detects a vulnerability in a package, it generates a PURL for that package and searches for matching VEX documents in the configured repositories.
The search process follows this order:

1. Trivy first looks for a VEX document matching the package's PURL in `repo1`.
2. If no matching VEX document is found in `repo1`, Trivy then searches in `repo2`.
3. This process continues through all configured repositories until a match is found.
 
If a matching VEX document is found in any repository (e.g., `repo1`), the search stops, and Trivy uses that VEX document.
Subsequent repositories (e.g., `repo2`) are not checked for that specific vulnerability and package combination.

It's important to note that the first matching VEX document found determines the final status of the vulnerability.
For example, if `repo1` states that a package is "Affected" by a vulnerability, this status will be used even if `repo2` states that the same package is "Not Affected" for the same vulnerability.
The "Affected" status from the higher-priority repository (`repo1`) takes precedence, and Trivy will consider the package as affected by the vulnerability.

### Repository Updates

VEX repositories are automatically updated during scanning.
Updates are performed based on the update frequency specified by the repository.

To disable auto-update, pass `--skip-vex-repo-update`.

```shell
$ trivy image ghcr.io/aquasecurity/trivy:0.50.0 --vex repo --skip-vex-repo-update
```

To download VEX repositories in advance without scanning, use `trivy vex repo download`.

The cache can be cleared with `trivy clean --vex-repo`.

### Displaying Filtered Vulnerabilities

To see which vulnerabilities were filtered and why, use the `--show-suppressed` option:

```shell
$ trivy image ghcr.io/aquasecurity/trivy:0.50.0 --vex repo --show-suppressed
...

Suppressed Vulnerabilities (Total: 4)
=====================================
┌───────────────┬────────────────┬──────────┬──────────────┬───────────────────────────────────────────────────┬──────────────────────────────────────────┐
│    Library    │ Vulnerability  │ Severity │    Status    │                     Statement                     │                  Source                  │
├───────────────┼────────────────┼──────────┼──────────────┼───────────────────────────────────────────────────┼──────────────────────────────────────────┤
│ busybox       │ CVE-2023-42364 │ MEDIUM   │ not_affected │ vulnerable_code_cannot_be_controlled_by_adversary │ VEX Repository: default                  │
│               │                │          │              │                                                   │ (https://github.com/aquasecurity/vexhub) │
│               ├────────────────┤          │              │                                                   │                                          │
│               │ CVE-2023-42365 │          │              │                                                   │                                          │
│               │                │          │              │                                                   │                                          │
├───────────────┼────────────────┤          │              │                                                   │                                          │
│ busybox-binsh │ CVE-2023-42364 │          │              │                                                   │                                          │
│               │                │          │              │                                                   │                                          │
│               ├────────────────┤          │              │                                                   │                                          │
│               │ CVE-2023-42365 │          │              │                                                   │                                          │
│               │                │          │              │                                                   │                                          │
└───────────────┴────────────────┴──────────┴──────────────┴───────────────────────────────────────────────────┴──────────────────────────────────────────┘

```

## Publishing VEX Documents

### For OSS Projects

As an OSS developer or maintainer, you may encounter vulnerabilities in the packages your project depends on.
These vulnerabilities might be discovered through your own scans or reported by third parties using your OSS project.

While Trivy strives to minimize false positives, it doesn't perform code graph analysis, which means it can't evaluate exploitability at the code level.
Consequently, Trivy may report vulnerabilities even in cases where:

1. The vulnerable function in a dependency is never called in your project.
2. The vulnerable code cannot be controlled by an attacker in the context of your project.

If you're confident that a reported vulnerability in a dependency doesn't affect your OSS project or container image, you can publish a VEX document to reduce noise in Trivy scans.
To assess exploitability, you have several options:

1. Manual assessment: As a maintainer, you can read the source code and determine if the vulnerability is exploitable in your project's context.
2. Automated assessment: You can use SAST (Static Application Security Testing) tools or similar tools to analyze the code and determine exploitability.

By publishing VEX documents in the source repository, Trivy can automatically utilize them through VEX Hub.
The main steps are:

1. Generate a VEX document
2. Commit the VEX document to the `.vex/` directory in the source repository (e.g., [Trivy's VEX][trivy-vex])
3. Register your project's [PURL][purl] in VEX Hub

Step 3 is only necessary once.
After that, updating the VEX file in your repository will automatically be fetched by VEX Hub and utilized by Trivy.
See the [VEX Hub repository][vexhub] for more information.

If you want to issue a VEX for an OSS project that you don't maintain, consider first proposing the VEX publication to the original repository.
Many OSS maintainers are open to contributions that improve the security posture of their projects.
However, if your proposal is not accepted, or if you want to issue a VEX with statements that differ from the maintainer's judgment, you may want to consider creating a [custom repository](#hosting-custom-repositories).

### For Private Projects

If you're working on private software or personal projects, you have several options:

1. [Local VEX files](./file.md): You can create local VEX files and have Trivy read them during scans. This is suitable for individual use or small teams.
2. [.trivyignore](../../configuration/filtering.md#trivyignore): For simpler cases, using a .trivyignore file might be sufficient to suppress specific vulnerabilities.
3. [Custom repositories](#hosting-custom-repositories): For large organizations wanting to share VEX information for internally used software across different departments, setting up a custom VEX repository might be the best approach.

## Hosting Custom Repositories

While the principle is to store VEX documents for OSS packages in the source repository, it's possible to create a custom repository if that's difficult.

There are various use cases for providing custom repositories:

- A Pull Request to add a VEX document upstream was not merged
- Consolidating VEX documents output by SAST tools
- Publishing vendor-specific VEX documents that differ from OSS maintainer statements
- Creating a private VEX repository to publish common VEX for your company

In these cases, you can create a repository that complies with [the VEX Repository Specification][vex-repo] to make it available for use with Trivy.

[vex-repo]: https://github.com/aquasecurity/vex-repo-spec
[vexhub]: https://github.com/aquasecurity/vexhub
[trivy-vex]: https://github.com/aquasecurity/trivy/blob/b76a7250912cfc028cfef743f0f98cd81b39f8aa/.vex/trivy.openvex.json
[purl]: https://github.com/package-url/purl-spec