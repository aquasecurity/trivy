# Developer Guide

## Developing Trivy plugins
This section will guide you through the process of developing Trivy plugins.
To help you get started quickly, we have published a [plugin template repository][plugin-template].
You can use this template as a starting point for your plugin development.

### Introduction
If you are looking to start developing plugins for Trivy, read [the user guide](./user-guide.md) first.

To summarize the documentation, the procedure is to:

- Create a repository for your plugin, named `trivy-plugin-<name>`.
- Create an executable binary that can be invoked as `trivy <name>`.
- Place the executable binary in a repository.
- Create a `plugin.yaml` file that describes the plugin.

After you develop a plugin with a good name following the best practices, you can develop a [Trivy plugin index][trivy-plugin-index] manifest and submit your plugin.

### Naming
This section describes guidelines for naming your plugins.

#### Use `trivy-plugin-` prefix
The name of the plugin repository should be prefixed with `trivy-plugin-`.

#### Use lowercase and hyphens
Plugin names must be all lowercase and separate words with hyphens.
Don’t use camelCase, PascalCase, or snake_case; use kebab-case.

- NO: `trivy OpenSvc`
- YES: `trivy open-svc`

#### Be specific
Plugin names should not be verbs or nouns that are generic, already overloaded, or likely to be used for broader purposes by another plugin.

- NO: trivy sast (Too broad)
- YES: trivy govulncheck


#### Be unique
Find a unique name for your plugin that differentiates it from other plugins that perform a similar function.

- NO: `trivy images` (Unclear how it is different from the builtin “image" command)
- YES: `trivy registry-images` (Unique name).

#### Prefix Vendor Identifiers
Use vendor-specific strings as prefix, separated with a dash.
This makes it easier to search/group plugins that are about a specific vendor.

- NO: `trivy security-hub-aws (Makes it harder to search or locate in a plugin list)
- YES: `trivy aws-security-hub (Will show up together with other aws-* plugins)

### Choosing a language
Since Trivy plugins are standalone executables, you can write them in any programming language.

If you are planning to write a plugin with Go, check out [the Report struct](https://github.com/aquasecurity/trivy/blob/787b466e069e2d04e73b3eddbda621e5eec8543b/pkg/types/report.go#L13-L24),
which is the output of Trivy scan.


### Writing your plugin
Each plugin has a top-level directory, and then a `plugin.yaml` file.

```bash
your-plugin/
  |
  |- plugin.yaml
  |- your-plugin.sh
```

In the example above, the plugin is contained inside a directory named `your-plugin`.
It has two files: `plugin.yaml` (required) and an executable script, `your-plugin.sh` (optional).

#### Writing a plugin manifest
The plugin manifest is a simple YAML file named `plugin.yaml`.
Here is an example YAML of [trivy-plugin-kubectl][trivy-plugin-kubectl] plugin that adds support for Kubernetes scanning.

```yaml
name: "kubectl"
repository: github.com/aquasecurity/trivy-plugin-kubectl
version: "0.1.0"
output: false
usage: scan kubectl resources
description: |-
  A Trivy plugin that scans the images of a kubernetes resource.
  Usage: trivy kubectl TYPE[.VERSION][.GROUP] NAME
platforms:
  - selector: # optional
      os: darwin
      arch: amd64
    uri: ./trivy-kubectl # where the execution file is (local file, http, git, etc.)
    bin: ./trivy-kubectl # path to the execution file
  - selector: # optional
      os: linux
      arch: amd64
    uri: https://github.com/aquasecurity/trivy-plugin-kubectl/releases/download/v0.1.0/trivy-kubectl.tar.gz
    bin: ./trivy-kubectl
```

We encourage you to copy and adapt plugin manifests of existing plugins.

- [count][trivy-plugin-count]
- [referrer][trivy-plugin-referrer]

The `plugin.yaml` field should contain the following information:

- name: The name of the plugin. This also determines how the plugin will be made available in the Trivy CLI. For example, if the plugin is named kubectl, you can call the plugin with `trivy kubectl`. (required)
- repository: The repository name where the plugin is hosted. (required)
- version: The version of the plugin. (required)
- output: Whether the plugin supports [the output mode](./user-guide.md#output-mode-support). (optional)
- usage: A short usage description. (required)
- description: A long description of the plugin. This is where you could provide a helpful documentation of your plugin. (required)
- platforms: (required)
    - selector: The OS/Architecture specific variations of a execution file. (optional)
        - os: OS information based on GOOS (linux, darwin, etc.) (optional)
        - arch: The architecture information based on GOARCH (amd64, arm64, etc.) (optional)
    - uri: Where the executable file is. Relative path from the root directory of the plugin or remote URL such as HTTP and S3. (required)
    - bin: Which file to call when the plugin is executed. Relative path from the root directory of the plugin. (required)

The following rules will apply in deciding which platform to select:

- If both `os` and `arch` under `selector` match the current platform, search will stop and the platform will be used.
- If `selector` is not present, the platform will be used.
- If `os` matches and there is no more specific `arch` match, the platform will be used.
- If no `platform` match is found, Trivy will exit with an error.

After determining platform, Trivy will download the execution file from `uri` and store it in the plugin cache.
When the plugin is called via Trivy CLI, `bin` command will be executed.

#### Plugin arguments/flags
The plugin is responsible for handling flags and arguments.
Any arguments are passed to the plugin from the `trivy` command.

#### Testing plugin installation locally
A plugin should be archived `*.tar.gz`.
After you have archived your plugin into a `.tar.gz` file, you can verify that your plugin installs correctly with Trivy.

```bash
$ tar -czvf myplugin.tar.gz plugin.yaml script.py
plugin.yaml
script.py

$ trivy plugin install myplugin.tar.gz
2023-03-03T19:04:42.026+0600	INFO	Installing the plugin from myplugin.tar.gz...
2023-03-03T19:04:42.026+0600	INFO	Loading the plugin metadata...

$ trivy myplugin
Hello from Trivy demo plugin!
```

## Publishing plugins
The [plugin.yaml](#writing-a-plugin-manifest) file is the core of your plugin, so as long as it is published somewhere, your plugin can be installed.
If you choose to publish your plugin on GitHub, you can make it installable by placing the plugin.yaml file in the root directory of your repository.
Users can then install your plugin with the command, `trivy plugin install github.com/org/repo`.

While the `uri` specified in the plugin.yaml file doesn't necessarily need to point to the same repository, it's a good practice to host the executable file within the same repository when using GitHub.
You can utilize GitHub Releases to distribute the executable file.
For an example of how to structure your plugin repository, refer to [the plugin template repository][plugin-template].

## Distributing plugins on the Trivy plugin index
Trivy can install plugins directly by specifying a repository, so you don't necessarily need to register your plugin in the Trivy Plugin Index.
However, we would recommend it since it makes it easier for other users to find and install your plugin.

See [the Trivy plugin index repository][trivy-plugin-index] for more information on how to submit your plugin to the plugin index.

[plugin-template]: https://github.com/aquasecurity/trivy-plugin-template
[trivy-plugin-index]: https://github.com/aquasecurity/trivy-plugin-index
[trivy-plugin-kubectl]: https://github.com/aquasecurity/trivy-plugin-kubectl
[trivy-plugin-count]: https://github.com/aquasecurity/trivy-plugin-count/blob/main/plugin.yaml
[trivy-plugin-referrer]: https://github.com/aquasecurity/trivy-plugin-referrer/blob/main/plugin.yaml
