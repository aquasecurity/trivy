# Developer Guide

## Introduction
If you are looking to start developing plugins for Trivy, read [the user guide](./user-guide.md) first.

To summarize the documentation, the procedure is to:

- Create a repository for your plugin, named `trivy-plugin-<name>`.
- Create an executable binary that can be invoked as `trivy <name>`.
- Place the executable binary in a repository.
- Create a `plugin.yaml` file that describes the plugin.

After you develop a plugin with a good name following the best practices, you can develop a [trivy-plugin-index][trivy-plugin-index] manifest and submit your plugin.

## Naming
This section describes guidelines for naming your plugins.

### Use `trivy-plugin-` prefix
The name of the plugin repository should be prefixed with `trivy-plugin-`.

### Use lowercase and hyphens
Plugin names must be all lowercase and separate words with hyphens.
Don’t use camelCase, PascalCase, or snake_case; use kebab-case.

- NO: `trivy OpenSvc`
- YES: `trivy open-svc`

### Be specific
Plugin names should not be verbs or nouns that are generic, already overloaded, or likely to be used for broader purposes by another plugin.

- NO: trivy sast (Too broad)
- YES: trivy govulncheck


### Be unique
Find a unique name for your plugin that differentiates it from other plugins that perform a similar function.

- NO: `trivy images` (Unclear how it is different from the builtin “image" command)
- YES: `trivy registry-images` (Unique name).

### Prefix Vendor Identifiers
Use vendor-specific strings as prefix, separated with a dash.
This makes it easier to search/group plugins that are about a specific vendor.

- NO: `trivy security-hub-aws (Makes it harder to search or locate in a plugin list)
- YES: `trivy aws-security-hub (Will show up together with other aws-* plugins)

Each plugin has a top-level directory, and then a plugin.yaml file.

```bash
your-plugin/
  |
  |- plugin.yaml
  |- your-plugin.sh
```

In the example above, the plugin is contained inside of a directory named `your-plugin`.
It has two files: plugin.yaml (required) and an executable script, your-plugin.sh (optional).

The core of a plugin is a simple YAML file named plugin.yaml.
Here is an example YAML of trivy-plugin-kubectl plugin that adds support for Kubernetes scanning.

```yaml
name: "kubectl"
repository: github.com/aquasecurity/trivy-plugin-kubectl
version: "0.1.0"
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

The `plugin.yaml` field should contain the following information:

- name: The name of the plugin. This also determines how the plugin will be made available in the Trivy CLI. For example, if the plugin is named kubectl, you can call the plugin with `trivy kubectl`. (required)
- version: The version of the plugin. (required)
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

The plugin is responsible for handling flags and arguments. Any arguments are passed to the plugin from the `trivy` command.

A plugin should be archived `*.tar.gz`.

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

[trivy-plugin-index]: https://github.com/aquasecurity/trivy-plugin-index