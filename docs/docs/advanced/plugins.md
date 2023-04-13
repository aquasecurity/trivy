# Plugins
Trivy provides a plugin feature to allow others to extend the Trivy CLI without the need to change the Trivycode base.
This plugin system was inspired by the plugin system used in [kubectl][kubectl], [Helm][helm], and [Conftest][conftest].

## Overview
Trivy plugins are add-on tools that integrate seamlessly with Trivy.
They provide a way to extend the core feature set of Trivy, but without requiring every new feature to be written in Go and added to the core tool.

- They can be added and removed from a Trivy installation without impacting the core Trivy tool.
- They can be written in any programming language.
- They integrate with Trivy, and will show up in Trivy help and subcommands.

!!! warning
    Trivy plugins available in public are not audited for security.
    You should install and run third-party plugins at your own risk, since they are arbitrary programs running on your machine.


## Installing a Plugin
A plugin can be installed using the `trivy plugin install` command.
This command takes a url and will download the plugin and install it in the plugin cache.

Trivy adheres to the XDG specification, so the location depends on whether XDG_DATA_HOME is set.
Trivy will now search XDG_DATA_HOME for the location of the Trivy plugins cache.
The preference order is as follows:

- XDG_DATA_HOME if set and .trivy/plugins exists within the XDG_DATA_HOME dir
- ~/.trivy/plugins

Under the hood Trivy leverages [go-getter][go-getter] to download plugins.
This means the following protocols are supported for downloading plugins:

- OCI Registries
- Local Files
- Git
- HTTP/HTTPS
- Mercurial
- Amazon S3
- Google Cloud Storage

For example, to download the Kubernetes Trivy plugin you can execute the following command:

```bash
$ trivy plugin install github.com/aquasecurity/trivy-plugin-kubectl
```
Also, Trivy plugin can be installed from a local archive:
```bash
$ trivy plugin install myplugin.tar.gz
```

## Using Plugins
Once the plugin is installed, Trivy will load all available plugins in the cache on the start of the next Trivy execution.
A plugin will be made in the Trivy CLI based on the plugin name.
To display all plugins, you can list them by `trivy --help`

```bash
$ trivy --help
NAME:
   trivy - A simple and comprehensive vulnerability scanner for containers

USAGE:
   trivy [global options] command [command options] target

VERSION:
   dev

COMMANDS:
   image, i          scan an image
   filesystem, fs    scan local filesystem
   repository, repo  scan remote repository
   client, c         client mode
   server, s         server mode
   plugin, p         manage plugins
   kubectl           scan kubectl resources
   help, h           Shows a list of commands or help for one command
```

As shown above, `kubectl` subcommand exists in the `COMMANDS` section.
To call the kubectl plugin and scan existing Kubernetes deployments, you can execute the following command:

```
$ trivy kubectl deployment <deployment-id> -- --ignore-unfixed --severity CRITICAL
```

Internally the kubectl plugin calls the kubectl binary to fetch information about that deployment and passes the using images to Trivy.
You can see the detail [here][trivy-plugin-kubectl].

If you want to omit even the subcommand, you can use `TRIVY_RUN_AS_PLUGIN` environment variable.

```bash
$ TRIVY_RUN_AS_PLUGIN=kubectl trivy job your-job -- --format json
```

## Installing and Running Plugins on the fly
`trivy plugin run` installs a plugin and runs it on the fly.
If the plugin is already present in the cache, the installation is skipped.

```bash
trivy plugin run github.com/aquasecurity/trivy-plugin-kubectl pod your-pod -- --exit-code 1
```

## Uninstalling Plugins
Specify a plugin name with `trivy plugin uninstall` command.

```bash
$ trivy plugin uninstall kubectl
```

## Building Plugins
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

## Example
https://github.com/aquasecurity/trivy-plugin-kubectl

[kubectl]: https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins/
[helm]: https://helm.sh/docs/topics/plugins/
[conftest]: https://www.conftest.dev/plugins/
[go-getter]: https://github.com/hashicorp/go-getter
[trivy-plugin-kubectl]: https://github.com/aquasecurity/trivy-plugin-kubectl

