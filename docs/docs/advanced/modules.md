# Modules

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Trivy provides a module feature to allow others to extend the Trivy CLI without the need to change the Trivy code base.
It changes the behavior during scanning by WebAssembly.

## Overview
Trivy modules are add-on tools that integrate seamlessly with Trivy.
They provide a way to extend the core feature set of Trivy, but without updating the Trivy binary.

- They can be added and removed from a Trivy installation without impacting the core Trivy tool.
- They can be written in any programming language supporting WebAssembly.
  - It supports only [TinyGo][tinygo] at the moment.

You can write your own detection logic.

- Evaluate complex vulnerability conditions like [Spring4Shell][spring4shell]
- Detect a shell script communicating with malicious domains
- Detect malicious python install script (setup.py)
- Even detect misconfigurations in WordPress setting
- etc.

Then, you can update the scan result however you want.

- Change a severity
- Remove a vulnerability
- Add a new vulnerability
- etc.

Modules should be distributed in OCI registries like GitHub Container Registry.

!!! warning
    Trivy modules available in public are not audited for security.
    You should install and run third-party modules at your own risk even though WebAssembly is sandboxed.


## Installing a Module
A module can be installed using the `trivy module install` command.
This command takes an url. It will download the module and install it in the module cache.

Trivy adheres to the XDG specification, so the location depends on whether XDG_DATA_HOME is set.
Trivy will now search XDG_DATA_HOME for the location of the Trivy modules cache.
The preference order is as follows:

- XDG_DATA_HOME if set and .trivy/plugins exists within the XDG_DATA_HOME dir
- $HOME/.trivy/plugins

For example, to download the WebAssembly module, you can execute the following command:

```bash
$ trivy module install ghcr.io/aquasecurity/trivy-module-spring4shell
```

## Using Modules
Once the module is installed, Trivy will load all available modules in the cache on the start of the next Trivy execution.
The modules may inject custom logic into scanning and change the result.

You will see the log messages about WASM modules.

```shell
2022-06-12T12:57:13.210+0300    INFO    Loading ghcr.io/aquasecurity/trivy-module-spring4shell/spring4shell.wasm...
2022-06-12T12:57:13.596+0300    INFO    Registering WASM module: spring4shell@v1
...
2022-06-12T12:57:14.865+0300    INFO    Module spring4shell: Java Version: 8, Tomcat Version: 8.5.77
2022-06-12T12:57:14.865+0300    INFO    Module spring4shell: change CVE-2022-22965 severity from CRITICAL to LOW
```

In the above example, the Spring4Shell module changed the severity to LOW because the application doesn't satisfy one of conditions.

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

## Example
https://github.com/aquasecurity/trivy-plugin-kubectl

[tinygo]: https://tinygo.org/
[spring4shell]: https://blog.aquasec.com/zero-day-rce-vulnerability-spring4shell

