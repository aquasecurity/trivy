# User Guide

## Discovering Plugins
You can find a list of Trivy plugins distributed via trivy-plugin-index [here][trivy-plugin-index].
However, you can find plugins using the command line as well.

First, refresh your local copy of the plugin index:

```bash
$ trivy plugin update
```

To list all plugins available, run:

```bash
$ trivy plugin search
NAME                 DESCRIPTION                                                  MAINTAINER           OUTPUT
aqua                 A plugin for integration with Aqua Security SaaS platform    aquasecurity
kubectl              A plugin scanning the images of a kubernetes resource        aquasecurity
referrer             A plugin for OCI referrers                                   aquasecurity           ✓
```

You can specify search keywords as arguments:

```bash
$ trivy plugin search referrer

NAME                 DESCRIPTION                                                  MAINTAINER           OUTPUT
referrer             A plugin for OCI referrers                                   aquasecurity           ✓
```

It lists plugins with the keyword in the name or description.

## Installing  Plugins
Plugins can be installed with the `trivy plugin install` command:

```bash
$ trivy plugin install referrer
```

This command will download the plugin and install it in the plugin cache.

Trivy adheres to the XDG specification, so the location depends on whether XDG_DATA_HOME is set.
Trivy will now search XDG_DATA_HOME for the location of the Trivy plugins cache.
The preference order is as follows:

- XDG_DATA_HOME if set and .trivy/plugins exists within the XDG_DATA_HOME dir
- ~/.trivy/plugins

Furthermore, it is possible to download plugins that are not registered in the index by specifying the URL directly or by specifying the file path.

```bash
$ trivy plugin install github.com/aquasecurity/trivy-plugin-kubectl
```
```bash
$ trivy plugin install https://github.com/aquasecurity/trivy-plugin-kubectl/archive/refs/heads/main.zip
```
```bash
$ trivy plugin install ./myplugin.tar.gz
```

If the plugin's Git repository is [properly tagged](./developer-guide.md#tagging-plugin-repositories), you can specify the version to install like this:

```bash
$ trivy plugin install referrer@v0.3.0
```

!!! note
    The leading `v` in the version is required. Also, the version must follow the [Semantic Versioning](https://semver.org/).

Under the hood Trivy leverages [go-getter][go-getter] to download plugins.
This means the following protocols are supported for downloading plugins:

- OCI Registries
- Local Files
- Git
- HTTP/HTTPS
- Mercurial
- Amazon S3
- Google Cloud Storage

## Listing Installed Plugins
To list all plugins installed, run:

```bash
$ trivy plugin list
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

Scanning Commands
  config      Scan config files for misconfigurations
  filesystem  Scan local filesystem
  image       Scan a container image
  
...

Plugin Commands
  kubectl     scan kubectl resources
  referrer    Put referrers to OCI registry
```

As shown above, `kubectl` subcommand exists in the `Plugin Commands` section.
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
trivy plugin run kubectl pod your-pod -- --exit-code 1
```

## Upgrading Plugins
To upgrade all plugins that you have installed to their latest versions, run:

```bash
$ trivy plugin upgrade
```

To upgrade only certain plugins, you can explicitly specify their names:

```bash
$ trivy plugin upgrade <PLUGIN1> <PLUGIN2>
```

## Uninstalling Plugins
Specify a plugin name with `trivy plugin uninstall` command.

```bash
$ trivy plugin uninstall kubectl
```

Here's the revised English documentation based on your requested changes:

## Output Mode Support
While plugins are typically intended to be used as subcommands of Trivy, plugins supporting the output mode can be invoked as part of Trivy's built-in commands.

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Trivy supports plugins that are compatible with the output mode, which process Trivy's output, such as by transforming the output format or sending it elsewhere.
You can determine whether a plugin supports the output mode by checking the `OUTPUT` column in the output of `trivy plugin search` or `trivy plugin list`.

```bash
$ trivy plugin search
NAME                 DESCRIPTION                                                  MAINTAINER           OUTPUT
aqua                 A plugin for integration with Aqua Security SaaS platform    aquasecurity
kubectl              A plugin scanning the images of a kubernetes resource        aquasecurity
referrer             A plugin for OCI referrers                                   aquasecurity           ✓
```

In this case, the `referrer` plugin supports the output mode.

For instance, in the case of image scanning, a plugin supporting the output mode can be called as follows:

```bash
$ trivy image --format json --output plugin=<plugin_name> [--output-plugin-arg <plugin_flags>] <image_name>
```

Since scan results are passed to the plugin via standard input, plugins must be capable of handling standard input.

!!! warning
    To avoid Trivy hanging, you need to read all data from `Stdin` before the plugin exits successfully or stops with an error.

While the example passes JSON to the plugin, other formats like SBOM can also be passed (e.g., `--format cyclonedx`).

If a plugin requires flags or other arguments, they can be passed using `--output-plugin-arg`.
This is directly forwarded as arguments to the plugin.
For example, `--output plugin=myplugin --output-plugin-arg "--foo --bar=baz"` translates to `myplugin --foo --bar=baz` in execution.

An example of a plugin supporting the output mode is available [here][trivy-plugin-count].
It can be used as below:

```bash
# Install the plugin first
$ trivy plugin install count

# Call the plugin supporting the output mode in image scanning
$ trivy image --format json --output plugin=count --output-plugin-arg "--published-after 2023-10-01" debian:12
```

## Example

- [kubectl][trivy-plugin-kubectl]
- [count][trivy-plugin-count]

[trivy-plugin-index]: https://aquasecurity.github.io/trivy-plugin-index/
[go-getter]: https://github.com/hashicorp/go-getter
[trivy-plugin-kubectl]: https://github.com/aquasecurity/trivy-plugin-kubectl
[trivy-plugin-count]: https://github.com/aquasecurity/trivy-plugin-count
