# Plugins
Trivy provides a plugin feature to allow others to extend the Trivy CLI without the need to change the Trivy code base.
This plugin system was inspired by the plugin system used in [kubectl][kubectl], [Helm][helm], and [Conftest][conftest].

## Overview
Trivy plugins are add-on tools that integrate seamlessly with Trivy.
They provide a way to extend the core feature set of Trivy, but without requiring every new feature to be written in Go and added to the core tool.

- They can be added and removed from a Trivy installation without impacting the core Trivy tool.
- They can be written in any programming language.
- They integrate with Trivy, and will show up in Trivy help and subcommands.

!!! warning
    Only install and run plugins from sources you trust. Plugins execute with your permissions and are not sandboxed; see [Security considerations](#security-considerations).

## Security considerations

Trivy plugins are external programs executed with the privileges of the user running Trivy. They inherit the Trivy process's environment variables, which may include credentials, and can access files and network services permitted by the execution environment. Trivy does not sandbox plugins or isolate them from these resources.

Publicly available plugins are not audited for security. Choose plugin sources you trust before installing or running them. In CI, provide only the credentials and permissions required by the plugin, and use an isolated execution environment when additional restrictions are needed.

## Quickstart
Trivy helps you discover and install plugins on your machine.

You can install and use a wide variety of Trivy plugins to enhance your experience.

Let’s get started:

1. Download the plugin list:

    ```bash
    $ trivy plugin update
    ```

2. Discover Trivy plugins available on the plugin index:

    ```bash
    $ trivy plugin search
    NAME                 DESCRIPTION                                                  MAINTAINER           OUTPUT
    aqua                 A plugin for integration with Aqua Security SaaS platform    aquasecurity
    kubectl              A plugin scanning the images of a kubernetes resource        aquasecurity
    referrer             A plugin for OCI referrers                                   aquasecurity           ✓
    [...]
    ```

3. Choose a plugin from the list and install it:

    ```bash
    $ trivy plugin install referrer
    ```

4. Use the installed plugin:

    ```bash
    $ trivy referrer --help
    ```

5. Keep your plugins up-to-date:

    ```bash
    $ trivy plugin upgrade
    ```

6. Uninstall a plugin you no longer use:

    ```bash
    trivy plugin uninstall referrer
    ``` 

This is practically all you need to know to start using Trivy plugins.


[kubectl]: https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins/
[helm]: https://helm.sh/docs/topics/plugins/
[conftest]: https://www.conftest.dev/plugins/
