Trivy can download images from a private registry without the need for installing Docker or any other 3rd party tools.
This makes it easy to run within a CI process.

## Login
You can log in to a private registry using the `trivy registry login` command.
It uses the Docker configuration file (`~/.docker/config.json`) to store the credentials under the hood, and the configuration file path can be configured by `DOCKER_CONFIG` environment variable.

```shell
$ cat ~/my_password.txt | trivy registry login --username foo --password-stdin ghcr.io
$ trivy image ghcr.io/your/private_image
```

## Passing Credentials
You can also provide your credentials when scanning.

```shell
$ TRIVY_USERNAME=YOUR_USERNAME TRIVY_PASSWORD=YOUR_PASSWORD trivy image YOUR_PRIVATE_IMAGE
```

!!! warning
    When passing credentials via environment variables or CLI flags, Trivy will attempt to use these credentials for all registries encountered during scanning, regardless of the target registry.
    This can potentially lead to unintended credential exposure.
    To mitigate this risk:

    1. Set credentials cautiously and only when necessary.
    2. Prefer using `trivy registry login` to pre-configure credentials with specific registries, which ensures credentials are only sent to appropriate registries.

Trivy also supports providing credentials through CLI flags:

```shell
$ TRIVY_PASSWORD=YOUR_PASSWORD trivy image --username YOUR_USERNAME YOUR_PRIVATE_IMAGE
```

!!! warning
    The CLI flag `--password` is available, but its use is not recommended for security reasons.


You can also store your credentials in `trivy.yaml`.
For more information, please refer to [the documentation](../../references/configuration/config-file.md).

It can handle multiple sets of credentials as well:

```shell
$ export TRIVY_USERNAME=USERNAME1,USERNAME2
$ export TRIVY_PASSWORD=PASSWORD1,PASSWORD2
$ trivy image YOUR_PRIVATE_IMAGE
```

In the example above, Trivy attempts to use two pairs of credentials:

- USERNAME1/PASSWORD1
- USERNAME2/PASSWORD2

Please note that the number of usernames and passwords must be the same.

!!! note
    `--password-stdin` doesn't support comma-separated passwords.