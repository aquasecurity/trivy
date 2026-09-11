# Configuration
Trivy's settings can be configured in any of the following methods, which will apply in the following precedence:

1. CLI flags (overrides all other settings)
2. Environment variables (overrides config file settings)
3. Configuration file

## CLI Flags
You can view the list of available flags by adding the `--help` flag to a Trivy command, or by exploring the [CLI reference](../references/configuration/cli/trivy.md).

## Environment Variables
Any CLI option can be set as an environment variable. The environment variable names are similar to the CLI option names, with the following augmentations:

- Add `TRIVY_` prefix
- All uppercase letters
- Replace `-` with `_`

For example:

- `--debug` => `TRIVY_DEBUG`
- `--cache-dir` => `TRIVY_CACHE_DIR`

```
$ TRIVY_DEBUG=true TRIVY_SEVERITY=CRITICAL trivy image alpine:3.15
```

## Configuration File
Any setting can be set in a YAML file. By default, config file named `trivy.yaml` is read from the current directory where Trivy is run. To load configuration from a different file, use the `--config` flag and specify the config path to load: `trivy fs --config /etc/trivy/myconfig.yaml /workspace/project`.

The structure and settings of the YAML config file is documented in the [Config file](../references/configuration/config-file.md) document.

### Disabling configuration files

Pass an empty string to `--config` to skip loading `trivy.yaml`. To also skip the default `.trivyignore` and `trivy-secret.yaml` files, pass empty strings to `--ignorefile` and `--secret-config`:

```shell
trivy fs --config="" --ignorefile="" --secret-config="" /workspace/project
```

CLI flags and environment variables still apply. Secret scanning continues to use its built-in rules and allow rules. Omitting these flags preserves the default file-loading behavior.

Empty environment variables such as `TRIVY_CONFIG=""`, `TRIVY_IGNOREFILE=""`, and `TRIVY_SECRET_CONFIG=""` are treated as unset and do not disable file loading. Use the CLI flags shown above to disable these files.

### Security considerations

Trivy loads `trivy.yaml` from the current working directory by default, independently of the scan target. Running Trivy from a repository checkout can therefore load configuration supplied by that repository.

When scanning a remote repository with `trivy repo <REPO_URL>`, Trivy clones it into a temporary directory and does not automatically load `trivy.yaml` from that clone. Configuration is still loaded from the directory where Trivy was started.

Configuration controls Trivy's behavior, including output paths, report templates, filtering, and exit codes. When scanning untrusted content, use `--config` to select a trusted configuration file outside the checkout. In CI, keep the configuration that determines whether a scan passes or fails outside the control of the code under review.

Selecting a trusted `--config` does not disable loading `.trivyignore` or, when secret scanning is enabled, `trivy-secret.yaml` from the current working directory. These files can suppress findings or change secret detection rules. Use `--ignorefile` and `--secret-config` to select trusted files, or [disable their loading](#disabling-configuration-files) when they are not needed.

For example, use a pipeline-managed configuration and disable the other configuration files when scanning a checkout:

```shell
trivy fs --config /opt/ci/trivy.yaml --ignorefile="" --secret-config="" /workspace/project
```

Templates and other files referenced by the configuration must also come from trusted sources. A trusted configuration file can still reference an untrusted template: relative template paths are resolved from the current working directory, not the configuration file's directory. Use trusted absolute template paths when the working directory contains untrusted content. Templates can read environment variables and include sensitive values in report output.
