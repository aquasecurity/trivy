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
Any setting can be set in a YAML file. By default, config file named `trivy.yaml` is read from the current directory where Trivy is run. To load configuration from a different file, use the `--config` flag and specify the config path to load: `trivy --config /etc/trivy/myconfig.yaml`.

The structure and settings of the YAML config file is documented in the [Config file](../references/configuration/config-file.md) document.

### Security considerations

Trivy loads `trivy.yaml` from the current working directory by default, independently of the scan target. Running Trivy from a repository checkout can therefore load configuration supplied by that repository.

When scanning a remote repository with `trivy repo <REPO_URL>`, Trivy clones it into a temporary directory and does not automatically load `trivy.yaml` from that clone. Configuration is still loaded from the directory where Trivy was started.

Configuration controls Trivy's behavior, including output paths, report templates, filtering, and exit codes. When scanning untrusted content, use `--config` to select a trusted configuration file outside the checkout. In CI, keep the configuration that determines whether a scan passes or fails outside the control of the code under review.

For example, use a pipeline-managed configuration to scan a checkout:

```shell
trivy --config /opt/ci/trivy.yaml fs /workspace/project
```

Templates and other files referenced by the configuration must also come from trusted sources. A trusted configuration file can still reference an untrusted template: relative template paths are resolved from the current working directory, not the configuration file's directory. Use trusted absolute template paths when the working directory contains untrusted content. Templates can read environment variables and include sensitive values in report output.
