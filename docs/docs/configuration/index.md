# Configuration
Trivy's settings can be configured in any of the following methods, which will apply in the following precedence:

1. CLI flags (overrides all other settings)
2. Environment variables (overrides config file settings)
3. Configuration file

## CLI Flags
You can view the list of available flags by adding the `--help` flag to a Trivy command, or by exploring the [CLI reference](../references/configuration/cli/trivy.md).

## Environment Variables
Any CLI option can be set as an environment variable. The environment variable name are similar to the CLI option name, with the following augmentations:

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
