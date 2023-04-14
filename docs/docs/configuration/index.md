# Configuration
Trivy can be configured using the following ways. Each item takes precedence over the item below it:

- CLI flags
- Environment variables
- Configuration file

## CLI Flags
You can view the list of available flags using the `--help` option.
For more details, please refer to [the CLI reference](../references/configuration/cli/trivy.md).

## Environment Variables
Trivy can be customized by environment variables.
The environment variable key is the flag name converted by the following procedure.

- Add `TRIVY_` prefix
- Make it all uppercase
- Replace `-` with `_`

For example,

- `--debug` => `TRIVY_DEBUG`
- `--cache-dir` => `TRIVY_CACHE_DIR`

```
$ TRIVY_DEBUG=true TRIVY_SEVERITY=CRITICAL trivy image alpine:3.15
```

## Configuration File
By default, Trivy reads the `trivy.yaml` file.
For more details, please refer to [the page](../references/configuration/config-file.md).
