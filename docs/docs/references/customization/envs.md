# Environment variables

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