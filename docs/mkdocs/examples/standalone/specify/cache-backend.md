[EXPERIMENTAL] This feature might change without preserving backwards compatibility.

Trivy supports local filesystem and Redis as the cache backend. This option is useful especially for client/server mode.

Two options:
- `fs` 
  - the cache path can be specified by `--cache-dir`
- `redis://`
  - `redis://[HOST]:[PORT]`

```
$ trivy server --cache-backend redis://localhost:6379
```
