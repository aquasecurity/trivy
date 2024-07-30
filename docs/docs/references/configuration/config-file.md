# Config file

Trivy can be customized by tweaking a `trivy.yaml` file.
The config path can be overridden by the `--config` flag.

An example is [here][example].

## Cache options

```yaml
cache:
  # Same as '--cache-backend'
  # Default is fs
  backend: fs

  # Same as '--cache-dir'
  # Default is /path/to/cache
  dir: /path/to/cache

  redis:
    # Same as '--redis-ca'
    # Default is 
    ca: 

    # Same as '--redis-cert'
    # Default is 
    cert: 

    # Same as '--redis-key'
    # Default is 
    key: 

```

## Config options

```yaml
# Same as '--config'
# Default is trivy.yaml
config: trivy.yaml

```

## Format options

```yaml
# Same as '--format'
# Default is table
format: table

```

## Ignore-Policy options

```yaml
# Same as '--ignore-policy'
# Default is 
ignore-policy: 

```

## Ignorefile options

```yaml
# Same as '--ignorefile'
# Default is .trivyignore
ignorefile: .trivyignore

```

## Image options

```yaml
image:
  docker:
    # Same as '--docker-host'
    # Default is 
    host: 

  # Same as '--input'
  # Default is 
  input: 

  # Same as '--platform'
  # Default is 
  platform: 

  podman:
    # Same as '--podman-host'
    # Default is 
    host: 

```

## Output options

```yaml
# Same as '--output'
# Default is 
output: 

```

## Output-Plugin-Arg options

```yaml
# Same as '--output-plugin-arg'
# Default is 
output-plugin-arg: 

```

## Report options

```yaml
# Same as '--report'
# Default is all
report: all

```

## Scan options

```yaml
scan:
  # Same as '--compliance'
  # Default is 
  compliance: 

```

## Template options

```yaml
# Same as '--template'
# Default is 
template: 

```

[example]: https://github.com/aquasecurity/trivy/tree/{{ git.tag }}/examples/trivy-conf/trivy.yaml