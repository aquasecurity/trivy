# Config file

Trivy can be customized by tweaking a `trivy.yaml` file.
The config path can be overridden by the `--config` flag.

An example is [here][example].

## Output options

```yaml
output: 
```

## Format options

```yaml
format: table
```

## Ignorefile options

```yaml
ignorefile: .trivyignore
```

## Ignore-Policy options

```yaml
ignore-policy: 
```

## Template options

```yaml
template: 
```

## Output-Plugin-Arg options

```yaml
output-plugin-arg: 
```

## Scan options

```yaml
scan:
  compliance: 
```

## Image options

```yaml
image:
  podman:
    host: 
  input: 
  platform: 
  docker:
    host: 
```

## Cache options

```yaml
cache:
  backend: fs
  redis:
    key: 
    ca: 
    cert: 
```

## Report options

```yaml
report: all
```

[example]: https://github.com/aquasecurity/trivy/tree/{{ git.tag }}/examples/trivy-conf/trivy.yaml