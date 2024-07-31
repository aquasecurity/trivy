# Config file

Trivy can be customized by tweaking a `trivy.yaml` file.
The config path can be overridden by the `--config` flag.

An example is [here][example].

## Global options

```yaml
cache:
  # Same as '--cache-dir'
  # Default is /path/to/cache
  dir: /path/to/cache

# Same as '--config'
# Default is trivy.yaml
config: trivy.yaml

# Same as '--debug'
# Default is false
debug: false

# Same as '--generate-default-config'
# Default is false
generate-default-config: false

# Same as '--insecure'
# Default is false
insecure: false

# Same as '--quiet'
# Default is false
quiet: false

# Same as '--timeout'
# Default is 5m0s
timeout: 5m0s

# Same as '--version'
# Default is false
version: false

```

## Report options

```yaml
# Same as '--dependency-tree'
# Default is false
dependency-tree: false

# Same as '--exit-code'
# Default is 0
exit-code: 0

# Same as '--exit-on-eol'
# Default is 0
exit-on-eol: 0

# Same as '--format'
# Default is table
format: table

# Same as '--ignore-policy'
# Default is 
ignore-policy: 

# Same as '--ignorefile'
# Default is .trivyignore
ignorefile: .trivyignore

# Same as '--list-all-pkgs'
# Default is false
list-all-pkgs: false

# Same as '--output'
# Default is 
output: 

# Same as '--output-plugin-arg'
# Default is 
output-plugin-arg: 

# Same as '--pkg-types'
# Default is [os library]
pkg-types: [os library]

# Same as '--report'
# Default is all
report: all

scan:
  # Same as '--compliance'
  # Default is 
  compliance: 

  # Same as '--show-suppressed'
  # Default is false
  show-suppressed: false

# Same as '--severity'
# Default is [UNKNOWN LOW MEDIUM HIGH CRITICAL]
severity: [UNKNOWN LOW MEDIUM HIGH CRITICAL]

# Same as '--template'
# Default is 
template: 

```

## Image options

```yaml
image:
  docker:
    # Same as '--docker-host'
    # Default is 
    host: 

  # Same as '--image-config-scanners'
  # Default is []
  image-config-scanners: []

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

  # Same as '--removed-pkgs'
  # Default is false
  removed-pkgs: false

  # Same as '--image-src'
  # Default is [docker containerd podman remote]
  source: [docker containerd podman remote]

```

## Cache options

```yaml
cache:
  # Same as '--cache-backend'
  # Default is fs
  backend: fs

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

    # Same as '--redis-tls'
    # Default is false
    tls: false

  # Same as '--cache-ttl'
  # Default is 0s
  ttl: 0s

```

[example]: https://github.com/aquasecurity/trivy/tree/{{ git.tag }}/examples/trivy-conf/trivy.yaml