# Config file

Trivy can be customized by tweaking a `trivy.yaml` file.
The config path can be overridden by the `--config` flag.

An example is [here][example].

## Global Options

```yaml
# Same as '--quiet'
# Default is false
quiet: false

# Same as '--debug'
# Default is false
debug: false

# Same as '--insecure'
# Default is false
insecure: false

# Same as '--timeout'
# Default is '5m'
timeout: 10m

# Same as '--cache-dir'
# Default is your system cache dir
cache:
  dir: $HOME/.cache/trivy
```

## Report Options

```yaml
# Same as '--format'
# Default is 'table'
format: table

# Same as '--report' (available with 'trivy k8s')
# Default is all
report: all

# Same as '--template'
# Default is empty
template:

# Same as '--dependency-tree'
# Default is false
dependency-tree: false

# Same as '--list-all-pkgs'
# Default is false
list-all-pkgs: false

# Same as '--ignorefile'
# Default is '.trivyignore'
ignorefile: .trivyignore

# Same as '--ignore-policy'
# Default is empty
ignore-policy:

# Same as '--exit-code'
# Default is 0
exit-code: 0

# Same as '--exit-on-eol'
# Default is 0
exit-on-eol: 0

# Same as '--output'
# Default is empty (stdout)
output:

# Same as '--severity'
# Default is all severities
severity:
  - UNKNOWN
  - LOW
  - MEDIUM
  - HIGH
  - CRITICAL
```

## Scan Options
Available in client/server mode

```yaml
scan:
  # Same as '--file-patterns'
  # Default is empty
  file-patterns:
    -

  # Same as '--skip-dirs'
  # Default is empty
  skip-dirs:
    - usr/local/
    - etc/

  # Same as '--skip-files'
  # Default is empty
  skip-files:
    - package-dev.json

  # Same as '--offline-scan'
  # Default is false
  offline-scan: false

  # Same as '--scanners'
  # Default depends on subcommand
  scanners:
    - vuln
    - config
    - secret
```

## Cache Options

```yaml
cache:
  # Same as '--cache-backend'
  # Default is 'fs'
  backend: 'fs'

  # Same as '--cache-ttl'
  # Default is 0 (no ttl)
  ttl: 0

  # Redis options
  redis:
    # Same as '--redis-ca'
    # Default is empty
    ca:

    # Same as '--redis-cert'
    # Default is empty
    cert:

    # Same as '--redis-key'
    # Default is empty
    key:
```

## DB Options

```yaml
db:
  # Same as '--skip-db-update'
  # Default is false
  skip-update: false

  # Same as '--no-progress'
  # Default is false
  no-progress: false

  # Same as '--db-repository'
  # Default is 'ghcr.io/aquasecurity/trivy-db'
  repository: ghcr.io/aquasecurity/trivy-db

  # Same as '--java-db-repository'
  # Default is 'ghcr.io/aquasecurity/trivy-java-db'
  java-repository: ghcr.io/aquasecurity/trivy-java-db
```

## Registry Options

```yaml
registry:
  # Same as '--username'
  # Default is empty
  username:

  # Same as '--password'
  # Default is empty
  password:
    
  # Same as '--registry-token'
  # Default is empty
  registry-token:
```

## Image Options
Available with container image scanning

```yaml
image:
  # Same as '--input' (available with 'trivy image')
  # Default is empty
  input:

  # Same as '--removed-pkgs'
  # Default is false
  removed-pkgs: false
  
  # Same as '--platform'
  # Default is empty
  platform: 
  
  docker:
    # Same as '--docker-host'
    # Default is empty
    host: 
```

## Vulnerability Options
Available with vulnerability scanning

```yaml
vulnerability:
  # Same as '--vuln-type'
  # Default is 'os,library'
  type:
    - os
    - library

  # Same as '--ignore-unfixed'
  # Default is false
  ignore-unfixed: false
```

## Secret Options
Available with secret scanning

```yaml
secret:
  # Same as '--secret-config'
  # Default is 'trivy-secret.yaml'
  config: config/trivy/secret.yaml
```

## Rego Options

```yaml
rego
  # Same as '--trace'
  # Default is false
  trace: false

  # Same as '--config-policy'
  # Default is empty
  policy:
    - policy/repository
    - policy/custom
    - policy/some-policy.rego

  # Same as '--config-data'
  # Default is empty
  data:
    - data/

  # Same as '--policy-namespaces'
  # Default is empty
  namespaces:
    - opa.examples
    - users
```

## Misconfiguration Options
Available with misconfiguration scanning

```yaml
misconfiguration:
  # Same as '--include-non-failures'
  # Default is false
  include-non-failures: false

  # helm value override configurations
  # set individual values
  helm:
    set:
      - securityContext.runAsUser=10001

  # set values with file
  helm:
    values:
      - overrides.yaml

  # set specific values from specific files
  helm:
    set-file:
      - image=dev-overrides.yaml

  # set as string and preserve type
  helm:
    set-string:
      - name=true

  # terraform tfvars overrrides
  terraform:
    vars:
      - dev-terraform.tfvars
      - common-terraform.tfvars
  
  # Same as '--tf-exclude-downloaded-modules'
  # Default is false
  terraform:
    exclude-downloaded-modules: false
```

## Kubernetes Options
Available with Kubernetes scanning

```yaml
kubernetes:
  # Same as '--context'
  # Default is empty
  context:

  # Same as '--namespace'
  # Default is empty
  namespace:
```

## Repository Options
Available with git repository scanning (`trivy repo`)

```yaml
repository:
  # Same as '--branch'
  # Default is empty
  branch:

  # Same as '--commit'
  # Default is empty
  commit:

  # Same as '--tag'
  # Default is empty
  tag:
```

## Client/Server Options
Available in client/server mode

```yaml
server:
  # Same as '--server' (available in client mode)
  # Default is empty
  addr: http://localhost:4954

  # Same as '--token'
  # Default is empty
  token: "something-secret"

  # Same as '--token-header'
  # Default is 'Trivy-Token'
  token-header: 'My-Token-Header'

  # Same as '--custom-headers'
  # Default is empty
  custom-headers:
    - scanner: trivy
    - x-api-token: xxx

  # Same as '--listen' (available in server mode)
  # Default is 'localhost:4954'
  listen: 0.0.0.0:10000
```

## Cloud Options

Available for cloud scanning (currently only `trivy aws`)

```yaml
cloud:
  # whether to force a cache update for every scan
  update-cache: false

  # how old cached results can be before being invalidated
  max-cache-age: 24h

  # aws-specific cloud settings
  aws:
    # the aws region to use
    region: us-east-1

    # the aws endpoint to use (not required for general use)
    endpoint: https://my.custom.aws.endpoint

    # the aws account to use (this will be determined from your environment when not set)
    account: 123456789012
```

[example]: https://github.com/aquasecurity/trivy/tree/{{ git.tag }}/examples/trivy-conf/trivy.yaml
