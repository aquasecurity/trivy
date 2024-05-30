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

scan:
  # Same as '--compliance'
  # Default is empty  
  compliance:

  # Same as '--show-suppressed'
  # Default is false  
  show-suppressed: false
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
  offline: false

  # Same as '--scanners'
  # Default depends on subcommand
  scanners:
    - vuln
    - misconfig
    - secret
    - license
    - 
  # Same as '--parallel'
  # Default is 5
  parallel: 1

  # Same as '--sbom-sources'
  # Default is empty
  sbom-sources: 
    - oci
    - rekor

  # Same as '--rekor-url'
  # Default is 'https://rekor.sigstore.dev'
  rekor-url: https://rekor.sigstore.dev

  # Same as '--include-dev-deps'
  # Default is false
  include-dev-deps: false
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
    # Same as '--redis-tls'
    # Default is false
    tls:    
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
  # Same as '--no-progress'
  # Default is false
  no-progress: false
  
  # Same as '--skip-db-update'
  # Default is false
  skip-update: false

  # Same as '--db-repository'
  # Default is 'ghcr.io/aquasecurity/trivy-db:2'
  repository: ghcr.io/aquasecurity/trivy-db:2

  # Same as '--skip-java-db-update'
  # Default is false
  java-skip-update: false  

  # Same as '--java-db-repository'
  # Default is 'ghcr.io/aquasecurity/trivy-java-db:1'
  java-repository: ghcr.io/aquasecurity/trivy-java-db:1
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

  # Same as '--image-src'
  # Default is 'docker,containerd,podman,remote'
  source:
    - podman
    - docker
      
  # Same as '--image-config-scanners'
  # Default is empty
  image-config-scanners:
    - misconfig
    - secret      
  
  docker:
    # Same as '--docker-host'
    # Default is empty
    host: 
  
  podman:
    # Same as '--podman-host'
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

  # Same as '--ignore-unfixed'
  # Default is empty
  ignore-status: 
    - end_of_life
```

## License Options
Available with license scanning

```yaml
license:
  # Same as '--license-full'
  # Default is false
  full: false

  # Same as '--ignored-licenses'
  # Default is empty
  ignored:
    - MPL-2.0
    - MIT

  # Same as '--license-confidence-level'
  # Default is 0.9
  confidenceLevel: 0.9

  # Set list of forbidden licenses
  # Default is https://github.com/aquasecurity/trivy/blob/164b025413c5fb9c6759491e9a306b46b869be93/pkg/licensing/category.go#L171
  forbidden:
    - AGPL-1.0
    - AGPL-3.0

  # Set list of restricted licenses
  # Default is https://github.com/aquasecurity/trivy/blob/164b025413c5fb9c6759491e9a306b46b869be93/pkg/licensing/category.go#L199
  restricted:
    - AGPL-1.0
    - AGPL-3.0

  # Set list of reciprocal licenses
  # Default is https://github.com/aquasecurity/trivy/blob/164b025413c5fb9c6759491e9a306b46b869be93/pkg/licensing/category.go#L238
  reciprocal:
    - AGPL-1.0
    - AGPL-3.0

  # Set list of notice licenses
  # Default is https://github.com/aquasecurity/trivy/blob/164b025413c5fb9c6759491e9a306b46b869be93/pkg/licensing/category.go#L260
  notice:
    - AGPL-1.0
    - AGPL-3.0  

  # Set list of permissive licenses
  # Default is empty
  permissive:
    - AGPL-1.0
    - AGPL-3.0  

  # Set list of unencumbered licenses
  # Default is https://github.com/aquasecurity/trivy/blob/164b025413c5fb9c6759491e9a306b46b869be93/pkg/licensing/category.go#L334
  unencumbered:
    - AGPL-1.0
    - AGPL-3.0    
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
rego:
  # Same as '--trace'
  # Default is false
  trace: false

  # Same as '--skip-policy-update'
  # Default is false
  skip-policy-update: false

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
  
  # Same as '--include-deprecated-checks'
  # Default is false
  include-deprecated-checks: false

  # Same as '--check-bundle-repository' and '--policy-bundle-repository'
  # Default is 'ghcr.io/aquasecurity/trivy-checks:0'
  check-bundle-repository: ghcr.io/aquasecurity/trivy-checks:0  
  
  # Same as '--miconfig-scanners'
  # Default is all scanners
  scanners:
    - dockerfile
    - terraform

  # helm value override configurations
  helm:
    # set individual values
    set:
      - securityContext.runAsUser=10001

    # set values with file
    values:
      - overrides.yaml

    # set specific values from specific files
    set-file:
      - image=dev-overrides.yaml

    # set as string and preserve type
    set-string:
      - name=true

    # Available API versions used for Capabilities.APIVersions. This flag is the same as the api-versions flag of the helm template command.
    api-versions:
      - policy/v1/PodDisruptionBudget
      - apps/v1/Deployment

    # Kubernetes version used for Capabilities.KubeVersion. This flag is the same as the kube-version flag of the helm template command.
    kube-version: "v1.21.0"

  # terraform tfvars overrrides
  terraform:
    vars:
      - dev-terraform.tfvars
      - common-terraform.tfvars
  
    # Same as '--tf-exclude-downloaded-modules'
    # Default is false
    exclude-downloaded-modules: false

    # Same as '--cf-params'
    # Default is false
  cloudformation:
    params:
      - params.json
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

  # Same as '--kubeconfig'
  # Default is empty
  kubeconfig: ~/.kube/config2

  # Same as '--components'
  # Default is 'workload,infra'
  components: 
    - workload
    - infra

  # Same as '--k8s-version'
  # Default is empty
  k8s-version: 1.21.0

  # Same as '--tolerations'
  # Default is empty
  tolerations:
    - key1=value1:NoExecute
    - key2=value2:NoSchedule

  # Same as '--all-namespaces'
  # Default is false
  all-namespaces: false

  node-collector:
    # Same as '--node-collector-namespace'
    # Default is 'trivy-temp'
    namespace: ~/.kube/config2

    # Same as '--node-collector-imageref'
    # Default is 'ghcr.io/aquasecurity/node-collector:0.0.9'
    imageref: ghcr.io/aquasecurity/node-collector:0.0.9

  exclude:
    # Same as '--exclude-owned'
    # Default is false
    owned: true

    # Same as '--exclude-nodes'
    # Default is empty
    nodes:
      - kubernetes.io/arch:arm64
      - team:dev

  # Same as '--qps'
  # Default is 5.0
  qps: 5.0

  # Same as '--burst'
  # Default is 10
  burst: 10
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

    # the aws specific services
    service: 
      - s3
      - ec2
        
    # the aws specific arn
    arn: arn:aws:s3:::example-bucket      

    # skip the aws specific services
    skip-service:
      - s3
      - ec2 
```

## Module Options
Available for modules

```yaml
module:
  # Same as '--module-dir'
  # Default is '$HOME/.trivy/modules'
  dir: $HOME/.trivy/modules

  # Same as '--enable-modules'
  # Default is empty
  enable-modules: 
    - trivy-module-spring4shell
    - trivy-module-wordpress
```

[example]: https://github.com/aquasecurity/trivy/tree/{{ git.tag }}/examples/trivy-conf/trivy.yaml
