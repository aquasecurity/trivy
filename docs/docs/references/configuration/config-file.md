# Config file

Trivy can be customized by tweaking a `trivy.yaml` file.
The config path can be overridden by the `--config` flag.

An example is [here][example].

These samples contain default values for flags.
## Global options

```yaml
cache:
  # Same as '--cache-dir'
  dir: "/path/to/cache"

# Same as '--debug'
debug: false

# Same as '--insecure'
insecure: false

# Same as '--quiet'
quiet: false

# Same as '--timeout'
timeout: 5m0s

```
## Cache options

```yaml
cache:
  # Same as '--cache-backend'
  backend: "fs"

  redis:
    # Same as '--redis-ca'
    ca: ""

    # Same as '--redis-cert'
    cert: ""

    # Same as '--redis-key'
    key: ""

    # Same as '--redis-tls'
    tls: false

  # Same as '--cache-ttl'
  ttl: 0s

```
## Clean options

```yaml
clean:
  # Same as '--all'
  all: false

  # Same as '--checks-bundle'
  checks-bundle: false

  # Same as '--java-db'
  java-db: false

  # Same as '--scan-cache'
  scan-cache: false

  # Same as '--vex-repo'
  vex-repo: false

  # Same as '--vuln-db'
  vuln-db: false

```
## Client/Server options

```yaml
server:
  # Same as '--server'
  addr: ""

  # Same as '--custom-headers'
  custom-headers: []

  # Same as '--listen'
  listen: "localhost:4954"

  # Same as '--token'
  token: ""

  # Same as '--token-header'
  token-header: "Trivy-Token"

```
## DB options

```yaml
db:
  # Same as '--download-java-db-only'
  download-java-only: false

  # Same as '--download-db-only'
  download-only: false

  # Same as '--java-db-repository'
  java-repository:
   - mirror.gcr.io/aquasec/trivy-java-db:1
   - ghcr.io/aquasecurity/trivy-java-db:1

  # Same as '--skip-java-db-update'
  java-skip-update: false

  # Same as '--no-progress'
  no-progress: false

  # Same as '--db-repository'
  repository:
   - mirror.gcr.io/aquasec/trivy-db:2
   - ghcr.io/aquasecurity/trivy-db:2

  # Same as '--skip-db-update'
  skip-update: false

```
## Image options

```yaml
image:
  docker:
    # Same as '--docker-host'
    host: ""

  # Same as '--image-config-scanners'
  image-config-scanners: []

  # Same as '--input'
  input: ""

  # Same as '--platform'
  platform: ""

  podman:
    # Same as '--podman-host'
    host: ""

  # Same as '--removed-pkgs'
  removed-pkgs: false

  # Same as '--image-src'
  source:
   - docker
   - containerd
   - podman
   - remote

```
## Kubernetes options

```yaml
kubernetes:
  # Same as '--burst'
  burst: 10

  # Same as '--disable-node-collector'
  disableNodeCollector: false

  exclude:
    # Same as '--exclude-nodes'
    nodes: []

    # Same as '--exclude-owned'
    owned: false

  # Same as '--exclude-kinds'
  excludeKinds: []

  # Same as '--exclude-namespaces'
  excludeNamespaces: []

  # Same as '--include-kinds'
  includeKinds: []

  # Same as '--include-namespaces'
  includeNamespaces: []

  # Same as '--k8s-version'
  k8s-version: ""

  # Same as '--kubeconfig'
  kubeconfig: ""

  node-collector:
    # Same as '--node-collector-imageref'
    imageref: "ghcr.io/aquasecurity/node-collector:0.3.1"

    # Same as '--node-collector-namespace'
    namespace: "trivy-temp"

  # Same as '--qps'
  qps: 5

  # Same as '--skip-images'
  skipImages: false

  # Same as '--tolerations'
  tolerations: []

```
## License options

```yaml
license:
  # Same as '--license-confidence-level'
  confidenceLevel: 0.9

  forbidden:
   - AGPL-1.0
   - AGPL-3.0
   - CC-BY-NC-1.0
   - CC-BY-NC-2.0
   - CC-BY-NC-2.5
   - CC-BY-NC-3.0
   - CC-BY-NC-4.0
   - CC-BY-NC-ND-1.0
   - CC-BY-NC-ND-2.0
   - CC-BY-NC-ND-2.5
   - CC-BY-NC-ND-3.0
   - CC-BY-NC-ND-4.0
   - CC-BY-NC-SA-1.0
   - CC-BY-NC-SA-2.0
   - CC-BY-NC-SA-2.5
   - CC-BY-NC-SA-3.0
   - CC-BY-NC-SA-4.0
   - Commons-Clause
   - Facebook-2-Clause
   - Facebook-3-Clause
   - Facebook-Examples
   - WTFPL

  # Same as '--license-full'
  full: false

  # Same as '--ignored-licenses'
  ignored: []

  notice:
   - AFL-1.1
   - AFL-1.2
   - AFL-2.0
   - AFL-2.1
   - AFL-3.0
   - Apache-1.0
   - Apache-1.1
   - Apache-2.0
   - Artistic-1.0-cl8
   - Artistic-1.0-Perl
   - Artistic-1.0
   - Artistic-2.0
   - BSL-1.0
   - BSD-2-Clause-FreeBSD
   - BSD-2-Clause-NetBSD
   - BSD-2-Clause
   - BSD-3-Clause-Attribution
   - BSD-3-Clause-Clear
   - BSD-3-Clause-LBNL
   - BSD-3-Clause
   - BSD-4-Clause
   - BSD-4-Clause-UC
   - BSD-Protection
   - CC-BY-1.0
   - CC-BY-2.0
   - CC-BY-2.5
   - CC-BY-3.0
   - CC-BY-4.0
   - FTL
   - ISC
   - ImageMagick
   - Libpng
   - Lil-1.0
   - Linux-OpenIB
   - LPL-1.02
   - LPL-1.0
   - MS-PL
   - MIT
   - NCSA
   - OpenSSL
   - PHP-3.01
   - PHP-3.0
   - PIL
   - Python-2.0
   - Python-2.0-complete
   - PostgreSQL
   - SGI-B-1.0
   - SGI-B-1.1
   - SGI-B-2.0
   - Unicode-DFS-2015
   - Unicode-DFS-2016
   - Unicode-TOU
   - UPL-1.0
   - W3C-19980720
   - W3C-20150513
   - W3C
   - X11
   - Xnet
   - Zend-2.0
   - zlib-acknowledgement
   - Zlib
   - ZPL-1.1
   - ZPL-2.0
   - ZPL-2.1

  permissive: []

  reciprocal:
   - APSL-1.0
   - APSL-1.1
   - APSL-1.2
   - APSL-2.0
   - CDDL-1.0
   - CDDL-1.1
   - CPL-1.0
   - EPL-1.0
   - EPL-2.0
   - FreeImage
   - IPL-1.0
   - MPL-1.0
   - MPL-1.1
   - MPL-2.0
   - Ruby

  restricted:
   - BCL
   - CC-BY-ND-1.0
   - CC-BY-ND-2.0
   - CC-BY-ND-2.5
   - CC-BY-ND-3.0
   - CC-BY-ND-4.0
   - CC-BY-SA-1.0
   - CC-BY-SA-2.0
   - CC-BY-SA-2.5
   - CC-BY-SA-3.0
   - CC-BY-SA-4.0
   - GPL-1.0
   - GPL-2.0
   - GPL-2.0-with-autoconf-exception
   - GPL-2.0-with-bison-exception
   - GPL-2.0-with-classpath-exception
   - GPL-2.0-with-font-exception
   - GPL-2.0-with-GCC-exception
   - GPL-3.0
   - GPL-3.0-with-autoconf-exception
   - GPL-3.0-with-GCC-exception
   - LGPL-2.0
   - LGPL-2.1
   - LGPL-3.0
   - NPL-1.0
   - NPL-1.1
   - OSL-1.0
   - OSL-1.1
   - OSL-2.0
   - OSL-2.1
   - OSL-3.0
   - QPL-1.0
   - Sleepycat

  unencumbered:
   - CC0-1.0
   - Unlicense
   - 0BSD

```
## Misconfiguration options

```yaml
misconfiguration:
  # Same as '--checks-bundle-repository'
  checks-bundle-repository: "mirror.gcr.io/aquasec/trivy-checks:1"

  cloudformation:
    # Same as '--cf-params'
    params: []

  # Same as '--config-file-schemas'
  config-file-schemas: []

  helm:
    # Same as '--helm-api-versions'
    api-versions: []

    # Same as '--helm-kube-version'
    kube-version: ""

    # Same as '--helm-set'
    set: []

    # Same as '--helm-set-file'
    set-file: []

    # Same as '--helm-set-string'
    set-string: []

    # Same as '--helm-values'
    values: []

  # Same as '--include-non-failures'
  include-non-failures: false

  # Same as '--misconfig-scanners'
  scanners:
   - azure-arm
   - cloudformation
   - dockerfile
   - helm
   - kubernetes
   - terraform
   - terraformplan-json
   - terraformplan-snapshot

  terraform:
    # Same as '--tf-exclude-downloaded-modules'
    exclude-downloaded-modules: false

    # Same as '--tf-vars'
    vars: []

```
## Module options

```yaml
module:
  # Same as '--module-dir'
  dir: "$HOME/.trivy/modules"

  # Same as '--enable-modules'
  enable-modules: []

```
## Package options

```yaml
pkg:
  # Same as '--include-dev-deps'
  include-dev-deps: false

  # Same as '--pkg-relationships'
  relationships:
   - unknown
   - root
   - workspace
   - direct
   - indirect

  # Same as '--pkg-types'
  types:
   - os
   - library

```
## Registry options

```yaml
registry:
  # Same as '--password'
  password: []

  # Same as '--password-stdin'
  password-stdin: false

  # Same as '--registry-token'
  token: ""

  # Same as '--username'
  username: []

```
## Rego options

```yaml
rego:
  # Same as '--config-check'
  check: []

  # Same as '--config-data'
  data: []

  # Same as '--include-deprecated-checks'
  include-deprecated-checks: false

  # Same as '--check-namespaces'
  namespaces: []

  # Same as '--skip-check-update'
  skip-check-update: false

  # Same as '--trace'
  trace: false

```
## Report options

```yaml
# Same as '--dependency-tree'
dependency-tree: false

# Same as '--exit-code'
exit-code: 0

# Same as '--exit-on-eol'
exit-on-eol: 0

# Same as '--format'
format: "table"

# Same as '--ignore-policy'
ignore-policy: ""

# Same as '--ignorefile'
ignorefile: ".trivyignore"

# Same as '--list-all-pkgs'
list-all-pkgs: false

# Same as '--output'
output: ""

# Same as '--output-plugin-arg'
output-plugin-arg: ""

# Same as '--report'
report: "all"

scan:
  # Same as '--compliance'
  compliance: ""

  # Same as '--show-suppressed'
  show-suppressed: false

# Same as '--severity'
severity:
 - UNKNOWN
 - LOW
 - MEDIUM
 - HIGH
 - CRITICAL

# Same as '--template'
template: ""

```
## Repository options

```yaml
repository:
  # Same as '--branch'
  branch: ""

  # Same as '--commit'
  commit: ""

  # Same as '--tag'
  tag: ""

```
## Scan options

```yaml
scan:
  # Same as '--detection-priority'
  detection-priority: "precise"

  # Same as '--distro'
  distro: ""

  # Same as '--file-patterns'
  file-patterns: []

  # Same as '--offline-scan'
  offline: false

  # Same as '--parallel'
  parallel: 5

  # Same as '--rekor-url'
  rekor-url: "https://rekor.sigstore.dev"

  # Same as '--sbom-sources'
  sbom-sources: []

  # Same as '--scanners'
  scanners:
   - vuln
   - secret

  # Same as '--skip-dirs'
  skip-dirs: []

  # Same as '--skip-files'
  skip-files: []

```
## Secret options

```yaml
secret:
  # Same as '--secret-config'
  config: "trivy-secret.yaml"

```
## Vulnerability options

```yaml
vulnerability:
  # Same as '--ignore-status'
  ignore-status: []

  # Same as '--ignore-unfixed'
  ignore-unfixed: false

  # Same as '--skip-vex-repo-update'
  skip-vex-repo-update: false

  # Same as '--vex'
  vex: []

```
[example]: https://github.com/aquasecurity/trivy/tree/{{ git.tag }}/examples/trivy-conf/trivy.yaml