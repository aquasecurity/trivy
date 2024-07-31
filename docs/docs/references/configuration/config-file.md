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

    # Same as '--redis-tls'
    # Default is false
    tls: false

  # Same as '--cache-ttl'
  # Default is 0s
  ttl: 0s

```

## Clean options

```yaml
clean:
  # Same as '--all'
  # Default is false
  all: false

  # Same as '--checks-bundle'
  # Default is false
  checks-bundle: false

  # Same as '--java-db'
  # Default is false
  java-db: false

  # Same as '--scan-cache'
  # Default is false
  scan-cache: false

  # Same as '--vex-repo'
  # Default is false
  vex-repo: false

  # Same as '--vuln-db'
  # Default is false
  vuln-db: false

```

## Client/Server options

```yaml
server:
  # Same as '--server'
  # Default is empty
  addr: 

  # Same as '--custom-headers'
  # Default is []
  custom-headers: []

  # Same as '--token'
  # Default is empty
  token: 

  # Same as '--token-header'
  # Default is Trivy-Token
  token-header: Trivy-Token

```

## DB options

```yaml
db:
  # Same as '--download-java-db-only'
  # Default is false
  download-java-only: false

  # Same as '--download-db-only'
  # Default is false
  download-only: false

  # Same as '--java-db-repository'
  # Default is ghcr.io/aquasecurity/trivy-java-db:1
  java-repository: ghcr.io/aquasecurity/trivy-java-db:1

  # Same as '--skip-java-db-update'
  # Default is false
  java-skip-update: false

  # Same as '--light'
  # Default is false
  light: false

  # Same as '--no-progress'
  # Default is false
  no-progress: false

  # Same as '--db-repository'
  # Default is ghcr.io/aquasecurity/trivy-db:2
  repository: ghcr.io/aquasecurity/trivy-db:2

  # Same as '--skip-db-update'
  # Default is false
  skip-update: false

# Same as '--reset'
# Default is false
reset: false

```

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

## Image options

```yaml
image:
  docker:
    # Same as '--docker-host'
    # Default is empty
    host: 

  # Same as '--image-config-scanners'
  # Default is []
  image-config-scanners: []

  # Same as '--input'
  # Default is empty
  input: 

  # Same as '--platform'
  # Default is empty
  platform: 

  podman:
    # Same as '--podman-host'
    # Default is empty
    host: 

  # Same as '--removed-pkgs'
  # Default is false
  removed-pkgs: false

  # Same as '--image-src'
  # Default is [docker containerd podman remote]
  source: [docker containerd podman remote]

```

## Kubernetes options

```yaml
kubernetes:
  # Same as '--burst'
  # Default is 10
  burst: 10

  # Same as '--disable-node-collector'
  # Default is false
  disableNodeCollector: false

  exclude:
    # Same as '--exclude-nodes'
    # Default is []
    nodes: []

    # Same as '--exclude-owned'
    # Default is false
    owned: false

  # Same as '--exclude-kinds'
  # Default is []
  excludeKinds: []

  # Same as '--exclude-namespaces'
  # Default is []
  excludeNamespaces: []

  # Same as '--include-kinds'
  # Default is []
  includeKinds: []

  # Same as '--include-namespaces'
  # Default is []
  includeNamespaces: []

  # Same as '--k8s-version'
  # Default is empty
  k8s-version: 

  # Same as '--kubeconfig'
  # Default is empty
  kubeconfig: 

  node-collector:
    # Same as '--node-collector-imageref'
    # Default is ghcr.io/aquasecurity/node-collector:0.3.1
    imageref: ghcr.io/aquasecurity/node-collector:0.3.1

    # Same as '--node-collector-namespace'
    # Default is trivy-temp
    namespace: trivy-temp

  # Same as '--qps'
  # Default is 5
  qps: 5

  # Same as '--skip-images'
  # Default is false
  skipImages: false

  # Same as '--tolerations'
  # Default is []
  tolerations: []

```

## License options

```yaml
license:
  # Same as '--license-confidence-level'
  # Default is 0.9
  confidenceLevel: 0.9

  # Same as '--'
  # Default is [AGPL-1.0 AGPL-3.0 CC-BY-NC-1.0 CC-BY-NC-2.0 CC-BY-NC-2.5 CC-BY-NC-3.0 CC-BY-NC-4.0 CC-BY-NC-ND-1.0 CC-BY-NC-ND-2.0 CC-BY-NC-ND-2.5 CC-BY-NC-ND-3.0 CC-BY-NC-ND-4.0 CC-BY-NC-SA-1.0 CC-BY-NC-SA-2.0 CC-BY-NC-SA-2.5 CC-BY-NC-SA-3.0 CC-BY-NC-SA-4.0 Commons-Clause Facebook-2-Clause Facebook-3-Clause Facebook-Examples WTFPL]
  forbidden: [AGPL-1.0 AGPL-3.0 CC-BY-NC-1.0 CC-BY-NC-2.0 CC-BY-NC-2.5 CC-BY-NC-3.0 CC-BY-NC-4.0 CC-BY-NC-ND-1.0 CC-BY-NC-ND-2.0 CC-BY-NC-ND-2.5 CC-BY-NC-ND-3.0 CC-BY-NC-ND-4.0 CC-BY-NC-SA-1.0 CC-BY-NC-SA-2.0 CC-BY-NC-SA-2.5 CC-BY-NC-SA-3.0 CC-BY-NC-SA-4.0 Commons-Clause Facebook-2-Clause Facebook-3-Clause Facebook-Examples WTFPL]

  # Same as '--license-full'
  # Default is false
  full: false

  # Same as '--ignored-licenses'
  # Default is []
  ignored: []

  # Same as '--'
  # Default is [AFL-1.1 AFL-1.2 AFL-2.0 AFL-2.1 AFL-3.0 Apache-1.0 Apache-1.1 Apache-2.0 Artistic-1.0-cl8 Artistic-1.0-Perl Artistic-1.0 Artistic-2.0 BSL-1.0 BSD-2-Clause-FreeBSD BSD-2-Clause-NetBSD BSD-2-Clause BSD-3-Clause-Attribution BSD-3-Clause-Clear BSD-3-Clause-LBNL BSD-3-Clause BSD-4-Clause BSD-4-Clause-UC BSD-Protection CC-BY-1.0 CC-BY-2.0 CC-BY-2.5 CC-BY-3.0 CC-BY-4.0 FTL ISC ImageMagick Libpng Lil-1.0 Linux-OpenIB LPL-1.02 LPL-1.0 MS-PL MIT NCSA OpenSSL PHP-3.01 PHP-3.0 PIL Python-2.0 Python-2.0-complete PostgreSQL SGI-B-1.0 SGI-B-1.1 SGI-B-2.0 Unicode-DFS-2015 Unicode-DFS-2016 Unicode-TOU UPL-1.0 W3C-19980720 W3C-20150513 W3C X11 Xnet Zend-2.0 zlib-acknowledgement Zlib ZPL-1.1 ZPL-2.0 ZPL-2.1]
  notice: [AFL-1.1 AFL-1.2 AFL-2.0 AFL-2.1 AFL-3.0 Apache-1.0 Apache-1.1 Apache-2.0 Artistic-1.0-cl8 Artistic-1.0-Perl Artistic-1.0 Artistic-2.0 BSL-1.0 BSD-2-Clause-FreeBSD BSD-2-Clause-NetBSD BSD-2-Clause BSD-3-Clause-Attribution BSD-3-Clause-Clear BSD-3-Clause-LBNL BSD-3-Clause BSD-4-Clause BSD-4-Clause-UC BSD-Protection CC-BY-1.0 CC-BY-2.0 CC-BY-2.5 CC-BY-3.0 CC-BY-4.0 FTL ISC ImageMagick Libpng Lil-1.0 Linux-OpenIB LPL-1.02 LPL-1.0 MS-PL MIT NCSA OpenSSL PHP-3.01 PHP-3.0 PIL Python-2.0 Python-2.0-complete PostgreSQL SGI-B-1.0 SGI-B-1.1 SGI-B-2.0 Unicode-DFS-2015 Unicode-DFS-2016 Unicode-TOU UPL-1.0 W3C-19980720 W3C-20150513 W3C X11 Xnet Zend-2.0 zlib-acknowledgement Zlib ZPL-1.1 ZPL-2.0 ZPL-2.1]

  # Same as '--'
  # Default is []
  permissive: []

  # Same as '--'
  # Default is [APSL-1.0 APSL-1.1 APSL-1.2 APSL-2.0 CDDL-1.0 CDDL-1.1 CPL-1.0 EPL-1.0 EPL-2.0 FreeImage IPL-1.0 MPL-1.0 MPL-1.1 MPL-2.0 Ruby]
  reciprocal: [APSL-1.0 APSL-1.1 APSL-1.2 APSL-2.0 CDDL-1.0 CDDL-1.1 CPL-1.0 EPL-1.0 EPL-2.0 FreeImage IPL-1.0 MPL-1.0 MPL-1.1 MPL-2.0 Ruby]

  # Same as '--'
  # Default is [BCL CC-BY-ND-1.0 CC-BY-ND-2.0 CC-BY-ND-2.5 CC-BY-ND-3.0 CC-BY-ND-4.0 CC-BY-SA-1.0 CC-BY-SA-2.0 CC-BY-SA-2.5 CC-BY-SA-3.0 CC-BY-SA-4.0 GPL-1.0 GPL-2.0 GPL-2.0-with-autoconf-exception GPL-2.0-with-bison-exception GPL-2.0-with-classpath-exception GPL-2.0-with-font-exception GPL-2.0-with-GCC-exception GPL-3.0 GPL-3.0-with-autoconf-exception GPL-3.0-with-GCC-exception LGPL-2.0 LGPL-2.1 LGPL-3.0 NPL-1.0 NPL-1.1 OSL-1.0 OSL-1.1 OSL-2.0 OSL-2.1 OSL-3.0 QPL-1.0 Sleepycat]
  restricted: [BCL CC-BY-ND-1.0 CC-BY-ND-2.0 CC-BY-ND-2.5 CC-BY-ND-3.0 CC-BY-ND-4.0 CC-BY-SA-1.0 CC-BY-SA-2.0 CC-BY-SA-2.5 CC-BY-SA-3.0 CC-BY-SA-4.0 GPL-1.0 GPL-2.0 GPL-2.0-with-autoconf-exception GPL-2.0-with-bison-exception GPL-2.0-with-classpath-exception GPL-2.0-with-font-exception GPL-2.0-with-GCC-exception GPL-3.0 GPL-3.0-with-autoconf-exception GPL-3.0-with-GCC-exception LGPL-2.0 LGPL-2.1 LGPL-3.0 NPL-1.0 NPL-1.1 OSL-1.0 OSL-1.1 OSL-2.0 OSL-2.1 OSL-3.0 QPL-1.0 Sleepycat]

  # Same as '--'
  # Default is [CC0-1.0 Unlicense 0BSD]
  unencumbered: [CC0-1.0 Unlicense 0BSD]

```

## Misconfiguration options

```yaml
misconfiguration:
  # Same as '--checks-bundle-repository'
  # Default is ghcr.io/aquasecurity/trivy-checks:0
  checks-bundle-repository: ghcr.io/aquasecurity/trivy-checks:0

  cloudformation:
    # Same as '--cf-params'
    # Default is []
    params: []

  helm:
    # Same as '--helm-api-versions'
    # Default is []
    api-versions: []

    # Same as '--helm-kube-version'
    # Default is empty
    kube-version: 

    # Same as '--helm-set'
    # Default is []
    set: []

    # Same as '--helm-set-file'
    # Default is []
    set-file: []

    # Same as '--helm-set-string'
    # Default is []
    set-string: []

    # Same as '--helm-values'
    # Default is []
    values: []

  # Same as '--include-non-failures'
  # Default is false
  include-non-failures: false

  # Same as '--reset-checks-bundle'
  # Default is false
  reset-checks-bundle: false

  # Same as '--misconfig-scanners'
  # Default is [azure-arm cloudformation dockerfile helm kubernetes terraform terraformplan-json terraformplan-snapshot]
  scanners: [azure-arm cloudformation dockerfile helm kubernetes terraform terraformplan-json terraformplan-snapshot]

  terraform:
    # Same as '--tf-exclude-downloaded-modules'
    # Default is false
    exclude-downloaded-modules: false

    # Same as '--tf-vars'
    # Default is []
    vars: []

```

## Module options

```yaml
module:
  # Same as '--module-dir'
  # Default is $HOME/.trivy/modules
  dir: $HOME/.trivy/modules

  # Same as '--enable-modules'
  # Default is []
  enable-modules: []

```

## Registry options

```yaml
registry:
  # Same as '--password'
  # Default is []
  password: []

  # Same as '--registry-token'
  # Default is empty
  token: 

  # Same as '--username'
  # Default is []
  username: []

```

## Rego options

```yaml
rego:
  # Same as '--config-check'
  # Default is []
  check: []

  # Same as '--config-data'
  # Default is []
  data: []

  # Same as '--include-deprecated-checks'
  # Default is false
  include-deprecated-checks: false

  # Same as '--check-namespaces'
  # Default is []
  namespaces: []

  # Same as '--skip-check-update'
  # Default is false
  skip-check-update: false

  # Same as '--trace'
  # Default is false
  trace: false

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
# Default is empty
ignore-policy: 

# Same as '--ignorefile'
# Default is .trivyignore
ignorefile: .trivyignore

# Same as '--list-all-pkgs'
# Default is false
list-all-pkgs: false

# Same as '--output'
# Default is empty
output: 

# Same as '--output-plugin-arg'
# Default is empty
output-plugin-arg: 

# Same as '--pkg-types'
# Default is [os library]
pkg-types: [os library]

# Same as '--report'
# Default is all
report: all

scan:
  # Same as '--compliance'
  # Default is empty
  compliance: 

  # Same as '--show-suppressed'
  # Default is false
  show-suppressed: false

# Same as '--severity'
# Default is [UNKNOWN LOW MEDIUM HIGH CRITICAL]
severity: [UNKNOWN LOW MEDIUM HIGH CRITICAL]

# Same as '--template'
# Default is empty
template: 

```

## Repository options

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

## Scan options

```yaml
scan:
  # Same as '--file-patterns'
  # Default is []
  file-patterns: []

  # Same as '--include-dev-deps'
  # Default is false
  include-dev-deps: false

  # Same as '--offline-scan'
  # Default is false
  offline: false

  # Same as '--parallel'
  # Default is 5
  parallel: 5

  # Same as '--rekor-url'
  # Default is https://rekor.sigstore.dev
  rekor-url: https://rekor.sigstore.dev

  # Same as '--sbom-sources'
  # Default is []
  sbom-sources: []

  # Same as '--scanners'
  # Default is [vuln secret]
  scanners: [vuln secret]

  # Same as '--skip-dirs'
  # Default is []
  skip-dirs: []

  # Same as '--skip-files'
  # Default is []
  skip-files: []

  # Same as '--slow'
  # Default is false
  slow: false

```

## Secret options

```yaml
secret:
  # Same as '--secret-config'
  # Default is trivy-secret.yaml
  config: trivy-secret.yaml

```

## Vulnerability options

```yaml
vulnerability:
  # Same as '--ignore-status'
  # Default is []
  ignore-status: []

  # Same as '--ignore-unfixed'
  # Default is false
  ignore-unfixed: false

  # Same as '--skip-vex-repo-update'
  # Default is false
  skip-vex-repo-update: false

  # Same as '--vex'
  # Default is []
  vex: []

```

[example]: https://github.com/aquasecurity/trivy/tree/{{ git.tag }}/examples/trivy-conf/trivy.yaml