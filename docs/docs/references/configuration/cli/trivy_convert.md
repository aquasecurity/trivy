## trivy convert

Convert Trivy JSON report into a different format

```
trivy convert [flags] RESULT_JSON
```

### Examples

```
  # report conversion
  $ trivy image --format json --output result.json --list-all-pkgs debian:11
  $ trivy convert --format cyclonedx --output result.cdx result.json

```

### Options

```
      --compliance string      compliance report to generate
      --dependency-tree        [EXPERIMENTAL] show dependency origin tree of vulnerable packages
      --exit-code int          specify exit code when any security issues are found
      --exit-on-eol int        exit with the specified code when the OS reaches end of service/life
  -f, --format string          format (table,json,template,sarif,cyclonedx,spdx,spdx-json,github,cosign-vuln) (default "table")
  -h, --help                   help for convert
      --ignore-policy string   specify the Rego file path to evaluate each vulnerability
      --ignorefile string      specify .trivyignore file (default ".trivyignore")
      --list-all-pkgs          enabling the option will output all packages regardless of vulnerability
  -o, --output string          output file name
      --report string          specify a report format for the output (all,summary) (default "all")
  -s, --severity strings       severities of security issues to be displayed (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL) (default [UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL])
  -t, --template string        output template
```

### Options inherited from parent commands

```
      --cache-dir string          cache directory (default "/path/to/cache")
  -c, --config string             config path (default "trivy.yaml")
  -d, --debug                     debug mode
      --generate-default-config   write the default config to trivy-default.yaml
      --insecure                  allow insecure server connections
  -q, --quiet                     suppress progress bar and log output
      --timeout duration          timeout (default 5m0s)
  -v, --version                   show version
```

### SEE ALSO

* [trivy](trivy.md)	 - Unified security scanner

