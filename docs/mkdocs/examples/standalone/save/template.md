```
$ trivy image --format template --template "{{ range . }} {{ .Target }} {{ end }}" golang:1.12-alpine
```
<details>
<summary>Result</summary>

```
2020-01-02T18:02:32.856+0100    INFO    Detecting Alpine vulnerabilities...
 golang:1.12-alpine (alpine 3.10.2)
```
</details>

You can compute different figures within the template using [sprig][sprig] functions. 
As an example you can summarize the different classes of issues:

```
$ trivy image --format template --template '{{- $critical := 0 }}{{- $high := 0 }}{{- range . }}{{- range .Vulnerabilities }}{{- if  eq .Severity "CRITICAL" }}{{- $critical = add $critical 1 }}{{- end }}{{- if  eq .Severity "HIGH" }}{{- $high = add $high 1 }}{{- end }}{{- end }}{{- end }}Critical: {{ $critical }}, High: {{ $high }}' golang:1.12-alpine
```
<details>
<summary>Result</summary>

```
Critical: 0, High: 2
```
</details>

For other features of sprig, see the official [sprig][sprig] documentation.

You can load templates from a file prefixing the template path with an @.

```
$ trivy image --format template --template "@/path/to/template" golang:1.12-alpine
```

In the following example using the template `junit.tpl` XML can be generated.
```
$ trivy image --format template --template "@contrib/junit.tpl" -o junit-report.xml  golang:1.12-alpine
```

In the following example using the template `sarif.tpl` [Sarif][sarif] can be generated.
```
$ trivy image --format template --template "@contrib/sarif.tpl" -o report.sarif  golang:1.12-alpine
```
This SARIF format can be uploaded to GitHub code scanning results, and there is a [Trivy GitHub Action][action] for automating this process.

Trivy also supports an [ASFF template for reporting findings to AWS Security Hub][asff]

[action]: https://github.com/aquasecurity/trivy-action
[asff]: https://github.com/aquasecurity/trivy/tree/main/docs/integration/security-hub.md
[sarif]: https://docs.github.com/en/github/finding-security-vulnerabilities-and-errors-in-your-code/managing-results-from-code-scanning
[sprig]: http://masterminds.github.io/sprig/
