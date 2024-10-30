#  Trivy Report:
{{- if . }}
**Target:** {{- escapeXML ( index . 0 ).Target }}
**Date:** {{- now }}
***
    {{- range . }}
## {{ .Type | toString | escapeXML }}
      {{- if (eq (len .Vulnerabilities) 0) }}
### Vulnerabilities:
      No Unfixed Vulnerabilities found.
      {{- else }}
### Vulnerabilities:
| Severity | Package Name | VulnerabilityID | InstalledVersion | FixedVersion |
| --- | --- | --- | --- | --- |
        {{- range .Vulnerabilities }}
| {{ escapeXML .Vulnerability.Severity }}| {{ escapeXML .PkgName }}| {{ escapeXML .VulnerabilityID }}| {{ escapeXML .InstalledVersion }}| {{ escapeXML .FixedVersion }}|
      {{- end }}
      {{- end }}

      {{- if (eq (len .Misconfigurations ) 0) }}
### Misconfigurations:
      No Unfixed Misconfigurations found.
      {{- else }}
### Misconfigurations:
| Severity | Type | ID | Title | Message |
| --- | --- | --- | --- | --- |
        {{- range .Misconfigurations }}
| {{ escapeXML .Severity }}| {{ escapeXML .Type }}| {{ escapeXML .ID }}| {{ escapeXML .Title }}| {{ escapeXML .Message }}|
        {{- end }}
      {{- end }}
      {{- end }}
{{- else }}
Trivy returned empty report
{{- end }}

