##  Trivy Report:
{{- if . }}
__Target:__ {{ escapeXML ( index . 0 ).Target }}
__Date:__ {{ now }}
***
      {{- range . }}
            {{- if (gt (len (.Type | toString | escapeXML)) 0) }}

### {{ .Type | toString | escapeXML }}
#### Vulnerabilities:
                  {{- if (eq (len .Vulnerabilities) 0) }}
      No Unfixed Vulnerabilities found.
                  {{- else }}
| Severity | Package Name | VulnerabilityID | InstalledVersion | FixedVersion |
| --- | --- | --- | --- | --- |
                        {{- range .Vulnerabilities }}
| {{ escapeXML .Vulnerability.Severity }}| {{ escapeXML .PkgName }}| {{ escapeXML .VulnerabilityID }}| {{ escapeXML .InstalledVersion }}| {{ escapeXML .FixedVersion }}|
                        {{- end }}
                  {{- end }}
#### Misconfigurations:                  
                  {{- if (eq (len .Misconfigurations ) 0) }}
      No Unfixed Misconfigurations found.
                  {{- else }}
| Severity | Type | ID | Title | Message |
| --- | --- | --- | --- | --- |
                        {{- range .Misconfigurations }}
| {{ escapeXML .Severity }}| {{ escapeXML .Type }}| {{ escapeXML .ID }}| {{ escapeXML .Title }}| {{ escapeXML .Message }}|
                        {{- end }}
                  {{- end }}
            {{- end }}
      {{- end }}
{{- else }}
Trivy returned empty report
{{- end }}
