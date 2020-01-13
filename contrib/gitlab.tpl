{{- /* Template based on https://docs.gitlab.com/ee/user/application_security/container_scanning/#reports-json-format */}}
{
"version": "2.3",
{{- range . }}
{{- $target := .Target }}
"vulnerabilities": [
    {{- $first := true}}
    {{- range .Vulnerabilities -}}
    {{- if $first -}}
      {{- $first = false -}}
    {{else -}}
,
    {{- end}}
    {
      "category": "container_scanning",
      "message": {{ .Title | printf "%q" }},
      "description": {{ .Description | printf "%q"}},
      "cve": "{{ .VulnerabilityID }}",
      "severity": {{ if eq .Severity "UNKNOWN" -}}
                    "Unknown"
                {{else if eq .Severity "LOW" -}}
                    "Low"
                {{else if eq .Severity "MEDIUM" -}}
                    "Medium"
                {{else if eq .Severity "HIGH" -}}
                    "High"
                {{else if eq .Severity "CRITICAL" -}}
                    "Critical"
                {{ else -}}
                "{{ .Severity }}"
                {{- end }},
      "confidence": "Unknown",
      "solution": {{ if .FixedVersion -}}
                  "Upgrade {{ .PkgName }} to {{ .FixedVersion }}",
                  {{- else -}}
                  "No solution provided",
                  {{- end }}
      "scanner": {
        "id": "trivy",
        "name": "trivy"
      },
      "location": {
        "dependency": {
          "package": {
            "name": "{{ .PkgName }}"
       },
            "version": "{{ .InstalledVersion }}"
        },
    {{- /* TODO: No mapping available - https://github.com/aquasecurity/trivy/issues/332 */}}
    "operating_system": "Unknown",
    "image": "{{ $target }}"
      },
      "identifiers": [
          {
	  {{- /* TODO: Type not extractable - https://github.com/aquasecurity/trivy-db/pull/24 */}}
          "type": "cve",
          "name": "{{ .VulnerabilityID }}",
          "value": "{{ .VulnerabilityID }}",
          "url": ""
          }
      ],
      "links": [
          {{ $first := true -}}
          {{- range .References -}}
          {{- if $first -}}
          {{- $first = false -}}
          {{else -}}
 ,
          {{ end -}}
      {
          "url": "{{ . }}"
      }
      {{- end }}
    ]
    }
  {{- end -}}
{{- end}}
  ],
  "remediations": []
}
