{{- /* Template based on https://github.com/codeclimate/platform/blob/master/spec/analyzers/SPEC.md#data-types */ -}}
[
  {{- $t_first := true }}
  {{- range . }}
  {{- $target := .Target }}
    {{- range .Vulnerabilities -}}
    {{- if $t_first -}}
      {{- $t_first = false -}}
    {{ else -}}
      ,
    {{- end }}
    {
      "type": "issue",
      "check_name": "container_scanning",
      "categories": [ "Security" ],
      "description": "{{ .VulnerabilityID }}: {{ .Title }}",
      "content": {{ .Description | printf "%q" }},
      "severity": {{ if eq .Severity "LOW" -}}
                    "info"
                  {{- else if eq .Severity "MEDIUM" -}}
                    "minor"
                  {{- else if eq .Severity "HIGH" -}}
                    "major"
                  {{- else if eq .Severity "CRITICAL" -}}
                    "critical"
                  {{-  else -}}
                    "info"
                  {{- end }},
      "location": {
        "path": "{{ .PkgName }}-{{ .InstalledVersion }}",
        "lines": {
          "begin": 1
        }
      }
    }
    {{- end -}}
  {{- end }}
]