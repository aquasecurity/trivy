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
      "description": {{ list .VulnerabilityID .PkgName .InstalledVersion .Title | join " - " | printf "%q" }},
      "fingerprint": "{{ list .VulnerabilityID .PkgName .InstalledVersion $target | join "" | sha1sum }}",
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
        "path": "{{ $target }}",
        "lines": {
          "begin": 0
        }
      }
    }
    {{- end -}}
    {{- range .Misconfigurations -}}
    {{- if $t_first -}}
      {{- $t_first = false -}}
    {{ else -}}
      ,
    {{- end }}
    {
      "type": "issue",
      "check_name": "container_scanning",
      "categories": [ "Security" ],
      "description": {{ list "Misconfig" .ID .Title | join " - " | printf "%q" }},
      "fingerprint": "{{ list .ID .Title $target | join "" | sha1sum }}",
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
        "path": "{{ $target }}",
        "lines": {
          "begin": {{ .CauseMetadata.StartLine }}
        }
      }
    }
    {{- end -}}
    {{- range .Secrets -}}
    {{- if $t_first -}}
      {{- $t_first = false -}}
    {{ else -}}
      ,
    {{- end }}
    {
      "type": "issue",
      "check_name": "container_scanning",
      "categories": [ "Security" ],
      "description": {{ list "Secret" .RuleID .Title | join " - " | printf "%q" }},
      "fingerprint": "{{ list .RuleID .Title $target | join "" | sha1sum }}",
      "content": {{ .Title | printf "%q" }},
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
        "path": "{{ $target }}",
        "lines": {
          "begin": {{ .StartLine }}
        }
      }
    }
    {{- end -}}
  {{- end }}
]
