Image,PackageName,VulnerabilityID,Severity,Score,InstalledVersion,FixedVersion,Title
{{ range . }}
{{- $target := .Target -}}
{{- if (eq (len .Vulnerabilities) 0) }}
    {{- $target }},,,,,,,
{{- else }}
{{- range .Vulnerabilities }}
    {{- $description := .Title }}
    {{- if not $description }}
        {{- $description = .Description -}}
        {{- if gt (len $description ) 150 -}}
            {{- $description = (slice $description 0 150) | printf "%v..." -}}
        {{- end}}
    {{- end }}
    {{- $target }},
    {{- .PkgName }},
    {{- .VulnerabilityID }},
    {{- .Vulnerability.Severity }},
    {{- $score := (index .CVSS "nvd").V3Score -}}
    {{- if not $score -}}
        {{- $score = (index .CVSS "redhat").V3Score -}}
    {{- end -}}
    {{- $score }},
    {{- .InstalledVersion }},
    {{- .FixedVersion }},
    {{- replace "," ";" $description }}
{{ end }}
{{ end -}}
{{- end }}
