Target,Target Type,Vulnerability ID,Severity,PackageName,Installed Version,Fixed Version,Title,Description,Resolution,Reference,Additional Reference,CVSS V3 Score,CVSS V3 Vector
{{ range . }}
{{- $target := .Target }}
{{- $vulnerabilityType := .Type }}
{{- if (eq (len .Vulnerabilities) 0) }}
	{{- $target }},,,,,,,,,,,,,
{{- else }}
{{- range .Vulnerabilities }}
	{{- $target }},
	{{- $vulnerabilityType }},
	{{- .VulnerabilityID }},
	{{- .Vulnerability.Severity }},
	{{- .PkgName }},
	{{- .InstalledVersion }},
	{{- .FixedVersion }},
	{{- abbrev 100 .Title | printf "%q" | replace "," ";" }},
	{{- abbrev 255 .Vulnerability.Description | printf "%q" | replace "," ";" }},
	{{- if .FixedVersion }}
		{{- printf "Update %s to at least version %s." .PkgName .FixedVersion | printf "%q" }}
	{{- end }},
	{{- .PrimaryURL }},
	{{- range .References }}
		{{- if contains "nvd.nist.gov" . }}
			{{- . }}
		{{- end }}
	{{- end }},
	{{- $cvss := (index .CVSS "nvd").V3Score -}}
	{{- if $cvss -}}
		{{- $cvss | printf "%.1f" -}}
	{{- end -}},
	{{- (index .CVSS "nvd").V3Vector | printf "%q" }}
{{ end -}}
{{- end -}}
{{- end -}}
