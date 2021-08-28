Target,Vulnerability Class,Target Type,Vulnerability ID,Severity,PackageName,Installed Version,Fixed Version,Title,Description,Resolution,Reference,Additional Reference,CVSS V3 Score,CVSS V3 Vector
{{ range . }}
{{- $target := .Target }}
{{- $class := .Class }}
{{- $vulnerabilityType := .Type }}
{{- range .Vulnerabilities }}
	{{- $target }},
	{{- $class }},
	{{- $vulnerabilityType }},
	{{- .VulnerabilityID }},
	{{- .Vulnerability.Severity }},
	{{- .PkgName | replace "," ";" }},
	{{- .InstalledVersion | replace "," ";" }},
	{{- .FixedVersion | replace "," ";" }},
	{{- if (eq (len .Title) 0) }}
		{{- printf "%s: %s - %s severity vulnerability" .PkgName .InstalledVersion .Vulnerability.Severity | printf "%q" | replace "," ";" }}
	{{- else }}
		{{- abbrev 100 .Title | printf "%q" | replace "," ";" }}
	{{- end }},
	{{- abbrev 500 .Vulnerability.Description | printf "%q" | replace "," ";" }},
	{{- if .FixedVersion }}
		{{- printf "Update %s to version %s or higher." .PkgName .FixedVersion | printf "%q" }}
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
{{- range .Misconfigurations }}
	{{- $target }},
	{{- $class }},
	{{- $vulnerabilityType }},
	{{- .ID }},
	{{- .Severity }},,,,
	{{- abbrev 100 .Title | printf "%q" | replace "," ";" }},
	{{- abbrev 500 .Description | printf "%q" | replace "," ";" }},
	{{- .Resolution | printf "%q" | replace "," ";" }},
	{{- .PrimaryURL }},
	{{- range .References }}
		{{- if contains "docs.docker.com" . }}
			{{- . }}
		{{- end }}
	{{- end }},,
{{ end -}}
{{- end -}}
