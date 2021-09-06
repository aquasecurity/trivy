"Target","Vulnerability Class","Target Type","Vulnerability ID","Severity","PackageName","Installed Version","Fixed Version","Title","Description","Resolution","Reference","Additional Reference","CVSS V3 Score","CVSS V3 Vector"
{{ range . }}
{{- $target := .Target }}
{{- $class := .Class }}
{{- $vulnerabilityType := .Type }}
{{- if (and (eq (len .Vulnerabilities) 0) (eq (len .Misconfigurations) 0)) -}}
	{{- $target | escapeCsv }},{{ printf "%s" $class | escapeCsv }},{{ $vulnerabilityType | escapeCsv }},"","","","","","","","","","","",""
{{ else }}
{{- range .Vulnerabilities }}
	{{- $target | escapeCsv }},
	{{- printf "%s" $class | escapeCsv }},
	{{- $vulnerabilityType | escapeCsv }},
	{{- .VulnerabilityID | escapeCsv }},
	{{- .Vulnerability.Severity | escapeCsv }},
	{{- .PkgName | escapeCsv }},
	{{- .InstalledVersion | escapeCsv }},
	{{- .FixedVersion | escapeCsv }},
	{{- if (eq (len .Title) 0) }}
		{{- printf "%s: %s - %s severity vulnerability" .PkgName .InstalledVersion .Vulnerability.Severity | escapeCsv }}
	{{- else }}
		{{- abbrev 100 .Title | escapeCsv }}
	{{- end }},
	{{- abbrev 500 .Vulnerability.Description | escapeCsv }},
	{{- if .FixedVersion }}
		{{- printf "Update %s to version %s or higher." .PkgName .FixedVersion | escapeCsv }}
	{{- else }}
		{{- printf "No resolution provided." | escapeCsv }}
	{{- end }},
	{{- .PrimaryURL | escapeCsv }},
	{{- $reference := false }}
	{{- range .References }}
		{{- if contains "nvd.nist.gov" . }}
			{{- . | escapeCsv }}
			{{- $reference = true }}
		{{- end }}
	{{- end }}
	{{- if not $reference }}
		{{- printf "" | escapeCsv }}
	{{- end }},
	{{- $cvss := (index .CVSS "nvd").V3Score -}}
	{{- $cvssRH := (index .CVSS "redhat").V3Score -}}
	{{- if $cvss }}
		{{- $cvss | printf "%.1f" | escapeCsv  -}},
		{{- (index .CVSS "nvd").V3Vector | escapeCsv }}
	{{- else if $cvssRH }}
		{{- $cvssRH | printf "%.1f" | escapeCsv -}},
		{{- (index .CVSS "redhat").V3Vector | escapeCsv }}
	{{- else }}
		{{- printf "" | escapeCsv }},
		{{- printf "" | escapeCsv }}
	{{- end }}
{{ end }}
{{- range .Misconfigurations }}
	{{- $target | escapeCsv }},
	{{- printf "%s" $class | escapeCsv }},
	{{- $vulnerabilityType | escapeCsv }},
	{{- .ID | escapeCsv }},
	{{- .Severity | escapeCsv }},"","","",
	{{- abbrev 100 .Title | escapeCsv }},
	{{- printf "%s - %s" .Description .Message | abbrev 500 | escapeCsv }},
	{{- .Resolution | escapeCsv }},
	{{- .PrimaryURL | escapeCsv }},
	{{- $reference := false }}
	{{- range .References }}
		{{- if contains "docs.docker.com" . }}
			{{- . | escapeCsv }}
			{{- $reference = true }}
		{{- end }}
	{{- end }}
	{{- if not $reference }}
		{{- printf "" | escapeCsv }}
	{{- end }},"",""
{{ end }}
{{- end }}
{{- end -}}
