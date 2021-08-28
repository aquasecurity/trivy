"Target","Target Type","Vulnerability ID","Severity","PackageName","Installed Version","Fixed Version","Title","Description","Resolution","Reference","Additional Reference","CVSS V3 Score","CVSS V3 Vector"
{{ range . }}
{{- $target := .Target }}
{{- $vulnerabilityType := .Type }}
{{- range .Vulnerabilities }}
	{{- $target | printf "%q" }},
	{{- $vulnerabilityType | printf "%q" }},
	{{- .VulnerabilityID | printf "%q" }},
	{{- .Vulnerability.Severity | printf "%q" }},
	{{- .PkgName | printf "%q" }},
	{{- .InstalledVersion | printf "%q" }},
	{{- .FixedVersion | printf "%q" }},
	{{- .Title | printf "%q" | replace "," ";" }},
	{{- .Vulnerability.Description | printf "%q" | replace "," ";" }},
	{{- if .FixedVersion }}
		{{- printf "Update %s to at least version %s" .PkgName .FixedVersion | printf "%q" }}
	{{- end }},
	{{- .PrimaryURL | printf "%q" }},
	{{- range .References }}
		{{- if contains "nvd.nist.gov" . }}
			{{- . | printf "%q" }}
		{{- end }}
	{{- end }},
	{{- $cvss := (index .CVSS "nvd").V3Score -}}
	{{- if $cvss -}}
		{{- $cvss | printf "\"%.1f\"" -}}
	{{- end -}},
	{{- (index .CVSS "nvd").V3Vector | printf "%q" }}
{{ end -}}
{{- range .Misconfigurations }}
	{{- $target | printf "%q" }},
	{{- $vulnerabilityType | printf "%q" }},
	{{- .ID | printf "%q" }},
	{{- .Severity | printf "%q" }},,,,
	{{- .Title | printf "%q" | replace "," ";" }},
	{{- .Description | printf "%q" | replace "," ";" }},
	{{- .Resolution | printf "%q" | replace "," ";" }},
	{{- .PrimaryURL | printf "%q" }},
	{{- range .References }}
		{{- if contains "docs.docker.com" . }}
			{{- . | printf "%q" }}
		{{- end }}
	{{- end }},,
{{ end -}}
{{- end -}}
