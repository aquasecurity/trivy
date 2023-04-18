VulnerabilityID,Severity,PackageName,InstalledVersion,FixedVersion,PackagePath,Target
{{- range . }}
{{- $target := .Target -}}
{{- if (gt (len .Vulnerabilities) 0) }}
{{- range .Vulnerabilities }}
"{{- .VulnerabilityID | replace "\"" "\"\"" }}","{{- .Vulnerability.Severity | replace "\"" "\"\"" }}","{{- .PkgName | replace "\"" "\"\""}}","{{- .InstalledVersion | replace "\"" "\"\"" }}","{{- .FixedVersion | replace "\"" "\"\"" }}","{{- .PkgPath | replace "\"" "\"\"" }}","{{- $target | replace "\"" "\"\"" }}",{{- end }}
{{- end -}}
{{- end }}
