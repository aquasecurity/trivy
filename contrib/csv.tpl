Target,PackageName,VulnerabilityID,Severity,InstalledVersion,FixedVersion,PackagePath
{{- range . }}
{{- $target := .Target -}}
{{- if (gt (len .Vulnerabilities) 0) }}
{{- range .Vulnerabilities }}
"{{- $target | replace "\"" "\"\"" }}","{{- .PkgName | replace "\"" "\"\""}}","{{- .VulnerabilityID | replace "\"" "\"\"" }}","{{- .Vulnerability.Severity | replace "\"" "\"\"" }}","{{- .InstalledVersion | replace "\"" "\"\"" }}","{{- .FixedVersion | replace "\"" "\"\"" }}","{{- .PkgPath | replace "\"" "\"\"" }}",{{- end }}
{{- end -}}
{{- end }}
