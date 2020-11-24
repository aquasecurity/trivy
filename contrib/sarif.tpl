{
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Trivy",
          "fullName": "Trivy Vulnerability Scanner",
          "rules": [
        {{- $t_first := true }}
        {{- range . }}
            {{- range .Vulnerabilities -}}
              {{- if $t_first -}}
                {{- $t_first = false -}}
              {{ else -}}
                ,
              {{- end }}
            {
              "id": "[{{ .Vulnerability.Severity }}] {{ .VulnerabilityID }}",
              "name": "dockerfile_scan",
              "shortDescription": {
                "text": {{ printf "%v Package: %v" .VulnerabilityID .PkgName | printf "%q" }}
              },
              "fullDescription": {
                "text": {{ endWithPeriod (escapeString .Title) | printf "%q" }}
              },
              "help": {
                "text": {{ printf "Vulnerability %v\nSeverity: %v\nPackage: %v\nInstalled Version: %v\nFixed Version: %v\nLink: [%v](%v)" .VulnerabilityID .Vulnerability.Severity .PkgName .InstalledVersion .FixedVersion .VulnerabilityID .PrimaryURL | printf "%q"}},
                "markdown": {{ printf "**Vulnerability %v**\n| Severity | Package | Installed Version | Fixed Version | Link |\n| --- | --- | --- | --- | --- |\n|%v|%v|%v|%v|[%v](%v)|\n" .VulnerabilityID .Vulnerability.Severity .PkgName .InstalledVersion .FixedVersion .VulnerabilityID .PrimaryURL | printf "%q"}}
              },
              "properties": {
                "tags": [
                  "vulnerability",
                  "{{ .Vulnerability.Severity }}",
                  {{ .PkgName | printf "%q" }}
                ],
                "precision": "very-high"
              }
            }
            {{- end -}}
         {{- end -}}
          ]
        }
      },
      "results": [
    {{- $t_first := true }}
    {{- range . }}
        {{- range $index, $vulnerability := .Vulnerabilities -}}
          {{- if $t_first -}}
            {{- $t_first = false -}}
          {{ else -}}
            ,
          {{- end }}
        {
          "ruleId": "[{{ $vulnerability.Vulnerability.Severity }}] {{ $vulnerability.VulnerabilityID }}",
          "ruleIndex": {{ $index }},
          "level": "error",
          "message": {
            "text": {{ endWithPeriod (escapeString $vulnerability.Description) | printf "%q" }}
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "Dockerfile"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        }
        {{- end -}}
      {{- end -}}
      ],
      "columnKind": "utf16CodeUnits"
    }
  ]
}