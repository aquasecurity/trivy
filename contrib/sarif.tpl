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
                "text": "{{ .VulnerabilityID }} Package: {{ .PkgName }}."
              },
              "fullDescription": {
                "text": "{{ endWithPeriod (escapeString .Title) }}"
              },
              "help": {
                "text": "Vulnerability {{ .VulnerabilityID }}\nSeverity: {{ .Vulnerability.Severity }}\nPackage: {{ .PkgName }}\nInstalled Version: {{ .InstalledVersion }}\nFixed Version: {{ .FixedVersion }}\nLink: [{{ .VulnerabilityID }}](https://nvd.nist.gov/vuln/detail/{{ .VulnerabilityID | toLower }})",
                "markdown": "**Vulnerability {{ .VulnerabilityID }}**\n| Severity | Package | Installed Version | Fixed Version | Link |\n| --- | --- | --- | --- | --- |\n|{{ .Vulnerability.Severity }}|{{ .PkgName }}|{{ .InstalledVersion }}|{{ .FixedVersion }}|[{{ .VulnerabilityID }}](https://nvd.nist.gov/vuln/detail/{{ .VulnerabilityID | toLower }})|\n"
              },
              "properties": {
                "tags": [
                  "vulnerability",
                  "{{ .Vulnerability.Severity }}",
                  "{{ .PkgName }}"
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