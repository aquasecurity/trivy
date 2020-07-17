{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Trivy: Vulnerability Scanner for Containers",
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
              "name": "container_scanning",
              "shortDescription": {
                "text": {{ printf "error found in package %s." (print .PkgName .Title ) | printf "%q" }}
              },
              "fullDescription": {
                "text": {{ endWithPeriod .Description | printf "%q" }}
              },
              "defaultConfiguration": null,
              "properties": {
                "tags": [
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
            "text": {{ endWithPeriod $vulnerability.Description | printf "%q" }}
          },
          "locations": []
        }
        {{- end -}}
      {{- end -}}
      ],
      "columnKind": "utf16CodeUnits"
    }
  ]
}