{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Trivy: Vulnerability Scanner for Containers",
          "semanticVersion": "0.9.1",
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
              "id": "{{ .VulnerabilityID }}",
              "name": "container_scanning",
              "shortDescription": {
                "text": {{ .Title | printf "%q" }}
              },
              "fullDescription": {
                "text": {{ .Description | printf "%q" }}
              },
              "defaultConfiguration": null
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
          "ruleId": "{{ $vulnerability.VulnerabilityID }}",
          "ruleIndex": {{ $index }},
          "level": {{ $vulnerability.Severity | printf "%q" }},
          "message": {
            "text": {{ $vulnerability.Description | printf "%q" }}
          },
          "locations": [],
          "partialFingerprints": {
             "primaryLocationLineHash": "{{ $vulnerability.VulnerabilityID }}"
          }
        }
        ],
          "codeFlows": [],
          "partialFingerprints": {
             "primaryLocationLineHash": "39fa2ee980eb94b0:1",
          }
        }
        {{- end -}}
      {{- end -}}
      ],
      "newlineSequences": [
        "\r\n",
        "\n",
        "",
        " "
      ],
      "columnKind": "utf16CodeUnits"
    }
  ]
}