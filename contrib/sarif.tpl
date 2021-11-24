{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  {{- $rules := makeRuleMap }}
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Trivy",
          "informationUri": "https://github.com/aquasecurity/trivy",
          "fullName": "Trivy Vulnerability Scanner",
          "version": "0.15.0",
          "rules": [
        {{- $t_first := true }}
        {{- range $result := . }}
            {{- $vulnerabilityType := .Type }}
            {{- range .Vulnerabilities -}}
                {{- if indexRule $rules .VulnerabilityID -}}
                  {{- if $t_first -}}
                    {{- $t_first = false -}}
                  {{ else -}}
                    ,
                  {{- end }}
                {
                  "id": {{ .VulnerabilityID | toJson }},
                  "name": "{{ toSarifRuleName $vulnerabilityType }}",
                  "shortDescription": {
                    "text": {{ .VulnerabilityID | toJson }}
                  },
                  "fullDescription": {
                    "text": {{ endWithPeriod (escapeString .Title) | printf "%q" }}
                  },
                  "defaultConfiguration": {
                    "level": "{{ toSarifErrorLevel .Vulnerability.Severity }}"
                  }
                  {{- with $help_uri := .PrimaryURL -}}
                  ,
                  {{ $help_uri | printf "\"helpUri\": %q," -}}
                  {{- else -}}
                  ,
                  {{- end }}
                  "properties": {
                    "tags": [
                      "vulnerability",
                      "{{ .Vulnerability.Severity }}"
                    ],
                    "precision": "very-high"
                  }
                }
                {{- end -}}
            {{- end -}}
         {{- end -}}
          ]
        }
      },
      "results": [
    {{- $t_first := true }}
    {{- range $result := . }}
        {{- $filePath := .Target }}
        {{- range $index, $vulnerability := .Vulnerabilities -}}
          {{- if $t_first -}}
            {{- $t_first = false -}}
          {{ else -}}
            ,
          {{- end }}
        {
          "ruleId": {{ .VulnerabilityID | toJson }},
          "ruleIndex": {{ index $rules .VulnerabilityID }},
          "level": "{{ toSarifErrorLevel $vulnerability.Vulnerability.Severity }}",
          "message": {
            "text": {{ endWithPeriod (escapeString $vulnerability.Description) | printf "%q" }}
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "{{ toPathUri $filePath }}",
                "uriBaseId": "ROOTPATH"
              },
              "region" : {
                "startLine": 1
              }
            }
          }]
        }
        {{- end -}}
      {{- end -}}
      ],
      "columnKind": "utf16CodeUnits",
      "originalUriBaseIds": {
        "ROOTPATH": {
          "uri": "file:///"
        }
      }
    }
  ]
}