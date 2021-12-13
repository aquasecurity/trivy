{
    {{- $rules := makeRuleMap }}
    {{- $critical := 0 -}}
    {{- $high := 0 -}}
    {{- $medium := 0 -}}
    {{- $low := 0 -}}
    {{- $total := 0 -}}
    "results": [{
        "vulnerabilities": [
    {{- range $result := . }}
        {{- $t_first := true }}            
            {{- range .Vulnerabilities -}}
                {{- if indexRule $rules .VulnerabilityID -}}
                  {{- if  eq .Severity "CRITICAL" }}{{- $critical = add $critical 1 }}{{- end }}
                  {{- if  eq .Severity "HIGH" }}{{- $high = add $high 1 }}{{- end }}
                  {{- if  eq .Severity "MEDIUM" }}{{- $medium = add $medium 1 }}{{- end }}
                  {{- if  eq .Severity "LOW" }}{{- $low = add $low 1 }}{{- end }}
                  {{- $total = add $total 1 }}
                  {{- if $t_first -}}
                    {{- $t_first = false -}}
                  {{ else -}}
                    ,
                  {{- end }}
            {
                "id": "{{ .VulnerabilityID }}",
                "cvss": {{ (index .CVSS "nvd").V3Score }},
                "vector": "{{ (index .CVSS "nvd").V3Vector }}",
                "description": {{ printf "%v" .Title | printf "%q"}},
                "severity": "{{ .Vulnerability.Severity }}",
                "packageName": "{{ .PkgName }}",
                "packageVersion": "{{ .InstalledVersion }}",
                "link": "{{ .PrimaryURL }}",
                "riskFactors": [],
                "impactedVersions": [],
                "publishedDate": "{{ .PublishedDate }}",
                "discoveredDate": "{{ getCurrentTime }}"
			}
                {{- end -}}
            {{- end -}}
    {{- end -}}
        ],
        "vulnerabilityDistribution": {
				"critical": {{ $critical }},
				"high": {{ $high }},
				"medium": {{ $medium }},
				"low": {{ $low }},
				"total": {{ $total }}
			}
    }]  
}
