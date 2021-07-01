[
{{- $t_first := true -}}
{{- range . -}}
{{- $target := .Target -}}
{{- range .Vulnerabilities -}}
{{- if $t_first -}}
  {{- $t_first = false -}}
{{- else -}}
  ,
{{- end -}}
{{- $severity := .Severity -}}
{{- if eq $severity "UNKNOWN" -}}
{{- $severity = "INFORMATIONAL" -}}
{{- end -}}
{{- $description := .Description -}}
{{- if gt (len $description ) 1021 -}}
    {{- $description = (substr 0 1021 $description) | printf "%v .." -}}
{{- end}}
    {
        "SchemaVersion": "2018-10-08",
        "Id": "{{ $target }}/{{ .VulnerabilityID }}",
        "ProductArn": "arn:aws:securityhub:{{ getEnv "AWS_REGION" }}::product/aquasecurity/aquasecurity",
        "GeneratorId": "Trivy",
        "AwsAccountId": "{{ getEnv "AWS_ACCOUNT_ID" }}",
        "Types": [ "Software and Configuration Checks/Vulnerabilities/CVE" ],
        "CreatedAt": "{{ getCurrentTime }}",
        "UpdatedAt": "{{ getCurrentTime }}",
        "Severity": {
            "Label": "{{ $severity }}"
        },
        "Title": "Trivy found a vulnerability to {{ .VulnerabilityID }} in container {{ $target }}",
        "Description": {{ escapeString $description | printf "%q" }},
        "Remediation": {
            "Recommendation": {
                "Text": "More information on this vulnerability is provided in the hyperlink",
                "Url": "{{ .PrimaryURL }}"
            }
        },
        "ProductFields": { "Product Name": "Trivy" },
        "Resources": [
            {
                "Type": "Container",
                "Id": "{{ $target }}",
                "Partition": "aws",
                "Region": "{{ getEnv "AWS_REGION" }}",
                "Details": {
                    "Container": { "ImageName": "{{ $target }}" },
                    "Other": {
                        "CVE ID": "{{ .VulnerabilityID }}",
                        "CVE Title": {{ .Title | printf "%q" }},
                        "PkgName": "{{ .PkgName }}",
                        "Installed Package": "{{ .InstalledVersion }}",
                        "Patched Package": "{{ .FixedVersion }}",
                        "NvdCvssScoreV3": "{{ (index .CVSS "nvd").V3Score }}",
                        "NvdCvssVectorV3": "{{ (index .CVSS "nvd").V3Vector }}",
                        "NvdCvssScoreV2": "{{ (index .CVSS "nvd").V2Score }}",
                        "NvdCvssVectorV2": "{{ (index .CVSS "nvd").V2Vector }}"
                    }
                }
            }
        ],
        "RecordState": "ACTIVE"
    }
   {{- end -}}
  {{- end }}
]
