{
    "blocks": [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": ":rotating_light: VULNERABILITIES FOUND:\n{{ escapeXML ( index . 0 ).Target }}",
                "emoji": true
            }
        },
        {{- range . }}
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Scan type: {{ escapeXML .Type }}*",
                }
            },
            {{- if (gt (len .Vulnerabilities) 40) }}
                {
                "type": "section",
                    "text": {
                    "type": "mrkdwn",
                    "text": ":scream: *{{ (len .Vulnerabilities) | toString }} vulnerabilities found!* \nThis is too many for Slack to render!\nPlease <https://aquasecurity.github.io/trivy/latest/getting-started/installation/|install> & <https://aquasecurity.github.io/trivy/latest/docs/target/container_image/|run> trivy locally to see the full list."
                }
            },
            {{- else if (eq (len .Vulnerabilities) 0) }}
                {
                "type": "section",
                    "text": {
                    "type": "mrkdwn",
                    "text": "- none"
                }
            },
            {{- else }}
            {{- range .Vulnerabilities }}
            {
                "type": "section",
                    "text": {
                    "type": "mrkdwn",
                    "text": "- *{{ escapeXML .Vulnerability.Severity }}:* <https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ escapeXML .VulnerabilityID }}|{{ escapeXML .VulnerabilityID }}> `{{ escapeXML .PkgName }} v{{ escapeXML .InstalledVersion }}` (upgrade to: {{ escapeXML .FixedVersion }})"
                }
            },
            {{- end }}
            
            {{- end }}
        {{- end }}
    ]
}
