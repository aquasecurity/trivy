<?xml version="1.0" ?>
<testsuites>
{{- range . -}}
{{- $failures := len .Vulnerabilities }}
    <testsuite tests="{{ $failures }}" failures="{{ $failures }}" name="{{  .Target }}" errors="0" skipped="0" time="">
    {{- if not (eq .Type "") }}
        <properties>
            <property name="type" value="{{ .Type }}"></property>
        </properties>
        {{- end -}}
        {{ range .Vulnerabilities }}
        <testcase classname="{{ .PkgName }}-{{ .InstalledVersion }}" name="[{{ .Vulnerability.Severity }}] {{ .VulnerabilityID }}" time="">
            <failure message="{{ escapeXML .Title }}" type="description">{{ escapeXML .Description }}</failure>
        </testcase>
    {{- end }}
    </testsuite>
{{- end }}
</testsuites>