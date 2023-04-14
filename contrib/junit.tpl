<?xml version="1.0" ?>
<testsuites name="trivy">
{{- range . -}}
{{- $failures := len .Vulnerabilities }}
    <testsuite tests="{{ $failures }}" failures="{{ $failures }}" name="{{ .Target }}" errors="0" skipped="0" time="">
    {{- if not (eq .Type "") }}
        <properties>
            <property name="type" value="{{ .Type }}"></property>
        </properties>
        {{- end -}}
        {{ range .Vulnerabilities }}
        <testcase classname="{{ .PkgName | replace "/" "." }}-{{ .InstalledVersion }}" file="{{ .PkgName }}" name="[{{ .Vulnerability.Severity }}] {{ .VulnerabilityID }}" time="">
          <failure message="{{ escapeXML .Title }}" type="description">
            Severity: {{ .Severity }}
            Package Path (if available): {{ .PkgPath }}
            Description: {{ escapeXML .Description }}
          </failure>
        </testcase>
    {{- end }}
    </testsuite>
{{- $failures := len .Misconfigurations }}
    <testsuite tests="{{ $failures }}" failures="{{ $failures }}" name="{{  .Target }}" errors="0" skipped="0" time="">
    {{- if not (eq .Type "") }}
        <properties>
            <property name="type" value="{{ .Type }}"></property>
        </properties>
        {{- end -}}
        {{ range .Misconfigurations }}
        <testcase classname="{{ .Type }}" name="[{{ .Severity }}] {{ .ID }}" time="">
            <failure message="{{ escapeXML .Title }}" type="description">{{ escapeXML .Description }}</failure>
        </testcase>
    {{- end }}
    </testsuite>
{{- $failures := len .Secrets }}
    <testsuite tests="{{ $failures }}" failures="{{ $failures }}" name="{{  .Target }}" errors="0" skipped="0" time="">
    {{- if not (eq .Type "") }}
        <properties>
            <property name="type" value="{{ .Type }}"></property>
        </properties>
        {{- end -}}
        {{ $Path := .Target }}
        {{ range .Secrets }}
        <testcase file="{{ escapeXML $Path }}" classname="{{ .Category }}" name="[{{ .Severity }}] {{ .RuleID }}" time="">
            <failure message="{{ escapeXML .Title }}" type="description">{{ escapeXML .Match }}</failure>
        </testcase>
    {{- end }}
    </testsuite>
{{- end }}
</testsuites>
