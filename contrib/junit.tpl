<?xml version="1.0" ?>
<testsuites name="trivy">
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

{{- if .MisconfSummary }}
    <testsuite tests="{{ add .MisconfSummary.Successes .MisconfSummary.Failures }}" failures="{{ .MisconfSummary.Failures }}" name="{{  .Target }}" errors="0" time="">
{{- else }}
    <testsuite tests="0" failures="0" name="{{  .Target }}" errors="0" skipped="0" time="">
{{- end }}
    {{- if not (eq .Type "") }}
        <properties>
            <property name="type" value="{{ .Type }}"></property>
        </properties>
        {{- end -}}
        {{ range .Misconfigurations }}
        <testcase classname="{{ .Type }}" name="[{{ .Severity }}] {{ .ID }}" time="">
        {{- if (eq .Status "FAIL") }}
            <failure message="{{ escapeXML .Title }}" type="description">{{ escapeXML .Description }}</failure>
        {{- end }}
        </testcase>
    {{- end }}
    </testsuite>

{{- if .Licenses }}
    {{- $licenses := len .Licenses }}
    <testsuite tests="{{ $licenses }}" failures="{{ $licenses }}" name="{{ .Target }}" time="0">{{ range .Licenses }}
        <testcase classname="{{ .PkgName }}" name="[{{ .Severity }}] {{ .Name }}">
            <failure/>
        </testcase>
    {{- end }}
    </testsuite>
{{- end }}

{{- if .Secrets }}
    {{- $secrets := len .Secrets }}
    <testsuite tests="{{ $secrets }}" failures="{{ $secrets }}" name="{{ .Target }}" time="0">{{ range .Secrets }}
        <testcase classname="{{ .RuleID }}" name="[{{ .Severity }}] {{ .Title }}">
            <failure message="{{ .Title }}" type="description">{{ escapeXML .Match }}</failure>
        </testcase>
    {{- end }}
    </testsuite>
{{- end }}

{{- end }}
</testsuites>
