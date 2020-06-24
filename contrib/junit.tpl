<?xml version="1.0" ?>
<testsuites>
{{ range . }}
	{{- $failures := 0 }}
    {{- range .Vulnerabilities -}}
		{{- $failures = sum $failures 2 -}}
	{{- end -}}
	<testsuite tests="1" failures="{{ $failures }}" time="" name="{{  .Target }}">
		{{- if not (eq .Type "") }}
			<properties>
                <property name="type" value="{{ .Type }}"></property>
            </properties>
        {{- end -}}
        {{ range .Vulnerabilities }}
            <testcase classname="{{ .PkgName }}-{{ .InstalledVersion }}" name="{{ .VulnerabilityID }}" time="">
                <failure message={{ .Title | printf "%q" }} type="description">{{ .Description | printf "%q" }}</failure>
                <failure message="" type="severity">{{ .Vulnerability.Severity }}</failure>
            </testcase>
        {{- end }}
	</testsuite>
{{- end }}
</testsuites>