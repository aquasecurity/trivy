{{/* vim: set filetype=mustache: */}}

{{- define "mysql.primary.fullname" -}}
{{- if eq .Values.architecture "replication" }}
{{- printf "%s-%s" (include "common.names.fullname" .) "primary" | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- include "common.names.fullname" . -}}
{{- end -}}
{{- end -}}

{{- define "mysql.secondary.fullname" -}}
{{- printf "%s-%s" (include "common.names.fullname" .) "secondary" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Return the proper MySQL image name
*/}}
{{- define "mysql.image" -}}
{{ include "common.images.image" (dict "imageRoot" .Values.image "global" .Values.global) }}
{{- end -}}

{{/*
Return the proper metrics image name
*/}}
{{- define "mysql.metrics.image" -}}
{{ include "common.images.image" (dict "imageRoot" .Values.metrics.image "global" .Values.global) }}
{{- end -}}

{{/*
Return the proper image name (for the init container volume-permissions image)
*/}}
{{- define "mysql.volumePermissions.image" -}}
{{ include "common.images.image" (dict "imageRoot" .Values.volumePermissions.image "global" .Values.global) }}
{{- end -}}

{{/*
Return the proper Docker Image Registry Secret Names
*/}}
{{- define "mysql.imagePullSecrets" -}}
{{ include "common.images.pullSecrets" (dict "images" (list .Values.image .Values.metrics.image .Values.volumePermissions.image) "global" .Values.global) }}
{{- end -}}

{{ template "mysql.initdbScriptsCM" . }}
{{/*
Get the initialization scripts ConfigMap name.
*/}}
{{- define "mysql.initdbScriptsCM" -}}
{{- if .Values.initdbScriptsConfigMap -}}
    {{- printf "%s" .Values.initdbScriptsConfigMap -}}
{{- else -}}
    {{- printf "%s-init-scripts" (include "mysql.primary.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
 Returns the proper service account name depending if an explicit service account name is set
 in the values file. If the name is not set it will default to either mysql.fullname if serviceAccount.create
 is true or default otherwise.
*/}}
{{- define "mysql.serviceAccountName" -}}
    {{- if .Values.serviceAccount.create -}}
        {{ default (include "common.names.fullname" .) .Values.serviceAccount.name }}
    {{- else -}}
        {{ default "default" .Values.serviceAccount.name }}
    {{- end -}}
{{- end -}}

{{/*
Return the configmap with the MySQL Primary configuration
*/}}
{{- define "mysql.primary.configmapName" -}}
{{- if .Values.primary.existingConfigmap -}}
    {{- printf "%s" (tpl .Values.primary.existingConfigmap $) -}}
{{- else -}}
    {{- printf "%s" (include "mysql.primary.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Return true if a configmap object should be created for MySQL Secondary
*/}}
{{- define "mysql.primary.createConfigmap" -}}
{{- if and .Values.primary.configuration (not .Values.primary.existingConfigmap) }}
    {{- true -}}
{{- else -}}
{{- end -}}
{{- end -}}

{{/*
Return the configmap with the MySQL Primary configuration
*/}}
{{- define "mysql.secondary.configmapName" -}}
{{- if .Values.secondary.existingConfigmap -}}
    {{- printf "%s" (tpl .Values.secondary.existingConfigmap $) -}}
{{- else -}}
    {{- printf "%s" (include "mysql.secondary.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Return true if a configmap object should be created for MySQL Secondary
*/}}
{{- define "mysql.secondary.createConfigmap" -}}
{{- if and (eq .Values.architecture "replication") .Values.secondary.configuration (not .Values.secondary.existingConfigmap) }}
    {{- true -}}
{{- else -}}
{{- end -}}
{{- end -}}

{{/*
Return the secret with MySQL credentials
*/}}
{{- define "mysql.secretName" -}}
    {{- if .Values.auth.existingSecret -}}
        {{- printf "%s" .Values.auth.existingSecret -}}
    {{- else -}}
        {{- printf "%s" (include "common.names.fullname" .) -}}
    {{- end -}}
{{- end -}}

{{/*
Return true if a secret object should be created for MySQL
*/}}
{{- define "mysql.createSecret" -}}
{{- if and (not .Values.auth.existingSecret) (not .Values.auth.customPasswordFiles) }}
    {{- true -}}
{{- end -}}
{{- end -}}

{{/*
Returns the available value for certain key in an existing secret (if it exists),
otherwise it generates a random value.
*/}}
{{- define "getValueFromSecret" }}
    {{- $len := (default 16 .Length) | int -}}
    {{- $obj := (lookup "v1" "Secret" .Namespace .Name).data -}}
    {{- if $obj }}
        {{- index $obj .Key | b64dec -}}
    {{- else -}}
        {{- randAlphaNum $len -}}
    {{- end -}}
{{- end }}

{{- define "mysql.root.password" -}}
    {{- if not (empty .Values.auth.rootPassword) }}
        {{- .Values.auth.rootPassword }}
    {{- else if (not .Values.auth.forcePassword) }}
        {{- include "getValueFromSecret" (dict "Namespace" .Release.Namespace "Name" (include "common.names.fullname" .) "Length" 10 "Key" "mysql-root-password") }}
    {{- else }}
        {{- required "A MySQL Root Password is required!" .Values.auth.rootPassword }}
    {{- end }}
{{- end -}}

{{- define "mysql.password" -}}
    {{- if and (not (empty .Values.auth.username)) (not (empty .Values.auth.password)) }}
        {{- .Values.auth.password }}
    {{- else if (not .Values.auth.forcePassword) }}
        {{- include "getValueFromSecret" (dict "Namespace" .Release.Namespace "Name" (include "common.names.fullname" .) "Length" 10 "Key" "mysql-password") }}
    {{- else }}
        {{- required "A MySQL Database Password is required!" .Values.auth.password }}
    {{- end }}
{{- end -}}

{{- define "mysql.replication.password" -}}
    {{- if not (empty .Values.auth.replicationPassword) }}
        {{- .Values.auth.replicationPassword }}
    {{- else if (not .Values.auth.forcePassword) }}
        {{- include "getValueFromSecret" (dict "Namespace" .Release.Namespace "Name" (include "common.names.fullname" .) "Length" 10 "Key" "mysql-replication-password") }}
    {{- else }}
        {{- required "A MySQL Replication Password is required!" .Values.auth.replicationPassword }}
    {{- end }}
{{- end -}}

{{/* Check if there are rolling tags in the images */}}
{{- define "mysql.checkRollingTags" -}}
{{- include "common.warnings.rollingTag" .Values.image }}
{{- include "common.warnings.rollingTag" .Values.metrics.image }}
{{- include "common.warnings.rollingTag" .Values.volumePermissions.image }}
{{- end -}}

{{/*
Compile all warnings into a single message, and call fail.
*/}}
{{- define "mysql.validateValues" -}}
{{- $messages := list -}}
{{- $messages := without $messages "" -}}
{{- $message := join "\n" $messages -}}

{{- if $message -}}
{{- printf "\nVALUES VALIDATION:\n%s" $message | fail -}}
{{- end -}}
{{- end -}}
