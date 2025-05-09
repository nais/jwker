{{/*
Expand the name of the chart.
*/}}
{{- define "tokenx.jwker.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "tokenx.jwker.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "tokenx.jwker.chart" -}}
{{- if .Values.fullnameOverride }}
{{- printf "%s-%s" .Values.fullnameOverride .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- printf "%s-%s" .Release.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}


{{/*
Common labels
*/}}
{{- define "tokenx.jwker.labels" -}}
helm.sh/chart: {{ include "tokenx.jwker.chart" . }}
{{ include "tokenx.jwker.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app: {{ include "tokenx.jwker.fullname" . }}
team: {{ .Values.team }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "tokenx.jwker.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tokenx.jwker.name" . }}
{{- if .Values.fullnameOverride }}
app.kubernetes.io/instance: {{ .Values.fullnameOverride }}
{{- else }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
{{- end }}

{{/*
Tokendings host.
*/}}
{{- define "tokenx.tokendings.URL" -}}
{{- if .Values.tokendings.host }}
{{- printf "https://%s" .Values.tokendings.host }}
{{- else }}
{{- fail ".Values.tokendings.host is required." }}
{{- end }}
{{- end }}
