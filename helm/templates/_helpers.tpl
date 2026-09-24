{{/* vim: set filetype=mustache: */}}
{{/******************************** GENERAL ********************************/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "rrst.name" -}}
{{-   default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "rrst.fullname" -}}
{{-   if .Values.fullnameOverride -}}
{{-     .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{-   else -}}
{{-     $name := default .Chart.Name .Values.nameOverride -}}
{{-     if contains $name .Release.Name -}}
{{-       .Release.Name | trunc 63 | trimSuffix "-" -}}
{{-     else -}}
{{-       printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{-     end -}}
{{-   end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "rrst.chart" -}}
{{-   printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "rrst.labels" -}}
app.kubernetes.io/name: {{ include "rrst.name" . }}
helm.sh/chart: {{ include "rrst.chart" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{-   if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{-   end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
The labels a Deployment selects its pods by, and a Service its endpoints. Never change them on a live release: a Deployment's
selector is immutable.
*/}}
{{- define "rrst.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rrst.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Renders a value that contains template.
Usage:
{{ include "rrst.render" ( dict "value" .Values.path.to.the.Value "context" $) }}
*/}}
{{- define "rrst.render" -}}
{{-   if typeIs "string" .value }}
{{-     tpl .value .context }}
{{-   else }}
{{-     tpl (.value | toYaml) .context }}
{{-   end }}
{{- end -}}

{{/*
"true" when `host` can get a real certificate: not localhost, *.localhost or *.local. Usage: include "rrst.publicHost" "example.com"
*/}}
{{- define "rrst.publicHost" -}}
{{-   if not (or (eq . "localhost") (hasSuffix ".localhost" .) (hasSuffix ".local" .)) -}}
true
{{-   end -}}
{{- end -}}

{{/*
The full name a Bitnami subchart gives its resources (its common.names.fullname), so this chart can address the bundled
MongoDB and Redis without the subcharts' fullnameOverride, which would collide between two releases in one namespace.
Usage: include "acme.subchartFullname" (dict "name" "mongodb" "values" .Values.mongodb "context" $)
*/}}
{{- define "acme.subchartFullname" -}}
{{-   if .values.fullnameOverride -}}
{{-     .values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{-   else -}}
{{-     $name := default .name .values.nameOverride -}}
{{-     if contains $name .context.Release.Name -}}
{{-       .context.Release.Name | trunc 63 | trimSuffix "-" -}}
{{-     else -}}
{{-       printf "%s-%s" .context.Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{-     end -}}
{{-   end -}}
{{- end -}}

{{/******************************** SECRETS ********************************/}}

{{/*
Fails the render when generated secrets can't be kept stable: without cluster access (`helm template`, a GitOps controller
rendering the chart, `--dry-run`) `lookup` returns nothing, so every render would generate new secrets - and roll the pods
on each sync. Detected by looking up the release namespace's "kube-root-ca.crt" ConfigMap (published into every namespace),
which a namespace-scoped install can read; only when that finds nothing (e.g. `--create-namespace`, which renders before the
namespace exists) is the cluster-scoped "default" Namespace tried. lookup fails the render on Forbidden, so the
cluster-scoped probe must not come first. Skipped for a development environment, where a changing generated secret costs nothing.
Usage: include "rrst.assertStableSecrets" (dict "missing" (list "metrics.secret" ...) "context" $)
*/}}
{{- define "rrst.assertStableSecrets" -}}
{{-   if and .missing (not .context.Values.secrets.existingSecret) (not (include "acme.isDev" .context)) -}}
{{-     $clusterAccess := lookup "v1" "ConfigMap" .context.Release.Namespace "kube-root-ca.crt" -}}
{{-     if not $clusterAccess -}}
{{-       $clusterAccess = lookup "v1" "Namespace" "" "default" -}}
{{-     end -}}
{{-     if not $clusterAccess -}}
{{-       required (printf "Rendering without cluster access (helm template, GitOps, --dry-run), so generated secrets would change on every render. Set %s explicitly, or secrets.existingSecret to a Secret you manage." (join ", " .missing)) "" -}}
{{-     end -}}
{{-   end -}}
{{- end -}}

{{/*
A base64-encoded secret that's generated once and kept: the explicit value when one is set, otherwise the value already
stored in the release's Secret (so it survives upgrades), otherwise a new random one. Random values start with a letter so
the service's settings parser (which reads JSON-looking environment values as numbers) can never turn one into a number.
Usage: include "rrst.persistedSecret" (dict "value" .Values.metrics.secret "stored" $storedB64 "context" $)
*/}}
{{- define "rrst.persistedSecret" -}}
{{-   $explicit := tpl (.value | default "") .context -}}
{{-   if $explicit -}}
{{-     $explicit | b64enc -}}
{{-   else if .stored -}}
{{-     .stored -}}
{{-   else -}}
{{-     printf "a%s" (randAlphaNum 47) | b64enc -}}
{{-   end -}}
{{- end -}}

{{/******************************** ACME CA ********************************/}}

{{/* "true" for NODE_ENV dev, development or test - the values under which the service skips its production start-up guard. */}}
{{- define "acme.isDev" -}}
{{-   if has .Values.environment (list "dev" "development" "test") -}}
true
{{-   end -}}
{{- end -}}

{{/* The rendered `host`. */}}
{{- define "acme.host" -}}
{{-   include "rrst.render" (dict "value" (.Values.host | default "") "context" .) -}}
{{- end -}}

{{/*
The name of the Secret holding the certificate of the Gateway's https listener, or empty when there is none (gateway or TLS
off, or a host no certificate can be issued for and no tlsSecretName). Usage: include "acme.tlsSecret" $
*/}}
{{- define "acme.tlsSecret" -}}
{{-   if and .Values.gateway.enabled .Values.gateway.tls -}}
{{-     if .Values.gateway.tlsSecretName -}}
{{-       tpl .Values.gateway.tlsSecretName . -}}
{{-     else if and .Values.certmanager.enabled (include "acme.host" .) (eq (include "rrst.publicHost" (include "acme.host" .)) "true") -}}
{{-       printf "%s-tls" (include "rrst.fullname" .) -}}
{{-     end -}}
{{-   end -}}
{{- end -}}

{{/*
The base URL of everything the CA hands out: acme.externalUrl, else https://<host> (http:// for a development install
without a certificate), else the development default.
*/}}
{{- define "acme.externalUrl" -}}
{{-   $host := include "acme.host" . -}}
{{-   if .Values.acme.externalUrl -}}
{{-     tpl .Values.acme.externalUrl . | trimSuffix "/" -}}
{{-   else if $host -}}
{{-     $scheme := ternary "http" "https" (and (eq (include "acme.isDev" .) "true") (not (include "acme.tlsSecret" .))) -}}
{{-     printf "%s://%s" $scheme $host -}}
{{-   else -}}
http://localhost:3000
{{-   end -}}
{{- end -}}

{{/* The challenge e-mail's From address: mail.from, else acme-challenge@<host>. */}}
{{- define "acme.mailFrom" -}}
{{-   if .Values.mail.from -}}
{{-     tpl .Values.mail.from . -}}
{{-   else if include "acme.host" . -}}
{{-     printf "acme-challenge@%s" (include "acme.host" .) -}}
{{-   else -}}
acme-challenge@acme.localdomain
{{-   end -}}
{{- end -}}

{{/* Where the applicant sends the reply: mail.replyTo, else acme-response@<host>. */}}
{{- define "acme.mailReplyTo" -}}
{{-   if .Values.mail.replyTo -}}
{{-     tpl .Values.mail.replyTo . -}}
{{-   else if include "acme.host" . -}}
{{-     printf "acme-response@%s" (include "acme.host" .) -}}
{{-   else -}}
acme-response@acme.localdomain
{{-   end -}}
{{- end -}}

{{/* The DKIM signing domain: mail.dkim.domain, else the domain of the From address. */}}
{{- define "acme.dkimDomain" -}}
{{-   if .Values.mail.dkim.domain -}}
{{-     tpl .Values.mail.dkim.domain . -}}
{{-   else -}}
{{-     regexReplaceAll "^.*@" (include "acme.mailFrom" .) "" -}}
{{-   end -}}
{{- end -}}

{{/* "true" when there is a shared cache (bundled or external Redis); without one, nonces and rate limits live per pod. */}}
{{- define "acme.hasRedis" -}}
{{-   if or .Values.redis.create .Values.redis.url -}}
true
{{-   end -}}
{{- end -}}

{{/* The container image: service.image.tag, else the chart's appVersion. */}}
{{- define "acme.image" -}}
{{-   printf "%s/%s:%s" .Values.service.image.registry .Values.service.image.repository (.Values.service.image.tag | default .Chart.AppVersion | toString) -}}
{{- end -}}

{{/*
Fails the render, with something actionable, when the values cannot make a working CA. The service itself refuses to start for
the same reasons in a real deployment (src/config.defaults.ts), which would only show up later as a crash loop.
Usage: include "acme.validate" $
*/}}
{{- define "acme.validate" -}}
{{-   $dev := eq (include "acme.isDev" .) "true" -}}
{{-   $host := include "acme.host" . -}}
{{-   $external := include "acme.externalUrl" . -}}
{{-   $from := include "acme.mailFrom" . -}}
{{-   $replyTo := include "acme.mailReplyTo" . -}}

{{-   if not .Values.ca.existingSecret -}}
{{-     fail "ca.existingSecret is required: the CA's certificate and key are never generated by the chart. Create the CA with `yarn ca:init` (the root on an offline machine, see docs/DEPLOYMENT.md), then `scripts/ca-k8s-secret.sh <ca-dir> acme-ca -- -n <namespace>` and set ca.existingSecret=acme-ca plus the ca.items it prints." -}}
{{-   end -}}

{{-   if and (not .Values.mongodb.create) (not .Values.mongodb.url) -}}
{{-     fail "No MongoDB: set mongodb.create=true for the bundled one, or mongodb.url (and mongodb.create=false) for an external one." -}}
{{-   end -}}
{{-   if and (gt (int .Values.service.replicas) 1) (not (include "acme.hasRedis" .)) -}}
{{-     fail (printf "service.replicas is %d, but there is no Redis: nonces and rate limits would then be kept per pod (a nonce issued by one pod is unknown to the next, and every limit multiplies). Set redis.create=true, or redis.url for an external Redis, or service.replicas=1." (int .Values.service.replicas)) -}}
{{-   end -}}
{{- /* A development install on a local host name simply gets no https listener; a real one must not silently lose TLS. */ -}}
{{-   if and (not $dev) .Values.gateway.enabled .Values.gateway.tls (not (include "acme.tlsSecret" .)) -}}
{{-     fail (printf "gateway.tls is true, but no certificate can be provided for host %q: cert-manager only issues for a public host name (not localhost, *.local, *.localhost) and certmanager.enabled must be true. Set gateway.tlsSecretName to a kubernetes.io/tls Secret of your own, or gateway.tls=false (with acme.externalUrl set, if TLS ends in front of this chart)." $host) -}}
{{-   end -}}
{{-   if and (not $dev) .Values.gateway.enabled (not .Values.trustedProxies) -}}
{{-     fail "trustedProxies is required with the Gateway: behind it every request comes from a proxy pod, so without the proxies' addresses every client shares one address and the per-IP rate limits cannot tell them apart (one applicant could exhaust them for all). Set trustedProxies to the CIDR(s) of your Gateway pods or load balancer, e.g. --set trustedProxies={10.42.0.0/16}, and nothing wider. See docs/DEPLOYMENT.md." -}}
{{-   end -}}
{{-   if and .Values.mail.smtp.user (not .Values.mail.smtp.existingSecret) -}}
{{-     fail "mail.smtp.user is set but mail.smtp.existingSecret (the Secret holding the relay password under mail.smtp.passwordKey) is not." -}}
{{-   end -}}
{{-   if and .Values.mail.smtp.secure .Values.mail.smtp.ignoreTLS -}}
{{-     fail "mail.smtp.secure (implicit TLS) and mail.smtp.ignoreTLS (never use TLS) contradict each other." -}}
{{-   end -}}
{{-   if not (has .Values.acme.dkimAlignment (list "strict" "relaxed")) -}}
{{-     fail (printf "acme.dkimAlignment is %q; it must be \"strict\" or \"relaxed\"." (toString .Values.acme.dkimAlignment)) -}}
{{-   end -}}
{{-   if and .Values.inboundSmtp.enabled (not (has .Values.inboundSmtp.service.type (list "LoadBalancer" "NodePort" "ClusterIP"))) -}}
{{-     fail (printf "inboundSmtp.service.type is %q; it must be LoadBalancer, NodePort or ClusterIP." (toString .Values.inboundSmtp.service.type)) -}}
{{-   end -}}

{{-   if not $dev -}}
{{-     if and (not $host) (or (not .Values.acme.externalUrl) .Values.gateway.enabled) -}}
{{-       fail "host is required (the CA's public host name, e.g. --set host=acme.example.com) unless environment is dev, development or test." -}}
{{-     end -}}
{{-     if not (regexMatch "^https://[^/?#@\\s]+/?$" $external) -}}
{{-       fail (printf "The external URL %q is not a bare https:// origin. A real deployment must hand out https URLs and nothing else; set host (or acme.externalUrl) accordingly." $external) -}}
{{-     end -}}
{{-     range $label, $address := dict "mail.from" $from "mail.replyTo" $replyTo -}}
{{-       if or (not (regexMatch "^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$" $address)) (regexMatch "(?i)@([^@]*\\.)?(localhost|localdomain|local)$" $address) -}}
{{-         fail (printf "%s is %q: it must be a real address on this CA's domain (the service refuses to start with a placeholder)." $label $address) -}}
{{-       end -}}
{{-     end -}}
{{-     if not .Values.mail.smtp.host -}}
{{-       fail "mail.smtp.host is required: the CA sends the verification e-mail through an SMTP relay (mail.smtp.port, secure, user and existingSecret configure it) unless environment is dev, development or test." -}}
{{-     end -}}
{{-     if or (not .Values.mail.dkim.existingSecret) (not .Values.mail.dkim.selector) -}}
{{-       fail "DKIM is required (RFC 8823: the verification e-mail must be signed): set mail.dkim.existingSecret (a Secret holding the private key under mail.dkim.key) and mail.dkim.selector. See docs/DEPLOYMENT.md for creating the key and its DNS record." -}}
{{-     end -}}
{{-   end -}}
{{- end -}}
