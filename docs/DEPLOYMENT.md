# Deploying the RapidMX ACME CA

How to run the CA for real: create its CA hierarchy, prepare the mail side (DKIM, DNS, inbound SMTP), install it with the Helm
chart or Docker, and keep it safe. [ARCHITECTURE.md](ARCHITECTURE.md) explains what the service does and lists every `acme.*`
setting; this document is only about running it.

> **What this is not.** Nothing here makes the CA publicly trusted. The root you create is in no trust store; certificates
> verify only where it is imported (see the trust model in [ARCHITECTURE.md](ARCHITECTURE.md)). Read
> [What has and has not been verified](#what-has-and-has-not-been-verified) before relying on any step below.

## Contents

1. [What you need](#what-you-need)
2. [Create the CA](#1-create-the-ca)
3. [DKIM key and DNS](#2-dkim-key-and-dns)
4. [Inbound e-mail: how replies reach the CA](#3-inbound-e-mail-how-replies-reach-the-ca)
5. [Quick start with Docker Compose (development)](#quick-start-with-docker-compose-development)
6. [Install with Helm](#install-with-helm)
7. [Docker without Kubernetes](#docker-without-kubernetes)
8. [Upgrading](#upgrading)
9. [Rotating the issuing CA](#rotating-the-issuing-ca)
10. [The operator API](#the-operator-api)
11. [Backing up MongoDB](#backing-up-mongodb)
12. [Hardening checklist](#hardening-checklist)
13. [What has and has not been verified](#what-has-and-has-not-been-verified)

## What you need

| | |
| --- | --- |
| A DNS domain you control | Its host name for the CA (`acme.example.com` below) and the domain of the challenge e-mail addresses. By default both are the CA's own host: `acme-challenge@<host>` (sender) and `acme-response@<host>` (where applicants reply). |
| A CA hierarchy | An **offline root** and an **issuing CA** whose key the service holds (or an OpenBao Transit key). Section 1. |
| A DKIM key | The challenge e-mail must be DKIM-signed by the domain of its From address (RFC 8823). Section 2. |
| An outbound SMTP relay | Any relay that accepts authenticated submission (SES, a Postfix you run, ...). The CA never delivers mail itself. |
| Inbound SMTP | Something that takes replies from the internet on port 25: the CA's built-in receiver, or your own MTA forwarding to the CA. Section 3. |
| MongoDB and Redis | Bundled (Bitnami subcharts) or your own. MongoDB holds the record of everything issued; Redis holds nonces and rate-limit buckets and is **mandatory** with more than one replica. |
| Kubernetes with the Gateway API and cert-manager | For the Helm chart's HTTPS exposure: a Gateway API implementation (the default class is `envoy`, `gateway.className`) and cert-manager with its Gateway API support enabled (its HTTP-01 solver uses a `gatewayHTTPRoute`). Without them use `gateway.enabled=false` and expose the Service yourself. |

The container image is `ghcr.io/rapidmx/acme:<version>`; the chart is `oci://ghcr.io/rapidmx/charts/acme`.

## 1. Create the CA

`scripts/ca-init.ts` (`yarn ca:init`, `--help` lists every option) builds the hierarchy with the service's own PKI code and
writes `issuers.json`, the manifest the service loads (`acme.ca.manifest`, default `/var/lib/acme/ca/issuers.json`; relative
paths inside it are resolved against its directory).

**The root private key belongs on an offline machine.** A root key that lives on the server, in a backup, an image or a
repository can mint certificates for anyone. Only the root *certificate* ever goes to the service.

On an offline machine with a checkout of this repository (`yarn install` done):

```sh
# 1. The root. Its key is encrypted with the passphrase in $ROOT_PASS; keep both offline, in more than one safe place.
ROOT_PASS='<long random passphrase>' \
  yarn ca:init --root-only --dir ./root --passphrase-env ROOT_PASS --base-url https://acme.example.com

# 2. The issuing CA, signed by that root. Its key is encrypted with $ACME_CA_KEY_PASSPHRASE, which the service will be given.
ROOT_PASS='<the root passphrase>' ACME_CA_KEY_PASSPHRASE='<a different long random passphrase>' \
  yarn ca:init --issuer-only \
    --root-cert ./root/root-r1/cert.pem --root-key ./root/root-r1/key.pem --root-key-passphrase-env ROOT_PASS \
    --dir ./server-ca --passphrase-env ACME_CA_KEY_PASSPHRASE --base-url https://acme.example.com
```

`--base-url` must be the URL the service will run under (`https://<host>`); use the same for every command. The root
certificate's SHA-256 fingerprint is printed: write it down, it is what relying parties pin. ECDSA P-384 is the default; use
`--key-alg` for another.

`./server-ca` now holds `issuers.json`, `smime-r1/cert.pem`, `smime-r1/key.pem` (the encrypted issuer key) and
`root-r1/cert.pem` (the root **certificate**). That directory, and nothing from `./root`, goes to the server. The key
passphrase is recorded in `issuers.json` only as the *name* of the environment variable (`passphrase_env`); the value reaches the
service as `ACME_CA_KEY_PASSPHRASE`.

Instead of a key file, an issuing key can live in an OpenBao/Vault Transit key (`"type": "openbao-transit"` in
`issuers.json`, see ARCHITECTURE.md): the private key then never enters the process. That path is implemented but has **not**
been exercised against a real OpenBao.

For development, `yarn ca:init` with no mode flag creates a root and an issuer in one go (`docker-compose.yml` does this for
you). Never use that for a CA you will rely on.

## 2. DKIM key and DNS

### The DKIM key

RFC 8823 requires the challenge e-mail to be DKIM-signed. Create an RSA 2048 key and the matching DNS value:

```sh
openssl genrsa -out dkim.private.pem 2048
echo "v=DKIM1; k=rsa; p=$(openssl rsa -in dkim.private.pem -pubout -outform der 2>/dev/null | openssl base64 -A)"
```

The private key (PKCS#8 PEM, what OpenSSL 3 writes) goes to the service as `acme.mail.dkim.private_key_path`; the printed
line is the TXT record's value. Pick a selector (`acme1` below) and a signing domain, which must be the domain of the From
address (`acme.mail.from`) when `acme.mail.dkim_alignment` is `strict` (the default; chart value `acme.dkimAlignment`).

### DNS records

For a CA at `acme.example.com` with the default addresses, published in the zone of `example.com`:

| Record | Purpose |
| --- | --- |
| `acme.example.com. A/AAAA` (or `CNAME`) → the Gateway's address | The API and the trust endpoints. |
| `acme1._domainkey.acme.example.com. TXT "v=DKIM1; k=rsa; p=..."` | The DKIM public key. The base64 of a 2048-bit key is longer than 255 characters: split it into several quoted strings inside one TXT record (`"v=DKIM1; k=rsa; p=MIIB..." "...rest..."`); most DNS providers do that for you. |
| `acme.example.com. MX 10 mx.acme.example.com.` and `mx.acme.example.com. A` → the inbound SMTP address | Applicants' replies are addressed to `acme-response@acme.example.com`, so **the domain of `acme.mail.reply_to` needs an MX record that reaches the CA's inbound SMTP** (section 3). |
| `acme.example.com. TXT "v=spf1 ... -all"` | SPF for the domain of `acme.mail.from`, authorising your outbound relay (SES: `include:amazonses.com`; use your relay's documented include). Needed so recipients' spam filters accept the challenge e-mail. |
| `_dmarc.acme.example.com. TXT "v=DMARC1; p=none; rua=mailto:..."` | Optional. Start with `p=none` and report addresses; tighten only once DKIM and SPF are seen to pass. |
| `acme.example.com. CAA 0 issue "letsencrypt.org"` | Optional, for the CA's own web certificate. |

Also make sure the outbound relay's IP has a matching reverse DNS record (that is the relay's business, but a missing PTR is
the most common reason challenge e-mails land in spam).

Applicants' domains are checked too: a domain that publishes a CAA `issuemail` record must name one of
`acme.caa_identities` (default `["rapidmx.io"]`; set it to **your** operator identity, chart value `acme.caaIdentities`), and
must be able to receive mail (the CA looks up its MX record).

## 3. Inbound e-mail: how replies reach the CA

The applicant's client replies to `acme.mail.reply_to`. The CA accepts a message only for its two addresses
(`acme.mail.from` and `acme.mail.reply_to`), then checks the reply's DKIM signature against the sender's real DNS (the `d=`
must equal the From domain), the sender and the digest. Two ways to receive it; they can be combined.

### A. The built-in SMTP receiver

`acme.mail.inbound.smtp.enabled=true` starts a receiver in the service on `acme.mail.inbound.smtp.host`:`port` (default
`0.0.0.0:2525`; unprivileged, so the container needs no capability). It keeps `max_size_bytes` (default 1 MiB) per message.

* **Helm:** `inboundSmtp.enabled=true` renders a **separate** Service named `<fullname>-smtp`, type
  `LoadBalancer` by default (also `NodePort` or `ClusterIP`), port 25 → the pod's 2525. It is off by default. Point the MX
  target's A record at that Service's address (`kubectl get service <fullname>-smtp`). Port 25 must be reachable from the
  internet; many clouds block it unless you ask. `externalTrafficPolicy: Local` (the default) keeps the sender's address;
  switch to `Cluster` if your load balancer cannot health-check nodes.
* **Compose:** published on `localhost:2525`; see the comments in `docker-compose.yml` for sending a test message.

**TLS on the listener.** Without a certificate the receiver does not offer STARTTLS, and most senders then deliver in the
clear (opportunistic TLS). To offer it, give it a certificate for the MX host name:
`acme.mail.inbound.smtp.tls_key_path` and `tls_cert_path`, or with the chart a Secret of type `kubernetes.io/tls` in
`inboundSmtp.tls.existingSecret` (for example one cert-manager issues for `mx.acme.example.com`). The files are read once at
start: restart the pods after a renewal (`kubectl rollout restart deploy/<fullname>-services`).

### B. HTTP ingest behind your own MTA

Run Postfix (or SES with a Lambda/SNS bridge, ...) in front and forward each accepted message to
`POST /internal/mail/inbound`: the raw RFC 5322 message as the body, `Authorization: Bearer <acme.mail.inbound.http_secret>`,
and optionally `X-Envelope-From` and `X-Remote-Address` (passed on as the envelope sender and the connecting address). The answer is `202` and never says what
became of the message. Without a secret the route answers 404.

The route is **not** exposed by the chart's Gateway (only the public paths are). Reach it through the in-cluster Service,
`http://<fullname>-services/internal/mail/inbound`. The secret is generated by the chart (`inboundHttp.enabled`, default true)
and printed by NOTES.txt as a `kubectl get secret` command.

## Quick start with Docker Compose (development)

```sh
docker compose up --build
```

Brings up the CA, MongoDB, Redis, [Mailpit](https://github.com/axllent/mailpit) as the outbound relay, and a one-shot
`ca-init` service that generates a throw-away development CA into the `ca` volume (the key passphrase is public; the root key
is not kept). Then:

* `http://localhost:3000/directory` is the ACME directory; `http://localhost:3000/ca/roots.pem` the trust anchor.
* `http://localhost:8025` is Mailpit: every challenge e-mail lands there and nothing leaves the host.
* `localhost:2525` is the built-in SMTP receiver. `docker-compose.yml` shows how to send a message to it with `curl` or `swaks`.
* `docker-compose.debug.yml` adds `node --inspect` on `127.0.0.1:9229`.
* `docker compose down -v` throws everything away, including the CA (certificates issued so far stop chaining to a new one).

It runs with `NODE_ENV=development`, which switches the production start-up guard off (an `http://localhost` external URL,
placeholder addresses, no DKIM key). Certificates it issues carry `http://localhost:3000` CRL/OCSP addresses: they are for
testing. There is no DNS in the stack, so a reply e-mail cannot pass DKIM verification unless the sender's domain really
publishes its key; to try `email-reply-00` end to end use an address on a domain you control, or give the `acme` service a
resolver (`dns:`) that serves the test domain's DKIM record.

## Install with Helm

The chart is in `helm/` (`acme`, version `0.1.0`). It creates the Deployment, the Services, the Gateway API resources,
cert-manager's Issuer/Certificate, the generated Secrets and the bundled MongoDB and Redis; it never creates the CA, the DKIM
key or the relay password. Those are Secrets you provide.

### 1. Secrets you provide

```sh
kubectl create namespace acme

# The CA: issuers.json, the issuer certificate and key, the root CERTIFICATE (never a root key: the script refuses).
# Prints the `ca.items` for your values.
scripts/ca-k8s-secret.sh ./server-ca acme-ca -- -n acme

# The passphrase of the issuer key (the environment variable ACME_CA_KEY_PASSPHRASE named in issuers.json).
kubectl -n acme create secret generic acme-ca-passphrase --from-literal=passphrase='<the issuer key passphrase>'

# The DKIM private key of section 2.
kubectl -n acme create secret generic acme-dkim --from-file=dkim.key=./dkim.private.pem

# The outbound relay's password (only when the relay needs one).
kubectl -n acme create secret generic acme-smtp --from-literal=password='<the relay password>'
```

Why the script and `ca.items`: a Secret's keys cannot contain `/`, but `issuers.json` names files in sub-directories
(`smime-r1/cert.pem`). Each file is stored as `smime-r1--cert.pem` and `ca.items` maps it back to its path, so `issuers.json` is
used exactly as `ca:init` wrote it. The equivalent by hand is one `--from-file=<key>=<path>` per file plus the matching
`items`.

Two things the settings parser does to values from the environment: it reads anything that looks like JSON (`1.0`, `true`,
`null`) as that value rather than as text, so avoid such a relay password or passphrase.

### 2. Values

`values.yaml`, with everything a real install needs:

```yaml
host: acme.example.com            # the CA's public host name; acme.externalUrl defaults to https://<host>
trustedProxies:                   # REQUIRED with the Gateway: your Gateway pods'/load balancer's CIDR(s), nothing wider
  - 10.42.0.0/16
acme:
  caaIdentities: [example.com]    # what a domain's CAA issuemail must name to allow this CA
mail:
  smtp: { host: smtp.example.net, port: 587, user: acme, existingSecret: acme-smtp }
  dkim: { existingSecret: acme-dkim, selector: acme1 }
ca:
  existingSecret: acme-ca
  items:                          # as printed by scripts/ca-k8s-secret.sh
    - { key: issuers.json,        path: issuers.json }
    - { key: root-r1--cert.pem,   path: root-r1/cert.pem }
    - { key: smime-r1--cert.pem,  path: smime-r1/cert.pem }
    - { key: smime-r1--key.pem,   path: smime-r1/key.pem }
  passphrase: { existingSecret: acme-ca-passphrase }
inboundSmtp:
  enabled: true                   # the built-in receiver behind a LoadBalancer on port 25 (section 3)
service:
  replicas: 2                     # more than one needs Redis, which is bundled by default
```

`mail.from` and `mail.replyTo` default to `acme-challenge@<host>` and `acme-response@<host>`; set them to use another domain.

### 3. Install

```sh
helm install acme oci://ghcr.io/rapidmx/charts/acme --version 0.1.0 -n acme -f values.yaml   # once published
# from a checkout:  helm dependency build ./helm && helm install acme ./helm -n acme -f values.yaml
helm test acme -n acme        # fetches /directory from inside the cluster
```

`NOTES.txt` prints the directory URL, the DNS records still to publish, the commands to read the generated secrets and how to
find the SMTP Service's address.

### What the chart refuses to render

Each is a clear `fail` message rather than a crash loop later:

* `ca.existingSecret` empty (every environment: the service does not start without an issuer manifest);
* in a real deployment (`environment` other than `dev`/`development`/`test`): no `host`, an external URL that is not a bare
  `https://` origin, placeholder mail addresses, no `mail.smtp.host`, no DKIM Secret or selector, `trustedProxies` empty while
  the Gateway is enabled, `gateway.tls` with no way to get a certificate;
* `service.replicas` above 1 without Redis (nonces and rate-limit buckets would be per pod);
* no MongoDB (`mongodb.create=false` without `mongodb.url`);
* generated secrets when rendered without cluster access (`helm template`, GitOps, `--dry-run`), where they could not be kept
  stable: set `metrics.secret`, `inboundHttp.secret`, `mongodb.auth.rootPassword` and `redis.auth.password` explicitly, or
  `secrets.existingSecret` for the first two (this is what `helm/ci/production-values.yaml` does for CI).

### What it creates

* **Deployment** `<fullname>-services`: non-root (uid 1000), read-only root file system with an `emptyDir` `/tmp`, all
  capabilities dropped, seccomp `RuntimeDefault`, no service-account token; probes on `GET /status`; a preStop sleep and a
  60 s grace period for the drain; rolling updates with `maxUnavailable: 0`; with more than one replica, topology spread over
  nodes and zones and a PodDisruptionBudget. The CA Secret is mounted read-only at `/var/lib/acme/ca`, the DKIM key at
  `/var/lib/acme/dkim`, the optional SMTP certificate at `/var/lib/acme/smtp-tls`, all mode `0440` for the pod's group.
* **Services:** `<fullname>-services` (port 80 → 3000) and, with `inboundSmtp.enabled`, `<fullname>-smtp` (port 25 → 2525).
* **Gateway API:** a Gateway (unless `gateway.name` names an existing one), an HTTPS listener with the certificate
  cert-manager issues for `host`, an HTTPRoute of the **public paths only** (`gateway.publicPaths`: `/acme`, `/ca`, `/certs`,
  `/crl`, `/directory`, `/ocsp`, `/rate-limits`, `/status`, `/terms`) and an HTTP-to-HTTPS redirect. `/metrics` and
  `/internal/*` are never routed.
* **Secrets:** `<fullname>-secrets` holds the bearer secrets of `/metrics` and the HTTP ingest route, and
  `<release>-datastore-auth` the bundled MongoDB/Redis passwords: generated once with `randAlphaNum` and **kept across upgrades**
  by reading the existing Secret back with `lookup`. `<fullname>-db-info` holds the connection strings; `<fullname>-config` the
  rest of the configuration.
* **MongoDB and Redis** (Bitnami): authenticated, NetworkPolicy admitting only the CA's pods, MongoDB persistent. Use your own
  with `mongodb.create=false` + `mongodb.url` and/or `redis.create=false` + `redis.url`. Anything else the service reads can be
  set with `service.config` (name → value, e.g. `acme__order_expiry_hours: 72`).

The Bitnami charts pull the `latest` image tag, so a chart upgrade can move MongoDB to a new major version; pin
`mongodb.image.tag` (and `redis.image.tag`) if you want to control that, or use a managed MongoDB.

## Docker without Kubernetes

The image needs the same things the chart wires up. A minimal run, with the CA directory from section 1 mounted read-only:

```sh
docker run -d --name acme --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -p 3000:3000 -p 25:2525 \
  -v "$PWD/server-ca:/var/lib/acme/ca:ro" -v "$PWD/dkim.private.pem:/var/lib/acme/dkim/dkim.key:ro" \
  -e ACME_CA_KEY_PASSPHRASE='...' \
  -e acme__external_url=https://acme.example.com \
  -e acme__mail__from=acme-challenge@acme.example.com -e acme__mail__reply_to=acme-response@acme.example.com \
  -e acme__mail__smtp__host=smtp.example.net -e acme__mail__smtp__user=acme -e acme__mail__smtp__pass='...' \
  -e acme__mail__dkim__domain=acme.example.com -e acme__mail__dkim__selector=acme1 \
  -e acme__mail__dkim__private_key_path=/var/lib/acme/dkim/dkim.key \
  -e acme__mail__inbound__smtp__enabled=true \
  -e datastores__mongo__url=mongodb://... -e datastores__cache__type=redis -e datastores__cache__url=redis://... \
  -e trusted_proxies='["203.0.113.5"]' \
  ghcr.io/rapidmx/acme:0.1.0
```

Put a TLS-terminating reverse proxy in front of port 3000 (the external URL must be `https`). The image runs as `node` and
its files are read-only to it, so the mounted files must be readable by uid 1000 (`chown 1000` the key files, or mode 0440
with a matching group). The HTTP server reads its port from the lower-case setting `port`, not from `PORT`.

## Upgrading

```sh
helm upgrade acme oci://ghcr.io/rapidmx/charts/acme --version <new> -n acme -f values.yaml
```

* Read `RELEASE_NOTES.md` first. Chart version, `appVersion` and `service.image.tag` move together.
* The generated secrets (bearer secrets, database passwords) are read back from the cluster and are not regenerated, so no
  value has to be supplied again. To rotate one deliberately, delete its Secret and upgrade, then
  `kubectl rollout restart deploy/<fullname>-services` (the pods read their environment only at start).
* The rolling update keeps the old pods until the new ones are Ready. The bundled MongoDB is replaced with `Recreate` (one
  `mongod` owns the volume), so it is briefly unavailable during a MongoDB pod-spec change; the CA answers 5xx until it is
  back. `helm rollback` does not roll data back.
* `acme.external_url`/`host` **must not change** once certificates were issued: their CRL, OCSP and issuer addresses are
  written into them.
* The collections' indexes are created by the service at start (`datastores.mongo.synchronize`); there are no separate
  migrations.

## Rotating the issuing CA

The issuing CA's certificate is valid for 10 years by default, but rotate earlier if its key may have been exposed, or before
expiry. Old issuers stay listed so that their CRLs and OCSP keep working and their certificates keep being served; exactly one
is `active` and signs new certificates.

On the offline machine, with the root key and the `./server-ca` directory from section 1:

```sh
ROOT_PASS='...' ACME_CA_KEY_PASSPHRASE='<the same passphrase as the current issuer key>' \
  yarn ca:init --issuer-only --issuer-id smime-r2 --root-id r1 --activate \
    --root-cert ./server-ca/root-r1/cert.pem --root-key ./root/root-r1/key.pem --root-key-passphrase-env ROOT_PASS \
    --dir ./server-ca --passphrase-env ACME_CA_KEY_PASSPHRASE --base-url https://acme.example.com
```

`--root-id r1` keeps the new issuer under the existing root (the default would invent `root-r2`), and `--root-cert` must be the
copy inside `--dir` (pointing it elsewhere makes ca:init refuse to overwrite that copy). `--activate` makes the new issuer the
active one in `issuers.json` and the old one inactive. Every issuer whose `passphrase_env` is `ACME_CA_KEY_PASSPHRASE` is
decrypted with that one value, so give the new key the same passphrase; to use a different one, name another variable
(`--passphrase-env ACME_CA_KEY_PASSPHRASE_R2`) and inject it with `service.extraEnv` (the chart wires only
`ACME_CA_KEY_PASSPHRASE` by itself). Then:

1. Create a **new** Secret from `./server-ca` (`scripts/ca-k8s-secret.sh ./server-ca acme-ca-r2 -- -n acme`); it contains
   both issuers' certificates and keys. Keep the old issuer's **key** in it for as long as its certificates can still be
   valid or revoked: it signs their CRL and OCSP answers.
2. `helm upgrade ... --set ca.existingSecret=acme-ca-r2` with the new `ca.items`. The rolling update swaps the pods; check
   `GET /ca` lists both issuers and `kubectl logs` says `Issuing with 'smime-r2'`.
3. New certificates are issued by `smime-r2`; existing ones remain valid until they expire. Renewals are re-issued by the new
   issuer. Delete `acme-ca` (the old Secret) only when the old issuer has nothing left to serve, and delete the retired
   issuer from `issuers.json` only after every certificate it issued has expired.

If the root itself is replaced, relying parties must trust the new root (`GET /ca/roots.pem` serves every root the issuers
chain to): plan that as a migration, not a routine rotation.

## The operator API

`/admin` lets an operator search what the CA issued and revoke it: one certificate, or every valid certificate of an address, an
account, a public key (the response to a compromised key) or a list of serials, and suspend an account. It is one bearer secret
(`acme.admin_secret`, env `acme__admin_secret`, at least 32 characters outside development) with power over everything the CA has
issued, so treat it like the CA's keys: it answers 404 until a secret is set, it is **never routed through the public gateway** (the
Helm chart only routes an allow-list of public paths and generates the secret into `<release>-secrets`), and a wrong token costs
the caller's address a token from a small bucket (20 an hour, burst 10), after which even the right token is refused for that
address. Reach it from inside the cluster or with a port-forward. Send `X-Operator: you@example.org` so the record shows who acted.

```bash
kubectl -n acme port-forward svc/acme-services 3000:3000 &
ADMIN=$(kubectl -n acme get secret acme-secrets -o jsonpath='{.data.acme__admin_secret}' | base64 -d)
api() { curl -sS -H "Authorization: Bearer $ADMIN" -H "X-Operator: you@example.org" -H "Content-Type: application/json" "$@"; }

# what has been issued to an address (any spelling of an internationalized one)
api "http://localhost:3000/admin/certificates?email=alice@example.com"
# revoke one certificate; reasons: unspecified, keyCompromise, affiliationChanged, superseded, cessationOfOperation, privilegeWithdrawn
api -X POST http://localhost:3000/admin/certificates/<serial>/revoke -d '{"reason":"keyCompromise","note":"ticket 4711"}'
# revoke everything certifying a compromised key: look first with dryRun, then do it
api -X POST http://localhost:3000/admin/revocations -d '{"selector":{"spki":"<sha256 hex of the SPKI>"},"reason":"keyCompromise","dryRun":true}'
api -X POST http://localhost:3000/admin/revocations -d '{"selector":{"spki":"<sha256 hex of the SPKI>"},"reason":"keyCompromise"}'
# suspend an abusive account and revoke its certificates; undo a mistaken suspension
api -X POST http://localhost:3000/admin/accounts/<id>/suspend -d '{"note":"abuse report 42","revokeCertificates":true,"reason":"keyCompromise"}'
api -X POST http://localhost:3000/admin/accounts/<id>/reinstate
```

A selection is capped at 1000 certificates per call (narrow it, or use `serials`); `dryRun` shows what would be revoked. The CRL of each
affected issuing CA is regenerated once at the end and OCSP answers `revoked` immediately. A revocation for `keyCompromise` also
puts the key on the list of keys the CA will never certify again. There is no way to un-revoke a certificate (there is no
`certificateHold`), and an account its holder deactivated cannot be reinstated.

## Backing up MongoDB

**The certificates in MongoDB are the record of what this CA issued and revoked. There is no other copy.** The collections are
`acme_account`, `acme_order`, `acme_authorization`, `acme_certificate` and `acme_crl`. Losing them means the CA can no longer
show what it issued, the CRLs it published shrink to nothing (revoked certificates would look valid again) and OCSP answers
`unknown`. The CA key alone is not a backup.

* Take regular backups to storage **outside the cluster**: `mongodump --uri "$MONGO_URL" --gzip --archive=acme.gz` (run it from
  a pod or a machine that can reach MongoDB; check that the image you use ships `mongodump`), and/or volume snapshots of the
  MongoDB volume. Encrypt them: they contain account public keys and e-mail addresses.
* Practise the restore (`mongorestore --gzip --archive=acme.gz` into a scratch database) and start a test instance against it.
  An untested backup is not a backup.
* A managed MongoDB with point-in-time recovery is the better production choice; set `mongodb.create=false` and
  `mongodb.url`.
* The bundled MongoDB is a single standalone instance on one volume (no replica set, so no transactions and no failover);
  size your recovery objectives accordingly.
* Redis needs no backup (nonces and rate-limit buckets only). Back up the CA Secret material and the offline root separately,
  encrypted, in more than one place.

## Hardening checklist

* [ ] The **root key is offline** (encrypted, in more than one safe place) and was never in a cluster, image, backup or
  repository. `scripts/ca-k8s-secret.sh` refuses a directory that holds one.
* [ ] The issuer key is **encrypted** (`--passphrase-env`), its passphrase is a separate Secret, or the key lives in OpenBao
  Transit. Restrict who can read Secrets in the namespace (RBAC) and enable encryption at rest for Secrets on the cluster.
* [ ] `host` / `acme.external_url` is a bare `https://` origin and will never change. HSTS is left on (`gateway.hsts: true`).
* [ ] **`trustedProxies` names exactly your Gateway pods' or load balancer's addresses, and nothing wider.** Behind the Gateway
  every request comes from a proxy pod: without it every client shares one address and the per-IP rate limits cannot tell them
  apart, and a range that is too wide lets any pod in it claim any client address. The chart refuses an empty value.
* [ ] Only the public paths are routed (`gateway.publicPaths`). `/metrics` and `/internal/*` are reached through the in-cluster
  Service only, with their bearer secrets, and are never put behind the public HTTPRoute or an Ingress.
* [ ] **Restrict the CA pod's egress.** It needs DNS, MongoDB, Redis, and the **one SMTP relay** it sends through (and OpenBao if
  used) - nothing else. In particular allow port 25 (and 465/587) only to the configured relay: the CA resolves MX and A records
  named by applicants' domains, which are attacker-influenced, and although it only looks them up (all outbound mail goes
  through the relay) it must not be able to reach arbitrary SMTP servers. Example, to adapt (labels and addresses are yours;
  not applied to a cluster by the author of this document):

  ```yaml
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata: { name: acme-egress, namespace: acme }
  spec:
    podSelector:
      matchLabels: { app.kubernetes.io/name: acme, app.kubernetes.io/component: services }
    policyTypes: [Egress]
    egress:
      - to:                                   # DNS (CAA/MX lookups, DKIM keys): the cluster resolver only
          - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } }
            podSelector: { matchLabels: { k8s-app: kube-dns } }
        ports: [{ port: 53, protocol: UDP }, { port: 53, protocol: TCP }]
      - to: [{ podSelector: { matchLabels: { app.kubernetes.io/name: mongodb } } }]
        ports: [{ port: 27017 }]
      - to: [{ podSelector: { matchLabels: { app.kubernetes.io/name: redis } } }]
        ports: [{ port: 6379 }]
      - to: [{ ipBlock: { cidr: 203.0.113.10/32 } }]   # the outbound SMTP relay, only
        ports: [{ port: 587 }]
  ```

  Publicly accessible DNS resolution must still work: if your cluster DNS does not forward, allow the resolvers named in
  `acme.dns.servers` instead.
* [ ] **MongoDB and Redis are unreachable from outside** their namespace and from other workloads: the chart enables their
  NetworkPolicies (only pods carrying the `<name>-client` label may connect), keeps the Services `ClusterIP`, enables
  authentication and never routes them through the Gateway. NetworkPolicy only works on a CNI that enforces it - check yours.
* [ ] The inbound SMTP Service exposes port 25 and nothing else. Give the listener a certificate (`inboundSmtp.tls`) and keep
  `max_size_bytes` small. If only a mail bridge is used, leave `inboundSmtp.enabled=false`.
* [ ] The namespace enforces the Pod Security `restricted` profile; the chart's pods (non-root, read-only root file system, no
  capabilities, seccomp `RuntimeDefault`) are written to satisfy it.
* [ ] Pin `service.image.tag` to a release (or a digest) and the Bitnami image tags; do not float on `latest`.
* [ ] DKIM, SPF and (once verified) DMARC pass for the challenge e-mail: send one to a mailbox you can inspect and read its
  `Authentication-Results`.
* [ ] MongoDB backups run, are stored off-cluster, encrypted, and a restore has been rehearsed.
* [ ] Monitor: `GET /status`, the age of the CRL (`acme.ca.crl_refresh_hours`, `crl_validity_hours`; the CRL must never lapse),
  the issuer certificate's `notAfter`, the rate of `rateLimited` and 5xx answers, and `/metrics` (bearer secret, in-cluster).
* [ ] Synchronised clocks (NTP) on the nodes: certificate validity and nonce lifetimes depend on the time.
* [ ] More than one replica, with Redis, if the CA must survive a node loss (the chart spreads them and adds a
  PodDisruptionBudget).

## What has and has not been verified

Verified by the author of these files, on a Windows workstation without a container runtime or a Kubernetes cluster:

* `yarn build` output layout: `node dist/src/server.js` is the entry point, and a **production-only** `node_modules`
  (`yarn workspaces focus --production`, as the Dockerfile does) starts with `NODE_ENV=production` against a MongoDB, with an
  encrypted issuer key from `ca:init`, the SMTP receiver enabled, and serves `/status`, `/directory`, `/ca`, the CRL and
  `/metrics`. It still starts and serves with Node's permission model denying every file-system write outside a scratch
  directory, which is the evidence for the read-only root file system.
* The Compose file and both workflows parse; `docker compose config` accepts the Compose files; the shell scripts pass
  `bash -n`; `ca-k8s-secret.sh` was run against a fake `kubectl` and against the ca-init output.
* `helm lint` and `helm template` with the vendored Bitnami subcharts (`helm dependency build` from the committed
  `Chart.lock`): a production-like install, three replicas with and without Redis, inbound SMTP, external MongoDB/Redis, an
  existing Gateway and a certificate of your own, a development install, and each of the failure messages above. The rendered
  YAML parses, and the Bitnami subcharts use the generated `<release>-datastore-auth` Secret and label selectors this chart
  provides.
* A DKIM signature made with the key from section 2 verifies with `mailauth` against the TXT value the command prints; the
  `ca:init` root-only / issuer-only / rotation commands above were run.
* The `curl --url smtp://...` recipe in `docker-compose.yml` against the built-in receiver (accepted with `250`).

**Not** verified: building the image or running Compose (no Docker daemon was available), any of it on a real cluster (Gateway
API, cert-manager HTTP-01, `lookup`-preserved secrets across a real upgrade, the bundled MongoDB/Redis starting with the
generated password, the NetworkPolicies, the PodDisruptionBudget, the LoadBalancer on port 25), a real DKIM-verified reply
completing a challenge, OpenBao Transit signing, the CI workflows themselves (never run), publishing to GHCR, and the
`mongodump` backup commands. Treat those steps as the first thing to test in a staging environment.
