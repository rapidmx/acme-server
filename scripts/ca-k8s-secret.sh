#!/usr/bin/env bash
# Creates the Kubernetes Secret the Helm chart mounts at /var/lib/acme/ca from the output directory of `yarn ca:init`
# (issuers.json plus the issuer's certificate and key and the root CERTIFICATE), and prints the matching `ca.items` values.
#
#   scripts/ca-k8s-secret.sh <ca-dir> [<secret-name>] [-- <extra kubectl args, e.g. -n acme>]
#
# Why the `items`: a Secret's keys cannot contain a slash, but issuers.json refers to files in sub-directories
# (smime-r1/cert.pem). Each file is stored under its path with "/" written as "--" (smime-r1--cert.pem), and `ca.items`
# tells the chart which key goes to which path, so issuers.json is used exactly as ca:init wrote it.
#
# Refuses a directory that still holds a root private key: that key belongs on offline media, never in a cluster.
set -euo pipefail

usage() {
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-1}"
}

[[ $# -ge 1 ]] || usage
[[ "$1" == "-h" || "$1" == "--help" ]] && usage 0

dir="$1"
shift
name="acme-ca"
if [[ $# -gt 0 && "$1" != "--" ]]; then
    name="$1"
    shift
fi
[[ "${1:-}" == "--" ]] && shift

[[ -f "$dir/issuers.json" ]] || { echo "ca-k8s-secret: $dir/issuers.json not found (is this a ca:init output directory?)" >&2; exit 1; }
if compgen -G "$dir/root-*/key.pem" > /dev/null; then
    echo "ca-k8s-secret: $dir holds a root private key (root-*/key.pem). Move it to offline media and delete it from here first." >&2
    exit 1
fi

args=()
items=""
while IFS= read -r file; do
    rel="${file#./}"
    key="${rel//\//--}"
    args+=("--from-file=$key=$dir/$rel")
    items+="    - key: $key"$'\n'"      path: $rel"$'\n'
done < <(cd "$dir" && find . -type f | LC_ALL=C sort)

kubectl create secret generic "$name" "${args[@]}" "$@"

echo
echo "Add this to your Helm values:"
echo
printf 'ca:\n  existingSecret: %s\n  items:\n%s' "$name" "$items"
