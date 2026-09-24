#!/bin/bash
# Smoke test for the image and docker-compose.yml: builds and starts the whole development stack (CA, MongoDB, Redis, mail
# sink, generated development CA), waits for the CA's own HEALTHCHECK to pass, then checks that it really serves what a
# client needs. Run from the repository root; used by CI (.github/workflows/ci.yml).
#
# The stack binds 127.0.0.1:3000 (and 2525, 8025): stop anything else using them first.
cd "$(dirname "$0")/.." || exit 1

BASE_URL="${BASE_URL:-http://localhost:3000}"
TIMEOUT="${TIMEOUT:-180}"

docker compose up -d --build
startTime=$(date +%s)

# The container's own HEALTHCHECK (GET /status from inside) is what has to turn healthy.
health() {
    docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$(docker compose ps -q acme)" 2>/dev/null
}

status=$(health)
while [[ "$status" != "healthy" && $(( $(date +%s) - startTime )) -lt $TIMEOUT ]]; do
    sleep 2
    echo "Waiting for the CA to become healthy (currently: ${status:-not running})..."
    status=$(health)
done

exitCode=1
if [[ "$status" == "healthy" ]]; then
    echo -e "\e[32mService started successfully.\e[0m"
    exitCode=0
    # What a client and a relying party need: the ACME directory, the trust anchor, the issuer's CRL.
    for path in /directory /ca/roots.pem /crl/smime-r1.crl; do
        if curl -fsS -o /dev/null "$BASE_URL$path"; then
            echo "OK   GET $path"
        else
            echo -e "\e[31mFAIL GET $path\e[0m"
            exitCode=1
        fi
    done
else
    echo -e "\e[31mService failed to become healthy.\e[0m"
fi

if [[ $exitCode -ne 0 ]]; then
    docker compose ps
    docker compose logs --no-color --tail=100
fi
docker compose down -v --rmi local
exit $exitCode
