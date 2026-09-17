#!/usr/bin/env bash
# Certificates for the conformance rig, under conformance/certs (ignored by git):
#
#   ca.crt/ca.key      a private CA for the run
#   ridm.crt/key       https://ridm.local, the TLS front for the OP under test
#   suite.crt/key      the suite's own nginx, which the OP calls back for
#                      back-channel logout; its stock certificate is self-signed,
#                      so we issue one from our CA for this host's address
#   truststore.p12     the CA as a Java truststore, so the suite trusts ridm.local
#   bundle.crt         the system roots plus the CA, for the OP's SSL_CERT_FILE
#
# The suite publishes itself at this host's own address, the one name both the
# containers and the host resolve without a hosts file. It is written to
# conformance/.env, which docker compose reads on its own.
set -euo pipefail
cd "$(dirname "$0")"
host_ip="${SUITE_HOST:-$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')}"
[ -n "$host_ip" ] || { echo "cannot determine this host's address; set SUITE_HOST" >&2; exit 1; }
printf 'SUITE_HOST=%s\n' "$host_ip" > .env
mkdir -p certs && cd certs

[ -f ca.key ] || openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 3650 -subj "/CN=rIDM conformance CA" 2>/dev/null

issue() { # issue <name> <san>
  openssl req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$1" 2>/dev/null
  printf "subjectAltName=%s\nextendedKeyUsage=serverAuth\n" "$2" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -out "$1.crt" -days 3650 -extfile "$1.ext" 2>/dev/null
}
issue ridm "DNS:ridm.local"
issue suite "IP:$host_ip,DNS:nginx,DNS:localhost"

openssl pkcs12 -export -nokeys -in ca.crt -out truststore.p12 -passout pass:changeit 2>/dev/null
for roots in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt; do
  [ -f "$roots" ] && cat "$roots" > bundle.crt && break
done
cat ca.crt >> bundle.crt
echo "certs ready in $PWD; the suite will publish itself at https://$host_ip:8443"
