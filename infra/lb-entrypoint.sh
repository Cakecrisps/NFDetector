#!/bin/sh
set -eu
mkdir -p /etc/nf/tls
if [ ! -f /etc/nf/tls/server.crt ] || [ ! -s /etc/nf/tls/server.crt ] || \
   [ ! -f /etc/nf/tls/server.key ] || [ ! -s /etc/nf/tls/server.key ]; then
    if [ "${NF_TLS_AUTOGENERATE:-1}" != "1" ]; then
        echo 'TLS certificate and private key must be mounted on lb' >&2
        exit 1
    fi
    openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
        -keyout /etc/nf/tls/server.key -out /etc/nf/tls/server.crt \
        -subj "/CN=${NF_TLS_HOST:-localhost}" \
        -addext "subjectAltName=DNS:${NF_TLS_HOST:-localhost},DNS:localhost,IP:127.0.0.1"
    chmod 600 /etc/nf/tls/server.key
fi
# Share only the public certificate with API. The private key remains on LB.
mkdir -p /etc/nf/public
cp /etc/nf/tls/server.crt /etc/nf/public/server.crt.tmp
chmod 644 /etc/nf/public/server.crt.tmp
mv /etc/nf/public/server.crt.tmp /etc/nf/public/server.crt
exec nginx -g 'daemon off;'
