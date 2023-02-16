#!/usr/bin/env bash

set -o pipefail -eux

TARGET="${1}"
PASSWORD="${2}"

generate () {
    NAME="${1}"
    SUBJECT="${2}"
    KEY="${3}"
    CA_NAME="${4}"
    CA_OPTIONS=("-CA" "${CA_NAME}.pem" "-CAkey" "${CA_NAME}.key" "-CAcreateserial")

    cat > openssl.conf << EOL
distinguished_name = req_distinguished_name

[req_distinguished_name]

[req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:${SUBJECT}
EOL

    echo "Generating ${NAME} signed cert"
    openssl req \
        -new \
        "-${KEY}" \
        -subj "/CN=${SUBJECT}" \
        -newkey rsa:2048 \
        -keyout "${NAME}.key" \
        -out "${NAME}.csr" \
        -config openssl.conf \
        -reqexts req \
        -passin pass:"${PASSWORD}" \
        -passout pass:"${PASSWORD}"

    openssl x509 \
        -req \
        -in "${NAME}.csr" \
        "-${KEY}" \
        -out "${NAME}.pem" \
        -days 365 \
        -extfile openssl.conf \
        -extensions req \
        -passin pass:"${PASSWORD}" \
        "${CA_OPTIONS[@]}"

    # PBE-SHA1-3DES/nomac is used for compatibility with Server 2016 and older
    openssl pkcs12 \
        -export \
        -out "${NAME}.pfx" \
        -inkey "${NAME}.key" \
        -in "${NAME}.pem" \
        -keypbe PBE-SHA1-3DES \
        -certpbe PBE-SHA1-3DES \
        -nomac \
        -passin pass:"${PASSWORD}" \
        -passout pass:"${PASSWORD}"

    rm openssl.conf
}

echo "Generating CA certificate"
openssl genrsa \
    -aes256 \
    -out ca.key \
    -passout pass:"${PASSWORD}"

openssl req \
    -new \
    -x509 \
    -days 365 \
    -key ca.key \
    -out ca.pem \
    -subj "/CN=microsoft.ad root" \
    -passin pass:"${PASSWORD}"

echo "Generating ${TARGET} LDAPS certificate"
generate ldaps "${TARGET}" sha256 ca
