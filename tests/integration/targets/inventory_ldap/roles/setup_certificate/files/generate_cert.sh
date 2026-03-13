#!/usr/bin/env bash

set -o pipefail -eux

TARGET="${1}"
PASSWORD="${2}"

echo "Generating CA certificate"
cat > openssl.conf << EOL
distinguished_name = req_distinguished_name

[req_distinguished_name]
[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign
EOL

openssl genrsa \
    -aes256 \
    -out ca.key \
    -passout pass:"${PASSWORD}"

openssl req \
    -new \
    -x509 \
    -days 365 \
    -key ca.key \
    -config openssl.conf \
    -extensions v3_ca \
    -out ca.pem \
    -subj "/CN=microsoft.ad root" \
    -passin pass:"${PASSWORD}"

echo "Generating ${TARGET} LDAPS certificate"
cat > openssl.conf << EOL
distinguished_name = req_distinguished_name

[req_distinguished_name]

[req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
subjectAltName = DNS:${TARGET}
EOL

openssl req \
    -new \
    -sha256 \
    -subj "/CN=${TARGET}" \
    -newkey rsa:2048 \
    -keyout "ldaps.key" \
    -out "ldaps.csr" \
    -passin pass:"${PASSWORD}" \
    -passout pass:"${PASSWORD}"

openssl x509 \
    -req \
    -in "ldaps.csr" \
    -sha256 \
    -out "ldaps.pem" \
    -days 365 \
    -extfile openssl.conf \
    -extensions req \
    -passin pass:"${PASSWORD}" \
    -CA "ca.pem" \
    -CAkey "ca.key" \
    -CAcreateserial

# PBE-SHA1-3DES/nomac is used for compatibility with Server 2016 and older
openssl pkcs12 \
    -export \
    -out "ldaps.pfx" \
    -inkey "ldaps.key" \
    -in "ldaps.pem" \
    -keypbe PBE-SHA1-3DES \
    -certpbe PBE-SHA1-3DES \
    -nomac \
    -passin pass:"${PASSWORD}" \
    -passout pass:"${PASSWORD}"

rm ca.srl
rm ldaps.csr
rm openssl.conf
