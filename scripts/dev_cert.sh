#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="${1:-certs/dev}"
CERT_NAME="${CERT_NAME:-relay}"
CERT_CN="${CERT_CN:-localhost}"
CERT_SAN_DNS="${CERT_SAN_DNS:-localhost}"
CERT_SAN_IP="${CERT_SAN_IP:-127.0.0.1}"

mkdir -p "${OUTPUT_DIR}"

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -sha256 \
  -nodes \
  -days 365 \
  -keyout "${OUTPUT_DIR}/${CERT_NAME}-key.pem" \
  -out "${OUTPUT_DIR}/${CERT_NAME}-cert.pem" \
  -subj "/CN=${CERT_CN}" \
  -addext "subjectAltName=DNS:${CERT_SAN_DNS},IP:${CERT_SAN_IP}"

echo "Wrote ${OUTPUT_DIR}/${CERT_NAME}-cert.pem and ${OUTPUT_DIR}/${CERT_NAME}-key.pem"
