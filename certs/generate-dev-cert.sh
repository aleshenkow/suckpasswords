#!/usr/bin/env sh
set -eu

openssl req -x509 -nodes -days 365 \
  -newkey rsa:4096 \
  -keyout server.key \
  -out server.crt \
  -subj "/CN=localhost"

echo "Generated certs: server.crt and server.key"
