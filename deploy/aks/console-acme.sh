#!/bin/sh
# Keeps a Let's Encrypt certificate for the console's DNS name. Runs as a sidecar next to the nginx proxy.
#
# nginx serves the HTTP-01 challenge files from /acme/webroot on port 80 and reads the certificate from /acme/live.
# Until the first certificate is issued, /acme/live holds the cluster-CA certificate from the TLS secret, so the
# console is reachable (with a browser warning) while issuing. Issued certificates and the ACME account live on a
# volume that survives pod restarts, so restarts do not request a new certificate each time.
#
# Environment: DOMAIN, EMAIL, ACME_SERVER (the directory URL).
set -u
WEBROOT=/acme/webroot
STATE=/acme/lego
LIVE=/acme/live
umask 022
mkdir -p "$WEBROOT/.well-known/acme-challenge" "$STATE" "$LIVE"

if [ ! -s "$LIVE/tls.crt" ]; then
  cp /etc/console-tls/tls.crt "$LIVE/tls.crt"
  cp /etc/console-tls/tls.key "$LIVE/tls.key"
fi

install_cert() {
  cp "$STATE/certificates/$DOMAIN.crt" "$LIVE/tls.crt.new" &&
    cp "$STATE/certificates/$DOMAIN.key" "$LIVE/tls.key.new" &&
    mv "$LIVE/tls.key.new" "$LIVE/tls.key" &&
    mv "$LIVE/tls.crt.new" "$LIVE/tls.crt"
}

lego_args="--server $ACME_SERVER --email $EMAIL --accept-tos --path $STATE --domains $DOMAIN --http --http.webroot $WEBROOT"

while :; do
  if [ -s "$STATE/certificates/$DOMAIN.crt" ]; then
    # shellcheck disable=SC2086
    /lego $lego_args renew --days 30 --no-random-sleep && install_cert && echo "certificate in place for $DOMAIN"
    wait_seconds=43200
  else
    # shellcheck disable=SC2086
    if /lego $lego_args run && install_cert; then
      echo "certificate issued for $DOMAIN"
      wait_seconds=43200
    else
      # Back off between failures: Let's Encrypt limits repeated failed validations per hostname.
      echo "issuing failed; retrying in 15 minutes" >&2
      wait_seconds=900
    fi
  fi
  sleep "$wait_seconds"
done
