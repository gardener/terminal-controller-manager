#!/bin/bash -e
#
# SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

script_dir=$(readlink -f "$(dirname "$0")")

# make sure that the local tmp directory exists, otherwise readlink will fail
mkdir -p $(readlink -f "$script_dir"/../tmp)
tls_output_path=$(readlink -f "${TLS_OUTPUT_PATH:-$script_dir/../tmp/tls}")

if [ -z "$WEBHOOK_CERTS_PATH" ]; then
  webhook_certs_path="/tmp/k8s-webhook-server/serving-certs"
else
  webhook_certs_path=$(readlink -f "$WEBHOOK_CERTS_PATH")
fi

if [ -z "$METRICS_CERTS_PATH" ]; then
  metrics_certs_path="/tmp/k8s-metrics-server/serving-certs"
else
  metrics_certs_path=$(readlink -f "$METRICS_CERTS_PATH")
fi

echo "> Generating certificates.."
"$script_dir"/gen-certs.sh --cert-name terminal-admission-controller-tls
"$script_dir"/gen-certs.sh --cert-name terminal-metrics-server-tls

echo "> Creating temporary directory for serving certificates under $webhook_certs_path"
mkdir -p "$webhook_certs_path"

echo "> Copying certificates to $webhook_certs_path"
cp "$tls_output_path/terminal-admission-controller-tls.pem" "$webhook_certs_path/tls.crt"
cp "$tls_output_path/terminal-admission-controller-tls-key.pem" "$webhook_certs_path/tls.key"

echo "> Creating temporary directory for metrics certificates under $metrics_certs_path"
mkdir -p "$metrics_certs_path"

echo "> Copying metrics certificates to $metrics_certs_path"
cp "$tls_output_path/terminal-metrics-server-tls.pem" "$metrics_certs_path/tls.crt"
cp "$tls_output_path/terminal-metrics-server-tls-key.pem" "$metrics_certs_path/tls.key"
