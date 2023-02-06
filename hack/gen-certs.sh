#!/bin/bash -e
#
# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

script_dir=$(readlink -f "$(dirname "$0")")

# make sure that the local tmp directory exists, otherwise readlink will fail
mkdir -p $(readlink -f $script_dir/../tmp)

output_path=$(readlink -f ${TLS_OUTPUT_PATH:-$script_dir/../tmp/tls})
config_path=$(readlink -f "${TLS_CONFIG_PATH:-$script_dir/../tls}")
ca_name=${CA_NAME:-ca}
cert_name=${CERT_NAME:-terminal-admission-controller-tls}

if [[ ! -f "$output_path/$ca_name.pem" || ! -f "$output_path/$cert_name.pem" ]]; then
  mkdir -p "$output_path"
  echo "> Generating ca and server certificate. Output dir: $output_path"

  cfssl gencert \
    -initca "$config_path/$ca_name-csr.json" | cfssljson -bare "$output_path/$ca_name" -

  cfssl gencert \
    -profile=server \
    -ca="$output_path/$ca_name.pem" \
    -ca-key="$output_path/$ca_name-key.pem" \
    -config="$config_path/ca-config.json" \
    "$config_path/$cert_name-config.json" | cfssljson -bare "$output_path/$cert_name"
else
  echo "> Certificates $output_path/$cert_name.pem and $output_path/$ca_name.pem already exist. Skipping generation."
fi

rm -f "$output_path/$ca_name.csr"
rm -f "$output_path/$cert_name.csr"
