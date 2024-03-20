#!/bin/bash -e
#
# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

script_dir=$(readlink -f "$(dirname "$0")")

# make sure that the local tmp directory exists, otherwise readlink will fail
mkdir -p $(readlink -f $script_dir/../tmp)

output_path=$(readlink -f "${TLS_OUTPUT_PATH:-$script_dir/../tmp/tls}")
config_path=$(readlink -f "${TLS_CONFIG_PATH:-$script_dir/../tls}")
ca_name=${CA_NAME:-ca}

while (( "$#" )); do
  case "$1" in
    --cert-name)
      if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
        cert_name=$2
        shift 2
      else
        echo "Error: Argument for $1 is missing" >&2
        exit 1
      fi
      ;;
    -*|--*=)
      echo "Error: Unsupported flag $1" >&2
      exit 1
      ;;
    *)
      shift
      ;;
  esac
done

if [ -z "$cert_name" ]; then
  echo "Error: server certificate name must be provided with --cert-name flag"
  exit 1
fi
new_ca=false

# Generate CA only if it doesn't exist
if [[ ! -f "$output_path/$ca_name.pem" ]]; then
  mkdir -p "$output_path"
  echo "> Generating ca. Output dir: $output_path"

  cfssl gencert \
    -initca "$config_path/$ca_name-csr.json" | cfssljson -bare "$output_path/$ca_name" -

  new_ca=true
fi

# Generate server certificate if CA was just created or if it doesn't exist
if [[ "$new_ca" = true || ! -f "$output_path/$cert_name.pem" ]]; then
  echo "> Generating server certificate. Output dir: $output_path"

  cfssl gencert \
    -profile=server \
    -ca="$output_path/$ca_name.pem" \
    -ca-key="$output_path/$ca_name-key.pem" \
    -config="$config_path/ca-config.json" \
    "$config_path/$cert_name-config.json" | cfssljson -bare "$output_path/$cert_name"
else
  echo "> Certificate $output_path/$cert_name.pem already exists. Skipping generation."
fi

rm -f "$output_path/$ca_name.csr"
rm -f "$output_path/$cert_name.csr"
