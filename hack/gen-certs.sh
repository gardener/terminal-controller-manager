#!/bin/bash -e
#
# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

path_tls_output="../config/secret/tls"
path_tls_config="../tls"

ca_name="terminal-ca"
cert_name="terminal-controller-manager-tls"

cd "$(dirname "$0")"

cfssl gencert \
  -initca "$path_tls_config/$ca_name-csr.json" | cfssljson -bare "$path_tls_output/$ca_name" -

cfssl gencert \
    -profile=server \
    -ca="$path_tls_output/$ca_name.pem" \
    -ca-key="$path_tls_output/$ca_name-key.pem" \
    -config="$path_tls_config/ca-config.json" \
    "$path_tls_config/$cert_name-config.json" | cfssljson -bare "$path_tls_output/$cert_name"

# cleanup csr files
rm $path_tls_output/$ca_name.csr
rm $path_tls_output/$cert_name.csr
