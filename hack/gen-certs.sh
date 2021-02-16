#!/bin/bash -e
#
# Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
