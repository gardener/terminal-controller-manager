#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail

# For the check step concourse will set the following environment variables:
# SOURCE_PATH - path to component repository root directory.
if [ -z "$SOURCE_PATH" ]; then
  SOURCE_PATH="$(dirname "$0")/.."
fi
export SOURCE_PATH="$(readlink -f "$SOURCE_PATH")"

# renovate: datasource=github-releases depName=golangci/golangci-lint
GOLANGCI_LINT_VERSION=${GOLANGCI_LINT_VERSION:-v1.56.2}

GOLANGCI_LINT_ADDITIONAL_FLAGS=${GOLANGCI_LINT_ADDITIONAL_FLAGS:-""}

# Install golangci-lint (linting tool)
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin $GOLANGCI_LINT_VERSION

echo "> Running golangci-lint for $SOURCE_PATH"
pushd "$SOURCE_PATH" > /dev/null
"$(go env GOPATH)"/bin/golangci-lint -v run ./... ${GOLANGCI_LINT_ADDITIONAL_FLAGS}
popd > /dev/null
