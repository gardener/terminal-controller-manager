#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail

# For the check step concourse will set the following environment variables:
# SOURCE_PATH - path to component repository root directory.

if [[ -z "${SOURCE_PATH}" ]]; then
  export SOURCE_PATH="$(readlink -f "$(dirname ${0})/..")"
else
  export SOURCE_PATH="$(readlink -f ${SOURCE_PATH})"
fi

GOLANGCI_LINT_ADDITIONAL_FLAGS=${GOLANGCI_LINT_ADDITIONAL_FLAGS:-""}

# Install golangci-lint (linting tool)
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.46.1

function run_lint {
  local component=$1
  local target_dir=$2
  local golangci_lint_additional_flags=$3
  echo "> Lint $component"

  pushd "$target_dir"

  golangci-lint -v run ./... ${golangci_lint_additional_flags}

  popd
}

run_lint terminal-controller-manager "${SOURCE_PATH}" "${GOLANGCI_LINT_ADDITIONAL_FLAGS}"
