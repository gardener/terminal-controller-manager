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

ENVTEST_K8S_VERSION=${ENVTEST_K8S_VERSION:-"1.33"}

GO_TEST_TIMEOUT="${GO_TEST_TIMEOUT:-5m}"
GO_TEST_RACE="${GO_TEST_RACE:-0}"

OS=${OS:-$(go env GOOS)}
ARCH=${ARCH:-$(go env GOARCH)}

run_test() {
  local component=$1
  local target_dir=$2
  echo "> Test $component"

  pushd "$target_dir"

  make envtest

  # --use-env allows overwriting the envtest tools path via the KUBEBUILDER_ASSETS env var just like it was before
  export KUBEBUILDER_ASSETS="$("bin/setup-envtest" use --use-env -p path ${ENVTEST_K8S_VERSION})"
  echo "> Using envtest tools installed at '$KUBEBUILDER_ASSETS'"

  RACE_FLAG=""
  if [ "${GO_TEST_RACE}" = "1" ]; then
    RACE_FLAG="-race"
  fi

  GO111MODULE=on go test ./... ${RACE_FLAG} -timeout "${GO_TEST_TIMEOUT}" -coverprofile cover.out

  popd
}

run_test terminal-controller-manager "${SOURCE_PATH}"
