# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

# Image URL to use all building/pushing image targets
IMG ?= eu.gcr.io/gardener-project/gardener/terminal-controller-manager

# Kube RBAC Proxy image to use
IMG_RBAC_PROXY ?= quay.io/brancz/kube-rbac-proxy:v0.8.0

REPO_ROOT           := $(shell git rev-parse --show-toplevel)
VERSION             := $(shell cat "$(REPO_ROOT)/VERSION")
EFFECTIVE_VERSION   := $(VERSION)-$(shell git rev-parse HEAD)

CR_VERSION := $(shell go mod edit -json | jq -r '.Require[] | select(.Path=="sigs.k8s.io/controller-runtime") | .Version')

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate ClusterRole object.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./controllers/..." paths="./api/..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./controllers/..." paths="./api/..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: lint
lint: ## Run golangci-lint against code.
	@./hack/golangci-lint.sh

.PHONY: test
test: manifests generate fmt lint ## Run tests.
	@./hack/test-integration.sh

.PHONY: bootstrap-dev
bootstrap-dev: install ## Install example resources into a dev cluster
	kubectl apply -f config/samples/bootstrap/01_namespaces.yaml
	kubectl apply -f config/samples/bootstrap/02_rbac.yaml

.PHONY: bootstrap-dev-project
bootstrap-dev-project: bootstrap-dev ## Install example resources and gardener project into a dev cluster
	kubectl apply -f config/samples/bootstrap/03_gardener-rbac.yaml
	kubectl apply -f config/samples/bootstrap/04_gardener-project.yaml

##@ Build

.PHONY: build
build: generate fmt lint ## Build manager binary.
	go build -o bin/manager main.go

.PHONY: run
run: manifests generate fmt lint ## Run a controller from your host.
	go run ./main.go

.PHONY: docker-build
docker-build: test ## Build docker image with the manager.
	docker build -t $(IMG):$(EFFECTIVE_VERSION) .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	docker push $(IMG):$(EFFECTIVE_VERSION)

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy-rt
deploy-rt: apply-image kustomize ## Multi-cluster use case: Deploy controller in the configured Kubernetes cluster in ~/.kube/config
	kustomize build config/overlay/multi-cluster/runtime | kubectl apply -f -

.PHONY: deploy-virtual
deploy-virtual: apply-image kustomize ## Multi-cluster use case: Deploy crd, admission configurations etc. in the configured Kubernetes cluster
	kustomize build config/overlay/multi-cluster/virtual-garden | kubectl apply -f -

.PHONY: deploy-singlecluster
deploy-singlecluster: apply-image ## Single-cluster use case: Deploy crd, admission configurations, controller etc. in the configured Kubernetes cluster
	kustomize build config/overlay/single-cluster | kubectl apply -f -

.PHONY: apply-image
apply-image: manifests kustomize ## Apply terminal controller and kube-rbac-proxy images according to the variables IMG and IMG_RBAC_PROXY
	cd config/manager && $(KUSTOMIZE) edit set image "controller=${IMG}:${EFFECTIVE_VERSION}"
	cd config/default && $(KUSTOMIZE) edit set image "quay.io/brancz/kube-rbac-proxy=${IMG_RBAC_PROXY}"

CONTROLLER_GEN = $(shell pwd)/bin/controller-gen
.PHONY: controller-gen
controller-gen: ## Download controller-gen locally if necessary.
	$(call go-get-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen@v0.7.0)

KUSTOMIZE = $(shell pwd)/bin/kustomize
.PHONY: kustomize
kustomize: ## Download kustomize locally if necessary.
	$(call go-get-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v4@v4.4.1)

ENVTEST = $(shell pwd)/bin/setup-envtest
.PHONY: envtest
envtest: ## Download envtest-setup locally if necessary.
	$(call go-get-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest@latest)

# go-get-tool will 'go get' any package $2 and install it to $1.
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-get-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
GOBIN=$(PROJECT_DIR)/bin go get $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef

