# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

REPO_ROOT      := $(shell git rev-parse --show-toplevel)
VERSION        := $(shell cat "$(REPO_ROOT)/VERSION")

# Docker image repository and tag for terminal-controller-manager
IMG_MANAGER_REPOSITORY ?= europe-docker.pkg.dev/gardener-project/public/gardener/terminal-controller-manager
IMG_MANAGER_TAG        ?= $(VERSION)-$(shell git rev-parse HEAD)

# Docker image repository and tag for Kube RBAC Proxy tool
IMG_RBAC_PROXY_REPOSITORY ?= quay.io/brancz/kube-rbac-proxy
IMG_RBAC_PROXY_TAG        ?= v0.15.0

# Chart variables
CREATE_NAMESPACE ?= true
NAMESPACE        ?= terminal-system
CHART_NAME       ?= terminal-controller-manager-local
VALUES_FILE      ?= "tmp/values.yaml"
VIRTUAL_GARDEN_ENABLED = false
CHART_PATH             = "charts/terminal"

# TLS output directory and certificate/key file names
TLS_OUTPUT_PATH    ?= "tmp/tls"
CA_NAME            ?= "ca"
CERT_NAME          ?= "terminal-admission-controller-tls"

# Kind cluster variables
KIND_CLUSTER_NAME ?= "gardener-local"

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
	$(CONTROLLER_GEN) crd paths="./controllers/..." paths="./api/..." output:crd:dir=charts/terminal/charts/application/crd-gen

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
test: manifests generate fmt lint go-test ## Run tests.

.PHONY: go-test
go-test: ## Run go tests.
	@./hack/test-integration.sh

.PHONY: bootstrap-dev
bootstrap-dev: ## Install example resources into a dev cluster
	@kubectl apply -f example/bootstrap/00_namespace.yaml
	@kubectl apply -f example/bootstrap/01_serviceaccount.yaml
	@kubectl apply -f example/bootstrap/02_clusterrolebinding.yaml
	@kubectl patch project local --patch-file example/bootstrap/03_gardener-project-patch.yaml

##@ Build

.PHONY: build
build: generate fmt lint ## Build manager binary.
	go build -o bin/manager main.go

.PHONY: run
run: manifests generate fmt lint ## Run a controller from your host.
	go run ./main.go

.PHONY: docker-build
docker-build: test ## Build docker image with the manager.
	docker build -t $(IMG_MANAGER_REPOSITORY):$(IMG_MANAGER_TAG) .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	docker push $(IMG_MANAGER_REPOSITORY):$(IMG_MANAGER_TAG)

##@ Deployment

.PHONY: load-manager-docker-image
load-manager-docker-image: docker-build ## Loads the manager docker image into the kind cluster
	kind load docker-image $(IMG_MANAGER_REPOSITORY):$(IMG_MANAGER_TAG) --name $(KIND_CLUSTER_NAME)

.PHONY: ensure-namespace
ensure-namespace: # Creates the namespace if not existing and applies requied helm metadata
	@if [ "$(CREATE_NAMESPACE)" = true ] && ! kubectl get namespace $(NAMESPACE) > /dev/null 2>&1; then \
	  kubectl create namespace $(NAMESPACE); \
	else \
	  echo "Namespace already exists. Skipping creation."; \
	fi

	@kubectl annotate namespace $(NAMESPACE) \
		"meta.helm.sh/release-name=$(CHART_NAME)" \
		"meta.helm.sh/release-namespace=$(NAMESPACE)"
	@kubectl label namespace $(NAMESPACE) \
		"app.kubernetes.io/managed-by=Helm"

.PHONY: gen-certs
gen-certs: cfssl ## Generates CA certificate and server certificate for the admission controller
	./hack/gen-certs.sh

.PHONY: install
install: helm gen-certs ## Deploys the terminal controller manager chart in the Garden cluster
	@touch $(VALUES_FILE)
	$(MAKE) ensure-namespace

	$(HELM) upgrade --install \
	  --force \
	  --wait \
	  --values $(VALUES_FILE) \
	  --namespace $(NAMESPACE) \
	  --set global.deployment.virtualGarden.enabled=$(VIRTUAL_GARDEN_ENABLED) \
	  --set global.deployment.virtualGarden.createNamespace=$(CREATE_NAMESPACE) \
	  --set global.controller.manager.image.repository=$(IMG_MANAGER_REPOSITORY) \
	  --set global.controller.manager.image.tag=$(IMG_MANAGER_TAG) \
	  --set global.controller.kubeRBACProxy.image.repository=$(IMG_RBAC_PROXY_REPOSITORY) \
	  --set global.controller.kubeRBACProxy.image.tag=$(IMG_RBAC_PROXY_TAG) \
	  --set-file global.admission.config.server.webhooks.caBundle=$(TLS_OUTPUT_PATH)/$(CA_NAME).pem \
	  --set-file global.admission.config.server.webhooks.tls.key=$(TLS_OUTPUT_PATH)/$(CERT_NAME)-key.pem \
	  --set-file global.admission.config.server.webhooks.tls.crt=$(TLS_OUTPUT_PATH)/$(CERT_NAME).pem \
	  $(CHART_NAME) \
	  $(CHART_PATH) 2> >(grep -v 'found symbolic link' >&2)

.PHONY: install-application
install-application: ## Deploys the application chart in the Garden cluster
	$(MAKE) install \
		VIRTUAL_GARDEN_ENABLED=true \
		CHART_PATH="charts/terminal/charts/application" \
		CHART_NAME=$(CHART_NAME)"-application"

.PHONY: install-runtime
install-runtime: ## Deploys the runtime chart in the hosting cluster
	$(MAKE) install \
		VIRTUAL_GARDEN_ENABLED=true \
		CHART_PATH="charts/terminal/charts/runtime" \
		CHART_NAME=$(CHART_NAME)"-runtime"

.PHONY: uninstall
uninstall: helm ## Uninstall the deployed helm chart.
	$(HELM) uninstall --namespace $(NAMESPACE) $(CHART_NAME)

.PHONY: uninstall-application
uninstall-application: helm ## Uninstall the deployed application helm chart.
	$(MAKE) uninstall \
		CHART_NAME=$(CHART_NAME)"-application"

.PHONY: uninstall-runtime
uninstall-runtime: helm ## Uninstall the deployed runtime helm chart.
	$(MAKE) uninstall \
		CHART_NAME=$(CHART_NAME)"-runtime"

##@ Build Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
HELM ?= $(LOCALBIN)/helm

## Tool Versions
CONTROLLER_TOOLS_VERSION ?= v0.11.2

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: envtest
envtest: $(ENVTEST) ## Download envtest-setup locally if necessary.
$(ENVTEST): $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

.PHONY: helm
helm: $(HELM) ## Download envtest-setup locally if necessary.
$(HELM): $(LOCALBIN)
	export HELM_INSTALL_DIR=$(LOCALBIN) && curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

.PHONY: cfssl
cfssl: $(CFSSL) ## Download cfssl locally if necessary.
$(CFSSL): $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install github.com/cloudflare/cfssl/cmd/...@latest
