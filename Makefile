
# Image URL to use all building/pushing image targets
IMG ?= eu.gcr.io/gardener-project/gardener/terminal-controller-manager:latest

# Kube RBAC Proxy image to use
IMG_RBAC_PROXY ?= gcr.io/kubebuilder/kube-rbac-proxy:v0.4.0

# Produce CRDs that work back to Kubernetes 1.11 (no version conversion)
CRD_OPTIONS ?= "crd:trivialVersions=true"

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

all: manager

# Run tests
test: generate fmt vet manifests
	go test ./api/... ./controllers/... -coverprofile cover.out

# Build manager binary
manager: generate fmt vet
	go build -o bin/manager main.go

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet
	go run ./main.go

# Install CRDs into a cluster
install: manifests
	kubectl apply -f config/crd/bases

# Install resources into a dev cluster
bootstrap-dev: install
	kubectl apply -f config/samples/bootstrap/01_namespaces.yaml
	kubectl apply -f config/samples/bootstrap/02_rbac.yaml

apply-image: manifests
	cd config/manager && kustomize edit set image "controller=${IMG}"
	cd config/default && kustomize edit set image "gcr.io/kubebuilder/kube-rbac-proxy=${IMG_RBAC_PROXY}"

# Multi-cluster use case: Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy-rt: apply-image
	kustomize build config/overlay/multi-cluster/runtime | kubectl apply -f -

# Multi-cluster use case: Deploy crd, admission configurations etc. in the configured Kubernetes cluster
deploy-virtual: apply-image
	kustomize build config/overlay/multi-cluster/virtual-garden | kubectl apply -f -

# Single-cluster use case: Deploy crd, admission configurations, controller etc. in the configured Kubernetes cluster
deploy-singlecluster: apply-image
	kustomize build config/overlay/single-cluster | kubectl apply -f -

# Generate manifests e.g. CRD, RBAC etc.
manifests: controller-gen
	$(CONTROLLER_GEN) $(CRD_OPTIONS) rbac:roleName=manager-role webhook paths="./..." output:crd:artifacts:config=config/crd/bases

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

# Generate code
generate: controller-gen
	$(CONTROLLER_GEN) object:headerFile=./hack/boilerplate.go.txt paths="./..."

# Build the docker image
docker-build: test
	docker build . -t ${IMG}

# Push the docker image
docker-push:
	docker push ${IMG}

# find or download controller-gen
# download controller-gen if necessary
controller-gen:
ifeq (, $(shell which controller-gen))
	go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.2.0
CONTROLLER_GEN=$(GOBIN)/controller-gen
else
CONTROLLER_GEN=$(shell which controller-gen)
endif
