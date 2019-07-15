module github.com/gardener/terminal-controller-manager

go 1.12

require (
	github.com/go-logr/logr v0.1.0
	github.com/onsi/ginkgo v1.8.0
	github.com/onsi/gomega v1.5.0
	github.com/satori/go.uuid v1.2.0
	golang.org/x/net v0.0.0-20190620200207-3b0461eec859
	k8s.io/api v0.0.0-20190409021203-6e4e0e4f393b
	k8s.io/apimachinery v0.0.0-20190404173353-6a84e37a896d
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	sigs.k8s.io/controller-runtime v0.2.0-beta.2
	sigs.k8s.io/kustomize/v3 v3.0.1 // indirect
	sigs.k8s.io/yaml v1.1.0
)
