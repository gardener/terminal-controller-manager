module github.com/gardener/terminal-controller-manager

go 1.16

require (
	github.com/gardener/gardener v1.15.3
	github.com/go-logr/logr v0.3.0
	github.com/kr/text v0.2.0 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.2
	github.com/satori/go.uuid v1.2.0
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	gopkg.in/yaml.v2 v2.3.0
	k8s.io/api v0.20.2
	k8s.io/apimachinery v0.20.2
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	sigs.k8s.io/controller-runtime v0.8.2
	sigs.k8s.io/yaml v1.2.0
)

replace k8s.io/client-go => k8s.io/client-go v0.20.2
