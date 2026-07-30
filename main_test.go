/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/test"
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Main Suite")
}

var _ = Describe("Controller Manager Configuration", func() {
	Describe("Allowed API server service reference defaulting", func() {
		readConfiguration := func(serviceRefsYAML string) *v1alpha1.ControllerManagerConfiguration {
			configFile := filepath.Join(GinkgoT().TempDir(), "config.yaml")
			config := "allowedAPIServerURLs:\n- https://api.example.com\n" + serviceRefsYAML
			Expect(os.WriteFile(configFile, []byte(config), 0o600)).To(Succeed())

			cfg, err := readControllerManagerConfiguration(configFile)
			Expect(err).NotTo(HaveOccurred())

			return cfg
		}

		It("uses defaults when the field is omitted", func() {
			cfg := readConfiguration("")

			Expect(cfg.AllowedAPIServerServiceRefs).To(Equal([]v1alpha1.AllowedAPIServerServiceRef{
				{
					Name:      "kubernetes",
					Namespace: "default",
				},
				{
					Name:             "kube-apiserver",
					UseHostNamespace: true,
				},
			}))
		})

		It("denies all service references when the list is explicitly empty", func() {
			cfg := readConfiguration("allowedAPIServerServiceRefs: []\n")

			Expect(cfg.AllowedAPIServerServiceRefs).To(BeEmpty())
			Expect(cfg.AllowedAPIServerServiceRefs).NotTo(BeNil())
		})

		It("replaces the defaults with a custom list", func() {
			cfg := readConfiguration(`allowedAPIServerServiceRefs:
- name: custom-apiserver
  namespace: custom-namespace
`)

			Expect(cfg.AllowedAPIServerServiceRefs).To(Equal([]v1alpha1.AllowedAPIServerServiceRef{
				{
					Name:      "custom-apiserver",
					Namespace: "custom-namespace",
				},
			}))
		})
	})

	Describe("Validating allowed API server service references", func() {
		var cfg *v1alpha1.ControllerManagerConfiguration

		BeforeEach(func() {
			cfg = test.DefaultConfiguration()
		})

		It("accepts valid exact and host namespace entries", func() {
			cfg.AllowedAPIServerServiceRefs = []v1alpha1.AllowedAPIServerServiceRef{
				{
					Name:      "kubernetes",
					Namespace: "default",
				},
				{
					Name:             "kube-apiserver",
					UseHostNamespace: true,
				},
			}

			Expect(validateConfig(cfg)).To(Succeed())
		})

		It("accepts an explicitly empty list", func() {
			cfg.AllowedAPIServerServiceRefs = []v1alpha1.AllowedAPIServerServiceRef{}

			Expect(validateConfig(cfg)).To(Succeed())
		})

		It("rejects an entry with both namespace and useHostNamespace", func() {
			cfg.AllowedAPIServerServiceRefs = []v1alpha1.AllowedAPIServerServiceRef{
				{
					Name:             "kube-apiserver",
					Namespace:        "default",
					UseHostNamespace: true,
				},
			}

			Expect(validateConfig(cfg)).To(MatchError(ContainSubstring("allowedAPIServerServiceRefs[0].namespace: Forbidden")))
		})

		It("requires a namespace for an exact entry", func() {
			cfg.AllowedAPIServerServiceRefs = []v1alpha1.AllowedAPIServerServiceRef{
				{Name: "kubernetes"},
			}

			Expect(validateConfig(cfg)).To(MatchError(ContainSubstring("allowedAPIServerServiceRefs[0].namespace: Required value")))
		})

		It("requires the name to be a DNS-1035 label", func() {
			cfg.AllowedAPIServerServiceRefs = []v1alpha1.AllowedAPIServerServiceRef{
				{
					Name:      "Invalid_Name",
					Namespace: "default",
				},
			}

			Expect(validateConfig(cfg)).To(MatchError(ContainSubstring("allowedAPIServerServiceRefs[0].name: Invalid value")))
		})

		It("requires an explicit namespace to be a DNS-1123 subdomain", func() {
			cfg.AllowedAPIServerServiceRefs = []v1alpha1.AllowedAPIServerServiceRef{
				{
					Name:      "kubernetes",
					Namespace: "Invalid_Namespace",
				},
			}

			Expect(validateConfig(cfg)).To(MatchError(ContainSubstring("allowedAPIServerServiceRefs[0].namespace: Invalid value")))
		})

		It("rejects duplicate entries", func() {
			cfg.AllowedAPIServerServiceRefs = []v1alpha1.AllowedAPIServerServiceRef{
				{
					Name:      "kubernetes",
					Namespace: "default",
				},
				{
					Name:      "kubernetes",
					Namespace: "default",
				},
			}

			Expect(validateConfig(cfg)).To(MatchError(ContainSubstring("allowedAPIServerServiceRefs[1]: Duplicate value")))
		})
	})

	Describe("Validating allowed API server URLs", func() {
		It("accepts an empty list", func() {
			cfg := test.DefaultConfiguration()
			cfg.AllowedAPIServerURLs = []string{}

			Expect(validateConfig(cfg)).To(Succeed())
		})
	})
})
