/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package webhooks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"time"

	"github.com/gardener/gardener/pkg/utils/secrets"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	dashboardv1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/test"
)

const (
	randomLength = 5
	charset      = "abcdefghijklmnopqrstuvwxyz0123456789"
)

func generateCaCert() *secrets.Certificate {
	csc := &secrets.CertificateSecretConfig{
		Name:       "ca-test",
		CommonName: "ca-test",
		CertType:   secrets.CACert,
	}
	caCertificate, err := csc.GenerateCertificate()
	Expect(err).ToNot(HaveOccurred())

	return caCertificate
}

func generatePrivateKeyPEM() []byte {
	csc := &secrets.CertificateSecretConfig{
		Name:       "test-key",
		CommonName: "test-key",
		CertType:   secrets.ServerCert,
	}
	cert, err := csc.GenerateCertificate()
	Expect(err).ToNot(HaveOccurred())

	return cert.PrivateKeyPEM
}

func generateCSRPEM() []byte {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).ToNot(HaveOccurred())

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test-csr",
			Organization: []string{"Test Organization"},
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	Expect(err).ToNot(HaveOccurred())

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM
}

var _ = Describe("Validating Webhook", func() {
	const (
		HostServiceAccountName   = "test-host-serviceaccount"
		TargetServiceAccountName = "test-target-serviceaccount"

		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	var (
		suffix                  string
		terminalName            string
		terminalNamespace       string
		hostNamespace           string
		targetNamespace         string
		terminalKey             types.NamespacedName
		hostServiceAccountKey   types.NamespacedName
		targetServiceAccountKey types.NamespacedName
		terminal                *dashboardv1alpha1.Terminal
		terminalCreationError   error
	)
	BeforeEach(func() {
		cmConfig = test.DefaultConfiguration()
		validator.injectConfig(cmConfig)

		suffix = test.StringWithCharset(randomLength, charset)
		terminalNamespace = "test-terminal-namespace-" + suffix
		hostNamespace = "test-host-serviceaccount-namespace-" + suffix
		targetNamespace = "test-target-serviceaccount-namespace-" + suffix
		terminalName = "test-terminal-" + suffix

		terminalKey = types.NamespacedName{Name: terminalName, Namespace: terminalNamespace}
		hostServiceAccountKey = types.NamespacedName{Name: HostServiceAccountName, Namespace: hostNamespace}
		targetServiceAccountKey = types.NamespacedName{Name: TargetServiceAccountName, Namespace: targetNamespace}

		terminal = &dashboardv1alpha1.Terminal{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "dashboard.gardener.cloud/v1alpha1",
				Kind:       "Terminal",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      terminalKey.Name,
				Namespace: terminalKey.Namespace,
			},
			Spec: dashboardv1alpha1.TerminalSpec{
				Host: dashboardv1alpha1.HostCluster{
					Credentials: dashboardv1alpha1.ClusterCredentials{
						ServiceAccountRef: &corev1.ObjectReference{
							Kind:      rbacv1.ServiceAccountKind,
							Name:      hostServiceAccountKey.Name,
							Namespace: hostServiceAccountKey.Namespace,
						},
					},
					Namespace:          &hostNamespace,
					TemporaryNamespace: nil,
					Pod: dashboardv1alpha1.Pod{
						Container: &dashboardv1alpha1.Container{
							Image: "foo",
						},
					},
				},
				Target: dashboardv1alpha1.TargetCluster{
					Credentials: dashboardv1alpha1.ClusterCredentials{
						ServiceAccountRef: &corev1.ObjectReference{
							Kind:      rbacv1.ServiceAccountKind,
							Name:      targetServiceAccountKey.Name,
							Namespace: targetServiceAccountKey.Namespace,
						},
					},
					Namespace:                  &targetNamespace,
					TemporaryNamespace:         nil,
					KubeconfigContextNamespace: "default",
				},
			},
		}

		By("By creating namespaces")
		namespaces := []string{terminalNamespace, hostNamespace, targetNamespace}
		for _, namespace := range namespaces {
			terminalNamespaceKey := types.NamespacedName{Name: namespace}
			e.CreateObject(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}, terminalNamespaceKey, timeout, interval)
		}

		By("By creating host serviceaccount")
		e.AddClusterAdminServiceAccount(ctx, HostServiceAccountName, hostNamespace, timeout, interval)
		By("By creating target serviceaccount")
		e.AddClusterAdminServiceAccount(ctx, TargetServiceAccountName, targetNamespace, timeout, interval)
	})

	AssertFailedBehavior := func(expectedSubstring string) {
		It("Should error", func() {
			Expect(terminalCreationError).To(HaveOccurred())
			Expect(terminalCreationError.Error()).To(ContainSubstring(expectedSubstring))
		})
	}

	JustBeforeEach(func() {
		terminalCreationError = e.K8sClient.Create(ctx, terminal)
	})

	Describe("mutation succeeds", func() {
		Context("identifier", func() {
			BeforeEach(func() {
				terminal.Spec.Identifier = ""
			})
			It("should generate an identifier", func() {
				Expect(terminalCreationError).To(Not(HaveOccurred()))

				Eventually(func() bool {
					err := e.K8sClient.Get(ctx, terminalKey, terminal)
					return err == nil
				}, timeout, interval).Should(BeTrue())
				Expect(terminal.Spec.Identifier).To(Not(BeEmpty()))
			})
		})

		Context("keepalive", func() {
			BeforeEach(func() {
				terminal.Spec.Identifier = ""
			})

			It("should update the last heartbeat", func() {
				Expect(terminalCreationError).To(Not(HaveOccurred()))

				Eventually(func() bool {
					terminal = &dashboardv1alpha1.Terminal{}
					err := e.K8sClient.Get(ctx, terminalKey, terminal)
					return err == nil
				}, timeout, interval).Should(BeTrue())
				Expect(terminal.Annotations[dashboardv1alpha1.TerminalLastHeartbeat]).To(Not(BeEmpty()))

				By("clearing last heartbeat and setting keepalive annotation")
				terminal.Annotations[dashboardv1alpha1.TerminalLastHeartbeat] = ""
				terminal.Annotations[dashboardv1alpha1.TerminalOperation] = dashboardv1alpha1.TerminalOperationKeepalive
				err := e.K8sClient.Update(ctx, terminal)
				Expect(err).To(Not(HaveOccurred()))

				By("by reading the terminal")
				terminal = &dashboardv1alpha1.Terminal{}
				err = e.K8sClient.Get(ctx, terminalKey, terminal)
				Expect(err).To(Not(HaveOccurred()))

				Expect(terminal.Annotations[dashboardv1alpha1.TerminalLastHeartbeat]).To(Not(BeEmpty()))
				Expect(terminal.Annotations[dashboardv1alpha1.TerminalOperation]).To(BeEmpty())
			})
		})
	})

	Describe("CREATE succeeds", func() {
		// test can be removed after deprecated field is removed
		Context("container image - deprecated", func() {
			BeforeEach(func() {
				terminal.Spec.Host.Pod.ContainerImage = "foo"
			})
			It("should allow to set containerImage", func() {
				Expect(terminalCreationError).To(Not(HaveOccurred()))
			})
		})

		Context("api server - serviceRef, server and caData fields", func() {
			BeforeEach(func() {
				terminal.Spec.Target.APIServer = &dashboardv1alpha1.APIServer{
					ServiceRef: nil,
					Server:     "",
					CAData:     nil,
				}
			})
			It("should allow to not specify serviceRef, server and caData", func() {
				Expect(terminalCreationError).To(Not(HaveOccurred()))
			})
		})

		Context("api server caData validation", func() {
			Context("valid CA certificate", func() {
				BeforeEach(func() {
					caCert := generateCaCert()
					terminal.Spec.Target.APIServer = &dashboardv1alpha1.APIServer{
						CAData: caCert.CertificatePEM,
					}
				})
				It("should accept a valid CA certificate", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))
				})
			})

			Context("CA bundle with multiple certificates", func() {
				BeforeEach(func() {
					caCert1 := generateCaCert()
					caCert2 := generateCaCert()
					bundleData := append(caCert1.CertificatePEM, caCert2.CertificatePEM...)
					terminal.Spec.Target.APIServer = &dashboardv1alpha1.APIServer{
						CAData: bundleData,
					}
				})
				It("should accept CA bundle with multiple certificates", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))
				})
			})

			Context("CA bundle with trailing whitespace", func() {
				BeforeEach(func() {
					caCert := generateCaCert()
					dataWithWhitespace := append(caCert.CertificatePEM, []byte("\n  \t  \n")...)
					terminal.Spec.Target.APIServer = &dashboardv1alpha1.APIServer{
						CAData: dataWithWhitespace,
					}
				})
				It("should accept CA certificate with trailing whitespace", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))
				})
			})

			Context("empty CA bundle data", func() {
				BeforeEach(func() {
					terminal.Spec.Target.APIServer = &dashboardv1alpha1.APIServer{
						CAData: nil, // Use nil instead of empty byte slice to avoid serialization issue
					}
				})
				It("should accept empty CA data (optional field)", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))
				})
			})

			Context("nil CA bundle data", func() {
				BeforeEach(func() {
					terminal.Spec.Target.APIServer = &dashboardv1alpha1.APIServer{
						CAData: nil,
					}
				})
				It("should accept nil CA data (optional field)", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))
				})
			})
		})
	})

	Describe("UPDATE succeeds", func() {
		Context("when changing mutable fields", func() {
			It("allow to update last heartbeat time", func() {
				Expect(terminalCreationError).To(Not(HaveOccurred()))

				By("Expecting terminal to be created")
				Eventually(func() bool {
					terminal = &dashboardv1alpha1.Terminal{}
					err := e.K8sClient.Get(ctx, terminalKey, terminal)
					return err == nil
				}, timeout, interval).Should(BeTrue())

				By("updating the last heartbeat time")
				terminal.Annotations[dashboardv1alpha1.TerminalLastHeartbeat] = time.Now().UTC().Format(time.RFC3339)
				err := e.K8sClient.Update(ctx, terminal)

				Expect(err).To(Not(HaveOccurred()))
			})
		})
	})

	Describe("UPDATE fails", func() {
		Context("when changing immutable fields", func() {
			Describe("spec should be immutable", func() {
				It("should fail when updating identifier", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))

					By("Expecting terminal to be created")
					Eventually(func() bool {
						terminal = &dashboardv1alpha1.Terminal{}
						err := e.K8sClient.Get(ctx, terminalKey, terminal)
						return err == nil
					}, timeout, interval).Should(BeTrue())

					terminal.Spec.Identifier = "changed"
					err := e.K8sClient.Update(ctx, terminal)

					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("field is immutable"))
				})

				It("should fail when updating host namespace", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))

					By("Expecting terminal to be created")
					Eventually(func() bool {
						terminal = &dashboardv1alpha1.Terminal{}
						err := e.K8sClient.Get(ctx, terminalKey, terminal)
						return err == nil
					}, timeout, interval).Should(BeTrue())

					changed := "changed"
					terminal.Spec.Host.Namespace = &changed
					err := e.K8sClient.Update(ctx, terminal)

					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("field is immutable"))
				})

				It("should fail when updating target namespace", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))

					By("Expecting terminal to be created")
					Eventually(func() bool {
						terminal = &dashboardv1alpha1.Terminal{}
						err := e.K8sClient.Get(ctx, terminalKey, terminal)
						return err == nil
					}, timeout, interval).Should(BeTrue())

					changed := "changed"
					terminal.Spec.Target.Namespace = &changed
					err := e.K8sClient.Update(ctx, terminal)

					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("field is immutable"))
				})

				It("should fail when updating target credential", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))

					By("Expecting terminal to be created")
					Eventually(func() bool {
						terminal = &dashboardv1alpha1.Terminal{}
						err := e.K8sClient.Get(ctx, terminalKey, terminal)
						return err == nil
					}, timeout, interval).Should(BeTrue())

					terminal.Spec.Target.Credentials.ShootRef = &dashboardv1alpha1.ShootRef{
						Namespace: targetNamespace,
						Name:      "changed",
					}
					err := e.K8sClient.Update(ctx, terminal)

					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("field is immutable"))
				})

				It("should fail when updating host credential", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))

					By("Expecting terminal to be created")
					Eventually(func() bool {
						terminal = &dashboardv1alpha1.Terminal{}
						err := e.K8sClient.Get(ctx, terminalKey, terminal)
						return err == nil
					}, timeout, interval).Should(BeTrue())

					terminal.Spec.Host.Credentials.ShootRef = &dashboardv1alpha1.ShootRef{
						Namespace: hostNamespace,
						Name:      "bar",
					}
					err := e.K8sClient.Update(ctx, terminal)

					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("field is immutable"))
				})

				It("should fail when changing target temporary namespace flag", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))

					By("Expecting terminal to be created")
					Eventually(func() bool {
						terminal = &dashboardv1alpha1.Terminal{}
						err := e.K8sClient.Get(ctx, terminalKey, terminal)
						return err == nil
					}, timeout, interval).Should(BeTrue())

					terminal.Spec.Target.TemporaryNamespace = ptr.To(true)
					err := e.K8sClient.Update(ctx, terminal)

					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("field is immutable"))
				})

				It("should fail when changing host temporary namespace flag", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))

					By("Expecting terminal to be created")
					Eventually(func() bool {
						terminal = &dashboardv1alpha1.Terminal{}
						err := e.K8sClient.Get(ctx, terminalKey, terminal)
						return err == nil
					}, timeout, interval).Should(BeTrue())

					terminal.Spec.Host.TemporaryNamespace = ptr.To(true)
					err := e.K8sClient.Update(ctx, terminal)

					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("field is immutable"))
				})
			})

			It("annotation createdBy should be immutable", func() {
				Expect(terminalCreationError).To(Not(HaveOccurred()))

				By("Expecting terminal to be created")
				Eventually(func() bool {
					terminal = &dashboardv1alpha1.Terminal{}
					err := e.K8sClient.Get(ctx, terminalKey, terminal)
					return err == nil
				}, timeout, interval).Should(BeTrue())

				terminal.Annotations[dashboardv1alpha1.GardenCreatedBy] = "changed"
				err := e.K8sClient.Update(ctx, terminal)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("metadata.annotations.gardener.cloud/created-by: Invalid value: \"changed\": field is immutable"))
			})

			It("should not allow to set last heartbeat in the future", func() {
				Expect(terminalCreationError).To(Not(HaveOccurred()))

				By("Expecting terminal to be created")
				Eventually(func() bool {
					terminal = &dashboardv1alpha1.Terminal{}
					err := e.K8sClient.Get(ctx, terminalKey, terminal)
					return err == nil
				}, timeout, interval).Should(BeTrue())

				By("updating the last heartbeat time to the future")
				future := time.Now().Local().Add(time.Hour)
				terminal.Annotations[dashboardv1alpha1.TerminalLastHeartbeat] = future.UTC().Format(time.RFC3339)
				err := e.K8sClient.Update(ctx, terminal)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("metadata.annotations.dashboard.gardener.cloud/last-heartbeat-at: Forbidden"))
			})

			It("should not allow to set invalid last heartbeat date", func() {
				Expect(terminalCreationError).To(Not(HaveOccurred()))

				By("Expecting terminal to be created")
				Eventually(func() bool {
					terminal = &dashboardv1alpha1.Terminal{}
					err := e.K8sClient.Get(ctx, terminalKey, terminal)
					return err == nil
				}, timeout, interval).Should(BeTrue())

				By("setting an invalid value as last heartbeat time")
				terminal.Annotations[dashboardv1alpha1.TerminalLastHeartbeat] = "invalid"
				err := e.K8sClient.Update(ctx, terminal)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("metadata.annotations.dashboard.gardener.cloud/last-heartbeat-at: Invalid value"))
			})
		})
	})

	Describe("CREATE fails", func() {
		Context("for missing required field", func() {
			Context("host credentials", func() {
				BeforeEach(func() {
					terminal.Spec.Host.Credentials.ShootRef = nil
					terminal.Spec.Host.Credentials.ServiceAccountRef = nil
				})
				AssertFailedBehavior("spec.host.credentials: Required value")
			})

			Context("target credentials", func() {
				BeforeEach(func() {
					terminal.Spec.Target.Credentials.ShootRef = nil
					terminal.Spec.Target.Credentials.ServiceAccountRef = nil
				})
				AssertFailedBehavior("spec.target.credentials: Required value")
			})

			Context("container", func() {
				BeforeEach(func() {
					terminal.Spec.Host.Pod.Container = nil
				})
				AssertFailedBehavior("spec.host.pod.container: Required value")
			})

			Context("container image", func() {
				BeforeEach(func() {
					terminal.Spec.Host.Pod.Container.Image = ""
				})
				AssertFailedBehavior("spec.host.pod.container.image: Required value")
			})

			Context("target namespace", func() {
				BeforeEach(func() {
					terminal.Spec.Target.Namespace = nil
				})
				AssertFailedBehavior("spec.target.namespace: Required value")
			})

			Context("target kubeconfigContextNamespace", func() {
				BeforeEach(func() {
					terminal.Spec.Target.KubeconfigContextNamespace = ""
				})
				AssertFailedBehavior("spec.target.kubeconfigContextNamespace: Required value")
			})

			Context("target authorization", func() {
				Context("roleRef name", func() {
					BeforeEach(func() {
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							RoleBindings: []dashboardv1alpha1.RoleBinding{
								{},
							},
						}
					})
					AssertFailedBehavior(" spec.target.authorization.roleBindings[0].roleRef.name: Required value")
				})

				Context("project membership project name", func() {
					BeforeEach(func() {
						cmConfig.HonourProjectMemberships = ptr.To(true)
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							ProjectMemberships: []dashboardv1alpha1.ProjectMembership{
								{
									ProjectName: "",
									Roles:       []string{"admin"},
								},
							},
						}
					})
					AssertFailedBehavior("spec.target.authorization.projectMemberships[0].projectName: Required value")
				})

				Context("project membership no roles", func() {
					BeforeEach(func() {
						cmConfig.HonourProjectMemberships = ptr.To(true)
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							ProjectMemberships: []dashboardv1alpha1.ProjectMembership{
								{
									ProjectName: "foo",
									Roles:       []string{},
								},
							},
						}
					})
					AssertFailedBehavior("spec.target.authorization.projectMemberships[0].roles: Required value")
				})

				Context("project membership empty role name", func() {
					BeforeEach(func() {
						cmConfig.HonourProjectMemberships = ptr.To(true)
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							ProjectMemberships: []dashboardv1alpha1.ProjectMembership{
								{
									ProjectName: "foo",
									Roles:       []string{"admin", ""},
								},
							},
						}
					})
					AssertFailedBehavior("spec.target.authorization.projectMemberships[0].roles[1]: Unsupported value: \"\": supported values: \"admin\", \"owner\", \"serviceaccountmanager\", \"uam\", \"viewer\", \"extension:*\"")
				})

				Context("project membership duplicate roles", func() {
					BeforeEach(func() {
						cmConfig.HonourProjectMemberships = ptr.To(true)
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							ProjectMemberships: []dashboardv1alpha1.ProjectMembership{
								{
									ProjectName: "foo",
									Roles:       []string{"admin", "viewer", "admin"},
								},
							},
						}
					})
					AssertFailedBehavior("spec.target.authorization.projectMemberships[0].roles[2]: Duplicate value: \"admin\"")
				})

				Context("project membership unsupported role", func() {
					BeforeEach(func() {
						cmConfig.HonourProjectMemberships = ptr.To(true)
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							ProjectMemberships: []dashboardv1alpha1.ProjectMembership{
								{
									ProjectName: "foo",
									Roles:       []string{"unsupported-role"},
								},
							},
						}
					})
					AssertFailedBehavior("spec.target.authorization.projectMemberships[0].roles[0]: Unsupported value: \"unsupported-role\": supported values: \"admin\", \"owner\", \"serviceaccountmanager\", \"uam\", \"viewer\", \"extension:*\"")
				})

				Context("project membership valid extension role", func() {
					BeforeEach(func() {
						cmConfig.HonourProjectMemberships = ptr.To(true)
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							ProjectMemberships: []dashboardv1alpha1.ProjectMembership{
								{
									ProjectName: "foo",
									Roles:       []string{"extension:custom-role"},
								},
							},
						}
					})
					It("should allow valid extension role", func() {
						Expect(terminalCreationError).To(Not(HaveOccurred()))
					})
				})

				Context("project membership extension role too long", func() {
					BeforeEach(func() {
						cmConfig.HonourProjectMemberships = ptr.To(true)
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							ProjectMemberships: []dashboardv1alpha1.ProjectMembership{
								{
									ProjectName: "foo",
									Roles:       []string{"extension:this-extension-role-name-is-way-too-long-to-be-valid"},
								},
							},
						}
					})
					AssertFailedBehavior("spec.target.authorization.projectMemberships[0].roles[0]: Too long: may not be more than 20 bytes")
				})

				Context("project membership extension role with invalid characters", func() {
					BeforeEach(func() {
						cmConfig.HonourProjectMemberships = ptr.To(true)
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							ProjectMemberships: []dashboardv1alpha1.ProjectMembership{
								{
									ProjectName: "foo",
									Roles:       []string{"extension:invalid/role"},
								},
							},
						}
					})
					AssertFailedBehavior("spec.target.authorization.projectMemberships[0].roles[0]: Invalid value: \"invalid/role\"")
				})

				Context("project membership multiple valid roles", func() {
					BeforeEach(func() {
						cmConfig.HonourProjectMemberships = ptr.To(true)
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							ProjectMemberships: []dashboardv1alpha1.ProjectMembership{
								{
									ProjectName: "foo",
									Roles:       []string{"admin", "viewer", "extension:custom"},
								},
							},
						}
					})
					It("should allow multiple valid roles", func() {
						Expect(terminalCreationError).To(Not(HaveOccurred()))
					})
				})

				Context("project membership all supported standard roles", func() {
					BeforeEach(func() {
						cmConfig.HonourProjectMemberships = ptr.To(true)
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							ProjectMemberships: []dashboardv1alpha1.ProjectMembership{
								{
									ProjectName: "test-project",
									Roles:       []string{"owner", "admin", "viewer", "uam", "serviceaccountmanager"},
								},
							},
						}
					})
					It("should allow all supported standard roles", func() {
						Expect(terminalCreationError).To(Not(HaveOccurred()))
					})
				})

				Context("project membership multiple project memberships", func() {
					BeforeEach(func() {
						cmConfig.HonourProjectMemberships = ptr.To(true)
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							ProjectMemberships: []dashboardv1alpha1.ProjectMembership{
								{
									ProjectName: "project-1",
									Roles:       []string{"admin"},
								},
								{
									ProjectName: "project-2",
									Roles:       []string{"viewer"},
								},
							},
						}
					})
					It("should allow multiple project memberships", func() {
						Expect(terminalCreationError).To(Not(HaveOccurred()))
					})
				})
			})

			Context("api server", func() {
				Context("service ref name - deprecated", func() {
					BeforeEach(func() {
						terminal.Spec.Target.APIServerServiceRef = &corev1.ObjectReference{
							Name: "",
						}
					})
					AssertFailedBehavior("spec.target.apiServerServiceRef.name: Required value")
				})

				Context("serviceRef and server field", func() {
					BeforeEach(func() {
						terminal.Spec.Target.APIServer = &dashboardv1alpha1.APIServer{
							ServiceRef: &corev1.ObjectReference{
								Name: "",
							},
						}
					})
					AssertFailedBehavior("spec.target.apiServer.serviceRef.name: Required value")
				})
			})

			Context("service account ref", func() {
				Context("name field (target credential)", func() {
					BeforeEach(func() {
						terminal.Spec.Target.Credentials.ShootRef = nil
						terminal.Spec.Target.Credentials.ServiceAccountRef = &corev1.ObjectReference{
							Namespace: "foo",
							Name:      "",
						}
					})
					AssertFailedBehavior("spec.target.credentials.serviceAccountRef.name: Required value")
				})

				Context("name field (target credential)", func() {
					BeforeEach(func() {
						terminal.Spec.Target.Credentials.ShootRef = nil
						terminal.Spec.Target.Credentials.ServiceAccountRef = &corev1.ObjectReference{
							Namespace: "",
							Name:      "bar",
						}
					})
					AssertFailedBehavior("spec.target.credentials.serviceAccountRef.namespace: Required value")
				})

				Context("name field (host credential)", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Credentials.ShootRef = nil
						terminal.Spec.Host.Credentials.ServiceAccountRef = &corev1.ObjectReference{
							Namespace: "foo",
							Name:      "",
						}
					})
					AssertFailedBehavior("spec.host.credentials.serviceAccountRef.name: Required value")
				})

				Context("name field (host credential)", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Credentials.ShootRef = nil
						terminal.Spec.Host.Credentials.ServiceAccountRef = &corev1.ObjectReference{
							Namespace: "",
							Name:      "bar",
						}
					})
					AssertFailedBehavior("spec.host.credentials.serviceAccountRef.namespace: Required value")
				})
			})

			Context("secret ref", func() {
				Context("honour service account ref disabled", func() {
					Context("secret ref required (host credential)", func() {
						BeforeEach(func() {
							cmConfig.HonourServiceAccountRefHostCluster = nil
							terminal.Spec.Host.Credentials.ServiceAccountRef = nil
							terminal.Spec.Host.Credentials.ShootRef = nil
						})
						AssertFailedBehavior("spec.host.credentials.shootRef: Required value")
					})
					Context("secret ref required (target credential)", func() {
						BeforeEach(func() {
							cmConfig.HonourServiceAccountRefTargetCluster = nil
							terminal.Spec.Target.Credentials.ServiceAccountRef = nil
							terminal.Spec.Target.Credentials.ShootRef = nil
						})
						AssertFailedBehavior("spec.target.credentials.shootRef: Required value")
					})
					Context("name field (target credential)", func() {
						BeforeEach(func() {
							terminal.Spec.Target.Credentials.ServiceAccountRef = nil
							terminal.Spec.Target.Credentials.ShootRef = &dashboardv1alpha1.ShootRef{
								Namespace: "foo",
								Name:      "",
							}
						})
						AssertFailedBehavior("spec.target.credentials.shootRef.name: Required value")
					})

					Context("name field (target credential)", func() {
						BeforeEach(func() {
							terminal.Spec.Target.Credentials.ServiceAccountRef = nil
							terminal.Spec.Target.Credentials.ShootRef = &dashboardv1alpha1.ShootRef{
								Namespace: "",
								Name:      "bar",
							}
						})
						AssertFailedBehavior("spec.target.credentials.shootRef.namespace: Required value")
					})

					Context("name field (host credential)", func() {
						BeforeEach(func() {
							terminal.Spec.Host.Credentials.ServiceAccountRef = nil
							terminal.Spec.Host.Credentials.ShootRef = &dashboardv1alpha1.ShootRef{
								Namespace: "foo",
								Name:      "",
							}
						})
						AssertFailedBehavior("spec.host.credentials.shootRef.name: Required value")
					})

					Context("name field (host credential)", func() {
						BeforeEach(func() {
							terminal.Spec.Host.Credentials.ServiceAccountRef = nil
							terminal.Spec.Host.Credentials.ShootRef = &dashboardv1alpha1.ShootRef{
								Namespace: "",
								Name:      "bar",
							}
						})
						AssertFailedBehavior("spec.host.credentials.shootRef.namespace: Required value")
					})
				})
			})
		})

		Context("for invalid value", func() {
			Context("namespace DNS validation", func() {
				Context("target namespace", func() {
					BeforeEach(func() {
						invalidNamespace := "Invalid_Namespace"
						terminal.Spec.Target.Namespace = &invalidNamespace
					})
					AssertFailedBehavior("spec.target.namespace: Invalid value: \"Invalid_Namespace\"")
				})

				Context("host namespace", func() {
					BeforeEach(func() {
						invalidNamespace := "Invalid_Namespace"
						terminal.Spec.Host.Namespace = &invalidNamespace
					})
					AssertFailedBehavior("spec.host.namespace: Invalid value: \"Invalid_Namespace\"")
				})

				Context("kubeconfigContextNamespace", func() {
					BeforeEach(func() {
						terminal.Spec.Target.KubeconfigContextNamespace = "Invalid_Namespace"
					})
					AssertFailedBehavior("spec.target.kubeconfigContextNamespace: Invalid value: \"Invalid_Namespace\"")
				})

				Context("shootRef namespace (target credential)", func() {
					BeforeEach(func() {
						terminal.Spec.Target.Credentials.ServiceAccountRef = nil
						terminal.Spec.Target.Credentials.ShootRef = &dashboardv1alpha1.ShootRef{
							Namespace: "Invalid_Namespace",
							Name:      "test-shoot",
						}
					})
					AssertFailedBehavior("spec.target.credentials.shootRef.namespace: Invalid value: \"Invalid_Namespace\"")
				})

				Context("shootRef namespace (host credential)", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Credentials.ServiceAccountRef = nil
						terminal.Spec.Host.Credentials.ShootRef = &dashboardv1alpha1.ShootRef{
							Namespace: "Invalid_Namespace",
							Name:      "test-shoot",
						}
					})
					AssertFailedBehavior("spec.host.credentials.shootRef.namespace: Invalid value: \"Invalid_Namespace\"")
				})

				Context("serviceAccountRef namespace (target credential)", func() {
					BeforeEach(func() {
						terminal.Spec.Target.Credentials.ShootRef = nil
						terminal.Spec.Target.Credentials.ServiceAccountRef = &corev1.ObjectReference{
							Namespace: "Invalid_Namespace",
							Name:      "test-sa",
						}
					})
					AssertFailedBehavior("spec.target.credentials.serviceAccountRef.namespace: Invalid value: \"Invalid_Namespace\"")
				})

				Context("serviceAccountRef namespace (host credential)", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Credentials.ShootRef = nil
						terminal.Spec.Host.Credentials.ServiceAccountRef = &corev1.ObjectReference{
							Namespace: "Invalid_Namespace",
							Name:      "test-sa",
						}
					})
					AssertFailedBehavior("spec.host.credentials.serviceAccountRef.namespace: Invalid value: \"Invalid_Namespace\"")
				})

				Context("serviceAccountRef name (target credential)", func() {
					BeforeEach(func() {
						terminal.Spec.Target.Credentials.ShootRef = nil
						terminal.Spec.Target.Credentials.ServiceAccountRef = &corev1.ObjectReference{
							Namespace: "foo",
							Name:      "Invalid_ServiceAccount_Name",
						}
					})
					AssertFailedBehavior("spec.target.credentials.serviceAccountRef.name: Invalid value: \"Invalid_ServiceAccount_Name\"")
				})

				Context("serviceAccountRef name (host credential)", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Credentials.ShootRef = nil
						terminal.Spec.Host.Credentials.ServiceAccountRef = &corev1.ObjectReference{
							Namespace: "foo",
							Name:      "Invalid_ServiceAccount_Name",
						}
					})
					AssertFailedBehavior("spec.host.credentials.serviceAccountRef.name: Invalid value: \"Invalid_ServiceAccount_Name\"")
				})

				Context("shootRef name (target credential)", func() {
					BeforeEach(func() {
						terminal.Spec.Target.Credentials.ServiceAccountRef = nil
						terminal.Spec.Target.Credentials.ShootRef = &dashboardv1alpha1.ShootRef{
							Namespace: "foo",
							Name:      "Invalid_Shoot_Name",
						}
					})
					AssertFailedBehavior("spec.target.credentials.shootRef.name: Invalid value: \"Invalid_Shoot_Name\"")
				})

				Context("shootRef name (host credential)", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Credentials.ServiceAccountRef = nil
						terminal.Spec.Host.Credentials.ShootRef = &dashboardv1alpha1.ShootRef{
							Namespace: "foo",
							Name:      "Invalid_Shoot_Name",
						}
					})
					AssertFailedBehavior("spec.host.credentials.shootRef.name: Invalid value: \"Invalid_Shoot_Name\"")
				})

				Context("apiServerServiceRef name - deprecated", func() {
					BeforeEach(func() {
						terminal.Spec.Target.APIServerServiceRef = &corev1.ObjectReference{
							Name: "Invalid_Service_Name",
						}
					})
					AssertFailedBehavior("spec.target.apiServerServiceRef.name: Invalid value: \"Invalid_Service_Name\"")
				})

				Context("apiServer serviceRef name", func() {
					BeforeEach(func() {
						terminal.Spec.Target.APIServer = &dashboardv1alpha1.APIServer{
							ServiceRef: &corev1.ObjectReference{
								Name: "Invalid_Service_Name",
							},
						}
					})
					AssertFailedBehavior("spec.target.apiServer.serviceRef.name: Invalid value: \"Invalid_Service_Name\"")
				})

				Context("apiServer caData validation", func() {
					Context("invalid PEM data", func() {
						BeforeEach(func() {
							terminal.Spec.Target.APIServer = &dashboardv1alpha1.APIServer{
								CAData: []byte("-----BEGIN CERTIFICATE-----\ninvalid-data\n-----END CERTIFICATE-----"),
							}
						})
						AssertFailedBehavior("spec.target.apiServer.caData: Invalid value: \"<redacted>\": CA bundle must contain at least one PEM-encoded certificate")
					})

					Context("non-PEM data", func() {
						BeforeEach(func() {
							terminal.Spec.Target.APIServer = &dashboardv1alpha1.APIServer{
								CAData: []byte("not a certificate"),
							}
						})
						AssertFailedBehavior("spec.target.apiServer.caData: Invalid value: \"<redacted>\": CA bundle must contain at least one PEM-encoded certificate")
					})

					Context("empty PEM block", func() {
						BeforeEach(func() {
							terminal.Spec.Target.APIServer = &dashboardv1alpha1.APIServer{
								CAData: []byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"),
							}
						})
						AssertFailedBehavior("spec.target.apiServer.caData: Invalid value: \"<redacted>\": cannot parse X.509 certificate")
					})

					Context("non-CERTIFICATE PEM block", func() {
						BeforeEach(func() {
							terminal.Spec.Target.APIServer = &dashboardv1alpha1.APIServer{
								CAData: generatePrivateKeyPEM(),
							}
						})
						AssertFailedBehavior("spec.target.apiServer.caData: Invalid value: \"<redacted>\": unexpected PEM block type \"RSA PRIVATE KEY\" (expected CERTIFICATE)")
					})

					Context("CA bundle with trailing non-PEM data", func() {
						BeforeEach(func() {
							caCert := generateCaCert()
							dataWithTrailing := append(caCert.CertificatePEM, []byte("\nsome trailing data")...)
							terminal.Spec.Target.APIServer = &dashboardv1alpha1.APIServer{
								CAData: dataWithTrailing,
							}
						})
						AssertFailedBehavior("spec.target.apiServer.caData: Invalid value: \"<redacted>\": CA bundle contains trailing non-PEM data")
					})

					Context("mixed PEM types in bundle", func() {
						BeforeEach(func() {
							caCert := generateCaCert()
							privateKey := generatePrivateKeyPEM()
							mixedBundle := append(caCert.CertificatePEM, privateKey...)
							terminal.Spec.Target.APIServer = &dashboardv1alpha1.APIServer{
								CAData: mixedBundle,
							}
						})
						AssertFailedBehavior("spec.target.apiServer.caData: Invalid value: \"<redacted>\": unexpected PEM block type \"RSA PRIVATE KEY\" (expected CERTIFICATE)")
					})

					Context("CA bundle with certificate followed by CSR", func() {
						BeforeEach(func() {
							caCert := generateCaCert()
							csr := generateCSRPEM()
							bundleWithCSR := append(caCert.CertificatePEM, csr...)
							terminal.Spec.Target.APIServer = &dashboardv1alpha1.APIServer{
								CAData: bundleWithCSR,
							}
						})
						AssertFailedBehavior("spec.target.apiServer.caData: Invalid value: \"<redacted>\": unexpected PEM block type \"CERTIFICATE REQUEST\" (expected CERTIFICATE)")
					})
				})
			})

			Context("target authorization", func() {
				// this test can be removed once the deprecated fields are removed
				Context("binding kind - deprecated", func() {
					BeforeEach(func() {
						terminal.Spec.Target.RoleName = "foo"
					})
					AssertFailedBehavior("spec.target.bindingKind: Invalid value: \"\": field should be either ClusterRoleBinding or RoleBinding")
				})

				Context("roleRef binding kind", func() {
					BeforeEach(func() {
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							RoleBindings: []dashboardv1alpha1.RoleBinding{
								{
									RoleRef: rbacv1.RoleRef{
										Name: "foo",
									},
								},
							},
						}
					})
					AssertFailedBehavior("spec.target.authorization.roleBindings[0].bindingKind: Invalid value: \"\": field should be either ClusterRoleBinding or RoleBinding")
				})

				Context("rolebinding nameSuffix", func() {
					BeforeEach(func() {
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							RoleBindings: []dashboardv1alpha1.RoleBinding{
								{
									NameSuffix: "same",
									RoleRef: rbacv1.RoleRef{
										Name: "foo",
									},
									BindingKind: "ClusterRoleBinding",
								},
								{
									NameSuffix: "same",
									RoleRef: rbacv1.RoleRef{
										Name: "bar",
									},
									BindingKind: "ClusterRoleBinding",
								},
							},
						}
					})
					AssertFailedBehavior("spec.target.authorization.roleBindings[1].nameSuffix: Invalid value: \"same\": name must be unique")
				})

				Context("roleRef name validation", func() {
					BeforeEach(func() {
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							RoleBindings: []dashboardv1alpha1.RoleBinding{
								{
									NameSuffix: "valid-suffix",
									RoleRef: rbacv1.RoleRef{
										Name: "invalid/role-name", // Invalid: contains "/"
									},
									BindingKind: "ClusterRoleBinding",
								},
							},
						}
					})
					AssertFailedBehavior("spec.target.authorization.roleBindings[0].roleRef.name: Invalid value: \"invalid/role-name\"")
				})

				Context("rolebinding nameSuffix validation", func() {
					BeforeEach(func() {
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							RoleBindings: []dashboardv1alpha1.RoleBinding{
								{
									NameSuffix: "invalid/suffix", // Invalid: contains "/"
									RoleRef: rbacv1.RoleRef{
										Name: "valid-role",
									},
									BindingKind: "ClusterRoleBinding",
								},
							},
						}
					})
					AssertFailedBehavior("spec.target.authorization.roleBindings[0].nameSuffix: Invalid value: \"invalid/suffix\"")
				})

				Context("rolebinding valid components", func() {
					BeforeEach(func() {
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							RoleBindings: []dashboardv1alpha1.RoleBinding{
								{
									NameSuffix: "valid-suffix",
									RoleRef: rbacv1.RoleRef{
										Name: "valid-role",
									},
									BindingKind: "ClusterRoleBinding",
								},
							},
						}
					})
					It("should succeed with valid roleRef name and nameSuffix", func() {
						Expect(terminalCreationError).To(Not(HaveOccurred()))
					})
				})

				Context("projectName validation", func() {
					BeforeEach(func() {
						cmConfig.HonourProjectMemberships = ptr.To(true)
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							ProjectMemberships: []dashboardv1alpha1.ProjectMembership{
								{
									ProjectName: "Invalid_Project_Name",
									Roles:       []string{"admin"},
								},
							},
						}
					})
					AssertFailedBehavior("spec.target.authorization.projectMemberships[0].projectName: Invalid value: \"Invalid_Project_Name\"")
				})
			})

			Context("pod labels validation", func() {
				Context("invalid label key", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Pod.Labels = map[string]string{
							"invalid/key/with/too/many/slashes": "value",
						}
					})
					AssertFailedBehavior("spec.host.pod.labels: Invalid value")
				})

				Context("invalid label key - too long", func() {
					BeforeEach(func() {
						// Create a key longer than 63 characters for the name part
						longKey := strings.Repeat("a", 64)
						terminal.Spec.Host.Pod.Labels = map[string]string{
							longKey: "value",
						}
					})
					AssertFailedBehavior("spec.host.pod.labels: Invalid value")
				})

				Context("invalid label value - too long", func() {
					BeforeEach(func() {
						// Create a value longer than 63 characters
						longValue := strings.Repeat("a", 64)
						terminal.Spec.Host.Pod.Labels = map[string]string{
							"valid-key": longValue,
						}
					})
					AssertFailedBehavior("spec.host.pod.labels: Invalid value")
				})

				Context("invalid label key - invalid characters", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Pod.Labels = map[string]string{
							"invalid@key": "value",
						}
					})
					AssertFailedBehavior("spec.host.pod.labels: Invalid value")
				})

				Context("invalid label value - invalid characters", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Pod.Labels = map[string]string{
							"valid-key": "invalid@value",
						}
					})
					AssertFailedBehavior("spec.host.pod.labels: Invalid value")
				})

				Context("valid labels", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Pod.Labels = map[string]string{
							"app":                        "my-app",
							"version":                    "v1.0.0",
							"environment":                "production",
							"kubernetes.io/managed-by":   "terminal-controller",
							"example.com/component":      "backend",
							"valid-key-with-dashes":      "valid-value-with-dashes",
							"valid_key_with_underscores": "valid_value_with_underscores",
							"valid.key.with.dots":        "valid.value.with.dots",
							"123numeric":                 "123numeric",
						}
					})
					It("should allow valid labels", func() {
						Expect(terminalCreationError).To(Not(HaveOccurred()))
					})
				})
			})

			Context("node selector validation", func() {
				Context("invalid node selector key", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Pod.NodeSelector = map[string]string{
							"invalid/key/with/too/many/slashes": "value",
						}
					})
					AssertFailedBehavior("spec.host.pod.nodeSelector: Invalid value")
				})

				Context("invalid node selector key - too long", func() {
					BeforeEach(func() {
						// Create a key longer than 63 characters for the name part
						longKey := strings.Repeat("a", 64)
						terminal.Spec.Host.Pod.NodeSelector = map[string]string{
							longKey: "value",
						}
					})
					AssertFailedBehavior("spec.host.pod.nodeSelector: Invalid value")
				})

				Context("invalid node selector value - too long", func() {
					BeforeEach(func() {
						// Create a value longer than 63 characters
						longValue := strings.Repeat("a", 64)
						terminal.Spec.Host.Pod.NodeSelector = map[string]string{
							"kubernetes.io/arch": longValue,
						}
					})
					AssertFailedBehavior("spec.host.pod.nodeSelector: Invalid value")
				})

				Context("invalid node selector key - invalid characters", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Pod.NodeSelector = map[string]string{
							"invalid@key": "amd64",
						}
					})
					AssertFailedBehavior("spec.host.pod.nodeSelector: Invalid value")
				})

				Context("invalid node selector value - invalid characters", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Pod.NodeSelector = map[string]string{
							"kubernetes.io/arch": "invalid@value",
						}
					})
					AssertFailedBehavior("spec.host.pod.nodeSelector: Invalid value")
				})

				Context("valid node selector", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Pod.NodeSelector = map[string]string{
							"kubernetes.io/arch":               "amd64",
							"kubernetes.io/os":                 "linux",
							"node.kubernetes.io/instance-type": "m5.large",
							"topology.kubernetes.io/zone":      "us-west-2a",
							"custom-label":                     "custom-value",
						}
					})
					It("should allow valid node selector", func() {
						Expect(terminalCreationError).To(Not(HaveOccurred()))
					})
				})
			})

			Context("empty labels and node selector", func() {
				BeforeEach(func() {
					terminal.Spec.Host.Pod.Labels = nil
					terminal.Spec.Host.Pod.NodeSelector = nil
				})
				It("should allow nil labels and node selector", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))
				})
			})

			Context("empty maps for labels and node selector", func() {
				BeforeEach(func() {
					terminal.Spec.Host.Pod.Labels = map[string]string{}
					terminal.Spec.Host.Pod.NodeSelector = map[string]string{}
				})
				It("should allow empty maps for labels and node selector", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))
				})
			})
		})

		Context("for forbidden value", func() {
			Context("target authorization", func() {
				Context("project membership", func() {
					BeforeEach(func() {
						cmConfig.HonourProjectMemberships = nil
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							ProjectMemberships: []dashboardv1alpha1.ProjectMembership{
								{
									ProjectName: "foo",
									Roles:       []string{"admin"},
								},
							},
						}
					})
					AssertFailedBehavior("spec.target.authorization.projectMemberships: Forbidden")
				})
				Context("service account ref (host credential)", func() {
					BeforeEach(func() {
						cmConfig.HonourServiceAccountRefHostCluster = nil
						terminal.Spec.Host.Credentials.ServiceAccountRef = &corev1.ObjectReference{
							Namespace: "foo",
							Name:      "bar",
						}
					})
					AssertFailedBehavior("spec.host.credentials.serviceAccountRef: Forbidden")
				})
				Context("service account ref (target credential)", func() {
					BeforeEach(func() {
						cmConfig.HonourServiceAccountRefTargetCluster = nil
						terminal.Spec.Target.Credentials.ServiceAccountRef = &corev1.ObjectReference{
							Namespace: "foo",
							Name:      "bar",
						}
					})
					AssertFailedBehavior("spec.target.credentials.serviceAccountRef: Forbidden")
				})
			})
		})

		Context("for bad request", func() {
			Context("terminal resource too big", func() {
				BeforeEach(func() {
					cmConfig.Webhooks.TerminalValidation.MaxObjectSize = 1
				})
				AssertFailedBehavior("resource must not have more than 1 bytes")
			})
		})
	})
})
