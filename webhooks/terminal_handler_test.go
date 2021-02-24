/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhooks

import (
	"fmt"
	"time"

	dashboardv1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	randomLength = 5
	charset      = "abcdefghijklmnopqrstuvwxyz0123456789"
)

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
		terminalNamespace = fmt.Sprintf("%s%s", "test-terminal-namespace-", suffix)
		hostNamespace = fmt.Sprintf("%s%s", "test-host-serviceaccount-namespace-", suffix)
		targetNamespace = fmt.Sprintf("%s%s", "test-target-serviceaccount-namespace-", suffix)
		terminalName = fmt.Sprintf("%s%s", "test-terminal-", suffix)

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
						ServiceAccountRef: &v1.ObjectReference{
							Kind:      rbacv1.ServiceAccountKind,
							Name:      hostServiceAccountKey.Name,
							Namespace: hostServiceAccountKey.Namespace,
						},
					},
					Namespace:          &hostNamespace,
					TemporaryNamespace: false,
					Pod: dashboardv1alpha1.Pod{
						Container: &dashboardv1alpha1.Container{
							Image: "foo",
						},
					},
				},
				Target: dashboardv1alpha1.TargetCluster{
					Credentials: dashboardv1alpha1.ClusterCredentials{
						ServiceAccountRef: &v1.ObjectReference{
							Kind:      rbacv1.ServiceAccountKind,
							Name:      targetServiceAccountKey.Name,
							Namespace: targetServiceAccountKey.Namespace,
						},
					},
					Namespace:                  &targetNamespace,
					TemporaryNamespace:         false,
					KubeconfigContextNamespace: "default",
				},
			},
		}

		By("By creating namespaces")
		namespaces := []string{terminalNamespace, hostNamespace, targetNamespace}
		for _, namespace := range namespaces {
			terminalNamespaceKey := types.NamespacedName{Name: namespace}
			test.CreateObject(ctx, k8sClient, &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}, terminalNamespaceKey, timeout, interval)
		}

		By("By creating host serviceaccount")
		test.CreateServiceAccount(ctx, k8sClient, HostServiceAccountName, hostNamespace, timeout, interval)
		By("By creating target serviceaccount")
		test.CreateServiceAccount(ctx, k8sClient, TargetServiceAccountName, targetNamespace, timeout, interval)
	})

	AssertFailedBehavior := func(expectedSubstring string) {
		It("Should error", func() {
			Expect(terminalCreationError).To(HaveOccurred())
			Expect(terminalCreationError.Error()).To(ContainSubstring(expectedSubstring))
		})
	}

	JustBeforeEach(func() {
		terminalCreationError = k8sClient.Create(ctx, terminal)
	})

	Describe("mutation succeeds", func() {
		Context("identifier", func() {
			BeforeEach(func() {
				terminal.Spec.Identifier = ""
			})
			It("should generate an identifier", func() {
				Expect(terminalCreationError).To(Not(HaveOccurred()))

				Eventually(func() bool {
					err := k8sClient.Get(ctx, terminalKey, terminal)
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
					err := k8sClient.Get(ctx, terminalKey, terminal)
					return err == nil
				}, timeout, interval).Should(BeTrue())
				Expect(terminal.Annotations[dashboardv1alpha1.TerminalLastHeartbeat]).To(Not(BeEmpty()))

				By("clearing last heartbeat and setting keepalive annotation")
				terminal.ObjectMeta.Annotations[dashboardv1alpha1.TerminalLastHeartbeat] = ""
				terminal.ObjectMeta.Annotations[dashboardv1alpha1.TerminalOperation] = dashboardv1alpha1.TerminalOperationKeepalive
				error := k8sClient.Update(ctx, terminal)
				Expect(error).To(Not(HaveOccurred()))

				By("by reading the terminal")
				terminal = &dashboardv1alpha1.Terminal{}
				error = k8sClient.Get(ctx, terminalKey, terminal)
				Expect(error).To(Not(HaveOccurred()))

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

		Context("secret ref (host credential)", func() {
			BeforeEach(func() {
				terminal.Spec.Host.Credentials.SecretRef = &v1.SecretReference{
					Namespace: hostNamespace,
					Name:      "bar",
				}
			})
			It("should allow to reference secret", func() {
				Expect(terminalCreationError).To(Not(HaveOccurred()))
			})
		})

		Context("secret ref (target credential)", func() {
			BeforeEach(func() {
				terminal.Spec.Target.Credentials.SecretRef = &v1.SecretReference{
					Namespace: targetNamespace,
					Name:      "bar",
				}
			})
			It("should allow to reference secret", func() {
				Expect(terminalCreationError).To(Not(HaveOccurred()))
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
					err := k8sClient.Get(ctx, terminalKey, terminal)
					return err == nil
				}, timeout, interval).Should(BeTrue())

				By("updating the last heartbeat time")
				terminal.ObjectMeta.Annotations[dashboardv1alpha1.TerminalLastHeartbeat] = time.Now().UTC().Format(time.RFC3339)
				error := k8sClient.Update(ctx, terminal)

				Expect(error).To(Not(HaveOccurred()))
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
						err := k8sClient.Get(ctx, terminalKey, terminal)
						return err == nil
					}, timeout, interval).Should(BeTrue())

					terminal.Spec.Identifier = "changed"
					error := k8sClient.Update(ctx, terminal)

					Expect(error).To(HaveOccurred())
					Expect(error.Error()).To(ContainSubstring("field is immutable"))
				})

				It("should fail when updating host namespace", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))

					By("Expecting terminal to be created")
					Eventually(func() bool {
						terminal = &dashboardv1alpha1.Terminal{}
						err := k8sClient.Get(ctx, terminalKey, terminal)
						return err == nil
					}, timeout, interval).Should(BeTrue())

					changed := "changed"
					terminal.Spec.Host.Namespace = &changed
					error := k8sClient.Update(ctx, terminal)

					Expect(error).To(HaveOccurred())
					Expect(error.Error()).To(ContainSubstring("field is immutable"))
				})

				It("should fail when updating target namespace", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))

					By("Expecting terminal to be created")
					Eventually(func() bool {
						terminal = &dashboardv1alpha1.Terminal{}
						err := k8sClient.Get(ctx, terminalKey, terminal)
						return err == nil
					}, timeout, interval).Should(BeTrue())

					changed := "changed"
					terminal.Spec.Target.Namespace = &changed
					error := k8sClient.Update(ctx, terminal)

					Expect(error).To(HaveOccurred())
					Expect(error.Error()).To(ContainSubstring("field is immutable"))
				})

				It("should fail when updating target credential secret", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))

					By("Expecting terminal to be created")
					Eventually(func() bool {
						terminal = &dashboardv1alpha1.Terminal{}
						err := k8sClient.Get(ctx, terminalKey, terminal)
						return err == nil
					}, timeout, interval).Should(BeTrue())

					terminal.Spec.Target.Credentials.SecretRef = &v1.SecretReference{
						Namespace: targetNamespace,
						Name:      "changed",
					}
					error := k8sClient.Update(ctx, terminal)

					Expect(error).To(HaveOccurred())
					Expect(error.Error()).To(ContainSubstring("field is immutable"))
				})

				It("should fail when updating host credential secret", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))

					By("Expecting terminal to be created")
					Eventually(func() bool {
						terminal = &dashboardv1alpha1.Terminal{}
						err := k8sClient.Get(ctx, terminalKey, terminal)
						return err == nil
					}, timeout, interval).Should(BeTrue())

					terminal.Spec.Host.Credentials.SecretRef = &v1.SecretReference{
						Namespace: hostNamespace,
						Name:      "bar",
					}
					error := k8sClient.Update(ctx, terminal)

					Expect(error).To(HaveOccurred())
					Expect(error.Error()).To(ContainSubstring("field is immutable"))
				})

				It("should fail when changing target temporary namespace flag", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))

					By("Expecting terminal to be created")
					Eventually(func() bool {
						terminal = &dashboardv1alpha1.Terminal{}
						err := k8sClient.Get(ctx, terminalKey, terminal)
						return err == nil
					}, timeout, interval).Should(BeTrue())

					terminal.Spec.Target.TemporaryNamespace = true
					error := k8sClient.Update(ctx, terminal)

					Expect(error).To(HaveOccurred())
					Expect(error.Error()).To(ContainSubstring("field is immutable"))
				})

				It("should fail when changing host temporary namespace flag", func() {
					Expect(terminalCreationError).To(Not(HaveOccurred()))

					By("Expecting terminal to be created")
					Eventually(func() bool {
						terminal = &dashboardv1alpha1.Terminal{}
						err := k8sClient.Get(ctx, terminalKey, terminal)
						return err == nil
					}, timeout, interval).Should(BeTrue())

					terminal.Spec.Host.TemporaryNamespace = true
					error := k8sClient.Update(ctx, terminal)

					Expect(error).To(HaveOccurred())
					Expect(error.Error()).To(ContainSubstring("field is immutable"))
				})
			})

			It("annotation createdBy should be immutable", func() {
				Expect(terminalCreationError).To(Not(HaveOccurred()))

				By("Expecting terminal to be created")
				Eventually(func() bool {
					terminal = &dashboardv1alpha1.Terminal{}
					err := k8sClient.Get(ctx, terminalKey, terminal)
					return err == nil
				}, timeout, interval).Should(BeTrue())

				terminal.ObjectMeta.Annotations[dashboardv1alpha1.GardenCreatedBy] = "changed"
				error := k8sClient.Update(ctx, terminal)

				Expect(error).To(HaveOccurred())
				Expect(error.Error()).To(ContainSubstring("metadata.annotations.gardener.cloud/created-by: Invalid value: \"changed\": field is immutable"))
			})

			It("should not allow to set last heartbeat in the future", func() {
				Expect(terminalCreationError).To(Not(HaveOccurred()))

				By("Expecting terminal to be created")
				Eventually(func() bool {
					terminal = &dashboardv1alpha1.Terminal{}
					err := k8sClient.Get(ctx, terminalKey, terminal)
					return err == nil
				}, timeout, interval).Should(BeTrue())

				By("updating the last heartbeat time to the future")
				future := time.Now().Local().Add(time.Hour)
				terminal.ObjectMeta.Annotations[dashboardv1alpha1.TerminalLastHeartbeat] = future.UTC().Format(time.RFC3339)
				error := k8sClient.Update(ctx, terminal)

				Expect(error).To(HaveOccurred())
				Expect(error.Error()).To(ContainSubstring("metadata.annotations.dashboard.gardener.cloud/last-heartbeat-at: Forbidden"))
			})

			It("should not allow to set invalid last heartbeat date", func() {
				Expect(terminalCreationError).To(Not(HaveOccurred()))

				By("Expecting terminal to be created")
				Eventually(func() bool {
					terminal = &dashboardv1alpha1.Terminal{}
					err := k8sClient.Get(ctx, terminalKey, terminal)
					return err == nil
				}, timeout, interval).Should(BeTrue())

				By("setting an invalid value as last heartbeat time")
				terminal.ObjectMeta.Annotations[dashboardv1alpha1.TerminalLastHeartbeat] = "invalid"
				error := k8sClient.Update(ctx, terminal)

				Expect(error).To(HaveOccurred())
				Expect(error.Error()).To(ContainSubstring("metadata.annotations.dashboard.gardener.cloud/last-heartbeat-at: Invalid value"))
			})
		})
	})

	Describe("CREATE fails", func() {
		Context("for missing required field", func() {
			Context("host credentials", func() {
				BeforeEach(func() {
					terminal.Spec.Host.Credentials.SecretRef = nil
					terminal.Spec.Host.Credentials.ServiceAccountRef = nil
				})
				AssertFailedBehavior("spec.host.credentials: Required value")
			})

			Context("target credentials", func() {
				BeforeEach(func() {
					terminal.Spec.Target.Credentials.SecretRef = nil
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
						cmConfig.HonourProjectMemberships = true
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
						cmConfig.HonourProjectMemberships = true
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
						cmConfig.HonourProjectMemberships = true
						terminal.Spec.Target.Authorization = &dashboardv1alpha1.Authorization{
							ProjectMemberships: []dashboardv1alpha1.ProjectMembership{
								{
									ProjectName: "foo",
									Roles:       []string{"role1", ""},
								},
							},
						}
					})
					AssertFailedBehavior("spec.target.authorization.projectMemberships[0].roles[1]: Required value")
				})
			})

			Context("api server", func() {
				Context("service ref name - deprecated", func() {
					BeforeEach(func() {
						terminal.Spec.Target.APIServerServiceRef = &v1.ObjectReference{
							Name: "",
						}
					})
					AssertFailedBehavior("spec.target.apiServerServiceRef.name: Required value")
				})

				Context("serviceRef and server field", func() {
					BeforeEach(func() {
						terminal.Spec.Target.APIServer = &dashboardv1alpha1.APIServer{
							ServiceRef: nil,
							Server:     "",
						}
					})
					AssertFailedBehavior("spec.target.apiServer.server: Required value: field or spec.target.apiServer.serviceRef field is required when spec.target.apiServer is set")
				})

				Context("serviceRef and server field", func() {
					BeforeEach(func() {
						terminal.Spec.Target.APIServer = &dashboardv1alpha1.APIServer{
							ServiceRef: &v1.ObjectReference{
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
						terminal.Spec.Target.Credentials.SecretRef = nil
						terminal.Spec.Target.Credentials.ServiceAccountRef = &v1.ObjectReference{
							Namespace: "foo",
							Name:      "",
						}
					})
					AssertFailedBehavior("spec.target.credentials.serviceAccountRef.name: Required value")
				})

				Context("name field (target credential)", func() {
					BeforeEach(func() {
						terminal.Spec.Target.Credentials.SecretRef = nil
						terminal.Spec.Target.Credentials.ServiceAccountRef = &v1.ObjectReference{
							Namespace: "",
							Name:      "bar",
						}
					})
					AssertFailedBehavior("spec.target.credentials.serviceAccountRef.namespace: Required value")
				})

				Context("name field (host credential)", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Credentials.SecretRef = nil
						terminal.Spec.Host.Credentials.ServiceAccountRef = &v1.ObjectReference{
							Namespace: "foo",
							Name:      "",
						}
					})
					AssertFailedBehavior("spec.host.credentials.serviceAccountRef.name: Required value")
				})

				Context("name field (host credential)", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Credentials.SecretRef = nil
						terminal.Spec.Host.Credentials.ServiceAccountRef = &v1.ObjectReference{
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
							cmConfig.HonourServiceAccountRefHostCluster = false
							terminal.Spec.Host.Credentials.ServiceAccountRef = nil
							terminal.Spec.Host.Credentials.SecretRef = nil
						})
						AssertFailedBehavior("spec.host.credentials.secretRef: Required value")
					})
					Context("secret ref required (target credential)", func() {
						BeforeEach(func() {
							cmConfig.HonourServiceAccountRefTargetCluster = false
							terminal.Spec.Target.Credentials.ServiceAccountRef = nil
							terminal.Spec.Target.Credentials.SecretRef = nil
						})
						AssertFailedBehavior("spec.target.credentials.secretRef: Required value")
					})
					Context("name field (target credential)", func() {
						BeforeEach(func() {
							terminal.Spec.Target.Credentials.ServiceAccountRef = nil
							terminal.Spec.Target.Credentials.SecretRef = &v1.SecretReference{
								Namespace: "foo",
								Name:      "",
							}
						})
						AssertFailedBehavior("spec.target.credentials.secretRef.name: Required value")
					})

					Context("name field (target credential)", func() {
						BeforeEach(func() {
							terminal.Spec.Target.Credentials.ServiceAccountRef = nil
							terminal.Spec.Target.Credentials.SecretRef = &v1.SecretReference{
								Namespace: "",
								Name:      "bar",
							}
						})
						AssertFailedBehavior("spec.target.credentials.secretRef.namespace: Required value")
					})

					Context("name field (host credential)", func() {
						BeforeEach(func() {
							terminal.Spec.Host.Credentials.ServiceAccountRef = nil
							terminal.Spec.Host.Credentials.SecretRef = &v1.SecretReference{
								Namespace: "foo",
								Name:      "",
							}
						})
						AssertFailedBehavior("spec.host.credentials.secretRef.name: Required value")
					})

					Context("name field (host credential)", func() {
						BeforeEach(func() {
							terminal.Spec.Host.Credentials.ServiceAccountRef = nil
							terminal.Spec.Host.Credentials.SecretRef = &v1.SecretReference{
								Namespace: "",
								Name:      "bar",
							}
						})
						AssertFailedBehavior("spec.host.credentials.secretRef.namespace: Required value")
					})
				})
			})
		})

		Context("for invalid value", func() {
			Context("target authorization", func() {
				// this test can be removed once the deprecated fields are removed
				Context("binding kind - deprecated", func() {
					BeforeEach(func() {
						terminal.Spec.Target.RoleName = "foo"
					})
					AssertFailedBehavior("spec.target.bindingKind: Invalid value: : field should be either ClusterRoleBinding or RoleBinding")
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
					AssertFailedBehavior("spec.target.authorization.roleBindings[0].bindingKind: Invalid value: : field should be either ClusterRoleBinding or RoleBinding")
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
			})
		})

		Context("for forbidden value", func() {
			Context("target authorization", func() {
				Context("project membership", func() {
					BeforeEach(func() {
						cmConfig.HonourProjectMemberships = false
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
						cmConfig.HonourServiceAccountRefHostCluster = false
						terminal.Spec.Host.Credentials.ServiceAccountRef = &v1.ObjectReference{
							Namespace: "foo",
							Name:      "bar",
						}
					})
					AssertFailedBehavior("spec.host.credentials.serviceAccountRef: Forbidden")
				})
				Context("service account ref (target credential)", func() {
					BeforeEach(func() {
						cmConfig.HonourServiceAccountRefTargetCluster = false
						terminal.Spec.Target.Credentials.ServiceAccountRef = &v1.ObjectReference{
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
