/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package controllers

import (
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kErros "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	dashboardv1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/test"
)

var _ = Describe("Terminal Controller", func() {
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

		terminalReconciler.injectConfig(cmConfig)
		terminalHeartbeatReconciler.injectConfig(cmConfig)

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

	JustBeforeEach(func() {
		terminalCreationError = e.K8sClient.Create(ctx, terminal)
	})

	Context("terminal lifecycle", func() {
		Context("temporary namespace", func() {
			Context("cleanup", func() {
				Context("host namespace", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Namespace = nil
						terminal.Spec.Host.TemporaryNamespace = ptr.To(true)

						terminal.Spec.Target.Namespace = nil
						terminal.Spec.Target.TemporaryNamespace = ptr.To(true)
					})
					It("Should delete temporary host and target host namespace", func() {
						Expect(terminalCreationError).Should(Not(HaveOccurred()))

						By("Expecting target namespace to be set")
						Eventually(func() bool {
							terminal = &dashboardv1alpha1.Terminal{}
							err := e.K8sClient.Get(ctx, terminalKey, terminal)
							if err != nil {
								return false
							}
							targetNamespace = *terminal.Spec.Target.Namespace
							return targetNamespace != ""
						}, timeout, interval).Should(BeTrue())

						By("Waiting for AccessServiceAccount to be created")
						accessServiceAccount := &corev1.ServiceAccount{}
						Eventually(func() bool {
							targetNamespace := *terminal.Spec.Target.Namespace
							err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier, Namespace: targetNamespace}, accessServiceAccount)
							return err == nil
						}, timeout, interval).Should(BeTrue())

						By("Waiting for terminal to be ready")
						Eventually(func() bool {
							t := &dashboardv1alpha1.Terminal{}
							err := e.K8sClient.Get(ctx, terminalKey, t)
							if err != nil {
								return false
							}
							return t.Status.AttachServiceAccountName != nil &&
								t.Status.PodName != nil &&
								*t.Status.AttachServiceAccountName == dashboardv1alpha1.TerminalAttachResourceNamePrefix+terminal.Spec.Identifier &&
								*t.Status.PodName == dashboardv1alpha1.TerminalPodResourceNamePrefix+terminal.Spec.Identifier
						}, timeout, interval).Should(BeTrue())

						temporaryHostNamespace := *terminal.Spec.Host.Namespace
						temporaryTargetNamespace := *terminal.Spec.Target.Namespace

						By("Deleting the terminal")
						err := e.K8sClient.Delete(ctx, terminal)
						Expect(err).To(Not(HaveOccurred()))

						Eventually(func() bool {
							t := &dashboardv1alpha1.Terminal{}
							err := e.K8sClient.Get(ctx, terminalKey, t)
							return kErros.IsNotFound(err)
						}, timeout, interval).Should(BeTrue())

						By("expecting temporary host namespace to be in deletion")
						namespace := &corev1.Namespace{}
						err = e.K8sClient.Get(ctx, types.NamespacedName{Name: temporaryHostNamespace}, namespace)
						Expect(err).To(Not(HaveOccurred())) // with envtest no kube-controller is running that is finally deleting the namespace
						Expect(namespace.DeletionTimestamp).To(Not(BeNil()))

						By("expecting temporary target namespace to be in deletion")
						namespace = &corev1.Namespace{}
						err = e.K8sClient.Get(ctx, types.NamespacedName{Name: temporaryTargetNamespace}, namespace)
						Expect(err).To(Not(HaveOccurred())) // with envtest no kube-controller is running that is finally deleting the namespace
						Expect(namespace.DeletionTimestamp).To(Not(BeNil()))
					})
				})
			})
			Context("creation", func() {
				Context("host and target namespace", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Namespace = nil
						terminal.Spec.Host.TemporaryNamespace = ptr.To(true)

						terminal.Spec.Target.Namespace = nil
						terminal.Spec.Target.TemporaryNamespace = ptr.To(true)
					})
					It("Should create temporary host and target namespace", func() {
						Expect(terminalCreationError).Should(Not(HaveOccurred()))

						By("Expecting target namespace to be set")
						Eventually(func() bool {
							terminal = &dashboardv1alpha1.Terminal{}
							err := e.K8sClient.Get(ctx, terminalKey, terminal)
							if err != nil {
								return false
							}
							targetNamespace = *terminal.Spec.Target.Namespace
							return targetNamespace != ""
						}, timeout, interval).Should(BeTrue())

						By("Waiting for AccessServiceAccount to be created")
						accessServiceAccount := &corev1.ServiceAccount{}
						Eventually(func() bool {
							err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier, Namespace: targetNamespace}, accessServiceAccount)
							return err == nil
						}, timeout, interval).Should(BeTrue())

						By("Waiting for terminal to be ready")
						Eventually(func() bool {
							t := &dashboardv1alpha1.Terminal{}
							err := e.K8sClient.Get(ctx, terminalKey, t)
							if err != nil {
								return false
							}
							return t.Status.AttachServiceAccountName != nil &&
								t.Status.PodName != nil &&
								*t.Status.AttachServiceAccountName == dashboardv1alpha1.TerminalAttachResourceNamePrefix+terminal.Spec.Identifier &&
								*t.Status.PodName == dashboardv1alpha1.TerminalPodResourceNamePrefix+terminal.Spec.Identifier
						}, timeout, interval).Should(BeTrue())

						By("Expecting (temporary) target namespace to be created")
						Expect(*terminal.Spec.Target.Namespace).To(Not(BeEmpty()))
						Eventually(func() bool {
							err := e.K8sClient.Get(ctx, types.NamespacedName{Name: *terminal.Spec.Target.Namespace}, &corev1.Namespace{})
							return err == nil
						}).Should(BeTrue())

						By("Expecting (temporary) host namespace to be created")
						Expect(*terminal.Spec.Host.Namespace).To(Not(BeEmpty()))
						Eventually(func() bool {
							err := e.K8sClient.Get(ctx, types.NamespacedName{Name: *terminal.Spec.Host.Namespace}, &corev1.Namespace{})
							return err == nil
						}).Should(BeTrue())
					})
				})
			})
		})

		It("Should cleanup resources on host and target", func() {
			Expect(terminalCreationError).Should(Not(HaveOccurred()))

			By("Expecting terminal to be created")
			Eventually(func() bool {
				err := e.K8sClient.Get(ctx, terminalKey, &dashboardv1alpha1.Terminal{})
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("Waiting for AccessServiceAccount to be created")
			accessServiceAccount := &corev1.ServiceAccount{}
			Eventually(func() bool {
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier, Namespace: targetNamespace}, accessServiceAccount)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("Waiting for terminal to be ready")
			Eventually(func() bool {
				t := &dashboardv1alpha1.Terminal{}
				err := e.K8sClient.Get(ctx, terminalKey, t)
				if err != nil {
					return false
				}
				return t.Status.AttachServiceAccountName != nil &&
					t.Status.PodName != nil &&
					*t.Status.AttachServiceAccountName == dashboardv1alpha1.TerminalAttachResourceNamePrefix+terminal.Spec.Identifier &&
					*t.Status.PodName == dashboardv1alpha1.TerminalPodResourceNamePrefix+terminal.Spec.Identifier
			}, timeout, interval).Should(BeTrue())

			By("Deleting the terminal")
			Eventually(func() bool {
				err := e.K8sClient.Delete(ctx, terminal)
				return kErros.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())

			By("Expecting AttachServiceAccount to be removed")
			Eventually(func() bool {
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAttachResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, &corev1.ServiceAccount{})
				return kErros.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())

			By("Expecting attach role to be removed")
			Eventually(func() bool {
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAttachRoleResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, &rbacv1.Role{})
				return kErros.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())

			By("Expecting AccessServiceAccount to be removed")
			Eventually(func() bool {
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier, Namespace: targetNamespace}, &corev1.ServiceAccount{})
				return kErros.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())

			By("Expecting kubeconfig secret to be removed")
			Eventually(func() bool {
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.KubeconfigSecretResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, &corev1.Secret{})
				return kErros.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())

			By("Expecting token secret to be removed")
			Eventually(func() bool {
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TokenSecretResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, &corev1.Secret{})
				return kErros.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())

			By("Expecting terminal pod to be removed")
			Eventually(func() bool {
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalPodResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, &corev1.Pod{})
				return kErros.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())

			By("Expecting terminal resource to be removed")
			Eventually(func() bool {
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: terminalKey.Name, Namespace: terminalKey.Namespace}, &dashboardv1alpha1.Terminal{})
				return kErros.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())

			By("Ensuring that host namespace is not deleted")
			Consistently(func() bool {
				namespace := &corev1.Namespace{}
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: hostNamespace}, namespace)
				if err != nil {
					return false
				}
				return namespace.DeletionTimestamp == nil
			}).Should(BeTrue())

			By("Ensuring that target namespace is not deleted")
			Consistently(func() bool {
				namespace := &corev1.Namespace{}
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: targetNamespace}, namespace)
				if err != nil {
					return false
				}
				return namespace.DeletionTimestamp == nil
			}).Should(BeTrue())
		})

		It("Should create resources on host and target", func() {
			Expect(terminalCreationError).Should(Not(HaveOccurred()))

			By("Expecting terminal to be created")
			Eventually(func() bool {
				err := e.K8sClient.Get(ctx, terminalKey, &dashboardv1alpha1.Terminal{})
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("Expecting reconcile to succeed")
			Eventually(func() bool {
				t := &dashboardv1alpha1.Terminal{}
				err := e.K8sClient.Get(ctx, terminalKey, t)
				if err != nil {
					return false
				}
				return t.Status.LastOperation != nil &&
					t.Status.LastOperation.Type == dashboardv1alpha1.LastOperationTypeReconcile &&
					t.Status.LastOperation.State == dashboardv1alpha1.LastOperationStateSucceeded
			}, timeout, interval).Should(BeTrue())

			By("Expecting AttachServiceAccount to be created")
			Eventually(func() bool {
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAttachResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, &corev1.ServiceAccount{})
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("Expecting AttachServiceAccountName to be set")
			Eventually(func() string {
				t := &dashboardv1alpha1.Terminal{}
				err := e.K8sClient.Get(ctx, terminalKey, t)
				if err != nil || t.Status.AttachServiceAccountName == nil {
					return ""
				}
				return *t.Status.AttachServiceAccountName
			}, timeout, interval).Should(Not(BeEmpty()))

			By("Expecting attach role to be created")
			Eventually(func() bool {
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAttachRoleResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, &rbacv1.Role{})
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("Expecting AccessServiceAccount to be created")
			accessServiceAccount := &corev1.ServiceAccount{}
			Eventually(func() bool {
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier, Namespace: targetNamespace}, accessServiceAccount)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("Expecting kubeconfig secret to be created")
			Eventually(func() bool {
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.KubeconfigSecretResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, &corev1.Secret{})
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("Expecting token secret to be created")
			Eventually(func() bool {
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TokenSecretResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, &corev1.Secret{})
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("Expecting terminal pod with foo image to be created")
			Eventually(func() string {
				pod := &corev1.Pod{}
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalPodResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, pod)
				if err != nil {
					return ""
				}
				return pod.Spec.Containers[0].Image
			}, timeout, interval).Should(Equal("foo"))

			By("Expecting PodName to be set")
			Eventually(func() string {
				t := &dashboardv1alpha1.Terminal{}
				err := e.K8sClient.Get(ctx, terminalKey, t)
				if err != nil || t.Status.PodName == nil {
					return ""
				}
				return *t.Status.PodName
			}, timeout, interval).Should(Not(BeEmpty()))
		})
	})

	Context("when using projected service account token volume", func() {
		BeforeEach(func() {
			By("Ensuring same service account and namespace is used for host and target")

			namespace := "test-same-namespace-" + suffix
			hostNamespace = namespace
			targetNamespace = namespace
			terminal.Spec.Host.Namespace = &namespace
			terminal.Spec.Target.Namespace = &namespace
			e.CreateObject(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}, types.NamespacedName{Name: namespace}, timeout, interval)

			serviceAccountName := "test-serviceaccount-" + suffix
			e.AddClusterAdminServiceAccount(ctx, serviceAccountName, namespace, timeout, interval)

			serviceAccountRef := corev1.ObjectReference{
				Namespace: namespace,
				Name:      serviceAccountName,
			}
			terminal.Spec.Host.Credentials.ServiceAccountRef = &serviceAccountRef
			terminal.Spec.Target.Credentials.ServiceAccountRef = &serviceAccountRef
		})

		It("should use projected service account token", func() {
			Expect(terminalCreationError).Should(Not(HaveOccurred()))
			By("Expecting no token secret to be created")
			Consistently(func() bool {
				secret := &corev1.Secret{}
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TokenSecretResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, secret)
				return kErros.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())

			var pod *corev1.Pod
			Eventually(func() bool {
				pod = &corev1.Pod{}
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalPodResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, pod)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("Expecting pod to use projected service account token")
			Expect(pod.Spec.ServiceAccountName).To(Equal(dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier))

			var tokenVolume *corev1.Volume
			for _, volume := range pod.Spec.Volumes {
				if volume.Name == "token" {
					tokenVolume = &volume
					break
				}
			}

			Expect(tokenVolume).NotTo(BeNil())
			Expect(tokenVolume.Projected).NotTo(BeNil())
			Expect(tokenVolume.Projected.Sources).To(HaveLen(1))
			Expect(tokenVolume.Projected.Sources[0].ServiceAccountToken).NotTo(BeNil())
			Expect(tokenVolume.Projected.Sources[0].ServiceAccountToken.Path).To(Equal("token"))
			Expect(tokenVolume.Projected.Sources[0].ServiceAccountToken.ExpirationSeconds).To(Equal(ptr.To(int64(3600))))
		})
	})

	Context("when using token secret on the pod", func() {
		BeforeEach(func() {
			// Ensure namespaces are different to simulate token secret usage scenario
			hostNamespace = "test-host-serviceaccount-namespace-" + suffix
			targetNamespace = "test-target-serviceaccount-namespace-" + suffix
			terminal.Spec.Host.Namespace = &hostNamespace
			terminal.Spec.Target.Namespace = &targetNamespace
		})

		It("should create a token secret for the pod", func() {
			Expect(terminalCreationError).Should(Not(HaveOccurred()))

			By("Expecting token secret to be created")
			Eventually(func() bool {
				secret := &corev1.Secret{}
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TokenSecretResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, secret)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			var pod *corev1.Pod
			Eventually(func() bool {
				pod = &corev1.Pod{}
				err := e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalPodResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, pod)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("Expecting pod to use token secret")
			var tokenVolume *corev1.Volume
			for _, volume := range pod.Spec.Volumes {
				if volume.Name == "token" {
					tokenVolume = &volume
					break
				}
			}

			Expect(tokenVolume).NotTo(BeNil())
			Expect(tokenVolume.Secret).NotTo(BeNil())
			Expect(tokenVolume.Secret.SecretName).To(Equal(dashboardv1alpha1.TokenSecretResourceNamePrefix + terminal.Spec.Identifier))
		})
	})

	Context("Terminal pod tolerations", func() {
		var (
			tolerations        []corev1.Toleration
			tolerationWithKey1 = corev1.Toleration{
				Key:      "key1",
				Effect:   corev1.TaintEffectNoSchedule,
				Operator: corev1.TolerationOpExists,
			}
			tolerationWithKey2 = corev1.Toleration{
				Key:      "key2",
				Operator: corev1.TolerationOpExists,
			}
			existingToleration = corev1.Toleration{
				Effect:   corev1.TaintEffectNoExecute,
				Operator: corev1.TolerationOpExists,
			}
			nonExistingToleration = corev1.Toleration{
				Effect:   corev1.TaintEffectNoSchedule,
				Operator: corev1.TolerationOpExists,
			}
		)

		BeforeEach(func() {
			tolerations = []corev1.Toleration{tolerationWithKey1, tolerationWithKey2, existingToleration}
		})

		It("Should correctly determine that toleration exists or not by comparing their keys", func() {
			Expect(tolerationExists(tolerations, matchByKey(tolerationWithKey1.Key))).To(BeTrue())
			Expect(tolerationExists(tolerations, matchByKey(tolerationWithKey2.Key))).To(BeTrue())

			Expect(tolerationExists(tolerations, matchByKey("key3"))).To(BeFalse())
		})

		It("Should correctly determine that toleration exists or not by comparing the entire toleration struct", func() {
			Expect(tolerationExists(tolerations, match(existingToleration))).To(BeTrue())

			Expect(tolerationExists(tolerations, match(nonExistingToleration))).To(BeFalse())
		})
	})

	Context("Terminal deletion when referenced resources are missing", func() {
		Context("when host cluster credentials are missing", func() {
			It("Should delete terminal and clean up target resources", func() {
				Expect(terminalCreationError).Should(Not(HaveOccurred()))

				By("Waiting for terminal to be ready")
				Eventually(func() bool {
					t := &dashboardv1alpha1.Terminal{}
					err := e.K8sClient.Get(ctx, terminalKey, t)
					if err != nil {
						return false
					}
					return t.Status.AttachServiceAccountName != nil &&
						t.Status.PodName != nil &&
						*t.Status.AttachServiceAccountName == dashboardv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier &&
						*t.Status.PodName == dashboardv1alpha1.TerminalPodResourceNamePrefix+t.Spec.Identifier
				}, timeout, interval).Should(BeTrue())

				By("Deleting host service account to simulate missing credentials")
				err := e.K8sClient.Delete(ctx, &corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      HostServiceAccountName,
						Namespace: hostNamespace,
					},
				})
				Expect(err).To(Not(HaveOccurred()))

				By("Triggering reconcile")
				err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
					if err := e.K8sClient.Get(ctx, terminalKey, terminal); err != nil {
						return err
					}
					if terminal.Annotations == nil {
						terminal.Annotations = map[string]string{}
					}
					terminal.Annotations["test-trigger"] = time.Now().String()
					return e.K8sClient.Update(ctx, terminal)
				})
				Expect(err).To(Not(HaveOccurred()))

				By("Expecting terminal to have deletion timestamp set")
				Eventually(func(g Gomega) *metav1.Time {
					t := &dashboardv1alpha1.Terminal{}
					err := e.K8sClient.Get(ctx, terminalKey, t)
					if kErros.IsNotFound(err) {
						return &metav1.Time{Time: time.Now()} // Treat as deleted (non-nil)
					}
					g.Expect(err).To(Not(HaveOccurred()))
					return t.DeletionTimestamp
				}, timeout, interval).Should(Not(BeNil()))

				By("Expecting terminal to be deleted")
				Eventually(func() error {
					t := &dashboardv1alpha1.Terminal{}
					return e.K8sClient.Get(ctx, terminalKey, t)
				}, timeout, interval).Should(Satisfy(kErros.IsNotFound))

				By("Expecting target access service account to be removed")
				Eventually(func() error {
					sa := &corev1.ServiceAccount{}
					return e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier, Namespace: targetNamespace}, sa)
				}, timeout, interval).Should(Satisfy(kErros.IsNotFound))

				By("Expecting host pod to remain (skipped cleanup)")
				Consistently(func() error {
					pod := &corev1.Pod{}
					return e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalPodResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, pod)
				}, timeout/2, interval).Should(Not(Satisfy(kErros.IsNotFound)))
			})
		})

		Context("when target cluster credentials are missing", func() {
			It("Should delete terminal and clean up host resources", func() {
				Expect(terminalCreationError).Should(Not(HaveOccurred()))

				By("Waiting for terminal to be ready")
				Eventually(func() bool {
					t := &dashboardv1alpha1.Terminal{}
					err := e.K8sClient.Get(ctx, terminalKey, t)
					if err != nil {
						return false
					}
					return t.Status.AttachServiceAccountName != nil &&
						t.Status.PodName != nil &&
						*t.Status.AttachServiceAccountName == dashboardv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier &&
						*t.Status.PodName == dashboardv1alpha1.TerminalPodResourceNamePrefix+t.Spec.Identifier
				}, timeout, interval).Should(BeTrue())

				By("Deleting target service account to simulate missing credentials")
				err := e.K8sClient.Delete(ctx, &corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      TargetServiceAccountName,
						Namespace: targetNamespace,
					},
				})
				Expect(err).To(Not(HaveOccurred()))

				By("Triggering reconcile")
				err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
					if err := e.K8sClient.Get(ctx, terminalKey, terminal); err != nil {
						return err
					}
					if terminal.Annotations == nil {
						terminal.Annotations = map[string]string{}
					}
					terminal.Annotations["test-trigger"] = time.Now().String()
					return e.K8sClient.Update(ctx, terminal)
				})
				Expect(err).To(Not(HaveOccurred()))

				By("Expecting terminal to have deletion timestamp set")
				Eventually(func(g Gomega) *metav1.Time {
					t := &dashboardv1alpha1.Terminal{}
					err := e.K8sClient.Get(ctx, terminalKey, t)
					if kErros.IsNotFound(err) {
						return &metav1.Time{Time: time.Now()} // Treat as deleted (non-nil)
					}
					g.Expect(err).To(Not(HaveOccurred()))
					return t.DeletionTimestamp
				}, timeout, interval).Should(Not(BeNil()))

				By("Expecting terminal to be deleted")
				Eventually(func() error {
					t := &dashboardv1alpha1.Terminal{}
					return e.K8sClient.Get(ctx, terminalKey, t)
				}, timeout, interval).Should(Satisfy(kErros.IsNotFound))

				By("Expecting host pod to be removed")
				Eventually(func() error {
					pod := &corev1.Pod{}
					return e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalPodResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, pod)
				}, timeout, interval).Should(Satisfy(kErros.IsNotFound))

				By("Expecting target access service account to remain (skipped cleanup)")
				Consistently(func() error {
					sa := &corev1.ServiceAccount{}
					return e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier, Namespace: targetNamespace}, sa)
				}, timeout/2, interval).Should(Not(Satisfy(kErros.IsNotFound)))
			})
		})

		Context("when namespace is being terminated for host", func() {
			It("Should delete terminal when host namespace is terminating", func() {
				Expect(terminalCreationError).Should(Not(HaveOccurred()))

				By("Waiting for terminal to be ready")
				Eventually(func() bool {
					t := &dashboardv1alpha1.Terminal{}
					err := e.K8sClient.Get(ctx, terminalKey, t)
					if err != nil {
						return false
					}
					return t.Status.AttachServiceAccountName != nil &&
						t.Status.PodName != nil &&
						*t.Status.AttachServiceAccountName == dashboardv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier &&
						*t.Status.PodName == dashboardv1alpha1.TerminalPodResourceNamePrefix+t.Spec.Identifier
				}, timeout, interval).Should(BeTrue())

				By("Deleting host namespace")
				ns := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: hostNamespace,
					},
				}
				err := e.K8sClient.Delete(ctx, ns)
				Expect(err).To(Not(HaveOccurred()))

				By("Triggering reconcile")
				err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
					if err := e.K8sClient.Get(ctx, terminalKey, terminal); err != nil {
						return err
					}
					if terminal.Annotations == nil {
						terminal.Annotations = map[string]string{}
					}
					terminal.Annotations["test-trigger"] = time.Now().String()
					return e.K8sClient.Update(ctx, terminal)
				})
				Expect(err).To(Not(HaveOccurred()))

				By("Expecting terminal to have deletion timestamp set")
				Eventually(func(g Gomega) *metav1.Time {
					t := &dashboardv1alpha1.Terminal{}
					err := e.K8sClient.Get(ctx, terminalKey, t)
					if kErros.IsNotFound(err) {
						return &metav1.Time{Time: time.Now()} // Treat as deleted (non-nil)
					}
					g.Expect(err).To(Not(HaveOccurred()))
					return t.DeletionTimestamp
				}, timeout, interval).Should(Not(BeNil()))

				By("Expecting terminal to be deleted")
				Eventually(func() error {
					t := &dashboardv1alpha1.Terminal{}
					return e.K8sClient.Get(ctx, terminalKey, t)
				}, timeout, interval).Should(Satisfy(kErros.IsNotFound))

				By("Expecting target access service account to be removed")
				Eventually(func() error {
					sa := &corev1.ServiceAccount{}
					return e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier, Namespace: targetNamespace}, sa)
				}, timeout, interval).Should(Satisfy(kErros.IsNotFound))

				By("Expecting host pod to remain (skipped cleanup)")
				Consistently(func() error {
					pod := &corev1.Pod{}
					return e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalPodResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, pod)
				}, timeout/2, interval).Should(Not(Satisfy(kErros.IsNotFound)))
			})
		})

		Context("when namespace is being terminated for target", func() {
			It("Should delete terminal when target namespace is terminating", func() {
				Expect(terminalCreationError).Should(Not(HaveOccurred()))

				By("Waiting for terminal to be ready")
				Eventually(func() bool {
					t := &dashboardv1alpha1.Terminal{}
					err := e.K8sClient.Get(ctx, terminalKey, t)
					if err != nil {
						return false
					}
					return t.Status.AttachServiceAccountName != nil &&
						t.Status.PodName != nil &&
						*t.Status.AttachServiceAccountName == dashboardv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier &&
						*t.Status.PodName == dashboardv1alpha1.TerminalPodResourceNamePrefix+t.Spec.Identifier
				}, timeout, interval).Should(BeTrue())

				By("Deleting target namespace")
				ns := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: targetNamespace,
					},
				}
				err := e.K8sClient.Delete(ctx, ns)
				Expect(err).To(Not(HaveOccurred()))

				By("Triggering reconcile")
				err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
					if err := e.K8sClient.Get(ctx, terminalKey, terminal); err != nil {
						return err
					}
					if terminal.Annotations == nil {
						terminal.Annotations = map[string]string{}
					}
					terminal.Annotations["test-trigger"] = time.Now().String()
					return e.K8sClient.Update(ctx, terminal)
				})
				Expect(err).To(Not(HaveOccurred()))

				By("Expecting terminal to have deletion timestamp set")
				Eventually(func(g Gomega) *metav1.Time {
					t := &dashboardv1alpha1.Terminal{}
					err := e.K8sClient.Get(ctx, terminalKey, t)
					if kErros.IsNotFound(err) {
						return &metav1.Time{Time: time.Now()} // Treat as deleted (non-nil)
					}
					g.Expect(err).To(Not(HaveOccurred()))
					return t.DeletionTimestamp
				}, timeout, interval).Should(Not(BeNil()))

				By("Expecting terminal to be deleted")
				Eventually(func() error {
					t := &dashboardv1alpha1.Terminal{}
					return e.K8sClient.Get(ctx, terminalKey, t)
				}, timeout, interval).Should(Satisfy(kErros.IsNotFound))

				By("Expecting host pod to be removed")
				Eventually(func() error {
					pod := &corev1.Pod{}
					return e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalPodResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, pod)
				}, timeout, interval).Should(Satisfy(kErros.IsNotFound))

				By("Expecting target access service account to remain (skipped cleanup)")
				Consistently(func() error {
					sa := &corev1.ServiceAccount{}
					return e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier, Namespace: targetNamespace}, sa)
				}, timeout/2, interval).Should(Not(Satisfy(kErros.IsNotFound)))
			})
		})
	})

	Context("Terminal deletion when referenced resources are missing", func() {
		Context("using serviceAccountRef", func() {
			Context("when host cluster credentials are missing", func() {
				It("Should delete terminal when host service account does not exist", func() {
					Expect(terminalCreationError).Should(Not(HaveOccurred()))

					By("Waiting for terminal to be ready")
					Eventually(func() bool {
						t := &dashboardv1alpha1.Terminal{}
						err := e.K8sClient.Get(ctx, terminalKey, t)
						if err != nil {
							return false
						}
						return t.Status.AttachServiceAccountName != nil &&
							t.Status.PodName != nil &&
							*t.Status.AttachServiceAccountName == dashboardv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier &&
							*t.Status.PodName == dashboardv1alpha1.TerminalPodResourceNamePrefix+t.Spec.Identifier
					}, timeout, interval).Should(BeTrue())

					By("Deleting host service account to simulate missing credentials")
					err := e.K8sClient.Delete(ctx, &corev1.ServiceAccount{
						ObjectMeta: metav1.ObjectMeta{
							Name:      HostServiceAccountName,
							Namespace: hostNamespace,
						},
					})
					Expect(err).To(Not(HaveOccurred()))

					By("Triggering reconcile")
					err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
						if err := e.K8sClient.Get(ctx, terminalKey, terminal); err != nil {
							return err
						}
						if terminal.Annotations == nil {
							terminal.Annotations = map[string]string{}
						}
						terminal.Annotations["test-trigger"] = time.Now().String()
						return e.K8sClient.Update(ctx, terminal)
					})
					Expect(err).To(Not(HaveOccurred()))

					By("Expecting event for missing host credentials")
					Eventually(func(g Gomega) {
						events := &corev1.EventList{}
						err := e.K8sClient.List(ctx, events, client.InNamespace(terminalNamespace), client.MatchingFields{"involvedObject.name": terminalName, "involvedObject.kind": "Terminal"})
						g.Expect(err).To(Not(HaveOccurred()))
						found := false
						for _, event := range events.Items {
							if event.Type == corev1.EventTypeWarning && event.Reason == dashboardv1alpha1.EventReconcileError &&
								strings.Contains(event.Message, "Host cluster credentials no longer available") &&
								strings.Contains(event.Message, "due to NotFound") {
								found = true
								break
							}
						}
						g.Expect(found).To(BeTrue())
					}, timeout, interval).Should(Succeed())

					By("Expecting terminal to have deletion timestamp set")
					Eventually(func(g Gomega) *metav1.Time {
						t := &dashboardv1alpha1.Terminal{}
						err := e.K8sClient.Get(ctx, terminalKey, t)
						if kErros.IsNotFound(err) {
							return &metav1.Time{Time: time.Now()} // Treat as deleted (non-nil)
						}
						g.Expect(err).To(Not(HaveOccurred()))
						return t.DeletionTimestamp
					}, timeout, interval).Should(Not(BeNil()))

					By("Expecting terminal to be deleted")
					Eventually(func() error {
						t := &dashboardv1alpha1.Terminal{}
						return e.K8sClient.Get(ctx, terminalKey, t)
					}, timeout, interval).Should(Satisfy(kErros.IsNotFound))

					By("Expecting target access service account to be removed")
					Eventually(func() error {
						sa := &corev1.ServiceAccount{}
						return e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier, Namespace: targetNamespace}, sa)
					}, timeout, interval).Should(Satisfy(kErros.IsNotFound))

					By("Expecting host pod to remain (skipped cleanup)")
					Consistently(func() error {
						pod := &corev1.Pod{}
						return e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalPodResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, pod)
					}, timeout/2, interval).Should(Not(Satisfy(kErros.IsNotFound)))
				})
			})

			Context("when host cluster namespace is terminating", func() {
				It("Should delete terminal when host namespace is terminating", func() {
					Expect(terminalCreationError).Should(Not(HaveOccurred()))

					By("Waiting for terminal to be ready")
					Eventually(func() bool {
						t := &dashboardv1alpha1.Terminal{}
						err := e.K8sClient.Get(ctx, terminalKey, t)
						if err != nil {
							return false
						}
						return t.Status.AttachServiceAccountName != nil &&
							t.Status.PodName != nil &&
							*t.Status.AttachServiceAccountName == dashboardv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier &&
							*t.Status.PodName == dashboardv1alpha1.TerminalPodResourceNamePrefix+t.Spec.Identifier
					}, timeout, interval).Should(BeTrue())

					By("Deleting host namespace to simulate termination")
					err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
						ns := &corev1.Namespace{}
						err := e.K8sClient.Get(ctx, types.NamespacedName{Name: hostNamespace}, ns)
						if err != nil {
							return err
						}
						return e.K8sClient.Delete(ctx, ns)
					})
					Expect(err).To(Not(HaveOccurred()))

					By("Triggering reconcile")
					err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
						if err := e.K8sClient.Get(ctx, terminalKey, terminal); err != nil {
							return err
						}
						if terminal.Annotations == nil {
							terminal.Annotations = map[string]string{}
						}
						terminal.Annotations["test-trigger"] = time.Now().String()
						return e.K8sClient.Update(ctx, terminal)
					})
					Expect(err).To(Not(HaveOccurred()))

					By("Expecting event for missing host credentials due to terminating namespace")
					Eventually(func(g Gomega) {
						events := &corev1.EventList{}
						err := e.K8sClient.List(ctx, events, client.InNamespace(terminalNamespace), client.MatchingFields{"involvedObject.name": terminalName, "involvedObject.kind": "Terminal"})
						g.Expect(err).To(Not(HaveOccurred()))
						found := false
						for _, event := range events.Items {
							if event.Type == corev1.EventTypeWarning && event.Reason == dashboardv1alpha1.EventReconcileError &&
								strings.Contains(event.Message, "Host cluster credentials no longer available") &&
								strings.Contains(event.Message, "due to NamespaceTerminating") {
								found = true
								break
							}
						}
						g.Expect(found).To(BeTrue())
					}, timeout, interval).Should(Succeed())

					By("Expecting terminal to have deletion timestamp set")
					Eventually(func(g Gomega) *metav1.Time {
						t := &dashboardv1alpha1.Terminal{}
						err := e.K8sClient.Get(ctx, terminalKey, t)
						if kErros.IsNotFound(err) {
							return &metav1.Time{Time: time.Now()} // Treat as deleted (non-nil)
						}
						g.Expect(err).To(Not(HaveOccurred()))
						return t.DeletionTimestamp
					}, timeout, interval).Should(Not(BeNil()))

					By("Expecting terminal to be deleted")
					Eventually(func() error {
						t := &dashboardv1alpha1.Terminal{}
						return e.K8sClient.Get(ctx, terminalKey, t)
					}, timeout, interval).Should(Satisfy(kErros.IsNotFound))

					By("Expecting target access service account to be removed")
					Eventually(func() error {
						sa := &corev1.ServiceAccount{}
						return e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier, Namespace: targetNamespace}, sa)
					}, timeout, interval).Should(Satisfy(kErros.IsNotFound))

					By("Expecting host pod to remain (skipped cleanup)")
					Consistently(func() error {
						pod := &corev1.Pod{}
						return e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalPodResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, pod)
					}, timeout/2, interval).Should(Not(Satisfy(kErros.IsNotFound)))
				})
			})

			Context("when target cluster credentials are missing", func() {
				It("Should delete terminal when target service account does not exist", func() {
					Expect(terminalCreationError).Should(Not(HaveOccurred()))

					By("Waiting for terminal to be ready")
					Eventually(func() bool {
						t := &dashboardv1alpha1.Terminal{}
						err := e.K8sClient.Get(ctx, terminalKey, t)
						if err != nil {
							return false
						}
						return t.Status.AttachServiceAccountName != nil &&
							t.Status.PodName != nil &&
							*t.Status.AttachServiceAccountName == dashboardv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier &&
							*t.Status.PodName == dashboardv1alpha1.TerminalPodResourceNamePrefix+t.Spec.Identifier
					}, timeout, interval).Should(BeTrue())

					By("Deleting target service account to simulate missing credentials")
					err := e.K8sClient.Delete(ctx, &corev1.ServiceAccount{
						ObjectMeta: metav1.ObjectMeta{
							Name:      TargetServiceAccountName,
							Namespace: targetNamespace,
						},
					})
					Expect(err).To(Not(HaveOccurred()))

					By("Triggering reconcile")
					err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
						if err := e.K8sClient.Get(ctx, terminalKey, terminal); err != nil {
							return err
						}
						if terminal.Annotations == nil {
							terminal.Annotations = map[string]string{}
						}
						terminal.Annotations["test-trigger"] = time.Now().String()
						return e.K8sClient.Update(ctx, terminal)
					})
					Expect(err).To(Not(HaveOccurred()))

					By("Expecting event for missing target credentials")
					Eventually(func(g Gomega) {
						events := &corev1.EventList{}
						err := e.K8sClient.List(ctx, events, client.InNamespace(terminalNamespace), client.MatchingFields{"involvedObject.name": terminalName, "involvedObject.kind": "Terminal"})
						g.Expect(err).To(Not(HaveOccurred()))
						found := false
						for _, event := range events.Items {
							if event.Type == corev1.EventTypeWarning && event.Reason == dashboardv1alpha1.EventReconcileError &&
								strings.Contains(event.Message, "Target cluster credentials no longer available") &&
								strings.Contains(event.Message, "due to NotFound") {
								found = true
								break
							}
						}
						g.Expect(found).To(BeTrue())
					}, timeout, interval).Should(Succeed())

					By("Expecting terminal to have deletion timestamp set")
					Eventually(func(g Gomega) *metav1.Time {
						t := &dashboardv1alpha1.Terminal{}
						err := e.K8sClient.Get(ctx, terminalKey, t)
						if kErros.IsNotFound(err) {
							return &metav1.Time{Time: time.Now()} // Treat as deleted (non-nil)
						}
						g.Expect(err).To(Not(HaveOccurred()))
						return t.DeletionTimestamp
					}, timeout, interval).Should(Not(BeNil()))

					By("Expecting terminal to be deleted")
					Eventually(func() error {
						t := &dashboardv1alpha1.Terminal{}
						return e.K8sClient.Get(ctx, terminalKey, t)
					}, timeout, interval).Should(Satisfy(kErros.IsNotFound))

					By("Expecting host pod to be removed")
					Eventually(func() error {
						pod := &corev1.Pod{}
						return e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalPodResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, pod)
					}, timeout, interval).Should(Satisfy(kErros.IsNotFound))

					By("Expecting target access service account to remain (skipped cleanup)")
					Consistently(func() error {
						sa := &corev1.ServiceAccount{}
						return e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier, Namespace: targetNamespace}, sa)
					}, timeout/2, interval).Should(Not(Satisfy(kErros.IsNotFound)))
				})
			})

			Context("when target cluster namespace is terminating", func() {
				It("Should delete terminal when target namespace is terminating", func() {
					Expect(terminalCreationError).Should(Not(HaveOccurred()))

					By("Waiting for terminal to be ready")
					Eventually(func() bool {
						t := &dashboardv1alpha1.Terminal{}
						err := e.K8sClient.Get(ctx, terminalKey, t)
						if err != nil {
							return false
						}
						return t.Status.AttachServiceAccountName != nil &&
							t.Status.PodName != nil &&
							*t.Status.AttachServiceAccountName == dashboardv1alpha1.TerminalAttachResourceNamePrefix+t.Spec.Identifier &&
							*t.Status.PodName == dashboardv1alpha1.TerminalPodResourceNamePrefix+t.Spec.Identifier
					}, timeout, interval).Should(BeTrue())

					By("Deleting target namespace to simulate termination")
					err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
						ns := &corev1.Namespace{}
						err := e.K8sClient.Get(ctx, types.NamespacedName{Name: targetNamespace}, ns)
						if err != nil {
							return err
						}
						return e.K8sClient.Delete(ctx, ns)
					})
					Expect(err).To(Not(HaveOccurred()))

					By("Triggering reconcile")
					err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
						if err := e.K8sClient.Get(ctx, terminalKey, terminal); err != nil {
							return err
						}
						if terminal.Annotations == nil {
							terminal.Annotations = map[string]string{}
						}
						terminal.Annotations["test-trigger"] = time.Now().String()
						return e.K8sClient.Update(ctx, terminal)
					})
					Expect(err).To(Not(HaveOccurred()))

					By("Expecting event for missing target credentials due to terminating namespace")
					Eventually(func(g Gomega) {
						events := &corev1.EventList{}
						err := e.K8sClient.List(ctx, events, client.InNamespace(terminalNamespace), client.MatchingFields{"involvedObject.name": terminalName, "involvedObject.kind": "Terminal"})
						g.Expect(err).To(Not(HaveOccurred()))
						found := false
						for _, event := range events.Items {
							if event.Type == corev1.EventTypeWarning && event.Reason == dashboardv1alpha1.EventReconcileError &&
								strings.Contains(event.Message, "Target cluster credentials no longer available") &&
								strings.Contains(event.Message, "due to NamespaceTerminating") {
								found = true
								break
							}
						}
						g.Expect(found).To(BeTrue())
					}, timeout, interval).Should(Succeed())

					By("Expecting terminal to have deletion timestamp set")
					Eventually(func(g Gomega) *metav1.Time {
						t := &dashboardv1alpha1.Terminal{}
						err := e.K8sClient.Get(ctx, terminalKey, t)
						if kErros.IsNotFound(err) {
							return &metav1.Time{Time: time.Now()} // Treat as deleted (non-nil)
						}
						g.Expect(err).To(Not(HaveOccurred()))
						return t.DeletionTimestamp
					}, timeout, interval).Should(Not(BeNil()))

					By("Expecting terminal to be deleted")
					Eventually(func() error {
						t := &dashboardv1alpha1.Terminal{}
						return e.K8sClient.Get(ctx, terminalKey, t)
					}, timeout, interval).Should(Satisfy(kErros.IsNotFound))

					By("Expecting host pod to be removed")
					Eventually(func() error {
						pod := &corev1.Pod{}
						return e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalPodResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, pod)
					}, timeout, interval).Should(Satisfy(kErros.IsNotFound))

					By("Expecting target access service account to remain (skipped cleanup)")
					Consistently(func() error {
						sa := &corev1.ServiceAccount{}
						return e.K8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier, Namespace: targetNamespace}, sa)
					}, timeout/2, interval).Should(Not(Satisfy(kErros.IsNotFound)))
				})
			})
		})
	})
})
