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

package controllers

import (
	"fmt"
	"time"

	"github.com/gardener/terminal-controller-manager/test"
	rbacv1 "k8s.io/api/rbac/v1"
	kErros "k8s.io/apimachinery/pkg/api/errors"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	dashboardv1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
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

		terminalReconciler.Config = cmConfig
		terminalHeartbeatReconciler.Config = cmConfig

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

	JustBeforeEach(func() {
		terminalCreationError = k8sClient.Create(ctx, terminal)
	})

	Context("terminal lifecycle", func() {
		Context("temporary namespace", func() {
			Context("cleanup", func() {
				Context("host namespace", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Namespace = nil
						terminal.Spec.Host.TemporaryNamespace = true

						terminal.Spec.Target.Namespace = nil
						terminal.Spec.Target.TemporaryNamespace = true
					})
					It("Should delete temporary host and target host namespace", func() {
						Expect(terminalCreationError).Should(Not(HaveOccurred()))

						By("Expecting target namespace to be set")
						Eventually(func() bool {
							terminal = &dashboardv1alpha1.Terminal{}
							err := k8sClient.Get(ctx, terminalKey, terminal)
							if err != nil {
								return false
							}
							targetNamespace = *terminal.Spec.Target.Namespace
							return targetNamespace != ""
						}, timeout, interval).Should(BeTrue())

						By("Waiting for AccessServiceAccount to be created")
						accessServiceAccount := &v1.ServiceAccount{}
						Eventually(func() bool {
							targetNamespace := *terminal.Spec.Target.Namespace
							err := k8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier, Namespace: targetNamespace}, accessServiceAccount)
							return err == nil
						}, timeout, interval).Should(BeTrue())

						By("By creating a dummy token as no kube-controller is running for AccessServiceAccount to be created")
						test.CreateServiceAccountSecret(ctx, k8sClient, accessServiceAccount, timeout, interval)

						By("Waiting for terminal to be ready")
						Eventually(func() bool {
							terminal = &dashboardv1alpha1.Terminal{}
							err := k8sClient.Get(ctx, terminalKey, terminal)
							if err != nil {
								return false
							}
							return terminal.Status.AttachServiceAccountName == dashboardv1alpha1.TerminalAttachResourceNamePrefix+terminal.Spec.Identifier &&
								terminal.Status.PodName == dashboardv1alpha1.TerminalPodResourceNamePrefix+terminal.Spec.Identifier
						}, timeout, interval).Should(BeTrue())

						temporaryHostNamespace := *terminal.Spec.Host.Namespace
						temporaryTargetNamespace := *terminal.Spec.Target.Namespace

						By("Deleting the terminal")
						err := k8sClient.Delete(ctx, terminal)
						Expect(err).To(Not(HaveOccurred()))

						Eventually(func() bool {
							t := &dashboardv1alpha1.Terminal{}
							err := k8sClient.Get(ctx, terminalKey, t)
							return kErros.IsNotFound(err)
						}, timeout, interval).Should(BeTrue())

						By("expecting host namespace to be in deletion")
						namespace := &v1.Namespace{}
						err = k8sClient.Get(ctx, types.NamespacedName{Name: temporaryHostNamespace}, namespace)
						Expect(err).To(Not(HaveOccurred())) // with envtest no kube-controller is running that is finally deleting the namespace
						Expect(namespace.DeletionTimestamp).To(Not(BeNil()))

						By("expecting target namespace to be deleted")
						namespace = &v1.Namespace{}
						err = k8sClient.Get(ctx, types.NamespacedName{Name: temporaryTargetNamespace}, namespace)
						Expect(err).To(Not(HaveOccurred()))                  // with envtest no kube-controller is running that is finally deleting the namespace
						Expect(namespace.DeletionTimestamp).To(Not(BeNil())) // with envtest no kube-controller is running that is finally deleting the namespace
					})
				})
			})
			Context("creation", func() {
				Context("host and target namespace", func() {
					BeforeEach(func() {
						terminal.Spec.Host.Namespace = nil
						terminal.Spec.Host.TemporaryNamespace = true

						terminal.Spec.Target.Namespace = nil
						terminal.Spec.Target.TemporaryNamespace = true
					})
					It("Should create temporary host and target namespace", func() {
						Expect(terminalCreationError).Should(Not(HaveOccurred()))

						By("Expecting target namespace to be set")
						Eventually(func() bool {
							terminal = &dashboardv1alpha1.Terminal{}
							err := k8sClient.Get(ctx, terminalKey, terminal)
							if err != nil {
								return false
							}
							targetNamespace = *terminal.Spec.Target.Namespace
							return targetNamespace != ""
						}, timeout, interval).Should(BeTrue())

						By("Waiting for AccessServiceAccount to be created")
						accessServiceAccount := &v1.ServiceAccount{}
						Eventually(func() bool {
							err := k8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier, Namespace: targetNamespace}, accessServiceAccount)
							return err == nil
						}, timeout, interval).Should(BeTrue())

						By("By creating a dummy token as no kube-controller is running for AccessServiceAccount to be created")
						test.CreateServiceAccountSecret(ctx, k8sClient, accessServiceAccount, timeout, interval)

						By("Waiting for terminal to be ready")
						Eventually(func() bool {
							t := &dashboardv1alpha1.Terminal{}
							err := k8sClient.Get(ctx, terminalKey, t)
							if err != nil {
								return false
							}
							return t.Status.AttachServiceAccountName == dashboardv1alpha1.TerminalAttachResourceNamePrefix+terminal.Spec.Identifier &&
								t.Status.PodName == dashboardv1alpha1.TerminalPodResourceNamePrefix+terminal.Spec.Identifier
						}, timeout, interval).Should(BeTrue())

						By("Expecting target namespace to be created")
						Expect(*terminal.Spec.Target.Namespace).To(Not(BeEmpty()))
						Eventually(func() bool {
							err := k8sClient.Get(ctx, types.NamespacedName{Name: *terminal.Spec.Target.Namespace}, &v1.Namespace{})
							return err == nil
						}).Should(BeTrue())

						By("Expecting host namespace to be created")
						Expect(*terminal.Spec.Host.Namespace).To(Not(BeEmpty()))
						Eventually(func() bool {
							err := k8sClient.Get(ctx, types.NamespacedName{Name: *terminal.Spec.Host.Namespace}, &v1.Namespace{})
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
				err := k8sClient.Get(ctx, terminalKey, &dashboardv1alpha1.Terminal{})
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("Waiting for AccessServiceAccount to be created")
			accessServiceAccount := &v1.ServiceAccount{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier, Namespace: targetNamespace}, accessServiceAccount)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("By creating a dummy token as no kube-controller is running for AccessServiceAccount to be created")
			test.CreateServiceAccountSecret(ctx, k8sClient, accessServiceAccount, timeout, interval)

			By("Waiting for terminal to be ready")
			Eventually(func() bool {
				t := &dashboardv1alpha1.Terminal{}
				err := k8sClient.Get(ctx, terminalKey, t)
				if err != nil {
					return false
				}
				return t.Status.AttachServiceAccountName == dashboardv1alpha1.TerminalAttachResourceNamePrefix+terminal.Spec.Identifier &&
					t.Status.PodName == dashboardv1alpha1.TerminalPodResourceNamePrefix+terminal.Spec.Identifier
			}, timeout, interval).Should(BeTrue())

			By("Deleting the terminal")
			Eventually(func() bool {
				err := k8sClient.Delete(ctx, terminal)
				return kErros.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())

			By("Expecting AttachServiceAccount to be removed")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAttachResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, &v1.ServiceAccount{})
				return kErros.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())

			By("Expecting attach role to be removed")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAttachRoleResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, &rbacv1.Role{})
				return kErros.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())

			By("Expecting AccessServiceAccount to be removed")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier, Namespace: targetNamespace}, &v1.ServiceAccount{})
				return kErros.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())

			By("Expecting kubeconfig to be removed")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.KubeconfigSecretResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, &v1.Secret{})
				return kErros.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())

			By("Expecting terminal pod to be removed")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalPodResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, &v1.Pod{})
				return kErros.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())

			By("Expecting terminal resource to be removed")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: terminalKey.Name, Namespace: terminalKey.Namespace}, &dashboardv1alpha1.Terminal{})
				return kErros.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())

			By("Ensuring that host namespace is not deleted")
			Consistently(func() bool {
				namespace := &v1.Namespace{}
				err := k8sClient.Get(ctx, types.NamespacedName{Name: hostNamespace}, namespace)
				if err != nil {
					return false
				}
				return namespace.DeletionTimestamp == nil
			}).Should(BeTrue())

			By("Ensuring that target namespace is not deleted")
			Consistently(func() bool {
				namespace := &v1.Namespace{}
				err := k8sClient.Get(ctx, types.NamespacedName{Name: targetNamespace}, namespace)
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
				err := k8sClient.Get(ctx, terminalKey, &dashboardv1alpha1.Terminal{})
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("Expecting AttachServiceAccount to be created")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAttachResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, &v1.ServiceAccount{})
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("Expecting AttachServiceAccountName to be set")
			Eventually(func() string {
				t := &dashboardv1alpha1.Terminal{}
				err := k8sClient.Get(ctx, terminalKey, t)
				if err != nil {
					return ""
				}
				return t.Status.AttachServiceAccountName
			}, timeout, interval).Should(Not(BeEmpty()))

			By("Expecting attach role to be created")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAttachRoleResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, &rbacv1.Role{})
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("Expecting AccessServiceAccount to be created")
			accessServiceAccount := &v1.ServiceAccount{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalAccessResourceNamePrefix + terminal.Spec.Identifier, Namespace: targetNamespace}, accessServiceAccount)
				return err == nil
			}, timeout, interval).Should(BeTrue())
			test.CreateServiceAccountSecret(ctx, k8sClient, accessServiceAccount, timeout, interval) // need to create a dummy token as no kube-controller is running

			By("Expecting kubeconfig to be created")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.KubeconfigSecretResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, &v1.Secret{})
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("Expecting terminal pod with foo image to be created")
			Eventually(func() string {
				pod := &v1.Pod{}
				err := k8sClient.Get(ctx, types.NamespacedName{Name: dashboardv1alpha1.TerminalPodResourceNamePrefix + terminal.Spec.Identifier, Namespace: hostNamespace}, pod)
				if err != nil {
					return ""
				}
				return pod.Spec.Containers[0].Image
			}, timeout, interval).Should(Equal("foo"))

			By("Expecting PodName to be set")
			Eventually(func() string {
				t := &dashboardv1alpha1.Terminal{}
				err := k8sClient.Get(ctx, terminalKey, t)
				if err != nil {
					return ""
				}
				//attachServiceAccountName = t.Status.AttachServiceAccountName
				return t.Status.PodName
			}, timeout, interval).Should(Not(BeEmpty()))
		})
	})
})
