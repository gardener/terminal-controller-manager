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

	kErros "k8s.io/apimachinery/pkg/api/errors"

	"github.com/gardener/terminal-controller-manager/test"
	rbacv1 "k8s.io/api/rbac/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/gardener/terminal-controller-manager/api/v1alpha1"
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
		Context("expired lifetime", func() {
			BeforeEach(func() {
				cmConfig.Controllers.TerminalHeartbeat.TimeToLive = v1alpha1.Duration{Duration: time.Duration(1) * time.Second}
			})
			It("Should delete terminal", func() {
				Expect(terminalCreationError).Should(Not(HaveOccurred()))

				Eventually(func() bool {
					t := &dashboardv1alpha1.Terminal{}
					err := k8sClient.Get(ctx, terminalKey, t)
					if kErros.IsNotFound(err) {
						return true
					}
					return t.DeletionTimestamp != nil
				}, timeout, interval).Should(BeTrue())
			})
		})

		Context("cleared heartbeat", func() {
			It("Should delete terminal", func() {
				Expect(terminalCreationError).To(Not(HaveOccurred()))

				By("Expecting terminal to be created")
				Eventually(func() bool {
					terminal = &dashboardv1alpha1.Terminal{}
					err := k8sClient.Get(ctx, terminalKey, terminal)
					return err == nil
				}, timeout, interval).Should(BeTrue())

				By("clearing the last heartbeat time")
				terminal.ObjectMeta.Annotations[dashboardv1alpha1.TerminalLastHeartbeat] = ""
				error := k8sClient.Update(ctx, terminal)
				Expect(error).To(Not(HaveOccurred()))

				Eventually(func() bool {
					t := &dashboardv1alpha1.Terminal{}
					err := k8sClient.Get(ctx, terminalKey, t)
					if kErros.IsNotFound(err) {
						return true
					}
					return t.DeletionTimestamp != nil
				}, timeout, interval).Should(BeTrue())
			})
		})
	})
})
