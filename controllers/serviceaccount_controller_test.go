/*
SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package controllers

import (
	"time"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/component/projectrbac"
	"github.com/gardener/gardener/pkg/controllerutils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kErros "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	dashboardv1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/internal/gardenclient"
	"github.com/gardener/terminal-controller-manager/test"
)

var _ = Describe("ServiceAccount Controller", func() {
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
		projectName             string
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
		terminalNamespace = "garden-term-" + suffix
		hostNamespace = "test-host-serviceaccount-namespace-" + suffix
		targetNamespace = terminalNamespace // target namespace must be the namespace of the terminal for CleanupProjectMembership
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
					CleanupProjectMembership:   ptr.To(true),
				},
			},
		}

		By("By creating namespaces")
		namespaces := []string{terminalNamespace, hostNamespace}
		for _, namespace := range namespaces {
			terminalNamespaceKey := types.NamespacedName{Name: namespace}
			e.CreateObject(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}, terminalNamespaceKey, timeout, interval)
		}

		By("By creating host serviceaccount")
		e.AddClusterAdminServiceAccount(ctx, HostServiceAccountName, hostNamespace, timeout, interval)
		By("By creating target serviceaccount")
		targetServiceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
			Name:      TargetServiceAccountName,
			Namespace: targetNamespace,
		}}
		Expect(e.K8sClient.Create(ctx, targetServiceAccount)).To(Succeed())

		By("By creating project")
		projectName = test.StringWithCharset(randomLength, charset)

		project := &gardencorev1beta1.Project{
			ObjectMeta: metav1.ObjectMeta{Name: projectName},
			Spec: gardencorev1beta1.ProjectSpec{
				Namespace: &terminalNamespace,
			},
		}
		e.CreateObject(ctx, project, client.ObjectKeyFromObject(project), timeout, interval)

		err := gardenclient.AddServiceAccountAsProjectMember(ctx, e.K8sClient, project, targetServiceAccount, []string{
			gardencorev1beta1.ProjectMemberServiceAccountManager,
		})
		Expect(err).NotTo(HaveOccurred())

		// make sure that there is a project-serviceaccountmanager ClusterRole
		clusterRoleServiceAccountManager := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "gardener.cloud:system:project-serviceaccountmanager"}}
		_, err = controllerutils.GetAndCreateOrMergePatch(ctx, e.K8sClient, clusterRoleServiceAccountManager, func() error {
			clusterRoleServiceAccountManager.Rules = []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"serviceaccounts"},
					Verbs: []string{
						"create",
						"delete",
						"deletecollection",
						"get",
						"list",
						"patch",
						"update",
						"watch",
					},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"serviceaccounts/token"},
					Verbs:     []string{"create"},
				},
			}
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		// ensure that role bindings are reconciled according to the project membership spec
		projectRBAC, err := projectrbac.New(e.K8sClient, project)
		Expect(err).NotTo(HaveOccurred())
		Expect(projectRBAC.Deploy(ctx)).To(Succeed())
	})

	JustBeforeEach(func() {
		terminalCreationError = e.K8sClient.Create(ctx, terminal)
	})

	Context("project membership lifecycle", func() {
		It("should remove ServiceAccount as project member", func() {
			Expect(terminalCreationError).To(Not(HaveOccurred()))

			By("Expecting terminal to be created")
			Eventually(func() bool {
				terminal = &dashboardv1alpha1.Terminal{}
				err := e.K8sClient.Get(ctx, terminalKey, terminal)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("Adding terminal ownerReference to service account")
			targetServiceAccount := &corev1.ServiceAccount{}
			err := e.K8sClient.Get(ctx, targetServiceAccountKey, targetServiceAccount)
			Expect(err).ToNot(HaveOccurred())
			if targetServiceAccount.OwnerReferences == nil {
				targetServiceAccount.OwnerReferences = []metav1.OwnerReference{}
			}
			targetServiceAccount.OwnerReferences = append(targetServiceAccount.OwnerReferences, metav1.OwnerReference{
				APIVersion: "dashboard.gardener.cloud/v1alpha1",
				Kind:       "Terminal",
				Name:       terminal.Name,
				UID:        terminal.UID,
			})
			Expect(e.K8sClient.Update(ctx, targetServiceAccount)).To(Succeed())

			isTargetServiceAccountMember := func() bool {
				project := &gardencorev1beta1.Project{ObjectMeta: metav1.ObjectMeta{Name: projectName}}
				err := e.K8sClient.Get(ctx, client.ObjectKeyFromObject(project), project)
				if err != nil {
					return false
				}

				isMember, _ := gardenclient.IsMember(project.Spec.Members, targetServiceAccountKey)
				return isMember
			}

			By("Ensuring that service account is member of the project")
			Expect(isTargetServiceAccountMember()).To(BeTrue())

			By("Expecting that terminal reference label is present")
			Eventually(func() bool {
				targetServiceAccount := &corev1.ServiceAccount{}
				if err := e.K8sClient.Get(ctx, targetServiceAccountKey, targetServiceAccount); err != nil {
					return false
				}
				return targetServiceAccount.Labels[dashboardv1alpha1.TerminalReference] == "true"
			}, timeout, interval).Should(BeTrue())

			By("Deleting the terminal")
			err = e.K8sClient.Delete(ctx, terminal)
			Expect(err).To(Not(HaveOccurred()))

			Eventually(func() bool {
				t := &dashboardv1alpha1.Terminal{}
				err := e.K8sClient.Get(ctx, terminalKey, t)
				return kErros.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())

			By("Expecting that service account is no longer a member of the project")
			Eventually(isTargetServiceAccountMember, timeout, interval).Should(BeFalse())

			By("Expecting that service account is finally deleted")
			Eventually(func() bool {
				targetServiceAccount := &corev1.ServiceAccount{}
				err := e.K8sClient.Get(ctx, targetServiceAccountKey, targetServiceAccount)
				return kErros.IsNotFound(err)
			}, timeout, interval).Should(BeFalse())
		})
	})
})
