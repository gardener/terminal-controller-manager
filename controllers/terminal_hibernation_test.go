/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package controllers

import (
	"context"
	"errors"
	"time"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kErros "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	dashboardv1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/internal/gardenclient"
	"github.com/gardener/terminal-controller-manager/test"
)

func newFakeClientWithObjects(objs ...client.Object) client.Client {
	scheme := runtime.NewScheme()
	Expect(gardencorev1beta1.AddToScheme(scheme)).To(Succeed())
	Expect(dashboardv1alpha1.AddToScheme(scheme)).To(Succeed())
	Expect(corev1.AddToScheme(scheme)).To(Succeed())
	Expect(rbacv1.AddToScheme(scheme)).To(Succeed())

	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&dashboardv1alpha1.Terminal{}).
		WithIndex(&dashboardv1alpha1.Terminal{}, TerminalShootRef, IndexTerminalByShootRef).
		Build()
}

func newFakeClientWithShoot(shoot *gardencorev1beta1.Shoot, terminals ...*dashboardv1alpha1.Terminal) client.Client {
	objs := []client.Object{}
	if shoot != nil {
		objs = append(objs, shoot)
	}

	for _, t := range terminals {
		objs = append(objs, t)
	}

	return newFakeClientWithObjects(objs...)
}

func newTestReconciler(c client.Client) *TerminalReconciler {
	return &TerminalReconciler{
		ClientSet: gardenclient.NewClientSet(
			&rest.Config{Host: "https://127.0.0.1:0"},
			c,
			nil,
		),
		Scheme:                      c.Scheme(),
		Recorder:                    record.NewFakeRecorder(100),
		Config:                      nil,
		ReconcilerCountPerNamespace: map[string]int{},
	}
}

func drainRecorderEvents(recorder record.EventRecorder) []string {
	fakeRecorder := recorder.(*record.FakeRecorder)

	var events []string

	for {
		select {
		case eventMessage := <-fakeRecorder.Events:
			events = append(events, eventMessage)
		default:
			return events
		}
	}
}

func newDeletingTerminal(name, namespace, identifier, hostNamespace, targetNamespace string) *dashboardv1alpha1.Terminal {
	return &dashboardv1alpha1.Terminal{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespace,
			Finalizers: []string{dashboardv1alpha1.TerminalName},
		},
		Spec: dashboardv1alpha1.TerminalSpec{
			Identifier: identifier,
			Host: dashboardv1alpha1.HostCluster{
				Credentials: dashboardv1alpha1.ClusterCredentials{
					ServiceAccountRef: &corev1.ObjectReference{Name: "host-sa", Namespace: hostNamespace},
				},
				Namespace: ptr.To(hostNamespace),
				Pod: dashboardv1alpha1.Pod{
					Container: &dashboardv1alpha1.Container{Image: "foo"},
				},
			},
			Target: dashboardv1alpha1.TargetCluster{
				Credentials: dashboardv1alpha1.ClusterCredentials{
					ShootRef: &dashboardv1alpha1.ShootRef{Namespace: "garden-project", Name: "hibernated-shoot"},
				},
				Namespace:                  ptr.To(targetNamespace),
				KubeconfigContextNamespace: "default",
			},
		},
	}
}

var _ = Describe("Shoot Hibernation", func() {
	Describe("IndexTerminalByShootRef", func() {
		It("should return empty for terminal without shoot refs", func() {
			t := &dashboardv1alpha1.Terminal{
				Spec: dashboardv1alpha1.TerminalSpec{
					Host: dashboardv1alpha1.HostCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ServiceAccountRef: &corev1.ObjectReference{
								Name:      "sa",
								Namespace: "ns",
							},
						},
					},
					Target: dashboardv1alpha1.TargetCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ServiceAccountRef: &corev1.ObjectReference{
								Name:      "sa",
								Namespace: "ns",
							},
						},
					},
				},
			}
			keys := IndexTerminalByShootRef(t)
			Expect(keys).To(BeEmpty())
		})

		It("should index target shoot ref", func() {
			t := &dashboardv1alpha1.Terminal{
				Spec: dashboardv1alpha1.TerminalSpec{
					Host: dashboardv1alpha1.HostCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ServiceAccountRef: &corev1.ObjectReference{
								Name:      "sa",
								Namespace: "ns",
							},
						},
					},
					Target: dashboardv1alpha1.TargetCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: "garden-project",
								Name:      "my-shoot",
							},
						},
					},
				},
			}
			keys := IndexTerminalByShootRef(t)
			Expect(keys).To(ConsistOf("garden-project/my-shoot"))
		})

		It("should index host shoot ref", func() {
			t := &dashboardv1alpha1.Terminal{
				Spec: dashboardv1alpha1.TerminalSpec{
					Host: dashboardv1alpha1.HostCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: "garden-project",
								Name:      "host-shoot",
							},
						},
					},
					Target: dashboardv1alpha1.TargetCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ServiceAccountRef: &corev1.ObjectReference{
								Name:      "sa",
								Namespace: "ns",
							},
						},
					},
				},
			}
			keys := IndexTerminalByShootRef(t)
			Expect(keys).To(ConsistOf("garden-project/host-shoot"))
		})

		It("should index both host and target shoot refs when different", func() {
			t := &dashboardv1alpha1.Terminal{
				Spec: dashboardv1alpha1.TerminalSpec{
					Host: dashboardv1alpha1.HostCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: "garden-project",
								Name:      "host-shoot",
							},
						},
					},
					Target: dashboardv1alpha1.TargetCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: "garden-project",
								Name:      "target-shoot",
							},
						},
					},
				},
			}
			keys := IndexTerminalByShootRef(t)
			Expect(keys).To(ConsistOf("garden-project/host-shoot", "garden-project/target-shoot"))
		})

		It("should deduplicate when host and target reference the same shoot", func() {
			t := &dashboardv1alpha1.Terminal{
				Spec: dashboardv1alpha1.TerminalSpec{
					Host: dashboardv1alpha1.HostCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: "garden-project",
								Name:      "same-shoot",
							},
						},
					},
					Target: dashboardv1alpha1.TargetCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: "garden-project",
								Name:      "same-shoot",
							},
						},
					},
				},
			}
			keys := IndexTerminalByShootRef(t)
			Expect(keys).To(ConsistOf("garden-project/same-shoot"))
			Expect(keys).To(HaveLen(1))
		})

		It("should return nil for non-Terminal objects", func() {
			keys := IndexTerminalByShootRef(&corev1.Pod{})
			Expect(keys).To(BeNil())
		})
	})

	Describe("shootWakeUpPredicate", func() {
		var pred = shootWakeUpPredicate()

		It("should reject create events", func() {
			result := pred.Create(event.CreateEvent{
				Object: &gardencorev1beta1.Shoot{
					Status: gardencorev1beta1.ShootStatus{IsHibernated: false},
				},
			})
			Expect(result).To(BeFalse())
		})

		It("should reject delete events", func() {
			result := pred.Delete(event.DeleteEvent{
				Object: &gardencorev1beta1.Shoot{},
			})
			Expect(result).To(BeFalse())
		})

		It("should accept update from hibernated to awake", func() {
			result := pred.Update(event.UpdateEvent{
				ObjectOld: &gardencorev1beta1.Shoot{
					Status: gardencorev1beta1.ShootStatus{IsHibernated: true},
				},
				ObjectNew: &gardencorev1beta1.Shoot{
					Status: gardencorev1beta1.ShootStatus{IsHibernated: false},
				},
			})
			Expect(result).To(BeTrue())
		})

		It("should reject update from awake to hibernated", func() {
			result := pred.Update(event.UpdateEvent{
				ObjectOld: &gardencorev1beta1.Shoot{
					Status: gardencorev1beta1.ShootStatus{IsHibernated: false},
				},
				ObjectNew: &gardencorev1beta1.Shoot{
					Status: gardencorev1beta1.ShootStatus{IsHibernated: true},
				},
			})
			Expect(result).To(BeFalse())
		})

		It("should reject update when both awake", func() {
			result := pred.Update(event.UpdateEvent{
				ObjectOld: &gardencorev1beta1.Shoot{
					Status: gardencorev1beta1.ShootStatus{IsHibernated: false},
				},
				ObjectNew: &gardencorev1beta1.Shoot{
					Status: gardencorev1beta1.ShootStatus{IsHibernated: false},
				},
			})
			Expect(result).To(BeFalse())
		})

		It("should reject update when both hibernated", func() {
			result := pred.Update(event.UpdateEvent{
				ObjectOld: &gardencorev1beta1.Shoot{
					Status: gardencorev1beta1.ShootStatus{IsHibernated: true},
				},
				ObjectNew: &gardencorev1beta1.Shoot{
					Status: gardencorev1beta1.ShootStatus{IsHibernated: true},
				},
			})
			Expect(result).To(BeFalse())
		})

		It("should reject update with non-Shoot objects", func() {
			result := pred.Update(event.UpdateEvent{
				ObjectOld: &corev1.Pod{},
				ObjectNew: &corev1.Pod{},
			})
			Expect(result).To(BeFalse())
		})
	})

	Describe("mapShootToTerminals", func() {
		It("should map a shoot to terminals referencing it", func() {
			shoot := &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-shoot",
					Namespace: "garden-project",
				},
			}
			terminal := &dashboardv1alpha1.Terminal{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-terminal",
					Namespace: "term-ns",
				},
				Spec: dashboardv1alpha1.TerminalSpec{
					Host: dashboardv1alpha1.HostCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: "garden-project",
								Name:      "my-shoot",
							},
						},
						Namespace: ptr.To("term-ns"),
						Pod: dashboardv1alpha1.Pod{
							Container: &dashboardv1alpha1.Container{Image: "foo"},
						},
					},
					Target: dashboardv1alpha1.TargetCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: "garden-project",
								Name:      "my-shoot",
							},
						},
						Namespace:                  ptr.To("term-ns"),
						KubeconfigContextNamespace: "default",
					},
				},
			}

			fakeClient := newFakeClientWithShoot(shoot, terminal)
			r := newTestReconciler(fakeClient)

			requests := r.mapShootToTerminals(context.Background(), shoot)

			Expect(requests).To(ContainElement(reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: "term-ns",
					Name:      "my-terminal",
				},
			}))
		})

		It("should return empty for a shoot not referenced by any terminal", func() {
			shoot := &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "other-shoot",
					Namespace: "garden-project",
				},
			}

			fakeClient := newFakeClientWithShoot(shoot)
			r := newTestReconciler(fakeClient)

			requests := r.mapShootToTerminals(context.Background(), shoot)

			Expect(requests).To(BeEmpty())
		})
	})

	Describe("newClientSetFromClusterCredentials", func() {
		It("should return a hibernation error instead of creating a shoot client", func() {
			shoot := &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "hibernated-shoot",
					Namespace: "garden-project",
				},
				Status: gardencorev1beta1.ShootStatus{IsHibernated: true},
			}
			r := newTestReconciler(newFakeClientWithShoot(shoot))

			clientSet, err := r.newClientSetFromClusterCredentials(context.Background(), r.ClientSet, dashboardv1alpha1.ClusterCredentials{
				ShootRef: &dashboardv1alpha1.ShootRef{
					Namespace: shoot.Namespace,
					Name:      shoot.Name,
				},
			}, nil, nil)

			Expect(clientSet).To(BeNil())
			Expect(errors.Is(err, errShootHibernated)).To(BeTrue())
			Expect(err).To(MatchError(errShootHibernated))
		})
	})

	Describe("handleTerminal hibernation", func() {
		It("should treat hibernated shoot as a wait state, not an error", func() {
			shoot := &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "hibernated-shoot",
					Namespace: "garden-project",
				},
				Status: gardencorev1beta1.ShootStatus{IsHibernated: true},
			}

			t := &dashboardv1alpha1.Terminal{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "terminal",
					Namespace: "terminal-namespace",
				},
				Spec: dashboardv1alpha1.TerminalSpec{
					Host: dashboardv1alpha1.HostCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: shoot.Namespace,
								Name:      shoot.Name,
							},
						},
						Namespace: ptr.To("host-namespace"),
						Pod: dashboardv1alpha1.Pod{
							Container: &dashboardv1alpha1.Container{Image: "foo"},
						},
					},
					Target: dashboardv1alpha1.TargetCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: shoot.Namespace,
								Name:      shoot.Name,
							},
						},
						Namespace:                  ptr.To("target-namespace"),
						KubeconfigContextNamespace: "default",
					},
				},
			}

			r := newTestReconciler(newFakeClientWithShoot(shoot, t))
			r.Config = test.DefaultConfiguration()

			result, err := r.handleTerminal(context.Background(), t)

			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(time.Hour))

			storedTerminal := &dashboardv1alpha1.Terminal{}
			Expect(r.Get(context.Background(), types.NamespacedName{Name: t.Name, Namespace: t.Namespace}, storedTerminal)).To(Succeed())
			Expect(storedTerminal.Status.LastError).To(BeNil())
			Expect(storedTerminal.Status.LastOperation).ToNot(BeNil())
			Expect(storedTerminal.Status.LastOperation.Type).To(Equal(dashboardv1alpha1.LastOperationTypeReconcile))
			Expect(storedTerminal.Status.LastOperation.State).To(Equal(dashboardv1alpha1.LastOperationStateProcessing))
			Expect(storedTerminal.Status.LastOperation.Description).To(ContainSubstring("wake from hibernation"))
		})
	})

	Describe("deleteTerminal hibernation", func() {
		It("should clean up the awake cluster and keep the finalizer when the target shoot is hibernated", func() {
			const (
				terminalName      = "terminal"
				terminalNamespace = "terminal-namespace"
				hostNamespace     = "host-namespace"
				targetNamespace   = "target-namespace"
				identifier        = "abc123"
			)

			t := newDeletingTerminal(terminalName, terminalNamespace, identifier, hostNamespace, targetNamespace)
			hostClient := newFakeClientWithObjects(
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: dashboardv1alpha1.TerminalAttachResourceNamePrefix + identifier, Namespace: hostNamespace}},
				&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: dashboardv1alpha1.TerminalAttachRoleResourceNamePrefix + identifier, Namespace: hostNamespace}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: dashboardv1alpha1.TerminalAttachResourceNamePrefix + identifier, Namespace: hostNamespace}},
				&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: dashboardv1alpha1.TerminalPodResourceNamePrefix + identifier, Namespace: hostNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: dashboardv1alpha1.KubeconfigSecretResourceNamePrefix + identifier, Namespace: hostNamespace}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: dashboardv1alpha1.TokenSecretResourceNamePrefix + identifier, Namespace: hostNamespace}},
			)
			hostClientSet := gardenclient.NewClientSet(&rest.Config{}, hostClient, nil)
			r := newTestReconciler(newFakeClientWithObjects(t.DeepCopy()))

			result, err := r.deleteTerminal(
				context.Background(),
				t,
				nil,
				errShootHibernated,
				nil,
				hostClientSet,
			)

			Expect(err).ToNot(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(time.Hour))

			for _, deletedObject := range []struct {
				key types.NamespacedName
				obj client.Object
			}{
				{key: types.NamespacedName{Name: dashboardv1alpha1.TerminalAttachResourceNamePrefix + identifier, Namespace: hostNamespace}, obj: &corev1.ServiceAccount{}},
				{key: types.NamespacedName{Name: dashboardv1alpha1.TerminalAttachRoleResourceNamePrefix + identifier, Namespace: hostNamespace}, obj: &rbacv1.Role{}},
				{key: types.NamespacedName{Name: dashboardv1alpha1.TerminalAttachResourceNamePrefix + identifier, Namespace: hostNamespace}, obj: &rbacv1.RoleBinding{}},
				{key: types.NamespacedName{Name: dashboardv1alpha1.TerminalPodResourceNamePrefix + identifier, Namespace: hostNamespace}, obj: &corev1.Pod{}},
				{key: types.NamespacedName{Name: dashboardv1alpha1.KubeconfigSecretResourceNamePrefix + identifier, Namespace: hostNamespace}, obj: &corev1.Secret{}},
				{key: types.NamespacedName{Name: dashboardv1alpha1.TokenSecretResourceNamePrefix + identifier, Namespace: hostNamespace}, obj: &corev1.Secret{}},
			} {
				Expect(kErros.IsNotFound(hostClient.Get(context.Background(), deletedObject.key, deletedObject.obj))).To(BeTrue())
			}

			storedTerminal := &dashboardv1alpha1.Terminal{}
			Expect(r.Get(context.Background(), types.NamespacedName{Name: terminalName, Namespace: terminalNamespace}, storedTerminal)).To(Succeed())
			Expect(storedTerminal.Finalizers).To(ContainElement(dashboardv1alpha1.TerminalName))
			Expect(storedTerminal.Status.LastError).To(BeNil())
			Expect(storedTerminal.Status.LastOperation).ToNot(BeNil())
			Expect(storedTerminal.Status.LastOperation.Type).To(Equal(dashboardv1alpha1.LastOperationTypeDelete))
			Expect(storedTerminal.Status.LastOperation.State).To(Equal(dashboardv1alpha1.LastOperationStateProcessing))

			events := drainRecorderEvents(r.Recorder)
			Expect(events).To(ContainElement(ContainSubstring("Normal Deleting Target cluster cleanup is deferred because the referenced shoot is hibernated")))
			Expect(events).To(ContainElement(ContainSubstring("Normal Deleting Processing external dependency deletion")))
			Expect(events).To(ContainElement(ContainSubstring("Normal Deleting External dependency deletion is waiting for deferred shoot cleanup")))
			Expect(events).To(ContainElement(ContainSubstring("Warning Reconciling Could not clean up resources in target cluster")))
			Expect(events).NotTo(ContainElement(ContainSubstring("Deleted available external dependencies")))
			Expect(events).NotTo(ContainElement(ContainSubstring("Normal Hibernated")))
		})
	})

	Describe("Shoot hibernation wake-up (integration)", func() {
		const (
			timeout  = time.Second * 30
			interval = time.Millisecond * 250
		)

		var (
			suffix            string
			terminalNamespace string
			hostNamespace     string
			shootNamespace    string
			shoot             *gardencorev1beta1.Shoot
			terminal          *dashboardv1alpha1.Terminal
			terminalKey       types.NamespacedName
		)

		BeforeEach(func() {
			suffix = test.StringWithCharset(randomLength, charset)
			terminalNamespace = "test-hib-term-ns-" + suffix
			hostNamespace = "test-hib-host-ns-" + suffix
			shootNamespace = "garden-hib-" + suffix

			By("Creating namespaces")

			for _, ns := range []string{terminalNamespace, hostNamespace, shootNamespace} {
				e.CreateObject(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, types.NamespacedName{Name: ns}, timeout, interval)
			}

			By("Creating host service account")
			e.AddClusterAdminServiceAccount(ctx, "hib-host-sa", hostNamespace, timeout, interval)

			By("Creating Project for Shoot namespace")

			project := &gardencorev1beta1.Project{
				ObjectMeta: metav1.ObjectMeta{Name: "hib-" + suffix},
				Spec: gardencorev1beta1.ProjectSpec{
					Namespace: &shootNamespace,
				},
			}
			e.CreateObject(ctx, project, client.ObjectKeyFromObject(project), timeout, interval)

			By("Creating Shoot")

			shoot = &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "hib-shoot-" + suffix,
					Namespace: shootNamespace,
				},
				Spec: gardencorev1beta1.ShootSpec{
					SecretBindingName: ptr.To("secretbinding"),
					CloudProfileName:  ptr.To("cloudprofile1"),
					Region:            "eu-central-1",
					Provider: gardencorev1beta1.Provider{
						Type: "foo-provider",
						Workers: []gardencorev1beta1.Worker{
							{
								Name:    "cpu-worker",
								Minimum: 1,
								Maximum: 1,
								Machine: gardencorev1beta1.Machine{
									Type: "large",
									Image: &gardencorev1beta1.ShootMachineImage{
										Name:    "some-image",
										Version: ptr.To("1.0.0"),
									},
								},
							},
						},
					},
					Kubernetes: gardencorev1beta1.Kubernetes{
						Version: "1.32.0",
					},
					Networking: &gardencorev1beta1.Networking{
						Type: ptr.To("foo-networking"),
					},
				},
			}
			Expect(e.K8sClient.Create(ctx, shoot)).To(Succeed())

			By("Setting Shoot status to hibernated")

			patch := client.MergeFrom(shoot.DeepCopy())
			shoot.Status.IsHibernated = true
			Expect(e.K8sClient.Status().Patch(ctx, shoot, patch)).To(Succeed())

			By("Creating Terminal referencing the hibernated Shoot")

			terminal = &dashboardv1alpha1.Terminal{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "hib-terminal-" + suffix,
					Namespace: terminalNamespace,
				},
				Spec: dashboardv1alpha1.TerminalSpec{
					Host: dashboardv1alpha1.HostCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ServiceAccountRef: &corev1.ObjectReference{
								Kind:      rbacv1.ServiceAccountKind,
								Name:      "hib-host-sa",
								Namespace: hostNamespace,
							},
						},
						Namespace: &hostNamespace,
						Pod: dashboardv1alpha1.Pod{
							Container: &dashboardv1alpha1.Container{Image: "foo"},
						},
					},
					Target: dashboardv1alpha1.TargetCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: shootNamespace,
								Name:      shoot.Name,
							},
						},
						Namespace:                  &hostNamespace,
						KubeconfigContextNamespace: "default",
					},
				},
			}
			terminalKey = types.NamespacedName{Name: terminal.Name, Namespace: terminal.Namespace}
			Expect(e.K8sClient.Create(ctx, terminal)).To(Succeed())
		})

		It("should wait while shoot is hibernated, then reconcile after wake-up", func() {
			By("Waiting for the terminal to report the hibernation wait state in LastOperation")
			Eventually(func(g Gomega) {
				t := &dashboardv1alpha1.Terminal{}
				g.Expect(e.K8sClient.Get(ctx, terminalKey, t)).To(Succeed())
				g.Expect(t.Status.LastError).To(BeNil())
				g.Expect(t.Status.LastOperation).ToNot(BeNil())
				g.Expect(t.Status.LastOperation.State).To(Equal(dashboardv1alpha1.LastOperationStateProcessing))
				g.Expect(t.Status.LastOperation.Description).To(ContainSubstring("wake from hibernation"))
			}, timeout, interval).Should(Succeed())

			By("Ensuring the terminal is NOT progressing to ready state while hibernated")
			Consistently(func(g Gomega) {
				t := &dashboardv1alpha1.Terminal{}
				g.Expect(e.K8sClient.Get(ctx, terminalKey, t)).To(Succeed())

				g.Expect(t.Status.AttachServiceAccountName).To(BeNil())
				g.Expect(t.Status.PodName).To(BeNil())
			}, 3*time.Second, interval).Should(Succeed())

			By("Waking the Shoot by clearing IsHibernated")

			patch := client.MergeFrom(shoot.DeepCopy())
			shoot.Status.IsHibernated = false
			Expect(e.K8sClient.Status().Patch(ctx, shoot, patch)).To(Succeed())

			By("Waiting for the terminal to progress past hibernation wait state")
			Eventually(func(g Gomega) {
				t := &dashboardv1alpha1.Terminal{}
				g.Expect(e.K8sClient.Get(ctx, terminalKey, t)).To(Succeed())
				g.Expect(t.Status.LastOperation).ToNot(BeNil())
				g.Expect(t.Status.LastOperation.Description).ToNot(ContainSubstring("hibernation"))
			}, timeout, interval).Should(Succeed())
		})
	})
})
