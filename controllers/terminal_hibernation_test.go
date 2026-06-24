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

func newFakeClientWithShoot(shoot *gardencorev1beta1.Shoot, terminals ...*dashboardv1alpha1.Terminal) client.Client {
	scheme := runtime.NewScheme()
	Expect(gardencorev1beta1.AddToScheme(scheme)).To(Succeed())
	Expect(dashboardv1alpha1.AddToScheme(scheme)).To(Succeed())
	Expect(corev1.AddToScheme(scheme)).To(Succeed())

	objs := []client.Object{}
	if shoot != nil {
		objs = append(objs, shoot)
	}

	for _, t := range terminals {
		objs = append(objs, t)
	}

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithIndex(&dashboardv1alpha1.Terminal{}, TerminalShootRef, IndexTerminalByShootRef)

	return builder.Build()
}

type failingShootGetClient struct {
	client.Client
	err error
}

func (c *failingShootGetClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*gardencorev1beta1.Shoot); ok {
		return c.err
	}

	return c.Client.Get(ctx, key, obj, opts...)
}

type countingShootGetClient struct {
	client.Client
	getCount int
}

func (c *countingShootGetClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*gardencorev1beta1.Shoot); ok {
		c.getCount++
	}

	return c.Client.Get(ctx, key, obj, opts...)
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

// drainEvents reads all currently-buffered events from a FakeRecorder without
// blocking. It does not close the channel, so the recorder remains usable.
func drainEvents(rec *record.FakeRecorder) []string {
	var events []string

	for {
		select {
		case ev := <-rec.Events:
			events = append(events, ev)
		default:
			return events
		}
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

	Describe("isAnyReferencedShootHibernated", func() {
		It("should return false when no shoot refs exist", func() {
			fakeClient := newFakeClientWithShoot(nil)
			r := newTestReconciler(fakeClient)

			t := &dashboardv1alpha1.Terminal{
				Spec: dashboardv1alpha1.TerminalSpec{
					Host: dashboardv1alpha1.HostCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ServiceAccountRef: &corev1.ObjectReference{Name: "sa", Namespace: "ns"},
						},
					},
					Target: dashboardv1alpha1.TargetCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ServiceAccountRef: &corev1.ObjectReference{Name: "sa", Namespace: "ns"},
						},
					},
				},
			}
			hibernated, _, err := r.isAnyReferencedShootHibernated(context.Background(), t)
			Expect(err).ToNot(HaveOccurred())
			Expect(hibernated).To(BeFalse())
		})

		It("should return true when target shoot is hibernated", func() {
			shoot := &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "hib-shoot",
					Namespace: "garden-project",
				},
				Status: gardencorev1beta1.ShootStatus{
					IsHibernated: true,
				},
			}
			fakeClient := newFakeClientWithShoot(shoot)
			r := newTestReconciler(fakeClient)

			t := &dashboardv1alpha1.Terminal{
				Spec: dashboardv1alpha1.TerminalSpec{
					Host: dashboardv1alpha1.HostCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ServiceAccountRef: &corev1.ObjectReference{Name: "sa", Namespace: "ns"},
						},
					},
					Target: dashboardv1alpha1.TargetCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: "garden-project",
								Name:      "hib-shoot",
							},
						},
					},
				},
			}

			hibernated, key, err := r.isAnyReferencedShootHibernated(context.Background(), t)
			Expect(err).ToNot(HaveOccurred())
			Expect(hibernated).To(BeTrue())
			Expect(key).To(Equal(types.NamespacedName{Namespace: "garden-project", Name: "hib-shoot"}))
		})

		It("should return true when host shoot is hibernated", func() {
			shoot := &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "hib-host",
					Namespace: "garden-project",
				},
				Status: gardencorev1beta1.ShootStatus{
					IsHibernated: true,
				},
			}
			fakeClient := newFakeClientWithShoot(shoot)
			r := newTestReconciler(fakeClient)

			t := &dashboardv1alpha1.Terminal{
				Spec: dashboardv1alpha1.TerminalSpec{
					Host: dashboardv1alpha1.HostCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: "garden-project",
								Name:      "hib-host",
							},
						},
					},
					Target: dashboardv1alpha1.TargetCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ServiceAccountRef: &corev1.ObjectReference{Name: "sa", Namespace: "ns"},
						},
					},
				},
			}

			hibernated, key, err := r.isAnyReferencedShootHibernated(context.Background(), t)
			Expect(err).ToNot(HaveOccurred())
			Expect(hibernated).To(BeTrue())
			Expect(key).To(Equal(types.NamespacedName{Namespace: "garden-project", Name: "hib-host"}))
		})

		It("should return false when shoot is not hibernated", func() {
			shoot := &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "awake-shoot",
					Namespace: "garden-project",
				},
				Status: gardencorev1beta1.ShootStatus{
					IsHibernated: false,
				},
			}
			fakeClient := newFakeClientWithShoot(shoot)
			r := newTestReconciler(fakeClient)

			t := &dashboardv1alpha1.Terminal{
				Spec: dashboardv1alpha1.TerminalSpec{
					Host: dashboardv1alpha1.HostCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ServiceAccountRef: &corev1.ObjectReference{Name: "sa", Namespace: "ns"},
						},
					},
					Target: dashboardv1alpha1.TargetCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: "garden-project",
								Name:      "awake-shoot",
							},
						},
					},
				},
			}

			hibernated, _, err := r.isAnyReferencedShootHibernated(context.Background(), t)
			Expect(err).ToNot(HaveOccurred())
			Expect(hibernated).To(BeFalse())
		})

		It("should treat a missing shoot as not hibernated", func() {
			fakeClient := newFakeClientWithShoot(nil)
			r := newTestReconciler(fakeClient)

			t := &dashboardv1alpha1.Terminal{
				Spec: dashboardv1alpha1.TerminalSpec{
					Host: dashboardv1alpha1.HostCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ServiceAccountRef: &corev1.ObjectReference{Name: "sa", Namespace: "ns"},
						},
					},
					Target: dashboardv1alpha1.TargetCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: "nonexistent-ns",
								Name:      "nonexistent-shoot",
							},
						},
					},
				},
			}

			hibernated, _, err := r.isAnyReferencedShootHibernated(context.Background(), t)
			Expect(err).ToNot(HaveOccurred())
			Expect(hibernated).To(BeFalse())
		})

		It("should return non-NotFound shoot read errors", func() {
			readErr := errors.New("cache unavailable")
			fakeClient := &failingShootGetClient{
				Client: newFakeClientWithShoot(nil),
				err:    readErr,
			}
			r := newTestReconciler(fakeClient)

			t := &dashboardv1alpha1.Terminal{
				Spec: dashboardv1alpha1.TerminalSpec{
					Host: dashboardv1alpha1.HostCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ServiceAccountRef: &corev1.ObjectReference{Name: "sa", Namespace: "ns"},
						},
					},
					Target: dashboardv1alpha1.TargetCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: "garden-project",
								Name:      "shoot",
							},
						},
					},
				},
			}

			hibernated, key, err := r.isAnyReferencedShootHibernated(context.Background(), t)
			Expect(hibernated).To(BeFalse())
			Expect(key).To(Equal(types.NamespacedName{}))
			Expect(err).To(MatchError(ContainSubstring("failed to read shoot garden-project/shoot for hibernation check: cache unavailable")))
			Expect(errors.Is(err, readErr)).To(BeTrue())
		})

		It("should read duplicate shoot refs only once", func() {
			shoot := &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "awake",
					Namespace: "garden-project",
				},
				Status: gardencorev1beta1.ShootStatus{IsHibernated: false},
			}
			fakeClient := &countingShootGetClient{
				Client: newFakeClientWithShoot(shoot),
			}
			r := newTestReconciler(fakeClient)

			t := &dashboardv1alpha1.Terminal{
				Spec: dashboardv1alpha1.TerminalSpec{
					Host: dashboardv1alpha1.HostCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: "garden-project",
								Name:      "awake",
							},
						},
					},
					Target: dashboardv1alpha1.TargetCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: "garden-project",
								Name:      "awake",
							},
						},
					},
				},
			}

			hibernated, key, err := r.isAnyReferencedShootHibernated(context.Background(), t)
			Expect(err).ToNot(HaveOccurred())
			Expect(hibernated).To(BeFalse())
			Expect(key).To(Equal(types.NamespacedName{}))
			Expect(fakeClient.getCount).To(Equal(1))
		})

		It("should detect hibernation on either ref when both host and target reference different shoots", func() {
			awakeShoot := &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "awake",
					Namespace: "garden-project",
				},
				Status: gardencorev1beta1.ShootStatus{IsHibernated: false},
			}
			hibShoot := &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "hibernated",
					Namespace: "garden-project",
				},
				Status: gardencorev1beta1.ShootStatus{IsHibernated: true},
			}

			scheme := runtime.NewScheme()
			Expect(gardencorev1beta1.AddToScheme(scheme)).To(Succeed())
			Expect(dashboardv1alpha1.AddToScheme(scheme)).To(Succeed())
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(awakeShoot, hibShoot).
				Build()

			r := newTestReconciler(fakeClient)

			t := &dashboardv1alpha1.Terminal{
				Spec: dashboardv1alpha1.TerminalSpec{
					Host: dashboardv1alpha1.HostCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: "garden-project",
								Name:      "awake",
							},
						},
					},
					Target: dashboardv1alpha1.TargetCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ShootRef: &dashboardv1alpha1.ShootRef{
								Namespace: "garden-project",
								Name:      "hibernated",
							},
						},
					},
				},
			}

			hibernated, key, err := r.isAnyReferencedShootHibernated(context.Background(), t)
			Expect(err).ToNot(HaveOccurred())
			Expect(hibernated).To(BeTrue())
			Expect(key).To(Equal(types.NamespacedName{Namespace: "garden-project", Name: "hibernated"}))
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

		It("should skip reconciliation while shoot is hibernated, then reconcile after wake-up", func() {
			By("Waiting for the hibernation event proving the skip path ran")
			Eventually(func(g Gomega) {
				events := &corev1.EventList{}
				err := e.K8sClient.List(ctx, events,
					client.InNamespace(terminalNamespace),
					client.MatchingFields{"involvedObject.name": terminal.Name, "involvedObject.kind": "Terminal"})
				g.Expect(err).To(Not(HaveOccurred()))

				found := false

				for _, ev := range events.Items {
					if ev.Reason == dashboardv1alpha1.EventHibernated {
						found = true
						break
					}
				}

				g.Expect(found).To(BeTrue())
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

			By("Triggering a reconcile to confirm hibernation check no longer blocks")
			Eventually(func(g Gomega) {
				t := &dashboardv1alpha1.Terminal{}
				g.Expect(e.K8sClient.Get(ctx, terminalKey, t)).To(Succeed())

				if t.Annotations == nil {
					t.Annotations = map[string]string{}
				}

				t.Annotations["test-wake-trigger"] = "true"
				g.Expect(e.K8sClient.Update(ctx, t)).To(Succeed())
			}, timeout, interval).Should(Succeed())

			By("Waiting for the terminal to progress past hibernation check (LastOperation transitions away from Succeeded)")
			Eventually(func(g Gomega) {
				t := &dashboardv1alpha1.Terminal{}
				g.Expect(e.K8sClient.Get(ctx, terminalKey, t)).To(Succeed())
				g.Expect(t.Status.LastOperation).ToNot(BeNil())
				g.Expect(t.Status.LastOperation.State).To(Equal(dashboardv1alpha1.LastOperationStateError))
			}, timeout, interval).Should(Succeed())
		})
	})

	Describe("handleTerminal hibernation skip (unit)", func() {
		It("should return early without error when target shoot is hibernated", func() {
			shoot := &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "hib-shoot",
					Namespace: "garden-project",
				},
				Status: gardencorev1beta1.ShootStatus{IsHibernated: true},
			}
			fakeClient := newFakeClientWithShoot(shoot)
			r := newTestReconciler(fakeClient)
			r.Config = test.DefaultConfiguration()
			r.ReconcilerCountPerNamespace = map[string]int{}

			t := &dashboardv1alpha1.Terminal{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-terminal",
					Namespace: "term-ns",
				},
				Spec: dashboardv1alpha1.TerminalSpec{
					Host: dashboardv1alpha1.HostCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ServiceAccountRef: &corev1.ObjectReference{Name: "sa", Namespace: "ns"},
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
								Name:      "hib-shoot",
							},
						},
						Namespace:                  ptr.To("term-ns"),
						KubeconfigContextNamespace: "default",
					},
				},
			}

			result, err := r.handleTerminal(context.Background(), t)
			Expect(err).ToNot(HaveOccurred())
			Expect(result.RequeueAfter).To(BeZero())

			// Verify a hibernation event was emitted, proving the skip path ran.
			rec, ok := r.Recorder.(*record.FakeRecorder)
			Expect(ok).To(BeTrue())
			Expect(rec.Events).To(Receive(ContainSubstring(dashboardv1alpha1.EventHibernated)))
		})

		It("should run deletion path even when target shoot is hibernated", func() {
			now := metav1.Now()
			shoot := &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "hib-shoot-del",
					Namespace: "garden-project",
				},
				Status: gardencorev1beta1.ShootStatus{IsHibernated: true},
			}
			fakeClient := newFakeClientWithShoot(shoot)
			r := newTestReconciler(fakeClient)
			r.Config = test.DefaultConfiguration()
			r.ReconcilerCountPerNamespace = map[string]int{}

			t := &dashboardv1alpha1.Terminal{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "my-terminal-del",
					Namespace:         "term-ns",
					DeletionTimestamp: &now,
					Finalizers:        []string{dashboardv1alpha1.TerminalName},
				},
				Spec: dashboardv1alpha1.TerminalSpec{
					Host: dashboardv1alpha1.HostCluster{
						Credentials: dashboardv1alpha1.ClusterCredentials{
							ServiceAccountRef: &corev1.ObjectReference{Name: "sa", Namespace: "ns"},
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
								Name:      "hib-shoot-del",
							},
						},
						Namespace:                  ptr.To("term-ns"),
						KubeconfigContextNamespace: "default",
					},
				},
			}

			// We don't care whether deleteTerminal succeeds against the fake
			// client — only that the hibernation skip was NOT taken and the
			// deletion path was entered.
			_, _ = r.handleTerminal(context.Background(), t)

			rec, ok := r.Recorder.(*record.FakeRecorder)
			Expect(ok).To(BeTrue())

			events := drainEvents(rec)
			Expect(events).ToNot(ContainElement(ContainSubstring(dashboardv1alpha1.EventHibernated)))
			Expect(events).To(ContainElement(ContainSubstring(dashboardv1alpha1.EventDeleting)))
		})
	})
})
