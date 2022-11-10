/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gardener/gardener/pkg/client/kubernetes"
	gardenenvtest "github.com/gardener/gardener/pkg/envtest"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	dashboardv1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
)

var (
	terminalMutatingWebhookPath   = "/terminal/mutate"
	terminalValidatingWebhookPath = "/terminal/validate"
)

type Environment struct {
	GardenEnv  *gardenenvtest.GardenerTestEnvironment
	K8sManager ctrl.Manager
	Config     *rest.Config
	K8sClient  client.Client
}

func New(cmConfig *dashboardv1alpha1.ControllerManagerConfiguration, mutator admission.Handler, validator admission.Handler) Environment {
	logf.SetLogger(zap.New(zap.WriteTo(ginkgo.GinkgoWriter), zap.UseDevMode(true)))

	ginkgo.By("bootstrapping test environment")

	failPolicy := admissionregistrationv1.Fail
	rules := []admissionregistrationv1.RuleWithOperations{
		{
			Operations: []admissionregistrationv1.OperationType{
				admissionregistrationv1.Create,
				admissionregistrationv1.Update,
			},
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{"dashboard.gardener.cloud"},
				APIVersions: []string{"v1alpha1"},
				Resources:   []string{"terminals"},
			},
		},
	}

	noSideEffects := admissionregistrationv1.SideEffectClassNone
	webhookInstallOptions := envtest.WebhookInstallOptions{
		MutatingWebhooks: []*admissionregistrationv1.MutatingWebhookConfiguration{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-mutating-webhook-configuration",
					Labels: map[string]string{
						"terminal": "admission-configuration",
					},
				},
				TypeMeta: metav1.TypeMeta{
					Kind:       "MutatingWebhookConfiguration",
					APIVersion: "admissionregistration.k8s.io/v1beta1",
				},
				Webhooks: []admissionregistrationv1.MutatingWebhook{
					{
						Name:           "test-mutating-create-update-terminal.gardener.cloud",
						FailurePolicy:  &failPolicy,
						TimeoutSeconds: pointer.Int32Ptr(10),
						ClientConfig: admissionregistrationv1.WebhookClientConfig{
							Service: &admissionregistrationv1.ServiceReference{
								Path: &terminalMutatingWebhookPath,
							},
						},
						Rules:                   rules,
						AdmissionReviewVersions: []string{"v1", "v1beta1"},
						SideEffects:             &noSideEffects,
					},
				},
			},
		},
		ValidatingWebhooks: []*admissionregistrationv1.ValidatingWebhookConfiguration{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-validating-webhook-configuration",
					Labels: map[string]string{
						"terminal": "admission-configuration",
					},
				},
				TypeMeta: metav1.TypeMeta{
					Kind:       "ValidatingWebhookConfiguration",
					APIVersion: "admissionregistration.k8s.io/v1beta1",
				},
				Webhooks: []admissionregistrationv1.ValidatingWebhook{
					{
						Name:           "test-validating-create-update-terminal.gardener.cloud",
						FailurePolicy:  &failPolicy,
						TimeoutSeconds: pointer.Int32Ptr(10),
						ClientConfig: admissionregistrationv1.WebhookClientConfig{
							Service: &admissionregistrationv1.ServiceReference{
								Path: &terminalValidatingWebhookPath,
							},
						},
						Rules:                   rules,
						AdmissionReviewVersions: []string{"v1", "v1beta1"},
						SideEffects:             &noSideEffects,
					},
				},
			},
		},
	}

	ginkgo.By("bootstrapping test environment")

	gardenTestEnv := &gardenenvtest.GardenerTestEnvironment{
		Environment: &envtest.Environment{
			CRDDirectoryPaths: []string{filepath.Join("..", "config", "crd", "bases")},
			ControlPlane: envtest.ControlPlane{
				APIServer: &envtest.APIServer{
					SecureServing: envtest.SecureServing{
						ListenAddr: envtest.ListenAddr{
							Address: os.Getenv("ENVTEST_APISERVER_ADDRESS"),
							Port:    os.Getenv("ENVTEST_APISERVER_PORT"),
						},
					},
				},
			},
			WebhookInstallOptions:    webhookInstallOptions,
			ControlPlaneStartTimeout: 2 * time.Minute,
			ControlPlaneStopTimeout:  2 * time.Minute,
		},
		GardenerAPIServer: &gardenenvtest.GardenerAPIServer{
			StopTimeout: 2 * time.Minute,
		},
	}

	cfg, err := gardenTestEnv.Start()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(cfg).NotTo(gomega.BeNil())

	gomega.Expect(dashboardv1alpha1.AddToScheme(kubernetes.GardenScheme)).NotTo(gomega.HaveOccurred())
	gomega.Expect(corev1.AddToScheme(kubernetes.GardenScheme)).NotTo(gomega.HaveOccurred())

	k8sClient, err := client.New(cfg, client.Options{Scheme: kubernetes.GardenScheme})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(k8sClient).NotTo(gomega.BeNil())

	//+kubebuilder:scaffold:scheme

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:             kubernetes.GardenScheme,
		LeaderElection:     false,
		Host:               gardenTestEnv.WebhookInstallOptions.LocalServingHost,
		Port:               gardenTestEnv.WebhookInstallOptions.LocalServingPort,
		CertDir:            gardenTestEnv.WebhookInstallOptions.LocalServingCertDir,
		MetricsBindAddress: "0", // disabled
	})
	gomega.Expect(err).ToNot(gomega.HaveOccurred())

	ginkgo.By("setting configuring webhook server")
	gomega.Expect(err).ToNot(gomega.HaveOccurred())

	hookServer := k8sManager.GetWebhookServer()
	hookServer.Register(terminalMutatingWebhookPath, &webhook.Admission{Handler: mutator})
	hookServer.Register(terminalValidatingWebhookPath, &webhook.Admission{Handler: validator})

	return Environment{
		gardenTestEnv,
		k8sManager,
		cfg,
		k8sClient,
	}
}

func (e Environment) Start(ctx context.Context) {
	go func() {
		defer ginkgo.GinkgoRecover()

		err := e.K8sManager.Start(ctx)
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
	}()

	ginkgo.By("waiting for webhook server to be ready")

	d := &net.Dialer{Timeout: time.Second}

	gomega.Eventually(func() error {
		serverURL := net.JoinHostPort(e.GardenEnv.WebhookInstallOptions.LocalServingHost, strconv.Itoa(e.GardenEnv.WebhookInstallOptions.LocalServingPort))
		conn, err := tls.DialWithDialer(d, "tcp", serverURL, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return err
		}
		return conn.Close()
	}).Should(gomega.Succeed())
}

type User struct {
	Name string
	// Groups are the groups to which the user belongs.
	Groups []string
}

// ServiceAccount represents a Kubernetes service account.
type ServiceAccount struct {
	// Name is the service acocunt's Name.
	Name string
	// Namespace is the service acocunt's Namespace.
	Namespace string
	// RoleRef is the desired roleRef for the ClusterRoleBinding. The service account will receive this role
	// +optional
	RoleRef *rbacv1.RoleRef
}

// AddClusterAdminServiceAccount adds a service account and creates a ClusterRoleBinding for this service account and cluster-admin ClusterRole.
func (e Environment) AddClusterAdminServiceAccount(ctx context.Context, name string, namespace string, timeout time.Duration, interval time.Duration) {
	e.AddServiceAccount(ctx, ServiceAccount{
		Name:      name,
		Namespace: namespace,
		RoleRef: &rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "cluster-admin",
		},
	}, timeout, interval)
}

// AddServiceAccount adds a service account and optionally also creates a ClusterRoleBinding for this service account for the given RoleRef of the passed ServiceAccount.
func (e Environment) AddServiceAccount(ctx context.Context, sa ServiceAccount, timeout time.Duration, interval time.Duration) {
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: sa.Name, Namespace: sa.Namespace}}
	key := client.ObjectKeyFromObject(serviceAccount)
	e.CreateObject(ctx, serviceAccount, key, timeout, interval)

	if sa.RoleRef != nil {
		crb := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s--%s-crb", serviceAccount.Name, serviceAccount.Namespace)},
			RoleRef:    *sa.RoleRef,
			Subjects: []rbacv1.Subject{
				{
					APIGroup:  "",
					Kind:      "ServiceAccount",
					Name:      serviceAccount.Name,
					Namespace: serviceAccount.Namespace,
				},
			},
		}
		crbKey := client.ObjectKeyFromObject(crb)
		e.CreateObject(ctx, crb, crbKey, timeout, interval)
	}
}

func (e Environment) CreateObject(ctx context.Context, obj client.Object, key types.NamespacedName, timeout time.Duration, interval time.Duration) {
	gomega.Expect(e.K8sClient.Create(ctx, obj)).Should(gomega.Succeed())
	gomega.Eventually(func() bool {
		err := e.K8sClient.Get(ctx, key, obj)
		return err == nil
	}, timeout, interval).Should(gomega.BeTrue())
}

var seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}

	return string(b)
}

func DefaultConfiguration() *dashboardv1alpha1.ControllerManagerConfiguration {
	return &dashboardv1alpha1.ControllerManagerConfiguration{
		Controllers: dashboardv1alpha1.ControllerManagerControllerConfiguration{
			Terminal: dashboardv1alpha1.TerminalControllerConfiguration{
				MaxConcurrentReconciles:             15,
				MaxConcurrentReconcilesPerNamespace: 3,
			},
			TerminalHeartbeat: dashboardv1alpha1.TerminalHeartbeatControllerConfiguration{
				MaxConcurrentReconciles: 1,
				TimeToLive:              dashboardv1alpha1.Duration{Duration: time.Duration(5) * time.Minute},
			},
			ServiceAccount: dashboardv1alpha1.ServiceAccountControllerConfiguration{
				MaxConcurrentReconciles: 1,
				AllowedServiceAccountNames: []string{
					"test-target-serviceaccount",
				},
			},
		},
		Webhooks: dashboardv1alpha1.ControllerManagerWebhookConfiguration{
			TerminalValidation: dashboardv1alpha1.TerminalValidatingWebhookConfiguration{
				MaxObjectSize: 10 * 1024,
			},
		},
		HonourServiceAccountRefHostCluster:   pointer.Bool(true),
		HonourServiceAccountRefTargetCluster: pointer.Bool(true),
		HonourProjectMemberships:             pointer.Bool(true),
		HonourCleanupProjectMembership:       pointer.Bool(true),
	}
}
