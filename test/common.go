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
	"net/url"
	"os"
	"path/filepath"
	"time"

	ginkgo "github.com/onsi/ginkgo"
	gomega "github.com/onsi/gomega"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	dashboardv1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
	//+kubebuilder:scaffold:imports
)

//var cfg *rest.Config
var k8sClient client.Client
var testEnv *envtest.Environment

var (
	terminalMutatingWebhookPath   = "/terminal/mutate"
	terminalValidatingWebhookPath = "/terminal/validate"
)

type Environment struct {
	Env        *envtest.Environment
	K8sManager ctrl.Manager
	Config     *rest.Config
	K8sClient  client.Client
}

func New(cmConfig *dashboardv1alpha1.ControllerManagerConfiguration, mutator admission.Handler, validator admission.Handler) Environment {
	logf.SetLogger(zap.New(zap.WriteTo(ginkgo.GinkgoWriter), zap.UseDevMode(true)))

	ginkgo.By("bootstrapping test environment")

	failPolicy := admissionregistrationv1beta1.Fail
	timeoutSeconds := int32(2)
	rules := []admissionregistrationv1beta1.RuleWithOperations{
		{
			Operations: []admissionregistrationv1beta1.OperationType{
				admissionregistrationv1beta1.Create,
				admissionregistrationv1beta1.Update,
			},
			Rule: admissionregistrationv1beta1.Rule{
				APIGroups:   []string{"dashboard.gardener.cloud"},
				APIVersions: []string{"v1alpha1"},
				Resources:   []string{"terminals"},
			},
		},
	}

	webhookInstallOptions := envtest.WebhookInstallOptions{
		//LocalServingHostExternalName: "host.docker.internal",
		MutatingWebhooks: []client.Object{
			&admissionregistrationv1beta1.MutatingWebhookConfiguration{
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
				Webhooks: []admissionregistrationv1beta1.MutatingWebhook{
					{
						Name:           "test-mutating-create-update-terminal.gardener.cloud",
						FailurePolicy:  &failPolicy,
						TimeoutSeconds: &timeoutSeconds,
						ClientConfig: admissionregistrationv1beta1.WebhookClientConfig{
							Service: &admissionregistrationv1beta1.ServiceReference{
								Path: &terminalMutatingWebhookPath,
							},
							//URL: &terminalMutatingWebhookUrl,
						},
						Rules: rules,
					},
				},
			},
		},
		ValidatingWebhooks: []client.Object{
			&admissionregistrationv1beta1.ValidatingWebhookConfiguration{
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
				Webhooks: []admissionregistrationv1beta1.ValidatingWebhook{
					{
						Name:           "test-validating-create-update-terminal.gardener.cloud",
						FailurePolicy:  &failPolicy,
						TimeoutSeconds: &timeoutSeconds,
						ClientConfig: admissionregistrationv1beta1.WebhookClientConfig{
							Service: &admissionregistrationv1beta1.ServiceReference{
								Path: &terminalValidatingWebhookPath,
							},
							//URL: &terminalValidatingWebhookUrl,
						},
						Rules: rules,
					},
				},
			},
		},
	}

	var apiServerURL *url.URL

	apiServer := os.Getenv("ENVTEST_APISERVER_URL")
	if apiServer != "" {
		var err error
		apiServerURL, err = url.Parse(apiServer)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	}

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
		ControlPlane: envtest.ControlPlane{
			APIServer: &envtest.APIServer{
				URL: apiServerURL,
			},
		},
		WebhookInstallOptions: webhookInstallOptions,
	}

	cfg, err := testEnv.Start()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(cfg).NotTo(gomega.BeNil())

	err = dashboardv1alpha1.AddToScheme(scheme.Scheme)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(k8sClient).NotTo(gomega.BeNil())

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:             scheme.Scheme,
		LeaderElection:     false,
		Host:               testEnv.WebhookInstallOptions.LocalServingHost,
		Port:               testEnv.WebhookInstallOptions.LocalServingPort,
		CertDir:            testEnv.WebhookInstallOptions.LocalServingCertDir,
		MetricsBindAddress: "0", // disabled
	})
	gomega.Expect(err).ToNot(gomega.HaveOccurred())

	ginkgo.By("setting configuring webhook server")
	gomega.Expect(err).ToNot(gomega.HaveOccurred())

	hookServer := k8sManager.GetWebhookServer()
	hookServer.Register(terminalMutatingWebhookPath, &webhook.Admission{Handler: mutator})
	hookServer.Register(terminalValidatingWebhookPath, &webhook.Admission{Handler: validator})

	return Environment{
		testEnv,
		k8sManager,
		cfg,
		k8sClient,
	}
}

func (e Environment) Start() {
	go func() {
		err := e.K8sManager.Start(ctrl.SetupSignalHandler())
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
	}()

	ginkgo.By("waiting for webhook server to be ready")

	d := &net.Dialer{Timeout: time.Second}

	gomega.Eventually(func() error {
		serverURL := fmt.Sprintf("%s:%d", testEnv.WebhookInstallOptions.LocalServingHost, testEnv.WebhookInstallOptions.LocalServingPort)
		conn, err := tls.DialWithDialer(d, "tcp", serverURL, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return err
		}
		return conn.Close()
	}).Should(gomega.Succeed())
}

var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}

	return string(b)
}

func CreateObject(ctx context.Context, k8sClient client.Client, obj client.Object, key types.NamespacedName, timeout time.Duration, interval time.Duration) {
	gomega.Expect(k8sClient.Create(ctx, obj)).Should(gomega.Succeed())
	gomega.Eventually(func() bool {
		err := k8sClient.Get(ctx, key, obj)
		return err == nil
	}, timeout, interval).Should(gomega.BeTrue())
}
func CreateServiceAccountSecret(ctx context.Context, k8sClient client.Client, serviceAccount *v1.ServiceAccount, timeout time.Duration, interval time.Duration) {
	tokenSecretName := serviceAccount.Name + "-token"
	tokenSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tokenSecretName,
			Namespace: serviceAccount.Namespace,
			Annotations: map[string]string{
				v1.ServiceAccountNameKey: serviceAccount.Name,
				v1.ServiceAccountUIDKey:  string(serviceAccount.UID),
			},
		},
		Data: map[string][]byte{
			"token": []byte(""),
		},
		Type: v1.SecretTypeServiceAccountToken,
	}
	secretTokenKey := types.NamespacedName{Name: tokenSecret.Name, Namespace: tokenSecret.Namespace}
	CreateObject(ctx, k8sClient, tokenSecret, secretTokenKey, timeout, interval)

	serviceAccount.Secrets = []v1.ObjectReference{
		{
			Kind:            "Secret",
			Namespace:       serviceAccount.Namespace,
			Name:            tokenSecretName,
			UID:             "",
			APIVersion:      "",
			ResourceVersion: "",
			FieldPath:       "",
		},
	}
	gomega.Expect(k8sClient.Update(ctx, serviceAccount)).Should(gomega.Succeed())
}
func CreateServiceAccount(ctx context.Context, k8sClient client.Client, name string, namespace string, timeout time.Duration, interval time.Duration) {
	serviceAccount := &v1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
	key := types.NamespacedName{Name: serviceAccount.Name, Namespace: serviceAccount.Namespace}
	CreateObject(ctx, k8sClient, serviceAccount, key, timeout, interval)

	CreateServiceAccountSecret(ctx, k8sClient, serviceAccount, timeout, interval)
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
		},
		Webhooks: dashboardv1alpha1.ControllerManagerWebhookConfiguration{
			TerminalValidation: dashboardv1alpha1.TerminalValidatingWebhookConfiguration{
				MaxObjectSize: 10 * 1024,
			},
		},
		Logger: dashboardv1alpha1.ControllerManagerLoggerConfiguration{
			Development: true,
		},
		HonourServiceAccountRefHostCluster:   true,
		HonourServiceAccountRefTargetCluster: true,
		HonourProjectMemberships:             true,
	}
}
