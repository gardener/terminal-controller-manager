/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package controllers

import (
	"context"
	"testing"
	"time"

	"github.com/gardener/gardener/pkg/api/indexer"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	dashboardv1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/internal/gardenclient"
	"github.com/gardener/terminal-controller-manager/test"
	"github.com/gardener/terminal-controller-manager/webhooks"
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

const (
	randomLength = 5
	charset      = "abcdefghijklmnopqrstuvwxyz0123456789"
)

var (
	e                           test.Environment
	ctx                         context.Context
	cancel                      context.CancelFunc
	cmConfig                    *dashboardv1alpha1.ControllerManagerConfiguration
	mutator                     *webhooks.TerminalMutator
	validator                   *webhooks.TerminalValidator
	terminalReconciler          *TerminalReconciler
	terminalHeartbeatReconciler *TerminalHeartbeatReconciler
	serviceAccountReconciler    *ServiceAccountReconciler
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	SetDefaultEventuallyTimeout(30 * time.Second)
	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	ctx, cancel = context.WithCancel(context.TODO())

	cmConfig = test.DefaultConfiguration()

	mutator = &webhooks.TerminalMutator{
		Log: ctrl.Log.WithName("webhooks").WithName("TerminalMutation"),
	}
	validator = &webhooks.TerminalValidator{
		Log:    ctrl.Log.WithName("webhooks").WithName("TerminalValidation"),
		Config: cmConfig,
	}

	e = test.New(mutator, validator)

	mutator.Decoder = admission.NewDecoder(e.GardenEnv.Scheme)
	validator.Decoder = admission.NewDecoder(e.GardenEnv.Scheme)
	validator.Client = e.K8sClient

	kube, err := kubernetes.NewForConfig(e.Config)
	Expect(err).ToNot(HaveOccurred())

	recorder := CreateRecorder(kube, e.K8sManager.GetScheme())

	terminalReconciler = &TerminalReconciler{
		ClientSet:                   gardenclient.NewClientSet(e.Config, e.K8sManager.GetClient(), kube),
		Scheme:                      e.K8sManager.GetScheme(),
		Recorder:                    recorder,
		Config:                      cmConfig,
		ReconcilerCountPerNamespace: map[string]int{},
	}
	err = terminalReconciler.SetupWithManager(e.K8sManager, cmConfig.Controllers.Terminal)
	Expect(err).ToNot(HaveOccurred())

	terminalHeartbeatReconciler = &TerminalHeartbeatReconciler{
		Client:   e.K8sManager.GetClient(),
		Recorder: recorder,
		Config:   cmConfig,
	}
	err = terminalHeartbeatReconciler.SetupWithManager(e.K8sManager, cmConfig.Controllers.TerminalHeartbeat)
	Expect(err).ToNot(HaveOccurred())

	serviceAccountReconciler = &ServiceAccountReconciler{
		Client:   e.K8sManager.GetClient(),
		Recorder: recorder,
		Config:   cmConfig,
		Log:      ctrl.Log.WithName("controllers").WithName("ServiceAccount"),
	}
	err = serviceAccountReconciler.SetupWithManager(e.K8sManager, cmConfig.Controllers.ServiceAccount)
	Expect(err).ToNot(HaveOccurred())

	err = indexer.AddProjectNamespace(ctx, e.K8sManager.GetFieldIndexer())
	Expect(err).ToNot(HaveOccurred())

	e.Start(ctx)
})

// TODO reuse from main
func CreateRecorder(kubeClient kubernetes.Interface, scheme *runtime.Scheme) record.EventRecorder {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartRecordingToSink(&v1.EventSinkImpl{Interface: v1.New(kubeClient.CoreV1().RESTClient()).Events("")})

	return eventBroadcaster.NewRecorder(scheme, corev1.EventSource{Component: dashboardv1alpha1.TerminalComponent})
}

var _ = AfterSuite(func() {
	cancel()
	By("tearing down the test environment")
	if e.GardenEnv == nil {
		return
	}
	err := e.GardenEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})
