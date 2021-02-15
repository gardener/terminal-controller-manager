/*
Copyright 2021.

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
	"context"
	"testing"
	"time"

	"github.com/gardener/terminal-controller-manager/test"
	"github.com/gardener/terminal-controller-manager/webhooks"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"

	dashboardv1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	//+kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

const (
	randomLength = 5
	charset      = "abcdefghijklmnopqrstuvwxyz0123456789"
)

var (
	k8sClient                   client.Client
	testEnv                     *envtest.Environment
	ctx                         context.Context
	cancel                      context.CancelFunc
	k8sManager                  ctrl.Manager
	cmConfig                    *dashboardv1alpha1.ControllerManagerConfiguration
	mutator                     *webhooks.TerminalMutator
	validator                   *webhooks.TerminalValidator
	terminalReconciler          *TerminalReconciler
	terminalHeartbeatReconciler *TerminalHeartbeatReconciler
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	SetDefaultEventuallyTimeout(30 * time.Second)
	RunSpecsWithDefaultAndCustomReporters(t,
		"Controller Suite",
		[]Reporter{printer.NewlineReporter{}})
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

	environment := test.New(cmConfig, mutator, validator)
	testEnv = environment.Env
	k8sManager = environment.K8sManager
	k8sClient = environment.K8sClient
	cfg := environment.Config

	kube, err := kubernetes.NewForConfig(cfg)
	Expect(err).ToNot(HaveOccurred())

	recorder := CreateRecorder(kube, k8sManager.GetScheme())

	terminalReconciler = &TerminalReconciler{
		ClientSet:                   NewClientSet(cfg, k8sManager.GetClient(), kube),
		Log:                         ctrl.Log.WithName("controllers").WithName("Terminal"),
		Scheme:                      k8sManager.GetScheme(),
		Recorder:                    recorder,
		Config:                      cmConfig,
		ReconcilerCountPerNamespace: map[string]int{},
	}
	err = terminalReconciler.SetupWithManager(k8sManager, cmConfig.Controllers.Terminal)
	Expect(err).ToNot(HaveOccurred())

	terminalHeartbeatReconciler = &TerminalHeartbeatReconciler{
		Client:   k8sManager.GetClient(),
		Log:      ctrl.Log.WithName("controllers").WithName("TerminalHeartbeat"),
		Recorder: recorder,
		Config:   cmConfig,
	}
	err = terminalHeartbeatReconciler.SetupWithManager(k8sManager, cmConfig.Controllers.TerminalHeartbeat)
	Expect(err).ToNot(HaveOccurred())

	environment.Start()
}, 60)

// TODO reuse from main
func CreateRecorder(kubeClient kubernetes.Interface, scheme *runtime.Scheme) record.EventRecorder {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartRecordingToSink(&v1.EventSinkImpl{Interface: v1.New(kubeClient.CoreV1().RESTClient()).Events("")})

	return eventBroadcaster.NewRecorder(scheme, corev1.EventSource{Component: dashboardv1alpha1.TerminalComponent})
}

var _ = AfterSuite(func() {
	cancel()
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
}, 5)
