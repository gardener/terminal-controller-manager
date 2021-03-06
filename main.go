/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/gardener/terminal-controller-manager/webhooks"

	"k8s.io/apimachinery/pkg/util/validation/field"

	"gopkg.in/yaml.v2"

	"sigs.k8s.io/controller-runtime/pkg/webhook"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/controllers"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	// +kubebuilder:scaffold:scheme
	_ = clientgoscheme.AddToScheme(scheme)

	_ = v1alpha1.AddToScheme(scheme)
	_ = gardencorev1beta1.AddToScheme(scheme)
}

func main() {
	var (
		metricsAddr          string
		enableLeaderElection bool
		certDir              string
		configFile           string
	)

	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&certDir, "cert-dir", "/tmp/k8s-webhook-server/serving-certs", "CertDir is the directory that contains the server key and certificate.")
	flag.StringVar(&configFile, "config-file", "/etc/terminal-controller-manager/config.yaml", "The path to the configuration file.")
	flag.Parse()

	cmConfig, err := readControllerManagerConfiguration(configFile)
	if err != nil {
		fmt.Printf("error reading config: %s", err.Error()) // Logger not yet set up
		os.Exit(1)
	}

	ctrl.SetLogger(zap.New(func(o *zap.Options) {
		o.Development = cmConfig.Logger.Development
	}))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		LeaderElectionID:   "terminal-controller-leader-election",
		LeaderElection:     enableLeaderElection,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	config := mgr.GetConfig()

	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		setupLog.Error(err, "could not create kubernetes client")
		os.Exit(1)
	}

	recorder := CreateRecorder(kube)

	if err = (&controllers.TerminalReconciler{
		ClientSet:                   controllers.NewClientSet(config, mgr.GetClient(), kube),
		Log:                         ctrl.Log.WithName("controllers").WithName("Terminal"),
		Scheme:                      mgr.GetScheme(),
		Recorder:                    recorder,
		Config:                      cmConfig,
		ReconcilerCountPerNamespace: map[string]int{},
	}).SetupWithManager(mgr, cmConfig.Controllers.Terminal); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Terminal")
		os.Exit(1)
	}

	if err = (&controllers.TerminalHeartbeatReconciler{
		Client:   mgr.GetClient(),
		Log:      ctrl.Log.WithName("controllers").WithName("TerminalHeartbeat"),
		Recorder: recorder,
		Config:   cmConfig,
	}).SetupWithManager(mgr, cmConfig.Controllers.TerminalHeartbeat); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "TerminalHeartbeat")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	// Setup webhooks
	setupLog.Info("setting up webhook server")

	hookServer := &webhook.Server{
		Port:    9443,
		CertDir: certDir,
	}
	if err := mgr.Add(hookServer); err != nil {
		setupLog.Error(err, "unable register webhook server with manager")
		os.Exit(1)
	}

	setupLog.Info("registering webhooks to the webhook server")
	hookServer.Register("/mutate-terminal", &webhook.Admission{Handler: &webhooks.TerminalMutator{
		Log: ctrl.Log.WithName("webhooks").WithName("TerminalMutation"),
	}})
	hookServer.Register("/validate-terminal", &webhook.Admission{Handler: &webhooks.TerminalValidator{
		Log:    ctrl.Log.WithName("webhooks").WithName("TerminalValidation"),
		Config: cmConfig,
	}})

	setupLog.Info("starting manager")

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func CreateRecorder(kubeClient kubernetes.Interface) record.EventRecorder {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartRecordingToSink(&v1.EventSinkImpl{Interface: v1.New(kubeClient.CoreV1().RESTClient()).Events("")})

	return eventBroadcaster.NewRecorder(scheme, corev1.EventSource{Component: v1alpha1.TerminalComponent})
}

func readControllerManagerConfiguration(configFile string) (*v1alpha1.ControllerManagerConfiguration, error) {
	// Default configuration
	cfg := v1alpha1.ControllerManagerConfiguration{
		Controllers: v1alpha1.ControllerManagerControllerConfiguration{
			Terminal: v1alpha1.TerminalControllerConfiguration{
				MaxConcurrentReconciles:             15,
				MaxConcurrentReconcilesPerNamespace: 3,
			},
			TerminalHeartbeat: v1alpha1.TerminalHeartbeatControllerConfiguration{
				MaxConcurrentReconciles: 1,
				TimeToLive:              v1alpha1.Duration{Duration: time.Duration(5) * time.Minute},
			},
		},
		Webhooks: v1alpha1.ControllerManagerWebhookConfiguration{
			TerminalValidation: v1alpha1.TerminalValidatingWebhookConfiguration{
				MaxObjectSize: 10 * 1024,
			},
		},
		Logger: v1alpha1.ControllerManagerLoggerConfiguration{
			Development: true,
		},
		HonourServiceAccountRefHostCluster:   true,
		HonourServiceAccountRefTargetCluster: true,
		HonourProjectMemberships:             true,
	}

	if err := readFile(configFile, &cfg); err != nil {
		return nil, err
	}

	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func readFile(configFile string, cfg *v1alpha1.ControllerManagerConfiguration) error {
	f, err := os.Open(configFile)
	if err != nil {
		return err
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)

	return decoder.Decode(cfg)
}

func validateConfig(cfg *v1alpha1.ControllerManagerConfiguration) error {
	if cfg.Controllers.Terminal.MaxConcurrentReconciles < 1 {
		fldPath := field.NewPath("controllers", "terminal", "maxConcurrentReconciles")
		return field.Invalid(fldPath, cfg.Controllers.Terminal.MaxConcurrentReconciles, "must be 1 or greater")
	}

	if cfg.Controllers.TerminalHeartbeat.MaxConcurrentReconciles < 1 {
		fldPath := field.NewPath("controllers", "terminalHeartbeat", "maxConcurrentReconciles")
		return field.Invalid(fldPath, cfg.Controllers.TerminalHeartbeat.MaxConcurrentReconciles, "must be 1 or greater")
	}

	if cfg.Controllers.Terminal.MaxConcurrentReconcilesPerNamespace > cfg.Controllers.Terminal.MaxConcurrentReconciles {
		fldPath := field.NewPath("controllers", "terminal", "maxConcurrentReconcilesPerNamespace")
		return field.Invalid(fldPath, cfg.Controllers.Terminal.MaxConcurrentReconcilesPerNamespace, "must not be greater than maxConcurrentReconciles")
	}

	return nil
}
