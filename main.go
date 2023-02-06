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

	"github.com/gardener/gardener/pkg/api/indexer"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
	"k8s.io/component-base/config"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/controllers"
	"github.com/gardener/terminal-controller-manager/internal/gardenclient"
	"github.com/gardener/terminal-controller-manager/webhooks"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	// +kubebuilder:scaffold:scheme
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(v1alpha1.AddToScheme(scheme))
	utilruntime.Must(gardencorev1beta1.AddToScheme(scheme))
}

func main() {
	var (
		certDir    string
		configFile string
	)

	flag.StringVar(&certDir, "cert-dir", "/tmp/k8s-webhook-server/serving-certs", "CertDir is the directory that contains the server key and certificate.")
	flag.StringVar(&configFile, "config-file", "/etc/terminal-controller-manager/config.yaml", "The path to the configuration file.")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	cmConfig, err := readControllerManagerConfiguration(configFile)
	if err != nil {
		setupLog.Error(err, "error reading config")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: fmt.Sprintf("%s:%d", cmConfig.Server.HealthProbes.BindAddress, cmConfig.Server.HealthProbes.Port),
		MetricsBindAddress:     fmt.Sprintf("%s:%d", cmConfig.Server.Metrics.BindAddress, cmConfig.Server.Metrics.Port),
		Port:                   9443,
		CertDir:                certDir,

		LeaderElection:                cmConfig.LeaderElection.LeaderElect,
		LeaderElectionResourceLock:    cmConfig.LeaderElection.ResourceLock,
		LeaderElectionID:              cmConfig.LeaderElection.ResourceName,
		LeaderElectionNamespace:       cmConfig.LeaderElection.ResourceNamespace,
		LeaderElectionReleaseOnCancel: true,
		LeaseDuration:                 &cmConfig.LeaderElection.LeaseDuration.Duration,
		RenewDeadline:                 &cmConfig.LeaderElection.RenewDeadline.Duration,
		RetryPeriod:                   &cmConfig.LeaderElection.RetryPeriod.Duration,
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
		ClientSet:                   gardenclient.NewClientSet(config, mgr.GetClient(), kube),
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
		Recorder: recorder,
		Config:   cmConfig,
	}).SetupWithManager(mgr, cmConfig.Controllers.TerminalHeartbeat); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "TerminalHeartbeat")
		os.Exit(1)
	}

	if err = (&controllers.ServiceAccountReconciler{
		Client:   mgr.GetClient(),
		Recorder: recorder,
		Config:   cmConfig,
		Log:      ctrl.Log.WithName("controllers").WithName("ServiceAccount"),
	}).SetupWithManager(mgr, cmConfig.Controllers.ServiceAccount); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ServiceAccount")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}

	if err := mgr.AddReadyzCheck("readyz", mgr.GetWebhookServer().StartedChecker()); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	// Setup webhooks
	setupLog.Info("setting up webhook server")

	hookServer := mgr.GetWebhookServer()

	setupLog.Info("registering webhooks to the webhook server")
	hookServer.Register("/mutate-terminal", &webhook.Admission{Handler: &webhooks.TerminalMutator{
		Log: ctrl.Log.WithName("webhooks").WithName("TerminalMutation"),
	}})
	hookServer.Register("/validate-terminal", &webhook.Admission{Handler: &webhooks.TerminalValidator{
		Log:    ctrl.Log.WithName("webhooks").WithName("TerminalValidation"),
		Config: cmConfig,
	}})

	ctx := ctrl.SetupSignalHandler()

	if err = indexer.AddProjectNamespace(ctx, mgr.GetFieldIndexer()); err != nil {
		setupLog.Error(err, "unable to add project namespace field indexer")
		os.Exit(1)
	}

	setupLog.Info("starting manager")

	if err := mgr.Start(ctx); err != nil {
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
		Server: v1alpha1.ServerConfiguration{
			HealthProbes: &v1alpha1.Server{
				BindAddress: "",
				Port:        8081,
			},
			Metrics: &v1alpha1.Server{
				BindAddress: "",
				Port:        8080,
			},
		},
		Controllers: v1alpha1.ControllerManagerControllerConfiguration{
			Terminal: v1alpha1.TerminalControllerConfiguration{
				MaxConcurrentReconciles:             15,
				MaxConcurrentReconcilesPerNamespace: 3,
			},
			TerminalHeartbeat: v1alpha1.TerminalHeartbeatControllerConfiguration{
				MaxConcurrentReconciles: 1,
				TimeToLive:              v1alpha1.Duration{Duration: time.Duration(5) * time.Minute},
			},
			ServiceAccount: v1alpha1.ServiceAccountControllerConfiguration{
				MaxConcurrentReconciles: 1,
			},
		},
		Webhooks: v1alpha1.ControllerManagerWebhookConfiguration{
			TerminalValidation: v1alpha1.TerminalValidatingWebhookConfiguration{
				MaxObjectSize: 10 * 1024,
			},
		},
		HonourServiceAccountRefHostCluster:   pointer.Bool(true),
		HonourServiceAccountRefTargetCluster: pointer.Bool(true),
		HonourProjectMemberships:             pointer.Bool(true),
		HonourCleanupProjectMembership:       pointer.Bool(false),

		LeaderElection: &config.LeaderElectionConfiguration{
			LeaderElect:       true,
			LeaseDuration:     metav1.Duration{Duration: 15 * time.Second},
			RenewDeadline:     metav1.Duration{Duration: 10 * time.Second},
			RetryPeriod:       metav1.Duration{Duration: 2 * time.Second},
			ResourceLock:      resourcelock.LeasesResourceLock,
			ResourceName:      "terminal-controller-leader-election",
			ResourceNamespace: "terminal-system",
		},
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

	defer func() {
		utilruntime.HandleError(f.Close())
	}()

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
