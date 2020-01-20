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

package main

import (
	"flag"
	"fmt"
	"os"

	"gopkg.in/yaml.v2"

	"sigs.k8s.io/controller-runtime/pkg/webhook"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"

	v1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/controllers"
	"github.com/gardener/terminal-controller-manager/webhooks/mutating"
	"github.com/gardener/terminal-controller-manager/webhooks/validating"
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

	cmConfig := readControllerManagerConfiguration(configFile)

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
		panic("could not create kubernetes client")
	}

	recorder := CreateRecorder(kube)

	if err = (&controllers.TerminalReconciler{
		ClientSet: controllers.NewClientSet(config, mgr.GetClient(), kube),
		Log:       ctrl.Log.WithName("controllers").WithName("Terminal"),
		Scheme:    mgr.GetScheme(),
		Recorder:  recorder,
	}).SetupWithManager(mgr, cmConfig.Controllers.Terminal); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Terminal")
		os.Exit(1)
	}

	if err = (&controllers.TerminalHeartbeatReconciler{
		Client:   mgr.GetClient(),
		Log:      ctrl.Log.WithName("controllers").WithName("TerminalHeartbeat"),
		Recorder: recorder,
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
	hookServer.Register("/mutate-terminal", &webhook.Admission{Handler: &mutating.TerminalMutator{}})
	hookServer.Register("/validate-terminal", &webhook.Admission{Handler: &validating.TerminalValidator{}})

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

func readControllerManagerConfiguration(configFile string) *v1alpha1.ControllerManagerConfiguration {
	// Default configuration
	cfg := v1alpha1.ControllerManagerConfiguration{
		Controllers: v1alpha1.ControllerManagerControllerConfiguration{
			Terminal: v1alpha1.TerminalControllerConfiguration{
				MaxConcurrentReconciles: 5,
			},
			TerminalHeartbeat: v1alpha1.TerminalHeartbeatControllerConfiguration{
				MaxConcurrentReconciles: 1,
			},
		},
		Logger: v1alpha1.ControllerManagerLoggerConfiguration{
			Development: true,
		},
	}

	readFile(configFile, &cfg)

	return &cfg
}

func readFile(configFile string, cfg *v1alpha1.ControllerManagerConfiguration) {
	f, err := os.Open(configFile)
	if err != nil {
		processError(err)
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)

	err = decoder.Decode(cfg)
	if err != nil {
		processError(err)
	}
}

func processError(err error) {
	fmt.Println(err)
	os.Exit(2)
}
