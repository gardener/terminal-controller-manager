/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package webhooks

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/test"
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.
var (
	e         test.Environment
	ctx       context.Context
	cancel    context.CancelFunc
	cmConfig  *v1alpha1.ControllerManagerConfiguration
	mutator   *TerminalMutator
	validator *TerminalValidator
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	SetDefaultEventuallyTimeout(30 * time.Second)
	RunSpecs(t, "Webhook Suite")
}

var _ = BeforeSuite(func() {
	ctx, cancel = context.WithCancel(context.TODO())

	cmConfig := test.DefaultConfiguration()

	mutator = &TerminalMutator{
		Log: ctrl.Log.WithName("webhooks").WithName("TerminalMutation"),
	}
	validator = &TerminalValidator{
		Log:    ctrl.Log.WithName("webhooks").WithName("TerminalValidation"),
		Config: cmConfig,
	}

	e = test.New(mutator, validator)

	mutator.Decoder = admission.NewDecoder(e.GardenEnv.Scheme)
	validator.Decoder = admission.NewDecoder(e.GardenEnv.Scheme)
	validator.Client = e.K8sClient

	e.Start(ctx)
})

var _ = AfterSuite(func() {
	cancel()
	By("tearing down the test environment")
	err := e.GardenEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})
