/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package webhooks

import (
	"context"
	"testing"
	"time"

	"github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/test"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
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
	RunSpecsWithDefaultAndCustomReporters(t,
		"Webhook Suite",
		[]Reporter{printer.NewlineReporter{}})
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

	e = test.New(cmConfig, mutator, validator)
	e.Start()
}, 60)

var _ = AfterSuite(func() {
	cancel()
	By("tearing down the test environment")
	err := e.GardenEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
}, 10)
