/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package controllers

import (
	"context"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"

	extensionsv1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
)

// TerminalHeartbeatReconciler reconciles a TerminalHeartbeat object
type TerminalHeartbeatReconciler struct {
	client.Client
	Recorder    record.EventRecorder
	Config      *extensionsv1alpha1.ControllerManagerConfiguration
	configMutex sync.RWMutex
}

func (r *TerminalHeartbeatReconciler) SetupWithManager(mgr ctrl.Manager, config extensionsv1alpha1.TerminalHeartbeatControllerConfiguration) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&extensionsv1alpha1.Terminal{}).
		Named("heartbeat").
		WithOptions(controller.Options{
			MaxConcurrentReconciles: config.MaxConcurrentReconciles,
		}).
		Complete(r)
}

func (r *TerminalHeartbeatReconciler) getConfig() *extensionsv1alpha1.ControllerManagerConfiguration {
	r.configMutex.RLock()
	defer r.configMutex.RUnlock()

	return r.Config
}

// Mainly used for tests to inject config
func (r *TerminalHeartbeatReconciler) injectConfig(config *extensionsv1alpha1.ControllerManagerConfiguration) {
	r.configMutex.Lock()
	defer r.configMutex.Unlock()

	r.Config = config
}

func (r *TerminalHeartbeatReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Fetch the TerminalHeartbeat instance
	t := &extensionsv1alpha1.Terminal{}

	err := r.Get(ctx, req.NamespacedName, t)
	if err != nil {
		if errors.IsNotFound(err) {
			// Object not found, return.  Created objects are automatically garbage collected.
			// For additional cleanup logic use finalizers.
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return ctrl.Result{}, err
	}

	if !t.DeletionTimestamp.IsZero() {
		// ignore already deleted terminal resource
		return ctrl.Result{}, nil
	}

	lastHeartbeat := t.Annotations[extensionsv1alpha1.TerminalLastHeartbeat]
	if len(lastHeartbeat) == 0 {
		// if there is no heartbeat set, delete right away
		return ctrl.Result{}, r.deleteTerminal(ctx, t)
	}

	lastHeartBeatParsed, err := time.Parse(time.RFC3339, lastHeartbeat)
	if err != nil {
		return ctrl.Result{}, r.deleteTerminal(ctx, t)
	}

	ttl := r.getConfig().Controllers.TerminalHeartbeat.TimeToLive.Duration
	expiration := lastHeartBeatParsed.Add(ttl)

	expiresIn := expiration.Sub(time.Now().UTC())
	if expiresIn <= 0 {
		return ctrl.Result{}, r.deleteTerminal(ctx, t)
	}

	return ctrl.Result{RequeueAfter: expiresIn}, nil
}

func (r *TerminalHeartbeatReconciler) deleteTerminal(ctx context.Context, t *extensionsv1alpha1.Terminal) error {
	r.recordEventAndLog(ctx, t, corev1.EventTypeNormal, extensionsv1alpha1.EventDeleting, "Deleting terminal resource due to missing heartbeat")

	deleteCtx, cancelFunc := context.WithTimeout(ctx, time.Duration(30*time.Second))
	defer cancelFunc()

	if err := r.Delete(deleteCtx, t); err != nil {
		return err
	}

	r.recordEventAndLog(ctx, t, corev1.EventTypeNormal, extensionsv1alpha1.EventDeleted, "Deleted terminal resource")

	return nil
}

func (r *TerminalHeartbeatReconciler) recordEventAndLog(ctx context.Context, t *extensionsv1alpha1.Terminal, eventType, reason, messageFmt string, args ...interface{}) {
	r.Recorder.Eventf(t, eventType, reason, messageFmt, args)
	log.FromContext(ctx).Info(fmt.Sprintf(messageFmt, args...))
}
