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

package controllers

import (
	"context"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/record"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	extensionsv1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
)

// TerminalHeartbeatReconciler reconciles a TerminalHeartbeat object
type TerminalHeartbeatReconciler struct {
	client.Client
	Log      logr.Logger
	Recorder record.EventRecorder
}

func (r *TerminalHeartbeatReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&extensionsv1alpha1.Terminal{}).
		Named("heartbeat").
		Complete(r)
}

func (r *TerminalHeartbeatReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()

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

	if !t.ObjectMeta.DeletionTimestamp.IsZero() {
		// ignore already deleted terminal resource
		return ctrl.Result{}, nil
	}

	lastHeartBeat := t.ObjectMeta.Annotations[extensionsv1alpha1.TerminalLastHeartBeat]
	if len(lastHeartBeat) == 0 {
		// if there is no heartbeat set, delete right away
		return ctrl.Result{}, r.deleteTerminal(ctx, t)
	}

	lastHeartBeatParsed, err := time.Parse(time.RFC3339, lastHeartBeat)
	if err != nil {
		return ctrl.Result{}, err
	}

	ttl := 5 * time.Minute // TODO make TTL configurable
	expiration := lastHeartBeatParsed.Add(time.Duration(ttl))
	if time.Now().UTC().After(expiration) {
		return ctrl.Result{}, r.deleteTerminal(ctx, t)
	}

	syncPeriod := int64(1 * time.Minute) // TODO make syncPeriod configurable
	return ctrl.Result{RequeueAfter: time.Duration(syncPeriod)}, nil
}

func (r *TerminalHeartbeatReconciler) deleteTerminal(ctx context.Context, t *extensionsv1alpha1.Terminal) error {
	r.Recorder.Eventf(t, corev1.EventTypeNormal, extensionsv1alpha1.EventDeleting, "Deleting terminal resource due to missing heartbeat")

	deleteCtx, cancelFunc := context.WithTimeout(ctx, time.Duration(30*time.Second)) // TODO make timeout configurable
	defer cancelFunc()
	if err := r.Delete(deleteCtx, t); err != nil {
		return err
	}
	r.Recorder.Eventf(t, corev1.EventTypeNormal, extensionsv1alpha1.EventDeleted, "Deleted terminal resource")
	return nil
}
