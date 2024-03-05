/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package controllers

import (
	"context"
	"sync"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	extensionsv1alpha1 "github.com/gardener/terminal-controller-manager/api/v1alpha1"
	"github.com/gardener/terminal-controller-manager/internal/gardenclient"
	"github.com/gardener/terminal-controller-manager/internal/utils"
)

// ServiceAccountReconciler reconciles a ServiceAccount object
type ServiceAccountReconciler struct {
	client.Client
	Log         logr.Logger
	Recorder    record.EventRecorder
	Config      *extensionsv1alpha1.ControllerManagerConfiguration
	configMutex sync.RWMutex
}

// SetupWithManager sets up manager with a new controller and r as the reconcile.Reconciler
func (r *ServiceAccountReconciler) SetupWithManager(mgr ctrl.Manager, config extensionsv1alpha1.ServiceAccountControllerConfiguration) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ServiceAccount{}, builder.WithPredicates(r.serviceAccountPredicate())).
		Watches(
			&extensionsv1alpha1.Terminal{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []reconcile.Request {
				// request reconciliation for service accounts that are referenced in deleted terminals and for which CleanupProjectMembership was set to true.
				logger := r.Log.WithValues("terminal", client.ObjectKeyFromObject(obj))

				terminal, ok := obj.(*extensionsv1alpha1.Terminal)
				if !ok {
					logger.Error(nil, "object cannot be converted to Terminal")
					return []reconcile.Request{}
				}

				if !ptr.Deref(terminal.Spec.Target.CleanupProjectMembership, false) || terminal.Spec.Target.Credentials.ServiceAccountRef == nil {
					// cleanup project membership not set or no service account referenced - nothing to do
					return []reconcile.Request{}
				}

				return []reconcile.Request{
					{
						NamespacedName: types.NamespacedName{
							Namespace: terminal.Spec.Target.Credentials.ServiceAccountRef.Namespace,
							Name:      terminal.Spec.Target.Credentials.ServiceAccountRef.Name,
						},
					},
				}
			}),
			builder.WithPredicates(r.terminalPredicate())).
		Named("serviceaccount").
		WithOptions(controller.Options{
			MaxConcurrentReconciles: config.MaxConcurrentReconciles,
		}).
		Complete(r)
}

// serviceAccountPredicate returns true for service accounts having the TerminalReference label
func (r *ServiceAccountReconciler) serviceAccountPredicate() predicate.Funcs {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			logger := r.Log.WithValues("event", e)

			if e.Object == nil {
				logger.Error(nil, "Create event has no runtime object to create")
				return false
			}

			obj, ok := e.Object.(*corev1.ServiceAccount)
			if !ok {
				logger.Error(nil, "Update event runtime object cannot be converted to ServiceAccount")
				return false
			}

			nameAllowed := utils.IsAllowed(r.getConfig().Controllers.ServiceAccount.AllowedServiceAccountNames, obj.Name)
			if !nameAllowed {
				logger.Info("service account name is not on allow-list -> event will be ignored")
				return false
			}

			if obj.Labels[extensionsv1alpha1.TerminalReference] == "true" {
				return true
			}

			// no change detected that is relevant for this controller
			return false
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			logger := r.Log.WithValues("event", e)

			if e.ObjectOld == nil {
				logger.Error(nil, "Update event has no old runtime object to update")
				return false
			}

			if e.ObjectNew == nil {
				logger.Error(nil, "Update event has no new runtime object for update")
				return false
			}

			oldObj, ok := e.ObjectOld.(*corev1.ServiceAccount)
			if !ok {
				logger.Error(nil, "Update event old runtime object cannot be converted to ServiceAccount")
				return false
			}

			nameAllowed := utils.IsAllowed(r.getConfig().Controllers.ServiceAccount.AllowedServiceAccountNames, oldObj.Name)
			if !nameAllowed {
				logger.Info("service account name is not on allow-list -> event will be ignored")
				return false
			}

			newObj, ok := e.ObjectNew.(*corev1.ServiceAccount)
			if !ok {
				logger.Error(nil, "Update event new runtime object cannot be converted to ServiceAccount")
				return false
			}

			// TerminalReference label has changed to true - event should be processed
			if oldObj.Labels[extensionsv1alpha1.TerminalReference] != newObj.Labels[extensionsv1alpha1.TerminalReference] &&
				newObj.Labels[extensionsv1alpha1.TerminalReference] == "true" {
				return true
			}

			// ServiceAccount was marked for deletion - event should be processed
			if oldObj.ObjectMeta.DeletionTimestamp.IsZero() && !newObj.ObjectMeta.DeletionTimestamp.IsZero() {
				return true
			}

			// no change detected that is relevant for this controller
			return false
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			logger := r.Log.WithValues("event", e)

			if e.Object == nil {
				logger.Error(nil, "Create event has no runtime object to create")
				return false
			}

			obj, ok := e.Object.(*corev1.ServiceAccount)
			if !ok {
				logger.Error(nil, "Update event runtime object cannot be converted to ServiceAccount")
				return false
			}

			nameAllowed := utils.IsAllowed(r.getConfig().Controllers.ServiceAccount.AllowedServiceAccountNames, obj.Name)
			if !nameAllowed {
				logger.Info("service account name is not on allow-list -> event will be ignored")
				return false
			}

			if controllerutil.ContainsFinalizer(obj, extensionsv1alpha1.ExternalTerminalName) {
				return true
			}

			if obj.Labels[extensionsv1alpha1.TerminalReference] == "true" {
				return true
			}

			// no change detected that is relevant for this controller
			return false
		},
	}
}

// terminalPredicate returns true for delete events of Terminal resources, where a service account is referenced and the CleanupProjectMembership flag is true
func (r *ServiceAccountReconciler) terminalPredicate() predicate.Funcs {
	return predicate.Funcs{
		CreateFunc: func(_ event.CreateEvent) bool {
			return false
		},
		UpdateFunc: func(_ event.UpdateEvent) bool {
			return false
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			logger := r.Log.WithValues("event", e)

			if e.Object == nil {
				logger.Error(nil, "Delete event has no old runtime object to update")
				return false
			}

			terminal, ok := e.Object.(*extensionsv1alpha1.Terminal)
			if !ok {
				logger.Error(nil, "Delete event runtime object cannot be converted to Terminal")
				return false
			}

			if !ptr.Deref(terminal.Spec.Target.CleanupProjectMembership, false) || terminal.Spec.Target.Credentials.ServiceAccountRef == nil {
				// cleanup project membership not set or no service account referenced - terminal resource is not relevant for this controller
				return false
			}

			return true
		},
		GenericFunc: func(_ event.GenericEvent) bool {
			return false
		},
	}
}

func (r *ServiceAccountReconciler) getConfig() *extensionsv1alpha1.ControllerManagerConfiguration {
	r.configMutex.RLock()
	defer r.configMutex.RUnlock()

	return r.Config
}

// Reconcile implements reconcile.Reconciler.
func (r *ServiceAccountReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Log.WithValues("serviceAccount", req.NamespacedName)
	logger.Info("Reconciling ServiceAccount")

	{ // serviceAccount-variable scope
		serviceAccount := &corev1.ServiceAccount{}

		if err := r.Get(ctx, req.NamespacedName, serviceAccount); err != nil {
			// IgnoreNotFound: if the service account is already gone we assume the project membership is already clean and do not attempt to clean it up
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}

		if serviceAccount.Labels[extensionsv1alpha1.TerminalReference] != "true" {
			logger.Info("service account is not labeled to have a terminal reference. Removing finalizer")

			return ctrl.Result{}, r.removeFinalizer(ctx, req)
		}
	}

	nameAllowed := utils.IsAllowed(r.getConfig().Controllers.ServiceAccount.AllowedServiceAccountNames, req.Name)
	if !nameAllowed {
		logger.Info("service account name is not on allow-list and thus will not be reconciled. Removing terminal reference label and finalizer")
		return ctrl.Result{}, r.removeTerminalReferenceLabelAndFinalizer(ctx, req)
	}

	terminals := &extensionsv1alpha1.TerminalList{}

	// only consider terminal resources in the same namespace as the service account
	err := r.List(ctx, terminals, &client.ListOptions{Namespace: req.Namespace})
	if err != nil {
		// Error reading the list - requeue the request.
		return ctrl.Result{}, err
	}

	referenced := false

	for _, t := range terminals.Items {
		if matchesNamespaceAndName(t.Spec.Target.Credentials.ServiceAccountRef, req.NamespacedName) {
			referenced = true
			break
		}

		if matchesNamespaceAndName(t.Spec.Host.Credentials.ServiceAccountRef, req.NamespacedName) {
			referenced = true
			break
		}
	}

	if referenced {
		logger.Info("ServiceAccount is still in use. Defer project membership cleanup")
		// nothing to do for now as it is still referenced. A reconcile request will be created once a terminal was deleted
		return ctrl.Result{}, nil
	}

	projectNamespace := req.Namespace

	if ptr.Deref(r.getConfig().HonourCleanupProjectMembership, false) {
		logger.Info("Removing ServiceAccount from project member list")

		if err := r.removeServiceAccountFromProjectMember(ctx, req.NamespacedName, projectNamespace); err != nil {
			return ctrl.Result{}, err
		}
	}

	logger.Info("Done. Removing finalizer")

	return ctrl.Result{}, r.removeFinalizer(ctx, req)
}

func (r *ServiceAccountReconciler) removeFinalizer(ctx context.Context, req ctrl.Request) error {
	serviceAccount := &corev1.ServiceAccount{}

	err := r.Get(ctx, req.NamespacedName, serviceAccount)
	if err != nil {
		return client.IgnoreNotFound(err)
	}

	controllerutil.RemoveFinalizer(serviceAccount, extensionsv1alpha1.ExternalTerminalName)

	return client.IgnoreNotFound(r.Update(ctx, serviceAccount))
}

func (r *ServiceAccountReconciler) removeTerminalReferenceLabelAndFinalizer(ctx context.Context, req ctrl.Request) error {
	serviceAccount := &corev1.ServiceAccount{}

	err := r.Get(ctx, req.NamespacedName, serviceAccount)
	if err != nil {
		return client.IgnoreNotFound(err)
	}

	delete(serviceAccount.Labels, extensionsv1alpha1.TerminalReference)
	controllerutil.RemoveFinalizer(serviceAccount, extensionsv1alpha1.ExternalTerminalName)

	return client.IgnoreNotFound(r.Update(ctx, serviceAccount))
}

// matchesNamespaceAndName returns true if namespace and name matches for the given ObjectReference and NamespacedName
func matchesNamespaceAndName(ref *corev1.ObjectReference, serviceAccount types.NamespacedName) bool {
	return ref != nil && ref.Namespace == serviceAccount.Namespace && ref.Name == serviceAccount.Name
}

func (r *ServiceAccountReconciler) removeServiceAccountFromProjectMember(ctx context.Context, serviceAccount types.NamespacedName, projectNamespace string) error {
	project, err := gardenclient.GetProjectByNamespace(ctx, r.Client, projectNamespace)
	if err != nil {
		return err
	}

	return gardenclient.RemoveServiceAccountFromProjectMember(ctx, r.Client, project, serviceAccount)
}
