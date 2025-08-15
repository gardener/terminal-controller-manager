# Gardener Terminal Controller Manager
<img src="https://user-images.githubusercontent.com/5526658/65958014-a64a9b00-e44e-11e9-9b0a-166247582b05.png" width="180"/>

[![REUSE status](https://api.reuse.software/badge/github.com/gardener/terminal-controller-manager)](https://api.reuse.software/info/github.com/gardener/terminal-controller-manager)
[![Build](https://github.com/gardener/terminal-controller-manager/actions/workflows/non-release.yaml/badge.svg)](https://github.com/gardener/terminal-controller-manager/actions/workflows/non-release.yaml)
[![Slack workspace](https://img.shields.io/badge/Slack-Gardener%20Project-brightgreen.svg?logo=slack)](https://gardener-cloud.slack.com/)
[![Go Report Card](https://goreportcard.com/badge/github.com/gardener/terminal-controller-manager)](https://goreportcard.com/report/github.com/gardener/terminal-controller-manager)
[![reuse compliant](https://reuse.software/badge/reuse-compliant.svg)](https://reuse.software/)

The `terminal-controller-manager` is used for the [webterminal feature](https://github.com/gardener/dashboard/blob/master/docs/operations/webterminals.md) of the [gardener/dashboard](https://github.com/gardener/dashboard).

The `terminal-controller-manager` watches `Terminal` resources under the `dashboard.gardener.cloud/v1alpha1` API group and ensures the desired state on the host and target cluster.
Host and target cluster can also be the same. For more details and a usage scenario [see docs here](https://github.com/gardener/dashboard/blob/master/docs/operations/webterminals.md).

## Development Setup

Prerequisites:
- [golang](https://golang.org/dl/)
- [kind](https://github.com/kubernetes-sigs/kind)
- [helm](https://helm.sh/docs/intro/install/)
- [kubectl](https://kubernetes.io/de/docs/tasks/tools/install-kubectl/)

To build and push the images, run `docker-build` and `docker-push` make targets. Adapt the image as necessary:

```bash
make docker-build docker-push IMG_MANAGER_REPOSITORY=example/my-repo
```

## Local Setup with `Kind`

The local setup describes the use of the local `kind` cluster setup of gardener. After deploying the gardener locally, the helm chart of the `terminal-controller-manager` can be installed into the `kind` cluster.

### Deploy Gardener locally
First, deploy the gardener locally `Deploying Gardener locally` into a `kind` cluster. For more information check out https://github.com/gardener/gardener/blob/master/docs/deployment/getting_started_locally.md#setting-up-the-kind-cluster-garden-and-seed. The basic steps are the following. 

Clone the gardener repository. 

```bash
git clone git@github.com:gardener/gardener.git
```

Change directory to `gardener`.

```bash
cd gardener
```

Set up a new `kind` cluster named `gardener-local`.

```bash
make kind-up
```

The kubeconfig is stored in the `./example/gardener-local/kind/local/kubeconfig` file within the `gardener` directory. Alternatively run `kind get kubeconfig --name gardener-local` to print out the kubeconfig.

Deploy Gardener resources into the cluster.

```bash
make gardener-up
```

Set the `KUBECONFIG` environment variable for the local garden cluster:

```bash
export KUBECONFIG=$PWD/example/gardener-local/kind/local/kubeconfig
```

### Deploy Terminal Controller Manager locally

Change directory to `terminal-controller-manager`.

```bash
cd terminal-controller-manager
```

Build the `terminal-controller-manager` image and load it into the kind cluster.
```bash
make load-manager-docker-image
```

Run `install` make target.

```bash
make install
```

To verify that everything worked, check if the `terminal-controller-manager` pod is running in the `terminal-system` namespace:

```bash
kubectl -n terminal-system get po

NAME                                           READY   STATUS    RESTARTS   AGE
terminal-controller-manager-6d7b5bfbdd-l6vg9   2/2     Running   0          10s
```
