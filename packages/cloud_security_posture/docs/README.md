# CIS Kubernetes Benchmark

This integration compares [Kubernetes](https://kubernetes.io/) configuration against CIS benchmark checks. It computes a score that ranges between 0 - 100. This integration requires access to node files, node processes, and the Kubernetes api-server therefore it assumes the agent will be installed as a [DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/) with the proper [Roles](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#role-and-clusterrole) and [RoleBindings](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#rolebinding-and-clusterrolebinding) attached.

## Leader election

To collect cluster level data (compared to node level information) the integration makes use of the [leader election](https://www.elastic.co/guide/en/fleet/master/kubernetes_leaderelection-provider.html) mechanism.
This mechanism assures that the cluster level data is collected by only one of the agents running as a part of the DaemonSet and not by all of them.

Cluster level data example: List of the running pods.
Node level data example: kubelet configuration.

## Compatibility

The Kubernetes package is tested with Kubernetes 1.21.x

## Dashboard

CIS Kubernetes Benchmark integration is shipped including default dashboards and screens to manage the benchmark rules and inspect the compliance score and findings.

## Deployment

#### Deploy the Elastic agent

Just like every other integration, the KSPM integration requires an Elastic agent to be deployed.

See agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/running-on-kubernetes-managed-by-fleet.html).
Note, this integration can only be added to Elastic agents with versions 8.3 or higher.
