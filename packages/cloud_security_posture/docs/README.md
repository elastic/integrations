# CIS Kubernetes Benchmark

This integration compares [Kubernetes](https://kubernetes.io/) configuration against CIS benchmark checks. It computes a score that ranges between 0 - 100. This integration requires access to node files, node processes, and the Kuberenetes api-server therefore it assumes the agent will be installed as a [DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/) with the proper [Roles](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#role-and-clusterrole) and [RoleBindings](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#rolebinding-and-clusterrolebinding) attached.

## Leader election

To collect cluster level data (compared to node level information) the integration makes use of the [leader election](https://www.elastic.co/guide/en/fleet/master/kubernetes_leaderelection-provider.html) mechanism.
This mechanism assures that the cluster level data is collected by only one of the agents running as aprt of the DeamonSet and not by all of them.

Cluster level data example: List of the running pods.
Node level data examle: kubelet configuration.

## Compatibility

The Kubernetes package is tested with Kubernetes 1.21.x

## Dashboard

CIS Kubernetes Benchmark integration is shipped including default dashboards and screens to manage the benchmark rules and inspect the compliance score and findings.

## Deployment

#### Configure Kibana

In order for the integration to be installed, The Cloud Security Posture Kibana plugin must be enabled.

This could be done by adding the following configuration line to `kibana.yml`:
```
xpack.cloudSecurityPosture.enabled: true
```
For Cloud users, see [Edit Kibana user settings](https://www.elastic.co/guide/en/cloud/current/ec-manage-kibana-settings.html).


#### Deploy the Elastic agent

Just like every other integration, the KSPM integration requires an Elastic agent to be deployed.

See agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/running-on-kubernetes-managed-by-fleet.html).

Note, if you want to add this integration to existing Elastic agents (deployed prior to 8.3 release), you'll have to update your Deamonset to include the additional required volumes and volume mounts.
This can be done in a few steps:

1. Create a patch file including all the necessary volumes and volume mounts:
```bash
cat << EOF > volumes-patch.yml
spec:
  template:
    spec:
      containers:
      - name: elastic-agent
        volumeMounts:
        - mountPath: /hostfs/proc
          name: proc
          readOnly: true
        - mountPath: /hostfs/sys/fs/cgroup
          name: cgroup
          readOnly: true
        - mountPath: /var/lib/docker/containers
          name: varlibdockercontainers
          readOnly: true
        - mountPath: /var/log
          name: varlog
          readOnly: true
        - mountPath: /hostfs/etc/kubernetes
          name: etc-kubernetes
          readOnly: true
      volumes:
      - hostPath:
          path: /proc
          type: ""
        name: proc
      - hostPath:
          path: /sys/fs/cgroup
          type: ""
        name: cgroup
      - hostPath:
          path: /var/lib/docker/containers
          type: ""
        name: varlibdockercontainers
      - hostPath:
          path: /var/log
          type: ""
        name: varlog
      - hostPath:
          path: /etc/kubernetes
          type: ""
        name: etc-kubernetes
EOF
```

2. Apply the patch file to your Kubernetes cluster
```bash
kubectl patch ds elastic-agent -n kube-system --patch-file volumes-patch.yml
# Expected result:
# daemonset.apps/elastic-agent patched
```

3. Check if the update was successful
```bash
kubectl rollout status ds/elastic-agent -n kube-system
# Expected result:
# daemon set "elastic-agent" successfully rolled out
```