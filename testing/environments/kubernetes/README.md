## Ingest Manager & Agent on Kubernetes

With this testing environment one can deploy Kibana, Elasticsearch, Package Registry and Agent
on Kubernetes in order to activate the Kubernetes' integration for Metrics.

### Setup

1. Install minikube (https://kubernetes.io/docs/setup/learning-environment/minikube/)
2. Start minikube (`minikube start`)
3. Verify that k8s is healthy. Run `kubectl get pods --all-namespaces` in order to verify that
 control plane Pods are running
4. In order to mount local packages to the registry pod one need to mount host's directory inside minikube VM.
 For instance `minikube mount -v 5 /Users/chrismark/go/src/github.com/elastic/integrations/build:/etc/build` should be
 running for the whole time in the background. Then the `/etc/build` directory of minikube VM (host for k8s cluster)
 will be mounted within the Registry's Pod serving the packages to the outside world.
 5. Deploy the stack with `kubectl apply -f snapshot.yml`. This will bing up Elasticsearch, Kibana and Package Registry.
 Verify that the services are running properly by finding their exposed endpoints. Run `minikube -n kube-system  service kibana --url` 
 and `minikube -n kube-system service registry --url` 
 (these commands return the endpoint which is a combination of the minikube VM's ip and the k8s exposed port) 
 to find the endpoint and check their health.
 6. Login to Kibana using the proper endpoint and `elastic:changeme` credentials. Verify that Kibana is ready to enroll Agent.
 7. Create 2 different configs in Kibana Ingest Management view, one for cluster scope and one for node scope agents.
 Use cluster scope token in `FLEET_ENROLLMENT_TOKEN` value of the Deployment and node scope token in the Daemonset one.
 8. Deploy Agent with `kubectl apply -f agent.yml`. This will enroll the Agent and after a while one should be able 
 to see the Agent enrolled in Kibana Ingest Manager view as well that Data streams are populated and 
 `system` metrics are being collected.
 9. Enable `Kubernetes` package for each scope/group of agents accordingly. `state_*`, `event` and `apiserver` should be deployed
 on cluster scope and all the rest on nodescope.
 
 
 In order to debug the whole Deployment use:
 1. `kubect -n kube-system logs -f agent-blabbla` in order to get the logs of the Pod
 2. `kubectl -n kube-system exec -it agent-blabbla /bin/bash` in order to get a shell inside the container/Pod and look for issues.
 3. In order to check accessibility from one service to another exec inside a services Pod, ie Kibana and try to 
 `curl` against the `registry` for instance `curl http://registry:8080` (use `kubectl -n kube-system get svc` to list all exposed services).
 4. Check stack's pods with `kubectl get pods -n kube-system -l group=ingest-management`
 
 
 ### Why to run Agent within a k8s cluster
 
 In order to enable `state_*` metricsets of Kubernetes module one needs access to `kube_state_metrics` service 
 which runs within k8s cluster. Currently it is suggested to deploy Metricbeat as k8s Deployment (with 1 Pod) 
 in order to collect these cluster-wide metrics. Of course this can be achieved by having Agent running
 outside of the cluster and querying `kube_state_metrics` if the service is actually exposed to the outside world.
 Then we will need access to the k8s API too in order to leverage `add_kubernetes_metadata`. Then issues regarding
 certificates, accessibility etc may occur so we end up that deploying Agent/Metricbeat within the k8s cluster
 is the best option to go with when it comes to the Kubernetes module (sorry, package 😅 )
 (https://github.com/elastic/beats/blob/master/deploy/kubernetes/metricbeat/metricbeat-deployment-configmap.yaml#L50).
 
 To add more to the above statement, `pod`, `node`, `container` etc metricsets require access to the Kubelet's API of
 each node. This seems to be impossible to happen from outside of the cluster. 
 On pure Metricbeat's installations we enable these Metricsets on Deamonset Pods running on each of the k8s nodes
 (https://github.com/elastic/beats/blob/master/deploy/kubernetes/metricbeat/metricbeat-daemonset-configmap.yaml#L79).
 
 In order to combine the above 2 different deployment strategies we could suggest that the users create 2 
 different configs in Ingest Manager one for the cluster-wide metrics and one for the metrics collected 
 from each node. Then the singleton agent will be enrolled using the cluster-wide config while the Agents 
 from the Daemonset Pods will be enrolled using the node-level config.
 This will provide k8s native experience to the users that aim to use our Kubernetes package.