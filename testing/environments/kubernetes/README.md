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
 Verify that the services are running properly by finding their exposed endpoints. Run `minikube service kibana --url` 
 and `minikube service registry --url` 
 (these commands return the endpoint which is a combination of the minikube VM's ip and the k8s exposed port) 
 to find the endpoint and check their health.
 6. Login to Kibana using the proper endpoint and `elastic:changeme` credentials. Verify that Kibana is ready to enroll Agent.
 7. Deploy Agent with `kubectl apply -f agent.yml`. This will enroll the Agent and after a while one should be able 
 to see the Agent enrolled in Kibana Ingest Manager view as well that Data streams are populated and 
 `system` metrics are being collected.
 
 In order to debug the whole Deployment use:
 1. `kubect logs -f agent-blabbla` in order to get the logs of the Pod
 2. `kubectl exec -it agent-blabbla /bin/bash` in order to get a shell inside the container/Pod and look for issues.
 3. In order to check accessibility from one service to another exec inside a services Pod, ie Kibana and try to 
 `curl` against the `registry` for instance `curl http://registry:8080` (use `kubectl get svc` to list all exposed services).