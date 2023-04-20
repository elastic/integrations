# Istio Integration

This integration ingest access logs and metrics created by the [Istio](https://istio.io/) service mesh.

## Compatibility

The Istio datasets were tested with Istio 1.14.3.

## Logs

### Access Logs

The `access_logs` data stream collects Istio access logs.

{{event "access_logs"}}

{{fields "access_logs"}}


## Metrics

### Istiod Metrics

The `istiod_metrics` data stream collects Istiod metrics.

{{event "istiod_metrics"}}

{{fields "istiod_metrics"}}

### Proxy Metrics

The `proxy_metrics` data stream collects Istio proxy metrics.

{{event "proxy_metrics"}}

{{fields "proxy_metrics"}}


## How to setup and test Istio locally

1. Setup a Kubernetes cluster. Since the Istio sample app requires lots of RAM (> 10GB) it's preferable to use a managed Kubernetes cluster (any cloud provider will do).
2. Setup a EK cluster on Elastic Cloud. For the same reason that Istio sample app requires a lot of RAM, it's unfeasible to run the Elastic cluster on your laptop via elastic-package. As an alternative ECK might be used as well.
3. Start elastic agents on Kubernetes cluster. The easiest way to achieve this is by using Fleet Server. You can find instructions [here](https://www.elastic.co/guide/en/fleet/master/running-on-kubernetes-managed-by-fleet.html)
4. Download Istio cli following the [instructions](https://istio.io/latest/docs/setup/getting-started/#download).
5. Install Istio via [instructions](https://istio.io/latest/docs/setup/getting-started/#install). The namespace `default` is used with this basic installation. This is the same namespace where we are going to run the Istio sample app.
6. Deploy the sample application via [instructions](https://istio.io/latest/docs/setup/getting-started/#bookinfo)
7. Open the application to external traffic and determine the ingress IP and ports. This step is slightly different depending where Kubernetes is running. More info at [here](https://istio.io/latest/docs/setup/getting-started/#ip) and [here](https://istio.io/latest/docs/setup/getting-started/#determining-the-ingress-ip-and-ports). The following commands should be enough to get this working.

```bash
kubectl apply -f samples/bookinfo/networking/bookinfo-gateway.yaml
istioctl analyze

# since we are using a cloud environment with an external load balancer
export INGRESS_HOST=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
export INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].port}')
export SECURE_INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="https")].port}')
export GATEWAY_URL=$INGRESS_HOST:$INGRESS_PORT
```

From the same terminal run the following command to open a browser to that link. This should verify that the sample application is reachable.

```bash
open "http://$GATEWAY_URL/productpage"
```

8. Generate some traffic to the sample application


```bash
for i in $(seq 1 100); do curl -s -o /dev/null "http://$GATEWAY_URL/productpage"; done
```

9. (Optional) You can visualize the graph of microservices in the sample app via [instructions](https://istio.io/latest/docs/setup/getting-started/#dashboard).
9.  Add the Istio integration from the registry. 
10. View logs and/or metrics from the Istio integration using the Discovery tab and selecting the right Data view