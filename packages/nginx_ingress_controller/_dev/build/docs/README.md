# Nginx Ingress Controller Integration

This integration periodically fetches logs from [Nginx Ingress Controller](https://github.com/kubernetes/ingress-nginx)
instances. It can parse access and error logs created by the ingress.

## Compatibility

The integration was tested with the Nginx Ingress Controller v0.30.0 and v0.40.2. The log format is described
[here](https://github.com/kubernetes/ingress-nginx/blob/nginx-0.30.0/docs/user-guide/nginx-configuration/log-format.md).

## Logs

### Access Logs

The `access` data stream collects the Nginx Ingress Controller access logs.

{{event "access"}}

{{fields "access"}}

### Error Logs

The `error` data stream collects the Nginx Ingress Controller error logs.

{{event "error"}}

{{fields "error"}}


## How to setup and test Ingress Controller locally

Ingress Controller is built around the Kubernetes Ingress resource, using a ConfigMap to store the NGINX configuration. Hence a k8s cluster is required before having
Ingress Controller up and runnning. Docs: https://kubernetes.github.io/ingress-nginx/

0. [Setup a k8s cluster](k8s.md).
1. Setup ingress controller following https://kubernetes.io/docs/tasks/access-application-cluster/ingress-minikube/
2. Redirect pods' logs to a temporary file: `kubectl -n kube-system logs -f nginx-ingress-controller-6fc5bcc8c9-zm8zv >> /tmp/ingresspod`
3. Configure Beats module:
```
- module: nginx
  # Ingress-nginx controller logs. This is disabled by default. It could be used in Kubernetes environments to parse ingress-nginx logs
  ingress_controller:
    enabled: true

    # Set custom paths for the log files. If left empty,
    # Filebeat will choose the paths depending on your OS.
    var.paths: ["/tmp/ingresspod"]
```
4. Setup pipelines and dashboards in ES
5. Start Filebeat
6. Produce traffic:
```
# visit `http://hello-world.info/v2` and `http://hello-world.info` from different browser engines
# use curl and wget to access the pages with different http words ie: curl -d "param1=value1&param2=value2" -X GET hello-world.info 
```


## Detailed example with kind

0. Use the `Quick start` guide under https://kubernetes.github.io/ingress-nginx/deploy/ and then local testing example

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.3.1/deploy/static/provider/cloud/deploy.yaml

kubectl create deployment demo --image=httpd --port=80
kubectl expose deployment demo

kubectl create ingress demo-localhost --class=nginx \
  --rule="demo.localdev.me/*=demo:80"

kubectl port-forward --namespace=ingress-nginx service/ingress-nginx-controller 8080:80
```

`Produce Traffic by visiting: http://demo.localdev.me:8080/`

> `demo.localdev.me` is DNS defaulting to localhost reserved by AWS


If you want to configure ingress-nginx to output to json format use the following  configuration in the `ingress-nginx-controller`

0. Download manifest
  ```bash
wget https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.3.1/deploy/static/provider/cloud/deploy.yaml
```

1. Edit deploy.yaml
  ```yaml
apiVersion: v1
data:
  allow-snippet-annotations: "true"
  log-format-escape-json: "true"
  log-format-upstream: '{"timestamp": "$time_iso8601", "requestID": "$req_id", "proxyUpstreamName":
    "$proxy_upstream_name", "proxyAlternativeUpstreamName": "$proxy_alternative_upstream_name","upstreamStatus":
    "$upstream_status", "upstreamAddr": "$upstream_addr","httpRequest":{"requestMethod":
    "$request_method", "requestUrl": "$host$request_uri", "status": $status,"requestSize":
    "$request_length", "responseSize": "$upstream_response_length", "userAgent": "$http_user_agent",
    "remoteIp": "$remote_addr", "referer": "$http_referer", "latency": "$upstream_response_time s",
    "protocol":"$server_protocol"}}'
kind: ConfigMap
metadata:
  labels:
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: ingress-nginx
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx
    app.kubernetes.io/version: 1.3.1
  name: ingress-nginx-controller
  namespace: ingress-nginx
```

2. Re apply manifest:
  ```bash
  kubectl apply -f deploy.yaml
```

3. Inspect logs
  ```bash
   kubectl logs -n ingress-nginx ingress-nginx-controller-7bf78659d-2th2m -f

   {"timestamp": "2022-09-07T09:36:15+00:00", "requestID": "92eea20d4058f5ee2b33f9366141101c", "proxyUpstreamName": "default-demo-80", "proxyAlternativeUpstreamName": "","upstreamStatus": "304", "upstreamAddr": "10.244.0.8:80","httpRequest":{"requestMethod": "GET", "requestUrl": "demo.localdev.me/", "status": 304,"requestSize": "565", "responseSize": "0", "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36", "remoteIp": "127.0.0.1", "referer": "", "latency": "0.002 s", "protocol":"HTTP/1.1"}}
    {"timestamp": "2022-09-07T09:36:37+00:00", "requestID": "b5a49957c5b0861b7c55b069cef7248f", "proxyUpstreamName": "default-demo-80", "proxyAlternativeUpstreamName": "","upstreamStatus": "404", "upstreamAddr": "10.244.0.8:80","httpRequest":{"requestMethod": "GET", "requestUrl": "demo.localdev.me/fdsfdsfads", "status": 404,"requestSize": "464", "responseSize": "196", "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36", "remoteIp": "127.0.0.1", "referer": "", "latency": "0.001 s", "protocol":"HTTP/1.1"}}
```