# Nginx Ingress Controller Integration

This integration periodically fetches metrics from [Nginx Ingress Controller](https://github.com/kubernetes/ingress-nginx)
instances. It can parse access logs created by the ingress. 

## Compatibility

The integration was tested with version v0.30.0 of Nginx Ingress Controller. The log format is described
[here](https://github.com/kubernetes/ingress-nginx/blob/nginx-0.30.0/docs/user-guide/nginx-configuration/log-format.md).

## Logs

### Ingress Controller Logs

Access log collects the Nginx Ingress Controller access logs.

{{fields "access"}}