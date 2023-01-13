FROM us.gcr.io/k8s-artifacts-prod/ingress-nginx/controller:v0.40.2

ENV KUBERNETES_SERVICE_HOST=127.0.0.1
ENV KUBERNETES_SERVICE_PORT=443

# User is required to create /var/run/secrets directories
USER root
RUN mkdir -p /var/run/secrets/kubernetes.io/serviceaccount

# Pass the check on non-empty account token
RUN echo token > /var/run/secrets/kubernetes.io/serviceaccount/token

# Create directory to expose service logs
RUN mkdir -p /tmp/service_logs/

# Add sample logs
ADD ingress.log /sample_logs/

# Add entrypoint
ADD entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh"]