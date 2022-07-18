# access-logs

access-logs integration collects and parses access logs of Istio proxy containers.

It requires access to the log files in each Kubernetes node where the container logs are stored.
This defaults to `/var/log/containers/*${kubernetes.container.id}.log`.  #FIXME change location

By default only (container parser)[https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-filestream.html#_parsers] is enabled. Additional log parsers can be added as an advanced options configuration.