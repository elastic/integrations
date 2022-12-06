# Hashicorp Vault

This integration collects logs and metrics from Hashicorp Vault. There are
three data streams:

- audit - Audit logs from file or TCP socket.
- log - Operation log from file.
- metrics - Telemetry data from the /sys/metrics API.

## Compatibility

This integration has been tested with Vault 1.11.

## Audit Logs

Vault audit logs provide a detailed accounting of who accessed or modified what
secrets. The logs do not contain the actual secret values (for strings), but
instead contain the value hashed with a salt using HMAC-SHA256. Hashes can be
compared to values by using the
[`/sys/audit-hash`](https://www.vaultproject.io/api/system/audit-hash.html) API.

In order to use this integration for audit logs you must configure Vault
to use a [`file` audit device](https://www.vaultproject.io/docs/audit/file)
or [`socket` audit device](https://www.vaultproject.io/docs/audit/socket). The
file audit device provides the strongest delivery guarantees.

### File audit device requirements

- Create a directory for audit logs on each Vault server host.

```
mkdir /var/log/vault
```

- Enable the file audit device.

```
vault audit enable file file_path=/var/log/vault/audit.json
```

- Configure log rotation for the audit log. The exact steps may vary by OS.
This example uses `logrotate` to call `systemctl reload` on the
[Vault service](https://learn.hashicorp.com/tutorials/vault/deployment-guide#step-3-configure-systemd)
which sends the process a SIGHUP signal. The SIGHUP signal causes Vault to start
writing to a new log file.

```
tee /etc/logrotate.d/vault <<'EOF'
/var/log/vault/audit.json {
    rotate 7
    daily
    compress
    delaycompress
    missingok
    notifempty
    extension json
    dateext
    dateformat %Y-%m-%d.
    postrotate
        /bin/systemctl reload vault || true
    endscript
}
EOF
```

### Socket audit device requirements

To enable the socket audit device in Vault you should first enable this
integration because Vault will test that it can connect to the TCP socket.

- Add this integration and enable audit log collection via TCP. If Vault will
be connecting remotely set the listen address to 0.0.0.0.

- Configure the socket audit device to stream logs to this integration.
Substitute in the IP address of the Elastic Agent to which you are sending the
audit logs.

```
vault audit enable socket address=${ELASTIC_AGENT_IP}:9007 socket_type=tcp
```

{{event "audit"}}

{{fields "audit"}}

## Operational Logs

Vault outputs its logs to stdout. In order to use the package to collect the
operational log you will need to direct its output to a file.

This table shows how the Vault field names are mapped in events. The remaining
structured data fields (indicated by the `*`) are placed under
`hashicorp_vault.log` which is mapped as `flattened` to allow for arbitrary
fields without causing mapping explosions or type conflicts.

| Original Field 	| Package Field         	|
|----------------	|-----------------------	|
| `@timestamp`   	| `@timestamp`          	|
| `@module`      	| `log.logger`          	|
| `@level`       	| `log.level`           	|
| `@message`     	| `message`             	|
| `*`            	| `hashicorp_vault.log` 	|

### Requirements

By default, Vault uses its `standard` log output as opposed to `json`. Please
enable the JSON output in order to have the log data in a structured format. In
a config file for Vault add the following:

```hcl
log_format = "json"
```

{{event "log"}}

{{fields "log"}}

## Metrics

Vault can provide [telemetry](https://www.vaultproject.io/docs/configuration/telemetry)
information in the form of Prometheus metrics. You can verify that metrics are
enabled by making an HTTP request to
`http://vault_server:8200/v1/sys/metrics?format=prometheus` on your Vault server.

### Requirements

You must configure the Vault prometheus endpoint to disable the hostname
prefixing. It's recommended to also enable the hostname label.

```hcl
telemetry {
  disable_hostname = true
  enable_hostname_label = true
}
```

{{fields "metrics"}}
