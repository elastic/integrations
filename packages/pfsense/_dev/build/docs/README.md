# Iptables Integration

This is an integration for `iptables` and `ip6tables` logs. It parses logs
received over the network via syslog (UDP) or from a file. Also, it understands
the prefix added by some Ubiquiti firewalls, which includes the rule set name,
rule number, and the action performed on the traffic (allow/deny).

The module is by default configured to run with the `udp` input on port `9001`.
However, it can also be configured to read from a file path.

## Logs

### Iptables log

This is the Iptables `log` dataset.

{{event "log"}}

{{fields "log"}}
