# Zeek Integration

This is an integration for [Zeek](https://www.zeek.org/), which was formerly
named Bro. Zeek is a passive, open-source network traffic analyzer. This
integrations ingests the logs Zeek produces about the network traffic that it
analyzes.

Zeek logs must be output in JSON format. This is normally done by appending the 
[json-logs policy](https://docs.zeek.org/en/lts/scripts/policy/tuning/json-logs.zeek.html)
to your `local.zeek` file. Add this line to your `local.zeek`.

`@load policy/tuning/json-logs.zeek`

## Compatibility
This module has been developed against Zeek 2.6.1, but is expected to work with
other versions of Zeek.

Zeek requires a Unix-like platform, and it currently supports Linux,
FreeBSD, and Mac OS X.

## Logs
### capture_loss

The `capture_loss` dataset collects the Zeek capture_loss.log file,
which contains packet loss rate data.

{{fields "capture_loss"}}

### connection

The `connection` dataset collects the Zeek conn.log file, which
contains TCP/UDP/ICMP connection data.

{{fields "connection"}}

### dce_rpc

The `dce_rpc` dataset collects the Zeek dce_rpc.log file, which
contains Distributed Computing Environment/RPC data.

{{fields "dce_rpc"}}

### dhcp

The `dhcp` dataset collects the Zeek dhcp.log file, which contains
DHCP lease data.

{{fields "dhcp"}}

### dnp3

The `dnp3` dataset collects the Zeek dnp3.log file which contains DNP3
requests and replies.

{{fields "dnp3"}}

### dns

The `dns` dataset collects the Zeek dns.log file which contains DNS
activity.

{{fields "dns"}}

### dpd

The `dpd` dataset collects the Zeek dpd.log, which contains dynamic
protocol detection failures.

{{fields "dpd"}}

### files

The `files` dataset collects the Zeek files.log file, which contains
file analysis results.

{{fields "files"}}

### ftp

The `ftp` dataset collects the Zeek ftp.log file, which contains FTP
activity.

{{fields "ftp"}}

### http

The `http` dataset collects the Zeek http.log file, which contains
HTTP requests and replies.

{{fields "http"}}

### intel

The `intel` dataset collects the Zeek intel.log file, which contains
intelligence data matches.

{{fields "intel"}}

### irc

The `irc` dataset collects the Zeek irc.log file, which contains IRC
commands and responses.

{{fields "irc"}}

### kerberos

The `kerberos` dataset collects the Zeek kerberos.log file, which
contains kerberos data.

{{fields "kerberos"}}

### known_certs

The `known_certs` dataset captures information about SSL/TLS certificates seen on the local network. See the [documentation](https://docs.zeek.org/en/master/logs/known-and-software.html#known-certs-log) for more details.

{{fields "known_certs"}}

### known_hosts

The `known_hosts` dataset simply records a timestamp and an IP address when Zeek observes a new system on the local network.. See the [documentation](https://docs.zeek.org/en/master/logs/known-and-software.html#known-hosts-log) for more details.

{{fields "known_hosts"}}

### known_services

The `known_services` dataset records a timestamp, IP, port number, protocol, and service (if available) when Zeek observes a system offering a new service on the local network. See the [documentation](https://docs.zeek.org/en/master/logs/known-and-software.html#known-services-log) for more details.

{{fields "known_services"}}

### modbus

The `modbus` dataset collects the Zeek modbus.log file, which contains
modbus commands and responses.

{{fields "modbus"}}

### mysql

The `mysql` dataset collects the Zeek mysql.log file, which contains
MySQL data.

{{fields "mysql"}}

### notice

The `notice` dataset collects the Zeek notice.log file, which contains
Zeek notices.

{{fields "notice"}}

### ntp

The `ntp` dataset collects the Zeek ntp.log file, which contains
NTP data.

{{fields "ntp"}}

### ntlm

The `ntlm` dataset collects the Zeek ntlm.log file, which contains NT
LAN Manager(NTLM) data.

{{fields "ntlm"}}

### ocsp

The `ocsp` dataset collects the Zeek ocsp.log file, which contains
Online Certificate Status Protocol (OCSP) data.

{{fields "ocsp"}}

### pe

The `pe` dataset collects the Zeek pe.log file, which contains
portable executable data.

{{fields "pe"}}

### radius

The `radius` dataset collects the Zeek radius.log file, which contains
RADIUS authentication attempts.

{{fields "radius"}}

### rdp

The `rdp` dataset collects the Zeek rdp.log file, which contains RDP
data.

{{fields "rdp"}}

### rfb

The `rfb` dataset collects the Zeek rfb.log file, which contains
Remote Framebuffer (RFB) data.

{{fields "rfb"}}

### signature

The `signature` dataset collects the Zeek signature.log file, which contains
Zeek signature matches.

{{fields "signature"}}

### sip

The `sip` dataset collects the Zeek sip.log file, which contains SIP
data.

{{fields "sip"}}

### smb_cmd

The `smb_cmd` dataset collects the Zeek smb_cmd.log file, which
contains SMB commands.

{{fields "smb_cmd"}}

### smb_files

The `smb_files` dataset collects the Zeek smb_files.log file, which
contains SMB file data.

{{fields "smb_files"}}

### smb_mapping

The `smb_mapping` dataset collects the Zeek smb_mapping.log file,
which contains SMB trees.

{{fields "smb_mapping"}}

### smtp

The `smtp` dataset collects the Zeek smtp.log file, which contains
SMTP transactions..

{{fields "smtp"}}

### snmp

The `snmp` dataset collects the Zeek snmp.log file, which contains
SNMP messages.

{{fields "snmp"}}

### socks

The `socks` dataset collects the Zeek socks.log file, which contains
SOCKS proxy requests.

{{fields "socks"}}

### software

The `software` dataset collects details on applications operated by the hosts it sees on the local network. See the [documentation](https://docs.zeek.org/en/master/logs/known-and-software.html#software-log) for more details.

{{fields "software"}}

### ssh

The `ssh` dataset collects the Zeek ssh.log file, which contains SSH
connection data.

{{fields "ssh"}}

### ssl

The `ssl` dataset collects the Zeek ssl.log file, which contains
SSL/TLS handshake info.

{{fields "ssl"}}

### stats

The `stats` dataset collects the Zeek stats.log file, which contains
memory/event/packet/lag statistics.

{{fields "stats"}}

### syslog

The `syslog` dataset collects the Zeek syslog.log file which contains
syslog messages.

{{fields "syslog"}}

### traceroute

The `traceroute` dataset collects the Zeek traceroute.log file, which
contains traceroute detections.

{{fields "traceroute"}}

### tunnel

The `tunnel` dataset collects the Zeek tunnel.log file, which contains
tunneling protocol events.

{{fields "tunnel"}}

### weird

The `weird` dataset collects the Zeek weird.log file, which contains
unexpected network-level activity.

{{fields "weird"}}

### x509

The `x509` dataset collects the Zeek x509.log file, which contains
X.509 certificate info.

{{fields "x509"}}
