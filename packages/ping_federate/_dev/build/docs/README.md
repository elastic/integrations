# PingFederate

## Overview

[PingFederate](https://www.pingidentity.com/en/platform/capabilities/authentication-authority/pingfederate.html) is a key component of the [PingIdentity](https://www.pingidentity.com/en.html) platform, which is a suite of solutions for identity and access management (IAM). Specifically, Ping Federate is an enterprise-grade federated identity server designed to enable secure single sign-on (SSO), identity federation, and access management for applications and services.

## Compatibility

This module has been tested with the latest version of PingFederate, **12.1.4(November 2024)**.
## Data streams

The PingFederate integration collects two types of logs:

**[Admin](https://docs.pingidentity.com/pingfederate/latest/administrators_reference_guide/pf_admin_audit_loggin.html)** - Record actions performed within the PingFederate Administrative Console and via the Administrative API.

**[Audit](https://docs.pingidentity.com/pingfederate/latest/administrators_reference_guide/pf_security_audit_loggin.html)** - Provides a detailed record of authentication, authorization, and federation transactions.

**Note**:

1. In the Admin datastream, only logs from the admin.log file are supported via filestream in the pipe format. The log pattern is as follows:
```
<pattern>%d | %X{user} | %X{roles} | %X{ip} | %X{component} | %X{event} | %X{eventdetailid} | %m%n</pattern>
```
Sample Log:
```
2024-11-28 5:58:55,832 | Administrator | UserAdmin,Admin,CryptoAdmin,ExpressionAdmin | 81.2.69.142 | A-rBnNPcJffxBiizBWDOWxq_Ek8cYxg3nxxxxyn6H4 | LICENSE | ROTATE | - Login was successful
```

2. Audit logs are supported through filestream, TCP, and UDP in the CEF format. The log pattern is as follows:
```
<pattern>%escape{CEF}{CEF:0|Ping Identity|PingFederate|%X{pfversion}|%X{event}|%X{event}|0|rt=%d{MMM dd yyyy HH:mm:ss.SSS} duid=%X{subject} src=%X{ip} msg=%X{status} cs1Label=Target Application URL cs1=%X{app} cs2Label=Connection ID cs2=%X{connectionid} cs3Label=Protocol cs3=%X{protocol} dvchost=%X{host} cs4Label=Role cs4=%X{role} externalId=%X{trackingid} cs5Label=SP Local User ID cs5=%X{localuserid} cs6Label=Attributes cs6=%X{attributes} %n}</pattern>
```
Sample Log:
```
CEF:0|Ping Identity|PingFederate|6.4|AUTHN_SESSION_DELETED|AUTHN_SESSION_DELETED|0|rt=May 18 2012 11:41:48.452 duid=joe src=89.160.20.112 msg=failure cs1Label=Target Application URL cs1=http://www.google.ca&landingpage\=pageA cs2Label=Connection ID cs2=sp:cloud:saml2 cs3Label=Protocol cs3=SAML20 dvchost=hello cs4Label=Role cs4=IdP externalId=tid:ae14b5ce8 cs5Label=SP Local User ID cs5=idlocal cs6Label=Attributes cs6={SAML_SUBJECT\=joe, ognl\=tom}
```

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data through the Filestream or TCP/UDP and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent. For more information, refer to the Elastic Agent [installation guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Setup

1. For step-by-step instructions on how to configure log files in PingFederate instance, see the [Log4j 2 logging service and configuration](https://docs.pingidentity.com/pingfederate/latest/administrators_reference_guide/pf_log4j_2_loggin_service_and_config.html) guide.
2. To write the audit logs in cef format, see the [Writing audit log in CEF](https://docs.pingidentity.com/pingfederate/latest/administrators_reference_guide/pf_writin_audit_log_cef.html) guide.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type PingFederate.
3. Click on the "PingFederate" integration from the search results.
4. Click on the "Add PingFederate" button to add the integration.
5. Select the toggle for the data stream for which you want to collect logs.
6. Enable the data collection mode from the following: Filestream, TCP, or UDP. (Admin logs are only supported through Filestream)
7. Add all the required configuration parameters, such as paths for the filestream or listen address and listen port for the TCP and UDP.
8. Click on "Save and Continue" to save the integration.

## Logs Reference

### Admin

This is the `Admin` dataset.

#### Example

{{event "admin"}}

{{fields "admin"}}

### Audit

This is the `Audit` dataset.

#### Example

{{event "audit"}}

{{fields "audit"}}