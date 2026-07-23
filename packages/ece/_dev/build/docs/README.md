# Elastic Cloud Enterprise Integration

The Elastic Cloud Enterprise (ECE) Integration allows you to collect the Adminconsole logs which contain all actions performed through the admin UI and as well as through the API. The Elastic Agent collecting this logs needs to be installed on all Control Planes in ECE, as the Control Planes usually host the adminconsole container.

## Overview

### Compability

This has been tested and verified on version ECE 3.8, as well as 4.0

### How it works

Install the Elastic Agent on the hosts that are running the adminconsole, which are usually your control plane hosts. This will spawn a filestream input which reads the adminconsole.log file.

## Adminconsole

{{ event "adminconsole" }}

{{ fields "adminconsole" }}
