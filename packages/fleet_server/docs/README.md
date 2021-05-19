# Fleet Server integration

Fleet Server is a component of the Elastic Stack used to centrally manage Elastic Agents. It’s launched as part of an Elastic Agent on a host intended to act as a server. One Fleet Server process can support many Elastic Agent connections. It is responsible for updating agent policies, collecting status information, and coordinating actions across Elastic Agents.

To add this integration to an Elastic Agent, just add it to an agent policy. The Elastic Agents enrolled into that policy must run with additional credentials such as a service token. Learn how to add a Fleet Server our [documentation](https://www.elastic.co/guide/en/fleet/current/fleet-server.html).

## Compatibility
Fleet Server is compatible with the Elastic Stack and Elastic Agents version 7.13 or higher. The version of Elastic Agents running Fleet Server must be greater than or equal to the version of the Elastic Agents that enroll in them.
