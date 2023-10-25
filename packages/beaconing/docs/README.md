# Network Beaconing Identification

The Network Beaconing Identification package consists of a framework to identify beaconing activity in your environment. The framework surfaces significant indicators of compromise (IoCs) for threat hunters and analysts to use as a starting point for an investigation in addition to helping them monitor network traffic for beaconing activities. 
This package is licensed under Elastic License 2.0. 

## Installation

You can install the Network Beaconing Identification package via **Management > Integrations > Network Beaconing Identification**.

To inspect the installed assets, you can navigate to **Stack Management > Data > Transforms**.

| Transform name            | Purpose| 	Source index  | Destination index       | Alias |
|---------------------------|--------|----------------|-------------------------|------------|
| beaconing.pivot_transform |	Flags beaconing activity in your environment| 	logs-*        | 	ml_beaconing-[version] | ml_beaconing.all |

For additional information on the transform's inner workings and the signals it generates, refer to [this blog post](https://www.elastic.co/security-labs/identifying-beaconing-malware-using-elastic).

**Note**: When querying the destination index to enquire about beaconing activities, we advise using the alias for the destination index (`ml_beaconing.all`). In the event that the underlying package is upgraded, the alias will aid in maintaining the previous findings.

## Dashboards

The **Network Beaconing Identification** has three dashboards: 
* **Network Beaconing**: The main dashboard to monitor beaconing activity
* **Beaconing Drilldown**: Drilldown into relevant event logs and some statistics related to the beaconing activity
* **Hosts Affected Over Time By Process Name**: Monitor the spread of beaconing processes across hosts in your environment

For the dashboards to work as expected, the following settings need to be configured in Kibana. 
1. Ensure the pivot transform is installed and running.
2. Go to **Management > Stack Management > Kibana > Data Views**. Click on **Create data view** button and enable **Allow hidden and system indices** under the **Show Advanced settings**.
3. Create a data view with the following settings:
    - Index pattern : `ml_beaconing.all`
    - Name: `ml_beaconing`
    - Custom data view ID: `ml_beaconing`
