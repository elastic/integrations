import type { IntegrationEvaluations } from "./types";

import { aws_bedrockEvaluations } from "./aws_bedrock";
import { aws_bedrock_agentcoreEvaluations } from "./aws_bedrock_agentcore";
import { aws_cloudtrail_otelEvaluations } from "./aws_cloudtrail_otel";
import { aws_securityhubEvaluations } from "./aws_securityhub";
import { aws_vpcflow_otelEvaluations } from "./aws_vpcflow_otel";
import { azure_ai_foundryEvaluations } from "./azure_ai_foundry";
import { azure_app_serviceEvaluations } from "./azure_app_service";
import { azure_openaiEvaluations } from "./azure_openai";
import { checkpoint_emailEvaluations } from "./checkpoint_email";
import { cisco_merakiEvaluations } from "./cisco_meraki";
import { cisco_secure_email_gatewayEvaluations } from "./cisco_secure_email_gateway";
import { cisco_umbrellaEvaluations } from "./cisco_umbrella";
import { citrix_wafEvaluations } from "./citrix_waf";
import { corelightEvaluations } from "./corelight";
import { cyeraEvaluations } from "./cyera";
import { darktraceEvaluations } from "./darktrace";
import { entityanalytics_adEvaluations } from "./entityanalytics_ad";
import { entityanalytics_oktaEvaluations } from "./entityanalytics_okta";
import { extrahopEvaluations } from "./extrahop";
import { forgerockEvaluations } from "./forgerock";
import { fortinet_fortigateEvaluations } from "./fortinet_fortigate";
import { gcp_vertexaiEvaluations } from "./gcp_vertexai";
import { gitlabEvaluations } from "./gitlab";
import { greenhouseEvaluations } from "./greenhouse";
import { infoblox_bloxone_ddiEvaluations } from "./infoblox_bloxone_ddi";
import { jamf_proEvaluations } from "./jamf_pro";
import { linuxEvaluations } from "./linux";
import { m365_defenderEvaluations } from "./m365_defender";
import { microsoft_dhcpEvaluations } from "./microsoft_dhcp";
import { microsoft_intuneEvaluations } from "./microsoft_intune";
import { openaiEvaluations } from "./openai";
import { osqueryEvaluations } from "./osquery";
import { ping_federateEvaluations } from "./ping_federate";
import { ping_oneEvaluations } from "./ping_one";
import { prisma_cloudEvaluations } from "./prisma_cloud";
import { qualys_vmdrEvaluations } from "./qualys_vmdr";
import { salesforceEvaluations } from "./salesforce";
import { servicenowEvaluations } from "./servicenow";
import { slackEvaluations } from "./slack";
import { snortEvaluations } from "./snort";
import { snykEvaluations } from "./snyk";
import { suricataEvaluations } from "./suricata";
import { sysdigEvaluations } from "./sysdig";
import { taniumEvaluations } from "./tanium";
import { ti_mispEvaluations } from "./ti_misp";
import { wizEvaluations } from "./wiz";
import { zscaler_ziaEvaluations } from "./zscaler_zia";

/** All integration evaluation snippets keyed by package code. */
export const allIntegrationEvaluations = {
  "aws_bedrock": aws_bedrockEvaluations,
  "aws_bedrock_agentcore": aws_bedrock_agentcoreEvaluations,
  "aws_cloudtrail_otel": aws_cloudtrail_otelEvaluations,
  "aws_securityhub": aws_securityhubEvaluations,
  "aws_vpcflow_otel": aws_vpcflow_otelEvaluations,
  "azure_ai_foundry": azure_ai_foundryEvaluations,
  "azure_app_service": azure_app_serviceEvaluations,
  "azure_openai": azure_openaiEvaluations,
  "checkpoint_email": checkpoint_emailEvaluations,
  "cisco_meraki": cisco_merakiEvaluations,
  "cisco_secure_email_gateway": cisco_secure_email_gatewayEvaluations,
  "cisco_umbrella": cisco_umbrellaEvaluations,
  "citrix_waf": citrix_wafEvaluations,
  "corelight": corelightEvaluations,
  "cyera": cyeraEvaluations,
  "darktrace": darktraceEvaluations,
  "entityanalytics_ad": entityanalytics_adEvaluations,
  "entityanalytics_okta": entityanalytics_oktaEvaluations,
  "extrahop": extrahopEvaluations,
  "forgerock": forgerockEvaluations,
  "fortinet_fortigate": fortinet_fortigateEvaluations,
  "gcp_vertexai": gcp_vertexaiEvaluations,
  "gitlab": gitlabEvaluations,
  "greenhouse": greenhouseEvaluations,
  "infoblox_bloxone_ddi": infoblox_bloxone_ddiEvaluations,
  "jamf_pro": jamf_proEvaluations,
  "linux": linuxEvaluations,
  "m365_defender": m365_defenderEvaluations,
  "microsoft_dhcp": microsoft_dhcpEvaluations,
  "microsoft_intune": microsoft_intuneEvaluations,
  "openai": openaiEvaluations,
  "osquery": osqueryEvaluations,
  "ping_federate": ping_federateEvaluations,
  "ping_one": ping_oneEvaluations,
  "prisma_cloud": prisma_cloudEvaluations,
  "qualys_vmdr": qualys_vmdrEvaluations,
  "salesforce": salesforceEvaluations,
  "servicenow": servicenowEvaluations,
  "slack": slackEvaluations,
  "snort": snortEvaluations,
  "snyk": snykEvaluations,
  "suricata": suricataEvaluations,
  "sysdig": sysdigEvaluations,
  "tanium": taniumEvaluations,
  "ti_misp": ti_mispEvaluations,
  "wiz": wizEvaluations,
  "zscaler_zia": zscaler_ziaEvaluations,
} as const satisfies Record<string, IntegrationEvaluations>;
