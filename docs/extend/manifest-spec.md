---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/manifest-spec.html
---

# manifest.yml [manifest-spec]

Integration metadata, like version, name, license level, description, category, icon and screenshot mappings, and policy template definitions.

**required**

Included from the package-spec repository. This will update when the spec is updated.

```yaml
##
## Describes the specification for the integration package's main manifest.yml file
##
spec:
  # Everything under here follows JSON schema (https://json-schema.org/), written as YAML for readability
  type: object
  additionalProperties: false
  definitions:
    agent:
      description: Declarations related to Agent configurations or requirements.
      type: object
      additionalProperties: false
      properties:
        privileges:
          type: object
          additionalProperties: false
          properties:
            root:
              description: Set to true if collection requires root privileges in the agent.
              type: boolean
    categories:
      description: Categories to which this package belongs.
      type: array
      items:
        type: string
        enum:
          - advanced_analytics_ueba
          - analytics_engine
          - application_observability
          - app_search
          - asset_inventory
          - auditd
          - authentication
          - aws
          - azure
          - big_data
          - cdn_security
          - cloud
          - cloudsecurity_cdr
          - config_management
          - connector
          - connector_client
          - connector_package
          - containers
          - content_source
          - crawler
          - credential_management
          - crm
          - custom
          - custom_logs
          - database_security
          - datastore
          - dns_security
          - edr_xdr
          - elasticsearch_sdk
          - elastic_stack
          - email_security
          - enterprise_search
          - firewall_security
          - google_cloud
          - iam
          - ids_ips
          - infrastructure
          - java_observability
          - kubernetes
          - language_client
          - languages
          - load_balancer
          - message_queue
          - monitoring
          - native_search
          - network
          - network_security
          - notification
          - observability
          - os_system
          - process_manager
          - productivity
          - productivity_security
          - proxy_security
          - sdk_search
          - security
          - siem
          - stream_processing
          - support
          - threat_intel
          - ticketing
          - version_control
          - virtualization
          - vpn_security
          - vulnerability_management
          - web
          - web_application_firewall
          - websphere
          - workplace_search
        examples:
          - web
    conditions:
      description: Conditions under which this package can be installed.
      type: object
      additionalProperties: false
      properties:
        elastic:
          description: Elastic conditions
          type: object
          additionalProperties: false
          properties:
            subscription:
              description: The subscription required for this package.
              type: string
              enum:
                - basic
                - gold
                - platinum
                - enterprise
              default: basic
              examples:
                - basic
            capabilities:
              description: |-
                Stack features that are required by the package to work properly.
                The package should not be used in deployments without the indicated features.
                Packages that don't indicate any capability condition can be used on any deployment.
              type: array
              uniqueItems: true
              items:
                type: string
                enum:
                  - apm
                  - enterprise_search
                  - observability
                  - security
                  - serverless_search
                  - uptime
        kibana:
          description: Kibana conditions
          type: object
          additionalProperties: false
          properties:
            version:
              type: string
              description: Kibana versions compatible with this package.
              examples:
                - ">=7.9.0"
    description:
      description: >
        A longer description of the package. It should describe, at least all the kinds of
        data that is collected and with what collectors, following the structure
        "Collect X from Y with X".
      type: string
      examples:
        - Collect logs and metrics from Apache HTTP Servers with Elastic Agent.
        - Collect logs and metrics from Amazon Web Services with Elastic Agent.
    deployment_modes:
      description: >
        Options related to the deployment modes. The deployment mode refers to the mode used to
        deploy the Elastic Agents running this policy.
      type: object
      additionalProperties: false
      properties:
        default:
          description: >
            Options specific to the default deployment mode, where agents are normally managed
            by users, explicitly enrolled to Fleet and visible in UIs.
          type: object
          properties:
            enabled:
              description: >
                Indicates if the default deployment mode is available for this template policy.
                It is enabled by default.
              type: boolean
              default: true
        agentless:
          description: >
            Options specific to the Agentless deployment mode. This mode is used in offerings
            where the Elastic Agents running these policies are fully managed for the user.
          type: object
          additionalProperties: false
          properties:
            enabled:
              description: >
                Indicates if the agentless deployment mode is available for this template policy.
                It is disabled by default.
              type: boolean
              default: false
            is_default:
              description: >
                On policy templates that support multiple deployment modes, this setting can be set to
                true to use agentless mode by default.
              type: boolean
              default: false
            organization:
              description: >
                The responsible organization of the integration. This is used to tag the agentless agent deployments
                for monitoring.
              type: string
              examples:
                - "security"
            division:
              description: >
                The division responsible for the integration. This is used to tag the agentless agent deployments
                for monitoring.
              type: string
              examples:
                - "cloud-security"
            team:
              description: >
                The team responsible for the integration. This is used to tag the agentless
                agent deployments for monitoring.
              type: string
              examples:
                - "cloud-security-posture-management"
            resources:
              description: >
                The computing resources specifications for the Agentless deployment.
              type: object
              additionalProperties: false
              properties:
                requests:
                  description: >
                    The computing resources that the Agentless deployment will be initially allocated.
                  type: object
                  additionalProperties: false
                  properties:
                    memory:
                      description: >
                        The amount of memory that the Agentless deployment will be initially allocated.
                      type: string
                      examples:
                        - "1G"
                        - "1.5G"
                    cpu:
                      description: >
                        The amount of CPUs that the Agentless deployment will be initially allocated.
                      type: string
                      examples:
                        - "1"
                        - "1.5"
                        - "1500m"
          allOf:
            - if:
                properties:
                  enabled:
                    const: true
              then:
                required:
                  - organization
                  - division
                  - team
    configuration_links:
      description: List of links related to inputs and policy templates.
      type: array
      minItems: 1
      items:
        type: object
        additionalProperties: false
        properties:
          title:
            description: Link title
            type: string
          url:
            description: Link url. Format is `http://...` or `https://...` for external links,  `kbn:/app/...` for links internal to Kibana.
            type: string
            pattern: '^(http(s)?://|kbn:/)'
          type:
            description: Type of link. `next_steps` for links to locations that can be relevant right after configuring the policy. `action` for actions that can be performed while the policy is in use.
            type: string
            enum:
              - action
              - next_step
          content:
            description: Link description
            type: string
        required:
        - title
        - url
        - type
    fips_compatible:
      type: boolean
      description: Indicate if this package is capable of satisfying FIPS requirements. Set to false if it uses any input that cannot be configured to use FIPS cryptography.
      default: true
    icons:
      description: List of icons for by this package.
      type: array
      items:
        type: object
        additionalProperties: false
        properties:
          src:
            description: Relative path to the icon's image file.
            type: string
            format: relative-path
            examples:
              - "/img/logo_apache.svg"
          title:
            description: Title of icon.
            type: string
            examples:
              - "Apache Logo"
          size:
            description: Size of the icon.
            type: string
            examples:
              - "32x32"
          type:
            description: MIME type of the icon image file.
            type: string
            examples:
              - "image/svg+xml"
          dark_mode:
            description: Is this icon to be shown in dark mode?
            type: boolean
            default: false
        required:
          - src
    screenshots:
      description: List of screenshots of Kibana assets created by this package.
      type: array
      items:
        type: object
        additionalProperties: false
        properties:
          src:
            description: Relative path to the screenshot's image file.
            type: string
            format: relative-path
            examples:
              - "/img/apache_httpd_server_status.png"
          title:
            description: Title of screenshot.
            type: string
            examples:
              - "Apache HTTPD Server Status"
          size:
            description: Size of the screenshot.
            type: string
            examples:
              - "1215x1199"
          type:
            description: MIME type of the screenshot image file.
            type: string
            examples:
              - "image/png"
        required:
          - src
          - title
    source:
      description: Information about the source of the package.
      type: object
      additionalProperties: false
      properties:
        license:
          description: Identifier of the license of the package, as specified in https://spdx.org/licenses/.
          type: string
          enum:
            - "Apache-2.0"
            - "Elastic-2.0"
          examples:
            - "Elastic-2.0"
    title:
      description: >
        Title of the package. It should be the usual title given to the product, service or
        kind of source being managed by this package.
      type: string
      examples:
        - Apache HTTP Server
        - MySQL
        - AWS
    version:
      description: Version of the package, following semantic versioning. It can include pre-release labels.
      type: string
      pattern: '^([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+)?$'
      examples:
        - "1.0.0"
        - "1.0.0-beta1"
        - "1.0.0-SNAPSHOT"
        - "1.0.0-next"
    owner:
      type: object
      additionalProperties: false
      properties:
        github:
          description: Github team name of the package maintainer.
          type: string
          pattern: '^(([a-zA-Z0-9-_]+)|([a-zA-Z0-9-_]+\/[a-zA-Z0-9-_]+))$'
          examples:
            - "elastic"
            - "apm-agent-java"
            - "ux_infra_team"
        type:
          description: >
            Describes who owns the package and the level of support that is
            provided. The 'elastic' value indicates that the package is built
            and maintained by Elastic. The 'partner' value indicates that the
            package is built and maintained by a partner vendor and may include
            involvement from Elastic. The 'community' value indicates the package
            is built and maintained by non-Elastic community members.
          type: string
          default: community
          enum:
            - elastic
            - partner
            - community
          examples:
            - community
      required:
        - github
        - type
  properties:
    format_version:
      description: The version of the package specification format used by this package.
      $ref: "#/definitions/version"
    name:
      description: The name of the package.
      type: string
      pattern: '^[a-z0-9_]+$'
      examples:
        - apache
    title:
      $ref: "#/definitions/title"
    description:
      $ref: "#/definitions/description"
    version:
      description: The version of the package.
      $ref: "#/definitions/version"
    source:
      $ref: "#/definitions/source"
    type:
      description: The type of package.
      type: string
      enum:
        - integration
      examples:
        - integration
    categories:
      $ref: "#/definitions/categories"
    conditions:
      $ref: "#/definitions/conditions"
    # requires a conditional JSON schema to update the value depending
    # on the policy_templates length
    policy_templates_behavior:
      description: >
        Expected behavior when there are more than one policy template defined.
        When set to `combined_policy`, a single policy template is available that
        combines all the defined templates. When set to `individual_policies`, all
        policies are individually available, but there is no combined policy.
        The default value is `all`, where the combined policy template is available
        along with the individual policies.
      type: string
    policy_templates:
      description: List of policy templates offered by this package.
      type: array
      items:
        type: object
        additionalProperties: false
        properties:
          name:
            description: Name of policy template.
            type: string
            examples:
              - apache
          title:
            description: Title of policy template.
            type: string
            examples:
              - Apache logs and metrics
          categories:
            $ref: "#/definitions/categories"
          description:
            description: Longer description of policy template.
            type: string
            examples:
              - Collect logs and metrics from Apache instances
          data_streams:
            description: List of data streams compatible with the policy template.
            type: array
            items:
              type: string
              description: Data stream name
              format: data-stream-name
              examples:
                - ec2_logs
                - spamfirewall
                - access
          deployment_modes:
            $ref: "#/definitions/deployment_modes"
          configuration_links:
            $ref: "#/definitions/configuration_links"
          fips_compatible:
            $ref: "#/definitions/fips_compatible"
          inputs:
            description: List of inputs supported by policy template.
            type: array
            items:
              type: object
              additionalProperties: false
              properties:
                type:
                  description: Type of input.
                  type: string
                title:
                  description: Title of input.
                  type: string
                  examples:
                    - Collect logs from Apache instances
                description:
                  description: Longer description of input.
                  type: string
                  examples:
                    - Collecting Apache access and error logs
                template_path:
                  description: Path of the config template for the input.
                  type: string
                  examples:
                    - ./agent/input/template.yml.hbs
                input_group:
                  description: Name of the input group
                  type: string
                  enum:
                    - logs
                    - metrics
                multi:
                  description: Can input be defined multiple times
                  type: boolean
                  default: false
                deployment_modes:
                  description: >
                    List of deployment modes that this input is compatible with.
                    If not specified, the input is compatible with all deployment modes.
                  type: array
                  minItems: 1
                  uniqueItems: true
                  items:
                    type: string
                    enum:
                      - default
                      - agentless
                  examples:
                    - ["default"]
                    - ["agentless"]
                    - ["default", "agentless"]
                required_vars:
                  $ref: "./data_stream/manifest.spec.yml#/definitions/required_vars"
                vars:
                  $ref: "./data_stream/manifest.spec.yml#/definitions/vars"
              required:
                - type
                - title
                - description
          multiple:
            type: boolean
          icons:
            $ref: "#/definitions/icons"
          screenshots:
            $ref: "#/definitions/screenshots"
          vars:
            $ref: "./data_stream/manifest.spec.yml#/definitions/vars"
        required:
          - name
          - title
          - description
    icons:
      $ref: "#/definitions/icons"
    screenshots:
      $ref: "#/definitions/screenshots"
    vars:
      $ref: "./data_stream/manifest.spec.yml#/definitions/vars"
    owner:
      $ref: "#/definitions/owner"
    agent:
      $ref: "#/definitions/agent"
    elasticsearch:
      description: Elasticsearch requirements
      type: object
      additionalProperties: false
      properties:
        privileges:
          description: Elasticsearch privilege requirements
          type: object
          additionalProperties: false
          properties:
            cluster:
              # Available cluster privileges are available at https://www.elastic.co/guide/en/elasticsearch/reference/7.16/security-privileges.html#privileges-list-cluster
              description: Elasticsearch cluster privilege requirements
              type: array
              items:
                type: string
  required:
    - format_version
    - name
    - title
    - description
    - version
    - type
    - owner
  allOf:
    - if:
        properties:
          policy_templates:
            maxItems: 1
      then:
        properties:
          policy_templates_behavior:
            enum:
              - all
            default: all
      else:
        properties:
          policy_templates_behavior:
            enum:
              - combined_policy
              - individual_policies
              - all
            default: all

# JSON patches for newer versions should be placed on top
versions:
  - before: 3.3.2
    patch:
      - op: remove
        path: "/properties/policy_templates/items/properties/inputs/items/properties/required_vars"
      - op: remove
        path: "/definitions/deployment_modes/properties/agentless/properties/is_default"
      - op: remove
        path: "/definitions/deployment_modes/properties/agentless/properties/resources"
  - before: 3.3.1
    patch:
      - op: remove
        path: "/properties/policy_templates/items/properties/configuration_links"
  - before: 3.2.0
    patch:
      - op: remove
        path: "/definitions/deployment_modes/properties/default"
  - before: 3.1.4
    patch:
      - op: remove
        path: "/properties/policy_templates/items/properties/deployment_modes"
  - before: 3.0.0
    patch:
      - op: replace
        path: "/definitions/owner/required"
        value:
          - github
  - before: 2.12.0
    patch:
      - op: remove
        path: "/properties/agent"
  - before: 2.11.0
    patch:
      - op: replace
        path: "/definitions/owner/properties/type/default"
        value: elastic
  - before: 2.10.0
    patch:
      - op: remove
        path: "/definitions/conditions/properties/elastic/properties/capabilities"
  - before: 2.3.0
    patch:
      - op: add
        path: "/properties/release"
        value:
          description: The stability of the package (deprecated, use prerelease tags in the version).
          deprecated: true # See https://github.com/elastic/package-spec/issues/225
          type: string
          enum:
            - experimental
            - beta
            - ga
          default: ga
          examples:
            - experimental
  - before: 2.0.0
    patch:
      - op: add
        path: "/properties/license"
        value:
          description: The license under which the package is being released (deprecated, use subscription instead).
          deprecated: true # See https://github.com/elastic/package-spec/issues/298.
          type: string
          enum:
            - basic
          default: basic
          examples:
            - basic
```
