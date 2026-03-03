# Tencent Cloud 集成

## 概述

Tencent Cloud 集成旨在通过 Elastic Agent 将腾讯云的各种云产品的日志无缝接入 Elastic Stack，帮助用户统一存储、分析和可视化云环境中的关键操作数据。


更多信息，请查看[概述指南](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-overview)。

## 数据流

### tencent_cloud.audit

该数据流将[腾讯云审计服务](https://cloud.tencent.com/product/cloudaudit)（Tencent Cloud Audit）作为第三方数据源，记录了用户在腾讯云控制台、API 或 SDK 中的所有操作行为，包括创建资源、修改配置、删除实例等。通过此集成，这些审计日志将被 Elastic Agent 采集，并通过 Elasticsearch 进行高效存储与检索，最终在 Kibana 中呈现直观的可视化分析，助力用户实现以下目标：
- **实时监控云操作**：追踪用户行为，及时发现异常操作或潜在安全风险。
- **合规性审计**：满足行业合规要求，快速回溯操作历史以应对审计需求。
- **故障排查与优化**：通过分析操作日志，定位云资源配置或使用中的问题，优化运维流程。
此集成建立了腾讯云审计服务与 Elastic Stack 的直接连接，利用 Elastic 的可观测性能力，将分散的云审计数据转化为可行动的洞察，帮助用户提升云环境的安全性、可靠性和可管理性。

### tencent_cloud.scf

该数据流以[腾讯云无服务器云函数](https://cloud.tencent.com/product/scf)（Tencent Cloud Serverless Cloud Function，SCF）为第三方数据源，它允许用户在无需管理服务器的情况下运行代码。SCF 会记录函数执行过程中的各类信息，涵盖函数调用的详细情况、运行时间、资源使用状况等。借助此集成，这些日志会被 Elastic Agent 采集，然后存储于 Elasticsearch 中，以便进行高效检索，最终在 Kibana 里展示直观的可视化分析，能帮助用户达成以下目标：
- **性能监控**：实时监测函数的执行时间、内存使用等性能指标，及时发现性能瓶颈并进行优化。
- **错误排查**：快速定位函数执行过程中出现的错误和异常，分析错误原因，加速问题解决。
- **成本优化**：通过分析函数的调用频率和资源使用情况，合理调整资源配置，降低使用成本。
此集成构建了腾讯云无服务器云函数与 Elastic Stack 的有效连接，借助 Elastic 的可观测性能力，将零散的云函数日志数据转化为有价值的洞察，助力用户提升云函数的性能、稳定性和成本效益。

### tencent_cloud.cos

该数据流把[腾讯云对象存储](https://cloud.tencent.com/product/cos)（Tencent Cloud Object Storage，COS）当作第三方数据源，COS 为用户提供了安全、稳定、高效的海量存储服务，会记录存储操作的相关信息，例如文件的上传、下载、删除操作，以及操作的时间、来源 IP 等。通过这个集成，这些存储操作日志会被 Elastic Agent 采集，再由 Elasticsearch 进行存储和检索，最终在 Kibana 上以直观的可视化形式呈现，帮助用户实现以下目标：
- **数据访问监控**：监控文件的访问情况，了解用户对存储数据的使用习惯，及时发现异常访问行为。
- **数据安全审计**：审计存储操作，确保数据的安全性和合规性，满足企业的安全要求。
- **存储成本管理**：分析存储操作的频率和数据量，优化存储策略，降低存储成本。
此集成实现了腾讯云对象存储与 Elastic Stack 的连接，利用 Elastic 的可观测性能力，将分散的存储操作日志转化为可利用的信息，帮助用户提升对象存储的安全性、可用性和成本效益。 

### tencent_cloud.clb

该数据流以[腾讯云负载均衡](https://cloud.tencent.com/product/clb)（Tencent Cloud Load Balancer，CLB）为第三方数据源，CLB 会记录负载均衡器的各类操作日志，涵盖请求的详细情况、响应时间、源 IP 等。借助此集成，这些日志会被 Elastic Agent 采集，然后存储于 Elasticsearch 中，以便进行高效检索，最终在 Kibana 里展示直观的可视化分析，能帮助用户达成以下目标：
- **性能监控**：实时监测负载均衡器的请求处理时间、响应时间等性能指标，及时发现性能瓶颈并进行优化。
- **错误排查**：快速定位负载均衡器处理请求过程中出现的错误和异常，分析错误原因，加速问题解决。
- **安全审计**：通过分析负载均衡器的访问日志，发现异常访问行为，提升系统的安全性。
此集成构建了腾讯云负载均衡与 Elastic Stack 的有效连接，借助 Elastic 的可观测性能力，将零散的负载均衡日志数据转化为有价值的洞察，助力用户提升负载均衡器的性能、稳定性和安全性。

## 系统要求

必须安装 Elastic Agent。有关更多信息，请参阅[这些说明](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html)。

#### 安装和管理 Elastic Agent：

您有几种选项可以安装和管理 Elastic Agent：

#### 安装 Fleet 管理的 Elastic Agent（推荐）：

通过这种方式，您安装 Elastic Agent，并使用 Kibana 中的 Fleet 来定义、配置和管理您的代理，在一个中央位置进行管理。我们推荐使用 Fleet 管理，因为它使代理的管理和升级更加轻松。

#### 在独立模式下安装 Elastic Agent（高级用户）：

通过这种方式，您安装 Elastic Agent，并手动在系统上配置代理。您需要负责管理和升级代理。此方法仅适用于高级用户。

#### 在容器化环境中安装 Elastic Agent：

您可以将 Elastic Agent 运行在容器中，可以选择与 Fleet Server 一起使用或独立使用。Elastic Agent 的所有版本的 Docker 镜像都可以从 Elastic Docker 注册表获得，我们还提供 Kubernetes 上运行的部署清单。

您需要 Elasticsearch 用于存储和搜索数据，Kibana 用于可视化和管理数据。  
您可以使用我们托管的 Elasticsearch 服务（Elastic Cloud 推荐），或者在您自己的硬件上自行管理 Elastic Stack。

“系统要求”部分帮助读者确认集成是否能在他们的系统上运行。  
更多信息，请查看[要求指南](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-requirements)。

## 设置

请参考[可观察性入门指南](https://www.elastic.co/guide/en/observability/master/observability-get-started.html) 获取通用的逐步说明。包括任何额外的设置说明，这些说明可能包括更新第三方服务配置的说明。  
更多信息，请查看[设置指南](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-setup)。

### 在 Elastic 中启用集成：

#### 从 ZIP 文件创建新集成（可选）
1. 在 Kibana 中，转到 **管理** > **集成**。
2. 选择 **创建新集成**。
3. 选择 **上传为 .zip**。
4. 上传 ZIP 文件。
5. 选择 **添加到 Elastic**。

### 安装集成
1. 在 Kibana 中，转到 **管理** > **集成**。
2. 在 **搜索集成** 搜索框中，输入 Tencent Cloud。
3. 从搜索结果中点击 **Tencent Cloud** 集成。
4. 点击 **添加 Tencent Cloud** 按钮以添加集成。
5. 添加所有必需的集成配置参数。
6. 点击 **保存并继续** 以保存集成。



## 要从腾讯云COS收集腾讯云各种产品的日志数据，您可以按照以下步骤进行：
1. **开启对应云产品的日志记录功能**：
   不同的腾讯云云产品开启日志记录功能的位置有所不同。例如:
    - 对于腾讯云审计日志：
      - 登录腾讯云控制台，进入【控制中心】>产品页面。
      - 在【审计实例】页，选择目标实例，点击【开通审计服务】。
      - 在弹出的窗口中，选择审计类型（全审计或规则审计），配置审计规则，并设置审计日志的保存时长和存储方式。
   - 完成配置后，点击【确定】以开通审计服务。
    - 对于腾讯云数据库（如MySQL）：
        - 登录腾讯云控制台，进入【云数据库 MySQL】页面。
        - 选择目标数据库实例，在实例管理页面中找到【日志管理】部分，根据数据库版本及实际需求开启慢查询日志、错误日志等相应日志记录功能。
    - 针对其他云产品，您可参考腾讯云官方文档中对应产品的日志管理章节，按照指引开启日志记录功能。确保日志记录功能开启后，相关产品的操作和运行信息能够被记录下来，以便后续采集。
2. **使用腾讯云日志服务（CLS）采集日志**：
    - 登录腾讯云日志服务（CLS）控制台。
    - 在CLS控制台左侧导航栏，点击【日志主题】。
    - 点击【新建日志主题】按钮，为要采集的云产品日志创建一个专属的日志主题，在创建过程中，设置合适的日志主题名称、所属地域、日志保存周期等参数。
    - 创建完成后，回到【日志主题】列表，点击刚才创建的日志主题名称进入详情页。
    - 在详情页中，找到【采集配置】部分，根据不同云产品的日志来源，选择合适的采集方式。例如：
        - 如果是服务器本地日志（如CVM的系统日志），可选择【机器组采集】，并按照提示安装和配置采集客户端到相应的服务器实例上，配置采集路径（如/var/log/ 等存放日志文件的目录）等参数。
        - 如果是云产品自身提供的日志API（如部分数据库产品），可选择【API采集】方式，按照指引配置相关的API密钥、请求参数等，以实现通过API拉取日志数据到CLS。
3. **配置CLS日志投递到COS**：
    - 在腾讯云CLS控制台，确保已完成日志采集并存储在相应日志主题中。
    - 点击左侧导航栏的【日志投递】。
    - 点击【新建投递任务】按钮，在弹出的配置窗口中：
        - 选择【源日志主题】，即前面步骤中通过CLS采集云产品日志所使用的日志主题。
        - 选择【投递方式】为【COS】。
        - 配置【投递目标】，填写要投递到的COS存储桶名称、所属地域，并可根据需求设置对象前缀，用于区分不同来源或类型的日志数据在COS中的存储路径。
        - 完成配置后，点击【确定】保存投递任务设置。
4. **使用Elastic Agent从COS获取日志**：
    - 确保已安装并启动Elastic Agent，且Elastic Agent所在服务器具有访问腾讯云COS的权限（可通过配置腾讯云访问密钥等方式实现）。
    - 根据不同的数据源，在integration的配置页面，针对从COS获取日志数据进行配置。在配置文件中，指定COS存储桶名称、地域信息，以及要获取的日志文件路径（结合前面设置的COS对象前缀）等关键信息。
    - 配置完成后，重启Elastic Agent使配置生效。此时，Elastic Agent将按照配置定时从COS存储桶中拉取日志数据，并将其传输到Elasticsearch集群进行后续存储和分析。
5. **验证日志收集全流程**：
    - 在Elasticsearch中，通过Kibana的Dev Tools或其他工具，执行查询语句，验证是否有从COS获取并成功存储到Elasticsearch中的云产品日志数据。例如，可根据云产品名称、时间范围等条件进行查询。
    - 在Kibana中创建可视化仪表盘，展示收集到的云产品日志数据的分析结果，如操作频率趋势、错误类型统计等。若发现日志收集流程中存在问题，可按照上述步骤依次排查，包括日志记录功能是否正常开启、CLS采集和投递配置是否正确、Elastic Agent与COS的连接及配置是否无误等。 

## 故障排除（可选）
- 注意：目前腾讯云上的COS与Elastic Agent存在一些已知问题，可能会导致数据流无法正常工作。如果你的COS bucket是创建于2024年1月1日之后。请直接使用 Filebeat 进行数据采集。或者使用创建时间修改为2024年1月1日之前的bucket。

- 如果某些字段在 ``logs-*`` 或 ``metrics-*`` 数据视图中出现冲突，可以通过[重建索引](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream)解决此问题。

提供有关特殊情况和异常的信息，这些情况对于入门并非必要，或者不会适用于所有用户。更多信息，请查看[故障排除指南](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-troubleshooting)。

## 参考

提供有关我们在集成中支持的日志或度量类型的详细信息。更多信息，请查看[参考指南](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-reference)。


**ECS 字段参考**

有关 ECS 字段的详细信息，请参见以下[文档](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)。

### 审计日志

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| tencent_cloud.audit.actionType | 审计日志中的操作类型 | keyword |
| tencent_cloud.audit.apiErrorCode | 审计日志中的API错误代码 | keyword |
| tencent_cloud.audit.errorMessage | 审计日志中的错误信息 | keyword |
| tencent_cloud.audit.eventTime | 审计日志中的事件时间 | long |
| tencent_cloud.audit.eventType | 审计日志中的事件类型 | keyword |
| tencent_cloud.audit.eventVersion | 审计日志中的事件版本 | long |
| tencent_cloud.audit.requestParameters.AccountArea | 请求参数中的账户区域 | keyword |
| tencent_cloud.audit.requestParameters.Conditions.Key | 请求条件中的键 | keyword |
| tencent_cloud.audit.requestParameters.Conditions.Operator | 请求条件中的操作符 | keyword |
| tencent_cloud.audit.requestParameters.Conditions.Value | 请求条件中的值 | keyword |
| tencent_cloud.audit.requestParameters.DiskChargeType | 请求参数中的磁盘计费类型 | keyword |
| tencent_cloud.audit.requestParameters.EndTime | 请求参数中的结束时间 | keyword |
| tencent_cloud.audit.requestParameters.InquiryType | 请求参数中的查询类型 | keyword |
| tencent_cloud.audit.requestParameters.InstanceIds | 请求参数中的实例ID | keyword |
| tencent_cloud.audit.requestParameters.Limit | 请求参数中的限制值 | long |
| tencent_cloud.audit.requestParameters.MetricNames | 请求参数中的指标名称 | keyword |
| tencent_cloud.audit.requestParameters.Module | 请求参数中的模块 | keyword |
| tencent_cloud.audit.requestParameters.Namespace | 请求参数中的命名空间 | keyword |
| tencent_cloud.audit.requestParameters.Period | 请求参数中的周期 | long |
| tencent_cloud.audit.requestParameters.Region | 请求参数中的区域 | keyword |
| tencent_cloud.audit.requestParameters.StartTime | 请求参数中的开始时间 | keyword |
| tencent_cloud.audit.requestParameters.Version | 请求参数中的版本 | keyword |
| tencent_cloud.audit.requestParameters.Zones | 请求参数中的区域 | keyword |
| tencent_cloud.audit.resourceName | 审计日志中的资源名称 | keyword |
| tencent_cloud.audit.resourceType | 审计日志中的资源类型 | keyword |
| tencent_cloud.audit.responseElements | 审计日志中的响应元素 | keyword |
| tencent_cloud.audit.sensitiveAction | 是否敏感操作 | keyword |
| tencent_cloud.audit.userIdentity.principalId | 用户身份中的主体ID | keyword |
| tencent_cloud.audit.userIdentity.roleSessionName | 用户身份中的角色会话名称 | keyword |
| tencent_cloud.audit.userIdentity.secretId | 用户身份中的密钥ID | keyword |
| tencent_cloud.audit.userIdentity.sessionContext | 用户身份中的会话上下文 | text |
| tencent_cloud.audit.userIdentity.type | 用户身份类型 | keyword |


### SCF 日志

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| tencent_cloud.scf.SCF_Alias | SCF别名 | keyword |
| tencent_cloud.scf.SCF_LogTime | SCF日志时间 | date |
| tencent_cloud.scf.SCF_MemUsage | 函数运行内存 | double |
| tencent_cloud.scf.SCF_Namespace | SCF命名空间 | keyword |
| tencent_cloud.scf.SCF_RetryNum | SCF重试次数 | long |
| tencent_cloud.scf.SCF_StartTime | SCF开始时间 | date |
| tencent_cloud.scf.SCF_Type | SCF类型，Platform 指平台日志，Custom 指用户日志。 | keyword |
| tencent_cloud.scf.__TIMESTAMP__ | 时间戳 | date |


### COS 日志

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.bytes | Destination bytes | long |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| tencent_cloud.cos.bucketName | 腾讯云COS桶的名称 | keyword |
| tencent_cloud.cos.deltaDataSize | 腾讯云COS操作中的增量数据大小 | long |
| tencent_cloud.cos.eventSource | 腾讯云COS中的事件来源 | keyword |
| tencent_cloud.cos.eventTime | COS日志中的事件时间 | date |
| tencent_cloud.cos.eventVersion | 腾讯云COS中的事件版本 | keyword |
| tencent_cloud.cos.logSourceType | 腾讯云COS中的日志源类型 | keyword |
| tencent_cloud.cos.objectSize | 腾讯云COS中的对象大小 | keyword |
| tencent_cloud.cos.qcsRegion | 腾讯云COS的qcs区域 | keyword |
| tencent_cloud.cos.range | COS日志中的范围信息 | keyword |
| tencent_cloud.cos.reqQcsSource | COS日志中的请求QCS来源 | keyword |
| tencent_cloud.cos.requester | 腾讯云COS操作中的请求者 | keyword |
| tencent_cloud.cos.resErrorCode | COS操作响应中的错误代码 | keyword |
| tencent_cloud.cos.resErrorMsg | 腾讯云COS操作中的响应错误信息 | keyword |
| tencent_cloud.cos.resTotalTime | 腾讯云COS操作中的总响应时间 | long |
| tencent_cloud.cos.storageClass | 腾讯云COS中的存储类别, STANDARD，STANDARD_IA，ARCHIVE | keyword |
| tencent_cloud.cos.targetStorageClass | 腾讯云COS中的目标存储类别, STANDARD，STANDARD_IA，ARCHIVE | keyword |
| tencent_cloud.cos.userSecretKeyId | 腾讯云COS中的用户密钥ID | keyword |
| tencent_cloud.cos.versionId | 腾讯云COS中的版本ID | keyword |
| tencent_cloud.cos.vpcId | VPC 请求 ID | long |


### CLB 日志

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| tencent_cloud.clb.__SOURCE__ | 日志来源 | keyword |
| tencent_cloud.clb.connection | 连接 | long |
| tencent_cloud.clb.connection_requests | 连接请求 | long |
| tencent_cloud.clb.http_traceparent | HTTP traceparent | keyword |
| tencent_cloud.clb.lb_id | 负载均衡器ID | keyword |
| tencent_cloud.clb.proxy_host | 代理主机 | long |
| tencent_cloud.clb.request | 请求 | keyword |
| tencent_cloud.clb.request_time | 请求时间 | long |
| tencent_cloud.clb.ssl_cipher | SSL密码 | keyword |
| tencent_cloud.clb.ssl_handshake_time | SSL握手时间 | keyword |
| tencent_cloud.clb.ssl_protocol | SSL协议 | keyword |
| tencent_cloud.clb.ssl_session_reused | SSL会话重用 | keyword |
| tencent_cloud.clb.stgw_engine_connect_time | STGW引擎连接时间 | keyword |
| tencent_cloud.clb.stgw_engine_response_time | STGW引擎响应时间 | keyword |
| tencent_cloud.clb.tcpinfo_rtt | TCP信息RTT | long |
| tencent_cloud.clb.time_local | 本地时间 | date |
| tencent_cloud.clb.upstream_header_time | 从 RS 接收完 HTTP 头部所花费时间：从开始 CONNECT RS 到从 RS 接收完 HTTP 应答头部的时间。单位：秒。 | double |
| tencent_cloud.clb.upstream_response_time | 整个后端请求所花费时间：从开始 CONNECT RS 到从 RS 接收完应答的时间。单位：秒。 | double |
| tencent_cloud.clb.upstream_status | RS 返回给 CLB 的状态码 | long |
| tencent_cloud.clb.via_stgw_engine | 通过STGW引擎 | keyword |
| tencent_cloud.clb.vip_vpcid | VIP VPC ID | long |
| tencent_cloud.clb.vsvc_id | Vsvc ID | long |

