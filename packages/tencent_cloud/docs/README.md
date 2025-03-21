# Tencent Cloud 集成

## 概述

Tencent Cloud 集成旨在将腾讯云的日志无缝接入 Elastic Stack，帮助用户统一存储、分析和可视化云环境中的关键操作数据。

腾讯云审计服务（Tencent Cloud Audit）作为第三方数据源，记录了用户在腾讯云控制台、API 或 SDK 中的所有操作行为，包括创建资源、修改配置、删除实例等。通过此集成，这些审计日志将被 Elastic Agent 采集，并通过 Elasticsearch 进行高效存储与检索，最终在 Kibana 中呈现直观的可视化分析，助力用户实现以下目标：
- **实时监控云操作**：追踪用户行为，及时发现异常操作或潜在安全风险。
- **合规性审计**：满足行业合规要求，快速回溯操作历史以应对审计需求。
- **故障排查与优化**：通过分析操作日志，定位云资源配置或使用中的问题，优化运维流程。
此集成建立了腾讯云审计服务与 Elastic Stack 的直接连接，利用 Elastic 的可观测性能力，将分散的云审计数据转化为可行动的洞察，帮助用户提升云环境的安全性、可靠性和可管理性。

更多信息，请查看[概述指南](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-overview)。

## 数据流

### tencent_cloud.audit

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


### 要从腾讯云 COS 收集腾讯云审计数据，您可以按照以下步骤进行：

1. **开通操作审计服务**：
   - 登录腾讯云控制台，进入【控制中心】>【合规审计】页面。
   - 在【审计实例】页，选择目标实例，点击【开通审计服务】。
   - 在弹出的窗口中，选择审计类型（全审计或规则审计），配置审计规则，并设置审计日志的保存时长和存储方式。
   - 完成配置后，点击【确定】以开通审计服务。
   

2. **配置审计日志投递到 COS**：
   - 在【控制中心】>【合规审计】页面，找到已开通的审计实例。
   - 在【操作审计日志投递】列表中，点击相应的投递名称，进入【操作审计】>【跟踪集】页面。
   - 在【跟踪集】页面，选择【投递方式】为【COS】。
   - 填写投递的存储桶名称、所属地域，并设置前缀。
   - 完成配置后，点击【确定】以保存设置。
   

3. **验证日志投递**：
   - 在【控制中心】>【合规审计】页面，查看【操作审计日志投递】列表，确认投递状态为【已投递】。
   - 登录腾讯云 COS 控制台，进入相应的存储桶，检查是否成功接收到审计日志文件。

通过以上步骤，您可以将腾讯云审计数据投递到 COS，实现对审计日志的集中存储和管理。 


## 故障排除（可选）

- 如果某些字段在 ``logs-*`` 或 ``metrics-*`` 数据视图中出现冲突，可以通过[重建索引](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream)解决此问题。

提供有关特殊情况和异常的信息，这些情况对于入门并非必要，或者不会适用于所有用户。更多信息，请查看[故障排除指南](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-troubleshooting)。

## 参考

提供有关我们在集成中支持的日志或度量类型的详细信息。更多信息，请查看[参考指南](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-reference)。


**ECS 字段参考**

有关 ECS 字段的详细信息，请参见以下[文档](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)。

**导出字段**

| 字段                                  | 描述                                                                                                                | 类型    |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ------- |
| @timestamp                            | 事件时间从腾讯云审计日志的eventTime字段转换而来的时间戳。                                                           | date    |
| cloud.account.id                      | 来自腾讯云审计日志中userIdentity.accountId字段重命名后的云账户ID。                                                  | keyword |
| user.name                             | 来自腾讯云审计日志中userIdentity.userName字段重命名后的用户名。                                                     | keyword |
| cloud.region                          | 来自腾讯云审计日志中eventRegion字段重命名后的事件发生的云区域。                                                     | keyword |
| error.code                            | 来自腾讯云审计日志中errorCode字段重命名后的错误代码。                                                               | keyword |
| event.id                              | 来自腾讯云审计日志中requestID字段重命名后的事件ID。                                                                 | keyword |
| http.request.method                   | 来自腾讯云审计日志中httpMethod字段重命名后的HTTP请求方法。                                                          | keyword |
| user_agent.original                   | 来自腾讯云审计日志中userAgent字段重命名后的原始用户代理信息。                                                       | keyword |
| source.ip                             | 来自腾讯云审计日志中sourceIPAddress字段重命名后的源IP地址。                                                         | ip      |
| event.action                          | 来自腾讯云审计日志中eventName字段重命名后的事件动作。                                                               | keyword |
| event.provider                        | 来自腾讯云审计日志中eventSource字段重命名后的事件提供者。                                                           | keyword |
| source.geo                            | 基于源IP地址通过geoip处理器获取的地理信息。                                                                         | object  |
| source.as                             | 基于源IP地址通过geoip处理器获取的自治系统信息。                                                                     | object  |
| source.as.number                      | source.as中的asn字段重命名后的自治系统编号。                                                                        | long    |
| source.as.organization.name           | source.as中的organization_name字段重命名后的自治系统所属组织名称。                                                  | keyword |
| destination.ip                        | 目标IP地址（若日志中有相关目标地址字段，经处理后得到）。                                                            | ip      |
| destination.geo                       | 基于目标IP地址通过geoip处理器获取的地理信息（若日志中有相关目标地址字段，经处理后得到）。                           | object  |
| destination.as                        | 基于目标IP地址通过geoip处理器获取的自治系统信息（若日志中有相关目标地址字段，经处理后得到）。                       | object  |
| destination.as.number                 | destination.as中的asn字段重命名后的自治系统编号（若日志中有相关目标地址字段，经处理后得到）。                       | long    |
| destination.as.organization.name      | destination.as中的organization_name字段重命名后的自治系统所属组织名称（若日志中有相关目标地址字段，经处理后得到）。 | keyword |
| tencent_cloud.audit                   | 腾讯云审计日志，经json处理器解析后得到。                                                                | object  |
| tencent_cloud.audit.requestParameters | 腾讯云审计日志中的请求参数，经json处理器解析后得到。                                                                | object  |
| tencent_cloud.audit.userIdentity      | 腾讯云审计日志中的用户身份信息，经json处理器解析后得到。                                                            | object  |
| tags                                  | 文档关联的标签。                                                                                                    | keyword |
| error.message                         | 若ingest pipeline处理失败时记录的错误信息。                                                                         | text    |
| event.kind                            | 事件类型，当管道出错时设置为pipeline_error 。                                                                       | keyword |
| ecs.version                           | 由ingest pipeline中set处理器设置的ECS版本。                                                                         | keyword |
