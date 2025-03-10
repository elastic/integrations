以下是您提供的内容的中文翻译：

# tencent_cloud_audit_log 集成

## 概述

解释集成的内容，定义提供数据的第三方产品，建立它与 Elastic 产品的关系，并帮助读者了解如何使用它解决实际问题。  
更多信息，请查看[概述指南](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-overview)。

## 数据流

### tencent_cloud_audit_log

腾讯云审计日志

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
2. 在 **搜索集成** 搜索框中，输入 tencent_cloud_audit_log。
3. 从搜索结果中点击 **tencent_cloud_audit_log** 集成。
4. 点击 **添加 tencent_cloud_audit_log** 按钮以添加集成。
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

### TLS/SSL 配置（可选）
为了增强安全性，可以配置服务器的 TLS/SSL 设置。这可以确保客户端与服务器之间的安全通信。以下是配置这些设置的示例：

```yml
ssl.certificate: "/etc/pki/server/cert.pem"
ssl.key: "/etc/pki/server/cert.key"
```

ssl.key：服务器用来解密使用其对应公钥加密的数据，并签署数据以验证其身份的私钥。  
ssl.certificate：服务器的证书，用于验证其身份，包含公钥，并通过证书颁发机构（CA）进行验证，以建立与客户端的加密连接。

在输入设置中，根据您的端点的具体要求，包括任何相关的 SSL 配置和秘密头值。您还可以配置其他选项，如证书、密钥、支持的协议和验证模式。更多详细信息，请参见 [Elastic SSL 文档](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-server-config)。

## 故障排除（可选）

- 如果某些字段在 ``logs-*`` 或 ``metrics-*`` 数据视图中出现冲突，可以通过[重建索引](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream)解决此问题。

提供有关特殊情况和异常的信息，这些情况对于入门并非必要，或者不会适用于所有用户。更多信息，请查看[故障排除指南](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-troubleshooting)。

## 参考

提供有关我们在集成中支持的日志或度量类型的详细信息。更多信息，请查看[参考指南](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-reference)。

## 日志

### tencent_cloud_audit_log

腾讯云审计日志

**ECS 字段参考**

有关 ECS 字段的详细信息，请参见以下[文档](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)。

**导出字段**

| 字段                  | 描述                                               | 类型             |
| --------------------- | -------------------------------------------------- | ---------------- |
| @timestamp            | 事件时间戳。                                       | date             |
| cloud.image.id        | 云实例的镜像 ID。                                  | keyword          |
| container.labels      | 镜像标签。                                         | object           |
| data_stream.dataset   | 数据流数据集名称。                                 | constant_keyword |
| data_stream.namespace | 数据流命名空间。                                   | constant_keyword |
| data_stream.type      | 数据流类型。                                       | constant_keyword |
| event.dataset         | 事件数据集                                         | constant_keyword |
| event.module          | 事件模块                                           | constant_keyword |
| host.containerized    | 主机是否为容器。                                   | boolean          |
| host.os.build         | 操作系统构建信息。                                 | keyword          |
| host.os.codename      | 操作系统代号（如果有）。                           | keyword          |
| input.type            | Filebeat 输入类型。                                | keyword          |
| log.file.device_id    | 包含文件系统的设备 ID。                            | keyword          |
| log.file.fingerprint  | 启用指纹识别时，文件的 sha256 指纹身份。           | keyword          |
| log.file.idxhi        | 与文件关联的唯一标识符的高位部分（仅限 Windows）。 | keyword          |
| log.file.idxlo        | 与文件关联的唯一标识符的低位部分（仅限 Windows）。 | keyword          |
| log.file.inode        | 日志文件的 inode 编号。                            | keyword          |
| log.file.vol          | 包含文件的卷的序列号（仅限 Windows）。             | keyword          |
| log.flags             | 日志文件的标志。                                   | keyword          |
| log.offset            | 日志文件中条目的偏移量。                           | long             |
