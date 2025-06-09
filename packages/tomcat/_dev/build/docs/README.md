> ⚠️ **IMPORTANT**
>
> This package is *deprecated* and is not supported for installation in Elastic Cloud Serverless.

# Tomcat NetWitness Logs integration (DEPRECATED)

This integration is for [Tomcat device's](https://tomcat.apache.org/tomcat-10.0-doc/logging.html) logs. It includes the following
datasets for receiving logs over syslog or read from a file:

- `log` dataset: supports Apache Tomcat logs.

Note:
- To collect Apache Tomcat Logs and Metrics please use [``Apache Tomcat``](https://docs.elastic.co/integrations/apache_tomcat) integration since [``Tomcat NetWitness Logs``](https://docs.elastic.co/integrations/tomcat) integration has been deprecated.

### Log

The `log` dataset collects Apache Tomcat logs.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "log"}}
