variable "TEST_RUN_ID" {
  default = "detached"
}

locals {
  activemq_log_group_name_general = "/aws/activemq/broker/test-${var.TEST_RUN_ID}/general"
  activemq_log_stream_name_general = "activemq-log-stream-general"

  region = "us-east-1"
}

provider "aws" {
  region = local.region
  
  default_tags {
    tags = {
      environment  = var.ENVIRONMENT
      repo         = var.REPO
      branch       = var.BRANCH
      build        = var.BUILD_ID
      created_date = var.CREATED_DATE
    }
  }
}

resource "aws_cloudwatch_log_group" "activemq_log_group" {
    name = local.activemq_log_group_name_general
}

resource "aws_cloudwatch_log_stream" "activemq_log_stream" {
    name = local.activemq_log_stream_name_general
    log_group_name = local.activemq_log_group_name_general

    depends_on = [aws_cloudwatch_log_group.activemq_log_group]
}

# Push data to CloudWatch log stream. Workaround for https://github.com/elastic/elastic-package/issues/3206
resource "null_resource" "push_logs" {
    depends_on = [ aws_cloudwatch_log_stream.activemq_log_stream ]

    triggers = {
        logs_hash = filemd5("${path.module}/files/activemq_general.log")
    }

    provisioner "local-exec" {
      command     = "${path.module}/files/put_logs.sh"
      interpreter = ["/bin/sh"]

      environment = {
        LOG_GROUP_NAME        = aws_cloudwatch_log_group.activemq_log_group.name
        LOG_STREAM_NAME       = aws_cloudwatch_log_stream.activemq_log_stream.name
        SAMPLE_LOG_FILE       = "${path.module}/files/activemq_general.log"
        AWS_REGION            = local.region
        AWS_DEFAULT_REGION    = local.region
      }
    }
}

output "log_group_arn" {
  value = aws_cloudwatch_log_group.activemq_log_group.arn
}
