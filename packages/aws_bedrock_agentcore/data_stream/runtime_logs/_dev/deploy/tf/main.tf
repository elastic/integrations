variable "TEST_RUN_ID" {
  default = "detached"
}

terraform {
  required_providers {
    aws  = { source = "hashicorp/aws" }
    null = { source = "hashicorp/null" }
    time = { source = "hashicorp/time" }
  }
}

locals {
  runtime_logs_log_group  = "/aws/bedrock-agentcore/runtimes/imds_lab_agent-Qr5TuVw8Xy-${var.TEST_RUN_ID}"
  runtime_logs_log_stream = "2026/07/01/[runtime-logs-a1-imds-0f1e2d3c4b5a69788796a5b4c3d2e1f0]7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d"

  runtime_logs_lines = [
    for line in split("\n", file("${path.module}/files/runtime-logs-sample.log")) : line
    if trimspace(line) != ""
  ]
}

provider "aws" {
  default_tags {
    tags = {
      environment  = var.ENVIRONMENT
      repo         = var.REPO
      branch       = var.BRANCH
      build        = var.BUILD_ID
      created_date = var.CREATED_DATE

      division = "engineering"
      org      = "obs"
      team     = "obs-signals-integrations-team"
      project  = "integrations-aws_bedrock_agentcore-package"
    }
  }
}

resource "aws_cloudwatch_log_group" "runtime_logs" {
  name              = local.runtime_logs_log_group
  retention_in_days = 1
}

resource "aws_cloudwatch_log_stream" "runtime_logs" {
  name           = local.runtime_logs_log_stream
  log_group_name = aws_cloudwatch_log_group.runtime_logs.name

  depends_on = [aws_cloudwatch_log_group.runtime_logs]
}

resource "time_static" "push_time" {
  triggers = {
    run_id    = var.TEST_RUN_ID
    logs_hash = filemd5("${path.module}/files/runtime-logs-sample.log")
  }
}

resource "null_resource" "push_runtime_logs" {
  depends_on = [aws_cloudwatch_log_stream.runtime_logs]

  triggers = {
    run_id    = var.TEST_RUN_ID
    logs_hash = filemd5("${path.module}/files/runtime-logs-sample.log")
  }

  provisioner "local-exec" {
    command     = <<-EOT
    set -e

    unset AWS_PROFILE

    if ! command -v aws >/dev/null 2>&1; then
      apt-get update -qq
      apt-get install -y -qq curl unzip > /dev/null 2>&1

      curl -sS "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
      unzip -q -o /tmp/awscliv2.zip -d /tmp
      /tmp/aws/install 2>/dev/null || /tmp/aws/install --update
    fi

    aws logs put-log-events \
        --region "$AWS_REGION" \
        --log-group-name "$LOG_GROUP_NAME" \
        --log-stream-name "$LOG_STREAM_NAME" \
        --log-events "$LOG_EVENTS"
    EOT
    interpreter = ["/bin/sh", "-c"]

    environment = {
      LOG_GROUP_NAME  = aws_cloudwatch_log_group.runtime_logs.name
      LOG_STREAM_NAME = aws_cloudwatch_log_stream.runtime_logs.name
      LOG_EVENTS = jsonencode([
        for index, line in local.runtime_logs_lines : {
          timestamp = (time_static.push_time.unix + index) * 1000
          message   = line
        }
      ])
    }
  }
}

data "aws_region" "current" {}

output "runtime_logs_log_group_arn" {
  value = aws_cloudwatch_log_group.runtime_logs.arn
}

output "region_name" {
  value = data.aws_region.current.region
}
